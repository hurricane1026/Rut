#!/usr/bin/env python3
"""Signed JWT scope-list authorization through native-loaded Rut on both backends."""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

KEY = "scope-list-test-key-0123456789abcdef0123456789abcdef"


def encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def token(claims):
    header = encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = encode(claims.encode() if isinstance(claims, str) else json.dumps(claims).encode())
    signed = header + b"." + payload
    return (signed + b"." + encode(hmac.new(KEY.encode(), signed, hashlib.sha256).digest())).decode()


def request(port, path, version, authorization, duplicate=False):
    fields = "" if authorization is None else f"Authorization: Bearer {authorization}\r\n"
    if duplicate:
        fields += fields
    wire = (f"GET {path} {version}\r\nHost: local\r\nConnection: close\r\n" + fields +
            "X-Scope: admin orders:write orders:read\r\nX-Consumer-ID: attacker\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(wire)
        response = b""
        while True:
            data = conn.recv(65536)
            if not data:
                break
            response += data
    lines = response.split(b"\r\n\r\n", 1)[0].decode().split("\r\n")
    challenges = [line.split(":", 1)[1].strip() for line in lines[1:]
                  if line.lower().startswith("www-authenticate:")]
    return int(lines[0].split()[1]), challenges


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    parser.add_argument("--exclusions", action="store_true")
    args = parser.parse_args()
    now = int(time.time())
    base = dict(sub="alice", iss="https://issuer.example", aud="orders", iat=now, exp=now + 600)
    read = token(dict(base, scope="orders:read"))
    signed, signature = read.rsplit(".", 1)
    tampered = signed + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
    duplicate_claim = json.dumps(base)[:-1] + ',"scope":"orders:read","sc\\u006fpe":"admin"}'
    cases = [
        (read, False, 204, 403),
        (token(dict(base, scope="orders:write")), False, 204, 403),
        (token(dict(base, scope="orders:read orders:write admin")), False, 204, 204),
        (token(dict(base, scope="delete")), False, 403, 403),
        (token(dict(base, scope="orders:reader")), False, 403, 403),
        (token(dict(base, scope="Orders:read")), False, 403, 403),
        (token(dict(base, scope="orders:read bad\t")), False, 403, 403),
        (token(dict(base, scope=["orders:read"])), False, 403, 403),
        (token(base), False, 403, 403),
        (token(duplicate_claim), False, 401, 401),
        (token(dict(base, scope="orders:read", exp=now - 1)), False, 401, 401),
        (token(dict(base, scope="orders:read", aud="other")), False, 401, 401),
        (tampered, False, 401, 401),
        (None, False, 401, 401),
        (read, True, 401, 401),
    ]
    denied = "debug suspended support:restricted"
    profiles = [("valid", "admin orders:write orders:read", denied),
                ("malformed", "orders:read  admin", denied),
                ("oversized", "orders:read " + "a" * 1024, denied)]
    if args.exclusions:
        cases.extend([
            (token(dict(base, scope="orders:read debug")), False, 403, 403),
            (token(dict(base, scope="orders:read orders:write admin debug")), False, 403, 403),
            (token(dict(base, scope="orders:read debug-extra")), False, 204, 403),
            (token(dict(base, scope="orders:read Debug")), False, 204, 403),
            (token(dict(base, scope="orders:read orders:write admin debug-extra")), False, 204, 204),
            (token(dict(base, scope="orders:read suspended support:restricted")), False, 403, 403),
        ])
        profiles.extend([
            ("malformed-deny", "admin orders:write orders:read", "debug  suspended"),
            ("oversized-deny", "admin orders:write orders:read", "debug " + "a" * 1024),
            ("empty-deny", "admin orders:write orders:read", ""),
        ])
    source = Path(args.source).resolve()
    checks = 0
    with tempfile.TemporaryDirectory(prefix="rut-jwt-scope-lists-") as directory:
        root = Path(directory)
        (root / "middleware").mkdir()
        for name in ("auth.rut", "jwt_scopes.rut"):
            shutil.copyfile(source.parent / "middleware" / name, root / "middleware" / name)
        for profile, scopes, exclusions in profiles:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            program = root / "scopes.rut"
            program.write_text(source.read_text().replace("listen :8080", f"listen :{port}"))
            env = dict(os.environ, JWT_SECRET=KEY, JWT_REQUIRED_SCOPES=scopes)
            if args.exclusions:
                env["JWT_EXCLUDED_SCOPES"] = exclusions
            with (root / "gateway.log").open("w+") as log:
                proc = subprocess.Popen([args.server, str(program), "--backend", args.backend,
                                         "--shards", "1", "--drain", "0"],
                                        env=env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        if proc.poll() is not None:
                            log.seek(0)
                            output = log.read()
                            if args.backend == "io_uring" and "io_uring is unavailable" in output:
                                print("SKIP: io_uring unavailable")
                                return 77
                            raise AssertionError(output)
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                log.seek(0)
                                raise AssertionError("startup timeout: " + log.read())
                            time.sleep(.02)
                    for version in ("HTTP/1.0", "HTTP/1.1"):
                        for path in ("/any", "/all"):
                            for credential, duplicate, any_status, all_status in cases:
                                expected = any_status if path == "/any" else all_status
                                if profile != "valid" and expected != 401:
                                    expected = 503
                                status, challenges = request(port, path, version, credential, duplicate)
                                context = (args.backend, profile, version, path, status, expected)
                                assert status == expected, context
                                expected_challenge = ["Bearer"] if expected == 401 else (
                                    ['Bearer error="insufficient_scope"'] if expected == 403 else [])
                                assert challenges == expected_challenge, (context, challenges)
                                checks += 1
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
    print(f"{args.backend}: {checks} signed JWT HTTP checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
