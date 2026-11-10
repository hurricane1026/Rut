#!/usr/bin/env python3
"""Bind separately verified credentials through native-loaded Rut on each backend."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


def exchange(port, path, version, fields):
    # Neither query/body credentials nor spoofed identity metadata may fill a factor.
    body = b"Authorization: Basic YWxpY2U6cGFzc3dvcmQ=\r\nX-API-Key: alice-key"
    request = (f"GET {path}?api_key=alice-key {version}\r\nHost: local\r\n"
               "Connection: close\r\nX-Consumer-ID: alice\r\n"
               "X-Credential-ID: password-and-key\r\n" + fields +
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(request)
        response = b""
        while True:
            data = conn.recv(65536)
            if not data:
                break
            response += data
    head, payload = response.split(b"\r\n\r\n", 1)
    lines = head.decode().split("\r\n")
    challenges = [line.split(":", 1)[1].strip() for line in lines[1:]
                  if line.lower().startswith("www-authenticate:")]
    return int(lines[0].split()[1]), payload.decode(), challenges


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    args = parser.parse_args()
    source = Path(args.source).resolve()
    # Independent fixture ownership; each verifier must succeed before binding.
    passwords = [
        ("", None),
        ("Authorization:\r\n", None),
        ("Authorization: Basic YWxpY2U6cGFzc3dvcmQ=\r\n", "alice"),
        ("authorization: Basic Ym9iOnBhc3N3b3Jk\r\n", "bob"),
        ("Authorization: Basic d3Jvbmc6cGFzc3dvcmQ=\r\n", None),
        ("Authorization: Bearer alice-key\r\n", None),
        ("Authorization: Basic YWxpY2U6cGFzc3dvcmQ=\r\n"
         "authorization: Basic Ym9iOnBhc3N3b3Jk\r\n", None),
        ("Authorization: Basic YWxpY2U6cGFzc3dvcmQ=\r\n"
         "authorization: Basic YWxpY2U6cGFzc3dvcmQ=\r\n", None),
    ]
    keys = [
        ("", None),
        ("X-API-Key:\r\n", None),
        ("X-API-Key: alice-key\r\n", "alice"),
        ("x-api-key: bob-key\r\n", "bob"),
        ("X-API-Key: wrong\r\n", None),
        ("X-API-Key: ALICE-KEY\r\n", None),
        ("X-API-Key: alice-key,bob-key\r\n", None),
        ("X-API-Key: alice-key\r\nx-api-key: bob-key\r\n", None),
        ("X-API-Key: alice-key\r\nx-api-key: alice-key\r\n", None),
    ]
    checks = 0
    with tempfile.TemporaryDirectory(prefix="rut-bound-credentials-") as directory:
        root = Path(directory)
        middleware = root / "middleware"
        middleware.mkdir()
        for name in ("auth.rut", "identity_auth.rut"):
            shutil.copyfile(source.parent / "middleware" / name, middleware / name)
        for valid_policy in (True, False):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            program = root / "bound.rut"
            text = source.read_text().replace("listen :8080", f"listen :{port}")
            if not valid_policy:
                text = text.replace('"password-and-key"', '""')
            program.write_text(text)
            env = dict(os.environ, ALICE_BASIC_CREDENTIALS="alice:password",
                       BOB_BASIC_CREDENTIALS="bob:password", ALICE_API_KEY="alice-key",
                       BOB_API_KEY="bob-key")
            with (root / "gateway.log").open("w+") as log:
                proc = subprocess.Popen(
                    [args.server, str(program), "--backend", args.backend,
                     "--shards", "1", "--no-pin", "--drain", "0",
                     "--max-connections-per-shard", "128"],
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
                        for path in ("/private", "/alice-only"):
                            for password, password_owner in passwords:
                                for key, key_owner in keys:
                                    expected = 200
                                    challenges = []
                                    if password_owner is None:
                                        expected = 401
                                        challenges = ["Bearer", 'Basic realm="rut"']
                                    elif key_owner is None:
                                        expected = 401
                                        challenges = ["ApiKey"]
                                    elif not valid_policy:
                                        expected = 503
                                    elif password_owner != key_owner or (
                                            path == "/alice-only" and password_owner != "alice"):
                                        expected = 403
                                    status, body, actual = exchange(
                                        port, path, version, password + key)
                                    context = (args.backend, valid_policy, version, path,
                                               password, key, status)
                                    assert status == expected, context
                                    assert actual == challenges, (context, actual)
                                    if status == 200:
                                        assert body == password_owner == key_owner, (context, body)
                                    checks += 1
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
    print(f"{args.backend}: {checks} native HTTP checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
