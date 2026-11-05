#!/usr/bin/env python3
"""Exercise client-bound JWT identities over two-shard TLS/native loading."""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import select
import ssl
import subprocess
import tempfile
import time


def exercise(args):
    secret = "jwt-client-test-secret-abcdefghijklmnopqrstuvwxyz"
    now = int(time.time())

    def token(updates=None, remove=(), raw=None, header=None):
        claims = dict(sub="alice", iss="issuer", aud="gateway", iat=now,
                      exp=now + 120, scope="orders:read", client_id="orders-web")
        claims.update(updates or {})
        for field in remove:
            claims.pop(field, None)
        encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
        protected = json.dumps(header or {"alg": "HS256", "typ": "JWT"}).encode()
        payload = raw.encode() if raw is not None else json.dumps(claims).encode()
        message = encode(protected) + b"." + encode(payload)
        signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        return (message + b"." + encode(signature)).decode()

    fixture = {
        "valid": token(),
        "scope": token({"scope": "other"}),
        "issuer": token({"iss": "wrong"}),
        "expired": token({"exp": 1}),
        "audience": token({"aud": "other"}),
        "client": token({"client_id": "mobile"}),
        "client_case": token({"client_id": "Orders-web"}),
        "missing_client": token(remove=("client_id",)),
        "null_client": token({"client_id": None}),
        "array_client": token({"client_id": ["orders-web"]}),
        "empty_client": token({"client_id": ""}),
        "azp_only": token({"azp": "orders-web"}, remove=("client_id",)),
        "header_only": token(remove=("client_id",),
                             header={"alg": "HS256", "client_id": "orders-web"}),
        "duplicate_client": token(raw='{"sub":"alice","iss":"issuer","aud":"gateway",'
            '"exp":4102444800,"scope":"orders:read","client_id":"orders-web",'
            '"client_id":"orders-web"}'),
    }
    original = Path(args.source)
    with tempfile.TemporaryDirectory(prefix="rut-jwt-client-auth-") as directory:
        root = Path(directory)
        source = root / "auth.rut"
        source.write_text(original.read_text() + '\nroute GET "/ready" { return 204 }\n')
        middleware = root / "middleware"
        middleware.mkdir()
        module = middleware / "auth.rut"
        module.write_bytes((original.parent / "middleware/auth.rut").read_bytes())
        env = dict(os.environ, JWT_SECRET=secret, JWT_ISSUER="issuer",
                   JWT_AUDIENCE="gateway", JWT_CLIENT_ID="orders-web")
        certificates = Path(args.testdata)
        context = ssl.create_default_context(cafile=str(certificates / "localhost_cert.pem"))
        process = subprocess.Popen(
            [args.server, "0", str(source), "--backend", args.backend, "--shards", "2",
             "--no-pin", "--drain", "0", "--max-connections-per-shard", "32",
             "--tls-cert", str(certificates / "localhost_cert.pem"),
             "--tls-key", str(certificates / "localhost_key.pem")],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        startup = b""
        try:
            port = None
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if select.select([process.stdout], [], [], 0.05)[0]:
                    startup += os.read(process.stdout.fileno(), 4096)
                    match = re.search(rb"Listening on port ([0-9]+) with", startup)
                    if match:
                        port = int(match.group(1))
                        break
                if process.poll() is not None:
                    break
            if port is None:
                if args.backend == "io_uring" and b"io_uring is unavailable" in startup:
                    raise SystemExit(77)
                raise AssertionError(f"gateway did not listen: {startup!r}")

            def request(path="/orders", headers=()):
                connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=5)
                try:
                    connection.putrequest("GET", path)
                    for name, value in headers:
                        connection.putheader(name, value)
                    connection.endheaders()
                    response = connection.getresponse()
                    return response.status, response.headers, response.read()
                finally:
                    connection.close()

            assert request("/ready")[0] == 204
            source.unlink()
            module.unlink()
            assert request()[0] == 401
            good = [("Authorization", "Bearer " + fixture["valid"])]
            for _ in range(8):
                status, _, body = request(headers=good + [("X-Consumer-ID", "mallory"), ("X-Client-ID", "spoofed")])
                assert (status, body) == (200, b"alice"), (status, body)
            for name, expected in [("scope", 403), ("issuer", 401), ("expired", 401),
                                    ("audience", 401), ("client", 403), ("client_case", 403),
                                    ("missing_client", 401), ("null_client", 401),
                                    ("array_client", 401), ("empty_client", 401),
                                    ("azp_only", 401), ("header_only", 401),
                                    ("duplicate_client", 401)]:
                status, fields, body = request(headers=[("Authorization", "Bearer " + fixture[name]),
                    ("X-Client-ID", "orders-web"), ("X-Consumer-ID", "alice")])
                assert status == expected, (name, status, body)
                assert b"alice" not in body, (name, body)
                if expected == 401 or name == "scope":
                    assert "Bearer" in fields.get("WWW-Authenticate", ""), (name, dict(fields))
            assert request(headers=good * 2)[0] == 401
            assert request(headers=[("Authorization", "Bearer malformed")])[0] == 401
            token = fixture["valid"]
            bad = token[:-5] + ("A" if token[-5] != "A" else "B") + token[-4:]
            assert request(headers=[("Authorization", "Bearer " + bad)])[0] == 401
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                remaining = process.communicate(timeout=15)[0]
            except subprocess.TimeoutExpired:
                process.kill()
                remaining = process.communicate()[0]
                raise AssertionError(f"gateway did not stop: {startup + remaining!r}")
            if args.backend == "io_uring" and b"io_uring is unavailable" in startup + remaining:
                raise SystemExit(77)
            assert process.returncode == 0, (process.returncode, startup + remaining)
    print(f"Client-bound JWT TLS/native auth passed: {args.backend}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=["epoll", "io_uring"], required=True)
    exercise(parser.parse_args())
