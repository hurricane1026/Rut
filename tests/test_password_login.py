#!/usr/bin/env python3
"""Run the shipped fixed-account password/JWT flow over verified local TLS."""
import argparse
import base64
from contextlib import contextmanager
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import time
import ssl
import uuid


# Independent PBKDF2 fixture for password=b"password", salt=bytes(range(16)).
RECORD = ("$rut-pbkdf2-sha256$600000$000102030405060708090a0b0c0d0e0f$"
          "3bc37118e625093e9b79ed08930ea7af7389591233fdd92dddf369371e60dbc0")
KEY = b"01234567890123456789012345678901"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def decode(data):
    return base64.b64decode(data + b"=" * (-len(data) % 4), altchars=b"-_", validate=True)


def sign(claims, algorithm="HS256"):
    header = b64(json.dumps({"alg": algorithm, "typ": "JWT"}).encode())
    payload = header + b"." + b64(json.dumps(claims, separators=(",", ":")).encode())
    return payload + b"." + b64(hmac.digest(KEY, payload, "sha256"))


def verify(token, expected_scope="orders.read"):
    header, payload, signature = token.split(b".")
    assert hmac.compare_digest(decode(signature), hmac.digest(KEY, header + b"." + payload, "sha256"))
    assert json.loads(decode(header)) == {"alg": "HS256", "typ": "JWT"}
    claims = json.loads(decode(payload))
    assert set(claims) == {"sub", "iss", "aud", "iat", "exp", "jti", "scope"}
    assert (claims["sub"], claims["iss"], claims["aud"], claims["scope"]) == (
        "alice", "rut-password-login", "orders", expected_scope)
    assert claims["exp"] - claims["iat"] == 300
    assert abs(claims["iat"] - time.time()) < 30
    assert uuid.UUID(claims["jti"]).version == 4
    return claims


@contextmanager
def gateway(args, *, subject="alice", key=KEY.decode(), timeout=5000, scope="orders.read"):
    source = Path(args.source)
    program = source.read_text()
    if scope != "orders.read":
        needle = '"orders.read", env("JWT_ISSUE_KEY"), 300)'
        assert program.count(needle) == 1
        program = program.replace(needle, f'{json.dumps(scope)}, env("JWT_ISSUE_KEY"), 300)')
    # Exercise another permission and their intersection with the same token.
    program += '''
route GET "/audit" {
    let claims = auth.jwtDocumentHs256(req.authorization.or(""), env("JWT_ISSUE_KEY"))
    let identity = auth.jwtIdentityWithLifetime(claims, "rut-password-login", "orders", "login-jwt", 300, 300)
    guard jwtHasScope(claims, "orders.audit") else { return 403 }
    let subject = identity.consumerId
    return response(200, body: subject)
}
route GET "/both" {
    let claims = auth.jwtDocumentHs256(req.authorization.or(""), env("JWT_ISSUE_KEY"))
    let identity = auth.jwtIdentityWithLifetime(claims, "rut-password-login", "orders", "login-jwt", 300, 300)
    guard jwtHasScope(claims, "orders.read") && jwtHasScope(claims, "orders.audit") else { return 403 }
    let subject = identity.consumerId
    return response(200, body: subject)
}
'''
    if timeout != 5000:
        needle = 'env("PASSWORD_HASH"), 5000)'
        assert program.count(needle) == 1
        program = program.replace(needle, f'env("PASSWORD_HASH"), {timeout})')
    with tempfile.TemporaryDirectory(prefix="rut-password-login-") as directory:
        path = Path(directory) / "login.rut"
        path.write_text(program)
        middleware = path.parent / "middleware"
        middleware.mkdir()
        module = middleware / "auth.rut"
        module.write_bytes((source.parent / "middleware/auth.rut").read_bytes())
        env = dict(os.environ, PASSWORD_HASH=args.record, PASSWORD_SUBJECT=subject, JWT_ISSUE_KEY=key)
        context = ssl.create_default_context(cafile=str(Path(args.testdata) / "localhost_cert.pem"))
        process = subprocess.Popen(
            [args.server, "0", str(path), "--backend", args.backend, "--shards", "2",
             "--no-pin", "--drain", "0", "--max-connections-per-shard", "32",
             "--tls-cert", str(Path(args.testdata) / "localhost_cert.pem"),
             "--tls-key", str(Path(args.testdata) / "localhost_key.pem")],
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

            def request(method, path, headers=()):
                connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=10)
                try:
                    connection.putrequest(method, path)
                    for name, value in headers:
                        connection.putheader(name, value)
                    connection.endheaders()
                    response = connection.getresponse()
                    return response.status, response.headers, response.read()
                finally:
                    connection.close()

            assert request("GET", "/ready")[0] == 204
            # The loader must own code, policy strings and imported helper data.
            path.unlink()
            module.unlink()
            yield request
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                output = process.communicate(timeout=15)[0]
            except subprocess.TimeoutExpired:
                process.kill()
                output = process.communicate()[0]
                raise AssertionError(f"gateway did not stop: {startup + output!r}")
            if args.backend == "io_uring" and b"io_uring is unavailable" in startup + output:
                raise SystemExit(77)
            assert process.returncode == 0, (process.returncode, startup + output)


def exercise(args):
    password = [("X-Password", "password")]
    with gateway(args) as request:
        assert request("GET", "/private")[0] == 401
        for headers in [[], [("X-Password", "password"), ("x-password", "password")],
                        [("X-Password", "wrong")]]:
            status, fields, body = request("POST", "/login", headers)
            assert status == 401, (status, body)
            assert fields.get("Cache-Control") == "no-store"

        tokens = []
        for _ in range(2):
            status, fields, token = request("POST", "/login", password + [
                ("X-Consumer-ID", "mallory"), ("X-Credential-ID", "forged"),
                ("X-Forwarded-For", "192.0.2.1")])
            assert status == 200, (status, token)
            assert fields.get("Content-Type") == "application/jwt"
            assert fields.get("Cache-Control") == "no-store"
            assert fields.get("Pragma") == "no-cache"
            tokens.append((token, verify(token)))
        assert tokens[0][1]["jti"] != tokens[1][1]["jti"]

        # Missing, ambiguous and incorrect credentials all consumed admission
        # budget, even across separate TLS connections and two shards.
        status, fields, body = request("POST", "/login", password + [
            ("X-Forwarded-For", "198.51.100.2"), ("Forwarded", "for=198.51.100.2")])
        assert status == 429, (status, body)
        assert int(fields.get("Retry-After")) > 0
        assert fields.get("Content-Type") != "application/jwt"

        token, claims = tokens[0]
        status, fields, body = request("GET", "/private", [("Authorization", "Bearer " + token.decode())])
        assert (status, body) == (200, b"alice")
        assert fields.get("Cache-Control") == "no-store"
        bad_signature = token.rsplit(b".", 1)[0] + b"." + b64(bytes(32))
        assert request("GET", "/private", [("Authorization", "Bearer " + bad_signature.decode())])[0] == 401
        for change, expected in [({"iss": "wrong"}, 401), ({"aud": "wrong"}, 401),
                                 ({"exp": claims["iat"] - 1}, 401),
                                 ({"exp": claims["iat"] + 301}, 401),
                                 ({"scope": "orders.write"}, 403)]:
            candidate = sign(dict(claims, **change)).decode()
            assert request("GET", "/private", [("Authorization", "Bearer " + candidate)])[0] == expected
        candidate = sign(claims, algorithm="HS384").decode()
        assert request("GET", "/private", [("Authorization", "Bearer " + candidate)])[0] == 401
        duplicate = [("Authorization", "Bearer " + token.decode())] * 2
        assert request("GET", "/private", duplicate)[0] == 401

    # Signatures, exact list bytes, and both permissions survive native loading
    # after source removal on each backend. Client scope headers confer nothing.
    with gateway(args, scope="orders.read orders.audit") as request:
        status, _, token = request("POST", "/login", password + [("X-Scope", "admin")])
        assert status == 200, (status, token)
        claims = verify(token, "orders.read orders.audit")
        authorization = [("Authorization", "Bearer " + token.decode())]
        for path in ("/private", "/audit", "/both"):
            status, _, body = request("GET", path, authorization)
            assert (status, body) == (200, b"alice"), (path, status, body)
        for scope, path, expected in [("orders.read", "/audit", 403),
                                      ("orders.audit", "/private", 403),
                                      ("orders.read", "/both", 403),
                                      ("orders.audit orders.read", "/both", 200),
                                      ("orders.read  orders.audit", "/both", 403),
                                      ("orders.read orders.audit\t", "/private", 403)]:
            candidate = sign(dict(claims, scope=scope)).decode()
            status = request("GET", path, [("Authorization", "Bearer " + candidate),
                                           ("X-Scope", "orders.read orders.audit")])[0]
            assert status == expected, (scope, path, status)
        assert request("GET", "/both", authorization * 2)[0] == 401

    # Issuer policy is never trimmed, split on arbitrary whitespace or normalized.
    for scope in ("orders.read  orders.audit", " orders.read", "orders.read ",
                  "orders.read orders.audit\t"):
        with gateway(args, scope=scope) as request:
            status, fields, body = request("POST", "/login", password)
            assert status == 503, (scope, status, body)
            assert fields.get("Content-Type") != "application/jwt"

    for options, expected in [({"subject": ""}, 503), ({"key": "short"}, 503), ({"timeout": 1}, 504)]:
        with gateway(args, **options) as request:
            status, fields, body = request("POST", "/login", password)
            assert status == expected, (options, status, body)
            assert fields.get("Content-Type") != "application/jwt"
    print(f"{args.backend}: TLS password/JWT login, global admission and fail-closed policies passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    parser.add_argument("--password-tool")
    args = parser.parse_args()
    args.record = RECORD
    if args.password_tool:
        result = subprocess.run([args.password_tool, "hash"], input=b"password",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        assert result.returncode == 0 and not result.stderr, result.stderr
        assert re.fullmatch(rb"\$rut-pbkdf2-sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}\n", result.stdout)
        args.record = result.stdout[:-1].decode("ascii")
    exercise(args)
