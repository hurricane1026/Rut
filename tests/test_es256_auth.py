#!/usr/bin/env python3
"""Exercise the shipped ES256 policy over real two-shard TLS/native loading."""
import argparse
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
    fixture = json.loads(subprocess.check_output([args.helper, "--emit-fixture"], timeout=10))
    original = Path(args.source)
    with tempfile.TemporaryDirectory(prefix="rut-es256-auth-") as directory:
        root = Path(directory)
        source = root / "auth.rut"
        source.write_text(original.read_text() + '\nroute GET "/ready" { return 204 }\n')
        middleware = root / "middleware"
        middleware.mkdir()
        module = middleware / "auth.rut"
        module.write_bytes((original.parent / "middleware/auth.rut").read_bytes())
        env = dict(os.environ, JWT_ES256_POLICY=json.dumps(fixture["policy"]))
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
                status, _, body = request(headers=good + [("X-Consumer-ID", "mallory")])
                assert (status, body) == (200, b"alice"), (status, body)
            for name, expected in [("scope", 403), ("issuer", 401), ("expired", 401),
                                    ("revoked", 401), ("algorithm", 401), ("unknown_kid", 401)]:
                status, fields, body = request(headers=[("Authorization", "Bearer " + fixture[name])])
                assert status == expected, (name, status, body)
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
    print(f"ES256 TLS/native auth passed: {args.backend}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--helper", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=["epoll", "io_uring"], required=True)
    exercise(parser.parse_args())
