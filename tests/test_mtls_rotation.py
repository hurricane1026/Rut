#!/usr/bin/env python3
"""Exercise static mTLS pin rotation through two-shard TLS/native loading."""
import argparse
import hashlib
import http.client
import os
from pathlib import Path
import re
import select
import ssl
import subprocess
import tempfile
import time


def exercise(args):
    certificates = Path(args.testdata)
    cert = certificates / "localhost_cert.pem"
    key = certificates / "localhost_key.pem"
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    other = "0" * 64
    assert pin != other
    original = Path(args.source)
    with tempfile.TemporaryDirectory(prefix="rut-mtls-rotation-") as directory:
        root = Path(directory)
        source = root / "gateway.rut"
        module = root / "middleware/auth.rut"
        module.parent.mkdir()
        module.write_bytes((original.parent / "middleware/auth.rut").read_bytes())
        text = original.read_text() + '\nroute GET "/ready" { return 204 }\n'
        cases = [
            ("current", pin, other, 200, b"current"),
            ("previous", other, pin, 200, b"previous"),
            ("revoked", other, "", 403, b""),
            ("current-only", pin, "", 200, b"current"),
            ("equal", pin, pin, 200, b"current"),
            ("bad-config", pin, "A" * 64, 503, b""),
            ("disabled", "", "", 503, b""),
        ]
        for path, current, previous, _, _ in cases:
            text += (f'route GET "/{path}" {{\n'
                     f'let identity = auth.rotatingPinnedMtlsIdentity("{current}", "{previous}", '
                     '"client", "current", "previous")\n'
                     'let credential = identity.credentialId\n'
                     'return response(200, body: credential)\n}\n')
        source.write_text(text)
        env = dict(os.environ, MTLS_CURRENT_PIN=pin, MTLS_PREVIOUS_PIN=other,
                   MTLS_CONSUMER_ID="client", MTLS_CURRENT_ID="current", MTLS_PREVIOUS_ID="previous")
        context = ssl.create_default_context(cafile=str(cert))
        context.load_cert_chain(str(cert), str(key))
        without_certificate = ssl.create_default_context(cafile=str(cert))
        process = subprocess.Popen(
            [args.server, "0", str(source), "--backend", args.backend, "--shards", "2",
             "--no-pin", "--drain", "0", "--max-connections-per-shard", "32",
             "--tls-cert", str(cert), "--tls-key", str(key), "--tls-client-ca", str(cert)],
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

            def request(path, client_context=context):
                connection = http.client.HTTPSConnection("localhost", port, context=client_context, timeout=5)
                try:
                    connection.request("GET", path, headers={
                        "X-Client-Cert-Sha256": other, "X-Consumer-ID": "attacker",
                        "X-Credential-ID": "forged"})
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            assert request("/ready")[0] == 204
            source.unlink()
            module.unlink()
            for _ in range(4):
                assert request("/private") == (200, b"client")
                for path, _, _, status, body in cases:
                    actual_status, actual_body = request("/" + path)
                    assert actual_status == status, (path, actual_status, actual_body)
                    if status == 200:
                        assert actual_body == body, (path, actual_body)
                    else:
                        assert b"client" not in actual_body and b"previous" not in actual_body
            try:
                result = request("/private", without_certificate)
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError,
                    http.client.RemoteDisconnected):
                pass
            else:
                raise AssertionError(f"request without a client certificate reached HTTP: {result}")
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
    print(f"mTLS pin rotation passed: {args.backend}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=["epoll", "io_uring"], required=True)
    exercise(parser.parse_args())
