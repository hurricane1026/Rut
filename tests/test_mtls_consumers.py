#!/usr/bin/env python3
"""Exercise static mTLS Consumer mapping with two distinct certificate identities."""
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
    # The second public fixture reuses the test key but has a different signed
    # subject, serial number and DER fingerprint. No system OpenSSL CLI is required at test time.
    second_cert = certificates / "mtls_second_cert.pem"
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    second_pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(second_cert.read_text())).hexdigest()
    assert pin != second_pin
    other = "0" * 64
    assert other not in (pin, second_pin)
    original = Path(args.source)
    with tempfile.TemporaryDirectory(prefix="rut-mtls-consumers-") as directory:
        root = Path(directory)
        source = root / "gateway.rut"
        module = root / "middleware/auth.rut"
        module.parent.mkdir()
        module.write_bytes((original.parent / "middleware/auth.rut").read_bytes())
        mtls_module = module.parent / "mtls.rut"
        mtls_module.write_bytes((original.parent / "middleware/mtls.rut").read_bytes())
        text = original.read_text() + '\nroute GET "/ready" { return 204 }\n'
        cases = [
            ("normal", pin, second_pin, "alice", "bob", (200, b"alice-cert"), (200, b"bob-cert")),
            ("first-disabled", "", second_pin, "alice", "bob", (403, b""), (200, b"bob-cert")),
            ("second-disabled", pin, "", "alice", "bob", (200, b"alice-cert"), (403, b"")),
            ("retired", other, second_pin, "alice", "bob", (403, b""), (200, b"bob-cert")),
            ("ambiguous", pin, pin, "alice", "bob", (503, b""), (503, b"")),
            ("same-owner", pin, second_pin, "alice", "alice", (503, b""), (503, b"")),
            ("invalid", pin, "A" * 64, "alice", "bob", (503, b""), (503, b"")),
        ]
        for path, first, second, first_id, second_id, _, _ in cases:
            text += (f'route GET "/{path}" {{\n'
                     'let identity = mtls.identity('
                     f'mtls.Consumer(consumerId: "{first_id}", sha256: "{first}", credentialId: "alice-cert"), '
                     f'mtls.Consumer(consumerId: "{second_id}", sha256: "{second}", credentialId: "bob-cert"))\n'
                     'let credential = identity.credentialId\n'
                     'return response(200, body: credential)\n}\n')
        source.write_text(text)
        env = dict(os.environ, MTLS_FIRST_PIN=pin, MTLS_SECOND_PIN=second_pin,
                   MTLS_FIRST_CONSUMER="alice", MTLS_SECOND_CONSUMER="bob",
                   MTLS_FIRST_ID="alice-cert", MTLS_SECOND_ID="bob-cert")
        contexts = []
        for client_cert in (cert, second_cert):
            context = ssl.create_default_context(cafile=str(cert))
            context.load_cert_chain(str(client_cert), str(key))
            contexts.append(context)
        without_certificate = ssl.create_default_context(cafile=str(cert))
        ca_bundle = root / "clients.pem"
        ca_bundle.write_text(cert.read_text() + second_cert.read_text())
        process = subprocess.Popen(
            [args.server, "0", str(source), "--backend", args.backend, "--shards", "2",
             "--no-pin", "--drain", "0", "--max-connections-per-shard", "32",
             "--tls-cert", str(cert), "--tls-key", str(key), "--tls-client-ca", str(ca_bundle)],
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

            def request(path, client_context=contexts[0]):
                connection = http.client.HTTPSConnection("localhost", port, context=client_context, timeout=5)
                try:
                    connection.request("GET", path, headers={
                        "X-Client-Cert-Sha256": pin, "X-Consumer-ID": "alice",
                        "X-Credential-ID": "forged"})
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            assert request("/ready")[0] == 204
            source.unlink()
            module.unlink()
            mtls_module.unlink()
            for _ in range(4):
                for context, consumer, allowed in ((contexts[0], b"alice", 200), (contexts[1], b"bob", 403)):
                    assert request("/private", context) == (200, consumer)
                    status, body = request("/first-only", context)
                    assert status == allowed, (consumer, status, body)
                for path, _, _, _, _, expected_first, expected_second in cases:
                    for context, expected in zip(contexts, (expected_first, expected_second)):
                        status, body = request("/" + path, context)
                        assert status == expected[0], (path, status, body)
                        if status == 200:
                            assert body == expected[1], (path, body)
                        else:
                            assert b"alice-cert" not in body and b"bob-cert" not in body
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
    print(f"mTLS Consumer mapping passed: {args.backend}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=["epoll", "io_uring"], required=True)
    exercise(parser.parse_args())
