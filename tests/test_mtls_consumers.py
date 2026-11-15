#!/usr/bin/env python3
"""Exercise static mTLS Consumer mapping with two distinct certificate identities."""
import argparse
from contextlib import contextmanager
import hashlib
import http.client
from auth_h2_fixture import request as h2_request
import json
import os
from pathlib import Path
import re
import select
import ssl
import subprocess
import tempfile
import time


@contextmanager
def registry_gateway(args, source, environment, mode):
    certificates = Path(args.testdata)
    command = [args.server, "0", str(source), "--backend", args.backend,
               "--shards", "2", "--no-pin", "--drain", "0"]
    if mode in ("mtls", "server-tls"):
        command += ["--h2", "--tls-cert", str(certificates / "localhost_cert.pem"),
                    "--tls-key", str(certificates / "localhost_key.pem")]
    if mode == "mtls":
        command += ["--tls-client-ca", str(args.client_ca)]
    process = subprocess.Popen(command, env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
            raise AssertionError(f"registry gateway failed to listen: {startup!r}")
        source.unlink()
        yield port
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            remaining = process.communicate(timeout=15)[0]
        except subprocess.TimeoutExpired:
            process.kill()
            remaining = process.communicate()[0]
            raise AssertionError(f"registry gateway did not stop: {startup + remaining!r}")
        if args.backend == "io_uring" and b"io_uring is unavailable" in startup + remaining:
            raise SystemExit(77)
        assert process.returncode == 0, (process.returncode, startup + remaining)


def registry_request(port, path, headers, tls_context=None):
    connection_type = http.client.HTTPSConnection if tls_context else http.client.HTTPConnection
    options = {"context": tls_context} if tls_context else {}
    connection = connection_type("localhost", port, timeout=5, **options)
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


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
        registry = {
            "version": 1,
            "consumers": [
                {"id": "alice", "enabled": True, "groups": ["staff"]},
                {"id": "bob", "enabled": True, "groups": []},
            ],
            "credentials": [
                {"id": "alice-cert", "consumerId": "alice", "method": "mtls", "secret": pin,
                 "enabled": True},
                {"id": "bob-cert", "consumerId": "bob", "method": "mtls", "secret": second_pin,
                 "enabled": True},
            ],
        }
        text += '''
route GET "/registry-private" {
    guard let identity = consumerAuthenticateMtls(env("MTLS_REGISTRY")) else { return 401 }
    guard let consumerId = json.string(json.get(identity, "/consumerId").or(identity)) else { return 503 }
    return response(200, body: consumerId)
}
route GET "/registry-staff" {
    guard let identity = consumerAuthenticateMtls(env("MTLS_REGISTRY")) else { return 401 }
    guard jwtHasGroup(identity, "staff") else { return 403 }
    return 204
}
'''
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
                   MTLS_FIRST_ID="alice-cert", MTLS_SECOND_ID="bob-cert",
                   MTLS_REGISTRY=json.dumps(registry))
        contexts = []
        for client_cert in (cert, second_cert):
            context = ssl.create_default_context(cafile=str(cert))
            context.load_cert_chain(str(client_cert), str(key))
            contexts.append(context)
        h2_contexts = []
        for client_cert in (cert, second_cert):
            context = ssl.create_default_context(cafile=str(cert))
            context.load_cert_chain(str(client_cert), str(key))
            context.set_alpn_protocols(["h2"])
            h2_contexts.append(context)
        without_certificate = ssl.create_default_context(cafile=str(cert))
        ca_bundle = root / "clients.pem"
        ca_bundle.write_text(cert.read_text() + second_cert.read_text())
        process = subprocess.Popen(
            [args.server, "0", str(source), "--backend", args.backend, "--shards", "2",
             "--no-pin", "--h2", "--drain", "0", "--max-connections-per-shard", "32",
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
            for context, consumer, group_status in ((contexts[0], b"alice", 204),
                                                     (contexts[1], b"bob", 403)):
                assert request("/registry-private", context) == (200, consumer)
                assert request("/registry-staff", context)[0] == group_status
                assert h2_request(port, "/registry-private", [
                    ("x-client-cert-sha256", "0" * 64), ("x-consumer-id", "forged")],
                    tls_context=h2_contexts[contexts.index(context)]) == (200, consumer)
                assert h2_request(port, "/registry-staff", [],
                                  tls_context=h2_contexts[contexts.index(context)])[0] == group_status
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

        ca_bundle = root / "clients.pem"
        ca_bundle.write_text(cert.read_text() + second_cert.read_text())
        args.client_ca = ca_bundle
        disabled_registry = json.loads(json.dumps(registry))
        disabled_registry["credentials"][1]["enabled"] = False
        server_cases = (("mtls", registry), ("mtls-disabled", disabled_registry),
                        ("cleartext", registry), ("server-tls", registry))
        for mode, current_registry in server_cases:
            environment = dict(os.environ, MTLS_REGISTRY=json.dumps(current_registry))
            registry_source = root / f"registry-{mode}.rut"
            registry_source.write_text(Path(args.registry_source).read_text())
            gateway_mode = "mtls" if mode.startswith("mtls") else mode
            with registry_gateway(args, registry_source, environment, gateway_mode) as registry_port:
                if mode == "mtls":
                    for context, consumer, group_status in ((contexts[0], b"alice", 204),
                                                             (contexts[1], b"bob", 403)):
                        forged = {"X-Client-Cert-Sha256": "0" * 64,
                                  "X-Consumer-ID": "forged"}
                        assert registry_request(registry_port, "/private", forged, context) == (200, consumer)
                        assert registry_request(registry_port, "/staff", forged, context)[0] == group_status
                        assert h2_request(registry_port, "/private", [
                            ("x-client-cert-sha256", "0" * 64), ("x-consumer-id", "forged")],
                            tls_context=h2_contexts[contexts.index(context)]) == (200, consumer)
                        assert h2_request(registry_port, "/staff", [],
                                          tls_context=h2_contexts[contexts.index(context)])[0] == group_status
                elif mode == "mtls-disabled":
                    assert registry_request(registry_port, "/private", {}, contexts[0]) == (200, b"alice")
                    denied = registry_request(registry_port, "/private", {}, contexts[1])
                    assert denied == (401, b"Unauthorized"), denied
                else:
                    scheme_context = contexts[0] if mode == "server-tls" else None
                    assert registry_request(
                        registry_port, "/private",
                        {"X-Client-Cert-Sha256": pin, "X-Consumer-ID": "alice"},
                        scheme_context) == (401, b"Unauthorized")

        bad_routes = (
            ('consumerAuthenticate("' + pin + '", env("MTLS_REGISTRY"), "mtls")',
             b"Consumer method must be bearer, basic or header"),
            ('consumerAuthenticateMtls(req.uniqueHeader("X-Pin").or(""))',
             b"Consumer registry must be compile-time configuration"),
        )
        for index, (call, diagnostic) in enumerate(bad_routes):
            invalid_source = root / f"invalid-{index}.rut"
            invalid_source.write_text(
                'listen :0\nroute GET "/" { guard let identity = ' + call +
                ' else { return 401 } return 204 }\n')
            result = subprocess.run(
                [args.server, "0", str(invalid_source), "--backend", "epoll", "--no-pin"],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
            assert result.returncode != 0 and diagnostic in result.stdout, result.stdout
    print(f"mTLS Consumer mapping passed: {args.backend}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--registry-source", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=["epoll", "io_uring"], required=True)
    exercise(parser.parse_args())
