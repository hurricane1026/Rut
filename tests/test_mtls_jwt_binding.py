#!/usr/bin/env python3
"""Independent JWT oracle and TLS certificates for RFC 8705 resource binding."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time


KEY = b"mtls-bound-jwt-test-secret-abcdefghijklmnopqrstuvwxyz"


def encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def token(confirmation, **updates):
    claims = dict(sub="alice", iss="issuer", aud="reports", exp=int(time.time()) + 3600,
                  scope="reports:read", cnf=confirmation)
    claims.update(updates)
    header = encode(b'{"alg":"HS256","typ":"JWT"}')
    payload = encode(json.dumps(claims, separators=(",", ":")).encode())
    message = (header + "." + payload).encode()
    return message.decode() + "." + encode(hmac.digest(KEY, message, "sha256"))


def exercise(args):
    fixtures = Path(args.testdata)
    certs = [fixtures / "localhost_cert.pem", fixtures / "mtls_second_cert.pem"]
    key = fixtures / "localhost_key.pem"
    digests = [hashlib.sha256(ssl.PEM_cert_to_DER_cert(c.read_text())).digest() for c in certs]
    assert digests[0] != digests[1]
    thumbprints = [encode(d) for d in digests]
    valid = [token({"x5t#S256": t}, sub=subject)
             for t, subject in zip(thumbprints, ("alice", "bob"))]

    def context(index=0, certificate=True):
        value = ssl.create_default_context(cafile=str(certs[0]))
        if certificate:
            value.load_cert_chain(str(certs[index]), str(key))
        return value

    original = Path(__file__).resolve().parent.parent / "examples"
    for mode in ("mtls", "tls", "cleartext"):
        with tempfile.TemporaryDirectory(prefix="rut-mtls-jwt-") as directory:
            root = Path(directory)
            source = root / "gateway.rut"
            module = root / "middleware/auth.rut"
            module.parent.mkdir()
            module.write_bytes((original / "middleware/auth.rut").read_bytes())
            binding_module = root / "middleware/jwt_binding.rut"
            binding_module.write_bytes((original / "middleware/jwt_binding.rut").read_bytes())
            source.write_text((original / "mtls-bound-jwt.rut").read_text() +
                              '\nroute GET "/ready" { return 204 }\n')
            ca = root / "clients.pem"
            ca.write_text("".join(c.read_text() for c in certs))
            command = [args.server, "0", str(source), "--backend", args.backend,
                       "--shards", "2", "--no-pin", "--drain", "0"]
            if mode != "cleartext":
                command += ["--h2", "--tls-cert", str(certs[0]), "--tls-key", str(key)]
            if mode == "mtls":
                command += ["--tls-client-ca", str(ca)]
            env = dict(os.environ, JWT_BINDING_KEY=KEY.decode(), JWT_BINDING_ISSUER="issuer",
                       JWT_BINDING_AUDIENCE="reports")
            log = root / "gateway.log"
            with log.open("wb") as output:
                process = subprocess.Popen(command, env=env, stdout=output, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 30
                    port = None
                    while time.monotonic() < deadline:
                        startup = log.read_bytes()
                        match = re.search(rb"Listening on port ([0-9]+) with", startup)
                        if match:
                            port = int(match[1])
                            break
                        if process.poll() is not None:
                            if args.backend == "io_uring" and b"io_uring is unavailable" in startup:
                                return 77
                            raise AssertionError(startup.decode(errors="replace"))
                        time.sleep(.02)
                    assert port, log.read_text(errors="replace")

                    def request(value, index=0, path="/private", client_context=None):
                        if mode == "cleartext":
                            connection = http.client.HTTPConnection("localhost", port, timeout=5)
                        else:
                            connection = http.client.HTTPSConnection(
                                "localhost", port, timeout=5,
                                context=client_context if client_context is not None else context(index))
                        try:
                            connection.request("GET", path, headers={
                                "Authorization": "Bearer " + value,
                                "X-Client-Cert-Sha256": digests[0].hex(),
                                "X-Forwarded-Client-Cert": thumbprints[0], "X-Consumer-ID": "forged"})
                            response = connection.getresponse()
                            return response.status, dict(response.headers), response.read()
                        finally:
                            connection.close()

                    assert request(valid[0], path="/ready")[0] == 204
                    source.unlink()
                    module.unlink()
                    binding_module.unlink()  # Artifact must own both policy and code.
                    if mode != "mtls":
                        status, headers, _ = request(valid[0])
                        assert status == 401, (mode, status)
                        assert 'invalid_token' in headers.get("WWW-Authenticate", "")
                        continue

                    for i in range(2):
                        status, _, body = request(valid[i], i)
                        assert (status, body) == (200, (b"alice", b"bob")[i])
                        status, headers, body = request(valid[1 - i], i)
                        assert status == 401, (i, status, body)
                        assert 'invalid_token' in headers.get("WWW-Authenticate", "")
                    with socket.create_connection(("localhost", port), timeout=5) as raw:
                        with context().wrap_socket(raw, server_hostname="localhost") as sock:
                            wire = ("GET /private HTTP/1.1\r\nHost: localhost\r\n"
                                    f"Authorization: Bearer {valid[0]}\r\n"
                                    f"Authorization: Bearer {valid[0]}\r\n\r\n").encode()
                            sock.sendall(wire)
                            assert b" 401 " in sock.recv(4096)
                    # A fresh H2 connection makes its first response status independent
                    # of dynamic HPACK entries. Test both accepted and stolen tokens.
                    def h2_request(value):
                        def integer(value, prefix, top=0):
                            maximum = (1 << prefix) - 1
                            if value < maximum:
                                return bytes((top | value,))
                            data = bytearray((top | maximum,))
                            value -= maximum
                            while value >= 128:
                                data.append((value & 127) | 128)
                                value >>= 7
                            data.append(value)
                            return bytes(data)

                        def string(value):
                            return integer(len(value), 7) + value

                        def frame(kind, flags, stream, payload=b""):
                            return (len(payload).to_bytes(3, "big") + bytes((kind, flags)) +
                                    stream.to_bytes(4, "big") + payload)

                        tls = context()
                        tls.set_alpn_protocols(["h2"])
                        with socket.create_connection(("localhost", port), timeout=5) as raw:
                            with tls.wrap_socket(raw, server_hostname="localhost") as sock:
                                assert sock.selected_alpn_protocol() == "h2"
                                block = (b"\x82\x87\x04" + string(b"/private") + b"\x01" +
                                         string(b"localhost") + b"\x0f\x08" +
                                         string(("Bearer " + value).encode()))
                                sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" +
                                             frame(4, 0, 0) + frame(1, 5, 1, block))

                                def exact(length):
                                    data = b""
                                    while len(data) < length:
                                        part = sock.recv(length - len(data))
                                        assert part, "H2 closed before response completion"
                                        data += part
                                    return data

                                status, body = None, b""
                                while True:
                                    header = exact(9)
                                    payload = exact(int.from_bytes(header[:3], "big"))
                                    kind, flags = header[3], header[4]
                                    stream = int.from_bytes(header[5:], "big") & 0x7fffffff
                                    if kind == 4 and not flags & 1:
                                        sock.sendall(frame(4, 1, 0))
                                    assert kind != 7, payload
                                    if stream != 1:
                                        continue
                                    assert kind != 3, payload
                                    if kind == 1:
                                        # :status 200 is static index 8; 401 is a literal
                                        # indexed-name 8, encoded raw or RFC 7541 Huffman.
                                        if payload.startswith(b"\x88"):
                                            status = 200
                                        elif payload.startswith((b"\x48\x82\x68\x01",
                                                                 b"\x48\x03" + b"401")):
                                            status = 401
                                        else:
                                            raise AssertionError(("unexpected H2 status", payload))
                                    if kind == 0:
                                        body += payload
                                    if kind in (0, 1) and flags & 1:
                                        return status, body

                    assert h2_request(valid[0]) == (200, b"alice")
                    assert h2_request(valid[1])[0] == 401
                    denied = [
                        token(None), token({}), token({"jkt": thumbprints[0]}),
                        token({"x5t#S256": thumbprints[0] + "="}),
                        token({"x5t#S256": thumbprints[0][:-1]}),
                        token({"x5t#S256": [thumbprints[0]]}),
                        token({"x5t#S256": thumbprints[0], "jkt": "other"}),
                        token({"x5t#S256": thumbprints[0]}, exp=int(time.time()) - 1),
                        token({"x5t#S256": thumbprints[0]}, iss="other"),
                        token({"x5t#S256": thumbprints[0]}, aud="other"),
                    ]
                    # Keep the valid binding, but replace the signature with an invalid MAC.
                    denied.append(valid[0].rsplit(".", 1)[0] + "." + encode(b"\x00" * 32))
                    for value in denied:
                        status, headers, body = request(value)
                        assert status == 401, (status, body)
                        assert "Bearer" in headers.get("WWW-Authenticate", "")
                    status, headers, _ = request(token({"x5t#S256": thumbprints[0]}, scope="other"))
                    assert status == 403
                    assert "insufficient_scope" in headers.get("WWW-Authenticate", "")
                    try:
                        request(valid[0], client_context=context(certificate=False))
                    except (ssl.SSLError, ConnectionResetError, BrokenPipeError,
                            http.client.RemoteDisconnected):
                        pass
                    else:
                        raise AssertionError("mTLS accepted an absent client certificate")
                    with ThreadPoolExecutor(max_workers=4) as workers:
                        results = list(workers.map(lambda i: request(valid[i % 2], (i // 2) % 2), range(8)))
                    for i, (status, _, body) in enumerate(results):
                        expected = 200 if i % 2 == (i // 2) % 2 else 401
                        assert status == expected, (i, status, body)
                        if expected == 200:
                            assert body == (b"alice", b"bob")[i % 2]
                    assert KEY not in log.read_bytes()
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise AssertionError("mTLS JWT gateway shutdown timed out")
                    assert process.returncode in (0, 77), log.read_text(errors="replace")
    print(f"PASS: {args.backend} certificate-bound JWT, mismatched certificates, claims, scopes, isolation and spoof rejection")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    raise SystemExit(exercise(parser.parse_args()))
