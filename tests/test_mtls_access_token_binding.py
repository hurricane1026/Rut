#!/usr/bin/env python3
"""Native RS256/ES256 access-token profile bound to verified client TLS identity."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from auth_h2_fixture import request as h2_request
from test_jwt_access_profile import es256_signer
from test_keycloak_roles import MODULUS, signed as rsa_signed

ISSUER = "https://access.example/issuer"
AUDIENCE = "orders-api"
CLIENT_ID = "orders-web"
SCOPE = "orders:read"


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@contextmanager
def gateway(args, policy, mode):
    certs = [Path(args.testdata) / "localhost_cert.pem",
             Path(args.testdata) / "mtls_second_cert.pem"]
    key = Path(args.testdata) / "localhost_key.pem"
    ders = [ssl.PEM_cert_to_DER_cert(cert.read_text()) for cert in certs]
    pins = [hashlib.sha256(der).digest() for der in ders]
    thumbprints = [b64url(pin) for pin in pins]
    assert ders[0] != ders[1] and pins[0] != pins[1]
    # Both distinct DER certificates are issued for the same private key.
    for cert in certs:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(str(cert), str(key))

    with tempfile.TemporaryDirectory(prefix="rut-mtls-access-bound-") as tmp:
        root = Path(tmp)
        middleware = root / "middleware"
        middleware.mkdir()
        source_path = Path(args.source).resolve()
        shutil.copyfile(source_path.parent / "middleware/jwt_access.rut",
                        middleware / "jwt_access.rut")
        shutil.copyfile(Path(__file__).resolve().parent.parent /
                        "examples/middleware/jwt_binding.rut",
                        middleware / "jwt_binding.rut")
        ca = root / "client-ca.pem"
        ca.write_text("".join(cert.read_text() for cert in certs))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        source = root / "gateway.rut"
        source.write_text(source_path.read_text())
        command = [args.server, str(port), str(source), "--backend", args.backend,
                   "--opt", str(args.opt), "--no-pin", "--shards", "2", "--drain", "0"]
        if mode != "cleartext":
            command += ["--h2", "--tls-cert", str(certs[0]), "--tls-key", str(key)]
        if mode == "mtls":
            command += ["--tls-client-ca", str(ca)]
        env = dict(os.environ, JWT_ACCESS_CLIENT_ID=CLIENT_ID,
                   JWT_ACCESS_REQUIRED_SCOPE=SCOPE)
        env[f"JWT_ACCESS_{args.algorithm.upper()}_POLICY"] = json.dumps(policy)
        log = root / "gateway.log"
        unavailable = False
        with log.open("wb") as output:
            process = subprocess.Popen(command, env=env, stdout=output,
                                       stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while True:
                if process.poll() is not None:
                    startup = log.read_bytes()
                    io_uring_unavailable = (
                        args.backend == "io_uring" and
                        b"--backend io_uring requested, but io_uring is unavailable\n" in startup)
                    if io_uring_unavailable:
                        unavailable = True
                        raise SystemExit(77)
                    raise AssertionError(startup.decode(errors="replace"))
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, log.read_text(errors="replace")
                    time.sleep(.02)
            source.unlink()
            shutil.rmtree(middleware)

            def context(index=0, client_certificate=True, use_h2=False):
                value = ssl.create_default_context(cafile=str(certs[0]))
                if use_h2:
                    value.set_alpn_protocols(["h2"])
                if client_certificate:
                    value.load_cert_chain(str(certs[index]), str(key))
                return value

            def get(path, token=None, index=0, version="HTTP/1.1",
                    client_certificate=True, duplicate=False):
                fields = [("X-Client-Cert-Sha256", pins[0].hex()),
                          ("X-Forwarded-Client-Cert", thumbprints[0]),
                          ("X-Consumer-ID", "forged")]
                if token is not None:
                    fields.extend([("Authorization", "Bearer " + token)] * (2 if duplicate else 1))
                if version == "h2":
                    tls_context = context(index, client_certificate, use_h2=True) if mode != "cleartext" else None
                    status, body = h2_request(port, path, fields, tls_context=tls_context)
                    return status, {}, body
                if mode == "cleartext":
                    connection = http.client.HTTPConnection("localhost", port, timeout=5)
                else:
                    connection = http.client.HTTPSConnection(
                        "localhost", port, timeout=5,
                        context=context(index, client_certificate))
                connection._http_vsn = 10 if version == "HTTP/1.0" else 11
                connection._http_vsn_str = version
                try:
                    connection.putrequest("GET", path, skip_accept_encoding=True)
                    for name, value in fields:
                        connection.putheader(name, value)
                    connection.endheaders()
                    response = connection.getresponse()
                    return response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
                finally:
                    connection.close()

            yield port, get, context, thumbprints
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("mTLS access gateway shutdown timed out")
            if unavailable:
                assert process.returncode == 1, log.read_text(errors="replace")
            else:
                assert process.returncode == 0, (process.returncode,
                                                 log.read_text(errors="replace"))


def exercise(args, policy, signer, opposite_signer=None):
    typ = "at+jwt" if args.opt == 0 else "application/at+jwt"
    policy["requiredType"] = typ
    now = int(time.time())
    base = dict(sub="alice", iss=ISSUER, aud=AUDIENCE, iat=now, exp=now + 600,
                client_id=CLIENT_ID, jti="cert-bound-1", scope=SCOPE)

    def token(claims, header=None):
        header = header or dict(alg=args.algorithm.upper(), kid="current", typ=typ)
        payload = json.dumps(claims, separators=(",", ":"))
        return rsa_signed(payload, header) if signer is None else signer(header, payload)

    cross_claims = dict(base, cnf={"x5t#S256": ""})

    with gateway(args, policy, "mtls") as (_, get, _, thumbprints):
        good = [token(dict(base, cnf={"x5t#S256": thumbprints[i]})) for i in range(2)]
        cross_claims["cnf"]["x5t#S256"] = thumbprints[0]
        cross_header = dict(alg="ES256" if args.algorithm == "rs256" else "RS256",
                            kid="current", typ=typ)
        cross_payload = json.dumps(cross_claims, separators=(",", ":"))
        cross_token = (opposite_signer(cross_header, cross_payload)
                       if opposite_signer is not None else rsa_signed(cross_payload, cross_header))
        for version in ("HTTP/1.0", "HTTP/1.1", "h2"):
            assert get("/read", cross_token, 0, version)[0] == 401
            for cert_index in (0, 1):
                status, _, _ = get("/access", good[cert_index], cert_index, version)
                assert status == 204, (version, cert_index, status)
                status, _, body = get("/read", good[cert_index], cert_index, version)
                assert (status, body) == (200, b"alice"), (version, cert_index, status, body)
                # Exercise both mismatch directions: A-token/B-cert and B-token/A-cert.
                status, headers, _ = get("/read", good[1 - cert_index], cert_index, version)
                assert status == 401, (version, cert_index, status)
                if version != "h2":
                    assert "invalid_token" in headers.get("www-authenticate", "")
                wrong_scope_and_cert = token(dict(base, scope="orders:write",
                    cnf={"x5t#S256": thumbprints[1 - cert_index]}))
                assert get("/read", wrong_scope_and_cert, cert_index, version)[0] == 401
                wrong_client_and_cert = token(dict(base, client_id="other",
                    cnf={"x5t#S256": thumbprints[1 - cert_index]}))
                assert get("/read", wrong_client_and_cert, cert_index, version)[0] == 401

            bad_claims = [
                dict(base), dict(base, cnf={}), dict(base, cnf=None),
                dict(base, cnf={"jkt": thumbprints[0]}),
                dict(base, cnf={"x5t#S256": thumbprints[0] + "="}),
                dict(base, cnf={"x5t#S256": thumbprints[0][:-1]}),
                dict(base, cnf={"x5t#S256": [thumbprints[0]]}),
                dict(base, cnf={"x5t#S256": thumbprints[0], "jkt": "other"}),
                dict(base, cnf={"x5t#S256": thumbprints[0]}, client_id="other"),
                dict(base, cnf={"x5t#S256": thumbprints[0]}, scope="orders:write"),
                dict(base, cnf={"x5t#S256": thumbprints[0]}, iat=now + 500),
                dict(base, cnf={"x5t#S256": thumbprints[0]}, exp=now - 1),
                {k: v for k, v in dict(base, cnf={"x5t#S256": thumbprints[0]}).items()
                 if k != "client_id"},
                {k: v for k, v in dict(base, cnf={"x5t#S256": thumbprints[0]}).items()
                 if k != "jti"},
                {k: v for k, v in dict(base, cnf={"x5t#S256": thumbprints[0]}).items()
                 if k != "iat"},
            ]
            for claims in bad_claims:
                status, headers, _ = get("/read", token(claims), 0, version)
                expected = 403 if claims.get("client_id") == "other" or claims.get("scope") == "orders:write" else 401
                assert status == expected, (version, claims, status, expected)
                if claims.get("scope") == "orders:write" and version != "h2":
                    assert "insufficient_scope" in headers.get("www-authenticate", "")
            for header in (dict(alg=args.algorithm.upper(), kid="current", typ="JWT"),
                           dict(alg="HS256", kid="current", typ=typ)):
                assert get("/read", token(dict(base, cnf={"x5t#S256": thumbprints[0]}), header),
                           0, version)[0] == 401
            good_signature = good[0]
            corrupt = good_signature[:-4] + ("AAAA" if not good_signature.endswith("AAAA") else "BBBB")
            assert get("/read", corrupt, 0, version)[0] == 401
            assert get("/read", good[0], 0, version, duplicate=True)[0] == 401
            status, headers, _ = get("/read", None, 0, version)
            assert status == 401
            if version != "h2":
                assert "invalid_token" in headers.get("www-authenticate", "")

        # Mandatory client CA rejects a TLS client with no certificate.
        try:
            get("/read", good[0], 0, "HTTP/1.1", client_certificate=False)
        except (ssl.SSLError, ConnectionError, OSError, http.client.HTTPException):
            pass
        else:
            raise AssertionError("mandatory client CA accepted a missing certificate")

    # Ordinary TLS and cleartext cannot acquire client identity through spoof headers.
    for mode in ("tls", "cleartext"):
        with gateway(args, policy, mode) as (_, get, _, _):
            status, _, _ = get("/read", good[0], 0, "HTTP/1.1")
            assert status == 401, (mode, status)


def main(args):
    if args.algorithm == "rs256":
        policy = dict(issuer=ISSUER, audience=AUDIENCE, kids=["current"],
                      jwks=dict(keys=[dict(kid="current", kty="RSA", alg="RS256",
                                           n=MODULUS, e="AQAB")]))
        with es256_signer(args.signer) as (_, opposite_signer):
            exercise(args, policy, None, opposite_signer)
    else:
        with es256_signer(args.signer) as (policy, signer):
            policy.update(issuer=ISSUER, audience=AUDIENCE)
            exercise(args, policy, signer)
    print(f"PASS: {args.algorithm} mTLS access binding ({args.backend}, O{args.opt})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    parser.add_argument("--opt", type=int, choices=(0, 2), required=True)
    parser.add_argument("--algorithm", choices=("rs256", "es256"), required=True)
    parser.add_argument("--signer")
    args = parser.parse_args()
    if not args.signer:
        parser.error("the ES256 test signer is required for cross-algorithm coverage")
    main(args)
