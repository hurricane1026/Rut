#!/usr/bin/env python3
"""Verify that a browser sees a clear cookie only after durable logout."""
import argparse
import http.client
import json
import os
from pathlib import Path
import shutil
import ssl
import tempfile
import time

from test_jwt_sessions import KEY, NAMESPACE, Peer, permit_key, signed
from test_mtls_consumers import registry_gateway


CLEAR_COOKIE = "__Host-rut_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
ORIGIN = "https://localhost"


def post(port, context, headers):
    connection = http.client.HTTPSConnection("localhost", port, timeout=5, context=context)
    try:
        connection.putrequest("POST", "/logout")
        for name, value in headers:
            connection.putheader(name, value)
        connection.putheader("Content-Length", "0")
        connection.endheaders()
        response = connection.getresponse()
        response.read()
        return response.status, response.headers
    finally:
        connection.close()


def exercise(args, peer):
    cert = Path(args.testdata).resolve() / "localhost_cert.pem"
    context = ssl.create_default_context(cafile=str(cert))
    endpoint = dict(address="127.0.0.1", port=peer.port, poolIdleMs=5000, tls=True,
                    caFile=str(cert), serverName="localhost")
    environment = dict(os.environ, BROWSER_ORIGIN=ORIGIN, BROWSER_FETCH_SITE="same-origin",
                       JWT_SECRET=KEY, JWT_PREVIOUS_SECRET="", JWT_ISSUER="issuer",
                       JWT_AUDIENCE="gateway", JWT_SESSION_NAMESPACE=NAMESPACE,
                       REDIS_ENDPOINT=json.dumps(endpoint), REDIS_USERNAME="gateway",
                       REDIS_PASSWORD="service-password", REDIS_DATABASE="1")
    now = int(time.time())
    expiry = now + 300
    token = signed(dict(sub="alice", iss="issuer", aud="gateway", iat=now, exp=expiry, jti="browser"))
    key = permit_key(token)
    cookie = ("Cookie", "__Host-rut_session=" + token)
    origin = ("Origin", ORIGIN)
    fetch = ("Sec-Fetch-Site", "same-origin")
    with peer.lock:
        peer.store[key] = b"active"
    with tempfile.TemporaryDirectory(prefix="rut-browser-session-revoke-") as directory:
        root = Path(directory)
        shutil.copytree(args.source.parent / "clients", root / "clients")
        shutil.copytree(args.source.parent / "middleware", root / "middleware")
        source = root / "browser-session-revoke.rut"
        shutil.copyfile(args.source, source)
        with registry_gateway(args, source, environment, "clear") as port:
            with peer.lock:
                calls = peer.accepted
            clear = http.client.HTTPConnection("localhost", port, timeout=5)
            try:
                clear.request("POST", "/logout", headers=dict([origin, fetch, cookie]))
                response = clear.getresponse()
                assert response.status == 503 and response.getheader("Set-Cookie") is None
                response.read()
            finally:
                clear.close()
            with peer.lock:
                assert peer.accepted == calls
        shutil.copyfile(args.source, source)
        with registry_gateway(args, source, environment, "server-tls") as port:
            with peer.lock:
                accepted = peer.accepted
            for headers, status in [
                ([fetch, cookie], 403),
                ([("Origin", "https://other.example"), fetch, cookie], 403),
                ([origin, cookie], 403),
                ([origin, fetch, ("Authorization", "Bearer " + token)], 401),
                ([origin, fetch, ("Cookie", "__Host-rut_session=malformed")], 401),
                ([origin, fetch, cookie, cookie], 401),
            ]:
                actual, response = post(port, context, headers)
                assert actual == status, (actual, status)
                assert response.get_all("Set-Cookie") is None
            with peer.lock:
                assert peer.accepted == accepted and peer.store[key] == b"active"

            for mode in ("aof-timeout", "reset-error", "normal", "normal"):
                with peer.lock:
                    peer.mode = mode
                status, response = post(port, context, [origin, fetch, cookie])
                if mode == "normal":
                    assert status == 204
                    assert response.get_all("Set-Cookie") == [CLEAR_COOKIE]
                    assert response.get("Cache-Control") == "no-store"
                    with peer.lock:
                        assert peer.store[key] == b"revoked"
                        assert peer.expiries[key] == expiry
                else:
                    assert status == 503
                    assert response.get_all("Set-Cookie") is None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    args = parser.parse_args()
    peer = Peer(Path(args.testdata), True)
    try:
        exercise(args, peer)
    finally:
        peer.close()


if __name__ == "__main__":
    main()
