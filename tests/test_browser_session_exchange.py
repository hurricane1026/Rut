#!/usr/bin/env python3
"""Exercise exchange, authorization and durable logout on one HTTPS origin."""
import argparse
import http.client
import json
import os
from pathlib import Path
import shutil
import ssl
import tempfile
import time

from auth_h2_fixture import request as h2_request
from test_browser_session_revoke import CLEAR_COOKIE, ORIGIN, exchange
from test_jwt_sessions import KEY, NAMESPACE, Peer, permit_key, signed
from test_mtls_consumers import registry_gateway


def exercise(args, peer):
    cert = Path(args.testdata).resolve() / "localhost_cert.pem"
    context = ssl.create_default_context(cafile=str(cert))
    h2_context = ssl.create_default_context(cafile=str(cert))
    h2_context.set_alpn_protocols(["h2"])
    endpoint = dict(address="127.0.0.1", port=peer.port, poolIdleMs=5000, tls=True,
                    caFile=str(cert), serverName="localhost")
    environment = dict(os.environ, BROWSER_ORIGIN=ORIGIN, JWT_SECRET=KEY,
                       JWT_PREVIOUS_SECRET="", JWT_ISSUER="issuer", JWT_AUDIENCE="gateway",
                       JWT_SESSION_NAMESPACE=NAMESPACE, REDIS_ENDPOINT=json.dumps(endpoint),
                       REDIS_USERNAME="gateway", REDIS_PASSWORD="service-password",
                       REDIS_DATABASE="1")
    now = int(time.time())
    claims = dict(sub="alice", iss="issuer", aud="gateway", iat=now - 60, exp=now + 300,
                  jti="browser-exchange", scope="orders:read orders:write")
    token = signed(claims)
    different = signed(dict(claims, nonce="different"))
    expired = signed(dict(claims, exp=now - 1))
    key = permit_key(token)
    with peer.lock:
        peer.store[key] = b"active"
        peer.store[permit_key(expired)] = b"active"
    origin = ("Origin", ORIGIN)
    fetch = ("Sec-Fetch-Site", "same-origin")
    bearer = ("Authorization", "Bearer " + token)
    expected_cookie = ("__Host-rut_session=" + token
                       + "; Path=/; Secure; HttpOnly; SameSite=Strict")
    path = "/session/cookie"

    with tempfile.TemporaryDirectory(prefix="rut-browser-session-exchange-") as directory:
        root = Path(directory)
        shutil.copytree(args.source.parent / "clients", root / "clients")
        shutil.copytree(args.source.parent / "middleware", root / "middleware")
        source = root / "browser-session-exchange.rut"
        shutil.copyfile(args.source, source)
        with registry_gateway(args, source, environment, "clear") as port:
            clear = http.client.HTTPConnection("localhost", port, timeout=5)
            try:
                for method, route in (("POST", path), ("GET", "/private"),
                                      ("POST", "/private/write"), ("POST", "/logout")):
                    headers = [origin, fetch, bearer, ("Cookie", "__Host-rut_session=" + token)]
                    clear.request(method, route, headers=dict(headers))
                    response = clear.getresponse()
                    assert response.status == (503 if method == "GET" else 403)
                    assert response.getheader("Set-Cookie") is None
                    response.read()
            finally:
                clear.close()

        shutil.copyfile(args.source, source)
        with registry_gateway(args, source, environment, "server-tls") as port:
            def check(headers, expected):
                status, response, body = exchange(port, context, "POST", path, headers)
                assert status == expected, (status, expected)
                assert token.encode() not in body and response.get("Authorization") is None
                if status == 204:
                    assert response.get_all("Set-Cookie") == [expected_cookie]
                    assert response.get("Cache-Control") == "no-store" and body == b""
                else:
                    assert response.get_all("Set-Cookie") is None
                return response

            with peer.lock:
                assert not peer.commands
            check([fetch, bearer], 403)
            check([origin, origin, fetch, bearer], 403)
            check([origin, ("Sec-Fetch-Site", "cross-site"), bearer], 403)
            check([origin, fetch, bearer, bearer], 401)
            status, _ = h2_request(port, path, [origin, fetch, bearer, bearer], method="POST",
                                   tls_context=h2_context)
            assert status == 401
            check([origin, fetch, ("Cookie", "__Host-rut_session=" + token)], 401)
            check([origin, fetch, ("Authorization", "Bearer " + expired)], 401)
            with peer.lock:
                assert not peer.commands
            check([origin, fetch, ("Authorization", "Bearer " + different)], 401)
            response = check([origin, fetch, bearer], 204)
            cookie = ("Cookie", response["Set-Cookie"].split(";", 1)[0])
            assert h2_request(port, path, [origin, fetch, bearer], method="POST",
                              tls_context=h2_context) == (204, b"")
            with peer.lock:
                peer.mode = "reset-error"
            check([origin, fetch, bearer], 503)
            with peer.lock:
                peer.mode = "normal"
                assert all(command[0] in (b"AUTH", b"SELECT", b"GET", b"RESET")
                           for command in peer.commands)
                reader = signed(dict(claims, scope="orders:read"))
                reader_key = permit_key(reader)
                peer.store[reader_key] = b"active"
            status, response, body = exchange(port, context, "POST", path, [
                origin, fetch, ("Authorization", "Bearer " + reader)])
            assert status == 204 and body == b""
            reader_cookie = ("Cookie", response["Set-Cookie"].split(";", 1)[0])

            status, response, body = exchange(port, context, "GET", "/private", [cookie])
            assert status == 200 and body == b"alice"
            assert response.get("Cache-Control") == "no-store"
            assert h2_request(port, "/private", [reader_cookie], tls_context=h2_context) == (
                200, b"alice")
            assert h2_request(port, "/private/write", [origin, fetch, cookie], method="POST",
                              tls_context=h2_context) == (204, b"")
            status, _ = h2_request(port, "/private/write", [origin, fetch, reader_cookie],
                                   method="POST", tls_context=h2_context)
            assert status == 403
            status, _, _ = exchange(port, context, "POST", "/private/write",
                                     [origin, fetch, bearer])
            assert status == 401

            with peer.lock:
                previous_commands = len(peer.commands)
            status, response, _ = exchange(port, context, "POST", "/logout", [
                origin, ("Sec-Fetch-Site", "cross-site"), cookie])
            assert status == 403 and response.get_all("Set-Cookie") is None
            with peer.lock:
                assert len(peer.commands) == previous_commands and peer.store[key] == b"active"
                peer.mode = "aof-timeout"
            status, response, _ = exchange(port, context, "POST", "/logout",
                                           [origin, fetch, cookie])
            assert status == 503 and response.get_all("Set-Cookie") is None
            with peer.lock:
                peer.mode = "normal"
            status, response, body = exchange(port, context, "POST", "/logout",
                                              [origin, fetch, cookie])
            assert status == 204 and body == b""
            assert response.get("Cache-Control") == "no-store"
            assert response.get_all("Set-Cookie") == [CLEAR_COOKIE]
            with peer.lock:
                assert peer.store[key] == b"revoked" and peer.expiries[key] == claims["exp"]
                assert peer.store[reader_key] == b"active"
            for method, route, headers in (("GET", "/private", [cookie]),
                                           ("POST", "/private/write", [origin, fetch, cookie])):
                status, body = h2_request(port, route, headers, method=method,
                                          tls_context=h2_context)
                assert status == 401 and b"alice" not in body
            assert h2_request(port, "/private", [reader_cookie], tls_context=h2_context) == (
                200, b"alice")
            check([origin, fetch, bearer], 401)
            status, _ = h2_request(port, path, [origin, fetch, bearer], method="POST",
                                   tls_context=h2_context)
            assert status == 401


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", type=Path, required=True)
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
