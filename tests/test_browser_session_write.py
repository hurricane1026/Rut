#!/usr/bin/env python3
"""Exercise same-origin browser writes with Redis-backed session permits."""
import argparse
import json
import os
from pathlib import Path
import shutil
import ssl
import tempfile
import time

from auth_h2_fixture import request as h2_request
from test_browser_session_revoke import exchange, ORIGIN
from test_jwt_sessions import KEY, NAMESPACE, Peer, permit_key, signed
from test_mtls_consumers import registry_gateway


def exercise(args, peer, http2):
    cert = Path(args.testdata).resolve() / "localhost_cert.pem"
    context = ssl.create_default_context(cafile=str(cert))
    if http2:
        context.set_alpn_protocols(["h2"])
    endpoint = dict(address="127.0.0.1", port=peer.port, poolIdleMs=5000, tls=True,
                    caFile=str(cert), serverName="localhost")
    env = dict(os.environ, BROWSER_ORIGIN=ORIGIN, BROWSER_FETCH_SITE="same-origin",
               JWT_SECRET=KEY, JWT_PREVIOUS_SECRET="", JWT_ISSUER="issuer",
               JWT_AUDIENCE="gateway", JWT_SESSION_NAMESPACE=NAMESPACE,
               REDIS_ENDPOINT=json.dumps(endpoint), REDIS_USERNAME="gateway",
               REDIS_PASSWORD="service-password", REDIS_DATABASE="1")
    now = int(time.time())
    claims = dict(sub="alice", iss="issuer", aud="gateway", iat=now, exp=now + 300)
    reader = signed(dict(claims, jti="reader", scope="orders:read"))
    writer = signed(dict(claims, jti="writer", scope="orders:read orders:write"))
    read_cookie = ("Cookie", "__Host-rut_session=" + reader)
    write_cookie = ("Cookie", "__Host-rut_session=" + writer)
    origin = ("Origin", ORIGIN)
    fetch = ("Sec-Fetch-Site", "same-origin")
    with peer.lock:
        peer.store[permit_key(reader)] = b"active"
        peer.store[permit_key(writer)] = b"active"
    with tempfile.TemporaryDirectory(prefix="rut-browser-session-write-") as directory:
        root = Path(directory)
        shutil.copytree(args.source.parent / "clients", root / "clients")
        shutil.copytree(args.source.parent / "middleware", root / "middleware")
        source = root / "browser-session-write.rut"
        shutil.copyfile(args.source, source)
        with registry_gateway(args, source, env, "server-tls") as port:
            def check(headers, expected):
                if http2:
                    status, body = h2_request(port, "/private/write", headers, method="POST",
                                              tls_context=context)
                    if status == 204:
                        assert not body
                else:
                    status, response, _ = exchange(port, context, "POST", "/private/write", headers)
                    if status == 204:
                        assert response.get("Cache-Control") == "no-store"
                assert status == expected, (status, expected, http2)

            with peer.lock:
                accepted = peer.accepted
            check([fetch, write_cookie], 403)
            check([origin, ("Sec-Fetch-Site", "cross-site"), write_cookie], 403)
            check([origin, fetch, write_cookie, write_cookie], 401)
            with peer.lock:
                assert peer.accepted == accepted
            check([origin, fetch, read_cookie], 403)
            check([origin, fetch, write_cookie], 204)
            with peer.lock:
                peer.mode = "reset-error"
            check([origin, fetch, write_cookie], 503)
            with peer.lock:
                peer.mode = "normal"
                peer.store[permit_key(writer)] = b"revoked"
            check([origin, fetch, write_cookie], 401)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    args = parser.parse_args()
    for http2 in (False, True):
        peer = Peer(Path(args.testdata), True)
        try:
            exercise(args, peer, http2)
        finally:
            peer.close()


if __name__ == "__main__":
    main()
