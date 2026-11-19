#!/usr/bin/env python3
"""Verify explicit Consumer query redaction at a real forwarding origin."""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from auth_h2_fixture import request as h2_request


def registry_for(raw_key, hashed_key, disabled_key, expired_key, group_key):
    def credential(name, key, **policy):
        record = dict(id=name, consumerId="alice", method="header", secret=key, enabled=True)
        record.update(policy)
        return record

    now = int(time.time())
    hashed = credential("hashed", hashed_key, notBefore=now - 60, expiresAt=now + 600)
    hashed["secretSha256"] = hashlib.sha256(hashed.pop("secret").encode()).hexdigest()
    return dict(
        version=1,
        consumers=[dict(id="alice", enabled=True, groups=["staff"])],
        credentials=[
            credential("raw", raw_key), hashed,
            credential("disabled", disabled_key, enabled=False),
            credential("expired", expired_key, expiresAt=now - 60),
            credential("no-staff", group_key, groups=[]),
        ],
    )


def exercise(port, received, secrets):
    raw, hashed, disabled, expired, no_staff = secrets
    path = "/query/resource%2fentry"
    headers = {
        "X-Unrelated": "preserve-me",
        "X-Consumer-ID": "client-claimed-user",
        "Authorization": f"Bearer {raw}",
        "X-API-Key": raw,
    }
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

    def h1(target, method="GET", body=None, fields=None):
        connection.request(method, target, body, headers if fields is None else fields)
        response = connection.getresponse()
        return response.status, response.read()

    def h2(target, method="GET", body=b"", fields=None):
        return h2_request(port, target, list((headers if fields is None else fields).items()),
                          body, method)

    try:
        assert h1("/projection-check", fields={}) == (204, b"")
        assert h1(f"{path}?api_key={raw}") == (200, b"origin")
        first_socket = connection.sock
        assert first_socket is not None, "the first request closed the downstream connection"
        assert h1(f"{path}?x=one+two&api%5fkey={hashed}&y=%2F") == (200, b"origin")
        assert connection.sock is first_socket, "the second request used a new connection"
        assert h1(f"{path}?z=two&api_key={raw}") == (200, b"origin")
        assert connection.sock is first_socket, "the third request used a new connection"
        assert h2(f"{path}?api_key={hashed}") == (200, b"origin")
        encoded_raw = raw.replace("-", "%2d", 1)
        assert h2(f"{path}?first=%2f&api%5Fkey={encoded_raw}&last=two%20words",
                  method="POST", body=b"unchanged=body") == (200, b"origin")
        prefix = f"{path}?api_key={raw}&item="
        near_limit = "x" * (4096 - len(prefix))
        assert h1(prefix + near_limit) == (200, b"origin")
        assert [row[:3] for row in received] == [
            ("GET", path, b""),
            ("GET", path + "?x=one+two&y=%2F", b""),
            ("GET", path + "?z=two", b""),
            ("GET", path, b""),
            ("POST", path + "?first=%2f&last=two%20words", b"unchanged=body"),
            ("GET", path + "?item=" + near_limit, b""),
        ], received
        for _, _, _, forwarded_headers in received:
            assert forwarded_headers["x-unrelated"] == "preserve-me", forwarded_headers
            assert not {"authorization", "x-api-key", "x-consumer-id"} & forwarded_headers.keys()
        before = len(received)
        denied = [
            path, f"{path}?api_key=", f"{path}?api_key=wrong",
            f"{path}?api_key={disabled}", f"{path}?api_key={expired}",
            f"{path}?api_key={raw}&api%5Fkey={raw}",
            f"{path}?api_key={raw}&x=1&x=2", f"{path}?api_key={raw}&",
            f"{path}?api_key={raw}&x=%gg", prefix + near_limit + "x",
        ]
        for request in (h1, h2):
            for target in denied:
                status, body = request(target)
                assert status == 401, (target, status, body)
                assert not any(key.encode() in body for key in secrets)
            assert request(f"{path}?api_key={no_staff}")[0] == 403
            assert request(path, method="POST", body=f"api_key={raw}".encode(),
                           fields={"Authorization": f"Bearer {raw}", "X-API-Key": raw})[0] == 401
        assert len(received) == before, received
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--backend", required=True, choices=("epoll", "io_uring"))
    parser.add_argument("--opt", required=True, choices=("0", "2"))
    args = parser.parse_args()
    secrets = ("query-raw-fixture-key", "query-hashed-fixture-key", "query-disabled-fixture-key",
               "query-expired-fixture-key", "query-no-staff-fixture-key")
    received = []

    class Origin(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            target = self.requestline.split(" ", 2)[1]
            fields = {name.lower(): value for name, value in self.headers.items()}
            received.append((self.command, target, body, fields))
            self.send_response(200)
            self.send_header("Content-Length", "6")
            self.end_headers()
            self.wfile.write(b"origin")

        do_POST = do_GET

        def log_message(self, *_):
            pass

    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="rut-consumer-query-") as directory:
            root = Path(directory)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            source = root / "gateway.rut"
            middleware = root / "middleware"
            middleware.mkdir()
            module = middleware / "consumer_query.rut"
            module.write_bytes((args.source.parent / "middleware" / module.name).read_bytes())
            access_log = root / "access.log"
            data = args.source.read_text().replace("listen :8080", f"listen :{port}")
            data = data.replace("127.0.0.1:9000", f"127.0.0.1:{origin.server_port}")
            data = data.replace("/tmp/rut-consumer-query-access.log", str(access_log))
            # The original request target is still visible before the forward effect.
            data = data.replace(
                "    return forward(",
                '    guard req.path == incoming && incoming != target else { return 500 }\n'
                '    guard json.get(identity, "/secret") == nil else { return 500 }\n'
                '    guard json.get(identity, "/secretSha256") == nil else { return 500 }\n'
                "    return forward(",
            )
            data += """
route GET "/projection-check" {
    guard let value = json.parse("\\"unused\\"") else { return 500 }
    guard consumer_query.forwardingTarget(req.pathOnly, value) == nil else { return 500 }
    return 204
}
"""
            source.write_text(data)
            log = root / "gateway.log"
            with log.open("w") as output:
                process = subprocess.Popen(
                    [args.server, str(source), "--backend", args.backend, "--opt", args.opt,
                     "--no-pin", "--shards", "2", "--drain", "0"],
                    env=dict(os.environ, AUTH_REGISTRY=json.dumps(registry_for(*secrets))),
                    stdout=output, stderr=subprocess.STDOUT,
                )
            try:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        data = log.read_text()
                        if args.backend == "io_uring" and "io_uring is unavailable" in data:
                            raise SystemExit(77)
                        raise AssertionError(data)
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, log.read_text()
                        time.sleep(.025)
                source.unlink()
                module.unlink()
                exercise(port, received, secrets)
                assert not any(key in repr(received) for key in secrets)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                assert not any(key in log.read_text() for key in secrets), log.read_text()
            lines = access_log.read_text().splitlines()
            assert len(lines) >= len(received) and all(line.isdecimal() for line in lines), lines
    finally:
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=5)
    print(f"PASS: {args.backend} O{args.opt} Consumer query credentials hidden in H1/H2 forwarding")


if __name__ == "__main__":
    main()
