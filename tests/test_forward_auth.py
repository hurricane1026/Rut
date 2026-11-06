#!/usr/bin/env python3
"""Native gateway Forward-auth against a local verified TLS authorization service."""
import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    args = parser.parse_args()
    received, forwarded = [], []
    entered, release = threading.Event(), threading.Event()

    class Authorizer(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            credential = self.headers.get("Authorization", "")
            received.append(dict(self.headers))
            if credential in ("Bearer slow", "Bearer abandon"):
                entered.set()
                release.wait(2)
            if credential == "Bearer delayed-body":
                try:
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Consumer-ID: alice\r\n\r\n")
                    entered.set()
                    release.wait(2)
                    self.connection.sendall(b"x")
                except (ConnectionError, ssl.SSLError):
                    pass
                self.close_connection = True
                return
            if credential == "Bearer truncated":
                self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nX-Consumer-ID: alice\r\n\r\nx")
                self.close_connection = True
                return
            status = {"Bearer reject": 401, "Bearer forbidden": 403,
                      "Bearer unavailable": 503, "Bearer redirect": 302}.get(credential, 200)
            try:
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                if credential != "Bearer missing":
                    self.send_header("X-Consumer-ID", "alice")
                if credential == "Bearer duplicate":
                    self.send_header("x-consumer-id", "mallory")
                self.send_header("X-Untrusted", "must-not-copy")
                self.send_header("Set-Cookie", "must-not-copy")
                self.end_headers()
            except (ConnectionError, ssl.SSLError):
                pass

        def log_message(self, *args):
            pass

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            forwarded.append(dict(self.headers))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    auth = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Authorizer)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(Path(args.testdata) / "localhost_cert.pem"),
                        str(Path(args.testdata) / "localhost_key.pem"))
    auth.socket = ctx.wrap_socket(auth.socket, server_side=True)
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    for server in (auth, upstream):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    process = None
    try:
        policy = {"address": "127.0.0.1", "port": auth.server_port, "serverName": "localhost",
                  "caFile": str(Path(args.testdata) / "localhost_cert.pem"),
                  "path": "/authorize", "identityHeader": "X-Consumer-ID"}
        literal = json.dumps(json.dumps(policy))
        source = f'''upstream backend at "127.0.0.1:{upstream.server_port}"
route GET "/private" {{
    let result = forwardAuthHeader("Authorization", {literal}, 400)
    guard result != -2 else {{ return 504 }}
    guard result != -1 else {{ return 503 }}
    guard result != -3 else {{ return 403 }}
    guard result == 1 else {{ return 401 }}
    return forward(backend, load_balance: .roundRobin)
}}
route GET "/health" {{ return 204 }}
'''
        with tempfile.TemporaryDirectory(prefix="rut-forward-auth-") as directory:
            path = Path(directory) / "gateway.rut"
            path.write_text(source)
            process = subprocess.Popen([args.server, "0", str(path), "--backend", args.backend,
                "--shards", "1", "--no-pin", "--drain", "0", "--max-connections-per-shard", "64"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = b""
            deadline = time.monotonic() + 20
            port = None
            while time.monotonic() < deadline:
                ready, _, _ = select.select([process.stdout], [], [], .05)
                if ready:
                    output += os.read(process.stdout.fileno(), 4096)
                    match = re.search(rb"Listening on port ([0-9]+) with", output)
                    if match:
                        port = int(match.group(1))
                        break
                if process.poll() is not None:
                    output += process.communicate()[0]
                    if args.backend == "io_uring" and b"io_uring is unavailable" in output:
                        print("SKIP: kernel does not provide io_uring")
                        return 77
                    raise AssertionError(output.decode(errors="replace"))
            assert port, output
            path.unlink()  # Loaded native code and policy must own all input views.

            def request(credential=None, *, duplicate=False, target="/private?resource=orders"):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                connection.putrequest("GET", target)
                connection.putheader("Connection", "close")
                connection.putheader("X-Consumer-ID", "mallory")
                connection.putheader("x-consumer-id", "eve")
                if credential:
                    connection.putheader("Authorization", credential)
                if duplicate:
                    connection.putheader("authorization", "Bearer attacker")
                connection.endheaders()
                response = connection.getresponse()
                response.read()
                status = response.status
                connection.close()
                return status

            assert request("Bearer allow") == 200
            assert len(forwarded) == 1
            assert forwarded[0].get("X-Consumer-ID") == "alice", forwarded
            assert not any(k.lower() in ("authorization", "x-untrusted", "set-cookie") for k in forwarded[0]), forwarded
            assert received[0]["X-Original-Method"] == "GET", received
            assert received[0]["X-Original-URI"] == "/private?resource=orders", received
            assert not any(k.lower() == "x-consumer-id" for k in received[0]), received
            for credential, status in ((None, 401), ("Bearer reject", 401), ("Bearer forbidden", 403),
                ("Bearer unavailable", 503), ("Bearer redirect", 503), ("Bearer missing", 503),
                ("Bearer duplicate", 503), ("Bearer truncated", 503)):
                assert request(credential) == status, credential
            count = len(received)
            assert request("Bearer allow", duplicate=True) == 401
            assert len(received) == count
            assert len(forwarded) == 1
            assert request("Bearer delayed-body") == 504
            assert len(forwarded) == 1
            assert request("Bearer slow") == 504
            assert entered.is_set()
            assert request(target="/health") == 204  # Pending callouts never block the shard.
            release.set()
            time.sleep(.05)
            assert request("Bearer allow") == 200  # Timed-out slot becomes reusable.
            # Abandon an in-flight request, then reuse connection slots repeatedly.
            release.clear(); entered.clear()
            abandoned = socket.create_connection(("127.0.0.1", port), timeout=2)
            abandoned.sendall(b"GET /private HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer abandon\r\n\r\n")
            assert entered.wait(1)
            abandoned.close()
            release.set()
            for _ in range(12):
                assert request("Bearer allow") == 200
            # Dependency-free HTTP/2 prior-knowledge client: literal HPACK input,
            # and the standard static-table index for the expected HTTP 200.
            def frame(kind, flags, stream, body=b""):
                return len(body).to_bytes(3, "big") + bytes((kind, flags)) + stream.to_bytes(4, "big") + body

            def h2_headers(credential):
                def field(name, value):
                    name, value = name.encode(), value.encode()
                    assert len(name) < 127 and len(value) < 127
                    return b"\0" + bytes((len(name),)) + name + bytes((len(value),)) + value
                return (b"\x82\x86" + field(":path", "/private") + field(":authority", "test") +
                        field("authorization", credential) + field("x-consumer-id", "mallory"))

            def h2_response(connection, stream):
                def read(size):
                    data = b""
                    while len(data) < size:
                        part = connection.recv(size - len(data))
                        assert part, "HTTP/2 connection closed"
                        data += part
                    return data
                status_seen = False
                for _ in range(50):
                    header = read(9)
                    length, kind, flags, sid = int.from_bytes(header[:3], "big"), header[3], header[4], int.from_bytes(header[5:], "big")
                    body = read(length)
                    if kind == 4 and not flags & 1:
                        connection.sendall(frame(4, 1, 0))
                    assert kind != 7, ("GOAWAY", body)
                    if sid != stream:
                        continue
                    assert kind != 3, ("RST_STREAM", body)
                    if kind == 1:
                        assert body and body[0] == 0x88, ("expected HTTP 200", body)
                        status_seen = True
                    if kind in (0, 1) and flags & 1:
                        assert status_seen
                        return
                raise AssertionError("HTTP/2 response did not complete")

            with socket.create_connection(("127.0.0.1", port), timeout=3) as h2:
                h2.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0) + frame(1, 5, 1, h2_headers("Bearer allow")))
                h2_response(h2, 1)
                assert forwarded[-1].get("X-Consumer-ID") == "alice"
                assert not any(k.lower() == "authorization" for k in forwarded[-1])
                release.clear(); entered.clear()
                h2.sendall(frame(1, 5, 3, h2_headers("Bearer abandon")))
                assert entered.wait(1)
                h2.sendall(frame(3, 0, 3, (8).to_bytes(4, "big")))
                release.set()
                h2.sendall(frame(1, 5, 5, h2_headers("Bearer allow")))
                h2_response(h2, 5)
            assert process.poll() is None
            print(f"PASS: forward-auth ({args.backend}) allow/deny/spoofing/framing/timeout/abandon/native ownership")
    finally:
        release.set()
        if process and process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate()
        for server in (auth, upstream):
            server.shutdown(); server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
