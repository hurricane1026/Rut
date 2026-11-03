#!/usr/bin/env python3
"""Real gateway/native-artifact and local authenticated HTTPS JWKS regression."""
import argparse
import http.server
import json
import pathlib
import os
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
    parser.add_argument("--helper", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    args = parser.parse_args()
    fixture = json.loads(subprocess.check_output([args.helper, "--fixture"], timeout=10))
    lock = threading.Lock()
    state = {"body": json.dumps(fixture["first"]["jwks"]).encode(), "status": 200, "requests": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path != "/keys":
                self.send_error(404)
                return
            with lock:
                state["requests"] += 1
                status, body = state["status"], state["body"]
            self.send_response(status)
            self.send_header("Content-Type", "application/jwk-set+json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *unused):
            pass

    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pathlib.Path(args.testdata) / "localhost_cert.pem"),
                            str(pathlib.Path(args.testdata) / "localhost_key.pem"))
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    process = None
    try:
        policy = fixture["first"]
        policy["remoteJwks"] = {"address": "127.0.0.1", "port": origin.server_port,
                                "serverName": "localhost", "path": "/keys",
                                "ca": str(pathlib.Path(args.testdata) / "localhost_cert.pem"),
                                "refreshSeconds": 1, "maxAgeSeconds": 3, "timeoutSeconds": 1}
        literal = json.dumps(json.dumps(policy, separators=(",", ":")))
        source = ('import Crypto\nroute GET "/" { guard let claims = Crypto.jwtRs256('
                  'bearerToken(req.authorization.or("")).or(""), ' + literal +
                  ') else { return 401 } return 200 }\n')
        with tempfile.TemporaryDirectory(prefix="rut-remote-jwks-") as directory:
            source_path = pathlib.Path(directory) / "gateway.rut"
            source_path.write_text(source)
            process = subprocess.Popen([args.server, "0", str(source_path), "--backend",
                                        args.backend, "--shards", "1", "--no-pin", "--drain", "0",
                                        "--max-connections-per-shard", "64"],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            # Let the gateway retain a kernel-assigned port through bind/listen;
            # a bind/release reservation races other parallel integration tests.
            startup = b""
            deadline = time.monotonic() + 12
            port = None
            while time.monotonic() < deadline:
                readable, _, _ = select.select([process.stdout], [], [], 0.05)
                if readable:
                    startup += os.read(process.stdout.fileno(), 4096)
                    match = re.search(rb"Listening on port ([0-9]+) with", startup)
                    if match:
                        port = int(match.group(1))
                        break
                if process.poll() is not None:
                    startup += process.communicate()[0]
                    output = startup.decode(errors="replace")
                    if args.backend == "io_uring" and "io_uring is unavailable" in output:
                        print("SKIP: kernel does not provide io_uring")
                        raise SystemExit(77)
                    raise AssertionError(f"gateway exited during startup: {output}")
            assert port is not None, f"gateway did not listen: {startup!r}"

            def request(token):
                if process.poll() is not None:
                    output = process.communicate()[0].decode(errors="replace")
                    if args.backend == "io_uring" and "io_uring is unavailable" in output:
                        print("SKIP: kernel does not provide io_uring")
                        raise SystemExit(77)
                    raise AssertionError(f"gateway exited: {output}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
                        connection.sendall(("GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n"
                                            "Authorization: Bearer " + token + "\r\n\r\n").encode())
                        data = connection.recv(4096)
                        return int(data.split(b" ", 2)[1])
                except (ConnectionError, TimeoutError):
                    return None

            def wait_status(token, expected, limit=12):
                deadline = time.monotonic() + limit
                while time.monotonic() < deadline:
                    status = request(token)
                    if status == expected:
                        return
                    assert status in (None, 200, 401), f"unexpected HTTP status: {status}"
                    time.sleep(0.025)
                raise AssertionError(f"expected status {expected}, last status {status}")

            def publish(body, status=200):
                with lock:
                    state.update(body=body, status=status)

            def wait_for_origin_request(previous, limit=4):
                deadline = time.monotonic() + limit
                while time.monotonic() < deadline:
                    with lock:
                        if state["requests"] > previous:
                            return
                    time.sleep(0.01)
                raise AssertionError("idle shard did not start the scheduled JWKS refresh")

            wait_status(fixture["a"], 200)
            assert request(fixture["b"]) == 401
            with lock:
                requests_before_refresh = state["requests"]
            publish(json.dumps(fixture["second"]["jwks"]).encode())
            # No gateway request is made while the one-second refresh becomes
            # due or while its TLS handshake/read advances on the idle shard.
            wait_for_origin_request(requests_before_refresh)
            time.sleep(0.1)
            assert request(fixture["b"]) == 200, "idle refresh did not install the rotated key"
            assert request(fixture["a"]) == 401, "replaced key still authenticates"
            publish(b'{"keys":[]}')
            wait_status(fixture["b"], 401)
            publish(json.dumps(fixture["second"]["jwks"]).encode())
            wait_status(fixture["b"], 200)
            publish(b"unavailable", 503)
            assert request(fixture["b"]) == 200, "fresh cache was discarded on outage"
            wait_status(fixture["b"], 401)
            publish(json.dumps(fixture["second"]["jwks"]).encode())
            wait_status(fixture["b"], 200)
            publish(b"{bad")
            wait_status(fixture["b"], 401)
            process.terminate()
            output = process.communicate(timeout=5)[0].decode(errors="replace")
            assert process.returncode == 0, output
            print(f"PASS: {args.backend} remote JWKS rotation, empty set, outage, malformed refresh and shutdown")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    main()
