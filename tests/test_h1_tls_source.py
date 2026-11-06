#!/usr/bin/env python3
"""Verify source forward lowering and keep-alive against an HTTPS origin."""
import argparse
import http.client
import http.server
import json
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import threading
import time


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.reply()

    def do_POST(self):
        self.reply()

    def reply(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        result = json.dumps([self.command, self.path, body.decode()]).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(result)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(result)

    def log_message(self, *args):
        pass


def exercise(args):
    fixtures = Path(args.fixtures).resolve()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(fixtures / "localhost_cert.pem", fixtures / "localhost_key.pem")
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin.daemon_threads = True
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="rut-h1-https-", dir="/var/tmp") as directory:
            root = Path(directory)
            source = root / "gateway.rut"
            source.write_text(
                f'upstream secure {{ host: "127.0.0.1", port: {origin.server_port}, '
                f'tls: {{ ca: "{fixtures / "localhost_cert.pem"}", server_name: "localhost" }} }}\n'
                f'upstream invalid {{ host: "127.0.0.1", port: {origin.server_port}, '
                f'tls: {{ ca: "{fixtures / "localhost_cert.pem"}", server_name: "wrong.example" }} }}\n'
                'route "/secure" { return forward(secure, load_balance: .roundRobin) }\n'
                'route GET "/connect-ok" { let ev = wait(upstream(secure).connect()) '
                'if ev.ok { return 204 } else { return 502 } }\n'
                'route GET "/connect-fail" { let ev = wait(upstream(invalid).connect()) '
                'if ev.ok { return 204 } else { return 502 } }\n'
                'route GET "/ready" { return 204 }\n'
            )
            with (root / "gateway.log").open("w+") as log:
                process = subprocess.Popen(
                    [args.server, "0", str(source), "--backend", args.backend,
                     "--shards", "1", "--no-pin", "--drain", "0",
                     "--max-connections-per-shard", "32"],
                    stdout=log, stderr=subprocess.STDOUT)
                try:
                    port = None
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline and process.poll() is None:
                        log.seek(0)
                        output = log.read()
                        matched = re.search(r"Listening on port (\d+)", output)
                        if matched:
                            port = int(matched[1])
                            break
                        time.sleep(0.02)
                    if port is None:
                        log.seek(0)
                        raise AssertionError(log.read())
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                    try:
                        for index in range(12):
                            method = "GET" if index % 2 == 0 else "POST"
                            path = f"/secure/{index}?q=a%2Fb"
                            data = "" if method == "GET" else "b" * 4096
                            connection.request(method, path, body=data)
                            response = connection.getresponse()
                            actual = response.read()
                            assert response.status == 200, (response.status, actual)
                            assert json.loads(actual) == [method, path, data]
                        for path, status in (("/connect-ok", 204), ("/connect-fail", 502)):
                            connection.request("GET", path)
                            response = connection.getresponse()
                            assert response.status == status, (path, response.status)
                            response.read()
                        connection.request("GET", "/ready")
                        response = connection.getresponse()
                        assert response.status == 204 and response.read() == b""
                    finally:
                        connection.close()
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    finally:
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("--backend", required=True, choices=("epoll", "io_uring"))
    exercise(parser.parse_args())
