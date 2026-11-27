#!/usr/bin/env python3
"""Exercise CLI idle timeout against a keep-alive HTTP/1 origin."""
import http.client
import http.server
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = str(self.client_address[1]).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def request(client):
    client.request("GET", "/")
    response = client.getresponse()
    body = response.read()
    assert response.status == 200, (response.status, body)
    return body


def exercise(binary, backend, timeout):
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin.daemon_threads = True
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="rut-idle-origin-") as directory:
            path = Path(directory)
            (path / "main.rut").write_text(
                f'upstream origin at "127.0.0.1:{origin.server_port}"\n'
                'listen 127.0.0.1:0\n'
                'route GET "/" { return forward(origin, load_balance: .roundRobin) }\n'
            )
            log_path = path / "log"
            with log_path.open("wb") as log:
                process = subprocess.Popen(
                    [binary, str(path / "main.rut"), "--backend", backend,
                     "--shards", "1", "--no-pin", "--drain", "0",
                     "--max-connections-per-shard", "128",
                     "--upstream-keepalive-idle-timeout", str(timeout)],
                    stdout=log, stderr=log,
                )
                try:
                    port = None
                    for _ in range(200):
                        output = log_path.read_text(errors="replace")
                        match = re.search(r"Listening on port (\d+)", output)
                        if match:
                            port = int(match.group(1))
                            break
                        if process.poll() is not None:
                            if backend == "io_uring" and "io_uring is unavailable" in output:
                                return 77
                            raise AssertionError(output)
                        time.sleep(0.05)
                    if port is None:
                        raise AssertionError("gateway startup timed out: " + output)
                    client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                    try:
                        first = request(client)
                        second = request(client)
                        assert first == second, (first, second)
                        time.sleep(2.2)
                        third = request(client)
                        assert (third != second) == (timeout != 0), (timeout, first, second, third)
                    finally:
                        client.close()
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    finally:
        origin.shutdown()
        origin.server_close()
    return 0


def main():
    binary, backend = sys.argv[1:]
    for timeout in (1, 0):
        result = exercise(binary, backend, timeout)
        if result:
            return result
    return 0


if __name__ == "__main__":
    sys.exit(main())
