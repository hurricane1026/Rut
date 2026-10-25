#!/usr/bin/env python3
"""Public cache checks through the real CLI, using only the Python standard library."""
import collections
import http.client
import http.server
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counts = collections.Counter()
    lock = threading.Lock()

    def log_message(self, *args):
        pass

    def respond(self):
        with self.lock:
            self.counts[(self.command, self.path)] += 1
            count = self.counts[(self.command, self.path)]
        body = f"{count}:{self.headers.get('Accept-Language', 'none')}".encode()
        self.send_response(200)
        truncated = self.path.startswith("/truncated") and count == 1
        self.send_header("Content-Length", str(len(body) + (5 if truncated else 0)))
        if truncated:
            self.close_connection = True
        if self.path.startswith("/private"):
            self.send_header("Cache-Control", "private, max-age=60")
        elif self.path.startswith("/nostore"):
            self.send_header("Cache-Control", "no-store")
        elif self.path.startswith("/cookie"):
            self.send_header("Set-Cookie", "session=secret")
        elif self.path.startswith("/star"):
            self.send_header("Vary", "*")
        else:
            self.send_header("Cache-Control", "max-age=60")
        if self.path.startswith("/vary"):
            self.send_header("Vary", "Accept-Language")
        self.end_headers()
        if self.path.startswith("/split"):
            self.wfile.write(body[:1])
            self.wfile.flush()
            time.sleep(0.02)
            self.wfile.write(body[1:])
        else:
            self.wfile.write(body)

    do_GET = respond
    do_POST = respond


def exercise(port):
    def request(path, headers=None, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            conn.request(method, path, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            conn.close()

    limited_first, limited_hit = request("/limited"), request("/limited")
    assert limited_first[:2] == limited_hit[:2] and "Age" in limited_hit[2]
    assert request("/limited")[0] == 429
    assert Origin.counts[("GET", "/limited")] == 1
    for path in ("/plain", "/split"):
        first, second = request(path), request(path)
        assert first[:2] == second[:2] and second[0] == 200, (first, second)
        assert "Age" in second[2] and Origin.counts[("GET", path)] == 1
    for name in ("Authorization", "Proxy-Authorization", "X-API-Key", "Cookie"):
        first = request("/plain", {name: "secret"})
        second = request("/plain", {name: "secret"})
        assert first[1] != second[1] and "Age" not in second[2], name
    first = request("/plain")
    assert request("/plain", method="POST")[0] == 200
    assert request("/plain")[1] != first[1]
    for path in ("/private", "/nostore", "/cookie", "/star"):
        first, second = request(path), request(path)
        assert first[1] != second[1] and "Age" not in second[2], path
    en = request("/vary", {"Accept-Language": "en"})
    fr = request("/vary", {"Accept-Language": "fr"})
    en_again = request("/vary", {"Accept-Language": "en"})
    assert en[1] != fr[1] and en[1] == en_again[1] and "Age" in en_again[2]
    assert request("/missing", {"Cache-Control": "only-if-cached"})[0] == 504
    assert Origin.counts[("GET", "/missing")] == 0
    first = request("/plain")
    bypass = request("/plain", {"Cache-Control": "no-cache"})
    assert first[1] != bypass[1] and "Age" not in bypass[2]
    try:
        broken = request("/truncated")
        assert broken[0] != 200, broken
    except (http.client.HTTPException, ConnectionError):
        pass
    healthy = request("/truncated")
    cached = request("/truncated")
    assert healthy[:2] == cached[:2] and healthy[0] == 200
    assert Origin.counts[("GET", "/truncated")] == 2 and "Age" in cached[2]
    first = request("/expiry")
    time.sleep(2.1)
    assert request("/expiry")[1] != first[1]


def exercise_h2(port):
    def request(path, credential=None):
        def frame(kind, flags, stream, body=b""):
            return (len(body).to_bytes(3, "big") + bytes([kind, flags]) +
                    stream.to_bytes(4, "big") + body)

        # HPACK static GET/http, literal indexed names :path/:authority.
        target = path.encode()
        headers = bytes([0x82, 0x86, 0x04, len(target)]) + target
        headers += bytes([0x01, 9]) + b"localhost"
        if credential:
            name = credential.encode()
            headers += bytes([0, len(name)]) + name + bytes([6]) + b"secret"
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" +
                         frame(4, 0, 0) + frame(1, 5, 1, headers))

            def read_exact(count):
                data = b""
                while len(data) < count:
                    part = sock.recv(count - len(data))
                    assert part, "HTTP/2 closed before complete response"
                    data += part
                return data

            body = b""
            saw_headers = False
            for _ in range(40):
                header = read_exact(9)
                length = int.from_bytes(header[:3], "big")
                kind, flags = header[3:5]
                stream = int.from_bytes(header[5:], "big") & 0x7fffffff
                payload = read_exact(length)
                assert kind not in (3, 7), ("RST_STREAM/GOAWAY", payload)
                if kind == 4 and not flags & 1:
                    sock.sendall(frame(4, 1, 0))
                if stream == 1 and kind == 1:
                    assert payload[0] == 0x88, ("expected :status 200", payload)
                    saw_headers = True
                if stream == 1 and kind == 0:
                    assert not flags & 8, "unexpected padded DATA"
                    body += payload
                if stream == 1 and kind in (0, 1) and flags & 1:
                    assert saw_headers
                    return body
            raise AssertionError("HTTP/2 response did not finish")

    for path in ("/h2plain", "/split-h2"):
        first, second = request(path), request(path)
        assert first == second and first, (first, second)
        assert Origin.counts[("GET", path)] == 1
    for name in ("authorization", "x-api-key", "cookie"):
        assert request("/h2plain", name) != request("/h2plain", name), name


def main():
    binary, backend = sys.argv[1:]
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="rut-http-cache-") as directory:
            path = Path(directory)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            (path / "main.rut").write_text(
                f'upstream origin at "127.0.0.1:{origin.server_port}"\n'
                f'listen 127.0.0.1:{port}\n'
                '@cache(ttl: 2s)\n'
                '@rateLimit(limit: 2, window: 1h)\n'
                'route GET "/limited" { return forward(origin, load_balance: .roundRobin) }\n'
                '@cache(ttl: 2s)\n'
                'route GET "/" { return forward(origin, load_balance: .roundRobin) }\n'
                'route POST "/" { return forward(origin, load_balance: .roundRobin) }\n'
            )
            with (path / "runtime.log").open("w+") as log:
                process = subprocess.Popen(
                    [binary, str(path / "main.rut"), "--backend", backend,
                     "--shards", "1", "--no-pin", "--max-connections-per-shard", "128"],
                    stdout=log, stderr=log,
                )
                try:
                    for _ in range(200):
                        if process.poll() is not None:
                            log.seek(0)
                            output = log.read()
                            if (backend == "io_uring" and
                                    "--backend io_uring requested, but io_uring is unavailable" in output):
                                print(output)
                                return 77
                            raise RuntimeError(output)
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                break
                        except OSError:
                            time.sleep(0.05)
                    else:
                        raise RuntimeError("gateway startup timed out")
                    exercise(port)
                    exercise_h2(port)
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
    print(f"{backend}: public cache socket tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
