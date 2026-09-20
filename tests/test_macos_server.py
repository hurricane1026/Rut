"""Local developer workflow: real JIT, kqueue, sockets, TLS and log writer."""
import concurrent.futures
import contextlib
import http.client
import http.server
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

BINARY = Path(sys.argv[1]).resolve()
FIXTURES = Path(__file__).parent / "fixtures"
PAYLOAD = b"macOS proxy body\n" * 16384


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = PAYLOAD * 16 if self.path == "/large" else PAYLOAD
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        data = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


@contextlib.contextmanager
def server(directory, origin_port, tls):
    source = directory / "app.rut"
    access_log = directory / "requests.log"
    source.write_text(
        f'upstream api at "127.0.0.1:{origin_port}"\n'
        f'accessLog {{ path: "{access_log}", format: downstreamRequestBytes, publication: live }}\n'
        'route GET "/" { return 200 }\n'
        'route GET "/wait" { wait(40)\n return 201 }\n'
        'route GET "/proxy" { return forward(api) }\n'
        'route GET "/large" { return forward(api) }\n'
        'route POST "/proxy" { return forward(api) }\n'
    )
    args = [str(BINARY), "0", str(source), "--drain", "1"]
    if tls:
        args += ["--h2", "--tls-cert", str(FIXTURES / "localhost_cert.pem"),
                 "--tls-key", str(FIXTURES / "localhost_key.pem")]
    log = directory / "server.log"
    with log.open("w") as output:
        process = subprocess.Popen(args, stdout=output, stderr=output)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            text = log.read_text()
            match = re.search(r"Listening on port (\d+) with 1 shard", text)
            if match:
                assert "Backend: kqueue" in text, text
                yield int(match.group(1)), access_log
                break
            assert process.poll() is None, text
            time.sleep(0.02)
        else:
            raise AssertionError("server startup timed out: " + log.read_text())
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=5) == 0, log.read_text()
        assert access_log.read_text().strip(), "live access log did not flush"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.returncode:
            print(log.read_text(), file=sys.stderr)


def exercise(port, tls):
    def connection():
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # checked-in test-only certificate
            context.set_alpn_protocols(["http/1.1"])
            return http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=context)
        return http.client.HTTPConnection("127.0.0.1", port, timeout=5)

    with contextlib.closing(connection()) as client:
        # Reuse one downstream connection across static, timer and proxy routes.
        for path, status, body in [("/", 200, None), ("/wait", 201, None),
                                   ("/proxy", 200, PAYLOAD), ("/proxy", 200, PAYLOAD)]:
            started = time.monotonic()
            client.request("GET", path)
            response = client.getresponse()
            assert response.status == status, (path, response.status)
            received = response.read()
            if body is not None:
                assert received == body, (path, len(received))
            if path == "/wait":
                assert time.monotonic() - started >= 0.025, "timer resumed early"
        client.request("POST", "/proxy", body=PAYLOAD)
        response = client.getresponse()
        assert response.status == 200
        assert response.read() == PAYLOAD

    def fetch(_):
        with contextlib.closing(connection()) as client:
            client.request("GET", "/proxy")
            response = client.getresponse()
            assert response.status == 200
            assert response.read() == PAYLOAD

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(fetch, range(12)))

    if not tls:
        # Abandon an active yield, then ensure its stale deadline cannot affect
        # a newly accepted connection which may reuse the same connection slot.
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(b"GET /wait HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(0.06)
        fetch(0)


def exercise_tls_backpressure(port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        with context.wrap_socket(raw, server_hostname="localhost") as sock:
            sock.sendall(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n")
            # Hold reads until the large proxy response encounters backpressure,
            # then make the read side ready while a TLS send is still pending.
            time.sleep(0.1)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            with sock.makefile("rb") as stream:
                for expected in (PAYLOAD * 16, None):
                    status = stream.readline()
                    assert b" 200 " in status, status
                    headers = {}
                    while True:
                        line = stream.readline()
                        assert line, "closed before complete response headers"
                        if line == b"\r\n":
                            break
                        name, value = line.split(b":", 1)
                        headers[name.lower()] = value.strip()
                    length = int(headers[b"content-length"])
                    body = stream.read(length)
                    assert len(body) == length
                    if expected is not None:
                        assert body == expected


def exercise_h2(port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as sock:
            assert sock.selected_alpn_protocol() == "h2"

            def frame(kind, flags, stream, body=b""):
                return len(body).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + body

            # HPACK static indices: GET, https, /; literal :authority localhost.
            headers = bytes([0x82, 0x87, 0x84, 0x01, 9]) + b"localhost"
            sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0) + frame(1, 5, 1, headers))

            def read_exact(count):
                data = b""
                while len(data) < count:
                    part = sock.recv(count - len(data))
                    assert part, "HTTP/2 connection closed before response"
                    data += part
                return data

            saw_headers = False
            for _ in range(20):
                header = read_exact(9)
                length = int.from_bytes(header[:3], "big")
                kind, flags = header[3:5]
                stream = int.from_bytes(header[5:], "big") & 0x7fffffff
                body = read_exact(length)
                assert kind not in (3, 7), ("HTTP/2 RST_STREAM/GOAWAY", body)
                if kind == 4 and not flags & 1:
                    sock.sendall(frame(4, 1, 0))
                if stream == 1 and kind == 1:
                    assert body[0] == 0x88, ("expected :status 200", body)
                    saw_headers = True
                if stream == 1 and kind in (0, 1) and flags & 1:
                    assert saw_headers
                    return
            raise AssertionError("HTTP/2 stream did not finish")


def main():
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        for tls in (False, True):
            with tempfile.TemporaryDirectory(prefix="rut-macos-") as tmp:
                with server(Path(tmp), origin.server_port, tls) as (port, _):
                    exercise(port, tls)
                    if tls:
                        exercise_h2(port)
                        exercise_tls_backpressure(port)
            print("PASS: " + ("TLS" if tls else "HTTP") + " JIT, proxy, timers, log and shutdown")
        bad = subprocess.run([str(BINARY), "0", "--shards", "2"], capture_output=True, timeout=5)
        assert bad.returncode != 0 and b"--shards 1 only" in bad.stderr
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join()


if __name__ == "__main__":
    main()
