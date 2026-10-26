#!/usr/bin/env python3
"""Exercise the shipped CORS policy through native compilation and real sockets."""
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
    calls = 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        Origin.calls += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.send_header("Access-Control-Allow-Origin", "https://evil.example")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "false")
        self.send_header("Access-Control-Expose-Headers", "Authorization")
        self.send_header("Vary", "Accept-Encoding")
        self.end_headers()
        self.wfile.write(b"ok")


def exercise(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)

    def request(method="OPTIONS", headers=None):
        conn.request(method, "/api", headers=headers or {})
        response = conn.getresponse()
        body = response.read()
        return response.status, response.headers, body

    allowed = {"Origin": "https://app.example.com",
               "Access-Control-Request-Method": "POST",
               "Access-Control-Request-Headers": "authorization, CONTENT-type, x-trace"}
    status, headers, _ = request(headers=allowed)
    assert status == 204, status
    assert headers.get_all("Access-Control-Allow-Origin") == [allowed["Origin"]]
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Access-Control-Max-Age"] == "600"
    assert "Access-Control-Request-Headers" in headers["Vary"]
    for name, value, expected in [
        ("Origin", "https://evil.example", 403),
        ("Origin", "https://app.example.com.evil", 403),
        ("Origin", "null", 403),
        ("Origin", "", 400),
        ("Access-Control-Request-Method", "post", 403),
        ("Access-Control-Request-Method", "POST, GET", 400),
        ("Access-Control-Request-Method", "", 400),
        ("Access-Control-Request-Headers", "Authorization, X-Secret", 403),
        ("Access-Control-Request-Headers", "Authorization,", 400),
        ("Access-Control-Request-Headers", '"Authorization"', 400),
        ("Access-Control-Request-Headers", "x" * 4097, 400),
    ]:
        altered = dict(allowed)
        altered[name] = value
        status, headers, _ = request(headers=altered)
        assert status == expected, (name, value[:80], status)
        assert headers.get("Access-Control-Allow-Origin") is None
    for duplicate in ("Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"):
        conn.putrequest("OPTIONS", "/api")
        for name, value in allowed.items():
            conn.putheader(name, value)
        conn.putheader(duplicate, allowed[duplicate])
        conn.endheaders()
        response = conn.getresponse()
        assert response.status == 400, (duplicate, response.status)
        response.read()
    no_headers = dict(allowed)
    del no_headers["Access-Control-Request-Headers"]
    assert request(headers=no_headers)[0] == 204
    assert Origin.calls == 0, "preflights must not reach upstream"
    for origin in ("https://evil.example", "https://app.example.com.evil"):
        assert request("GET", {"Origin": origin})[0] == 403
    assert Origin.calls == 0
    for origin in (allowed["Origin"], None, allowed["Origin"]):
        status, headers, body = request("GET", {"Origin": origin} if origin else {})
        assert (status, body) == (200, b"ok")
        assert headers.get_all("Access-Control-Allow-Origin") == [allowed["Origin"]]
        assert headers.get_all("Access-Control-Allow-Credentials") == ["true"]
        assert headers.get("Access-Control-Expose-Headers") is None
        vary = ",".join(headers.get_all("Vary"))
        assert "Origin" in vary and "Accept-Encoding" in vary, vary
    # The explicit uniqueness check rejects duplicate Origin before forwarding.
    conn.putrequest("GET", "/api")
    conn.putheader("Origin", allowed["Origin"])
    conn.putheader("Origin", "https://evil.example")
    conn.endheaders()
    response = conn.getresponse()
    assert response.status == 403, response.status
    response.read()
    conn.close()
    assert Origin.calls == 3
    for sensitive, requested, expected in [("yes", "get", 403), ("no", "get", 204),
                                            ("yes", "GET", 204), ("no", "GET,", 403)]:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/tokens", headers={"Allowed": "GET", "Requested": requested,
                                              "Sensitive": sensitive})
        response = conn.getresponse()
        assert response.status == expected, (sensitive, requested, response.status)
        response.read()
        conn.close()

    for origin, methods, headers, expected in [
        ("*", "GET", "", 204),
        ("https://app.example.com", "GET, POST", "X-Trace", 204),
        ("https://app.example.com/path", "GET", "", 503),
        ("https://app.example.com", "*", "", 503),
        ("https://app.example.com", "GET", "X-Trace, *", 503),
        ("https://app.example.com", "GET,", "", 503),
    ]:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/policy", headers={"Origin": origin, "Methods": methods, "Headers": headers})
        response = conn.getresponse()
        assert response.status == expected, (origin, methods, headers, response.status)
        response.read()
        conn.close()


def exercise_h2(port):
    def frame(kind, flags, stream, payload=b""):
        return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload

    def request(method, extra, expected_status_index):
        # Literal uncompressed HPACK request fields; every request has its own connection.
        headers = bytes([0x86, 0x04, 4]) + b"/api" + bytes([0x01, 9]) + b"localhost"
        for name, value in [(":method", method)] + extra:
            name, value = name.encode(), value.encode()
            headers += bytes([0, len(name)]) + name + bytes([len(value)]) + value
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0) + frame(1, 5, 1, headers))

            def exact(count):
                data = b""
                while len(data) < count:
                    part = sock.recv(count - len(data))
                    assert part, "incomplete HTTP/2 response"
                    data += part
                return data

            saw_headers = False
            for _ in range(40):
                head = exact(9)
                payload = exact(int.from_bytes(head[:3], "big"))
                kind, flags = head[3:5]
                stream = int.from_bytes(head[5:], "big") & 0x7fffffff
                assert kind not in (3, 7), (kind, payload)
                if kind == 4 and not flags & 1:
                    sock.sendall(frame(4, 1, 0))
                if stream == 1 and kind == 1:
                    assert payload[0] == expected_status_index, payload
                    saw_headers = True
                if stream == 1 and kind in (0, 1) and flags & 1:
                    assert saw_headers
                    return
            raise AssertionError("HTTP/2 response did not finish")

    allowed = [("origin", "https://app.example.com"),
               ("access-control-request-method", "POST"),
               ("access-control-request-headers", "AUTHORIZATION, x-trace")]
    request("OPTIONS", allowed, 0x89)  # HPACK static :status 204.
    request("OPTIONS", allowed[:1], 0x8c)  # HPACK static :status 400.
    request("OPTIONS", allowed + [("origin", "https://evil.example")], 0x8c)
    request("GET", allowed[:1], 0x88)  # HPACK static :status 200.


def main():
    binary, backend = sys.argv[1:]
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    source_root = Path(__file__).resolve().parent.parent
    try:
        with tempfile.TemporaryDirectory(prefix="rut-cors-") as directory:
            path = Path(directory)
            (path / "middleware").mkdir()
            (path / "middleware/cors.rut").write_text(
                (source_root / "examples/middleware/cors.rut").read_text())
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            source = (source_root / "examples/cors.rut").read_text()
            source = source.replace("127.0.0.1:9000", f"127.0.0.1:{origin.server_port}")
            source = source.replace("127.0.0.1:8080", f"127.0.0.1:{port}")
            source += '\nroute GET "/tokens" {\n'
            source += 'guard httpTokenListAllows(req.header("Allowed").or(""), req.header("Requested").or(""), req.header("Sensitive").or("") == "yes") else { return 403 }\n'
            source += 'return 204\n}\n'
            source += 'route GET "/policy" {\n'
            source += 'guard cors.validOrigin(req.header("Origin").or("")) && cors.validLists(req.header("Methods").or(""), req.header("Headers").or("")) else { return 503 }\n'
            source += 'return 204\n}\n'
            (path / "main.rut").write_text(source)
            with (path / "runtime.log").open("w+") as log:
                process = subprocess.Popen(
                    [binary, str(path / "main.rut"), "--backend", backend,
                     "--shards", "1", "--no-pin", "--max-connections-per-shard", "128"],
                    stdout=log, stderr=log)
                try:
                    for _ in range(200):
                        if process.poll() is not None:
                            log.seek(0)
                            output = log.read()
                            if backend == "io_uring" and "io_uring is unavailable" in output:
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
    print(f"{backend}: CORS socket tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
