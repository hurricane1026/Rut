#!/usr/bin/env python3
"""Check request-specific CORS mutations on public HTTP/1 cache hits."""
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
    protocol_version = 'HTTP/1.1'
    counts = collections.Counter()
    lock = threading.Lock()

    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.lock:
            self.counts[self.path] += 1
            count = self.counts[self.path]
        body = b'x' * 15700 if self.path == '/large' else f'origin:{count}'.encode()
        self.send_response(200)
        self.send_header('Cache-Control', 'public, max-age=60')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', 'https://evil.example')
        self.send_header('Access-Control-Allow-Credentials', 'false')
        self.send_header('Access-Control-Allow-Methods', 'EVIL')
        self.send_header('Vary', 'Accept-Encoding')
        self.end_headers()
        self.wfile.write(body)


def main():
    binary, backend = sys.argv[1:]
    root = Path(__file__).resolve().parent.parent
    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-cors-cache-') as directory:
            path = Path(directory)
            (path / 'middleware').mkdir()
            (path / 'middleware/cors.rut').write_text((root / 'examples/middleware/cors.rut').read_text())
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            source = (root / 'examples/cors.rut').read_text()
            source = source.replace('127.0.0.1:9000', f'127.0.0.1:{origin.server_port}')
            source = source.replace('listen 127.0.0.1:8080', '')
            source += '''\nchain cache_cors { after applyPolicy(req, resp, browserPolicy()) }
@cache(ttl: 30s)
route GET "/cached" use chain cache_cors { return forward(api, load_balance: .roundRobin) }
@cache(ttl: 30s)
route GET "/only" use chain cache_cors { return forward(api, load_balance: .roundRobin) }
'''
            source += 'func long_header(_ req: i32, _ resp: Response) -> i32 { resp.set("Access-Control-Allow-Origin", "' + ('a' * 1500) + '")\n0\n}\n'
            source += 'chain large_cors { after long_header(req, resp) }\n@cache(ttl: 30s)\nroute GET "/large" use chain large_cors { return forward(api, load_balance: .roundRobin) }\n'
            source += f'listen 127.0.0.1:{port}\n'
            (path / 'main.rut').write_text(source)
            with (path / 'runtime.log').open('w+') as log:
                proc = subprocess.Popen([binary, str(path / 'main.rut'), '--backend', backend,
                                         '--shards', '1', '--no-pin', '--max-connections-per-shard', '128'],
                                        stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        if proc.poll() is not None:
                            log.seek(0)
                            output = log.read()
                            if backend == 'io_uring' and 'io_uring is unavailable' in output:
                                print(output)
                                return 77
                            raise RuntimeError(output)
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                                break
                        except OSError:
                            time.sleep(0.05)
                    else:
                        raise RuntimeError('gateway startup timed out')
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    def request(origins, route='/cached', only=False):
                        conn.putrequest('GET', route)
                        for value in origins:
                            conn.putheader('Origin', value)
                        if only:
                            conn.putheader('Cache-Control', 'only-if-cached')
                        conn.endheaders()
                        response = conn.getresponse()
                        return response.status, response.headers, response.read()
                    def check(origins, expected, cached):
                        status, headers, body = request(origins)
                        assert status == 200, status
                        assert headers.get_all('Access-Control-Allow-Origin') == ([expected] if expected else None)
                        assert headers.get_all('Access-Control-Allow-Credentials') == (['true'] if expected else None)
                        assert headers.get('Access-Control-Allow-Methods') is None
                        assert ('Age' in headers) == cached, headers
                        assert 'Accept-Encoding' in ','.join(headers.get_all('Vary'))
                        assert 'Origin' in ','.join(headers.get_all('Vary'))
                        return body
                    a = ['https://app.example.com']
                    b = ['https://admin.example.com']
                    assert check(a, a[0], False) == check(a, a[0], True)
                    assert check(b, b[0], False) == check(b, b[0], True)
                    assert check([], None, False) == check([], None, True)
                    assert check(['https://evil.example'], None, False) == check(['https://evil.example'], None, True)
                    assert check(a + a, None, False) == check(a + a, None, True)
                    assert Origin.counts['/cached'] == 5, Origin.counts
                    # Two pipelined hits keep their own headers and response bodies.
                    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
                        request_wire = (b'GET /cached HTTP/1.1\r\nHost: 127.0.0.1:' +
                                        str(port).encode() + b'\r\nAccept-Encoding: identity\r\n' +
                                        b'Origin: https://app.example.com\r\n\r\n')
                        sock.sendall(request_wire + request_wire)
                        remaining = b''
                        for _ in range(2):
                            while b'\r\n\r\n' not in remaining:
                                part = sock.recv(4096)
                                assert part
                                remaining += part
                            head, remaining = remaining.split(b'\r\n\r\n', 1)
                            lines = head.split(b'\r\n')
                            assert lines[0].startswith(b'HTTP/1.1 200 '), lines[0]
                            fields = [line.lower() for line in lines[1:]]
                            assert b'access-control-allow-origin: https://app.example.com' in fields
                            assert any(line.startswith(b'age: ') for line in fields)
                            length = int(next(line.split(b':', 1)[1] for line in fields
                                              if line.startswith(b'content-length:')))
                            while len(remaining) < length:
                                part = sock.recv(4096)
                                assert part
                                remaining += part
                            assert remaining[:length] == b'origin:1'
                            remaining = remaining[length:]
                    assert Origin.counts['/cached'] == 5
                    status, headers, _ = request(a, '/only', only=True)
                    assert status == 200 and headers.get('Access-Control-Allow-Origin') == a[0]
                    assert 'Age' not in headers and Origin.counts['/only'] == 1
                    conn.close()
                    # The raw entry fits the cache but its decorated hit exceeds
                    # the bounded send buffer: it must close before sending bytes.
                    large = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    large.request('GET', '/large')
                    response = large.getresponse()
                    assert response.status == 200 and len(response.read()) == 15700
                    large.close()
                    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
                        sock.sendall(b'GET /large HTTP/1.1\r\nHost: 127.0.0.1:' + str(port).encode() +
                                     b'\r\nAccept-Encoding: identity\r\n\r\n')
                        assert sock.recv(1) == b'', 'oversized cache hit published partial bytes'
                    assert Origin.counts['/large'] == 1

                    def h2_request():
                        def frame(kind, flags, stream, payload=b''):
                            return (len(payload).to_bytes(3, 'big') + bytes([kind, flags]) +
                                    stream.to_bytes(4, 'big') + payload)
                        headers = bytes([0x82, 0x86, 0x04, 7]) + b'/cached'
                        headers += bytes([0x01, 9]) + b'localhost'
                        headers += bytes([0, 6]) + b'origin' + bytes([23]) + b'https://app.example.com'
                        with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
                            sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) + frame(1, 5, 1, headers))
                            def exact(size):
                                data = b''
                                while len(data) < size:
                                    part = sock.recv(size - len(data))
                                    assert part, 'incomplete HTTP/2 frame'
                                    data += part
                                return data
                            body = b''
                            saw_headers = False
                            while True:
                                head = exact(9)
                                payload = exact(int.from_bytes(head[:3], 'big'))
                                kind, flags = head[3:5]
                                stream = int.from_bytes(head[5:], 'big') & 0x7fffffff
                                assert kind not in (3, 7), (kind, payload)
                                if kind == 4 and not flags & 1:
                                    sock.sendall(frame(4, 1, 0))
                                if stream == 1 and kind == 1:
                                    assert payload[0] == 0x88, payload
                                    saw_headers = True
                                if stream == 1 and kind == 0:
                                    body += payload
                                if stream == 1 and kind in (0, 1) and flags & 1:
                                    assert saw_headers
                                    return body
                    before = Origin.counts['/cached']
                    assert h2_request() != h2_request()
                    assert Origin.counts['/cached'] == before + 2
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
    finally:
        origin.shutdown()
        origin.server_close()
    print(f'{backend}: CORS cache socket tests passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
