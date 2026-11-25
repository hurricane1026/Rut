#!/usr/bin/env python3
"""Verify route request-body admission before forwarding."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time

from test_cli_access_log_host import known_io_uring_environment_failure
from auth_h2_fixture import request as h2_request, frame, string, status


def h2_sibling_admission(port):
    def headers(path, content_length=None):
        block = b'\x83\x86\x04' + string(path) + b'\x01' + string('localhost')
        if content_length is not None:
            block += b'\x00' + string('content-length') + string(str(content_length))
        return block

    with socket.create_connection(('127.0.0.1', port), timeout=8) as client:
        client.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) +
                       frame(1, 4, 1, headers('/static', 5)) +
                       frame(1, 5, 3, headers('/ok')) +
                       frame(1, 4, 5, headers('/static')) +
                       frame(0, 1, 5, b'unknown') +
                       frame(0, 1, 1, b'abcde') +
                       frame(1, 5, 7, headers('/ok')))
        replies = {}
        def exact(n):
            data = b''
            while len(data) < n:
                chunk = client.recv(n - len(data))
                assert chunk, replies
                data += chunk
            return data
        while len(replies) < 4:
            header = exact(9)
            payload = exact(int.from_bytes(header[:3], 'big'))
            kind, flags = header[3:5]
            stream = int.from_bytes(header[5:9], 'big') & 0x7fffffff
            assert kind != 7, (kind, payload)
            if kind == 4 and not flags & 1:
                client.sendall(frame(4, 1, 0))
            if kind == 1 and stream:
                replies[stream] = status(payload)
        assert replies == {1: 413, 3: 204, 5: 411, 7: 204}, replies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    lock = threading.Lock()
    received = []

    class Origin(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_POST(self):
            data = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            with lock:
                received.append((self.path, data))
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'ok')

        def log_message(self, *unused):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='rut-body-limit-') as tmp:
            root = Path(tmp)
            source, log = root / 'app.rut', root / 'server.log'
            source.write_text(f'''
upstream limited {{ host: "127.0.0.1", port: {origin.server_port} }}
upstream unlimited at "127.0.0.1:{origin.server_port}"
@requestBodyLimit(max: 4b)
route POST "/static" {{ return forward(limited, load_balance: .roundRobin,
    target_transform: {{ strip_prefix: "/", replace_prefix: "/", mode: .rawPrefix }}) }}
@requestBodyLimit(max: 4b)
route POST "/jit" {{ if req.header("X-Test").or("") == "yes" {{ return forward(limited, load_balance: .roundRobin) }} else {{ return 400 }} }}
route POST "/ok" {{ return 204 }}
route POST "/unlimited" {{ return forward(unlimited, load_balance: .roundRobin) }}
''')
            with log.open('wb') as stream:
                process = subprocess.Popen([args.server, '0', str(source), '--shards', '1',
                                            '--no-pin', '--drain', '0', '--backend', args.backend],
                                           stdout=stream, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace')
                match = re.search(r'Listening on port (\d+) with', text)
                if match:
                    port = int(match[1])
                    break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and known_io_uring_environment_failure(text):
                        return 77
                    raise AssertionError(text)
                time.sleep(.025)
            else:
                raise AssertionError(log.read_text(errors='replace'))
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                for path, body in [('/static', b''), ('/static', b'a'), ('/static', b'abcd'),
                                   ('/jit', b'abcd'), ('/unlimited', b'abcdef')]:
                    conn.request('POST', path, body=body, headers={'X-Test': 'yes'})
                    response = conn.getresponse()
                    assert (response.status, response.read()) == (200, b'ok')
            finally:
                conn.close()
            for path in ('/static', '/jit'):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                try:
                    conn.request('POST', path, body=b'abcde', headers={'X-Test': 'yes'})
                    response = conn.getresponse()
                    assert response.status == 413, (path, response.status)
                    response.read()
                    assert response.will_close
                finally:
                    conn.close()
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                client.settimeout(5)
                client.sendall(b'POST /static HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n')
                client.sendall(b'\r\n')  # No body: admission must run at the header boundary.
                assert client.recv(4096).startswith(b'HTTP/1.1 413 ')
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                client.settimeout(5)
                client.sendall(b'POST /static HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n'
                               b'1\r\na\r\n0\r\n\r\n')
                response = bytearray()
                while True:
                    part = client.recv(4096)
                    if not part:
                        break
                    response.extend(part)
                assert response.startswith(b'HTTP/1.1 411 '), response
            assert h2_request(port, '/static', [], b'abcd', 'POST') == (200, b'ok')
            assert h2_request(port, '/static', [], b'', 'POST') == (200, b'ok')
            for path in ('/static', '/jit'):
                assert h2_request(port, path, [('X-Test', 'yes')], b'abcde', 'POST')[0] == 413
            h2_sibling_admission(port)
            with lock:
                assert received == [('/static', b''), ('/static', b'a'), ('/static', b'abcd'),
                                    ('/jit', b'abcd'), ('/unlimited', b'abcdef'),
                                    ('/static', b'abcd'), ('/static', b'')], received
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=2)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
