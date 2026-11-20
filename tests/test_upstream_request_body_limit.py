#!/usr/bin/env python3
"""Verify source-configured H1 forwarding body admission on real sockets."""
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
upstream limited {{ host: "127.0.0.1", port: {origin.server_port}, max_request_body_bytes: 4 }}
upstream unlimited at "127.0.0.1:{origin.server_port}"
route POST "/static" {{ return forward(limited, load_balance: .roundRobin) }}
route POST "/jit" {{
    if req.header("X-Test").or("") == "yes" {{
        return forward(limited, load_balance: .roundRobin)
    }} else {{
        return 400
    }}
}}
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
                for path, body in [('/static', b'a'), ('/static', b'abcd'),
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
                client.sendall(b'POST /static HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n'
                               b'1\r\na\r\n0\r\n\r\n')
                response = bytearray()
                while True:
                    part = client.recv(4096)
                    if not part:
                        break
                    response.extend(part)
                assert response.startswith(b'HTTP/1.1 411 '), response
            with lock:
                assert received == [('/static', b'a'), ('/static', b'abcd'),
                                    ('/jit', b'abcd'), ('/unlimited', b'abcdef')], received
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
