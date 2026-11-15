#!/usr/bin/env python3
"""Native Rut routing intent witnesses over real downstream/upstream sockets."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    seen = []
    lock = threading.Lock()

    class Origin(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            size = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(size)
            with lock:
                seen.append((self.command, self.path, self.headers.get('Host'), body))
            response = self.path.encode() + b'|' + body
            self.send_response(200)
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        do_POST = do_GET

        def log_message(self, *_):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-routing-capabilities-') as directory:
            root = Path(directory)
            source = root / 'gateway.rut'
            source.write_text(f'''upstream backend at "127.0.0.1:{origin.server_port}"
route "/users/:id" {{
    let target = "/internal/accounts/" + req.params.id
    return forward(backend, load_balance: .roundRobin, set_path: target)
}}
route GET "/alias" {{
    guard let target = req.header("X-Target") else {{ return 400 }}
    return forward(backend, load_balance: .roundRobin, set_path: target)
}}
route GET "/plain" {{ return forward(backend, load_balance: .roundRobin) }}
''')
            log = root / 'gateway.log'
            with log.open('wb') as output:
                process = subprocess.Popen(
                    [args.server, '0', str(source), '--backend', args.backend,
                     '--shards', '2', '--no-pin', '--drain', '0'],
                    stdout=output, stderr=subprocess.STDOUT)
            try:
                port = None
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    data = log.read_bytes()
                    match = re.search(rb'Listening on port ([0-9]+) with', data)
                    if match:
                        port = int(match[1])
                        break
                    if process.poll() is not None:
                        if args.backend == 'io_uring' and b'io_uring is unavailable' in data:
                            print('SKIP: io_uring is unavailable')
                            return 77
                        raise AssertionError(data.decode(errors='replace'))
                    time.sleep(.02)
                assert port, log.read_text(errors='replace')
                client = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                try:
                    cases = [
                        ('GET', '/users/7', None, {}, b'/internal/accounts/7|'),
                        ('GET', '/alias', None, {'X-Target': '/much/longer/aliased/path?q=1&q=2'},
                         b'/much/longer/aliased/path?q=1&q=2|'),
                        ('GET', '/alias', None, {'X-Target': '/x'}, b'/x|'),
                        ('POST', '/users/42', b'payload', {}, b'/internal/accounts/42|payload'),
                        ('GET', '/plain', None, {}, b'/plain|'),
                    ]
                    for method, path, body, headers, expected in cases:
                        client.request(method, path, body=body, headers=headers)
                        reply = client.getresponse()
                        received = reply.read()
                        assert (reply.status, received) == (200, expected), (path, reply.status, received)
                finally:
                    client.close()
                # Invalid target is refused before any origin request, including
                # request-header-backed values and non-origin-form URIs.
                for target in ('not-origin-form', '/bad%xx', '/bad#fragment', '/bad path'):
                    with lock:
                        before = len(seen)
                    client = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    try:
                        client.request('GET', '/alias', headers={'X-Target': target})
                        reply = client.getresponse()
                        reply.read()
                        assert reply.status == 400, (target, reply.status)
                    finally:
                        client.close()
                    with lock:
                        assert len(seen) == before, (target, seen[before:])
                with lock:
                    assert len(seen) == len(cases), seen
                    assert seen[3][3] == b'payload', seen
                print(f'PASS: {args.backend}: dynamic captures, borrowed target ownership, body, '
                      'keepalive reset, invalid-target refusal; 9 requests')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    finally:
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=5)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
