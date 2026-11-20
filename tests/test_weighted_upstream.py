#!/usr/bin/env python3
"""Weighted forwarding and explicit connects against live upstream sockets."""

import argparse
from collections import Counter
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time

from auth_h2_fixture import request as h2_request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    observed = Counter()
    lock = threading.Lock()
    servers = []
    threads = []
    process = None
    dead = socket.socket()
    dead.bind(('127.0.0.1', 0))  # Reserved but not listening: deterministic refused connect.
    try:
        for identity in ('A', 'B', 'disabled'):
            def handler(label):
                class Upstream(BaseHTTPRequestHandler):
                    def do_GET(self):
                        with lock:
                            observed[label] += 1
                        body = label.encode()
                        self.send_response(200)
                        self.send_header('Content-Length', str(len(body)))
                        self.send_header('Connection', 'close')
                        self.end_headers()
                        self.wfile.write(body)

                    def log_message(self, *unused):
                        pass
                return Upstream
            server = ThreadingHTTPServer(('127.0.0.1', 0), handler(identity))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
        ports = [server.server_port for server in servers]
        addresses = ', '.join(f'"127.0.0.1:{port}": {weight}'
                              for port, weight in zip(ports, (65535, 21845, 0)))
        disabled = ', '.join(f'"127.0.0.1:{port}": 0' for port in ports)
        source = f'''
upstream api {{ backends: [{addresses}] }}
upstream off {{ backends: [{disabled}] }}
upstream retry {{ backends: ["127.0.0.1:{dead.getsockname()[1]}": 65535, "127.0.0.1:{ports[1]}": 1] }}
upstream one {{ connect_attempts: 1, backends: ["127.0.0.1:{dead.getsockname()[1]}": 65535, "127.0.0.1:{ports[1]}": 1] }}
upstream two {{ connect_attempts: 2, backends: ["127.0.0.1:{dead.getsockname()[1]}": 65535, "127.0.0.1:{ports[1]}": 1] }}
upstream connect_api {{ backends: ["127.0.0.1:{dead.getsockname()[1]}": 0, "127.0.0.1:{ports[1]}": 1] }}
route GET "/rr" {{ return forward(api, load_balance: .roundRobin) }}
route GET "/least" {{ return forward(api, load_balance: .leastRequests) }}
route GET "/off" {{ return forward(off, load_balance: .roundRobin) }}
route GET "/retry" {{ return forward(retry, load_balance: .roundRobin) }}
route GET "/one" {{ return forward(one, load_balance: .roundRobin) }}
route GET "/two" {{ return forward(two, load_balance: .roundRobin) }}
route GET "/connect" {{
    let ev = wait(upstream(connect_api).connect())
    if ev.ok {{ return 204 }} else {{ return 502 }}
}}
route GET "/connect-off" {{
    let ev = wait(upstream(off).connect())
    if ev.ok {{ return 204 }} else {{ return 502 }}
}}
'''
        with tempfile.TemporaryDirectory(prefix='rut-weighted-upstream-') as directory:
            root = Path(directory)
            program = root / 'gateway.rut'
            program.write_text(source)
            log = root / 'server.log'
            with log.open('wb') as output:
                process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                            '--no-pin', '--shards', '1', '--drain', '0'],
                                           stdout=output, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace')
                match = re.search(r'Listening on port ([0-9]+) with', text)
                if match:
                    port = int(match[1])
                    break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and 'io_uring is unavailable' in text:
                        return 77
                    raise AssertionError(text)
                time.sleep(.025)
            else:
                raise AssertionError('Gateway startup timed out:\n' + log.read_text(errors='replace'))

            def h1(path):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
                try:
                    connection.request('GET', path)
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            for protocol, request in [('H1', h1), ('H2', lambda path: h2_request(port, path, []))]:
                for path in ('/rr', '/least'):
                    replies = Counter()
                    for _ in range(40):
                        code, body = request(path)
                        assert code == 200, (protocol, path, code, body)
                        replies[body] += 1
                    assert replies == {b'A': 30, b'B': 10}, (protocol, path, replies)
                for _ in range(8):
                    code, body = request('/off')
                    assert code == 503, (protocol, 'all disabled', code, body)
                for _ in range(5):
                    code, body = request('/retry')
                    assert (code, body) == (200, b'B'), (protocol, 'retry', code, body)
            assert h1('/one')[0] == 502
            assert h1('/two') == (200, b'B')
            for path, status in (('/connect', 204), ('/connect-off', 503)):
                for _ in range(2):
                    code, body = h1(path)
                    assert code == status, (path, code, body)
            assert observed['disabled'] == 0, observed
            print(f'Weighted forwarding and explicit connects passed: {args.backend}')
            return 0
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        dead.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


if __name__ == '__main__':
    raise SystemExit(main())
