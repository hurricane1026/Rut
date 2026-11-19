#!/usr/bin/env python3
"""Observe active HTTP health ejection and recovery through the real gateway."""

import argparse
from collections import Counter
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
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
    lock = threading.Lock()
    healthy = {'A': True, 'B': True, 'disabled': True}
    probes = Counter()
    data_requests = Counter()
    servers, threads = [], []
    process = None
    try:
        def handler(label):
            class Origin(BaseHTTPRequestHandler):
                def do_GET(self):
                    with lock:
                        if self.path == '/healthz':
                            probes[label] += 1
                            code = 200 if healthy[label] else 500
                        else:
                            data_requests[label] += 1
                            code = 200  # Health endpoint controls eligibility independently.
                    body = label.encode()
                    self.send_response(code)
                    self.send_header('Content-Length', str(len(body)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *unused):
                    pass
            return Origin

        for label in healthy:
            origin = ThreadingHTTPServer(('127.0.0.1', 0), handler(label))
            thread = threading.Thread(target=origin.serve_forever, daemon=True)
            thread.start()
            servers.append(origin)
            threads.append(thread)
        entries = ', '.join(f'"127.0.0.1:{origin.server_port}": {weight}'
                            for origin, weight in zip(servers, (1, 1, 0)))
        source = f'''
upstream api {{
    backends: [{entries}]
    health_check: {{
        path: "/healthz", interval: 1s, status: 200,
        failure_threshold: 2, success_threshold: 3
    }}
}}
route GET "/" {{ return forward(api, load_balance: .roundRobin) }}
'''
        with tempfile.TemporaryDirectory(prefix='rut-active-health-') as directory:
            root = Path(directory)
            program, log = root / 'gateway.rut', root / 'server.log'
            program.write_text(source)
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
                raise AssertionError('gateway startup timed out\n' + log.read_text(errors='replace'))

            def h1():
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                try:
                    connection.request('GET', '/')
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            def wait_for(predicate, message):
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if predicate():
                        return
                    if process.poll() is not None:
                        raise AssertionError(log.read_text(errors='replace'))
                    time.sleep(.025)
                raise AssertionError(message + '\n' + log.read_text(errors='replace'))

            wait_for(lambda: probes['A'] > 0 and probes['B'] > 0, 'no periodic health probes')
            for protocol, request in [('H1', h1), ('H2', lambda: h2_request(port, '/', []))]:
                initial = Counter(request() for _ in range(20))
                assert initial == {(200, b'A'): 10, (200, b'B'): 10}, (protocol, initial)
                with lock:
                    healthy['A'] = False
                    before = probes['A']
                wait_for(lambda: probes['A'] > before, 'unhealthy endpoint was not probed')
                wait_for(lambda: all(request() == (200, b'B') for _ in range(4)),
                         'unhealthy endpoint was not ejected')
                with lock:
                    assert probes['A'] - before >= 2, (protocol, probes)
                assert all(request() == (200, b'B') for _ in range(20)), protocol
                with lock:
                    healthy['A'] = True
                    before = probes['A']
                wait_for(lambda: probes['A'] > before, 'disabled-by-health target was not reprobed')
                wait_for(lambda: request() == (200, b'A'), 'recovered target was not re-enabled')
                with lock:
                    assert probes['A'] - before >= 3, (protocol, probes)
                recovered = Counter(request() for _ in range(20))
                assert recovered == {(200, b'A'): 10, (200, b'B'): 10}, (protocol, recovered)
            with lock:
                assert probes['disabled'] == 0, probes
                assert data_requests['disabled'] == 0, data_requests
                print(args.backend, 'H1/H2 active health ejection/recovery passed', dict(probes))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
