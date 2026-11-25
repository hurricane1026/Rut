#!/usr/bin/env python3
"""Active probes gate new traffic until the configured success streak."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
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
    state = {'healthy': False, 'probes': 0, 'business': 0}

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                if self.path == '/health':
                    state['probes'] += 1
                    status = 200 if state['healthy'] else 500
                else:
                    state['business'] += 1
                    status = 200
            self.send_response(status)
            self.send_header('Content-Length', '2')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(b'ok')

        def log_message(self, *unused):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='rut-readiness-') as tmp:
            root = Path(tmp)
            source, log = root / 'app.rut', root / 'server.log'
            source.write_text(f'''
upstream api {{ host: "127.0.0.1", port: {origin.server_port},
    health_check: {{ path: "/health", interval: 1s, success_threshold: 2, require_initial_success: true }} }}
route GET "/" {{ return forward(api, load_balance: .roundRobin) }}
route GET "/least" {{ return forward(api, load_balance: .leastRequests) }}
route GET "/connect" {{ let ev = wait(upstream(api).connect()) if ev.ok {{ return 204 }} else {{ return 502 }} }}
''')
            with log.open('wb') as stream:
                process = subprocess.Popen([args.server, '0', str(source), '--shards', '1', '--no-pin',
                                            '--drain', '0', '--backend', args.backend],
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
                raise AssertionError('startup timed out\n' + log.read_text(errors='replace'))

            def request(path):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                try:
                    conn.request('GET', path)
                    response = conn.getresponse()
                    return response.status, response.read()
                finally:
                    conn.close()

            assert request('/')[0] == 503
            assert request('/least')[0] == 503
            assert request('/connect')[0] == 503
            def wait_for_probe_after(previous):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with lock:
                        count = state['probes']
                    if count > previous:
                        return count
                    time.sleep(.01)
                raise AssertionError('health probe did not arrive')

            with lock:
                assert state['business'] == 0
            first_failure = wait_for_probe_after(0)
            with lock:
                state['healthy'] = True
            first_success = wait_for_probe_after(first_failure)
            assert request('/')[0] == 503
            with lock:
                state['healthy'] = False
            second_failure = wait_for_probe_after(first_success)
            assert request('/')[0] == 503
            with lock:
                state['healthy'] = True
                baseline = second_failure
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                result = request('/')
                if result[0] == 200:
                    break
                assert result[0] == 503, result
                time.sleep(.05)
            else:
                raise AssertionError('upstream never became ready')
            with lock:
                assert state['probes'] - baseline >= 2, state
            assert request('/least') == (200, b'ok')
            assert request('/connect')[0] == 204
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
