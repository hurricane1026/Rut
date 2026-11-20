#!/usr/bin/env python3
"""Exercise source-configured upstream admission through both Linux backends."""

import argparse
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
    entered, release = threading.Event(), threading.Event()
    requests = []
    lock = threading.Lock()

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                requests.append(self.path)
            if self.path == '/hold':
                entered.set()
                if not release.wait(15):
                    return
            self.send_response(200)
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
    held_thread = None
    held = []
    try:
        source = f'''
upstream api {{ host: "127.0.0.1", port: {origin.server_port}, max_inflight: 1 }}
route GET "/hold" {{ return forward(api, load_balance: .roundRobin) }}
route GET "/other" {{ return forward(api, load_balance: .roundRobin) }}
route GET "/jit" {{
    if req.header("X-Test").or("") == "yes" {{
        return forward(api, load_balance: .roundRobin)
    }} else {{
        return 400
    }}
}}
'''
        with tempfile.TemporaryDirectory(prefix='rut-inflight-') as directory:
            root = Path(directory)
            program, log = root / 'gateway.rut', root / 'server.log'
            program.write_text(source)
            with log.open('wb') as output:
                process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                            '--no-pin', '--shards', '2', '--drain', '0'],
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
                raise AssertionError('startup timeout\n' + log.read_text(errors='replace'))

            def h1(path, headers=None):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                try:
                    conn.request('GET', path, headers=headers or {})
                    response = conn.getresponse()
                    return response.status, response.read()
                finally:
                    conn.close()

            held_thread = threading.Thread(target=lambda: held.append(h1('/hold')), daemon=True)
            held_thread.start()
            assert entered.wait(10), 'held request never reached upstream'
            assert h1('/other')[0] == 503
            assert h1('/jit', {'X-Test': 'yes'})[0] == 503
            assert h2_request(port, '/other', [])[0] == 503
            with lock:
                assert requests == ['/hold'], requests
            release.set()
            held_thread.join(10)
            assert held == [(200, b'ok')], held
            assert h1('/other') == (200, b'ok')
            assert h1('/jit', {'X-Test': 'yes'}) == (200, b'ok')
            assert h2_request(port, '/other', []) == (200, b'ok')
    finally:
        release.set()
        if held_thread:
            held_thread.join(10)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=2)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
