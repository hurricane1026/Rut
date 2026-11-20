#!/usr/bin/env python3
"""Exercise source upstream-attempt logging with real proxy requests."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

from test_cli_access_log_host import known_io_uring_environment_failure


def exercise(binary, backend, upstream_port, dead_port):
    with tempfile.TemporaryDirectory(prefix='rut-attempt-log-') as tmp:
        directory = Path(tmp)
        log = directory / 'access.log'
        source = directory / 'app.rut'
        source.write_text(f'''
accessLog {{ path: "{log}", format: upstreamAttempts, publication: live }}
upstream api {{ backends: ["127.0.0.1:{dead_port}", "127.0.0.1:{upstream_port}"] }}
route GET "/local" {{ return 204 }}
route GET "/forward" {{ return forward(api, load_balance: .roundRobin) }}
''')
        output = directory / 'server.log'
        with output.open('wb') as stream:
            process = subprocess.Popen([binary, '0', str(source), '--shards', '1', '--no-pin',
                                        '--drain', '0', '--backend', backend],
                                       stdout=stream, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            port = None
            while time.monotonic() < deadline:
                text = output.read_text(errors='replace')
                match = re.search(r'Listening on port (\d+) with', text)
                if match:
                    port = int(match[1])
                    break
                if process.poll() is not None:
                    if backend == 'io_uring' and known_io_uring_environment_failure(text):
                        return
                    raise AssertionError(text)
                time.sleep(.025)
            assert port is not None, output.read_text(errors='replace')
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                for path, expected in [('/local', 204), ('/forward', 200)]:
                    connection.request('GET', path)
                    response = connection.getresponse()
                    assert response.status == expected
                    response.read()
            finally:
                connection.close()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                lines = log.read_text().splitlines()
                if len(lines) >= 2:
                    break
                time.sleep(.025)
            assert lines == ['204 0', '200 2'], lines
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)


def main():
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'ok')

        def log_message(self, *unused):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    dead = socket.socket()
    dead.bind(('127.0.0.1', 0))
    try:
        for backend in ('epoll', 'io_uring'):
            exercise(sys.argv[1], backend, origin.server_port, dead.getsockname()[1])
    finally:
        dead.close()
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=2)


if __name__ == '__main__':
    main()
