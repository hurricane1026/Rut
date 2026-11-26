#!/usr/bin/env python3
"""Loopback upload gaps remain governed by the client-side timeout."""
import argparse
import http.client
import http.server
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time


class Origin(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True)
    args = parser.parse_args()
    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    origin.daemon_threads = True
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='rut-write-idle-') as directory:
            root = Path(directory)
            source = root / 'gateway.rut'
            source.write_text(
                f'upstream api {{ host: "127.0.0.1", port: {origin.server_port}, write_timeout: 1s }}\n'
                'route POST "/" { return forward(api, load_balance: .roundRobin) }\n')
            log = root / 'gateway.log'
            with log.open('wb') as output:
                process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                                            '--no-pin', '--shards', '1', '--drain', '0'],
                                           stdout=output, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace')
                match = re.search(r'Listening on port (\d+)', text)
                if match:
                    port = int(match[1])
                    break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and 'io_uring is unavailable' in text:
                        return 77
                    raise AssertionError(text)
                time.sleep(.025)
            else:
                raise AssertionError(log.read_text(errors='replace'))
            with socket.create_connection(('127.0.0.1', port), timeout=10) as client:
                client.sendall(b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n'
                               b'Connection: close\r\n\r\na')
                time.sleep(2.5)
                client.sendall(b'bcd')
                response = http.client.HTTPResponse(client)
                response.begin()
                assert response.status == 200, response.status
                assert response.read() == b'abcd'
        return 0
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=10)
        origin.shutdown()
        origin.server_close()


if __name__ == '__main__':
    raise SystemExit(main())
