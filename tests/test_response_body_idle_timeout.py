#!/usr/bin/env python3
"""Exercise the opt-in HTTP/1 origin body idle deadline on loopback."""
import argparse
import http.client
import http.server
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        try:
            if self.path.endswith('/paced'):
                self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n')
                for _ in range(8):
                    self.connection.sendall(b'x')
                    time.sleep(.4)
            elif self.path.endswith('/backpressure'):
                self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8388608\r\n\r\n')
                self.connection.sendall(b'z' * 8388608)
            elif self.path.endswith('/stall'):
                self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx')
                time.sleep(4)
                self.connection.sendall(b'y')
            else:
                self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
        except OSError:
            pass

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
        with tempfile.TemporaryDirectory(prefix='rut-body-idle-') as directory:
            root = Path(directory)
            source = root / 'gateway.rut'
            source.write_text(
                f'upstream api {{ host: "127.0.0.1", port: {origin.server_port}, '
                'response_body_idle_timeout: 2s }\n'
                'route "/:tail" { return forward(api, load_balance: .roundRobin) }\n')
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
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
            conn.request('GET', '/paced')
            response = conn.getresponse()
            assert response.status == 200 and response.read() == b'xxxxxxxx'
            conn.request('GET', '/ok')
            response = conn.getresponse()
            assert response.status == 200 and response.read() == b'ok'
            conn.request('GET', '/backpressure')
            response = conn.getresponse()
            assert response.status == 200
            time.sleep(3)
            assert response.read() == b'z' * 8388608
            conn.request('GET', '/stall')
            response = conn.getresponse()
            assert response.status == 200
            try:
                response.read()
                raise AssertionError('stalled body was not truncated')
            except http.client.IncompleteRead as exc:
                assert exc.partial == b'x', exc.partial
            conn.close()
        return 0
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=10)
        origin.shutdown()
        origin.server_close()


if __name__ == '__main__':
    raise SystemExit(main())
