#!/usr/bin/env python3
"""Exercise total upstream HTTP/1 header deadlines on plaintext and HTTPS."""
import argparse
import http.client
import http.server
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import threading
import time


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith('/body'):
            self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n')
            time.sleep(2.5)
            self.connection.sendall(b'x')
        elif self.path.endswith('/interim'):
            try:
                for _ in range(12):
                    self.connection.sendall(b'HTTP/1.1 103 Early Hints\r\n\r\n')
                    time.sleep(.25)
                self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
            except OSError:
                pass
        elif self.path.endswith('/slow'):
            try:
                self.connection.sendall(b'HTTP/1.1 200 OK\r\nX-Partial: ')
                for _ in range(12):
                    time.sleep(.25)
                    self.connection.sendall(b'x')
                self.connection.sendall(b'\r\nContent-Length: 0\r\n\r\n')
            except OSError:
                pass
        else:
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True)
    parser.add_argument('--fixtures', required=True)
    args = parser.parse_args()
    fixtures = Path(args.fixtures).resolve()
    origins = []
    for secure in (False, True):
        origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        origin.daemon_threads = True
        if secure:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(fixtures / 'localhost_cert.pem', fixtures / 'localhost_key.pem')
            origin.socket = context.wrap_socket(origin.socket, server_side=True)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        origins.append(origin)
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='rut-header-timeout-') as directory:
            root = Path(directory)
            source = root / 'gateway.rut'
            source.write_text(
                f'upstream plain {{ host: "127.0.0.1", port: {origins[0].server_port}, response_header_timeout: 1s }}\n'
                f'upstream secure {{ host: "127.0.0.1", port: {origins[1].server_port}, response_header_timeout: 1s, '
                f'tls: {{ ca: "{fixtures / "localhost_cert.pem"}", server_name: "localhost" }} }}\n'
                'route "/plain/:tail" { return forward(plain, load_balance: .roundRobin) }\n'
                'route "/secure/:tail" { return forward(secure, load_balance: .roundRobin) }\n')
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
            for prefix in ('plain', 'secure'):
                for path, expected in (('ok', 200), ('slow', 504), ('interim', 504), ('body', 200), ('ok', 200)):
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
                    try:
                        conn.request('GET', f'/{prefix}/{path}')
                        response = conn.getresponse()
                        status, body = response.status, response.read()
                        assert status == expected, (prefix, path, status, body)
                        if path == 'body':
                            assert body == b'x', (prefix, body)
                    finally:
                        conn.close()
        return 0
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=10)
        for origin in origins:
            origin.shutdown()
            origin.server_close()


if __name__ == '__main__':
    raise SystemExit(main())
