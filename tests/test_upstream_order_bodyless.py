#!/usr/bin/env python3
"""Exercise strict upstream-order bodyless responses and downstream persistence."""
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

    class Origin(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            if self.path == '/empty':
                self.send_response_only(204)
                self.send_header('X-Origin', 'empty')
            else:
                self.send_response_only(304)
                if self.path == '/metadata':
                    self.send_header('Content-Length', '123')
                self.send_header('X-Origin', 'cached')
            self.send_header('Date', 'Mon, 01 Jan 2024 00:00:00 GMT')
            self.end_headers()

        def log_message(self, *unused):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='rut-bodyless-order-') as tmp:
            root = Path(tmp)
            source, log = root / 'app.rut', root / 'server.log'
            route = '''return forward(api, load_balance: .roundRobin, request_policy: {
                version: .http11, host: .preserve, connection: .omit,
                header_names: .lowercase, forwarded_proto: .http,
                strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade, .proxyConnection]
            }, response_policy: {
                version: .http11, framing: .contentLength, connection: .request,
                header_order: .upstream, header_names: .lowercase,
                connection_header: .closeOnly, status_reason: .canonical,
                server: "envoy", date: .preserveOrCurrent, hide_headers: []
            })'''
            source.write_text(f'upstream api at "127.0.0.1:{origin.server_port}"\n' +
                              ''.join(f'route GET "{path}" {{ {route} }}\n'
                                      for path in ('/empty', '/metadata', '/no-length')))
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
                raise AssertionError('gateway startup timeout\n' + log.read_text(errors='replace'))
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                for path, status, length in [('/empty', 204, None), ('/metadata', 304, '123'),
                                              ('/no-length', 304, None), ('/empty', 204, None)]:
                    conn.request('GET', path)
                    response = conn.getresponse()
                    assert response.status == status, (path, response.status)
                    assert response.getheader('Content-Length') == length
                    assert response.read() == b''
                    assert response.getheader('X-Origin') in ('empty', 'cached')
            finally:
                conn.close()
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                client.settimeout(5)
                client.sendall(b'GET /empty HTTP/1.1\r\nHost: test\r\n\r\n'
                               b'GET /metadata HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n')
                wire = bytearray()
                while True:
                    part = client.recv(4096)
                    if not part:
                        break
                    wire.extend(part)
                blocks = bytes(wire).split(b'\r\n\r\n')
                assert len(blocks) == 3 and blocks[2] == b'', wire
                assert blocks[0].startswith(b'HTTP/1.1 204 '), wire
                assert blocks[1].startswith(b'HTTP/1.1 304 '), wire
                assert b'content-length: 123\r\n' in blocks[1] + b'\r\n', wire
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
