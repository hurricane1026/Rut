#!/usr/bin/env python3
"""Verify real TCP-only probes and health-driven routing on Linux backends."""
import argparse
from contextlib import contextmanager
from pathlib import Path
import re
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

from auth_h2_fixture import request as h2_request


class Origin(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port=0):
        super().__init__(('127.0.0.1', port), Handler)
        self.probes = 0
        self.requests = 0
        self.unexpected = 0
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        data = self.request.recv(4096)
        if not data:
            self.server.probes += 1  # gateway closed after committing its TCP verdict
            return
        self.server.requests += 1
        if not data.startswith(b'GET '):
            self.server.unexpected += 1
            return
        while b'\r\n\r\n' not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')


def until(predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.025)
    assert predicate(), 'health transition deadline expired'


@contextmanager
def gateway(args, source):
    with tempfile.TemporaryDirectory(prefix='rut-tcp-health-') as directory:
        root = Path(directory)
        program = root / 'gateway.rut'
        program.write_text(source)
        log = root / 'gateway.log'
        with log.open('wb') as output:
            process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                        '--shards', '1', '--no-pin', '--drain', '0'],
                                       stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace')
                match = re.search(r'Listening on port ([0-9]+) with', text)
                if match:
                    yield int(match[1])
                    break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and 'io_uring is unavailable' in text:
                        raise SystemExit(77)
                    raise AssertionError(text)
                time.sleep(.025)
            else:
                raise AssertionError(log.read_text())
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    origins = [Origin() for _ in range(5)]
    first, second, h2, tls, disabled = origins
    port_a, port_b, port_h2, port_tls, port_disabled = [o.server_address[1] for o in origins]
    cert = (Path(__file__).parent / 'fixtures' / 'localhost_cert.pem').resolve()
    source = f'''
upstream api {{
    backends: ["127.0.0.1:{port_a}": 1, "127.0.0.1:{port_b}": 1, "127.0.0.1:{port_disabled}": 0]
    minimum_healthy_weight_percent: 51
    health_check: {{ type: .tcp interval: 1s timeout: 1s failure_threshold: 2 success_threshold: 2 }}
}}
upstream h2 {{
    host: "127.0.0.1" port: {port_h2} protocol: .http2
    health_check: {{ type: .tcp interval: 1s timeout: 1s }}
}}
upstream secure {{
    host: "127.0.0.1" port: {port_tls}
    tls: {{ ca: "{cert}" server_name: "localhost" }}
    health_check: {{ type: .tcp interval: 1s timeout: 1s }}
}}
route GET "/" {{ return forward(api, load_balance: .roundRobin) }}
'''
    try:
        with gateway(args, source) as port:
            until(lambda: min(first.probes, second.probes, h2.probes, tls.probes) >= 2)
            assert disabled.probes == disabled.requests == 0
            assert h2.requests == tls.requests == 0, 'TCP probes sent HTTP or TLS bytes'
            assert h2_request(port, '/', [])[0] == 200
            first.stop()
            origins.remove(first)
            # Do not issue business requests during ejection: passive connect
            # failures must not be mistaken for active TCP-health evidence.
            baseline = second.probes
            until(lambda: second.probes >= baseline + 3)
            contacts = second.requests
            assert h2_request(port, '/', [])[0] == 503
            assert second.requests == contacts, 'health floor contacted an origin'
            recovered = Origin(port_a)
            origins.append(recovered)
            until(lambda: recovered.probes >= 2)
            assert h2_request(port, '/', [])[0] == 200
            assert h2.requests == tls.requests == h2.unexpected == tls.unexpected == 0
            assert disabled.probes == disabled.requests == 0
        print(f'TCP health {args.backend}: probe-only HTTP/2/TLS targets, zero application bytes, '
              'zero weight, active ejection before traffic, capacity floor and recovery passed')
    finally:
        for origin in origins:
            origin.stop()


if __name__ == '__main__':
    main()
