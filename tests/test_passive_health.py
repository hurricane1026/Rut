#!/usr/bin/env python3
"""Live passive-health verdicts, endpoint isolation on both Linux backends."""
import argparse
from contextlib import contextmanager
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


class Origin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=0):
        super().__init__(('127.0.0.1', port), Handler)
        self.codes = []
        self.observed = 0
        self.persistent = True
        self.large_body = False
        self.informational = False
        self.probes = 0
        self.probe_healthy = False


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        origin = self.server
        if self.path == '/healthz':
            origin.probes += 1
            code = 200 if origin.probe_healthy else 500
        else:
            index = origin.observed
            origin.observed += 1
            code = origin.codes[min(index, len(origin.codes) - 1)]
        if origin.informational:
            self.wfile.write(b'HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n')
        body = b'x' * (65536 if origin.large_body else 1)
        headers = (f'HTTP/1.1 {code} Origin\r\nContent-Length: {len(body)}\r\n' +
                   ('' if origin.persistent else 'Connection: close\r\n') + '\r\n').encode()
        # Force a final status line split across reads, following any informational reply.
        self.wfile.write(headers[:11])
        self.wfile.flush()
        time.sleep(.005)
        self.wfile.write(headers[11:] + body)
        self.close_connection = not origin.persistent

    def log_message(self, *_):
        pass


POLICY = '''passive_health: {
    tcp_failures: 2, timeouts: 2, http_failures: 2, successes: 1,
    healthy_statuses: [200], unhealthy_statuses: [503]
}'''


@contextmanager
def gateway(args, endpoints, selection, policy=POLICY, floor=1):
    with tempfile.TemporaryDirectory(prefix='rut-passive-health-') as directory:
        root = Path(directory)
        source = root / 'gateway.rut'
        source.write_text(f'''upstream api {{
    backends: [{endpoints}]
    minimum_healthy_weight_percent: {floor}
    {policy}
}}
route GET "/" {{ return forward(api, load_balance: .{selection}''' +
            (', hash_key: "fixed", hash_seed: "0123456789abcdef0123456789abcdef"'
             if selection == 'consistentHash' else '') + ') }\n')
        log = root / 'gateway.log'
        with log.open('wb') as output:
            process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                                        '--shards', '1', '--no-pin', '--drain', '0'],
                                       stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace')
                match = re.search(r'Listening on port ([0-9]+) with', text)
                if match:
                    yield int(match[1]), process, source
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
    origin = Origin()
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f'"127.0.0.1:{origin.server_port}"'
        for protocol in ('h1', 'h2'):
            for selection in ('roundRobin', 'leastRequests', 'consistentHash'):
                origin.codes = [503, 404, 200, 503, 503, 200]
                origin.observed = 0
                origin.persistent = protocol == 'h1'
                origin.large_body = protocol == 'h1'
                origin.informational = True
                with gateway(args, endpoint, selection) as (port, _, __):
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    try:
                        def request():
                            if protocol == 'h2':
                                return h2_request(port, '/', [])
                            connection.request('GET', '/')
                            response = connection.getresponse()
                            return response.status, response.read()
                        for expected in (503, 404, 200, 503, 503):
                            code, body = request()
                            assert code == expected, (protocol, selection, expected, code, body[:40])
                        assert origin.observed == 5, (protocol, selection, origin.observed)
                        # Health floor rejects before upstream I/O. No timed passive recovery.
                        for _ in range(3):
                            code, body = request()
                            assert code == 503, (protocol, selection, code, origin.observed, body[:40])
                        assert origin.observed == 5, (protocol, selection, origin.observed)
                    finally:
                        connection.close()
        # TCP connection errors get their own threshold, not HTTP counters.
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))  # bound, not listening: deterministic ECONNREFUSED
            refused = f'"127.0.0.1:{reserved.getsockname()[1]}"'
            for protocol in ('h1', 'h2'):
                with gateway(args, refused, 'roundRobin') as (port, _, __):
                    results = []
                    for _ in range(3):
                        if protocol == 'h2':
                            results.append(h2_request(port, '/', [])[0])
                        else:
                            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                            try:
                                connection.request('GET', '/')
                                response = connection.getresponse()
                                response.read()
                                results.append(response.status)
                            finally:
                                connection.close()
                    assert results == [502, 502, 503], (protocol, results)
        # A healthy second target remains selectable after connect failures.
        origin.codes = [200]
        origin.observed = 0
        origin.persistent = False
        origin.large_body = False
        origin.informational = False
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            refused_port = reserved.getsockname()[1]
            endpoints = f'"127.0.0.1:{refused_port}": 1, {endpoint}: 1'
            with gateway(args, endpoints, 'leastRequests') as (port, _, __):
                assert [h2_request(port, '/', [])[0] for _ in range(2)] == [200, 200]
                reserved.close()
                resurrected = Origin(refused_port)
                resurrected.codes = [200]
                resurrected.persistent = False
                resurrected_thread = threading.Thread(target=resurrected.serve_forever, daemon=True)
                resurrected_thread.start()
                try:
                    origin.observed = 0
                    results = [h2_request(port, '/', [])[0] for _ in range(8)]
                    assert results == [200] * len(results), results
                    assert resurrected.observed == 0, resurrected.observed
                    assert origin.observed == len(results), (origin.observed, results)
                finally:
                    resurrected.shutdown()
                    resurrected.server_close()
                    resurrected_thread.join(timeout=2)
        # Active checks restore a latched passive target only after their full streak.
        origin.codes = [503, 503, 200]
        origin.observed = origin.probes = 0
        origin.probe_healthy = False
        active = POLICY + '\nhealth_check: { path: "/healthz", interval: 1s, status: 200, ' + \
                 'failure_threshold: 255, success_threshold: 2 }'
        with gateway(args, endpoint, 'roundRobin', policy=active) as (port, _, __):
            assert h2_request(port, '/', [])[0] == 503
            assert h2_request(port, '/', [])[0] == 503
            assert origin.observed == 2
            assert h2_request(port, '/', [])[0] == 503
            assert origin.observed == 2
            origin.probe_healthy = True
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                if h2_request(port, '/', [])[0] == 200:
                    break
                time.sleep(.025)
            else:
                raise AssertionError(('active recovery timeout', origin.probes, origin.observed))
            assert origin.probes >= 2
            assert origin.observed == 3
        print(f'passive health {args.backend}: H1/H2, all LB policies, informational/large replies, '
              'counter reset, latching, TCP thresholds and failover passed')
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=2)


if __name__ == '__main__':
    main()
