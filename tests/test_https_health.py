#!/usr/bin/env python3
"""Exercise TLS active health verification, deadline and recovery."""
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True)
    args = parser.parse_args()
    fixtures = Path(__file__).resolve().parent / 'fixtures'
    state = {'stall': False, 'probes': 0, 'hosts': set(), 'sni': set(), 'status': 302}

    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            state['probes'] += 1
            state['hosts'].add(self.headers.get('Host'))
            if state['stall']:
                time.sleep(4)
            try:
                self.wfile.write(b'HTTP/1.1 103 Early Hints\r\n\r\n')
                self.wfile.flush()
                self.send_response(state['status'])
                self.send_header('Content-Length', '0')
                self.end_headers()
            except OSError:
                pass

        def log_message(self, *args):
            pass

    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    origin.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(fixtures / 'localhost_cert.pem', fixtures / 'localhost_key.pem')
    context.set_servername_callback(lambda sock, name, ctx: state['sni'].add(name))
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-https-health-') as directory:
            root = Path(directory)
            cert = fixtures / 'localhost_cert.pem'
            other = fixtures / 'mtls_second_cert.pem'
            source = root / 'gateway.rut'
            source.write_text(''.join(
                f'upstream {name} {{ host: "127.0.0.1", port: {origin.server_port}, '
                f'tls: {{ ca: "{ca}", server_name: "{hostname}" }}, '
                'minimum_healthy_weight_percent: 100, '
                f'health_check: {{ path: "/health", interval: 1s, timeout: 1s{host}, '
                'healthy_statuses: [200, 302], unhealthy_statuses: [503] } }\n'
                f'route GET "/{name}" {{ let ev = wait(upstream({name}).connect()) '
                'if ev.ok { return 204 } else { return 502 } }\n'
                for name, ca, hostname, host in [('good', cert, 'localhost', ', host: "Tenant.Example:8443"'),
                                           ('default', cert, 'localhost', ''),
                                           ('wrong', cert, 'wrong.example', ''),
                                           ('untrusted', other, 'localhost', '')]))
            log = root / 'gateway.log'
            with log.open('w') as output:
                process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                    '--shards', '1', '--no-pin', '--drain', '0'], stdout=output, stderr=subprocess.STDOUT)
            try:
                def wait(predicate, message):
                    deadline = time.monotonic() + 12
                    while time.monotonic() < deadline:
                        if predicate():
                            return
                        if process.poll() is not None:
                            if args.backend == 'io_uring' and 'io_uring is unavailable' in log.read_text(errors='replace'):
                                raise SystemExit(77)
                            break
                        time.sleep(.05)
                    raise AssertionError(message + '\n' + log.read_text(errors='replace'))

                port = [None]
                def started():
                    match = re.search(r'Listening on port (\d+)', log.read_text(errors='replace'))
                    if match:
                        port[0] = int(match[1])
                    return bool(match)
                wait(started, 'startup failed')

                def request(path):
                    connection = http.client.HTTPConnection('127.0.0.1', port[0], timeout=5)
                    try:
                        connection.request('GET', path)
                        response = connection.getresponse()
                        response.read()
                        return response.status
                    finally:
                        connection.close()
                wait(lambda: state['probes'] > 0 and request('/good') == 204, 'trusted probe failed')
                wait(lambda: request('/default') == 204 and
                     f'127.0.0.1:{origin.server_port}' in state['hosts'] and
                     'Tenant.Example:8443' in state['hosts'], 'probe Host mismatch')
                assert 'localhost' in state['sni']
                wait(lambda: request('/wrong') == 503 and request('/untrusted') == 503,
                     'invalid TLS identity or trust did not eject')
                state['status'] = 301
                before = state['probes']
                wait(lambda: state['probes'] >= before + 3, 'neutral status was not probed')
                assert request('/good') == 204, 'neutral status ejected healthy target'
                state['status'] = 503
                wait(lambda: request('/good') == 503, 'listed unhealthy status did not eject')
                state['status'] = 301
                before = state['probes']
                wait(lambda: state['probes'] >= before + 3, 'neutral status was not reprobed')
                assert request('/good') == 503, 'neutral status restored unhealthy target'
                state['status'] = 200
                wait(lambda: request('/good') == 204, 'listed status did not recover')
                state['stall'] = True
                wait(lambda: request('/good') == 503, 'stalled probe did not time out')
                state['stall'] = False
                wait(lambda: request('/good') == 204, 'probe did not recover')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
