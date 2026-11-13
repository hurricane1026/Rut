#!/usr/bin/env python3
"""Explicit source admission, canonical duplicates, real TLS upstream redaction."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from auth_h2_fixture import request as h2_request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', required=True)
    args = parser.parse_args()
    received = []
    lock = threading.Lock()

    class Origin(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            with lock:
                received.append((self.path, dict(self.headers), body))
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, *unused):
            pass

    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                            str(Path(args.testdata) / 'localhost_key.pem'))
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    registry = dict(version=1, consumers=[dict(id='alice', enabled=True, groups=['staff'])],
                    credentials=[dict(id='current', consumerId='alice', method='header',
                                      secret='custom-key', enabled=True)])
    policy = dict(address='127.0.0.1', port=origin.server_port, serverName='localhost',
                  caFile=str(Path(args.testdata) / 'localhost_cert.pem'), path='/submit')
    try:
        with tempfile.TemporaryDirectory(prefix='rut-consumer-fields-') as temporary:
            root = Path(temporary)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            source = root / 'gateway.rut'
            source.write_text(Path(args.source).read_text().replace('listen :8080', f'listen :{port}'))
            log = root / 'gateway.log'
            with log.open('w') as output:
                process = subprocess.Popen([args.server, str(source), '--backend', args.backend,
                                            '--no-pin', '--shards', '2', '--drain', '0'],
                    env=dict(os.environ, AUTH_REGISTRY=json.dumps(registry),
                             CONSUMER_SUBMIT_ENDPOINT=json.dumps(policy)), stdout=output,
                    stderr=subprocess.STDOUT)
            def request(path, body=None, fields=None):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=6)
                headers = {'Authorization': 'Bearer custom-key', 'X-Consumer-ID': 'mallory',
                           'X-API-Key': 'custom-key'}
                if body is not None:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                headers.update(fields or {})
                connection.request('POST' if body is not None else 'GET', path, body, headers)
                response = connection.getresponse()
                status = response.status
                response.read()
                connection.close()
                return status
            try:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        if args.backend == 'io_uring' and 'io_uring is unavailable' in log.read_text():
                            raise SystemExit(77)
                        raise AssertionError(log.read_text())
                    try:
                        if request('/ready') == 204:
                            break
                    except OSError:
                        pass
                    assert time.monotonic() < deadline, log.read_text()
                    time.sleep(.025)
                source.unlink()  # All later routes execute the published native artifact.
                assert request('/query?a=one+two&api%5fkey=custom%2Dkey&b=%2F') == 204
                assert request('/form', 'a=one+two&api_key=custom-key&b=%2F') == 204
                assert h2_request(port, '/query?api_key=custom-key&item=1', []) == (204, b'')
                assert h2_request(port, '/form', [('content-type', 'application/x-www-form-urlencoded')],
                                  b'api_key=custom-key&item=2', 'POST') == (204, b'')
                with lock:
                    assert [item[2] for item in received] == [b'a=one+two&b=%2F', b'a=one+two&b=%2F', b'item=1', b'item=2'], received
                before = len(received)
                for encoded in ['', 'api_key=', 'api_key=wrong',
                                'api_key=custom-key&api%5Fkey=custom-key',
                                'api_key=custom-key&x=1&x=2', 'api_key=custom-key&x=%00',
                                'api_key=custom-key;x=1', 'api_key=custom-key&x=%gg',
                                'api_key=custom-key&', 'api_key=custom-key&=empty']:
                    assert request('/query?' + encoded) == 401, encoded
                    assert request('/form', encoded) == 401, encoded
                assert request('/form?api_key=custom-key', 'item=1') == 401
                assert request('/query', 'api_key=custom-key') == 404
                assert request('/form', 'api_key=custom-key', {'Content-Type': 'application/json'}) == 415
                assert h2_request(port, '/form', [('content-type', 'application/x-www-form-urlencoded'),
                    ('content-type', 'application/x-www-form-urlencoded')], b'api_key=custom-key', 'POST')[0] == 415
                assert len(received) == before, received
                with ThreadPoolExecutor(max_workers=4) as executor:
                    assert list(executor.map(lambda _: request('/query?api_key=custom-key&item=3'), range(8))) == [204] * 8
                for path, headers, body in received:
                    assert path == '/submit'
                    assert headers['X-Consumer-ID'] == 'alice', headers
                    assert 'custom-key' not in str((path, headers, body)), (path, headers, body)
                    assert not any(name.lower() in ('authorization', 'x-api-key') for name in headers)
            finally:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                assert 'custom-key' not in log.read_text(), log.read_text()
    finally:
        origin.shutdown()
        origin.server_close()
    print('PASS: explicit query/form keys, encoded duplicates, H1/H2, TLS redaction and concurrent shards')


if __name__ == '__main__':
    main()
