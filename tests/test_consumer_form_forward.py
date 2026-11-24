#!/usr/bin/env python3
"""Sanitized form-body forwarding on the owned forward effect."""
import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time

from auth_h2_fixture import request as h2_request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', required=True)
    args = parser.parse_args()
    received = []
    lock = threading.Lock()

    class Origin(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_POST(self):
            length = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(length)
            with lock:
                received.append((self.path, dict(self.headers), body))
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, *unused):
            pass

    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    registry = dict(
        version=1,
        consumers=[dict(id='alice', enabled=True, groups=['staff'])],
        credentials=[dict(id='current', consumerId='alice', method='header',
                          secret='custom-key', enabled=True)])
    try:
        with tempfile.TemporaryDirectory(prefix='rut-consumer-form-forward-') as temporary:
            root = Path(temporary)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            source = root / 'gateway.rut'
            shutil.copytree(Path(args.source).resolve().parent / 'middleware', root / 'middleware')
            text = Path(args.source).read_text().replace('listen :8080', f'listen :{port}')
            text = text.replace('127.0.0.1:9000', f'127.0.0.1:{origin.server_port}')
            text = text.replace('/tmp/rut-consumer-form-access.log', str(root / 'access.log'))
            text += (
                '\nroute POST "/chunked-override" {'
                ' return forward(api, load_balance: .roundRobin, set_body: "sanitized") }\n'
                'route POST "/combined" {'
                ' req.remove("Authorization")'
                ' req.remove("X-API-Key")'
                ' req.remove("X-Consumer-ID")'
                ' guard req.uniqueHeader("Content-Type").or("") == "application/x-www-form-urlencoded" else { return 415 }'
                ' guard let identity = consumerAuthenticateForm(req.body, env("AUTH_REGISTRY"), "api_key") else { return 401 }'
                ' guard jwtHasGroup(identity, "staff") else { return 403 }'
                ' guard let body = consumer_form.remainingBody(identity) else { return 503 }'
                ' return forward(api, load_balance: .roundRobin, set_path: "/combined-target", set_body: body) }\n'
                'route POST "/oversize-override" {'
                ' return forward(api, load_balance: .roundRobin, set_body: "' + 'x' * 65537 + '") }\n'
                'func echoBack(_ req: i32, _ resp: Response) -> i32 {'
                ' resp.set("X-Echo-Back", req.uniqueHeader("X-Echo-Back").or("missing")) 0 }\n'
                'chain echo { after echoBack(req, resp) }\n'
                'route POST "/override-echo" use chain echo {'
                ' return forward(api, load_balance: .roundRobin, set_body: "0123456789") }\n')
            source.write_text(text)
            log = root / 'gateway.log'
            with log.open('w') as output:
                process = subprocess.Popen(
                    [args.server, str(source), '--backend', args.backend, '--no-pin',
                     '--shards', '2', '--drain', '0'],
                    env=dict(os.environ, AUTH_REGISTRY=json.dumps(registry)),
                    stdout=output, stderr=subprocess.STDOUT)

            def request(path, body=None, content_type='application/x-www-form-urlencoded',
                        api_key='custom-key'):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=6)
                headers = {'Authorization': 'Bearer custom-key', 'X-Consumer-ID': 'mallory',
                           'X-API-Key': api_key}
                if content_type is not None:
                    headers['Content-Type'] = content_type
                connection.request('POST' if body is not None else 'GET', path, body, headers)
                response = connection.getresponse()
                status = response.status
                response.read()
                connection.close()
                return status

            def chunked(path, body):
                wire = (f'POST {path} HTTP/1.1\r\nHost: local\r\nConnection: close\r\n'
                        'Content-Type: application/x-www-form-urlencoded\r\n'
                        'Transfer-Encoding: chunked\r\n\r\n').encode()
                wire += f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n'
                with socket.create_connection(('127.0.0.1', port), timeout=6) as connection:
                    connection.sendall(wire)
                    data = b''
                    while True:
                        part = connection.recv(65536)
                        if not part:
                            break
                        data += part
                return int(data.split(b' ', 2)[1])

            def raw_response(path, headers, body):
                wire = f'POST {path} HTTP/1.1\r\nHost: local\r\n{headers}\r\n'.encode() + body
                with socket.create_connection(('127.0.0.1', port), timeout=6) as connection:
                    connection.sendall(wire)
                    data = b''
                    while True:
                        part = connection.recv(65536)
                        if not part:
                            break
                        data += part
                head, _, _ = data.partition(b'\r\n\r\n')
                lines = head.split(b'\r\n')
                received_headers = {}
                for line in lines[1:]:
                    name, _, value = line.partition(b':')
                    received_headers[name.strip().lower()] = value.strip()
                return int(lines[0].split(b' ')[1]), received_headers

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
                source.unlink()
                status = request('/form/items', 'a=one+two&api_key=custom-key&b=%2F')
                assert status == 200, status
                h2 = h2_request(port, '/form/h2',
                                [('content-type', 'application/x-www-form-urlencoded')],
                                b'api_key=custom-key&item=1', 'POST')
                assert h2 == (200, b''), h2
                assert request('/form/empty', 'api_key=custom-key') == 200
                assert h2_request(port, '/form/empty',
                                  [('content-type', 'application/x-www-form-urlencoded')],
                                  b'api_key=custom-key', 'POST') == (200, b'')
                with lock:
                    assert [item[2] for item in received] == [
                        b'a=one+two&b=%2F', b'item=1', b'', b''], received
                assert request('/combined', 'a=1&api_key=custom-key') == 200
                with lock:
                    combined = received[-1]
                assert combined[0] == '/combined-target' and combined[2] == b'a=1', combined
                assert h2_request(port, '/combined',
                                  [('content-type', 'application/x-www-form-urlencoded')],
                                  b'a=2&api_key=custom-key', 'POST') == (200, b'')
                with lock:
                    combined_h2 = received[-1]
                assert combined_h2[0] == '/combined-target' and combined_h2[2] == b'a=2', combined_h2
                for path, headers, body in received[:-2]:
                    assert path.startswith('/form/'), path
                    assert headers['Content-Length'] == str(len(body)), headers
                    assert not any(name.lower() in ('authorization', 'x-api-key', 'x-consumer-id')
                                   for name in headers), headers
                    assert 'custom-key' not in str((path, headers, body))
                keepalive = http.client.HTTPConnection('127.0.0.1', port, timeout=6)
                for payload in ('a=1&api_key=custom-key', 'b=2&api_key=custom-key'):
                    keepalive.request('POST', '/form/keep', payload,
                                      {'Content-Type': 'application/x-www-form-urlencoded',
                                       'X-API-Key': 'custom-key'})
                    response = keepalive.getresponse()
                    assert response.status == 200, response.status
                    response.read()
                keepalive.close()
                with lock:
                    assert [item[2] for item in received[-2:]] == [b'a=1', b'b=2'], received[-2:]
                # A response header borrowed from a request header must survive
                # the in-place set_body rewrite. Content-Length is listed first
                # so its length change shifts the borrowed header bytes.
                status, echoed_headers = raw_response(
                    '/override-echo',
                    'Content-Length: 9\r\nX-Echo-Back: needle\r\nConnection: close\r\n',
                    b'012345678')
                assert status == 200, status
                assert echoed_headers.get(b'x-echo-back') == b'needle', echoed_headers
                with lock:
                    assert received[-1][0] == '/override-echo', received[-1]
                    assert received[-1][2] == b'0123456789', received[-1]
                before = len(received)
                for body in ['api_key=', 'api_key=wrong', 'api_key=custom-key&x=1&x=2',
                             'api_key=custom-key&x=%00', 'api_key=custom-key&x=%gg',
                             'api_key=custom-key&']:
                    assert request('/form/reject', body) == 401, body
                assert request('/form/reject', 'api_key=custom-key', 'application/json') == 415
                assert len(received) == before, received
                # Chunked or missing/empty Content-Length body overrides must
                # fail closed before forwarding the original request.
                assert chunked('/chunked-override', b'a=1') == 500
                assert request('/chunked-override', b'') == 500
                assert request('/oversize-override', b'a=1') == 500
                assert len(received) == before, received
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
    print('PASS: form body replacement, H1/H2 redaction and fail-closed framing')


if __name__ == '__main__':
    main()
