#!/usr/bin/env python3
"""RFC 7009 client fixture plus revocation-to-introspection lifecycle over TLS."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    service_auth = 'Basic Y2xpZW50OnNlY3JldA=='
    calls, revoked = [], set()
    owned = {'alice-token', 'session+/==', 'h2-token', 'slow', 'abandoned', 'no-permission'}
    owned.update('concurrent-' + str(i) for i in range(4))
    lock = threading.Lock()

    class Authorizer(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            fields = parse_qs(raw.decode('ascii'), strict_parsing=True)
            token = fields['token'][0]
            with lock:
                calls.append((self.path, dict(self.headers), raw, token))
            status, body = 200, b''
            if self.headers.get('Authorization') != service_auth:
                status, body = 401, b'{"error":"invalid_client"}'
            elif self.path == '/introspect':
                with lock:
                    active = token in owned and token not in revoked
                body = json.dumps(dict(active=active, exp=int(time.time()) + 3600,
                                       aud='reports-api', scope='reports:reader' if token == 'no-permission' else 'reports:read', sub='alice')).encode()
            elif self.path == '/revoke':
                status = {'service-denied': 403, 'server-error': 503, 'redirect': 302,
                          'no-content': 204, 'unsupported': 400, 'foreign-client': 400}.get(token, 200)
                body = {'text-success': b'not JSON, and deliberately ignored',
                        'json-success': b'{"ignored":true}',
                        'malformed-json-success': b'{',
                        'error-body-success': b'{"error":"ignored-under-200"}'}.get(token, b'')
                if token == 'oversized':
                    body = b'x' * 9000
                elif token == 'non-utf8':
                    body = b'\xff'
                if status == 200:
                    with lock:
                        if token in owned:
                            revoked.add(token)
            else:
                status = 404
            time.sleep(.2 if token in ('slow', 'abandoned') and self.path == '/revoke' else .01)
            try:
                if token == 'truncated':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 900\r\n\r\n{}')
                    self.close_connection = True
                    return
                self.send_response(status)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Set-Cookie', 'as-secret=must-not-leak')
                self.send_header('X-Token-Exists', 'must-not-leak')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)
            except (OSError, ssl.SSLError):
                pass

        def log_message(self, *unused):
            pass

    authorizer = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Authorizer)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                            str(Path(args.testdata) / 'localhost_key.pem'))
    authorizer.socket = context.wrap_socket(authorizer.socket, server_side=True)
    threading.Thread(target=authorizer.serve_forever, daemon=True).start()
    examples = Path(__file__).resolve().parent.parent / 'examples'
    endpoint = dict(address='127.0.0.1', port=authorizer.server_port, serverName='localhost',
                    caFile=str(Path(args.testdata) / 'localhost_cert.pem'), path='/revoke')
    try:
        with tempfile.TemporaryDirectory(prefix='rut-oauth-revocation-') as directory:
            root = Path(directory)
            (root / 'middleware').mkdir()
            modules = []
            for name in ('oauth_revocation.rut', 'introspection.rut'):
                module = root / 'middleware' / name
                module.write_bytes((examples / 'middleware' / name).read_bytes())
                modules.append(module)
            source = (examples / 'oauth-revocation.rut').read_text().replace('listen :8080\n', '')
            start = source.index('route POST "/logout"')
            route = source[start:source.index('// No local cached allow:', start)]
            for path, auth, policy, timeout in (
                    ('/timeout', 'env("OAUTH_SERVICE_AUTH")', 'REVOCATION_ENDPOINT', 50),
                    ('/wrong-tls', 'env("OAUTH_SERVICE_AUTH")', 'WRONG_TLS', 1000),
                    ('/bad-service', '"Basic d3Jvbmc6c2VjcmV0"', 'REVOCATION_ENDPOINT', 1000),
                    ('/bad-config', '""', 'REVOCATION_ENDPOINT', 1000),
                    ('/unsafe-config', 'env("UNSAFE_AUTH")', 'REVOCATION_ENDPOINT', 1000)):
                source += route.replace('/logout', path).replace('env("OAUTH_SERVICE_AUTH")', auth).replace(
                    'env("REVOCATION_ENDPOINT")', f'env("{policy}")').replace(', 1000)', f', {timeout})')
            program, log = root / 'gateway.rut', root / 'gateway.log'
            program.write_text(source)
            env = dict(os.environ, OAUTH_SERVICE_AUTH=service_auth, REVOCATION_ENDPOINT=json.dumps(endpoint),
                       INTROSPECTION_ENDPOINT=json.dumps(dict(endpoint, path='/introspect')),
                       WRONG_TLS=json.dumps(dict(endpoint, serverName='wrong.invalid')),
                       UNSAFE_AUTH=service_auth + '\r\nInjected: yes')
            with log.open('wb') as output:
                process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                            '--shards', '2', '--no-pin', '--drain', '0'],
                                           env=env, stdout=output, stderr=subprocess.STDOUT)
                try:
                    port = None
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        startup = log.read_bytes()
                        match = re.search(rb'Listening on port ([0-9]+) with', startup)
                        if match:
                            port = int(match.group(1))
                            break
                        if process.poll() is not None:
                            if args.backend == 'io_uring' and b'io_uring is unavailable' in startup:
                                return 77
                            raise AssertionError(startup.decode(errors='replace'))
                        time.sleep(.02)
                    assert port, log.read_text(errors='replace')
                    program.unlink()
                    for module in modules:
                        module.unlink()

                    def request(token='alice-token', path='/logout', authorization=None):
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                        try:
                            connection.request('GET' if path == '/protected' else 'POST', path, headers={
                                'Authorization': 'Bearer ' + token if authorization is None else authorization,
                                'Cookie': 'client-secret', 'X-Consumer-ID': 'forged'})
                            response = connection.getresponse()
                            return response.status, dict(response.headers), response.read()
                        finally:
                            connection.close()

                    for authorization in ('', 'Basic abc', 'Bearer a&token=stolen', 'Bearer a=b'):
                        status, headers, _ = request(authorization=authorization)
                        assert status == 401 and 'Bearer' in headers.get('WWW-Authenticate', '')
                        assert not calls
                    assert request('x' * 1025)[0] == 503 and not calls
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                    try:
                        connection.request('GET', '/logout', headers={'Authorization': 'Bearer alice-token'})
                        response = connection.getresponse()
                        assert response.status == 405, response.status
                        response.read()
                    finally:
                        connection.close()
                    assert not calls
                    status, headers, _ = request('no-permission', '/protected')
                    assert status == 403 and 'insufficient_scope' in headers.get('WWW-Authenticate', '')
                    assert request('no-permission')[0] == 204
                    assert request('no-permission', '/protected')[0] == 401
                    for token in ('alice-token', 'session+/=='):
                        assert request(token, '/protected')[0] == 200
                        status, headers, body = request(token)
                        assert (status, body) == (204, b'')
                        assert headers.get('Cache-Control') == 'no-store'
                        assert 'Set-Cookie' not in headers and 'X-Token-Exists' not in headers
                        assert request(token, '/protected')[0] == 401
                        assert request(token)[0] == 204  # Same outcome after prior revocation.
                    encoded = next(raw for path, _, raw, token in calls if path == '/revoke' and token == 'session+/==')
                    assert encoded == b'token=session%2B%2F%3D%3D&token_type_hint=access_token'
                    for token in ('unknown-token', 'text-success', 'json-success', 'malformed-json-success',
                                  'error-body-success'):
                        status, headers, body = request(token)
                        assert (status, body) == (204, b''), (token, status, body)
                        assert headers.get('Cache-Control') == 'no-store'
                        assert 'Set-Cookie' not in headers and 'X-Token-Exists' not in headers
                    for token in ('service-denied', 'server-error', 'redirect', 'no-content',
                                  'unsupported', 'foreign-client', 'truncated', 'oversized', 'non-utf8'):
                        before = len(calls)
                        status, _, body = request(token)
                        assert status == 503, (token, status, body)
                        assert len(calls) == before + 1  # No automatic retry or redirect.
                    for path in ('/bad-config', '/unsafe-config', '/wrong-tls', '/bad-service'):
                        before = len(calls)
                        assert request(path=path)[0] == 503, path
                        if path != '/bad-service':
                            assert len(calls) == before
                    before = len(calls)
                    assert request('slow', '/timeout')[0] == 503
                    assert len(calls) == before + 1
                    # A timeout is not proof of rollback: AS state may already be committed.
                    assert 'slow' in revoked
                    with ThreadPoolExecutor(max_workers=4) as workers:
                        results = list(workers.map(lambda i: request('concurrent-' + str(i)), range(4)))
                    assert all((status, body) == (204, b'') for status, _, body in results), results
                    for i in range(4):
                        assert request('concurrent-' + str(i), '/protected')[0] == 401
                    before = len(calls)
                    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                        sock.sendall(b'POST /logout HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer abandoned\r\nContent-Length: 0\r\n\r\n')
                        deadline = time.monotonic() + 2
                        while len(calls) == before and time.monotonic() < deadline:
                            time.sleep(.01)
                        assert len(calls) == before + 1
                    time.sleep(.3)
                    assert request('abandoned', '/protected')[0] == 401

                    def frame(kind, flags, stream, data=b''):
                        return len(data).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + data

                    assert request('h2-token', '/protected')[0] == 200
                    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                        auth = b'Bearer h2-token'
                        block = b'\x83\x86\x04\x07/logout\x01\x09localhost\x0f\x08' + bytes((len(auth),)) + auth
                        sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) + frame(1, 5, 1, block))

                        def exact(length):
                            data = b''
                            while len(data) < length:
                                part = sock.recv(length - len(data))
                                assert part, 'HTTP/2 closed before revocation completed'
                                data += part
                            return data

                        saw_status = False
                        while True:
                            header = exact(9)
                            payload = exact(int.from_bytes(header[:3], 'big'))
                            kind, flags = header[3], header[4]
                            stream = int.from_bytes(header[5:], 'big') & 0x7fffffff
                            if kind == 4 and not flags & 1:
                                sock.sendall(frame(4, 1, 0))
                            assert kind != 7, payload
                            if stream != 1:
                                continue
                            assert kind != 3, payload
                            if kind == 1:
                                assert payload[0] == 0x89, payload  # HPACK indexed :status 204.
                                saw_status = True
                            if kind == 0:
                                assert not payload
                            if kind in (0, 1) and flags & 1:
                                break
                        assert saw_status
                    assert request('h2-token', '/protected')[0] == 401
                    before = len(calls)
                    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                        sock.sendall(b'POST /logout HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer alice-token\r\nAuthorization: Bearer alice-token\r\nContent-Length: 0\r\n\r\n')
                        assert b' 401 ' in sock.recv(4096)
                    assert len(calls) == before
                    for path, headers, raw, token in calls:
                        assert path in ('/revoke', '/introspect')
                        fields = parse_qs(raw.decode('ascii'), strict_parsing=True)
                        assert fields == {'token': [token], 'token_type_hint': ['access_token']}
                        assert headers['Authorization'] in (service_auth, 'Basic d3Jvbmc6c2VjcmV0')
                        assert headers['Content-Type'] == 'application/x-www-form-urlencoded'
                        assert not any(key.lower() in ('cookie', 'x-consumer-id') for key in headers)
                    logged = log.read_bytes()
                    assert service_auth.encode() not in logged and b'session+/==' not in logged
                    assert b'session%2B%2F%3D%3D' not in logged and b'alice-token' not in logged
                    print(f'PASS: {args.backend} revocation, ignored success bodies, HTTP/2, isolation and introspection lifecycle')
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise AssertionError('revocation worker shutdown timed out')
                    if process.returncode not in (0, 77):
                        raise AssertionError((process.returncode, log.read_text(errors='replace')))
    finally:
        authorizer.shutdown()
        authorizer.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
