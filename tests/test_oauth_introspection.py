#!/usr/bin/env python3
"""RFC 7662 protocol fixture over verified TLS and native-loaded Rut routes."""
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
    received, forwarded = [], []
    lock = threading.Lock()
    service_auth = 'Basic Y2xpZW50OnNlY3JldA=='
    revoked = threading.Event()

    class Authorizer(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            fields = parse_qs(raw.decode('ascii'), strict_parsing=True)
            assert set(fields) == {'token', 'token_type_hint'}, fields
            assert fields['token_type_hint'] == ['access_token']
            assert len(fields['token']) == 1
            token = fields['token'][0]
            with lock:
                received.append((self.path, dict(self.headers), raw, token))
            now = int(time.time())
            body = dict(active=True, exp=now + 3600, aud=['other-api', 'reports-api'],
                        scope='reports:read reports:write', sub='subject-' + token,
                        iss='https://issuer.example', client_id='reports-client')
            updates = {
                'inactive': dict(active=False), 'revoked': dict(active=not revoked.is_set()),
                'expired': dict(exp=now - 1), 'future-nbf': dict(nbf=now + 3600),
                'future-iat': dict(iat=now + 3600), 'wrong-audience': dict(aud='another-api'),
                'bad-audience': dict(aud=['reports-api', 7]), 'typed-active': dict(active='true'),
                'typed-exp': dict(exp=str(now + 3600)), 'typed-scope': dict(scope=['reports:read']),
                'wrong-scope': dict(scope='reports:reader'), 'wrong-type': dict(token_type='MAC'),
                'read-only': dict(scope='reports:read'), 'write-only': dict(scope='reports:write'),
                'scope-case': dict(scope='Reports:read Reports:write'),
                'scope-prefix': dict(scope='reports:reader reports:writer'),
                'scope-repeated': dict(scope='reports:read reports:read reports:write'),
                'scope-bad-suffix': dict(scope='reports:read reports:write\t'),
                'scope-double-space': dict(scope='reports:read  reports:write'),
                'scope-nul': dict(scope='reports:read\x00 reports:write'),
                'scope-empty': dict(scope=''), 'scope-null': dict(scope=None),
                'wrong-issuer': dict(iss='https://other.example'),
                'issuer-case': dict(iss='https://ISSUER.example'),
                'issuer-suffix': dict(iss='https://issuer.example/'),
                'wrong-client': dict(client_id='another-client'),
                'service-client': dict(client_id='client'),
                'client-case': dict(client_id='Reports-client'),
                'client-prefix': dict(client_id='reports-client-extra'),
                'empty-issuer': dict(iss=''), 'typed-issuer': dict(iss=True),
                'array-issuer': dict(iss=['https://issuer.example']),
                'null-issuer': dict(iss=None),
                'empty-client': dict(client_id=''), 'typed-client': dict(client_id=42),
                'object-client': dict(client_id={'id': 'reports-client'}),
                'null-client': dict(client_id=None),
                'nul-issuer': dict(iss='https://issuer.example\x00'),
                'nul-client': dict(client_id='reports-client\x00'),
                'no-subject': dict(sub=''),
                'typed-subject': dict(sub=True), 'unsafe-subject': dict(sub='alice\r\nInjected: yes'),
            }
            body.update(updates.get(token, {}))
            if token == 'no-expiry':
                del body['exp']
            if token == 'no-scope':
                del body['scope']
            if token == 'no-subject':
                del body['sub']
            if token == 'no-issuer':
                del body['iss']
            if token == 'no-client':
                del body['client_id']
            data = json.dumps(body).encode()
            if token == 'escaped-binding':
                data = data.replace(b'issuer.example', b'issu\\u0065r.example')
                data = data.replace(b'reports-client', b'reports-clie\\u006et')
            if token == 'escaped-binding-names':
                data = data.replace(b'"iss"', b'"i\\u0073s"')
                data = data.replace(b'"client_id"', b'"client\\u005fid"')
            if token == 'escaped-scope':
                data = data.replace(b'reports:read', b'reports:r\\u0065ad')
                data = data.replace(b'"scope"', b'"sc\\u006fpe"')
            if token == 'duplicate-scope':
                data = data[:-1] + b', "sc\\u006fpe":"reports:write"}'
            if token == 'duplicate-client':
                data = data[:-1] + b', "client_id":"other"}'
            if token == 'aliased-issuer':
                data = data[:-1] + b', "i\\u0073s":"https://other.example"}'
            if token == 'malformed':
                data = b'{'
            elif token == 'duplicate':
                data = b'{"active":false,"act\\u0069ve":true,"aud":"reports-api","exp":9999999999}'
            elif token == 'large':
                data = b'x' * 9000
            status = {'redirect': 302, 'unavailable': 503, 'service-denied': 403}.get(token, 200)
            if self.headers.get('Authorization') != service_auth:
                status = 401
            assert self.headers.get('Content-Type') == 'application/x-www-form-urlencoded'
            assert self.headers.get('Accept') == 'application/json'
            if token == 'slow':
                time.sleep(.25)
            else:
                time.sleep(.02)  # Exercise actual timer suspension/continuation.
            try:
                if token == 'truncated':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 900\r\n\r\n{}')
                    self.close_connection = True
                    return
                self.send_response(status)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Content-Type', 'application/json')
                self.send_header('Set-Cookie', 'service-secret=must-not-leak')
                self.send_header('X-Consumer-ID', 'header-must-not-supply-identity')
                self.send_header('X-Token-Issuer', 'https://issuer.example')
                self.send_header('X-OAuth-Client-ID', 'reports-client')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)
            except (OSError, ssl.SSLError):
                pass

        def log_message(self, *unused):
            pass

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                forwarded.append(dict(self.headers))
            body = self.headers.get('X-Consumer-ID', '').encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *unused):
            pass

    authorizer = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Authorizer)
    upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                            str(Path(args.testdata) / 'localhost_key.pem'))
    authorizer.socket = context.wrap_socket(authorizer.socket, server_side=True)
    for server in (authorizer, upstream):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    examples = Path(__file__).resolve().parent.parent / 'examples'
    endpoint = dict(address='127.0.0.1', port=authorizer.server_port, serverName='localhost',
                    caFile=str(Path(args.testdata) / 'localhost_cert.pem'), path='/introspect')
    try:
        with tempfile.TemporaryDirectory(prefix='rut-introspection-') as directory:
            root = Path(directory)
            (root / 'middleware').mkdir()
            module = root / 'middleware' / 'introspection.rut'
            module.write_bytes((examples / 'middleware' / 'introspection.rut').read_bytes())
            source = (examples / 'oauth-introspection.rut').read_text()
            source = source.replace('listen :8080\n', '').replace(':9000"', f':{upstream.server_port}"')
            for path, auth, policy, timeout in (
                    ('/timeout', 'env("INTROSPECTION_AUTH")', 'INTROSPECTION_ENDPOINT', 50),
                    ('/bad-service', '"Bearer wrong-service"', 'INTROSPECTION_ENDPOINT', 1000),
                    ('/wrong-tls', 'env("INTROSPECTION_AUTH")', 'WRONG_TLS', 1000),
                    ('/bad-config', '""', 'INTROSPECTION_ENDPOINT', 1000)):
                source += f'''
route GET "{path}" {{
    let request = introspection.request(req.authorization.or(""), {auth})
    let pending = httpCall(env("{policy}"), request, {timeout})
    guard let reply = pending else {{ return 503 }}
    let document = introspection.requireActive(reply, "reports-api")
    return 204
}}
'''
            for path, issuer, client in (
                    ('/empty-issuer', '', 'reports-client'),
                    ('/empty-client', 'https://issuer.example', '')):
                source += f'''
route GET "{path}" {{
    let request = introspection.request(req.authorization.or(""), env("INTROSPECTION_AUTH"))
    let pending = httpCall(env("INTROSPECTION_ENDPOINT"), request, 1000)
    guard let reply = pending else {{ return 503 }}
    let document = introspection.requireActive(reply, "reports-api")
    let bound = introspection.requireBinding(document, {json.dumps(issuer)}, {json.dumps(client)})
    return 204
}}
'''
            scope_configuration = {}
            invalid_scope_paths = []
            # A valid first branch must never hide an invalid second OR policy.
            for index, (first, second) in enumerate((
                    ('', 'reports:write'), ('reports:read', ''),
                    ('reports:read reports:write', 'reports:write'),
                    ('reports:read', 'reports:write extra'),
                    ('reports:read', 'reports:write\t'),
                    ('reports:read', 'bad"scope'),
                    ('reports:read', 'bad\\scope'),
                    ('reports:read', 'réports:write'))):
                scope_configuration[f'SCOPE_FIRST_{index}'] = first
                scope_configuration[f'SCOPE_SECOND_{index}'] = second
                for helper in ('requireEitherScope', 'requireBothScopes'):
                    path = f'/scope-policy-{index}-{helper}'
                    invalid_scope_paths.append(path)
                    source += f'''
route GET "{path}" {{
    let request = introspection.request(req.authorization.or(""), env("INTROSPECTION_AUTH"))
    let pending = httpCall(env("INTROSPECTION_ENDPOINT"), request, 1000)
    guard let reply = pending else {{ return 503 }}
    let document = introspection.requireActive(reply, "reports-api")
    let authorized = introspection.{helper}(document, env("SCOPE_FIRST_{index}"), env("SCOPE_SECOND_{index}"))
    return 204
}}
'''
            for helper in ('requireEitherScope', 'requireBothScopes'):
                source += f'''
route GET "/same-scope-{helper}" {{
    let request = introspection.request(req.authorization.or(""), env("INTROSPECTION_AUTH"))
    let pending = httpCall(env("INTROSPECTION_ENDPOINT"), request, 1000)
    guard let reply = pending else {{ return 503 }}
    let document = introspection.requireActive(reply, "reports-api")
    let authorized = introspection.{helper}(document, "reports:read", "reports:read")
    return 204
}}
'''
            program, log = root / 'gateway.rut', root / 'gateway.log'
            program.write_text(source)
            env = dict(os.environ, INTROSPECTION_AUTH=service_auth, INTROSPECTION_ENDPOINT=json.dumps(endpoint),
                       WRONG_TLS=json.dumps(dict(endpoint, serverName='wrong.invalid')),
                       TOKEN_ISSUER='https://issuer.example', TOKEN_CLIENT_ID='reports-client',
                       **scope_configuration)
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
                    module.unlink()  # Native artifacts must own code/config after compiler exit.

                    def request(token='valid', path='/reports', authorization=None):
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                        try:
                            connection.request('GET', path, headers={
                                'Authorization': 'Bearer ' + token if authorization is None else authorization,
                                'X-Consumer-ID': 'forged', 'Cookie': 'client-secret=must-not-leak',
                                'X-Token-Issuer': 'https://issuer.example',
                                'X-OAuth-Client-ID': 'reports-client'})
                            response = connection.getresponse()
                            return response.status, dict(response.headers), response.read()
                        finally:
                            connection.close()

                    for authorization in ('', 'Basic abc', 'Bearer a&token=stolen', 'Bearer a=b'):
                        before = len(received)
                        status, headers, data = request(authorization=authorization)
                        assert status == 401, (authorization[:20], status, data)
                        assert 'Bearer' in headers.get('WWW-Authenticate', '')
                        assert len(received) == before and not forwarded
                    assert request('x' * 1025)[0] == 503  # Bounded request cannot be constructed.
                    assert not received and not forwarded
                    for token in ('valid', 'special+/=='):
                        status, headers, data = request(token)
                        assert (status, data) == (200, ('subject-' + token).encode()), (status, data)
                        assert 'Set-Cookie' not in headers and 'X-Consumer-ID' not in headers
                        assert received[-1][3] == token
                        assert 'Authorization' not in forwarded[-1]
                    assert b'token=special%2B%2F%3D%3D&token_type_hint=access_token' == received[-1][2]
                    for token, expected in (
                            ('inactive', 401), ('expired', 401), ('future-nbf', 401), ('future-iat', 401),
                            ('wrong-audience', 401), ('bad-audience', 401), ('typed-active', 401),
                            ('typed-exp', 401), ('typed-scope', 401), ('wrong-type', 401),
                            ('no-expiry', 401), ('no-subject', 401), ('typed-subject', 401),
                            ('unsafe-subject', 401), ('wrong-scope', 403), ('no-scope', 403),
                            ('malformed', 503), ('duplicate', 503), ('large', 503), ('truncated', 503),
                            ('redirect', 503), ('unavailable', 503), ('service-denied', 503)):
                        before = len(forwarded)
                        status, headers, data = request(token)
                        assert status == expected, (token, status, expected, data)
                        assert len(forwarded) == before, (token, forwarded)
                        if expected == 403:
                            assert 'insufficient_scope' in headers.get('WWW-Authenticate', '')
                        elif expected == 401:
                            assert 'invalid_token' in headers.get('WWW-Authenticate', '')
                    # Binding is opt-in: active metadata without issuer/client still works
                    # on the original route, but cannot reach the bound route's upstream.
                    for token in ('no-issuer', 'no-client', 'wrong-issuer', 'wrong-client'):
                        assert request(token)[0] == 200
                    for token in ('valid', 'escaped-binding', 'escaped-binding-names'):
                        status, headers, data = request(token, '/bound-reports')
                        assert (status, data) == (200, ('subject-' + token).encode()), (token, status, data)
                        assert 'Set-Cookie' not in headers and 'X-Consumer-ID' not in headers
                        assert 'Authorization' not in forwarded[-1]
                    for token in ('wrong-issuer', 'issuer-case', 'issuer-suffix',
                                  'wrong-client', 'service-client', 'client-case', 'client-prefix',
                                  'empty-issuer', 'typed-issuer', 'array-issuer', 'null-issuer',
                                  'empty-client', 'typed-client', 'object-client', 'null-client',
                                  'no-issuer', 'no-client', 'nul-issuer', 'nul-client',
                                  'inactive', 'expired', 'wrong-audience',
                                  'no-subject', 'typed-subject', 'unsafe-subject'):
                        before = len(forwarded)
                        status, headers, data = request(token, '/bound-reports')
                        assert status == 401, (token, status, data)
                        assert 'invalid_token' in headers.get('WWW-Authenticate', '')
                        assert len(forwarded) == before
                    for token, expected in (('wrong-scope', 403), ('duplicate-client', 503),
                                            ('aliased-issuer', 503), ('malformed', 503),
                                            ('unavailable', 503)):
                        before = len(forwarded)
                        status, headers, data = request(token, '/bound-reports')
                        assert status == expected, (token, status, data)
                        assert len(forwarded) == before
                        if expected == 403:
                            assert 'insufficient_scope' in headers.get('WWW-Authenticate', '')
                    scope_paths = ('/read-or-write-reports', '/read-and-write-reports')
                    for index, path in enumerate(scope_paths):
                        for token, expected in (
                                ('valid', 200), ('read-only', 200 if index == 0 else 403),
                                ('write-only', 200 if index == 0 else 403),
                                ('scope-repeated', 200), ('escaped-scope', 200),
                                ('scope-case', 403), ('scope-prefix', 403), ('no-scope', 403),
                                ('scope-empty', 401), ('scope-null', 401),
                                ('typed-scope', 401), ('scope-bad-suffix', 401),
                                ('scope-double-space', 401), ('scope-nul', 401),
                                ('duplicate-scope', 503), ('inactive', 401),
                                ('expired', 401), ('wrong-audience', 401), ('unavailable', 503)):
                            before = len(forwarded)
                            status, headers, data = request(token, path)
                            assert status == expected, (path, token, status, data)
                            if expected == 200:
                                assert data == ('subject-' + token).encode()
                                assert len(forwarded) == before + 1
                                assert 'Authorization' not in forwarded[-1]
                                assert forwarded[-1]['X-Consumer-ID'] == 'subject-' + token
                            else:
                                assert len(forwarded) == before
                                if expected in (401, 403):
                                    error = 'invalid_token' if expected == 401 else 'insufficient_scope'
                                    assert error in headers.get('WWW-Authenticate', '')
                        before = len(received)
                        assert request(path=path, authorization='')[0] == 401
                        assert len(received) == before
                    for path in invalid_scope_paths:
                        before = len(forwarded)
                        status, headers, data = request('valid', path)
                        assert status == 503, (path, status, data)
                        assert 'WWW-Authenticate' not in headers
                        assert len(forwarded) == before
                    for helper in ('requireEitherScope', 'requireBothScopes'):
                        assert request('read-only', '/same-scope-' + helper)[0] == 204
                        status, headers, _ = request('write-only', '/same-scope-' + helper)
                        assert status == 403
                        assert 'insufficient_scope' in headers.get('WWW-Authenticate', '')
                    for path in ('/empty-issuer', '/empty-client'):
                        before = len(forwarded)
                        assert request('valid', path)[0] == 503
                        assert len(forwarded) == before
                        assert request(authorization='', path=path)[0] == 401
                    for path, token in (('/timeout', 'slow'), ('/wrong-tls', 'valid'),
                                        ('/bad-service', 'valid'), ('/bad-config', 'valid')):
                        before = len(forwarded)
                        status, _, data = request(token, path)
                        assert status == 503, (path, status, data)
                        assert len(forwarded) == before
                    assert request('revoked')[0] == 200
                    before = len(received)
                    revoked.set()
                    assert request('revoked')[0] == 401
                    assert len(received) == before + 1  # No cached allow after remote revocation.
                    with ThreadPoolExecutor(max_workers=4) as workers:
                        results = list(workers.map(lambda i: request('user-' + str(i)), range(4)))
                    for i, (status, _, data) in enumerate(results):
                        assert (status, data) == (200, f'subject-user-{i}'.encode()), (i, status, data)
                    # Concurrent requests must retain their own permission result and identity.
                    with ThreadPoolExecutor(max_workers=4) as workers:
                        results = list(workers.map(
                            lambda i: request('read-only' if i % 2 else 'valid', scope_paths[1]),
                            range(8)))
                    for i, (status, headers, data) in enumerate(results):
                        if i % 2:
                            assert status == 403, (i, status, data)
                            assert 'insufficient_scope' in headers.get('WWW-Authenticate', '')
                        else:
                            assert (status, data) == (200, b'subject-valid'), (i, status, data)
                    def frame(kind, flags, stream, data=b''):
                        return len(data).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + data

                    for h2_path in ('/reports', '/bound-reports', *scope_paths):
                        with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                            block = (b'\x82\x86\x04' + bytes((len(h2_path),)) + h2_path.encode() +
                                     b'\x01\x09localhost\x0f\x08\x09Bearer h2')
                            sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) + frame(1, 5, 1, block))

                            def exact(length):
                                data = b''
                                while len(data) < length:
                                    part = sock.recv(length - len(data))
                                    assert part, 'HTTP/2 closed before introspection completed'
                                    data += part
                                return data

                            data = b''
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
                                if kind == 0:
                                    data += payload
                                if kind in (0, 1) and flags & 1:
                                    break
                            assert data == b'subject-h2', data
                    # Duplicate Authorization must fail before contacting the AS.
                    for path in ('/reports', '/bound-reports', *scope_paths):
                        before = len(received)
                        with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                            wire = (f'GET {path} HTTP/1.1\r\nHost: test\r\n'
                                    'Authorization: Bearer valid\r\n'
                                    'Authorization: Bearer valid\r\n\r\n').encode()
                            sock.sendall(wire)
                            assert b' 401 ' in sock.recv(4096)
                        assert len(received) == before
                    for path, headers, _, token in received:
                        assert path == '/introspect'
                        assert not any(key.lower() in ('cookie', 'x-consumer-id') for key in headers)
                        assert headers['Authorization'] in (service_auth, 'Bearer wrong-service')
                    assert service_auth.encode() not in log.read_bytes()
                    print(f'PASS: {args.backend} authenticated RFC 7662 requests, strict metadata, issuer/client binding, either/both scope policy, revocation and isolation')
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise AssertionError('introspection worker shutdown timed out')
                    if process.returncode not in (0, 77):
                        raise AssertionError((process.returncode, log.read_text(errors='replace')))
    finally:
        for server in (authorizer, upstream):
            server.shutdown()
            server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
