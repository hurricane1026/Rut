#!/usr/bin/env python3
"""Client-credentials protocol fixture with a native-loaded gateway and verified TLS."""
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
    caller_key = 'downstream-caller-key'
    requested_scope = 'reports:read reports:write a+b/x=%&'
    scoped_body = (b'grant_type=client_credentials&scope=reports%3Aread%20'
                   b'reports%3Awrite%20a%2Bb%2Fx%3D%25%26')
    resource = 'https://api.example.test/reports?tenant=a+b&scope=write%2Fread'
    other_resource = 'https://api.example.test/other'
    resource_body = scoped_body + (b'&resource=https%3A%2F%2Fapi.example.test%2Freports'
                                   b'%3Ftenant%3Da%2Bb%26scope%3Dwrite%252Fread')
    calls, forwarded, issued = [], [], []
    token_resources = {}
    lock = threading.Lock()
    mode = 'valid'

    class TokenEndpoint(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            with lock:
                selected = mode
                serial = len(calls)
                calls.append((self.path, dict(self.headers), raw))
            parameters = parse_qs(raw.decode(), strict_parsing=True)
            token = 'upstream-private-' + str(serial)
            body = dict(access_token=token, token_type='Bearer', expires_in=3600,
                        scope=parameters.get('scope', ['reports:read reports:write'])[0], refresh_token='unused-refresh-secret')
            updates = {
                'wrong-type': dict(token_type='MAC'), 'typed-type': dict(token_type=True),
                'spaced-type': dict(token_type='Bearer '), 'mixed-type': dict(token_type='bEaReR'),
                'empty-token': dict(access_token=''), 'typed-token': dict(access_token=7),
                'space-token': dict(access_token='a b'), 'leading-token': dict(access_token=' token'),
                'trailing-token': dict(access_token='token '),
                'newline-token': dict(access_token='token\r\nInjected: yes'),
                'nul-token': dict(access_token='token\x00'),
                'unicode-token': dict(access_token='tökén'), 'bad-padding': dict(access_token='ab=c'),
                'expired': dict(expires_in=0), 'negative-expiry': dict(expires_in=-1),
                'typed-expiry': dict(expires_in='3600'), 'bool-expiry': dict(expires_in=True),
                'fractional-expiry': dict(expires_in=1.5), 'overflow-expiry': dict(expires_in=2**63),
                'narrow-scope': dict(scope='reports:read'),
                'two-scopes': dict(scope='reports:read reports:write'),
                'reordered-scopes': dict(scope='a+b/x=%& reports:write reports:read'),
                'wider-scopes': dict(scope='admin ' + requested_scope),
                'repeated-scopes': dict(scope=requested_scope + ' reports:read'),
                'case-scope': dict(scope='Reports:read reports:write a+b/x=%&'),
                'prefix-scope': dict(scope='reports:read reports:write a+b/x=%&extra'),
                'wrong-scope': dict(scope='reports:reader'), 'typed-scope': dict(scope=['reports:read']),
                'bad-scope': dict(scope='reports:read  reports:write'),
                'error-field': dict(error='invalid_client'), 'null-error': dict(error=None),
                'escaped-token': dict(access_token='special+/=='),
            }
            body.update(updates.get(selected, {}))
            requested_resource = parameters.get('resource', [None])[0]
            if requested_resource not in (None, resource, other_resource) or selected == 'invalid-target':
                body['error'] = 'invalid_target'
            for name, field in (('no-token', 'access_token'), ('no-type', 'token_type'),
                                ('no-expiry', 'expires_in'), ('no-scope', 'scope')):
                if selected == name:
                    del body[field]
            data = json.dumps(body).encode()
            if selected == 'escaped-token':
                data = data.replace(b'special', b'sp\\u0065cial')
            elif selected == 'duplicate':
                data = data[:-1] + b', "access_token":"replacement"}'
            elif selected == 'aliased-duplicate':
                data = data[:-1] + b', "access\\u005ftoken":"replacement"}'
            elif selected == 'malformed':
                data = b'{'
            elif selected == 'non-object':
                data = b'[]'
            elif selected == 'large':
                data = b'x' * 9000
            status = {'redirect': 302, 'unavailable': 503, 'denied': 403, 'invalid-target': 400}.get(selected, 200)
            if body.get('error') == 'invalid_target':
                status = 400
            if self.headers.get('Authorization') != service_auth:
                status = 401
            if status == 200 and selected in ('valid', 'mixed-type', 'escaped-token', 'concurrent', 'narrow-scope', 'ignore-resource', 'two-scopes', 'reordered-scopes', 'wider-scopes', 'repeated-scopes'):
                with lock:
                    issued.append(body['access_token'])
                    token_resources[body['access_token']] = None if selected == 'ignore-resource' else requested_resource
            time.sleep(.20 if selected == 'slow' else .01)
            try:
                if selected == 'truncated':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{}')
                    self.close_connection = True
                    return
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Set-Cookie', 'as-secret=do-not-leak')
                self.send_header('Authorization', 'Bearer forged-as-header')
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
                forwarded.append((self.path, dict(self.headers)))
            token = self.headers.get('Authorization', '').removeprefix('Bearer ')
            bound = token_resources.get(token)
            protected = self.path.startswith(('/resource-reports', '/mismatched-resource'))
            accepted = not protected or bound == resource
            body = b'upstream-ok' if accepted else b'wrong-resource'
            self.send_response(200 if accepted else 403)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *unused):
            pass

    authorizer = http.server.ThreadingHTTPServer(('127.0.0.1', 0), TokenEndpoint)
    upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                            str(Path(args.testdata) / 'localhost_key.pem'))
    authorizer.socket = context.wrap_socket(authorizer.socket, server_side=True)
    for server in (authorizer, upstream):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    examples = Path(__file__).resolve().parent.parent / 'examples'
    endpoint = dict(address='127.0.0.1', port=authorizer.server_port, serverName='localhost',
                    caFile=str(Path(args.testdata) / 'localhost_cert.pem'), path='/token')
    try:
        with tempfile.TemporaryDirectory(prefix='rut-upstream-oauth-') as directory:
            root = Path(directory)
            (root / 'middleware').mkdir()
            modules = []
            for name in ('oauth_client.rut', 'introspection.rut'):
                target = root / 'middleware' / name
                target.write_bytes((examples / 'middleware' / name).read_bytes())
                modules.append(target)
            source = (examples / 'upstream-oauth.rut').read_text()
            source = source.replace('listen :8080\n', '').replace(':9000"', f':{upstream.server_port}"')
            route = source[source.index('route GET'):]
            for path, auth, policy, timeout, scope in (
                    ('/timeout', 'env("TOKEN_SERVICE_AUTH")', 'TOKEN_ENDPOINT', 50, 'reports:read'),
                    ('/bad-service', '"Basic d3Jvbmc6c2VjcmV0"', 'TOKEN_ENDPOINT', 1000, 'reports:read'),
                    ('/bad-config', '""', 'TOKEN_ENDPOINT', 1000, 'reports:read'),
                    ('/unsafe-config', 'env("UNSAFE_AUTH")', 'TOKEN_ENDPOINT', 1000, 'reports:read'),
                    ('/wrong-tls', 'env("TOKEN_SERVICE_AUTH")', 'WRONG_TLS', 1000, 'reports:read'),
                    ('/empty-scope', 'env("TOKEN_SERVICE_AUTH")', 'TOKEN_ENDPOINT', 1000, '')):
                source += route.replace('/service-reports', path).replace(
                    'env("TOKEN_SERVICE_AUTH")', auth).replace('env("TOKEN_ENDPOINT")',
                    f'env("{policy}")').replace(', 1000)', f', {timeout})').replace(
                    'reply, "reports:read"', 'reply, ' + json.dumps(scope))
            scoped = (examples / 'upstream-oauth-scoped.rut').read_text()
            scoped = scoped[scoped.index('route GET'):]
            source += scoped
            all_scopes = (examples / 'upstream-oauth-all-scopes.rut').read_text()
            source += all_scopes[all_scopes.index('route GET'):]
            invalid_scopes = ('', ' reports:read', 'reports:read ', 'reports:read  write',
                              'reports:read\twrite', 'reports:read\nwrite', 'reports:read"',
                              'reports:read\\', 'réad', 'reports:read\x00', 'x' * 1025)
            for index, value in enumerate(invalid_scopes):
                source += scoped.replace('/scoped-reports', f'/invalid-scope-{index}').replace(
                    'env("UPSTREAM_SCOPE")', json.dumps(value, ensure_ascii=False).replace('\\u0000', '\\u{0}'))
            source += scoped.replace('/scoped-reports', '/scoped-bearer').replace(
                'env("TOKEN_SERVICE_AUTH")', '"Bearer forbidden"')
            resource_route = (examples / 'upstream-oauth-resource.rut').read_text()
            resource_route = resource_route[resource_route.index('route GET'):]
            source += resource_route
            source += resource_route.replace('/resource-reports', '/mismatched-resource').replace(
                'env("UPSTREAM_RESOURCE")', json.dumps(other_resource))
            source += resource_route.replace('/resource-reports', '/unknown-resource').replace(
                'env("UPSTREAM_RESOURCE")', '"https://unknown.example.test/"')
            invalid_resources = ('', '/relative', 'http://api.example.test/', 'https://',
                                 'https://user:secret@api.example.test/', 'https://host/#fragment',
                                 'https://host/space here', 'https://host/%zz', 'https://host/\\path',
                                 'https://host/\r\n', 'https://host/ré', 'https://host/\x00',
                                 'https://[bad]/', 'https://[::1\x00evil]/', 'https://host:65536/', 'https://host/' + 'x' * 1024)
            for index, value in enumerate(invalid_resources):
                source += resource_route.replace('/resource-reports', f'/invalid-resource-{index}').replace(
                    'env("UPSTREAM_RESOURCE")', json.dumps(value, ensure_ascii=False).replace('\\u0000', '\\u{0}'))
            source += resource_route.replace('/resource-reports', '/encoded-overflow').replace(
                'env("UPSTREAM_SCOPE")', json.dumps('&' * 1024)).replace(
                'env("UPSTREAM_RESOURCE")', json.dumps('https://host/' + '&' * 1011))
            program, log = root / 'gateway.rut', root / 'gateway.log'
            program.write_text(source)
            env = dict(os.environ, TOKEN_SERVICE_AUTH=service_auth, DOWNSTREAM_KEY=caller_key,
                       UPSTREAM_SCOPE=requested_scope, UPSTREAM_RESOURCE=resource,
                       TOKEN_ENDPOINT=json.dumps(endpoint), UNSAFE_AUTH=service_auth + '\r\nInjected: yes',
                       WRONG_TLS=json.dumps(dict(endpoint, serverName='wrong.invalid')))
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

                    def request(path='/service-reports', authorization=None):
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                        try:
                            connection.request('GET', path, headers={
                                'Authorization': 'Bearer ' + caller_key if authorization is None else authorization,
                                'Cookie': 'caller-secret', 'X-Consumer-ID': 'forged',
                                'Scope': 'admin&grant_type=password', 'Resource': 'https://attacker.invalid/'})
                            response = connection.getresponse()
                            return response.status, dict(response.headers), response.read()
                        finally:
                            connection.close()

                    for authorization in ('', 'Basic YTpi', 'Bearer wrong', 'Bearer a b'):
                        for path in ('/service-reports', '/scoped-reports', '/resource-reports', '/all-scope-reports'):
                            assert request(path, authorization=authorization)[0] == 401
                        assert not calls and not forwarded
                    for selected in ('valid', 'mixed-type', 'escaped-token'):
                        mode = selected
                        before = len(calls)
                        status, headers, body = request()
                        assert (status, body) == (200, b'upstream-ok'), (selected, status, body)
                        assert len(calls) == before + 1
                        assert forwarded[-1][1]['Authorization'] == 'Bearer ' + issued[-1]
                        assert 'Authorization' not in headers and 'Set-Cookie' not in headers
                    for path in ('/scoped-reports', '/scoped-reports?scope=admin'):
                        mode = 'valid'
                        before = len(calls)
                        assert request(path)[::2] == (200, b'upstream-ok')
                        assert len(calls) == before + 1 and calls[-1][2] == scoped_body
                    for selected in ('valid', 'reordered-scopes', 'wider-scopes', 'repeated-scopes'):
                        mode = selected
                        before = len(calls)
                        assert request('/all-scope-reports')[::2] == (200, b'upstream-ok')
                        assert len(calls) == before + 1 and calls[-1][2] == scoped_body
                    for selected in ('narrow-scope', 'two-scopes', 'case-scope', 'prefix-scope', 'bad-scope'):
                        mode = selected
                        before = len(forwarded)
                        assert request('/all-scope-reports')[0] == 503, selected
                        assert len(forwarded) == before
                    mode = 'narrow-scope'
                    assert request('/scoped-reports')[::2] == (200, b'upstream-ok')
                    mode = 'valid'
                    for path in ('/resource-reports', '/resource-reports?resource=https://attacker.invalid/'):
                        before = len(calls)
                        assert request(path)[::2] == (200, b'upstream-ok')
                        assert len(calls) == before + 1 and calls[-1][2] == resource_body
                    for path in [f'/invalid-resource-{i}' for i in range(len(invalid_resources))] + ['/encoded-overflow']:
                        before = (len(calls), len(forwarded))
                        assert request(path)[0] == 503, path
                        assert (len(calls), len(forwarded)) == before
                    for selected in ('invalid-target', 'wrong-scope'):
                        mode = selected
                        before = len(forwarded)
                        assert request('/resource-reports')[0] == 503
                        assert len(forwarded) == before
                    mode = 'valid'
                    before = len(forwarded)
                    assert request('/unknown-resource')[0] == 503
                    assert len(forwarded) == before
                    # The upstream enforces the AS token's resource restriction.
                    assert request('/mismatched-resource')[0] == 403
                    mode = 'ignore-resource'
                    assert request('/resource-reports')[0] == 403
                    mode = 'valid'
                    for path in [f'/invalid-scope-{i}' for i in range(len(invalid_scopes))] + ['/scoped-bearer']:
                        before = (len(calls), len(forwarded))
                        assert request(path)[0] == 503, path
                        assert (len(calls), len(forwarded)) == before, path
                    mode = 'wrong-scope'
                    before = len(forwarded)
                    assert request('/scoped-reports')[0] == 503
                    assert len(forwarded) == before
                    bad = ('wrong-type', 'typed-type', 'spaced-type', 'empty-token', 'typed-token',
                           'space-token', 'leading-token', 'trailing-token', 'newline-token',
                           'nul-token', 'unicode-token', 'bad-padding', 'expired', 'negative-expiry',
                           'typed-expiry', 'bool-expiry', 'fractional-expiry', 'overflow-expiry',
                           'wrong-scope', 'typed-scope', 'bad-scope', 'error-field', 'null-error',
                           'no-token', 'no-type', 'no-expiry', 'no-scope', 'duplicate',
                           'aliased-duplicate', 'malformed', 'non-object', 'large', 'truncated',
                           'redirect', 'unavailable', 'denied')
                    for selected in bad:
                        mode = selected
                        for path in ('/service-reports', '/all-scope-reports'):
                            before = len(forwarded)
                            status, _, body = request(path)
                            assert status == 503, (path, selected, status, body)
                            assert len(forwarded) == before
                    mode = 'valid'
                    for path in ('/bad-config', '/unsafe-config', '/wrong-tls', '/bad-service', '/empty-scope'):
                        before = len(forwarded)
                        before_calls = len(calls)
                        assert request(path)[0] == 503, path
                        assert len(forwarded) == before
                        if path in ('/bad-config', '/unsafe-config', '/wrong-tls'):
                            assert len(calls) == before_calls
                    mode = 'slow'
                    before = len(forwarded)
                    assert request('/timeout')[0] == 503
                    assert len(forwarded) == before
                    mode = 'concurrent'
                    before = len(calls)
                    before_forwarded = len(forwarded)
                    before_issued = len(issued)
                    with ThreadPoolExecutor(max_workers=4) as workers:
                        results = list(workers.map(lambda i: request(('/service-reports', '/scoped-reports', '/resource-reports', '/all-scope-reports')[i % 4]), range(4)))
                    assert all((status, body) == (200, b'upstream-ok') for status, _, body in results), results
                    assert len(calls) == before + 4  # Every request gets a new token; no cached allow.
                    actual = {headers['Authorization'] for _, headers in forwarded[before_forwarded:]}
                    assert actual == {'Bearer ' + value for value in issued[before_issued:]}
                    assert len(actual) == 4
                    # A disconnected caller must not forward a late token response.
                    mode = 'slow'
                    before = len(calls)
                    before_forwarded = len(forwarded)
                    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                        sock.sendall(('GET /resource-reports HTTP/1.1\r\nHost: test\r\n'
                                      'Authorization: Bearer ' + caller_key + '\r\n\r\n').encode())
                        deadline = time.monotonic() + 2
                        while len(calls) == before and time.monotonic() < deadline:
                            time.sleep(.01)
                        assert len(calls) == before + 1
                    time.sleep(.3)
                    assert len(forwarded) == before_forwarded
                    mode = 'valid'
                    assert request()[0] == 200

                    def frame(kind, flags, stream, data=b''):
                        return len(data).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + data

                    # The same native policy also resumes into HTTP/2 forwarding.
                    for path in (b'/service-reports', b'/scoped-reports', b'/resource-reports', b'/all-scope-reports'):
                        with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                            auth = ('Bearer ' + caller_key).encode()
                            block = (b'\x82\x86\x04' + bytes((len(path),)) + path +
                                     b'\x01\x09localhost\x0f\x08' + bytes((len(auth),)) + auth)
                            sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) + frame(1, 5, 1, block))

                            def exact(length):
                                data = b''
                                while len(data) < length:
                                    part = sock.recv(length - len(data))
                                    assert part, 'HTTP/2 closed before upstream token forwarding'
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
                            assert data == b'upstream-ok', data
                        assert forwarded[-1][1]['Authorization'] == 'Bearer ' + issued[-1]
                    mode = 'valid'
                    before = len(calls)
                    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                        wire = ('GET /service-reports HTTP/1.1\r\nHost: test\r\n' +
                                ('Authorization: Bearer ' + caller_key + '\r\n') * 2 + '\r\n').encode()
                        sock.sendall(wire)
                        assert b' 401 ' in sock.recv(4096)
                    assert len(calls) == before
                    for path, headers, raw in calls:
                        assert path == '/token'
                        assert raw in (b'grant_type=client_credentials', scoped_body, resource_body,
                                       scoped_body + b'&resource=https%3A%2F%2Fapi.example.test%2Fother',
                                       scoped_body + b'&resource=https%3A%2F%2Funknown.example.test%2F')
                        expected = {'grant_type': ['client_credentials']}
                        if raw != b'grant_type=client_credentials':
                            expected['scope'] = [requested_scope]
                        if b'&resource=' in raw:
                            actual_resource = parse_qs(raw.decode())['resource']
                            assert actual_resource in ([resource], [other_resource], ['https://unknown.example.test/'])
                            expected['resource'] = actual_resource
                        assert parse_qs(raw.decode(), strict_parsing=True) == expected
                        assert headers['Authorization'] in (service_auth, 'Basic d3Jvbmc6c2VjcmV0')
                        assert headers['Content-Type'] == 'application/x-www-form-urlencoded'
                        assert headers['Accept'] == 'application/json'
                        assert not any(name.lower() in ('cookie', 'x-consumer-id', 'scope', 'resource') for name in headers)
                    logged = log.read_bytes()
                    assert service_auth.encode() not in logged and caller_key.encode() not in logged
                    assert b'upstream-private-' not in logged and b'unused-refresh-secret' not in logged
                    print(f'PASS: {args.backend} client credentials, configured scopes/resources, strict token policy and isolation')
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise AssertionError('token worker shutdown timed out')
                    if process.returncode not in (0, 77):
                        raise AssertionError((process.returncode, log.read_text(errors='replace')))
    finally:
        for server in (authorizer, upstream):
            server.shutdown()
            server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
