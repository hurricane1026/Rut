#!/usr/bin/env python3
"""Bounded RFC 8693 access-token exchange through a source-unlinked native gateway."""
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
    subject = 'subject+/=='
    service = 'Basic Y2xpZW50OnNlY3JldA=='
    scope = 'reports:read a+b&x=y'
    resource = 'https://api.example.test/reports?tenant=a+b&scope=write%2Fread'
    access_type = 'urn:ietf:params:oauth:token-type:access_token'
    grant = 'urn:ietf:params:oauth:grant-type:token-exchange'
    policy = dict(scope=scope, resource=resource)
    calls, forwarded, violations = [], [], []
    issued = {}
    lock = threading.Lock()
    mode = 'valid'

    class AS(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            with lock:
                selected = mode
                serial = len(calls)
                calls.append((self.path, dict(self.headers), raw))
            parameters = parse_qs(raw.decode(), strict_parsing=True)
            token_subject = parameters.get('subject_token', [''])[0]
            expected = dict(grant_type=[grant], subject_token_type=[access_type],
                            requested_token_type=[access_type], subject_token=[token_subject],
                            scope=[scope], resource=[resource])
            if parameters != expected or self.path != '/token':
                violations.append((parameters, self.path))
            for name in ('Cookie', 'X-Consumer-ID', 'Scope', 'Resource', 'Actor-Token'):
                if self.headers.get(name):
                    violations.append(('leaked header', name))
            token = 'exchanged-private-' + str(serial)
            body = dict(access_token=token, issued_token_type=access_type, token_type='Bearer',
                        expires_in=60, scope=scope, refresh_token='unused-refresh-secret')
            updates = {
                'id-token': dict(issued_token_type='urn:ietf:params:oauth:token-type:id_token'),
                'jwt-token': dict(issued_token_type='urn:ietf:params:oauth:token-type:jwt'),
                'typed-issued': dict(issued_token_type=True), 'empty-issued': dict(issued_token_type=''),
                'case-issued': dict(issued_token_type=access_type.upper()),
                'wrong-type': dict(token_type='N_A'), 'typed-type': dict(token_type=True),
                'spaced-type': dict(token_type='Bearer '), 'mixed-type': dict(token_type='bEaReR'),
                'empty-token': dict(access_token=''), 'typed-token': dict(access_token=7),
                'injected-token': dict(access_token='a\r\nInjected: yes'),
                'space-token': dict(access_token='a b'), 'bad-padding': dict(access_token='ab=c'),
                'expired': dict(expires_in=0), 'typed-expiry': dict(expires_in='60'),
                'fractional-expiry': dict(expires_in=1.5), 'overflow-expiry': dict(expires_in=2**63),
                'wrong-scope': dict(scope='reports:reader'), 'typed-scope': dict(scope=['reports:read']),
                'bad-scope': dict(scope='reports:read  write'), 'error-field': dict(error='invalid_request'),
                'null-error': dict(error=None),
            }
            body.update(updates.get(selected, {}))
            status = {'unavailable': 503, 'redirect': 302, 'denied': 403}.get(selected, 200)
            if token_subject not in (subject, 'another-subject', 'a' * 1024):
                status, body = 400, dict(error='invalid_request')
            if self.headers.get('Authorization') != service:
                status, body = 401, dict(error='invalid_client')
            if selected == 'invalid-target':
                status, body = 400, dict(error='invalid_target')
            for name, field in (('no-issued', 'issued_token_type'), ('no-token', 'access_token'),
                                ('no-type', 'token_type'), ('no-expiry', 'expires_in'), ('no-scope', 'scope')):
                if selected == name:
                    del body[field]
            data = json.dumps(body).encode()
            if selected == 'duplicate':
                data = data[:-1] + b',"issued_token_type":"forged"}'
            elif selected == 'aliased-duplicate':
                data = data[:-1] + b',"issued\\u005ftoken_type":"forged"}'
            elif selected == 'malformed':
                data = b'{'
            elif selected == 'non-object':
                data = b'[]'
            elif selected == 'large':
                data = b'x' * 9000
            if status == 200 and selected in ('valid', 'mixed-type', 'concurrent', 'ignore-resource'):
                with lock:
                    issued[token] = (token_subject, None if selected == 'ignore-resource' else resource)
            time.sleep(.2 if selected == 'slow' else .005)
            try:
                if selected == 'truncated':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{}')
                    self.close_connection = True
                    return
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Set-Cookie', 'as-secret=do-not-leak')
                self.send_header('Authorization', 'Bearer forged-as-header')
                self.end_headers()
                self.wfile.write(data)
            except (OSError, ssl.SSLError):
                pass

        def log_message(self, *unused):
            pass

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            auth = self.headers.get('Authorization', '')
            with lock:
                forwarded.append(dict(self.headers))
                binding = issued.get(auth.removeprefix('Bearer '))
            accepted = binding is not None and binding[1] == resource
            body = b'upstream-ok' if accepted else b'wrong-resource'
            self.send_response(200 if accepted else 403)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *unused):
            pass

    authorizer = http.server.ThreadingHTTPServer(('127.0.0.1', 0), AS)
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
        with tempfile.TemporaryDirectory(prefix='rut-token-exchange-') as directory:
            root = Path(directory)
            (root / 'middleware').mkdir()
            modules = []
            for name in ('oauth_client.rut', 'introspection.rut'):
                target = root / 'middleware' / name
                target.write_bytes((examples / 'middleware' / name).read_bytes())
                modules.append(target)
            source = (examples / 'upstream-oauth-exchange.rut').read_text().replace('listen :8080\n', '')
            source = source.replace(':9000"', f':{upstream.server_port}"')
            route = source[source.index('route GET'):]
            # Replace the policy expression with trusted malformed/unsupported configurations.
            expression = 'json.value({scope: env("UPSTREAM_SCOPE"), resource: env("UPSTREAM_RESOURCE")})'
            invalid = ('json.value({scope: "read"})',
                       'json.value({scope: "read", resource: "http://api.test/"})',
                       'json.value({scope: "read", resource: "https://api.test/", actor_token: "forged"})',
                       'json.value({scope: "read  write", resource: "https://api.test/"})',
                       'json.value({scope: "read", resource: "https://[::1\\u{0}evil]/"})',
                       'json.value({scope: "' + '&' * 1024 + '", resource: "https://host/' + '&' * 1011 + '"})')
            for index, value in enumerate(invalid):
                source += route.replace('/exchanged-reports', f'/invalid-{index}').replace(expression, value)
            source += route.replace('/exchanged-reports', '/timeout').replace(', 1000)', ', 50)')
            source += route.replace('/exchanged-reports', '/bad-service').replace(
                'env("TOKEN_SERVICE_AUTH")', '"Basic d3Jvbmc6c2VjcmV0"')
            source += route.replace('/exchanged-reports', '/wrong-tls').replace('env("TOKEN_ENDPOINT")', 'env("WRONG_TLS")')
            program, log = root / 'gateway.rut', root / 'gateway.log'
            program.write_text(source)
            env = dict(os.environ, TOKEN_ENDPOINT=json.dumps(endpoint), TOKEN_SERVICE_AUTH=service,
                       UPSTREAM_SCOPE=scope, UPSTREAM_RESOURCE=resource,
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

                    def request(path='/exchanged-reports', authorization=None):
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                        try:
                            connection.request('GET', path, headers={
                                'Authorization': 'Bearer ' + subject if authorization is None else authorization,
                                'Cookie': 'caller-secret', 'X-Consumer-ID': 'forged',
                                'Scope': 'admin', 'Resource': 'https://attacker.invalid/', 'Actor-Token': 'forged'})
                            response = connection.getresponse()
                            return response.status, dict(response.headers), response.read()
                        finally:
                            connection.close()

                    for auth in ('', 'Basic YTpi', 'Bearer a b', 'Bearer a=b'):
                        status, headers, _ = request(authorization=auth)
                        assert status == 401
                        assert {name.lower(): value for name, value in headers.items()}['www-authenticate'] == 'Bearer'
                        assert not calls and not forwarded
                    for selected in ('valid', 'mixed-type'):
                        mode = selected
                        status, headers, body = request('/exchanged-reports?scope=admin&resource=evil')
                        assert (status, body) == (200, b'upstream-ok')
                        assert 'Set-Cookie' not in headers and 'Authorization' not in headers
                        token = forwarded[-1]['Authorization'].removeprefix('Bearer ')
                        assert issued[token] == (subject, resource)
                        assert forwarded[-1]['Authorization'] != 'Bearer ' + subject
                    assert request(authorization='Bearer ' + 'a' * 1024)[0] == 200
                    before = len(calls)
                    assert request(authorization='Bearer ' + 'a' * 1025)[0] == 503
                    assert len(calls) == before
                    bad = ('id-token', 'jwt-token', 'typed-issued', 'empty-issued', 'case-issued', 'no-issued',
                           'wrong-type', 'typed-type', 'spaced-type', 'empty-token', 'typed-token',
                           'injected-token', 'space-token', 'bad-padding', 'expired', 'typed-expiry',
                           'fractional-expiry', 'overflow-expiry', 'wrong-scope', 'typed-scope', 'bad-scope',
                           'error-field', 'null-error', 'no-token', 'no-type', 'no-expiry', 'no-scope',
                           'duplicate', 'aliased-duplicate', 'malformed', 'non-object', 'large', 'truncated',
                           'unavailable', 'redirect', 'denied', 'invalid-target')
                    for selected in bad:
                        mode = selected
                        before = len(forwarded)
                        status, _, body = request()
                        assert status == 503, (selected, status, body)
                        assert len(forwarded) == before
                    mode = 'valid'
                    before = len(forwarded)
                    assert request(authorization='Bearer unknown-subject')[0] == 503
                    assert request('/bad-service')[0] == 503
                    assert len(forwarded) == before
                    for path in [f'/invalid-{i}' for i in range(len(invalid))] + ['/wrong-tls']:
                        before = (len(calls), len(forwarded))
                        assert request(path)[0] == 503, path
                        assert (len(calls), len(forwarded)) == before
                    mode = 'ignore-resource'
                    assert request()[0] == 403  # The upstream, not the request parameter, proves audience.
                    mode = 'slow'
                    before = len(forwarded)
                    assert request('/timeout')[0] == 503
                    assert len(forwarded) == before
                    mode = 'concurrent'
                    before = len(calls)
                    before_forwarded = len(forwarded)
                    subjects = [subject, 'another-subject', subject, 'another-subject']
                    with ThreadPoolExecutor(max_workers=4) as workers:
                        results = list(workers.map(lambda value: request(authorization='Bearer ' + value), subjects))
                    assert all((status, body) == (200, b'upstream-ok') for status, _, body in results), results
                    assert len(calls) == before + 4
                    tokens = [headers['Authorization'].removeprefix('Bearer ') for headers in forwarded[before_forwarded:]]
                    assert len(set(tokens)) == 4
                    assert sorted(issued[token][0] for token in tokens) == sorted(subjects)
                    mode = 'slow'
                    before = len(calls)
                    before_forwarded = len(forwarded)
                    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                        sock.sendall(('GET /exchanged-reports HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer ' + subject + '\r\n\r\n').encode())
                        deadline = time.monotonic() + 2
                        while len(calls) == before and time.monotonic() < deadline:
                            time.sleep(.01)
                        assert len(calls) == before + 1
                    time.sleep(.3)
                    assert len(forwarded) == before_forwarded
                    mode = 'valid'
                    assert request()[0] == 200
                    # Minimal dependency-free HTTP/2 request through the same native artifact.
                    def frame(kind, flags, stream, data=b''):
                        return len(data).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + data
                    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                        path, auth = b'/exchanged-reports', ('Bearer ' + subject).encode()
                        block = b'\x82\x86\x04' + bytes((len(path),)) + path + b'\x01\x09localhost\x0f\x08' + bytes((len(auth),)) + auth
                        sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) + frame(1, 5, 1, block))
                        def exact(length):
                            data = b''
                            while len(data) < length:
                                part = sock.recv(length - len(data))
                                assert part, 'HTTP/2 closed before exchange forwarding'
                                data += part
                            return data
                        body = b''
                        while True:
                            header = exact(9)
                            data = exact(int.from_bytes(header[:3], 'big'))
                            kind, flags = header[3:5]
                            stream = int.from_bytes(header[5:], 'big') & 0x7fffffff
                            if kind == 4 and not flags & 1:
                                sock.sendall(frame(4, 1, 0))
                            assert kind != 7, data
                            if stream != 1:
                                continue
                            assert kind != 3, data
                            if kind == 0:
                                body += data
                            if kind in (0, 1) and flags & 1:
                                break
                        assert body == b'upstream-ok'
                    before = len(calls)
                    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                        sock.sendall(('GET /exchanged-reports HTTP/1.1\r\nHost: test\r\n' + ('Authorization: Bearer ' + subject + '\r\n') * 2 + '\r\n').encode())
                        assert b' 401 ' in sock.recv(4096)
                    assert len(calls) == before
                    assert not violations, violations
                    assert all(headers['Authorization'] in (service, 'Basic d3Jvbmc6c2VjcmV0') and
                               headers['Content-Type'] == 'application/x-www-form-urlencoded' and
                               headers['Accept'] == 'application/json' for _, headers, _ in calls)
                    first_body = calls[0][2]
                    assert b'subject_token=subject%2B%2F%3D%3D' in first_body
                    assert b'scope=reports%3Aread%20a%2Bb%26x%3Dy' in first_body
                    assert b'resource=https%3A%2F%2Fapi.example.test%2Freports%3Ftenant%3Da%2Bb%26scope%3Dwrite%252Fread' in first_body
                    logged = log.read_bytes()
                    assert all(secret.encode() not in logged for secret in (subject, service, 'caller-secret', 'unused-refresh-secret', 'exchanged-private-'))
                    print(f'PASS: {args.backend} access-token exchange, strict issued type, subject/resource isolation, HTTP/2 and cancellation')
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise AssertionError('exchange worker shutdown timed out')
                    if process.returncode not in (0, 77):
                        raise AssertionError((process.returncode, log.read_text(errors='replace')))
    finally:
        for server in (authorizer, upstream):
            server.shutdown()
            server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
