#!/usr/bin/env python3
"""Configured OAuth client Basic through native policy and an independent TLS AS."""
import argparse
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, quote_plus, unquote_plus

from auth_h2_fixture import request as h2_request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    client_id, client_secret = 'client: +%~*', 'secret:/+ %&='
    caller_key, token = 'caller-private-key', 'as-private-service-token'
    scopes = 'reports:read reports:write'
    def component(value):
        return quote_plus(value, safe='*-._').replace('~', '%7E')
    userinfo = component(client_id) + ':' + component(client_secret)
    expected_header = 'Basic ' + base64.b64encode(userinfo.encode()).decode()
    calls, forwarded = [], []
    lock = threading.Lock()

    class Authorizer(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            headers = self.headers.get_all('Authorization', [])
            accepted = False
            try:
                assert len(headers) == 1 and headers[0].startswith('Basic ')
                encoded = headers[0][6:]
                decoded = base64.b64decode(encoded, validate=True).decode('ascii')
                parts = decoded.split(':')
                assert parts == [component(client_id), component(client_secret)]
                assert [unquote_plus(part, encoding='ascii', errors='strict') for part in parts] == [client_id, client_secret]
                assert base64.b64encode(decoded.encode()).decode() == encoded
                parameters = parse_qs(body.decode('ascii'), strict_parsing=True)
                assert parameters in ({'grant_type': ['client_credentials']},
                                      {'grant_type': ['client_credentials'], 'scope': [scopes]})
                assert 'client_id' not in parameters and 'client_secret' not in parameters
                assert not any(self.headers.get(name) for name in ('Cookie', 'X-Client-ID', 'X-Client-Secret'))
                accepted = True
            except (AssertionError, ValueError, UnicodeError):
                pass
            with lock:
                calls.append((accepted, body))
            result = (dict(access_token=token, token_type='Bearer', expires_in=3600, scope=scopes)
                      if accepted else dict(error='invalid_client'))
            data = json.dumps(result).encode()
            self.send_response(200 if accepted else 401)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Authorization', expected_header)
            self.send_header('Set-Cookie', 'as-private-cookie')
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *unused):
            pass

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                forwarded.append(dict(self.headers))
            accepted = self.headers.get('Authorization') == 'Bearer ' + token
            data = b'upstream-ok' if accepted else b'bad-upstream-authorization'
            self.send_response(200 if accepted else 403)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *unused):
            pass

    authorizer = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Authorizer)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                            str(Path(args.testdata) / 'localhost_key.pem'))
    authorizer.socket = context.wrap_socket(authorizer.socket, server_side=True)
    upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    for server in (authorizer, upstream):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='rut-client-basic-') as directory:
            root = Path(directory)
            examples = Path(__file__).resolve().parent.parent / 'examples'
            (root / 'middleware').mkdir()
            modules = []
            for name in ('oauth_client.rut', 'introspection.rut'):
                target = root / 'middleware' / name
                target.write_bytes((examples / 'middleware' / name).read_bytes())
                modules.append(target)
            example = (examples / 'upstream-oauth-client-basic.rut').read_text()
            prefix = example[:example.index('route GET')].replace('listen :8080\n', '').replace(
                '127.0.0.1:9000', f'127.0.0.1:{upstream.server_port}')
            route = example[example.index('route GET'):]
            stable = route.replace('match authorization.isEmpty',
                'match authorization.isEmpty || serviceAuthorization != oauthClientBasicAuthorization(env("TOKEN_CLIENT_ID"), env("TOKEN_CLIENT_SECRET")).or("")')
            source = prefix + stable
            source += stable.replace('/raw-client-reports', '/raw-scoped-reports').replace(
                'oauth_client.clientCredentials(serviceAuthorization)',
                'oauth_client.clientCredentialsForScope(serviceAuthorization, env("UPSTREAM_SCOPE"))')
            invalid_paths = ['/empty-id']
            source += ('route GET "/empty-id" {\n'
                       '    let built = oauth_client.basicAuthorization("", env("TOKEN_CLIENT_SECRET"))\n'
                       '    return response(200, body: built)\n}\n')
            program, log = root / 'gateway.rut', root / 'gateway.log'
            program.write_text(source)
            endpoint = dict(address='127.0.0.1', port=authorizer.server_port,
                            serverName='localhost', caFile=str(Path(args.testdata) / 'localhost_cert.pem'), path='/token')
            env = dict(os.environ, TOKEN_ENDPOINT=json.dumps(endpoint), TOKEN_CLIENT_ID=client_id,
                       TOKEN_CLIENT_SECRET=client_secret, UPSTREAM_SCOPE=scopes,
                       DOWNSTREAM_KEY=caller_key)
            with log.open('wb') as output:
                process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                            '--shards', '2', '--no-pin', '--drain', '0'],
                                           env=env, stdout=output, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            port = None
            while time.monotonic() < deadline:
                startup = log.read_bytes()
                found = re.search(rb'Listening on port ([0-9]+) with', startup)
                if found:
                    port = int(found.group(1))
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

            def request(path, authorization=None):
                headers = [('authorization', authorization or 'Bearer ' + caller_key),
                           ('x-client-id', 'caller-forged'), ('x-client-secret', 'caller-forged')]
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                try:
                    connection.request('GET', path, headers=dict(headers))
                    reply = connection.getresponse()
                    result = reply.status, reply.read()
                    assert 'Authorization' not in reply.headers and 'Set-Cookie' not in reply.headers
                finally:
                    connection.close()
                result_h2 = h2_request(port, path, headers)
                assert result_h2[0] == result[0], (path, result, result_h2)
                if result[0] == 200:
                    assert result_h2[1] == result[1]
                return result

            assert request('/raw-client-reports', 'Bearer wrong')[0] == 401
            assert not calls and not forwarded
            for path in ('/raw-client-reports', '/raw-scoped-reports'):
                before = len(calls)
                assert request(path) == (200, b'upstream-ok')
                assert len(calls) == before + 2 and all(ok for ok, _ in calls)
                for values in forwarded:
                    assert all(client_id not in value and client_secret not in value and expected_header not in value
                               for value in values.values())
            for path in invalid_paths:
                before = len(calls), len(forwarded)
                assert request(path)[0] == 503
                assert (len(calls), len(forwarded)) == before
            process.terminate()
            process.wait(timeout=5)
            assert process.returncode == 0
            logged = log.read_bytes()
            assert all(value.encode() not in logged for value in
                       (client_id, client_secret, expected_header, userinfo, token, caller_key))
            print(f'PASS: {args.backend} configured client Basic, independent TLS AS, H1/H2 and credential isolation')
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        authorizer.shutdown()
        authorizer.server_close()
        upstream.shutdown()
        upstream.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
