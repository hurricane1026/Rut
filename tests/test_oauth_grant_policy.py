#!/usr/bin/env python3
"""Exercise opt-in OAuth grant policies against a real HTTPS token service."""
import argparse
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', required=True)
    args = parser.parse_args()
    state = {'lifetime': 60, 'forwarded': 0}

    class Token(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            body = json.dumps(dict(access_token='issued', token_type='Bearer', expires_in=state['lifetime'], scope='read write')).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass

    class Backend(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            state['forwarded'] += 1
            self.send_response(204)
            self.end_headers()
        def log_message(self, *args):
            pass

    token = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Token)
    backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Backend)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'), str(Path(args.testdata) / 'localhost_key.pem'))
    token.socket = tls.wrap_socket(token.socket, server_side=True)
    for server in (token, backend):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    examples = Path(__file__).resolve().parent.parent / 'examples'
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'middleware').mkdir()
            for name in ('oauth_client.rut', 'introspection.rut', 'oauth_grant_lifetime.rut'):
                (root / 'middleware' / name).write_bytes((examples / 'middleware' / name).read_bytes())
            source = '''import "middleware/oauth_client.rut"
import "middleware/oauth_grant_lifetime.rut"
upstream backend at "127.0.0.1:PORT"
route GET "/cap" {
    let message = oauth_client.clientCredentialsForScope("Basic YTpi", "read write")
    let pending = httpCall(env("ENDPOINT"), message, 1000)
    guard let reply = pending else { return 503 }
    let authorization = oauth_client.authorizationForScopes(reply, "read write")
    guard let document = json.parse(json.string(json.get(reply, "/body").or(reply)).or("")) else { return 503 }
    let checked = oauth_grant_lifetime.documentWithMaxLifetime(document, 60)
    match authorization.isEmpty {
        false => {
            req.set("Authorization", authorization)
            return forward(backend, load_balance: .roundRobin)
        }
        _ => { return 503 }
    }
}
'''.replace('PORT', str(backend.server_port))
            (root / 'gateway.rut').write_text(source)
            endpoint = dict(address='127.0.0.1', port=token.server_port, serverName='localhost', caFile=str(Path(args.testdata).resolve() / 'localhost_cert.pem'), path='/token')
            with (root / 'log').open('wb') as log:
                process = subprocess.Popen([args.server, '0', str(root / 'gateway.rut'), '--backend', args.backend, '--shards', '1', '--no-pin', '--drain', '0'], env=dict(os.environ, ENDPOINT=json.dumps(endpoint)), stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        text = (root / 'log').read_bytes()
                        match = re.search(rb'Listening on port ([0-9]+) with', text)
                        if match:
                            break
                        if process.poll() is not None:
                            if args.backend == 'io_uring' and b'io_uring is unavailable' in text:
                                return 77
                            raise AssertionError(text.decode(errors='replace'))
                        time.sleep(.02)
                    else:
                        raise AssertionError('startup timed out')
                    port = int(match.group(1))
                    for lifetime, expected in ((1, 204), (60, 204), (61, 503), (0, 503), ('60', 503), (2**63, 503)):
                        state['lifetime'] = lifetime
                        before = state['forwarded']
                        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                        conn.request('GET', '/cap')
                        response = conn.getresponse()
                        response.read()
                        assert response.status == expected, (lifetime, response.status)
                        assert state['forwarded'] == before + (expected == 204)
                        conn.close()
                finally:
                    process.terminate()
                    process.wait(timeout=15)
    finally:
        for server in (token, backend):
            server.shutdown()
            server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
