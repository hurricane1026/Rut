#!/usr/bin/env python3
"""RFC 8705 introspection binding over real TLS and relocated native routes."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
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


def exercise(args):
    fixtures = Path(args.testdata)
    certs = [fixtures / 'localhost_cert.pem', fixtures / 'mtls_second_cert.pem']
    key = fixtures / 'localhost_key.pem'
    digests = [hashlib.sha256(ssl.PEM_cert_to_DER_cert(c.read_text())).digest() for c in certs]
    thumbs = [base64.urlsafe_b64encode(d).rstrip(b'=').decode() for d in digests]
    assert digests[0] != digests[1]  # Same public key, different certificate DER.
    service_auth = 'Basic cmVzb3VyY2U6c2VydmljZS1zZWNyZXQ='
    received, forwarded = [], []
    lock = threading.Lock()
    revoked = threading.Event()

    class Authorizer(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            fields = parse_qs(raw.decode('ascii'), strict_parsing=True)
            assert self.path == '/introspect'
            assert set(fields) == {'token', 'token_type_hint'}
            assert fields['token_type_hint'] == ['access_token']
            assert len(fields['token']) == 1
            value = fields['token'][0]
            assert self.headers.get('Authorization') == service_auth
            assert self.headers.get('Cookie') is None
            with lock:
                received.append(value)
            index = 1 if value == 'bob' else 0
            body = dict(active=True, exp=int(time.time()) + 3600, aud='reports-api',
                        sub='bob' if index else 'alice', scope='reports:read',
                        cnf={'x5t#S256': thumbs[index]})
            changes = {
                'inactive': {'active': False}, 'expired': {'exp': 1},
                'wrong-audience': {'aud': 'another-api'}, 'no-permission': {'scope': 'other'},
                'no-subject': {'sub': ''}, 'unsafe-subject': {'sub': 'alice\r\nInjected: yes'},
                'null-cnf': {'cnf': None}, 'empty-cnf': {'cnf': {}},
                'other-method': {'cnf': {'jkt': thumbs[0]}},
                'ambiguous': {'cnf': {'x5t#S256': thumbs[0], 'jkt': 'other'}},
                'typed-thumb': {'cnf': {'x5t#S256': [thumbs[0]]}},
                'padded': {'cnf': {'x5t#S256': thumbs[0] + '='}},
                'short': {'cnf': {'x5t#S256': thumbs[0][:-1]}},
            }
            body.update(changes.get(value, {}))
            if value == 'revoked':
                body['active'] = not revoked.is_set()
            if value == 'missing-cnf':
                del body['cnf']
            data = json.dumps(body).encode()
            if value == 'escaped':
                data = data.replace(b'"cnf"', b'"c\\u006ef"').replace(b'x5t#S256', b'x5t\\u0023S256')
            if value == 'duplicate':
                data = data.replace(b'"cnf":', b'"cnf": {}, "c\\u006ef":')
            if value == 'malformed':
                data = b'{'
            if value == 'timeout':
                time.sleep(1.5)
            try:
                self.send_response(500 if value == 'unavailable' else 200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Connection', 'close')
                self.send_header('Set-Cookie', 'as-secret=do-not-leak')
                self.send_header('X-Client-Cert-Sha256', digests[0].hex())
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
            data = self.headers.get('X-Consumer-ID', '').encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *unused):
            pass

    authorizer = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Authorizer)
    upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(certs[0]), str(key))
    authorizer.socket = tls.wrap_socket(authorizer.socket, server_side=True)
    for server in (authorizer, upstream):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def context(index=0, certificate=True):
        result = ssl.create_default_context(cafile=str(certs[0]))
        if certificate:
            result.load_cert_chain(str(certs[index]), str(key))
        return result

    endpoint = dict(address='127.0.0.1', port=authorizer.server_port, serverName='localhost',
                    caFile=str(certs[0]), path='/introspect')
    examples = Path(__file__).resolve().parent.parent / 'examples'
    try:
        for mode in ('mtls', 'tls', 'cleartext'):
            with tempfile.TemporaryDirectory(prefix='rut-mtls-introspection-') as directory:
                root = Path(directory)
                source = root / 'gateway.rut'
                module = root / 'middleware/introspection.rut'
                module.parent.mkdir()
                module.write_bytes((examples / 'middleware/introspection.rut').read_bytes())
                source.write_text((examples / 'mtls-introspection.rut').read_text().replace(
                    ':9000"', f':{upstream.server_port}"') + '\nroute GET "/ready" { return 204 }\n')
                ca = root / 'clients.pem'
                ca.write_text(''.join(c.read_text() for c in certs))
                command = [args.server, '0', str(source), '--backend', args.backend,
                           '--shards', '2', '--no-pin', '--drain', '0']
                if mode != 'cleartext':
                    command += ['--h2', '--tls-cert', str(certs[0]), '--tls-key', str(key)]
                if mode == 'mtls':
                    command += ['--tls-client-ca', str(ca)]
                env = dict(os.environ, INTROSPECTION_AUTH=service_auth,
                           INTROSPECTION_ENDPOINT=json.dumps(endpoint))
                log = root / 'gateway.log'
                with log.open('wb') as output:
                    process = subprocess.Popen(command, env=env, stdout=output, stderr=subprocess.STDOUT)
                    try:
                        deadline, port = time.monotonic() + 30, None
                        while time.monotonic() < deadline:
                            startup = log.read_bytes()
                            match = re.search(rb'Listening on port ([0-9]+) with', startup)
                            if match:
                                port = int(match[1])
                                break
                            if process.poll() is not None:
                                if args.backend == 'io_uring' and b'io_uring is unavailable' in startup:
                                    return 77
                                raise AssertionError(startup.decode(errors='replace'))
                            time.sleep(.02)
                        assert port, log.read_text(errors='replace')

                        def request(value='alice', index=0, path='/reports', certificate=True):
                            if mode == 'cleartext':
                                connection = http.client.HTTPConnection('localhost', port, timeout=5)
                            else:
                                connection = http.client.HTTPSConnection(
                                    'localhost', port, timeout=5, context=context(index, certificate))
                            try:
                                connection.request('GET', path, headers={
                                    'Authorization': 'Bearer ' + value, 'X-Consumer-ID': 'forged',
                                    'X-Client-Cert-Sha256': digests[0].hex(),
                                    'X-Forwarded-Client-Cert': thumbs[0], 'Cookie': 'client-secret=do-not-leak'})
                                response = connection.getresponse()
                                return response.status, dict(response.headers), response.read()
                            finally:
                                connection.close()

                        assert request(path='/ready')[0] == 204
                        source.unlink()
                        module.unlink()  # Native artifact retains code after compiler/source removal.
                        if mode != 'mtls':
                            before = len(forwarded)
                            status, headers, _ = request()
                            assert status == 401, (mode, status)
                            assert 'invalid_token' in headers.get('WWW-Authenticate', '')
                            assert len(forwarded) == before
                            continue
                        for value, index in (('alice', 0), ('bob', 1), ('escaped', 0)):
                            status, headers, body = request(value, index)
                            assert (status, body) == (200, b'bob' if index else b'alice')
                            assert 'Set-Cookie' not in headers
                            assert 'Authorization' not in forwarded[-1] and 'Cookie' not in forwarded[-1]
                        for value, index, expected in (
                                ('alice', 1, 401), ('bob', 0, 401), ('inactive', 0, 401),
                                ('expired', 0, 401), ('wrong-audience', 0, 401),
                                ('no-subject', 0, 401), ('unsafe-subject', 0, 401),
                                ('missing-cnf', 0, 401), ('null-cnf', 0, 401), ('empty-cnf', 0, 401),
                                ('other-method', 0, 401), ('ambiguous', 0, 401), ('typed-thumb', 0, 401),
                                ('padded', 0, 401), ('short', 0, 401), ('no-permission', 0, 403),
                                ('duplicate', 0, 503), ('malformed', 0, 503),
                                ('unavailable', 0, 503), ('timeout', 0, 503)):
                            before = len(forwarded)
                            status, headers, body = request(value, index)
                            assert status == expected, (value, status, body)
                            if expected in (401, 403):
                                error = 'invalid_token' if expected == 401 else 'insufficient_scope'
                                assert error in headers.get('WWW-Authenticate', '')
                            assert len(forwarded) == before, value
                        before = len(forwarded)
                        before_received = len(received)
                        with socket.create_connection(('localhost', port), timeout=5) as raw:
                            with context().wrap_socket(raw, server_hostname='localhost') as sock:
                                sock.sendall(b'GET /reports HTTP/1.1\r\nHost: localhost\r\n'
                                             b'Authorization: Bearer timeout\r\n\r\n')
                                deadline = time.monotonic() + 2
                                while len(received) == before_received and time.monotonic() < deadline:
                                    time.sleep(.01)
                                assert len(received) > before_received and received[-1] == 'timeout'
                        time.sleep(1.6)  # Late AS completion cannot forward a cancelled request.
                        assert len(forwarded) == before
                        assert request('revoked')[0] == 200
                        revoked.set()
                        assert request('revoked')[0] == 401  # No stale active-token cache.
                        with socket.create_connection(('localhost', port), timeout=5) as raw:
                            with context().wrap_socket(raw, server_hostname='localhost') as sock:
                                before = len(received)
                                sock.sendall(b'GET /reports HTTP/1.1\r\nHost: localhost\r\n'
                                             b'Authorization: Bearer alice\r\nAuthorization: Bearer bob\r\n\r\n')
                                assert b' 401 ' in sock.recv(4096)
                                assert len(received) == before
                        try:
                            request(certificate=False)
                        except (ssl.SSLError, ConnectionResetError, BrokenPipeError,
                                http.client.RemoteDisconnected):
                            pass
                        else:
                            raise AssertionError('mTLS accepted absent client certificate')
                        def h2_request(value):
                            def integer(value, prefix, top=0):
                                maximum = (1 << prefix) - 1
                                if value < maximum:
                                    return bytes((top | value,))
                                data = bytearray((top | maximum,))
                                value -= maximum
                                while value >= 128:
                                    data.append((value & 127) | 128)
                                    value >>= 7
                                data.append(value)
                                return bytes(data)

                            def string(value):
                                return integer(len(value), 7) + value

                            def frame(kind, flags, stream, payload=b""):
                                return (len(payload).to_bytes(3, "big") + bytes((kind, flags)) +
                                        stream.to_bytes(4, "big") + payload)

                            tls = context()
                            tls.set_alpn_protocols(["h2"])
                            with socket.create_connection(("localhost", port), timeout=5) as raw:
                                with tls.wrap_socket(raw, server_hostname="localhost") as sock:
                                    assert sock.selected_alpn_protocol() == "h2"
                                    block = (b"\x82\x87\x04" + string(b"/reports") + b"\x01" +
                                             string(b"localhost") + b"\x0f\x08" +
                                             string(("Bearer " + value).encode()))
                                    sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" +
                                                 frame(4, 0, 0) + frame(1, 5, 1, block))

                                    def exact(length):
                                        data = b""
                                        while len(data) < length:
                                            part = sock.recv(length - len(data))
                                            assert part, "H2 closed before response completion"
                                            data += part
                                        return data

                                    status, body = None, b""
                                    while True:
                                        header = exact(9)
                                        payload = exact(int.from_bytes(header[:3], "big"))
                                        kind, flags = header[3], header[4]
                                        stream = int.from_bytes(header[5:], "big") & 0x7fffffff
                                        if kind == 4 and not flags & 1:
                                            sock.sendall(frame(4, 1, 0))
                                        assert kind != 7, payload
                                        if stream != 1:
                                            continue
                                        assert kind != 3, payload
                                        if kind == 1:
                                            # :status 200 is static index 8; 401 is a literal
                                            # indexed-name 8, encoded raw or RFC 7541 Huffman.
                                            if payload.startswith(b"\x88"):
                                                status = 200
                                            elif payload.startswith((b"\x48\x82\x68\x01",
                                                                     b"\x48\x03" + b"401")):
                                                status = 401
                                            else:
                                                raise AssertionError(("unexpected H2 status", payload))
                                        if kind == 0:
                                            body += payload
                                        if kind in (0, 1) and flags & 1:
                                            return status, body

                        assert h2_request("alice") == (200, b"alice")
                        assert h2_request("bob")[0] == 401
                        with ThreadPoolExecutor(max_workers=4) as workers:
                            results = list(workers.map(
                                lambda i: request(('alice', 'bob')[i % 2], (i // 2) % 2), range(8)))
                        for i, (status, _, body) in enumerate(results):
                            assert status == (200 if i % 2 == (i // 2) % 2 else 401), (i, status, body)
                        assert service_auth.encode() not in log.read_bytes()
                        assert b'client-secret' not in log.read_bytes()
                    finally:
                        if process.poll() is None:
                            process.terminate()
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                            raise AssertionError('mTLS introspection gateway shutdown timed out')
                        assert process.returncode in (0, 77), log.read_text(errors='replace')
    finally:
        for server in (authorizer, upstream):
            server.shutdown()
            server.server_close()
    print(f'PASS: {args.backend} certificate-bound introspection, fail-closed policy, isolation and spoof rejection')
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    raise SystemExit(exercise(parser.parse_args()))
