#!/usr/bin/env python3
"""Native Rut routing intent witnesses over real downstream/upstream sockets."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import subprocess
import ssl
import socket
from auth_h2_fixture import request as h2_request, frame, string, status
import tempfile
import threading
import time


def h2_body_abort_then_probe(port, context, cancel):
    transport = socket.create_connection(('127.0.0.1', port), timeout=5)
    if context:
        transport = context.wrap_socket(transport, server_hostname='localhost')
    def headers(method, path):
        return bytes((0x83 if method == 'POST' else 0x82, 0x87 if context else 0x86, 4)) + string(path) + b'\x01' + string('localhost')
    with transport as peer:
        first = headers('POST', '/raw/aborted') + b'\x00' + string('content-length') + string('7')
        packet = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0)
        packet += frame(1, 4, 1, first) + frame(0, 0 if cancel else 1, 1, b'abc')
        if cancel:
            packet += frame(3, 0, 1, (8).to_bytes(4, 'big'))
        packet += frame(1, 5, 3, headers('GET', '/plain'))
        peer.sendall(packet)
        codes, bodies, ended = {}, {}, set()
        def exact(length):
            result = b''
            while len(result) < length:
                data = peer.recv(length - len(result))
                assert data, 'H2 abort/probe connection closed early'
                result += data
            return result
        for _ in range(64):
            head = exact(9)
            payload = exact(int.from_bytes(head[:3], 'big'))
            kind, flags = head[3:5]
            stream = int.from_bytes(head[5:], 'big') & 0x7fffffff
            assert kind != 7, payload
            if kind == 4 and not flags & 1:
                peer.sendall(frame(4, 1, 0))
            if kind == 1:
                codes[stream] = status(payload)
            if kind == 0:
                bodies[stream] = bodies.get(stream, b'') + payload
            if kind in (0, 1) and flags & 1:
                ended.add(stream)
            if 3 in ended and (cancel or 1 in ended):
                assert codes[3] == 200 and bodies.get(3) == b'/plain|', (codes, bodies)
                if cancel:
                    assert 1 not in codes, codes
                else:
                    assert codes[1] == 400, codes
                return
        raise AssertionError('H2 abort/probe did not complete')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--h2', action='store_true')
    parser.add_argument('--testdata')
    args = parser.parse_args()
    context = None
    if args.tls:
        assert args.testdata, '--testdata is required for TLS'
        context = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem'))
        context.set_alpn_protocols(['h2' if args.h2 else 'http/1.1'])
    def connection(port):
        if context:
            return http.client.HTTPSConnection('localhost', port, context=context, timeout=5)
        return http.client.HTTPConnection('127.0.0.1', port, timeout=5)

    seen = []
    lock = threading.Lock()
    stream_headers_seen = threading.Event()

    class Origin(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            if self.path == '/v1/stream':
                stream_headers_seen.set()
            size = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(size)
            with lock:
                seen.append((self.command, self.path, self.headers.get('Host'), body))
            response = self.path.encode() + b'|' + body
            self.send_response(200)
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        do_POST = do_GET

        def log_message(self, *_):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-routing-capabilities-') as directory:
            root = Path(directory)
            source = root / 'gateway.rut'
            source.write_text(f'''upstream backend at "127.0.0.1:{origin.server_port}"
route "/users/:id" {{
    let target = "/internal/accounts/" + req.params.id
    return forward(backend, load_balance: .roundRobin, set_path: target)
}}
route GET "/alias" {{
    guard let target = req.header("X-Target") else {{ return 400 }}
    return forward(backend, load_balance: .roundRobin, set_path: target)
}}
route GET "/plain" {{ return forward(backend, load_balance: .roundRobin) }}
''' + r'''
func originalPath(_ req: i32, _ resp: Response) -> i32 {
    resp.set("X-Original-Path", req.path)
    0
}
chain audit { after originalPath(req, resp) }
route "/raw" {
    return forward(backend, load_balance: .roundRobin,
        target_transform: { strip_prefix: "/raw/", replace_prefix: "/v1/", mode: .rawPrefix })
}
route POST "/wait" {
    wait(1ms)
    return forward(backend, load_balance: .roundRobin,
        target_transform: { strip_prefix: "/wait/", replace_prefix: "/v1/", mode: .rawPrefix })
}
route GET "/norm" {
    return forward(backend, load_balance: .roundRobin,
        target_transform: { strip_prefix: "/norm/", replace_prefix: "/v1/", mode: .normalizedPrefix })
}
route GET "/audit" use chain audit {
    return forward(backend, load_balance: .roundRobin,
        target_transform: { strip_prefix: "/audit/", replace_prefix: "/v1/", mode: .rawPrefix })
}
route GET "/preserve" {
    return forward(backend, load_balance: .roundRobin, request_policy: {
        version: .http11, host: .preserve, connection: .omit,
        header_names: .lowercase, forwarded_proto: .http,
        strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade, .proxyConnection]
    }, target_transform: { strip_prefix: "/preserve/", replace_prefix: "/v1/", mode: .rawPrefix })
}
route GET "/metadata" {
    guard let local = parseInt(req.header("X-Local-Port").or("")) else { return 400 }
    guard req.localPort == local && req.remotePort > 0 else { return 422 }
    let secure = req.header("X-Secure").or("") == "yes"
    guard req.isTls == secure else { return 403 }
    let name = req.sni.or("none")
    return response(200, body: name)
}
route "/" {
    guard let path = req.normalizedPath else { return 400 }
    guard let target = req.normalizedTarget else { return 400 }
    guard path != "/private" else { return 403 }
    if path == "/admin" || path == "/api/users" {
        return forward(backend, load_balance: .roundRobin, set_path: target)
    } else { if req.pathOnly.hasPrefix("/catalog") {
        return forward(backend, load_balance: .roundRobin,
            target_transform: { strip_prefix: "/catalog", replace_prefix: "/", mode: .rawPrefix })
    } else { return 404 } }
}
''')
            log = root / 'gateway.log'
            with log.open('wb') as output:
                command = [args.server, '0', str(source), '--backend', args.backend,
                           '--shards', '2', '--no-pin', '--drain', '0']
                if args.h2 or args.tls:
                    command += ['--h2']
                if args.tls:
                    command += ['--tls-cert', str(Path(args.testdata) / 'localhost_cert.pem'),
                                '--tls-key', str(Path(args.testdata) / 'localhost_key.pem')]
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                port = None
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    data = log.read_bytes()
                    match = re.search(rb'Listening on port ([0-9]+) with', data)
                    if match:
                        port = int(match[1])
                        break
                    if process.poll() is not None:
                        if args.backend == 'io_uring' and b'io_uring is unavailable' in data:
                            print('SKIP: io_uring is unavailable')
                            return 77
                        raise AssertionError(data.decode(errors='replace'))
                    time.sleep(.02)
                assert port, log.read_text(errors='replace')
                metadata_headers = {'X-Local-Port': str(port), 'X-Secure': 'yes' if args.tls else 'no',
                                    'X-Forwarded-Proto': 'http' if args.tls else 'https', 'SNI': 'spoof.example'}
                expected_name = b'localhost' if args.tls else b'none'
                if args.h2:
                    result = h2_request(port, '/metadata', list(metadata_headers.items()), tls_context=context)
                else:
                    probe = connection(port)
                    try:
                        probe.request('GET', '/metadata', headers=metadata_headers)
                        reply = probe.getresponse()
                        result = (reply.status, reply.read())
                    finally:
                        probe.close()
                assert result == (200, expected_name), ('metadata', result)
                normalized = [('/api/../admin?q=%2f', b'/admin?q=%2f|'),
                              ('/api/%75sers', b'/api/users|'), ('/api//users', b'/api/users|')]
                for path, expected in normalized:
                    if args.h2:
                        result = h2_request(port, path, [], tls_context=context)
                    else:
                        probe = connection(port)
                        try:
                            probe.request('GET', path)
                            reply = probe.getresponse()
                            result = (reply.status, reply.read())
                        finally:
                            probe.close()
                    assert result == (200, expected), ('normalized selection', path, result)
                if args.h2:
                    cases = [
                        ('GET', '/users/7', [], b'', b'/internal/accounts/7|'),
                        ('GET', '/alias', [('x-target', '/grown/aliased/path?q=1')], b'', b'/grown/aliased/path?q=1|'),
                        ('POST', '/raw/users', [], b'payload', b'/v1/users|payload'),
                        ('POST', '/wait/users', [], b'payload', b'/v1/users|payload'),
                        ('GET', '/norm//a/../%75sers?x=%2f', [], b'', b'/v1/users?x=%2f|'),
                        ('GET', '/audit/users?x=1', [], b'', b'/v1/users?x=1|'),
                        ('GET', '/catalogue', [], b'', b'/ue|'),
                    ]
                    for method, path, fields, body, expected in cases:
                        result = h2_request(port, path, fields, body=body, method=method, tls_context=context)
                        assert result == (200, expected), (path, result)
                    with lock:
                        before = len(seen)
                    for target in ('relative', '/bad%xx', '/bad#fragment', '/bad path'):
                        code, _ = h2_request(port, '/alias', [('x-target', target)], tls_context=context)
                        assert code == 400, (target, code)
                    with lock:
                        assert len(seen) == before, seen[before:]
                    for cancel in (True, False):
                        with lock:
                            before = len(seen)
                        h2_body_abort_then_probe(port, context, cancel)
                        with lock:
                            assert len(seen) == before + 1 and seen[-1][1] == '/plain', seen[before:]
                    print(f'PASS: {args.backend} H2 tls={args.tls}: dynamic and prefix targets, body, after headers, timer continuation, refusal and body abort/reuse; 19 requests')
                    return 0
                client = connection(port)
                try:
                    cases = [
                        ('GET', '/users/7', None, {}, b'/internal/accounts/7|'),
                        ('GET', '/alias', None, {'X-Target': '/much/longer/aliased/path?q=1&q=2'},
                         b'/much/longer/aliased/path?q=1&q=2|'),
                        ('GET', '/alias', None, {'X-Target': '/x'}, b'/x|'),
                        ('POST', '/users/42', b'payload', {}, b'/internal/accounts/42|payload'),
                        ('GET', '/plain', None, {}, b'/plain|'),
                        ('GET', '/catalogue', None, {}, b'/ue|'),
                        ('GET', '/raw/%75sers?x=%2f&x=1', None, {}, b'/v1/%75sers?x=%2f&x=1|'),
                        ('POST', '/raw/users', b'payload', {}, b'/v1/users|payload'),
                        ('GET', '/raw/users', None, {'Content-Length': '0'}, b'/v1/users|'),
                        ('GET', '/norm//a/../%75sers?x=%2f', None, {}, b'/v1/users?x=%2f|'),
                        ('GET', '/audit/users?x=1', None, {}, b'/v1/users?x=1|'),
                        ('GET', '/preserve/users', None, {'Host': 'client.example:8000'}, b'/v1/users|'),
                    ]
                    if args.tls:
                        # This legacy explicit-header profile is cleartext-only;
                        # the transparent profiles above preserve Host on TLS.
                        cases = [case for case in cases if not case[1].startswith('/preserve/')]
                    for method, path, body, headers, expected in cases:
                        client.request(method, path, body=body, headers=headers)
                        reply = client.getresponse()
                        received = reply.read()
                        assert (reply.status, received) == (200, expected), (path, reply.status, received)
                        if path.startswith('/audit/'):
                            assert reply.getheader('X-Original-Path') == path, reply.getheaders()
                        if path.startswith('/preserve/'):
                            with lock:
                                assert seen[-1][2] == 'client.example:8000', seen[-1]
                    # Headers and body arrive separately; verifies the rewritten
                    # header boundary survives the later body-read callback.
                    client.putrequest('POST', '/raw/stream')
                    client.putheader('Content-Length', '7')
                    client.endheaders()
                    assert stream_headers_seen.wait(2), 'H1 origin headers were buffered behind the body'
                    client.send(b'delayed')
                    reply = client.getresponse()
                    assert (reply.status, reply.read()) == (200, b'/v1/stream|delayed')
                finally:
                    client.close()
                # Invalid target is refused before any origin request, including
                # request-header-backed values and non-origin-form URIs.
                for target in ('not-origin-form', '/bad%xx', '/bad#fragment', '/bad path'):
                    with lock:
                        before = len(seen)
                    client = connection(port)
                    try:
                        client.request('GET', '/alias', headers={'X-Target': target})
                        reply = client.getresponse()
                        reply.read()
                        assert reply.status == 400, (target, reply.status)
                    finally:
                        client.close()
                    with lock:
                        assert len(seen) == before, (target, seen[before:])
                with lock:
                    assert len(seen) == len(cases) + 4, seen
                    assert seen[6][3] == b'payload', seen
                print(f'PASS: {args.backend} tls={args.tls}: dynamic captures, borrowed target ownership, body, '
                      f'prefix modes, Host/after headers, streaming body and invalid-target refusal; {len(cases) + 9} requests')
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
        worker.join(timeout=5)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
