#!/usr/bin/env python3
"""Real TLS callouts: data-dependent composition, failure, isolation and cancellation."""
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    received = []
    lock = threading.Lock()
    entered, release = threading.Event(), threading.Event()

    class Origin(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            with lock:
                fields = dict(self.headers)
                fields['_once_count'] = len(self.headers.get_all('X-Once', []))
                received.append((self.path, fields, body))
            mode = self.headers.get('X-Mode', '')
            if mode == 'slow':
                entered.set()
                release.wait(3)
            else:
                time.sleep(.025)  # Force several timer continuations per call.
            try:
                if mode == 'truncated':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nx')
                    self.close_connection = True
                    return
                if mode == 'chunked':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n')
                    return
                if mode == 'large':
                    output = b'x' * 9000
                elif self.path == '/first':
                    output = b'{"consumer":"alice","scope":"read"}'
                else:
                    output = b'accepted:' + body
                status = {'deny': 403, 'redirect': 302, 'unavailable': 503}.get(mode, 200)
                self.send_response(status)
                self.send_header('Content-Length', str(len(output)))
                self.send_header('X-User', 'alice')
                self.send_header('X-Consumer-Id', 'alice')
                self.send_header('X-Consumer-Group', 'readers')
                self.send_header('X-Role', 'reader')
                self.send_header('x-role', 'writer')
                self.send_header('Set-Cookie', 'external=secret')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(output)
            except (OSError, ssl.SSLError):
                pass

        def log_message(self, *unused):
            pass

    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                            str(Path(args.testdata) / 'localhost_key.pem'))
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    policy = dict(address='127.0.0.1', port=origin.server_port, serverName='localhost',
                  caFile=str(Path(args.testdata) / 'localhost_cert.pem'), path='/first')
    second = dict(policy, path='/second')
    source = '''
func invoke(_ request: Json) -> Json {
    httpCall(env("CALLOUT_FIRST"), request, 300)
}
func text(_ reply: Json, _ path: str) -> str {
    guard let value = json.get(reply, path) else { nil }
    json.string(value)
}
func accepted(_ reply: Json) -> bool {
    guard let value = json.get(reply, "/status") else { false }
    guard let status = json.int(value) else { false }
    status == 200
}
func composed(_ request: Json) -> Json {
    let pending = invoke(request)
    guard let first = pending else { nil }
    guard accepted(first) else { nil }
    let role = text(first, "/headers/x-role/1").or("missing")
    guard let body = json.value("helper:" + role) else { nil }
    guard let next = json.set(request, "/body", body) else { nil }
    httpCall(env("CALLOUT_SECOND"), next, 300)
}
route GET "/ready" { return 204 }
route POST "/helper" {
    guard let request = json.parse(req.body) else { return 400 }
    let result = composed(request)
    guard let reply = result else { return 503 }
    let body = text(reply, "/body").or("missing")
    return response(200, body: body)
}
route POST "/compose" {
    let saved = req.header("X-Saved").or("saved")
    guard let request = json.parse(req.body) else { return 400 }
    let pending = invoke(request)
    guard let first = pending else { return 501 }
    guard accepted(first) else { return 403 }
    let role = text(first, "/headers/x-role/1").or("missing")
    guard let nextBody = json.value(saved + ":" + role) else { return 504 }
    guard let nextRequest = json.set(request, "/body", nextBody) else { return 505 }
    let nextPending = httpCall(env("CALLOUT_SECOND"), nextRequest, 300)
    guard let next = nextPending else { return 506 }
    let body = text(next, "/body").or("missing")
    return response(200, body: body)
}
route POST "/one" {
    guard let request = json.parse(req.body) else { return 400 }
    let result = httpCall(env("CALLOUT_FIRST"), request, 100)
    guard let reply = result else { return 503 }
    guard let body = json(reply) else { return 503 }
    return response(200, body: body)
}
route POST "/untrusted" {
    guard let request = json.parse(req.body) else { return 400 }
    let result = httpCall(env("CALLOUT_UNTRUSTED"), request, 100)
    guard let reply = result else { return 503 }
    guard let body = json(reply) else { return 503 }
    return response(200, body: body)
}
'''
    source += r"""
func choose(_ request: Json, _ first: bool) -> Json {
    if first {
        httpCall(env("CALLOUT_FIRST"), request, 300)
    } else {
        httpCall(env("CALLOUT_SECOND"), request, 300)
    }
}
route POST "/choose" {
    guard let request = json.parse(req.body) else { return 400 }
    let result = choose(request, req.header("X-Choice").or("first") == "first")
    guard let reply = result else { return 503 }
    guard let body = json(reply) else { return 503 }
    return response(200, body: body)
}
route POST "/proxy" {
    req.add("X-Once", "yes")
    guard let request = json.parse(req.body) else { return 400 }
    let result = httpCall(env("CALLOUT_FIRST"), request, 300)
    guard let reply = result else { return 503 }
    let user = text(reply, "/headers/x-user/0").or("")
    match user != "" {
        true => {
            req.set("X-Identity", user)
            req.remove("Authorization")
            return forward(backend, load_balance: .roundRobin)
        }
        _ => { return 403 }
    }
}
route POST "/param/:id" {
    let saved = req.param("id").or("missing")
    guard let request = json.parse("{\"method\":\"POST\",\"headers\":{\"X-Mode\":\"slow\"}}") else { return 400 }
    let pending = httpCall(env("CALLOUT_FIRST"), request, 300)
    guard let reply = pending else { return 503 }
    return response(200, body: saved)
}
"""
    source += ('upstream backend { host: "127.0.0.1", port: ' + str(origin.server_port) +
               ', tls: { ca: ' + json.dumps(policy['caFile']) + ', server_name: "localhost" } }\n')
    source += (Path(__file__).resolve().parent.parent / 'examples/http-call.rut').read_text()
    # Keep the test independent of implicit credential/identity propagation.
    with tempfile.TemporaryDirectory(prefix='rut-http-call-') as directory:
        root = Path(directory)
        program = root / 'gateway.rut'
        program.write_text(source)
        log = root / 'gateway.log'
        env = dict(os.environ, CALLOUT_FIRST=json.dumps(policy), CALLOUT_SECOND=json.dumps(second),
                   CALLOUT_UNTRUSTED=json.dumps(dict(policy, serverName='wrong.invalid')),
                   CALL_AUTH=json.dumps(policy), CALL_AUDIT=json.dumps(second))
        with log.open('wb') as output:
            process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                '--shards', '1', '--no-pin', '--drain', '0', '--max-connections-per-shard', '32'],
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
                program.unlink()  # Native artifact must own policy/code after source removal.

                def request(path='/compose', mode='', saved='saved', headers=None, body='input', choice='first'):
                    message = json.dumps(dict(method='POST', headers=dict({'X-Mode': mode}, **(headers or {})), body=body))
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                    try:
                        conn.request('POST', path, message, {'X-Saved': saved, 'Authorization': 'Bearer must-not-leak',
                                                           'X-User': 'forged', 'Cookie': 'client=secret', 'X-Choice': choice})
                        reply = conn.getresponse()
                        return reply.status, reply.headers, reply.read()
                    finally:
                        conn.close()

                def frame(kind, flags, stream, payload=b''):
                    return len(payload).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + payload

                def h2_send(sock, stream, path='/compose', mode='', saved='h2-snapshot',
                            end_stream=False):
                    data = json.dumps(dict(method='POST', headers={'X-Mode': mode}, body='input')).encode()
                    # Literal HPACK fields without Huffman or a dynamic table.
                    content_length = 0 if end_stream else len(data)
                    fields = [(':method', 'POST'), (':scheme', 'http'), (':path', path),
                              (':authority', 'localhost'), ('content-length', str(content_length)), ('x-saved', saved)]
                    block = b''
                    for name, value in fields:
                        name, value = name.encode(), value.encode()
                        assert len(name) < 127 and len(value) < 127
                        block += bytes((0, len(name))) + name + bytes((len(value),)) + value
                    flags = 5 if end_stream else 4
                    sock.sendall(frame(1, flags, stream, block) +
                                 (b'' if end_stream else frame(0, 1, stream, data)))

                def h2_body(sock, target):
                    def exact(size):
                        result = b''
                        while len(result) < size:
                            data = sock.recv(size - len(result))
                            assert data, 'incomplete HTTP/2 frame'
                            result += data
                        return result
                    body = b''
                    while True:
                        head = exact(9)
                        payload = exact(int.from_bytes(head[:3], 'big'))
                        kind, flags = head[3:5]
                        stream = int.from_bytes(head[5:], 'big') & 0x7fffffff
                        if kind == 4 and not flags & 1:
                            sock.sendall(frame(4, 1, 0))
                        assert kind != 7, payload
                        if stream != target:
                            continue
                        assert kind != 3, payload
                        if kind == 0:
                            body += payload
                        if kind in (0, 1) and flags & 1:
                            return body

                def h2_open():
                    sock = socket.create_connection(('127.0.0.1', port), timeout=4)
                    sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0))
                    return sock

                before = len(received)
                status, fields, body = request(saved='stable')
                assert (status, body) == (200, b'accepted:stable:writer'), (status, body)
                assert len(received) == before + 2, received
                assert [r[0] for r in received[-2:]] == ['/first', '/second']
                assert not any(name.lower() in ('authorization', 'cookie', 'x-user', 'x-saved')
                               for _, headers, _ in received for name in headers), received
                assert fields.get('Set-Cookie') is None and fields.get('X-User') is None
                before = len(received)
                status, _, data = request('/helper')
                assert (status, data) == (200, b'accepted:helper:writer'), (status, data)
                assert len(received) == before + 2, 'helper bindings replayed a completed call'
                before = len(received)
                assert request('/helper', mode='deny')[0] == 503
                assert len(received) == before + 1, 'helper guard executed the second call'
                before = len(received)
                status, _, data = request('/authorize-and-audit', headers={'Authorization': 'Bearer selected'})
                assert status == 204, (status, data)
                assert len(received) == before + 2, received
                assert received[-2][1]['Authorization'] == 'Bearer selected', received[-2]
                assert received[-1][2] == b'alice:readers', received[-1]
                assert 'Authorization' not in received[-1][1], received[-1]
                for choice, path in [('first', '/first'), ('second', '/second')]:
                    before = len(received)
                    status, _, data = request('/choose', choice=choice)
                    assert status == 200 and json.loads(data)['ok'], (status, data)
                    assert len(received) == before + 1 and received[-1][0] == path, received
                status, _, data = request('/proxy')
                assert status == 200, (status, data)
                assert received[-1][0] == '/proxy' and received[-1][1]['_once_count'] == 1, received[-1]
                assert received[-1][1].get('X-Identity') == 'alice', received[-1]
                assert 'Authorization' not in received[-1][1], received[-1]
                before = len(received)
                assert request(mode='deny')[0] == 403
                assert len(received) == before + 1, 'failed guard executed the second call'
                for mode, expected in [('deny', 403), ('redirect', 302), ('unavailable', 503)]:
                    status, _, data = request('/one', mode)
                    reply = json.loads(data)
                    assert status == 200 and reply['ok'] and reply['status'] == expected, (mode, reply)
                    assert reply['headers']['x-role'] == ['reader', 'writer']
                status, _, data = request('/one', 'chunked')
                assert json.loads(data)['body'] == 'ok', (status, data)
                for mode in ('truncated', 'large'):
                    _, _, data = request('/one', mode)
                    assert json.loads(data)['error'] == 'transport', (mode, data)
                before = len(received)
                _, _, data = request('/one', headers={'Host': 'attacker'})
                assert json.loads(data)['error'] == 'invalidRequest', data
                assert len(received) == before
                _, _, data = request('/untrusted')
                assert json.loads(data)['error'] == 'transport', data
                assert len(received) == before, 'unverified TLS peer received an HTTP request'
                entered.clear(); release.clear()
                _, _, data = request('/one', 'slow')
                assert json.loads(data)['error'] == 'timeout', data
                assert entered.is_set()
                release.set()
                with ThreadPoolExecutor(max_workers=4) as workers:
                    results = list(workers.map(lambda i: request(saved=f'user-{i}'), range(4)))
                for i, (status, _, data) in enumerate(results):
                    assert (status, data) == (200, f'accepted:user-{i}:writer'.encode()), (i, status, data)
                with h2_open() as sock:
                    before = len(received)
                    h2_send(sock, 1)
                    assert h2_body(sock, 1) == b'accepted:h2-snapshot:writer'
                    assert len(received) == before + 2, received
                    h2_send(sock, 3, saved='next-stream')
                    assert h2_body(sock, 3) == b'accepted:next-stream:writer'
                # Keep the first callout pending while another H2 connection
                # reuses the synthesized-request stack with a different capture.
                entered.clear(); release.clear()
                before = len(received)
                with h2_open() as first, h2_open() as second:
                    h2_send(first, 1, path='/param/original', end_stream=True)
                    assert entered.wait(4)
                    h2_send(second, 1, path='/param/replacement', end_stream=True)
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        with lock:
                            if len(received) >= before + 2:
                                break
                        time.sleep(.01)
                    assert len(received) >= before + 2, received
                    release.set()
                    second_body = h2_body(second, 1)
                    assert second_body == b'replacement', (second_body, received[before:])
                    first_body = h2_body(first, 1)
                    assert first_body == b'original', (first_body, received[before:])
                # Reset a suspended H2 stream and reuse its connection for a fresh call.
                entered.clear(); release.clear()
                with h2_open() as sock:
                    h2_send(sock, 1, path='/one', mode='slow')
                    assert entered.wait(1)
                    sock.sendall(frame(3, 0, 1, (8).to_bytes(4, 'big')))
                    release.set()
                    h2_send(sock, 3, saved='after-reset')
                    assert h2_body(sock, 3) == b'accepted:after-reset:writer'
                # Disconnect during the call, then force small connection slots to be reused.
                entered.clear(); release.clear()
                sock = socket.create_connection(('127.0.0.1', port), timeout=2)
                data = json.dumps(dict(method='POST', headers={'X-Mode': 'slow'})).encode()
                sock.sendall(b'POST /one HTTP/1.1\r\nHost: test\r\nContent-Length: ' + str(len(data)).encode() + b'\r\n\r\n' + data)
                assert entered.wait(1)
                sock.close(); release.set()
                for i in range(8):
                    assert request(saved=f'fresh-{i}')[2] == f'accepted:fresh-{i}:writer'.encode()
                print(f'PASS: {args.backend} composed TLS callouts, guards, errors, isolation and cancellation')
            finally:
                release.set()
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                    raise AssertionError('gateway shutdown did not join callout workers')
                if process.returncode not in (0, 77):
                    raise AssertionError((process.returncode, log.read_text(errors='replace')))
    origin.shutdown(); origin.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
