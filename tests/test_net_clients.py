#!/usr/bin/env python3
"""Native-loaded Rut clients over TCP, verified TLS and actual UDP datagrams."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    args = parser.parse_args()
    requests = []
    tls_alpn = []
    active = set()
    received_datagrams = []
    lock = threading.Lock()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            with lock:
                active.add(self.request)
            try:
                self.request.settimeout(3)
                data = b''
                while not data.endswith(b'\r\n') or data.startswith(b'*') and len(data) < 14:
                    chunk = self.request.recv(8192)
                    if not chunk:
                        return
                    data += chunk
                with lock:
                    requests.append(data)
                    if isinstance(self.request, ssl.SSLSocket):
                        tls_alpn.append((data, self.request.selected_alpn_protocol()))
                if data == b'eof\r\n':
                    return
                if data == b'slow\r\n':
                    while self.request.recv(8192):
                        pass
                    return
                if data.startswith(b'GET /http '):
                    reply = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
                elif data == b'*1\r\n$4\r\nPING\r\n':
                    reply = b'+PONG\r\n'
                elif data == b'short\r\n':
                    reply = b'x'
                elif data == b'long\r\n':
                    reply = b'x' * 100
                else:
                    reply = b'hello\r\nTAIL'
                for byte in reply:
                    self.request.sendall(bytes((byte,)))
                    time.sleep(.001)
                if data == b'short\r\n':
                    return
                # Wait for request-scope automatic cleanup, not a server EOF.
                while self.request.recv(8192):
                    pass
            except (OSError, ssl.SSLError):
                pass
            finally:
                with lock:
                    active.discard(self.request)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    plain = Server(('127.0.0.1', 0), Handler)
    secure = Server(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert = Path(args.testdata) / 'localhost_cert.pem'
    context.load_cert_chain(str(cert), str(Path(args.testdata) / 'localhost_key.pem'))
    context.set_alpn_protocols(['http/1.1'])
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    for server in (plain, secure):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('127.0.0.1', 0))
    stopped = threading.Event()
    udp_socket.settimeout(.05)

    # Observe the wire offer directly. Python's ssl API only exposes the
    # negotiated protocol, which cannot distinguish no offer from no overlap.
    alpn_offers = []

    class ClientHelloProbe(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)

            def exact(length):
                data = b''
                while len(data) < length:
                    part = self.request.recv(length - len(data))
                    if not part:
                        raise EOFError()
                    data += part
                return data

            try:
                header = exact(5)
                assert header[0] == 22
                body = exact(int.from_bytes(header[3:5], 'big'))
                assert body[0] == 1
                hello = body[4:]
                offset = 2 + 32
                offset += 1 + hello[offset]
                offset += 2 + int.from_bytes(hello[offset:offset + 2], 'big')
                offset += 1 + hello[offset]
                ext_length = int.from_bytes(hello[offset:offset + 2], 'big')
                offset += 2
                end = offset + ext_length
                offered = None
                while offset < end:
                    kind = int.from_bytes(hello[offset:offset + 2], 'big')
                    size = int.from_bytes(hello[offset + 2:offset + 4], 'big')
                    value = hello[offset + 4:offset + 4 + size]
                    if kind == 16:
                        offered = value
                    offset += 4 + size
                alpn_offers.append(offered)
            except (EOFError, OSError, AssertionError):
                alpn_offers.append(b'invalid-clienthello')

    probe = Server(('127.0.0.1', 0), ClientHelloProbe)
    threading.Thread(target=probe.serve_forever, daemon=True).start()

    def datagrams():
        while not stopped.is_set():
            try:
                data, address = udp_socket.recvfrom(16384)
                received_datagrams.append(data)
                if data == b'slow':
                    continue
                udp_socket.sendto(b'x' * 9000 if data == b'large' else b'x' * 8192 if data == b'maximum' else data, address)
            except socket.timeout:
                pass
            except OSError:
                break

    threading.Thread(target=datagrams, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-net-clients-') as directory:
            root = Path(directory)
            (root / 'clients').mkdir()
            module = root / 'clients/redis.rut'
            module.write_bytes((Path(__file__).parent.parent / 'examples/clients/redis.rut').read_bytes())
            binary = root / 'clients/binary.rut'
            binary.write_bytes((Path(__file__).parent.parent / 'examples/clients/binary.rut').read_bytes())
            source = 'import "clients/redis.rut"\nimport "clients/binary.rut"\n'
            source += '''
func emit(_ socket: UdpSocket) -> bool {
    let sent = socket.send("helper", 1000)
    true
}
func closeUnused(_ connection: TcpConnection) -> bool {
    let closed = connection.close()
    true
}
func ignore(_ result: bool) -> bool { true }
func twice(_ result: bool) -> bool { result && result }
func first(_ left: bool, _ right: bool) -> bool {
    if right { left } else { left }
}
func firstCode(_ code: i32, _ ignored: bool) -> i32 { code }
func failClosedRead(_ connection: TcpConnection) -> bool {
    let pending = connection.receive(64, 1000)
    let failureCode = netError()
    failureCode == -4
}
'''
            for path, policy in (('tcp', 'TCP'), ('tls', 'TLS')):
                source += f'''
route GET "/{path}" {{
    let pending = tcp(env("{policy}"), 1000)
    guard let connection = pending else {{ return 503 }}
    let pendingSend = connection.send("hello\\r\\n", 1000)
    guard let sent = pendingSend else {{ return 503 }}
    let pendingLine = connection.readLine(64, 1000)
    guard let line = pendingLine else {{ return 503 }}
    let pendingTail = connection.readExactly(4, 1000)
    guard let tail = pendingTail else {{ return 503 }}
    guard tail == b"TAIL" && binary.readU16BE(line, 0).or(-1) == 26725 &&
        tail[tail.count - 1].or(-1) == 76 && tail[tail.count] == nil else {{ return 500 }}
    let closed = connection.close()
    guard closed else {{ return 500 }}
    return response(200, body: line)
}}
'''
            source += '''
route GET "/tls-alpn-probe" {
    let pending = tcp(env("TLS_PROBE"), 1000)
    guard let connection = pending else { return 503 }
    return 500
}
'''
            source += '''
route GET "/redis" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let pendingReply = redis.ping(connection)
    guard let reply = pendingReply else { return 503 }
    return response(200, body: reply)
}
route POST "/udp" {
    let pending = udp(env("UDP"), 1000)
    guard let socket = pending else { return 503 }
    let pendingSend = socket.send(req.bodyBytes, 1000)
    guard let sent = pendingSend else { return 503 }
    let pendingRead = socket.receive(8192, 1000)
    guard let reply = pendingRead else { return 503 }
    guard reply[-1] == nil && reply[reply.count] == nil else { return 500 }
    return response(200, body: reply)
}
route GET "/udp-helper" {
    let pending = udp(env("UDP"), 1000)
    guard let socket = pending else { return 503 }
    let result = emit(socket)
    return 204
}
route GET "/close-helper" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let alias = connection
    let result = closeUnused(connection)
    let pendingRead = alias.receive(64, 1000)
    let failure = netError()
    guard failure != -4 else { return 204 }
    return 500
}
route GET "/ignored-close-argument" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let alias = connection
    let result = ignore(connection.close())
    let pendingRead = alias.receive(64, 1000)
    let failure = netError()
    guard failure != -4 else { return 204 }
    return 500
}
route GET "/reused-close-argument" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let alias = connection
    let result = twice(connection.close())
    guard result else { return 500 }
    let pendingRead = alias.receive(64, 1000)
    let failure = netError()
    guard failure != -4 else { return 204 }
    return 500
}
route GET "/ordered-close-arguments" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let alias = connection
    let result = first(connection.close(), connection.close())
    guard result else { return 500 }
    let pendingRead = alias.receive(64, 1000)
    let failure = netError()
    guard failure != -4 else { return 204 }
    return 500
}
route GET "/capture-net-error-argument" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let alias = connection
    let closed = connection.close()
    guard closed else { return 500 }
    let captured = firstCode(netError() + 0, failClosedRead(alias))
    guard captured == 0 else { return 500 }
    let afterClose = netError()
    guard afterClose == -4 else { return 501 }
    return 204
}
route GET "/capture-net-error-local" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let alias = connection
    let saved = netError()
    let closed = connection.close()
    let pendingRead = alias.receive(64, 1000)
    let current = netError()
    guard saved == 0 else { return 500 }
    guard current == -4 else { return 501 }
    return 204
}
route GET "/mixed" {
    guard let message = json.parse("{\\"method\\":\\"GET\\"}") else { return 503 }
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let pendingSend = connection.send("hello\\r\\n", 1000)
    guard let sent = pendingSend else { return 503 }
    let pendingLine = connection.readLine(64, 1000)
    guard let line = pendingLine else { return 503 }
    let pendingHttp = httpCall(env("HTTP"), message, 1000)
    guard let httpReply = pendingHttp else { return 503 }
    guard json.bool(json.get(httpReply, "/ok").or(httpReply)).or(false) else { return 503 }
    let pendingTail = connection.readExactly(4, 1000)
    guard let tail = pendingTail else { return 503 }
    return response(200, body: tail)
}
route GET "/wrong-tls" {
    let pending = tcp(env("WRONG_TLS"), 1000)
    guard let connection = pending else { return 503 }
    return 500
}
route GET "/timeout" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let pendingSend = connection.send("slow\\r\\n", 1000)
    guard let sent = pendingSend else { return 503 }
    let pendingRead = connection.readExactly(4, 50)
    let failure = netError()
    guard failure != -2 else { return 504 }
    guard let reply = pendingRead else { return 503 }
    return 500
}
route GET "/eof" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let pendingSend = connection.send("eof\\r\\n", 1000)
    guard let sent = pendingSend else { return 503 }
    let pendingRead = connection.receive(64, 1000)
    guard let reply = pendingRead else { return 503 }
    guard reply.isEmpty else { return 500 }
    return 204
}
route GET "/truncated" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let pendingSend = connection.send("short\\r\\n", 1000)
    guard let sent = pendingSend else { return 503 }
    let pendingRead = connection.readExactly(2, 1000)
    guard let reply = pendingRead else { return 503 }
    return 500
}
route GET "/closed" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let alias = connection
    let closed = connection.close()
    guard closed else { return 500 }
    let pendingRead = alias.receive(64, 1000)
    let failure = netError()
    guard failure != -4 else { return 400 }
    return 500
}
route GET "/limit" {
    let pending = tcp(env("TCP"), 1000)
    guard let connection = pending else { return 503 }
    let pendingSend = connection.send("long\\r\\n", 1000)
    guard let sent = pendingSend else { return 503 }
    let pendingRead = connection.readLine(8, 1000)
    guard let reply = pendingRead else { return 503 }
    return 500
}
'''
            env = dict(os.environ, TCP=json.dumps(dict(address='127.0.0.1', port=plain.server_address[1])),
                       TLS=json.dumps(dict(address='127.0.0.1', port=secure.server_address[1], tls=True,
                                           caFile=str(cert), serverName='localhost')),
                       TLS_PROBE=json.dumps(dict(address='127.0.0.1', port=probe.server_address[1], tls=True,
                                                 caFile=str(cert), serverName='localhost')),
                       WRONG_TLS=json.dumps(dict(address='127.0.0.1', port=secure.server_address[1], tls=True,
                                                 caFile=str(cert), serverName='wrong.invalid')),
                       UDP=json.dumps(dict(address='127.0.0.1', port=udp_socket.getsockname()[1])),
                       HTTP=json.dumps(dict(address='127.0.0.1', port=secure.server_address[1],
                                            serverName='localhost', caFile=str(cert), path='/http')))
            program, log = root / 'gateway.rut', root / 'gateway.log'
            program.write_text(source)
            with log.open('wb') as output:
                process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                            '--shards', '2', '--no-pin', '--drain', '0'],
                                           env=env, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                port = None
                while time.monotonic() < deadline:
                    data = log.read_bytes()
                    match = re.search(rb'Listening on port ([0-9]+) with', data)
                    if match:
                        port = int(match[1])
                        break
                    if process.poll() is not None:
                        if args.backend == 'io_uring' and b'io_uring is unavailable' in data:
                            return 77
                        raise AssertionError(data.decode(errors='replace'))
                    time.sleep(.02)
                assert port, log.read_text(errors='replace')
                program.unlink()
                module.unlink()
                binary.unlink()

                def request(path, body=None):
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                    try:
                        conn.request('GET' if body is None else 'POST', path, body=body)
                        reply = conn.getresponse()
                        return reply.status, reply.read()
                    finally:
                        conn.close()

                for path in ('/tcp', '/tls'):
                    assert request(path) == (200, b'hello\r\n'), path
                assert any(data == b'hello\r\n' and protocol is None
                           for data, protocol in tls_alpn), tls_alpn
                assert request('/tls-alpn-probe')[0] == 503
                assert alpn_offers == [None], alpn_offers
                redis_result = request('/redis')
                assert redis_result == (200, b'+PONG\r\n'), (redis_result, requests, log.read_text(errors="replace"))
                for body in (b'\x00\xff\r\nhello', b'', b'x' * 8000):
                    result = request('/udp', body)
                    assert result == (200, body), (len(body), result[0], len(result[1]))
                assert request('/udp', b'maximum') == (200, b'x' * 8192)
                assert request('/udp', b'large')[0] == 503
                assert request('/udp-helper') == (204, b'')
                assert b'helper' in received_datagrams, received_datagrams
                assert request('/close-helper') == (204, b'')
                assert request('/ignored-close-argument') == (204, b'')
                assert request('/reused-close-argument') == (204, b'')
                assert request('/ordered-close-arguments') == (204, b'')
                captured_error = request('/capture-net-error-argument')
                assert captured_error == (204, b''), captured_error
                assert request('/capture-net-error-local') == (204, b'')
                assert request('/mixed') == (200, b'TAIL')
                assert request('/wrong-tls')[0] == 503
                assert request('/timeout')[0] == 504
                assert request('/limit')[0] == 503
                assert request('/eof')[0] == 204
                assert request('/truncated')[0] == 503
                assert request('/closed')[0] == 400
                def frame(kind, flags, stream, data=b''):
                    return len(data).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + data

                with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                    block = b'\x82\x86\x04\x06/redis\x01\x09localhost'
                    sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) + frame(1, 5, 1, block))
                    def exact(size):
                        data = b''
                        while len(data) < size:
                            part = sock.recv(size - len(data))
                            assert part, 'HTTP/2 closed during client operation'
                            data += part
                        return data
                    body = b''
                    while True:
                        header = exact(9)
                        payload = exact(int.from_bytes(header[:3], 'big'))
                        kind, flags = header[3:5]
                        stream = int.from_bytes(header[5:], 'big') & 0x7fffffff
                        if kind == 4 and not flags & 1:
                            sock.sendall(frame(4, 1, 0))
                        assert kind != 7, payload
                        if stream != 1:
                            continue
                        assert kind != 3, payload
                        if kind == 0:
                            body += payload
                        if kind in (0, 1) and flags & 1:
                            break
                    assert body == b'+PONG\r\n', body
                with ThreadPoolExecutor(max_workers=4) as pool:
                    results = list(pool.map(lambda _: request('/redis'), range(24)))
                assert all(result == (200, b'+PONG\r\n') for result in results), results
                for _ in range(24):
                    with socket.create_connection(('127.0.0.1', port), timeout=2) as sock:
                        sock.sendall(b'GET /timeout HTTP/1.1\r\nHost: test\r\n\r\n')
                        time.sleep(.005)
                time.sleep(.15)
                assert request('/redis') == (200, b'+PONG\r\n')
                deadline = time.monotonic() + 3
                while active and time.monotonic() < deadline:
                    time.sleep(.02)
                assert not active, len(active)
                assert requests.count(b'*1\r\n$4\r\nPING\r\n') == 27, requests
                print(f'PASS: {args.backend} TCP/TLS/UDP, fragmented reads, binary and empty datagrams, bounds, timeout, cancellation, auto-close, native library')
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise AssertionError('network worker shutdown timed out')
    finally:
        stopped.set()
        udp_socket.close()
        for server in (plain, secure):
            server.shutdown()
            server.server_close()
        probe.shutdown()
        probe.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
