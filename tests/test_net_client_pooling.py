#!/usr/bin/env python3
"""Independent TCP/TLS peers observe physical connection reuse and dirty eviction."""
import argparse
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
    parser.add_argument('--opt', required=True, choices=('0', '2'))
    args = parser.parse_args()
    lock = threading.Lock()
    peers = set()
    accepted = [0]
    commands = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            with lock:
                accepted[0] += 1
                identity = accepted[0]
                peers.add(self.request)
            self.request.settimeout(8)
            try:
                pending = b''
                while True:
                    while b'\n' not in pending:
                        chunk = self.request.recv(8192)
                        if not chunk:
                            return
                        pending += chunk
                    command, pending = pending.split(b'\n', 1)
                    with lock:
                        commands.append((identity, command))
                    if command == b'slow':
                        while self.request.recv(8192):
                            pass
                        return
                    self.request.sendall(str(identity).encode() + b'\n' +
                                         (b'JUNK' if command == b'extra' else b''))
                    if command == b'eof':
                        return
                    if command == b'dirty':
                        time.sleep(.04)
                        self.request.sendall(b'UNSOLICITED\n')
            except (OSError, ssl.SSLError):
                pass
            finally:
                with lock:
                    peers.discard(self.request)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    plain = Server(('127.0.0.1', 0), Handler)
    secure = Server(('127.0.0.1', 0), Handler)
    cert = Path(args.testdata) / 'localhost_cert.pem'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(Path(args.testdata) / 'localhost_key.pem'))
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    for server in (plain, secure):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-client-pool-') as directory:
            root = Path(directory)
            source = '''
func park(_ connection: TcpConnection) -> bool { connection.release() }
func ignored(_ value: bool) -> bool { true }
'''
            for name in ('plain', 'tls', 'tlsother', 'other', 'disabled', 'short'):
                source += f'''
route POST "/{name}" {{
    let opening = tcp(env("{name.upper()}"), 1000)
    guard let connection = opening else {{ return 503 }}
    let sending = connection.send(req.bodyBytes, 1000)
    guard let sent = sending else {{ return 502 }}
    let reading = connection.readLine(64, 1000)
    guard let data = reading else {{ return 504 }}
    let released = park(connection)
    let stale = connection.send(b"ILLEGAL\\n", 1000)
    guard stale == nil && netError() == -4 else {{ return 500 }}
    return response(200, body: data)
}}
'''
            for mode in ('close', 'abandon', 'ignored'):
                finish = ('let done = connection.close()' if mode == 'close' else
                          'let done = ignored(connection.release())' if mode == 'ignored' else '')
                source += f'''
route POST "/{mode}" {{
    let opening = tcp(env("PLAIN"), 1000)
    guard let connection = opening else {{ return 503 }}
    let sending = connection.send(req.bodyBytes, 1000)
    guard let sent = sending else {{ return 502 }}
    let reading = connection.readLine(64, 1000)
    guard let data = reading else {{ return 504 }}
    {finish}
    return response(200, body: data)
}}
'''
            source += '''
route POST "/cancel" {
    let opening = tcp(env("PLAIN"), 1000)
    guard let connection = opening else { return 503 }
    let sending = connection.send(b"slow\\n", 1000)
    guard let sent = sending else { return 502 }
    let reading = connection.readLine(64, 300)
    guard let data = reading else { return 504 }
    let released = connection.release()
    return 500
}
'''
            policy = dict(address='127.0.0.1', port=plain.server_address[1], poolIdleMs=5000)
            env = dict(os.environ, PLAIN=json.dumps(policy),
                       OTHER=json.dumps(dict(policy, poolIdleMs=4000)),
                       SHORT=json.dumps(dict(policy, poolIdleMs=20)),
                       DISABLED=json.dumps(dict(address='127.0.0.1', port=plain.server_address[1])),
                       TLSOTHER=json.dumps(dict(policy, port=secure.server_address[1], tls=True,
                                                caFile=str(cert), serverName='LOCALHOST')),
                       TLS=json.dumps(dict(policy, port=secure.server_address[1], tls=True,
                                           caFile=str(cert), serverName='localhost')))
            program, log = root / 'pool.rut', root / 'gateway.log'
            program.write_text(source)
            with log.open('wb') as out:
                process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                            '--shards', '1', '--no-pin', '--drain', '0', '--opt', args.opt],
                                           env=env, stdout=out, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                port = None
                while time.monotonic() < deadline:
                    data = log.read_bytes()
                    found = re.search(rb'Listening on port ([0-9]+) with', data)
                    if found:
                        port = int(found[1])
                        break
                    if process.poll() is not None:
                        if args.backend == 'io_uring' and b'io_uring is unavailable' in data:
                            return 77
                        raise AssertionError(data.decode(errors='replace'))
                    time.sleep(.02)
                assert port, log.read_text(errors='replace')
                program.unlink()  # executable/native load owns policy and helper code

                def request(path='plain', body=b'ok\n'):
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                    try:
                        conn.request('POST', '/' + path, body=body)
                        response = conn.getresponse()
                        return response.status, response.read()
                    finally:
                        conn.close()

                first = request()
                assert first[0] == 200, (first, log.read_text(errors='replace'))
                for _ in range(8):
                    assert request() == first, 'separate HTTP requests must reuse the TCP transport'
                def frame(kind, flags, stream, data=b''):
                    return (len(data).to_bytes(3, 'big') + bytes((kind, flags)) +
                            stream.to_bytes(4, 'big') + data)

                with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                    sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0))

                    def exact(size):
                        data = b''
                        while len(data) < size:
                            chunk = sock.recv(size - len(data))
                            assert chunk, 'HTTP/2 closed during pooled client operation'
                            data += chunk
                        return data

                    for stream_id in (1, 3):
                        # Indexed POST/http; literal :path, :authority and content-length.
                        block = b'\x83\x86\x04\x06/plain\x01\x09localhost\x0f\x0d\x013'
                        sock.sendall(frame(1, 4, stream_id, block) + frame(0, 1, stream_id, b'ok\n'))
                        body = b''
                        while True:
                            header = exact(9)
                            payload = exact(int.from_bytes(header[:3], 'big'))
                            kind, flags = header[3:5]
                            stream = int.from_bytes(header[5:], 'big') & 0x7fffffff
                            if kind == 4 and not flags & 1:
                                sock.sendall(frame(4, 1, 0))
                            assert kind != 7, payload
                            if stream != stream_id:
                                continue
                            assert kind != 3, payload
                            if kind == 0:
                                body += payload
                            if kind in (0, 1) and flags & 1:
                                break
                        assert body == first[1], 'HTTP/2 stream leases must share the clean transport'
                assert request() == first
                assert request('other') != first, 'pool policy identity must be isolated'
                assert request() == first
                disabled = request('disabled')
                assert disabled[0] == 200 and request('disabled') != disabled
                assert request('ignored') == first, 'ignored helper argument must execute release once'
                assert request() == first
                assert request('close') == first
                after_close = request()
                assert after_close[0] == 200 and after_close != first
                assert request('abandon') == after_close
                after_abandon = request()
                assert after_abandon[0] == 200 and after_abandon != after_close
                assert request(body=b'extra\n') == after_abandon
                after_extra = request()
                assert after_extra[0] == 200 and after_extra != after_abandon
                assert request(body=b'dirty\n') == after_extra
                time.sleep(.08)
                after_dirty = request()
                assert after_dirty[0] == 200 and after_dirty != after_extra
                assert request(body=b'eof\n') == after_dirty
                time.sleep(.02)
                after_eof = request()
                assert after_eof[0] == 200 and after_eof != after_dirty
                short = request('short')
                time.sleep(.05)
                assert short[0] == 200 and request('short') != short
                tls = request('tls')
                assert tls[0] == 200
                for _ in range(4):
                    assert request('tls') == tls, 'verified TLS session must survive explicit return'
                assert request('tlsother')[0] == 200
                assert request('tlsother') != tls, 'TLS server identity must have its own pool'
                assert request('tls') == tls
                assert request('tls', b'extra\n') == tls
                after_tls_extra = request('tls')
                assert after_tls_extra[0] == 200 and after_tls_extra != tls
                assert request('cancel')[0] == 504
                after_timeout = request()
                assert after_timeout[0] == 200 and after_timeout != after_eof
                conn = socket.create_connection(('127.0.0.1', port))
                conn.sendall(b'POST /cancel HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n')
                time.sleep(.08)
                conn.close()
                time.sleep(.35)
                assert request()[0] == 200
                with lock:
                    assert not any(command == b'ILLEGAL' for _, command in commands)
                print(f'PASS client pooling {args.backend} O{args.opt}: cross-request TCP/TLS reuse, '
                      'policy isolation, aliases, dirty/EOF/TTL eviction, cancel/timeout, no replay')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                with lock:
                    if not peers:
                        break
                time.sleep(.01)
            with lock:
                assert not peers, 'shutdown must close idle pooled TLS and TCP peers'
    finally:
        for server in (plain, secure):
            server.shutdown()
            server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
