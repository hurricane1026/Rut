#!/usr/bin/env python3
"""Independent batch-gated RESP2 peer and pinned real Redis pipeline checks."""
import argparse
import contextlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from test_redis_commands import packet, read_value, real_redis


PROGRAM = r'''
struct RootPadding { marker: i32 }
variant RootPaddingKind { absent }
func pipelineReply(_ result: RedisPipelineResult) -> RedisPipelineReply {
    match result { .reply(value) => value _ => nil }
}
func pipelineStatus(_ result: RedisPipelineResult) -> i32 {
    match result {
        .reply(value) => 200
        .requestFailure => 413
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        .replyFailure => 502
    }
}
func pipelineOutput(_ reply: RedisPipelineReply, _ index: i32) -> Bytes {
    if index == -1 { reply.frame } else { redisPipelineReply(reply, index) }
}
route POST "/execute" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let batch = RedisPipeline(request: req.bodyBytes, count: parseInt(req.header("X-Count").or("2")).or(-1))
    let result = redisPipelineExecute(connection, batch)
    let closed = connection.close()
    let status = pipelineStatus(result)
    guard status != 413 else { return 413 }
    guard status != 504 else { return 504 }
    guard let reply = pipelineReply(result) else { return 502 }
    guard let data = pipelineOutput(reply, parseInt(req.header("X-Index").or("-1")).or(-2)) else { return 422 }
    return response(200, body: data)
}
route POST "/poison" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let alias = connection
    let batch = RedisPipeline(request: req.bodyBytes, count: 2)
    let result = redisPipelineExecute(connection, batch)
    guard pipelineStatus(result) == 502 || pipelineStatus(result) == 504 else { return 500 }
    let sending = alias.send(b"must-not-arrive", 1000)
    guard sending == nil && netError() == -4 else { return 500 }
    return 204
}
route POST "/recover" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let batch = RedisPipeline(request: req.bodyBytes, count: 2)
    let result = redisPipelineExecute(connection, batch)
    guard pipelineStatus(result) == parseInt(req.header("X-Status").or("200")).or(0) else { return 500 }
    let sending = connection.send(b"*1\r\n$4\r\nPING\r\n", 1000)
    guard let sent = sending else { return 500 }
    let reading = connection.receive(64, 1000)
    guard let pong = reading else { return 500 }
    let closed = connection.close()
    guard pong == b"+PONG\r\n" else { return 500 }
    return 204
}
route POST "/slice" {
    let reply = RedisPipelineReply(frame: req.bodyBytes, count: parseInt(req.header("X-Count").or("2")).or(-1))
    guard let data = redisPipelineReply(reply, parseInt(req.header("X-Index").or("0")).or(-2)) else { return 422 }
    return response(200, body: data)
}
route POST "/values" {
    let reply = RedisPipelineReply(frame: req.bodyBytes, count: parseInt(req.header("X-Count").or("2")).or(-1))
    guard let values = redisPipelineValues(reply) else { return 422 }
    guard let node = values.get(parseInt(req.header("X-Token").or("0")).or(-1)) else { return 404 }
    guard node.reply == parseInt(req.header("X-Reply").or("0")).or(-1) else { return 500 }
    let data = node.value.data
    return response(200, body: data)
}
route POST "/build" {
    guard let cut = parseInt(req.header("X-Cut").or("0")) else { return 400 }
    guard let first = req.bodyBytes.slice(0, cut) else { return 400 }
    guard let second = req.bodyBytes.slice(cut, req.bodyBytes.count) else { return 400 }
    let initial = redisPipeline()
    guard let one = redisPipelineAdd(initial, first) else { return 413 }
    guard let two = redisPipelineAdd(one, second) else { return 413 }
    guard initial.count == 0 && initial.request == b"" && one.count == 1 && two.count == 2 else { return 500 }
    let data = two.request
    return response(200, body: data)
}
route POST "/append" {
    let initial = RedisPipeline(request: req.bodyBytes, count: parseInt(req.header("X-Count").or("0")).or(-1))
    guard let added = redisPipelineAdd(initial, b"*1\r\n$4\r\nPING\r\n") else { return 413 }
    let data = added.request
    return response(200, body: data)
}
route POST "/build-repeat" {
    let initial = redisPipeline()
    guard let one = redisPipelineAdd(initial, req.bodyBytes) else { return 413 }
    guard let two = redisPipelineAdd(one, req.bodyBytes) else { return 413 }
    let data = two.request
    return response(200, body: data)
}
'''

AUTH_PROGRAM = r'''
route POST "/authenticated" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let initialized = redisInitialize(connection, b"alice", b"secret", 2)
    guard redisInitializeSucceeded(initialized) else { return 502 }
    let batch = RedisPipeline(request: req.bodyBytes, count: 2)
    let result = redisPipelineExecute(connection, batch)
    let reset = redisReset(connection)
    let returned = connection.release()
    guard redisCommandSucceeded(reset) && netError() == 0 else { return 502 }
    guard let reply = pipelineReply(result) else { return 502 }
    let data = reply.frame
    return response(200, body: data)
}
'''


def source_text(args, root):
    text = PROGRAM + (AUTH_PROGRAM if args.real_redis else '')
    auth = ['redisInitialize', 'redisInitializeSucceeded', 'redisReset', 'redisCommandSucceeded',
            'RedisInitializeResult', 'RedisCommandResult']
    if args.opt == '2':
        imports = 'import * as batch from "redis-pipeline.rut"\nimport * as request from "resp2-command.rut"\n'
        for namespace, names in (
            ('batch', ('redis-pipeline.rut', 'resp2.rut')),
            ('request', ('resp2-command.rut',)),
        ):
            symbols = set()
            for name in names:
                symbols.update(re.findall(r'^(?:func|struct|variant) (\w+)', (root / name).read_text(), re.M))
            text = re.sub(r'\b(' + '|'.join(sorted(symbols)) + r')\b', namespace + r'.\1', text)
        auth += ['Resp2Command', 'Resp2State', 'Resp2Token', 'Resp2Cursor', 'Resp2Stream']
    else:
        imports = 'import "redis-pipeline.rut"\nimport "resp2-command.rut"\n'
    if args.real_redis:
        imports += 'import { ' + ', '.join(auth) + ' } from "redis-client.rut"\n'
    return imports + text


@contextlib.contextmanager
def gateway(args, endpoint):
    with tempfile.TemporaryDirectory(prefix='rut-redis-pipeline-') as directory:
        root = Path(directory)
        for name in ('resp2.rut', 'resp2-command.rut', 'redis-client.rut', 'redis-pipeline.rut'):
            shutil.copyfile(Path(args.library) / name, root / name)
        source, log = root / 'gateway.rut', root / 'server.log'
        source.write_text(source_text(args, root))
        with log.open('wb') as output:
            process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                                        '--opt', args.opt, '--no-pin', '--shards', '1', '--drain', '0'],
                                       env=dict(os.environ, REDIS_ENDPOINT=json.dumps(endpoint)),
                                       stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                data = log.read_bytes()
                found = re.search(rb'Listening on port ([0-9]+) with', data)
                if found:
                    port = int(found[1])
                    break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and b'io_uring is unavailable' in data:
                        raise SystemExit(77)
                    raise AssertionError(data.decode(errors='replace'))
                time.sleep(.025)
            else:
                raise AssertionError(log.read_text(errors='replace'))
            for path in root.glob('*.rut'):
                path.unlink()
            def request(path, body=b'', headers=None):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                try:
                    connection.request('POST', '/' + path, body, headers or {})
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()
            yield request
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


class Fixture:
    def __init__(self, context):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.context = context
        self.stop = threading.Event()
        self.sockets, self.workers, self.observed, self.errors = [], [], [], []
        self.acceptor = threading.Thread(target=self.accept, daemon=True)
        self.acceptor.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.sockets.append(connection)
            worker = threading.Thread(target=self.serve, args=(connection,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, connection):
        try:
            if self.context:
                connection = self.context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                while not self.stop.is_set():
                    first = read_value(stream)
                    self.observed.append(first)
                    if first == [b'PING']:
                        connection.sendall(b'+PONG\r\n')
                        continue
                    assert first[0] == b'FIXTURE', first
                    case = first[1]
                    count = 8 if case == b'eight' else 2
                    # Deliberately withhold every reply until all requests have
                    # arrived. A sequential implementation hits its deadline.
                    for _ in range(count - 1):
                        self.observed.append(read_value(stream))
                    if case == b'timeout':
                        self.stop.wait(1.3)
                        continue
                    if case == b'eof':
                        connection.sendall(b'+OK\r\n')
                        return
                    first_reply = b'*3\r\n$4\r\na\x00\xffb\r\n*2\r\n:9223372036854775807\r\n-ERR nested\r\n$-1\r\n'
                    frames = first_reply + b':-9223372036854775808\r\n'
                    if case == b'error':
                        frames = b'-WRONGTYPE first\r\n+OK\r\n'
                    if case == b'eight':
                        frames = b'+OK\r\n$-1\r\n*0\r\n*-1\r\n:0\r\n-ERR sixth\r\n$0\r\n\r\n:8\r\n'
                    if case in (b'nodes', b'too-many-nodes'):
                        size = 62 if case == b'nodes' else 63
                        frames = b'*%d\r\n' % size + b':1\r\n' * size + b'+OK\r\n'
                    if case in (b'bytes', b'too-many-bytes'):
                        size = 8178 if case == b'bytes' else 8179
                        frames = b'+OK\r\n$%d\r\n' % size + b'x' * size + b'\r\n'
                    if case == b'invalid':
                        frames = b'+OK\r\n:9223372036854775808\r\n'
                    if case == b'extra':
                        frames += b'+EXTRA\r\n'
                    if case == b'fragmented':
                        cuts = [1, 4, len(frames) // 2]
                        for a, b in zip([0] + cuts, cuts + [len(frames)]):
                            connection.sendall(frames[a:b])
                            time.sleep(.04)
                    elif case == b'read-budget':
                        for part in (b'+', b'O', b'K', b'\r', b'\n+OK\r\n'):
                            connection.sendall(part)
                            time.sleep(.1)
                    else:
                        connection.sendall(frames)
        except (EOFError, OSError, ConnectionError):
            pass
        except Exception as error:
            self.errors.append(error)

    def close(self):
        self.stop.set()
        self.listener.close()
        for connection in self.sockets:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
        self.acceptor.join(2)
        for worker in self.workers:
            worker.join(2)
        assert not self.errors, self.errors


def oracle_checks(request, peer):
    def batch(case, count=2):
        return packet([b'FIXTURE', case]) + packet([b'PING']) * (count - 1)
    first = b'*3\r\n$4\r\na\x00\xffb\r\n*2\r\n:9223372036854775807\r\n-ERR nested\r\n$-1\r\n'
    second = b':-9223372036854775808\r\n'
    for case in (b'normal', b'fragmented'):
        assert request('execute', batch(case)) == (200, first + second)
    for index, expected in enumerate((first, second)):
        assert request('execute', batch(b'normal'), {'X-Index': str(index)}) == (200, expected)
        assert request('slice', first + second, {'X-Index': str(index)}) == (200, expected)
    for token, reply, value in ((1, 0, b'a\x00\xffb'), (4, 0, b'ERR nested'),
                                (6, 1, b'-9223372036854775808')):
        assert request('values', first + second, {'X-Token': str(token), 'X-Reply': str(reply)}) == (200, value)
    eight = b'+OK\r\n$-1\r\n*0\r\n*-1\r\n:0\r\n-ERR sixth\r\n$0\r\n\r\n:8\r\n'
    assert request('execute', batch(b'eight', 8), {'X-Count': '8'}) == (200, eight)
    assert request('slice', eight, {'X-Count': '8', 'X-Index': '5'}) == (200, b'-ERR sixth\r\n')
    assert request('execute', batch(b'nodes')) == (200, b'*62\r\n' + b':1\r\n' * 62 + b'+OK\r\n')
    maximum = b'+OK\r\n$8178\r\n' + b'x' * 8178 + b'\r\n'
    assert len(maximum) == 8192
    assert request('execute', batch(b'bytes')) == (200, maximum)
    assert request('recover', batch(b'error'))[0] == 204
    assert request('execute', batch(b'error')) == (200, b'-WRONGTYPE first\r\n+OK\r\n')
    before = len(peer.observed)
    malformed = [(b'', '0'), (packet([b'PING']), '2'), (batch(b'normal'), '1'),
                 (batch(b'normal'), '9'), (batch(b'normal') + b'junk', '2'),
                 (packet([b'FIXTURE', b'normal']) + b'*1\r\n:1\r\n', '2'),
                 (packet([b'FIXTURE', b'normal']) + b'*0\r\n', '2')]
    for data, count in malformed:
        result = request('execute', data, {'X-Count': count})
        assert result[0] == 413, (data, count, result)
    assert len(peer.observed) == before, 'invalid batch was written'
    assert request('recover', b'*0\r\n', {'X-Status': '413'})[0] == 204
    for case in (b'timeout', b'eof', b'invalid', b'extra', b'read-budget', b'too-many-nodes', b'too-many-bytes'):
        result = request('poison', batch(case))
        assert result[0] == 204, (case, result)
        assert peer.observed.count([b'FIXTURE', case]) == 1, 'batch was replayed'
    # Exactly 64 aggregate request nodes, then one node over that limit.
    wire = packet([b'FIXTURE', b'normal']) + packet([b'PING'] + [b'x'] * 59)
    assert request('execute', wire) == (200, first + second)
    before = len(peer.observed)
    wire = packet([b'FIXTURE', b'normal']) + packet([b'PING'] + [b'x'] * 60)
    assert request('execute', wire)[0] == 413
    assert len(peer.observed) == before


def pure_checks(request):
    first, second = packet([b'SET', b'key\x00\xff', b'value\r\n']), packet([b'GET', b'key\x00\xff'])
    assert request('build', first + second, {'X-Cut': str(len(first))}) == (200, first + second)
    for first, second in ((b'*0\r\n', second), (first, b'*1\r\n$-1\r\n'), (first + second, second)):
        assert request('build', first + second, {'X-Cut': str(len(first))})[0] == 413
    for count in ('-1', '8', '9'):
        assert request('append', b'', {'X-Count': count})[0] == 413
    assert request('append', b'x', {'X-Count': '0'})[0] == 413
    assert request('append', b'') == (200, packet([b'PING']))
    assert request('append', packet([b'PING']) * 7, {'X-Count': '7'}) == (200, packet([b'PING']) * 8)
    maximum = max(n for n in range(4200) if len(packet([b'ECHO', b'x' * n])) * 2 <= 8192)
    encoded = packet([b'ECHO', b'x' * maximum])
    assert request('build-repeat', encoded) == (200, encoded * 2)
    assert request('build-repeat', packet([b'ECHO', b'x' * (maximum + 1)]))[0] == 413
    for frame in (b'+OK\r\n', b'+OK\r\n:bad\r\n', b'+OK\r\n+OK\r\n+EXTRA\r\n',
                  b'+OK\r\n*1\r\n', b'+OK\r\n$-2\r\n'):
        assert request('slice', frame)[0] == 422, frame
        assert request('values', frame)[0] == 422, frame
    for index in ('-1', '2', '2147483647'):
        assert request('slice', b'+OK\r\n+OK\r\n', {'X-Index': index})[0] == 422


def live_checks(request, command):
    key, value = b'pipeline\x00\xff', b'a\x00\xff\r\n'
    wire = packet([b'SET', key, value]) + packet([b'GET', key])
    expected = b'+OK\r\n$5\r\n' + value + b'\r\n'
    assert request('execute', wire) == (200, expected)
    assert command(b'GET', key) == value
    assert request('execute', wire, {'X-Index': '1'}) == (200, b'$5\r\n' + value + b'\r\n')
    assert command(b'SET', b'counter', b'9223372036854775807') == b'OK'
    wire = packet([b'INCR', b'counter']) + packet([b'SET', b'after-error', b'applied'])
    result = request('execute', wire)
    assert result[0] == 200 and result[1].startswith(b'-ERR ') and result[1].endswith(b'+OK\r\n'), result
    assert command(b'GET', b'after-error') == b'applied'
    assert command(b'GET', b'counter') == b'9223372036854775807'
    wire = packet([b'MGET', key, b'absent']) + packet([b'PTTL', b'absent'])
    assert request('execute', wire) == (200, b'*2\r\n$5\r\n' + value + b'\r\n$-1\r\n:-2\r\n')
    assert request('execute', packet([b'PING']) * 8, {'X-Count': '8'}) == (200, b'+PONG\r\n' * 8)
    assert request('execute', packet([b'ECHO', value]), {'X-Count': '1'}) == (200, b'$5\r\n' + value + b'\r\n')
    assert command(b'ACL', b'SETUSER', b'alice', b'on', b'>secret', b'~*', b'+@all') == b'OK'
    wire = packet([b'SET', b'auth-pipeline', value]) + packet([b'GET', b'auth-pipeline'])
    assert request('authenticated', wire) == (200, expected)
    assert command(b'SELECT', b'2') == b'OK'
    assert command(b'GET', b'auth-pipeline') == value
    assert command(b'SELECT', b'0') == b'OK'
    rows = [dict(field.split(b'=', 1) for field in line.split()) for line in command(b'CLIENT', b'LIST').splitlines()]
    oracle = str(command(b'CLIENT', b'ID')).encode()
    returned = [row for row in rows if row[b'id'] != oracle]
    assert len(returned) == 1 and returned[0][b'user'] == b'default' and returned[0][b'db'] == b'0', returned
    identity = returned[0][b'id']
    wire = packet([b'CLIENT', b'ID']) + packet([b'ACL', b'WHOAMI'])
    assert request('execute', wire) == (200, b':' + identity + b'\r\n$7\r\ndefault\r\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--testdata')
    parser.add_argument('--real-redis', action='store_true')
    args = parser.parse_args()
    if args.tls and not args.testdata:
        parser.error('--tls requires --testdata')
    def policy(port):
        endpoint = dict(address='127.0.0.1', port=port, poolIdleMs=5000)
        if args.tls:
            endpoint.update(tls=True, caFile=str(Path(args.testdata).resolve() / 'localhost_cert.pem'), serverName='localhost')
        return endpoint
    if args.real_redis:
        with real_redis(args) as (port, command):
            with gateway(args, policy(port)) as request:
                pure_checks(request)
                live_checks(request, command)
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'), str(Path(args.testdata) / 'localhost_key.pem'))
        peer = Fixture(context)
        try:
            with gateway(args, policy(peer.port)) as request:
                pure_checks(request)
                oracle_checks(request, peer)
        finally:
            peer.close()
    print(f'PASS Redis pipeline {args.backend} O{args.opt} TLS={args.tls} live={args.real_redis}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
