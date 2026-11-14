#!/usr/bin/env python3
"""Ordered Redis multi-get and CAS-conditional Memcached retrieval."""
import argparse
from pathlib import Path
import ssl
import time

from test_redis_commands import Fixture, gateway as redis_gateway, packet, read_value, real_redis
from test_memcache_client import gateway as memcache_gateway, real_memcached
from test_client_read_control import connect, meta, VALUE

REDIS = r'''import "redis-mget.rut"
func keys(_ last: Bytes) {
    guard let first = redisKeysAdd(redisKeys(), b"key") else { nil }
    guard let second = redisKeysAdd(first, b"missing") else { nil }
    redisKeysAdd(second, last)
}
func status(_ result: RedisMgetResult) -> i32 {
    match result { .reply(reply) => 200
        .serverError(message) => 409
        .requestFailure => 400
        _ => 502 }
}
func selected(_ result: RedisMgetResult, _ index: i32) {
    match result { .reply(reply) => redisMgetItem(reply, index)
        _ => nil }
}
route POST "/get" {
    guard let batch = keys(req.bodyBytes) else { return 400 }
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisMget(connection, batch)
    let sending = connection.send(b"*2\r\n$3\r\nGET\r\n$6\r\nstable\r\n", 1000)
    let reading = connection.receive(8192, 1000)
    let closed = connection.close()
    guard (status(result) != 502 || !closed) && (status(result) == 502 || closed) else { return 500 }
    guard status(result) != 502 else { return 502 }
    guard status(result) != 409 else { return 409 }
    guard status(result) != 400 else { return 400 }
    guard let item = selected(result, parseInt(req.header("X-Index").or("0")).or(-1)) else { return 416 }
    guard item.found else { return 404 }
    let value = item.data
    return response(200, body: value)
}
route POST "/build" {
    guard let wire = redisMgetRequest(RedisKeys(arguments: req.bodyBytes,
        count: parseInt(req.header("X-Count").or("1")).or(-1))) else { return 400 }
    return response(200, body: wire)
}
route POST "/parse" {
    let reply = RedisMgetReply(frame: req.bodyBytes, count: parseInt(req.header("X-Count").or("1")).or(-1))
    guard let item = redisMgetItem(reply, parseInt(req.header("X-Index").or("0")).or(-1)) else { return 400 }
    guard item.found else { return 404 }
    let value = item.data
    return response(200, body: value)
}
'''

MEMCACHE = r'''import "memcache-meta.rut"
func status(_ result: MemcacheGetCasResult) -> i32 {
    match result { .value(item) => 200
        .unchanged(item) => 304
        .missing => 404
        .serverError(message) => 409
        .requestFailure => 400
        _ => 502 }
}
func data(_ result: MemcacheGetCasResult) -> Bytes {
    match result { .value(item) => item.data
        _ => b"" }
}
func cas(_ result: MemcacheGetCasResult) -> Bytes {
    match result { .value(item) => item.cas
        .unchanged(item) => item.cas
        _ => b"" }
}
route POST "/get" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheGetCas(connection, req.bodyBytes, Bytes(req.header("X-Cas").or("1")))
    let sending = connection.send(b"get stable\r\n", 1000)
    let reading = connection.receive(8192, 1000)
    let closed = connection.close()
    guard status(result) != 502 && status(result) != 409 || !closed else { return 500 }
    guard status(result) == 502 || status(result) == 409 || closed else { return 500 }
    guard status(result) != 502 else { return 502 }
    guard status(result) != 409 else { return 409 }
    guard status(result) != 400 else { return 400 }
    guard status(result) != 404 else { return 404 }
    guard status(result) != 304 else { return 304 }
    let value = data(result)
    return response(200, body: value)
}
// A body-bearing route exposes unchanged metadata, separate from HTTP 304.
route POST "/metadata" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheGetCas(connection, req.bodyBytes, Bytes(req.header("X-Cas").or("1")))
    let closed = connection.close()
    guard closed && (status(result) == 200 || status(result) == 304) else { return 502 }
    let value = cas(result)
    return response(200, body: value)
}
route POST "/build" {
    guard let wire = memcacheGetCasRequest(req.bodyBytes, Bytes(req.header("X-Cas").or("1"))) else { return 400 }
    return response(200, body: wire)
}
'''


def bulk(value):
    return b'$' + str(len(value)).encode() + b'\r\n' + value + b'\r\n'


def array(values):
    return b'*' + str(len(values)).encode() + b'\r\n' + b''.join(b'$-1\r\n' if value is None else bulk(value) for value in values)


class CacheReadPeer(Fixture):
    def __init__(self, protocol, context):
        self.protocol = protocol
        self.case = 'normal'
        super().__init__(context)

    def serve(self, connection):
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                while not self.stop.is_set():
                    command = read_value(stream) if self.protocol == 'redis' else stream.readline()
                    if not command:
                        return
                    self.observed.append(command)
                    if command == [b'GET', b'stable'] or command == b'get stable\r\n':
                        connection.sendall(bulk(VALUE) if self.protocol == 'redis' else b'END\r\n')
                        continue
                    if self.protocol == 'redis':
                        assert command == [b'MGET', b'key', b'missing', b'empty'], command
                        good = array([VALUE, None, b''])
                        replies = dict(normal=good, fragments=good, error=b'-ERR unavailable\r\n',
                                       wrong=b'+OK\r\n', extra=good + b'+OK\r\n', truncated=good[:-1],
                                       mismatch=array([VALUE]), nested=b'*3\r\n*0\r\n$-1\r\n$0\r\n\r\n',
                                       badItem=b'*3\r\n:1\r\n$-1\r\n$0\r\n\r\n',
                                       max=array([b'x' * 8168, None, b'']), large=array([b'x' * 8169, None, b'']))
                    else:
                        assert command.startswith(b'mg key v f c t C') and command.endswith(b'\r\n'), command
                        expected_cas = str(int(command.split(b' C')[1].strip())).encode()
                        good = meta(fields=b'f4294967295 c2 t-1')
                        replies = dict(normal=good, fragments=good, error=b'SERVER_ERROR unavailable\r\n',
                                       wrong=b'HD\r\n', extra=good + b'EN\r\n', truncated=good[:-1],
                                       mismatch=b'HD f0 c2 t-1\r\n', nested=meta(fields=b'f0 c1 t0'),
                                       badItem=b'HD f0 c1 t0 X\r\n', unchanged=b'HD f4294967295 c' + expected_cas + b' t-1\r\n',
                                       empty=meta(b'', b'f0 c2 t0'), missing=b'EN\r\n',
                                       max=meta(b'x' * 8172, b'f0 c2 t0'), large=meta(b'x' * 8173, b'f0 c2 t0'))
                    if self.case == 'eof':
                        return
                    if self.case == 'timeout':
                        time.sleep(1.2)
                        continue
                    reply = replies[self.case]
                    if self.case == 'fragments':
                        for part in (reply[:2], reply[2:-1], reply[-1:]):
                            connection.sendall(part)
                            time.sleep(.04)
                    else:
                        connection.sendall(reply)
                    if self.case == 'truncated':
                        return
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)


def pure_checks(request, protocol):
    if protocol == 'redis':
        for keys in ([b''], [VALUE, b'', VALUE], [str(i).encode() for i in range(8)]):
            arguments = b''.join(bulk(key) for key in keys)
            assert request('build', arguments, {'X-Count': str(len(keys))}) == (200, packet([b'MGET', *keys]))
        maximum = max(n for n in range(8193) if len(packet([b'MGET', b'x' * n])) <= 8192)
        assert request('build', bulk(b'x' * maximum)) == (200, packet([b'MGET', b'x' * maximum]))
        assert request('build', bulk(b'x' * (maximum + 1)))[0] == 400
        for count, arguments in ((0, b''), (9, bulk(b'x') * 9), (2, bulk(b'x')),
                                 (1, b'$-1\r\n'), (1, b'$+1\r\nx\r\n'), (1, b'*0\r\n'), (1, bulk(b'x') + b'+OK\r\n')):
            assert request('build', arguments, {'X-Count': str(count)})[0] == 400
        for frame in (array([VALUE]) + b'+OK\r\n', b'*1\r\n*0\r\n', array([]), array([None, None]), b'*1\r\n-ERR nested\r\n'):
            assert request('parse', frame)[0] == 400
        assert request('parse', array([None]))[0] == 404
        assert request('parse', array([b''])) == (200, b'')
        assert request('parse', array([VALUE] * 8), {'X-Count': '8', 'X-Index': '7'}) == (200, VALUE)
        assert request('parse', array([None] * 8), {'X-Count': '8', 'X-Index': '7'})[0] == 404
        assert request('parse', array([VALUE] * 9), {'X-Count': '9'})[0] == 400
        frame = array([VALUE, None, b''])
        for index in (-1, 3):
            assert request('parse', frame, {'X-Count': '3', 'X-Index': str(index)})[0] == 400
        # Revalidate a bad later element even when the caller asks for index 0.
        assert request('parse', b'*2\r\n$1\r\nx\r\n:2\r\n', {'X-Count': '2'})[0] == 400
    else:
        for token in ('0', '0001', '18446744073709551615'):
            assert request('build', b'key', {'X-Cas': token}) == (200, b'mg key v f c t C' + token.encode() + b'\r\n')
        for token in ('', '-1', '+1', '1x', '18446744073709551616'):
            assert request('build', b'key', {'X-Cas': token})[0] == 400
        assert request('build', b'bad key')[0] == 400


def live_checks(args, server, request):
    if args.protocol == 'redis':
        _, command = server
        command(b'SET', b'key', VALUE)
        assert request('get', b'key') == (200, VALUE)
        assert request('get', b'key', {'X-Index': '1'})[0] == 404
        assert request('get', b'key', {'X-Index': '2'}) == (200, VALUE)
        command(b'SET', b'', b'')
        assert request('get', b'', {'X-Index': '2'}) == (200, b'')
        command(b'LPUSH', b'list', b'x')
        assert request('get', b'list', {'X-Index': '2'})[0] == 404
        assert request('get', b'key', {'X-Index': '3'})[0] == 416
    else:
        with connect(args, server) as connection, connection.makefile('rb') as stream:
            def store(value):
                connection.sendall(b'set key 4294967295 60 ' + str(len(value)).encode() + b'\r\n' + value + b'\r\n')
                assert stream.readline() == b'STORED\r\n'
                connection.sendall(b'gets key\r\n')
                header = stream.readline().split()
                assert stream.read(len(value) + 2) == value + b'\r\n'
                assert stream.readline() == b'END\r\n'
                return header[4].decode()

            token = store(VALUE)
            assert request('get', b'key', {'X-Cas': token})[0] == 304
            assert request('get', b'key', {'X-Cas': '000' + token})[0] == 304
            assert request('metadata', b'key', {'X-Cas': token}) == (200, token.encode())
            replacement = store(b'new\x00\xff')
            assert replacement != token
            assert request('get', b'key', {'X-Cas': token}) == (200, b'new\x00\xff')
            assert request('metadata', b'key', {'X-Cas': token}) == (200, replacement.encode())
            store(b'')
            assert request('get', b'key', {'X-Cas': token}) == (200, b'')
            assert request('get', b'missing', {'X-Cas': token})[0] == 404


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--protocol', choices=('redis', 'memcache'), required=True)
    parser.add_argument('--real', action='store_true')
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--testdata')
    args = parser.parse_args()
    args.real_redis = args.real
    args.real_memcached = args.real
    args.example = None
    if args.tls and not args.testdata:
        parser.error('--tls requires --testdata')

    def gateway(port):
        endpoint = dict(address='127.0.0.1', port=port)
        if args.tls:
            endpoint.update(tls=True, caFile=str(Path(args.testdata).resolve() / 'localhost_cert.pem'), serverName='localhost')
        if args.protocol == 'redis':
            return redis_gateway(args, endpoint, program_factory=lambda _: REDIS,
                                 extra_libraries=('redis-mget.rut',), entrypoint='redis-mget.rut')
        return memcache_gateway(args, endpoint, program_factory=lambda: MEMCACHE,
                                extra_libraries=('memcache-meta.rut',), entrypoint='memcache-meta.rut')

    if args.real:
        manager = real_redis(args) if args.protocol == 'redis' else real_memcached(args)
        with manager as server:
            port = server[0] if args.protocol == 'redis' else server
            with gateway(port) as request:
                pure_checks(request, args.protocol)
                live_checks(args, server, request)
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'), str(Path(args.testdata) / 'localhost_key.pem'))
        peer = CacheReadPeer(args.protocol, context)
        try:
            with gateway(peer.port) as request:
                pure_checks(request, args.protocol)
                cases = ['normal', 'fragments', 'error', 'wrong', 'extra', 'truncated', 'mismatch', 'nested', 'badItem', 'eof', 'timeout', 'max', 'large']
                if args.protocol == 'memcache':
                    cases += ['unchanged', 'empty', 'missing']
                for case in cases:
                    peer.case = case
                    before = len(peer.observed)
                    code, value = request('get', b'empty' if args.protocol == 'redis' else b'key')
                    expected = 200 if case in ('normal', 'fragments', 'max', 'empty') else (304 if case == 'unchanged' else (404 if case == 'missing' else (409 if case == 'error' else 502)))
                    assert code == expected, (case, code, value[:80])
                    if case in ('normal', 'fragments'):
                        assert value == VALUE
                    followup = expected in (200, 304, 404) or (expected == 409 and args.protocol == 'redis')
                    assert len(peer.observed) == before + 1 + followup, (case, peer.observed[before:])
                if args.protocol == 'memcache':
                    peer.case = 'unchanged'
                    for token in ('0', '0001', '9999999999', '10000000000', '18446744073709551614', '18446744073709551615'):
                        assert request('get', b'key', {'X-Cas': token})[0] == 304
                        assert request('metadata', b'key', {'X-Cas': token}) == (200, str(int(token)).encode())
                    before = len(peer.observed)
                    assert request('get', b'key', {'X-Cas': '-1'})[0] == 400
                    assert len(peer.observed) == before + 1
                assert not peer.errors, peer.errors
        finally:
            peer.close()
    print(f'Client cache reads passed ({args.protocol}, {args.backend}, O{args.opt}, tls={args.tls}, real={args.real})')


if __name__ == '__main__':
    main()
