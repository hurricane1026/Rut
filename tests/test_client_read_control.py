#!/usr/bin/env python3
"""Atomic Redis read mutations and bounded Memcached metadata retrieval."""
import argparse
import itertools
from pathlib import Path
import socket
import ssl
import time

from test_redis_commands import Fixture, gateway as redis_gateway, packet, read_value, real_redis
from test_memcache_client import gateway as memcache_gateway, real_memcached

REDIS = r'''import "redis-client.rut"
func expiry(_ unit: str, _ amount: Bytes) -> RedisGetExpiry {
    match unit {
        "EX" => RedisGetExpiry.seconds(parseInt(amount).or(-1))
        "PX" => RedisGetExpiry.milliseconds(parseInt(amount).or(-1))
        "EXAT" => RedisGetExpiry.unixSeconds(amount)
        "PXAT" => RedisGetExpiry.unixMilliseconds(amount)
        "PERSIST" => RedisGetExpiry.persist
        _ => RedisGetExpiry.unchanged
    }
}
func status(_ result: RedisGetResult) -> i32 {
    match result { .value(value) => 200
        .missing => 404
        .serverError(message) => 409
        .requestFailure => 400
        _ => 502 }
}
func data(_ result: RedisGetResult) -> Bytes {
    match result { .value(value) => value
        .serverError(message) => message
        _ => b"" }
}
route POST "/build" {
    guard let wire = resp2GetExRequest(req.bodyBytes,
        expiry(req.header("X-Unit").or(""), Bytes(req.header("X-Time").or("0")))) else { return 400 }
    return response(200, body: wire)
}
'''
ROUTE = r'''route POST "/OP" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = CALL
    let readback = redisGet(connection, b"stable")
    let closed = connection.close()
    guard status(result) != 502 || !closed else { return 500 }
    guard status(result) == 502 || closed else { return 500 }
    let payload = data(result)
    guard status(result) != 502 else { return 502 }
    guard status(result) != 400 else { return 400 }
    guard status(result) != 404 else { return 404 }
    guard status(result) != 409 else { return 409 }
    return response(200, body: payload)
}
'''
REDIS += ROUTE.replace('OP', 'getex').replace('CALL', 'redisGetEx(connection, req.bodyBytes, expiry(req.header("X-Unit").or(""), Bytes(req.header("X-Time").or("0"))))')
REDIS += ROUTE.replace('OP', 'getdel').replace('CALL', 'redisGetDel(connection, req.bodyBytes)')

MEMCACHE = r'''import "memcache-meta.rut"
func status(_ result: MemcacheMetaResult) -> i32 {
    match result { .value(item) => 200
        .missing => 404
        .serverError(message) => 409
        .requestFailure => 400
        _ => 502 }
}
func packed(_ item: MemcacheMetaItem) {
    guard let ttl = formatInt(item.ttlSeconds) else { nil }
    guard let first = concatBytes(item.flags, b":", 8192) else { nil }
    guard let second = concatBytes(first, item.cas, 8192) else { nil }
    guard let third = concatBytes(second, b":", 8192) else { nil }
    guard let fourth = concatBytes(third, Bytes(ttl), 8192) else { nil }
    guard let prefix = concatBytes(fourth, b":", 8192) else { nil }
    concatBytes(prefix, item.data, 8192)
}
func data(_ result: MemcacheMetaResult) -> Bytes {
    match result { .value(item) => packed(item).or(b"PACK_FAILURE")
        .serverError(message) => message
        _ => b"" }
}
route POST "/get" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheMetaGet(connection, req.bodyBytes)
    let sending = connection.send(b"get stable\r\n", 1000)
    let reading = connection.receive(8192, 1000)
    let closed = connection.close()
    guard status(result) != 502 && status(result) != 409 || !closed else { return 500 }
    guard status(result) == 502 || status(result) == 409 || closed else { return 500 }
    let payload = data(result)
    guard status(result) != 502 else { return 502 }
    guard status(result) != 400 else { return 400 }
    guard status(result) != 404 else { return 404 }
    guard status(result) != 409 else { return 409 }
    return response(200, body: payload)
}
route POST "/parse" {
    guard let reply = memcacheMetaParse(req.bodyBytes) else { return 400 }
    guard reply.kind == 1 else { return 400 }
    guard let value = packed(reply.item) else { return 400 }
    return response(200, body: value)
}
route POST "/build" {
    guard let wire = memcacheMetaGetRequest(req.bodyBytes) else { return 400 }
    return response(200, body: wire)
}
'''

VALUE = b'a\x00\xff\r\nb'


def bulk(value):
    return b'$' + str(len(value)).encode() + b'\r\n' + value + b'\r\n'


def meta(value=VALUE, fields=b'f4294967295 c18446744073709551615 t-1'):
    return b'VA ' + str(len(value)).encode() + b' ' + fields + b'\r\n' + value + b'\r\n'


class ReadPeer(Fixture):
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
                        assert command in ([b'GETEX', b'key'], [b'GETDEL', b'key']), command
                        good = bulk(VALUE)
                        replies = dict(normal=good, fragments=good, missing=b'$-1\r\n', empty=bulk(b''),
                                       error=b'-WRONGTYPE wrong kind\r\n', wrong=b':1\r\n',
                                       extra=good + b'+OK\r\n', truncated=good[:-1],
                                       max=bulk(b'x' * 8183), large=bulk(b'x' * 8184))
                    else:
                        assert command == b'mg key v f c t\r\n', command
                        good = meta()
                        replies = dict(normal=good, fragments=good, missing=b'EN\r\n', empty=meta(b''),
                                       error=b'SERVER_ERROR unavailable\r\n', wrong=b'HD f0 c1 t-1\r\n',
                                       extra=good + b'EN\r\n', truncated=good[:-1],
                                       max=meta(b'x' * 8171, b'f0 c1 t-1'),
                                       large=meta(b'x' * 8172, b'f0 c1 t-1'))
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
        for unit, amount, suffix in (
            ('', '0', []), ('PERSIST', '0', [b'PERSIST']),
            ('EX', '20', [b'EX', b'20']), ('PX', '123', [b'PX', b'123']),
            ('EXAT', '000123', [b'EXAT', b'123']),
            ('PXAT', '9223372036854775807', [b'PXAT', b'9223372036854775807']),
            ('EXAT', '9223372036854775', [b'EXAT', b'9223372036854775']),
        ):
            assert request('build', VALUE, {'X-Unit': unit, 'X-Time': amount}) == (200, packet([b'GETEX', VALUE, *suffix]))
        for unit in ('EX', 'PX', 'EXAT', 'PXAT'):
            for amount in ('0', '-1', '1x', '9223372036854775808'):
                assert request('build', b'key', {'X-Unit': unit, 'X-Time': amount})[0] == 400, (unit, amount)
        assert request('build', b'key', {'X-Unit': 'EXAT', 'X-Time': '9223372036854776'})[0] == 400
        assert request('build', b'x' * 8192)[0] == 400
    else:
        for fields in itertools.permutations((b'f4294967295', b'c18446744073709551615', b't-1')):
            assert request('parse', meta(fields=b' '.join(fields))) == (200, b'4294967295:18446744073709551615:-1:' + VALUE)
        assert request('parse', meta(b'', b'f0 c0 t2147483647')) == (200, b'0:0:2147483647:')
        bad_fields = (b'f0 c1', b'f0 c1 t-2', b'f0 c1 t+1', b'f0 c1 t2147483648',
                      b'f4294967296 c1 t0', b'f-1 c1 t0', b'f0 c18446744073709551616 t0',
                      b'f0 c-1 t0', b'f0 c1 t0 X', b'f0 f1 t0', b'f0  c1 t0', b'f0 c1 t0 ')
        for fields in bad_fields:
            assert request('parse', meta(fields=fields))[0] == 400, fields
        for frame in (b'VA -1 f0 c1 t0\r\n\r\n', b'VA 8192 f0 c1 t0\r\n',
                      meta() + b'EN\r\n', meta()[:-1], b'EN\r\n', b'VA 0 f0 c1 t0\r\nx\r\n'):
            assert request('parse', frame)[0] == 400, frame[:80]
        assert request('build', b'x' * 250) == (200, b'mg ' + b'x' * 250 + b' v f c t\r\n')
        for key in (b'', b'x' * 251, b'a b', b'a\x00b', b'a\x7fb', b'a\r\nb'):
            assert request('build', key)[0] == 400


def connect(args, port):
    connection = socket.create_connection(('127.0.0.1', port), timeout=3)
    if args.tls:
        context = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem'))
        connection = context.wrap_socket(connection, server_hostname='localhost')
    return connection


def live_checks(args, server, request):
    if args.protocol == 'redis':
        _, command = server
        for unit, amount in (('', '0'), ('EX', '60'), ('PX', '60000'),
                             ('EXAT', str(int(time.time()) + 60)),
                             ('PXAT', str(int(time.time() * 1000) + 60000)), ('PERSIST', '0')):
            assert command(b'SET', VALUE, VALUE, b'EX', b'90') == b'OK'
            assert request('getex', VALUE, {'X-Unit': unit, 'X-Time': amount}) == (200, VALUE)
            ttl = command(b'PTTL', VALUE)
            assert (ttl == -1 if unit == 'PERSIST' else (50000 < ttl <= (90000 if not unit else 60000))), (unit, ttl)
        assert command(b'SET', b'expired', VALUE) == b'OK'
        assert request('getex', b'expired', {'X-Unit': 'EXAT', 'X-Time': '1'}) == (200, VALUE)
        assert command(b'EXISTS', b'expired') == 0
        assert command(b'SET', b'keep', VALUE) == b'OK'
        assert request('getex', b'keep', {'X-Unit': 'PX', 'X-Time': '0'})[0] == 400
        assert command(b'GET', b'keep') == VALUE
        assert request('getdel', b'keep') == (200, VALUE)
        assert command(b'EXISTS', b'keep') == 0
        assert request('getdel', b'keep')[0] == 404
        assert command(b'LPUSH', b'list', b'x') == 1
        for route in ('getex', 'getdel'):
            assert request(route, b'list')[0] == 409
            assert command(b'LLEN', b'list') == 1
            assert request(route, b'absent')[0] == 404
        assert command(b'SET', b'', b'') == b'OK'
        assert request('getdel', b'') == (200, b'')
    else:
        with connect(args, server) as connection, connection.makefile('rb') as stream:
            def store(key, ttl, value):
                connection.sendall(b'set ' + key + b' 4294967295 ' + str(ttl).encode() + b' ' + str(len(value)).encode() + b'\r\n' + value + b'\r\n')
                assert stream.readline() == b'STORED\r\n'
            for ttl in (0, 60):
                store(b'key', ttl, VALUE)
                connection.sendall(b'gets key\r\n')
                header = stream.readline().split()
                cas = header[4]
                assert stream.read(len(VALUE) + 2) == VALUE + b'\r\n'
                assert stream.readline() == b'END\r\n'
                code, value = request('get', b'key')
                flags, returned_cas, remaining, data = value.split(b':', 3)
                assert code == 200 and data == VALUE and flags == b'4294967295' and cas == returned_cas
                assert (int(remaining) == -1 if ttl == 0 else 50 <= int(remaining) <= 60)
                # Consume the metadata CAS through the existing text CAS operation.
                connection.sendall(b'cas key 0 0 1 ' + returned_cas + b'\r\nx\r\n')
                assert stream.readline() == b'STORED\r\n'
            store(b'empty', 0, b'')
            assert request('get', b'empty')[1].endswith(b':-1:')
            assert request('get', b'absent')[0] == 404


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
            return redis_gateway(args, endpoint, program_factory=lambda _: REDIS)
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
        peer = ReadPeer(args.protocol, context)
        try:
            with gateway(peer.port) as request:
                pure_checks(request, args.protocol)
                for route in (('getex', 'getdel') if args.protocol == 'redis' else ('get',)):
                    for case in ('normal', 'fragments', 'missing', 'empty', 'error', 'wrong', 'extra', 'truncated', 'eof', 'timeout', 'max', 'large'):
                        peer.case = case
                        before = len(peer.observed)
                        code, value = request(route, b'key')
                        expected = 200 if case in ('normal', 'fragments', 'empty', 'max') else (404 if case == 'missing' else (409 if case == 'error' else 502))
                        assert code == expected, (route, case, code, value[:80])
                        if case in ('normal', 'fragments'):
                            assert value == (VALUE if args.protocol == 'redis' else b'4294967295:18446744073709551615:-1:' + VALUE)
                        followup = expected in (200, 404) or (expected == 409 and args.protocol == 'redis')
                        assert len(peer.observed) == before + 1 + followup, (route, case, peer.observed[before:])
                peer.case = 'normal'
                before = len(peer.observed)
                if args.protocol == 'redis':
                    assert request('getex', b'key', {'X-Unit': 'EX', 'X-Time': '0'})[0] == 400
                else:
                    assert request('get', b'bad key')[0] == 400
                assert len(peer.observed) == before + 1  # only the clean-handle probe
                assert not peer.errors, peer.errors
        finally:
            peer.close()
    print(f'Client read control passed ({args.protocol}, {args.backend}, O{args.opt}, tls={args.tls}, real={args.real})')


if __name__ == '__main__':
    main()
