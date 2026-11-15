#!/usr/bin/env python3
"""Conditional TTL changes and CAS-protected deletion, without mutation replay."""
import argparse
from pathlib import Path
import ssl
import time

from test_redis_commands import Fixture, gateway as redis_gateway, packet, read_value, real_redis
from test_memcache_client import gateway as memcache_gateway, real_memcached
from test_client_read_control import connect

REDIS = r'''import "redis-expiry.rut"
func condition(_ name: str) -> RedisExpireCondition {
    match name {
        "NX" => RedisExpireCondition.noExpiry
        "XX" => RedisExpireCondition.hasExpiry
        "GT" => RedisExpireCondition.longer
        "LT" => RedisExpireCondition.shorter
        "XXGT" => RedisExpireCondition.hasExpiryLonger
        "XXLT" => RedisExpireCondition.hasExpiryShorter
        _ => RedisExpireCondition.always
    }
}
func status(_ result: RedisExpireResult) -> i32 {
    match result { .applied => 200
        .notApplied => 412
        .serverError(message) => 409
        .requestFailure => 400
        _ => 502 }
}
func data(_ result: RedisExpireResult) -> Bytes {
    match result { .applied => b"applied"
        .notApplied => b"notApplied"
        .serverError(message) => message
        _ => b"" }
}
route POST "/build" {
    guard let request = resp2ExpireRequest(req.bodyBytes, parseInt(req.header("X-Time").or("60")).or(0),
        req.header("X-Unit").or("") == "PX", condition(req.header("X-Condition").or(""))) else { return 400 }
    return response(200, body: request)
}
'''
ROUTE = r'''route POST "/OP" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = CALL(connection, req.bodyBytes, parseInt(req.header("X-Time").or("60")).or(0),
        condition(req.header("X-Condition").or("")))
    let sending = connection.send(b"*2\r\n$3\r\nGET\r\n$6\r\nstable\r\n", 1000)
    let reading = connection.receive(8192, 1000)
    let closed = connection.close()
    guard status(result) != 502 || !closed else { return 500 }
    guard status(result) == 502 || closed else { return 500 }
    guard status(result) != 502 else { return 502 }
    guard status(result) != 409 else { return 409 }
    guard status(result) != 400 else { return 400 }
    guard status(result) != 412 else { return 412 }
    let payload = data(result)
    return response(200, body: payload)
}
'''
for mode, call in (('seconds', 'redisExpireWithCondition'), ('millis', 'redisPexpireWithCondition')):
    REDIS += ROUTE.replace('OP', mode).replace('CALL', call)

MEMCACHE = r'''import "memcache-meta.rut"
func status(_ result: MemcacheDeleteCasResult) -> i32 {
    match result { .deleted => 200
        .exists => 412
        .missing => 404
        .serverError(message) => 409
        .requestFailure => 400
        _ => 502 }
}
func data(_ result: MemcacheDeleteCasResult) -> Bytes {
    match result { .deleted => b"deleted"
        .serverError(message) => message
        _ => b"" }
}
route POST "/build" {
    guard let wire = memcacheDeleteCasRequest(req.bodyBytes, Bytes(req.header("X-Cas").or("1"))) else { return 400 }
    return response(200, body: wire)
}
route POST "/delete" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheDeleteCas(connection, req.bodyBytes, Bytes(req.header("X-Cas").or("1")))
    let sending = connection.send(b"get stable\r\n", 1000)
    let reading = connection.receive(8192, 1000)
    let closed = connection.close()
    guard status(result) != 502 && status(result) != 409 || !closed else { return 500 }
    guard status(result) == 502 || status(result) == 409 || closed else { return 500 }
    guard status(result) != 502 else { return 502 }
    guard status(result) != 409 else { return 409 }
    guard status(result) != 400 else { return 400 }
    guard status(result) != 412 else { return 412 }
    guard status(result) != 404 else { return 404 }
    let payload = data(result)
    return response(200, body: payload)
}
func token(_ result: MemcacheMetaResult) -> Bytes {
    match result { .value(item) => item.cas
        _ => b"" }
}
route POST "/read-delete" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let reading = memcacheMetaGet(connection, req.bodyBytes)
    let cas = token(reading)
    let result = memcacheDeleteCas(connection, req.bodyBytes, cas)
    let closed = connection.close()
    guard closed && status(result) == 200 else { return 502 }
    return 200
}
'''


COMPOSE = r'''import * as cache from "redis-client.rut"
import * as expiry from "redis-expiry.rut"
func applied(_ result: expiry.RedisExpireResult) -> bool {
    match result { .applied => true
        _ => false }
}
func fetched(_ result: cache.RedisGetResult) -> Bytes {
    match result { .value(value) => value
        _ => b"" }
}
route POST "/compose" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = expiry.redisExpireWithCondition(connection, b"key", 60, expiry.RedisExpireCondition.hasExpiryLonger)
    let readback = cache.redisGet(connection, b"stable")
    let closed = connection.close()
    guard closed && applied(result) else { return 502 }
    let value = fetched(readback)
    return response(200, body: value)
}
'''


class ConditionalPeer(Fixture):
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
                        connection.sendall(b'$1\r\nx\r\n' if self.protocol == 'redis' else b'END\r\n')
                        continue
                    if self.protocol == 'redis':
                        assert command[0] in (b'EXPIRE', b'PEXPIRE'), command
                        assert command[1:] == [b'key', b'60', b'XX', b'GT'], command
                        replies = dict(normal=b':1\r\n', fragments=b':1\r\n', rejected=b':0\r\n',
                                       missing=b':0\r\n', error=b'-ERR unsupported\r\n',
                                       wrong=b'+OK\r\n', extra=b':1\r\n:0\r\n', truncated=b':1\r',
                                       negative=b':-1\r\n', outOfRange=b':2\r\n',
                                       huge=b':9223372036854775807\r\n')
                    else:
                        assert command == b'md key C18446744073709551615\r\n', command
                        replies = dict(normal=b'HD\r\n', fragments=b'HD\r\n', rejected=b'EX\r\n',
                                       missing=b'NF\r\n', error=b'SERVER_ERROR unavailable\r\n',
                                       wrong=b'DELETED\r\n', extra=b'HD\r\nNF\r\n', truncated=b'HD\r',
                                       negative=b'HD Ounexpected\r\n', outOfRange=b'HD \r\n',
                                       huge=b'VA 1 f0 c1 t0\r\nx\r\n')
                    if self.case == 'eof':
                        return
                    if self.case == 'timeout':
                        time.sleep(1.2)
                        continue
                    reply = replies[self.case]
                    if self.case == 'fragments':
                        for part in (reply[:1], reply[1:-1], reply[-1:]):
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
        for condition, suffix in (('', []), ('NX', [b'NX']), ('XX', [b'XX']), ('GT', [b'GT']),
                                  ('LT', [b'LT']), ('XXGT', [b'XX', b'GT']), ('XXLT', [b'XX', b'LT'])):
            for amount in ('60', '0', '-1', '-2147483648', '2147483647'):
                for unit, name in (('', b'EXPIRE'), ('PX', b'PEXPIRE')):
                    assert request('build', b'a\x00\xff\r\n', {'X-Condition': condition, 'X-Time': amount, 'X-Unit': unit}) == (200, packet([name, b'a\x00\xff\r\n', amount.encode(), *suffix]))
        # Largest accepted key and the next byte, including all five arguments.
        for size in (8132, 8133):
            expected = packet([b'PEXPIRE', b'x' * size, b'-2147483648', b'XX', b'GT'])
            result = request('build', b'x' * size, {'X-Condition': 'XXGT', 'X-Time': '-2147483648', 'X-Unit': 'PX'})
            assert (result == (200, expected) if len(expected) <= 8192 else result[0] == 400)
        assert request('build', b'x' * 8192)[0] == 400
    else:
        for cas in (b'0', b'1', b'18446744073709551615'):
            assert request('build', b'x' * 250, {'X-Cas': cas.decode()}) == (200, b'md ' + b'x' * 250 + b' C' + cas + b'\r\n')
        for cas in ('', '-1', '+1', '1x', '18446744073709551616', '1 2', '1\tX'):
            assert request('build', b'key', {'X-Cas': cas})[0] == 400, cas
        for key in (b'', b'x' * 251, b'a b', b'a\r\nb', b'a\x00b', b'a\x7fb'):
            assert request('build', key)[0] == 400


def live_checks(args, server, request):
    if args.protocol == 'redis':
        _, command = server
        # Compare every helper result with an independent Redis key in the same
        # initial state. Check both mutation and rejected-condition preservation.
        for route, name, ttl in (('seconds', b'EXPIRE', 60), ('millis', b'PEXPIRE', 60000)):
            for state in ('missing', 'persistent', 'volatile'):
                for condition, suffix in (('', []), ('NX', [b'NX']), ('XX', [b'XX']), ('GT', [b'GT']),
                                          ('LT', [b'LT']), ('XXGT', [b'XX', b'GT']), ('XXLT', [b'XX', b'LT'])):
                    for amount in (ttl // 2, ttl * 2, 0, -1):
                        command(b'DEL', b'key', b'oracle')
                        if state != 'missing':
                            for key in (b'key', b'oracle'):
                                command(b'SET', key, b'unchanged')
                                if state == 'volatile':
                                    command(name, key, str(ttl).encode())
                        expected = command(name, b'oracle', str(amount).encode(), *suffix)
                        code, _ = request(route, b'key', {'X-Condition': condition, 'X-Time': str(amount)})
                        assert code == (200 if expected == 1 else 412), (route, state, condition, amount, code)
                        assert command(b'GET', b'key') == command(b'GET', b'oracle')
                        actual_ttl, oracle_ttl = command(b'PTTL', b'key'), command(b'PTTL', b'oracle')
                        assert (actual_ttl == oracle_ttl if actual_ttl < 0 else abs(actual_ttl - oracle_ttl) < 200), (actual_ttl, oracle_ttl)
        command(b'LPUSH', b'list', b'x')
        assert request('seconds', b'list', {'X-Condition': 'NX'})[0] == 200
        assert command(b'LLEN', b'list') == 1
    else:
        with connect(args, server) as connection, connection.makefile('rb') as stream:
            def store(value):
                connection.sendall(b'set key 7 0 ' + str(len(value)).encode() + b'\r\n' + value + b'\r\n')
                assert stream.readline() == b'STORED\r\n'

            def gets():
                connection.sendall(b'gets key\r\n')
                header = stream.readline().split()
                assert header[0] == b'VALUE'
                value = stream.read(int(header[3]) + 2)[:-2]
                assert stream.readline() == b'END\r\n'
                return value, header[4].decode()

            store(b'old')
            _, old = gets()
            store(b'new\x00\xff')
            _, current = gets()
            assert current != old
            assert request('delete', b'key', {'X-Cas': old})[0] == 412
            assert gets() == (b'new\x00\xff', current)
            assert request('delete', b'key', {'X-Cas': current}) == (200, b'deleted')
            connection.sendall(b'get key\r\n')
            assert stream.readline() == b'END\r\n'
            assert request('delete', b'key', {'X-Cas': current})[0] == 404
            store(b'preserved')
            assert request('delete', b'key', {'X-Cas': '-1'})[0] == 400
            assert gets()[0] == b'preserved'
            assert request('read-delete', b'key')[0] == 200
            connection.sendall(b'get key\r\n')
            assert stream.readline() == b'END\r\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--protocol', choices=('redis', 'memcache'), required=True)
    parser.add_argument('--real', action='store_true')
    parser.add_argument('--compose', action='store_true')
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--testdata')
    args = parser.parse_args()
    if args.compose and (args.protocol != 'redis' or args.opt != '0' or args.real or args.tls):
        parser.error('--compose requires Redis O0 with the plain independent peer')
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
            return redis_gateway(args, endpoint, program_factory=lambda _: COMPOSE if args.compose else REDIS,
                                 extra_libraries=('redis-expiry.rut',), entrypoint='redis-expiry.rut')
        return memcache_gateway(args, endpoint, program_factory=lambda: MEMCACHE,
                                extra_libraries=('memcache-meta.rut',), entrypoint='memcache-meta.rut')

    if args.compose:
        peer = ConditionalPeer('redis', None)
        try:
            with gateway(peer.port) as request:
                assert request('compose') == (200, b'x')
                assert peer.observed == [[b'EXPIRE', b'key', b'60', b'XX', b'GT'], [b'GET', b'stable']]
        finally:
            peer.close()
        print('Client conditional namespace composition passed')
        return
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
        peer = ConditionalPeer(args.protocol, context)
        try:
            with gateway(peer.port) as request:
                pure_checks(request, args.protocol)
                for route in (('seconds', 'millis') if args.protocol == 'redis' else ('delete',)):
                    for case in ('normal', 'fragments', 'rejected', 'missing', 'error', 'wrong', 'extra', 'truncated', 'negative', 'outOfRange', 'huge', 'eof', 'timeout'):
                        peer.case = case
                        before = len(peer.observed)
                        code, value = request(route, b'key', {'X-Condition': 'XXGT', 'X-Cas': '18446744073709551615'})
                        expected = 200 if case in ('normal', 'fragments') else (412 if case == 'rejected' else ((412 if args.protocol == 'redis' else 404) if case == 'missing' else (409 if case == 'error' else 502)))
                        assert code == expected, (route, case, code, value[:80])
                        followup = expected in (200, 404, 412) or (expected == 409 and args.protocol == 'redis')
                        assert len(peer.observed) == before + 1 + followup, (route, case, peer.observed[before:])
                if args.protocol == 'memcache':
                    before = len(peer.observed)
                    assert request('delete', b'key', {'X-Cas': '-1'})[0] == 400
                    assert len(peer.observed) == before + 1
                assert not peer.errors, peer.errors
        finally:
            peer.close()
    print(f'Client conditional passed ({args.protocol}, {args.backend}, O{args.opt}, tls={args.tls}, real={args.real})')


if __name__ == '__main__':
    main()
