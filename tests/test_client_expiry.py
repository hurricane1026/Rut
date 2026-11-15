#!/usr/bin/env python3
"""Explicit expiry encoding and mutation lifecycle against peers and pinned servers."""
import argparse
from pathlib import Path
import socket
import ssl
import time

from test_redis_commands import Fixture, gateway as redis_gateway, packet, read_value, real_redis
from test_memcache_client import gateway as memcache_gateway, real_memcached

REDIS = r'''import "redis-client.rut"
func expiry(_ unit: str, _ amount: Bytes) -> RedisSetExpiry {
    if unit == "EXAT" { RedisSetExpiry.unixSeconds(amount) }
    else { RedisSetExpiry.unixMilliseconds(amount) }
}
func condition(_ name: str) -> RedisSetCondition {
    match name { "NX" => RedisSetCondition.absent "XX" => RedisSetCondition.present
        _ => RedisSetCondition.always }
}
route POST "/build" {
    let exp = expiry(req.header("X-Unit").or("EXAT"), Bytes(req.header("X-Time").or("0")))
    let cond = condition(req.header("X-Condition").or(""))
    guard let wire = resp2SetGetRequest(b"expiry", req.bodyBytes, cond, exp) else { return 400 }
    return response(200, body: wire)
}
route POST "/write" {
    let pending = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = pending else { return 503 }
    let result = redisSetWithOptions(connection, Bytes(req.header("X-Key").or("expiry")), req.bodyBytes,
        condition(req.header("X-Condition").or("")),
        expiry(req.header("X-Unit").or("EXAT"), Bytes(req.header("X-Time").or("0"))))
    let closed = connection.close()
    match result {
        .ok => if closed { return 200 } else { return 500 }
        .notSet => if closed { return 409 } else { return 500 }
        .requestFailure => if closed { return 400 } else { return 500 }
        _ => if closed { return 500 } else { return 502 }
    }
}
'''

REDIS_GET = r'''func previous(_ result: RedisSetGetResult) -> Bytes {
    match result {
        .stored(old) => old.data
        .notStored(old) => old.data
        _ => b""
    }
}
func status(_ result: RedisSetGetResult) -> i32 {
    match result {
        .stored(old) => 200
        .notStored(old) => 409
        _ => 502
    }
}
func previousPrefix(_ result: RedisSetGetResult) -> Bytes {
    if status(result) == 200 { b"S:" } else { b"N:" }
}
route POST "/write-get" {
    let pending = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = pending else { return 503 }
    let result = redisSetGet(connection, b"expiry", req.bodyBytes,
        condition(req.header("X-Condition").or("")),
        expiry(req.header("X-Unit").or("EXAT"), Bytes(req.header("X-Time").or("0"))))
    let closed = connection.close()
    guard closed else { return 500 }
    guard status(result) != 502 else { return 502 }
    guard let data = concatBytes(previousPrefix(result), previous(result), 8192) else { return 500 }
    return response(200, body: data)
}
'''

MEMCACHE = r'''import "memcache-client.rut"
func expiry(_ unit: str, _ amount: Bytes) -> MemcacheExpiry {
    if unit == "relative" { MemcacheExpiry.seconds(parseInt(amount).or(-1)) }
    else { MemcacheExpiry.unixSeconds(amount) }
}
route POST "/build" {
    let exp = expiry(req.header("X-Unit").or("absolute"), Bytes(req.header("X-Time").or("0")))
    let mode = req.header("X-Mode").or("set")
    let wire = buildRequest(mode, req.bodyBytes, exp)
    guard let request = wire else { return 400 }
    return response(200, body: request)
}
func buildRequest(_ mode: str, _ value: Bytes, _ exp: MemcacheExpiry) {
    match mode {
        "touch" => memcacheTouchExpiryRequest(b"expiry", exp)
        "cas" => memcacheCasExpiryRequest(b"expiry", value, b"4294967295", exp, b"18446744073709551615")
        "gat" => memcacheManyExpiryRequest(MemcacheKeys(bytes: b"expiry other", count: 2), MemcacheRetrievalMode.touching, exp)
        "gats" => memcacheManyExpiryRequest(MemcacheKeys(bytes: b"expiry other", count: 2), MemcacheRetrievalMode.touchingCas, exp)
        "add" => memcacheStoreExpiryRequest(MemcacheStoreMode.add, b"expiry", value, b"4294967295", exp)
        "replace" => memcacheStoreExpiryRequest(MemcacheStoreMode.replace, b"expiry", value, b"4294967295", exp)
        _ => memcacheStoreExpiryRequest(MemcacheStoreMode.set, b"expiry", value, b"4294967295", exp)
    }
}
route POST "/write" {
    let pending = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = pending else { return 503 }
    let result = memcacheStoreWithExpiry(connection, MemcacheStoreMode.set,
        Bytes(req.header("X-Key").or("expiry")), req.bodyBytes, b"4294967295",
        expiry(req.header("X-Unit").or("absolute"), Bytes(req.header("X-Time").or("0"))))
    let closed = connection.close()
    match result {
        .stored => if closed { return 200 } else { return 500 }
        .requestFailure => if closed { return 400 } else { return 500 }
        _ => if closed { return 500 } else { return 502 }
    }
}
'''


def helper_program(group):
    source = MEMCACHE[:MEMCACHE.index('route POST "/build"')]
    operations = ('cas', 'touch') if group == 'mutations' else ('gat', 'gats', 'multi-gat', 'multi-gats')
    if group == 'retrievals':
        source += '''func firstData(_ reply: MemcacheManyReply) -> Bytes {
 guard let item = memcacheManyItem(reply, 0) else { b"" }
 item.data
}
'''
    for operation in operations:
        if operation == 'cas':
            call = 'memcacheCasWithExpiry(connection, b"expiry", req.bodyBytes, b"4294967295", exp, Bytes(req.header("X-Cas").or("0")))'
            branches = '.stored => if closed { return 200 } else { return 500 } .exists => if closed { return 409 } else { return 500 } .missing => if closed { return 404 } else { return 500 }'
        elif operation == 'touch':
            call = 'memcacheTouchWithExpiry(connection, b"expiry", exp)'
            branches = '.ok => if closed { return 200 } else { return 500 } .missing => if closed { return 404 } else { return 500 }'
        elif operation.startswith('multi-'):
            name = 'memcacheMultiGatsWithExpiry' if operation == 'multi-gats' else 'memcacheMultiGatWithExpiry'
            call = name + '(connection, MemcacheKeys(bytes: b"expiry other", count: 2), exp)'
        else:
            name = 'memcacheGatsWithExpiry' if operation == 'gats' else 'memcacheGatWithExpiry'
            call = name + '(connection, b"expiry", exp)'
        if operation not in ('cas', 'touch'):
            tag = operation.replace('-', '')
            many = operation.startswith('multi-')
            result_type = 'MemcacheManyResult' if many else ('MemcacheGetsResult' if operation == 'gats' else 'MemcacheGetResult')
            status_branch = '.values(reply) => if reply.count > 0 { 200 } else { 404 }' if many else '.value(item) => 200 .missing => 404'
            data_branch = '.values(reply) => firstData(reply)' if many else '.value(item) => item.data'
            source += ("func status" + tag + "(_ result: " + result_type + ") -> i32 { match result {\n" +
                       status_branch.replace(' .', '\n .') + '\n .requestFailure => 400 _ => 502 } }\n' +
                       "func data" + tag + "(_ result: " + result_type + ") -> Bytes { match result {\n" +
                       data_branch + '\n _ => b"" } }\n')
            source += ('''route POST "/$OP" {
 let pending = tcp(env("MEMCACHE_ENDPOINT"), 1000)
 guard let connection = pending else { return 503 }
 let exp = expiry("absolute", Bytes(req.header("X-Time").or("0")))
 let result = $CALL
 let closed = connection.close()
 let status = status$TAG(result)
 guard status != 502 || !closed else { return 500 }
 guard status != 502 else { return 502 }
 guard closed else { return 500 }
 guard status != 400 else { return 400 }
 guard status != 404 else { return 404 }
 let data = data$TAG(result)
 return response(200, body: data)
}
'''.replace('$OP', operation).replace('$CALL', call).replace('$TAG', tag))
            continue
        branches = branches.replace(' .', '\n .')
        source += ('route POST "/' + operation + '" {\n'
                   ' let pending = tcp(env("MEMCACHE_ENDPOINT"), 1000)\n'
                   ' guard let connection = pending else { return 503 }\n'
                   ' let exp = expiry("absolute", Bytes(req.header("X-Time").or("0")))\n'
                   ' let result = ' + call + '\n'
                   ' let closed = connection.close()\n'
                   ' match result { ' + branches + '\n'
                   ' .requestFailure => if closed { return 400 } else { return 500 }\n'
                   ' _ => if closed { return 500 } else { return 502 } }\n}\n')
    return source


def helper_checks(args):
    assert args.protocol == 'memcache' and args.real
    with real_memcached(args) as port:
        def command(wire, value=False):
            connection = socket.create_connection(('127.0.0.1', port), timeout=2)
            if args.tls:
                context = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem'))
                connection = context.wrap_socket(connection, server_hostname='localhost')
            with connection, connection.makefile('rb') as stream:
                connection.sendall(wire)
                line = stream.readline()
                if not value or line == b'END\r\n':
                    return line, b''
                body = stream.read(int(line.split()[3]))
                assert stream.read(2) == b'\r\n' and stream.readline() == b'END\r\n'
                return line, body
        endpoint = dict(address='127.0.0.1', port=port)
        if args.tls:
            endpoint.update(tls=True, caFile=str(Path(args.testdata).resolve() / 'localhost_cert.pem'), serverName='localhost')
        with memcache_gateway(args, endpoint, program_factory=lambda: helper_program(args.helpers)) as request:
            operations = ('cas', 'touch') if args.helpers == 'mutations' else ('gat', 'gats', 'multi-gat', 'multi-gats')
            for operation in operations:
                for key in (b'expiry', b'other'):
                    assert command(b'set ' + key + b' 4294967295 0 3\r\nold\r\n')[0] == b'STORED\r\n'
                token = command(b'gets expiry\r\n', True)[0].split()[4].decode()
                headers = {'X-Time': str(int(time.time()) + 30), 'X-Cas': token}
                expected = b'OK' if operation in ('cas', 'touch') else b'old'
                actual = request(operation, b'new', headers)
                assert actual == (200, expected), (operation, actual)
                assert command(b'get expiry\r\n', True)[1] == (b'new' if operation == 'cas' else b'old')
                if operation == 'cas':
                    assert request(operation, b'wrong', headers)[0] == 409
                    assert command(b'get expiry\r\n', True)[1] == b'new'
                    headers['X-Cas'] = command(b'gets expiry\r\n', True)[0].split()[4].decode()
                assert request(operation, b'bad', {**headers, 'X-Time': '2147483648'})[0] == 400
                # The largest supported timestamp remains readable.
                assert request(operation, b'new', {**headers, 'X-Time': '2147483647'})[0] == 200
                if operation == 'cas':
                    headers['X-Cas'] = command(b'gets expiry\r\n', True)[0].split()[4].decode()
                assert request(operation, b'past', {**headers, 'X-Time': '2600001'})[0] == 200
                assert command(b'get expiry\r\n', True)[0] == b'END\r\n'
                if operation in ('cas', 'touch', 'gat', 'gats'):
                    assert request(operation, b'missing', headers)[0] == 404
        print(f'PASS Memcache expiry helpers {args.helpers} {args.backend} O{args.opt}')


class ExpiryPeer(Fixture):
    def __init__(self, protocol, context):
        self.protocol = protocol
        super().__init__(context)

    def serve(self, connection):
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                if self.protocol == 'redis':
                    command = read_value(stream)
                    key = command[1]
                else:
                    line = stream.readline()
                    if not line:
                        return
                    fields = line.split()
                    key = fields[1]
                    value = stream.read(int(fields[4]) + 2)
                    assert value.endswith(b'\r\n')
                    command = fields + [value[:-2]]
                self.observed.append(command)
                if key == b'eof':
                    return
                if key == b'timeout':
                    self.stop.wait(1.3)
                    return
                connection.sendall(b'+OK\r\n' if self.protocol == 'redis' else b'STORED\r\n')
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)


def builders(request, protocol):
    value = b'a\x00\xff\r\nz'
    if protocol == 'redis':
        for unit, maximum in (('EXAT', 9223372036854775), ('PXAT', 9223372036854775807)):
            for amount in (1, 2147483648, maximum):
                for condition in ('', 'NX', 'XX'):
                    headers = {'X-Unit': unit, 'X-Time': str(amount), 'X-Condition': condition}
                    expected = [b'SET', b'expiry', value]
                    if condition:
                        expected.append(condition.encode())
                    expected += [unit.encode(), str(amount).encode(), b'GET']
                    assert request('build', value, headers) == (200, packet(expected))
            for amount in ('0', '-1', '+1', '1x', str(maximum + 1), '9223372036854775808', ''):
                assert request('build', value, {'X-Unit': unit, 'X-Time': amount})[0] == 400
    else:
        for unit, amounts in (('relative', (0, 2592000)), ('absolute', (2592001, 2147483646, 2147483647))):
            for amount in amounts:
                for mode in ('set', 'add', 'replace', 'cas', 'touch', 'gat', 'gats'):
                    headers = {'X-Unit': unit, 'X-Time': str(amount), 'X-Mode': mode}
                    if mode in ('gat', 'gats'):
                        wire = f'{mode} {amount} expiry other\r\n'.encode()
                    elif mode == 'touch':
                        wire = f'touch expiry {amount}\r\n'.encode()
                    else:
                        cas = ' 18446744073709551615' if mode == 'cas' else ''
                        wire = f'{mode} expiry 4294967295 {amount} {len(value)}{cas}\r\n'.encode() + value + b'\r\n'
                    assert request('build', value, headers) == (200, wire)
        for unit, amounts in (('relative', ('-1', '2592001')), ('absolute', ('0', '2592000', '2147483648', '4294967295', '4294967296', '-1', '+2600000', '1x', ''))):
            for amount in amounts:
                for mode in ('set', 'cas', 'touch', 'gat', 'gats'):
                    assert request('build', value, {'X-Unit': unit, 'X-Time': amount, 'X-Mode': mode})[0] == 400
    # Canonicalize leading zeros without narrowing the timestamp.
    assert request('build', value, {'X-Time': '0002147483647'})[0] == 200
    # Bounds include expiry overhead and binary payload, with exact fit accepted.
    headers = {'X-Time': '2147483647'}
    low, high = 0, 8192
    while low < high:
        middle = (low + high + 1) // 2
        if request('build', b'x' * middle, headers)[0] == 200:
            low = middle
        else:
            high = middle - 1
    assert len(request('build', b'x' * low, headers)[1]) == 8192
    assert request('build', b'x' * (low + 1), headers)[0] == 400


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--protocol', choices=('redis', 'memcache'), required=True)
    parser.add_argument('--real', action='store_true')
    parser.add_argument('--helpers', choices=('mutations', 'retrievals'))
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--testdata')
    args = parser.parse_args()
    args.real_redis = args.real
    args.real_memcached = args.real
    args.example = None
    if args.tls and not args.testdata:
        parser.error('--tls requires --testdata')

    if args.helpers:
        helper_checks(args)
        return

    def gateway(port):
        endpoint = {'address': '127.0.0.1', 'port': port}
        if args.tls:
            endpoint.update(tls=True, caFile=str(Path(args.testdata).resolve() / 'localhost_cert.pem'), serverName='localhost')
        if args.protocol == 'redis':
            return redis_gateway(args, endpoint, program_factory=lambda _: REDIS + (REDIS_GET if args.real else ""))
        return memcache_gateway(args, endpoint, program_factory=lambda: MEMCACHE)

    if args.real:
        manager = real_redis(args) if args.protocol == 'redis' else real_memcached(args)
        with manager as server:
            port = server[0] if args.protocol == 'redis' else server
            def get():
                if args.protocol == 'redis':
                    return server[1](b'GET', b'expiry')
                connection = socket.create_connection(('127.0.0.1', port), timeout=2)
                if args.tls:
                    context = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem'))
                    connection = context.wrap_socket(connection, server_hostname='localhost')
                with connection, connection.makefile('rb') as stream:
                    connection.sendall(b'get expiry\r\n')
                    line = stream.readline()
                    if line == b'END\r\n':
                        return None
                    assert line.startswith(b'VALUE expiry 4294967295 '), line
                    value = stream.read(int(line.split()[3]))
                    assert stream.read(2) == b'\r\n' and stream.readline() == b'END\r\n'
                    return value
            with gateway(port) as request:
                builders(request, args.protocol)
                for unit, scale in ((('EXAT', 1), ('PXAT', 1000)) if args.protocol == 'redis' else (('absolute', 1),)):
                    value = b'live\x00\xff'
                    deadline = int((time.time() + 4) * scale)
                    assert request('write', value, {'X-Unit': unit, 'X-Time': str(deadline)})[0] == 200
                    assert get() == value
                    if args.protocol == 'redis':
                        assert server[1](b'PEXPIRETIME', b'expiry') == deadline * (1000 // scale)
                    end = time.monotonic() + 7
                    while get() is not None and time.monotonic() < end:
                        time.sleep(.05)
                    assert get() is None
                if args.protocol == 'redis':
                    for unit, maximum, scale in (('EXAT', 9223372036854775, 1000), ('PXAT', 9223372036854775807, 1)):
                        for present in (False, True):
                            for condition in ('', 'NX', 'XX'):
                                server[1](b'DEL', b'expiry')
                                if present:
                                    assert server[1](b'SET', b'expiry', b'old') == b'OK'
                                stored = condition != ('NX' if present else 'XX')
                                assert request('write-get', b'new', {'X-Unit': unit, 'X-Time': str(maximum), 'X-Condition': condition}) == (
                                    200, (b'S:' if stored else b'N:') + (b'old' if present else b''))
                                assert get() == (b'new' if stored else (b'old' if present else None))
                                assert server[1](b'PEXPIRETIME', b'expiry') == (maximum * scale if stored else (-1 if present else -2))
                assert request('write', b'future', {'X-Time': '2147483647'})[0] == 200
                assert get() == b'future'
                assert request('write', b'past', {'X-Time': '2600001'})[0] == 200
                assert get() is None
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'), str(Path(args.testdata) / 'localhost_key.pem'))
        peer = ExpiryPeer(args.protocol, context)
        try:
            with gateway(peer.port) as request:
                builders(request, args.protocol)
                assert not peer.observed
                assert request('write', b'value', {'X-Time': '0'})[0] == 400
                assert not peer.observed
                for key, status in (('expiry', 200), ('eof', 502), ('timeout', 502)):
                    before = len(peer.observed)
                    assert request('write', b'value', {'X-Time': '2147483647', 'X-Key': key})[0] == status
                    assert len(peer.observed) == before + 1, 'mutation must not be replayed'
                assert not peer.errors, peer.errors
        finally:
            peer.close()
    print(f'PASS {args.protocol} explicit expiry {args.backend} O{args.opt} TLS={args.tls} real={args.real}')


if __name__ == '__main__':
    main()
