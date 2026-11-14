#!/usr/bin/env python3
"""Bounded diagnostics: independent peers, pure framing, and pinned live servers."""
import argparse
from pathlib import Path
import ssl
import time

from test_redis_commands import Fixture, gateway as redis_gateway, packet, read_value, real_redis
from test_memcache_client import gateway as memcache_gateway, real_memcached

REDIS = r'''import "redis-client.rut"
func status(_ result: RedisResult) -> i32 {
    match result { .reply(reply) => 200
        .serverError(data) => 409
        .requestFailure => 400
        _ => 502 }
}
func data(_ result: RedisResult) -> Bytes {
    match result { .reply(reply) => reply.root.data
        .serverError(value) => value
        _ => b"" }
}
route POST "/info" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = execute(connection, req.header("X-Mode").or("info"), req.bodyBytes)
    let readback = redisGet(connection, b"stable")
    let closed = connection.close()
    guard status(result) != 502 || !closed else { return 500 }
    guard status(result) == 502 || closed else { return 500 }
    guard status(result) != 502 else { return 502 }
    guard status(result) != 400 else { return 400 }
    guard status(result) != 409 else { return 409 }
    let payload = data(result)
    return response(200, body: payload)
}
'''
# Keep each command on its own route so the compiler can verify its I/O budget.
_start = REDIS.index('route POST "/info"')
_route = REDIS[_start:]
REDIS = REDIS[:_start] + ''.join(
    _route.replace('"/info"', '"/' + mode + '"').replace(
        'execute(connection, req.header("X-Mode").or("info"), req.bodyBytes)', call)
    for mode, call in (('ping', 'redisPing(connection)'),
                       ('echo', 'redisEcho(connection, req.bodyBytes)'),
                       ('info', 'redisInfo(connection, req.bodyBytes)')))

REDIS += r'''route POST "/build" {
 guard let wire = resp2EchoRequest(req.bodyBytes) else { return 400 }
 return response(200, body: wire)
}
'''

MEMCACHE = r'''import "memcache-info.rut"
func section(_ name: str) -> MemcacheStatsSection {
    match name { "settings" => MemcacheStatsSection.settings "items" => MemcacheStatsSection.items
        "slabs" => MemcacheStatsSection.slabs _ => MemcacheStatsSection.general }
}
func status(_ result: MemcacheInfoResult) -> i32 {
    match result { .version(value) => 200
        .stats(value) => 200
        .serverError(value) => 409
        _ => 502 }
}
func data(_ result: MemcacheInfoResult) -> Bytes {
    match result { .version(value) => value
        .stats(value) => value.frame
        _ => b"" }
}
route POST "/info" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = execute(connection, req.header("X-Mode").or("general"))
    let sending = connection.send(b"get stable\r\n", 1000)
    let readback = connection.receive(8192, 1000)
    let closed = connection.close()
    guard status(result) == 200 || !closed else { return 500 }
    guard status(result) != 200 || closed else { return 500 }
    guard status(result) != 502 else { return 502 }
    guard status(result) != 409 else { return 409 }
    let payload = data(result)
    return response(200, body: payload)
}
func parsed(_ frame: Bytes, _ version: bool, _ key: Bytes) {
    guard let state = memcacheInfoScan(frame, version) else { nil }
    guard state.status == 1 else { nil }
    if version { frame.slice(8, frame.count - 2).or(b"") } else {
        let stats = MemcacheStats(frame: frame, count: state.count)
        guard let count = formatInt(state.count) else { nil }
        guard let prefix = concatBytes(Bytes(count), b":", 8192) else { nil }
        concatBytes(prefix, memcacheStatsGet(stats, key).or(b"MISSING"), 8192)
    }
}
route POST "/parse" {
    guard let value = parsed(req.bodyBytes, req.header("X-Mode").or("") == "version",
        Bytes(req.header("X-Key").or("version"))) else { return 400 }
    return response(200, body: value)
}
'''

_start = MEMCACHE.index('route POST "/info"')
_end = MEMCACHE.index('func parsed', _start)
_route = MEMCACHE[_start:_end]
MEMCACHE = MEMCACHE[:_start] + ''.join(
    _route.replace('"/info"', '"/' + mode + '"').replace(
        'execute(connection, req.header("X-Mode").or("general"))', call)
    for mode, call in (('version', 'memcacheVersion(connection)'),
                       ('info', 'memcacheStats(connection, section(req.header("X-Mode").or("general")))'))
) + MEMCACHE[_end:]


class InfoPeer(Fixture):
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
                        connection.sendall(b'$4\r\na\x00\xffb\r\n' if self.protocol == 'redis'
                                           else b'VALUE stable 0 4\r\na\x00\xffb\r\nEND\r\n')
                        continue
                    case = self.case
                    if case == 'eof':
                        return
                    if case == 'timeout':
                        self.stop.wait(1.3)
                        return
                    if self.protocol == 'redis':
                        normal = b'+PONG\r\n' if command[0] == b'PING' else packet_bulk(command[1] if command[0] == b'ECHO' else b'# Server\r\nredis_version:7.2.11\r\n')
                        replies = dict(normal=normal, fragments=normal, error=b'-NOAUTH fixture\r\n',
                                       wrong=b'$4\r\nPONG\r\n' if command[0] == b'PING' else b'+OK\r\n',
                                       truncated=b'$4\r\nab', extra=normal + b'+EXTRA\r\n',
                                       null=b'$-1\r\n', nested=b'*1\r\n+PONG\r\n',
                                       max=packet_bulk(b'x' * 8183), large=packet_bulk(b'x' * 8184))
                    else:
                        normal = b'VERSION 1.6.45\r\n' if command == b'version\r\n' else b'STAT version 1.6.45\r\nSTAT future_field a b\r\nEND\r\n'
                        replies = dict(normal=normal, fragments=normal, error=b'SERVER_ERROR fixture\r\n',
                                       wrong=b'STORED\r\n', truncated=b'STAT version 1.6.45\r\n',
                                       extra=normal + b'END\r\n', null=b'VERSION \r\n',
                                       nested=b'STAT version 1.6.45\r\nSERVER_ERROR late\r\n',
                                       max=b'STAT version ' + b'x' * 8172 + b'\r\nEND\r\n',
                                       large=b'STAT version ' + b'x' * 8173 + b'\r\nEND\r\n')
                    reply = replies[case]
                    if case == 'fragments':
                        for part in (reply[:2], reply[2:7], reply[7:]):
                            connection.sendall(part)
                            time.sleep(.04)
                    else:
                        connection.sendall(reply)
                    if case == 'truncated':
                        return
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)


def packet_bulk(value):
    return b'$' + str(len(value)).encode() + b'\r\n' + value + b'\r\n'


def parser_checks(request):
    assert request('parse', b'END\r\n') == (200, b'0:MISSING')
    assert request('parse', b'STAT version \r\nEND\r\n') == (200, b'1:')
    assert request('parse', b'STAT version a b\r\nSTAT version last\r\nEND\r\n') == (200, b'2:last')
    for count in (1, 63, 64, 65, 127, 128):
        frame = b''.join(b'STAT key' + str(i).encode() + b' ' + str(i).encode() + b'\r\n' for i in range(count)) + b'END\r\n'
        assert request('parse', frame, {'X-Key': f'key{count-1}'}) == (200, f'{count}:{count-1}'.encode())
        assert request('parse', frame[:-1])[0] == 400
    bad = (b'STAT  value\r\nEND\r\n', b'STAT bad\tkey value\r\nEND\r\n',
           b'STAT key value\n\r\nEND\r\n', b'STAT key value\r\nERROR\r\n',
           b'END\r\nEND\r\n', b'VERSION x\r\n',
           b'STAT k v\r\n' * 129 + b'END\r\n')
    for frame in bad:
        assert request('parse', frame)[0] == 400, frame[:80]
    assert request('parse', b'VERSION 1.6.45\r\n', {'X-Mode': 'version'}) == (200, b'1.6.45')
    for frame in (b'VERSION \r\n', b'VERSION a b\r\n', b'VERSION 1.6.45\r\nEND\r\n', b'END\r\n'):
        assert request('parse', frame, {'X-Mode': 'version'})[0] == 400


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--protocol', choices=('redis', 'memcache'), required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--testdata')
    parser.add_argument('--real', action='store_true')
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
                                extra_libraries=('memcache-info-codec.rut', 'memcache-info.rut'), entrypoint='memcache-info.rut')

    if args.real:
        manager = real_redis(args) if args.protocol == 'redis' else real_memcached(args)
        with manager as server:
            port = server[0] if args.protocol == 'redis' else server
            with gateway(port) as request:
                if args.protocol == 'redis':
                    assert request('ping', headers={'X-Mode': 'ping'}) == (200, b'PONG')
                    assert request('echo', b'a\x00\xff\r\n', {'X-Mode': 'echo'}) == (200, b'a\x00\xff\r\n')
                    code, frame = request('info', b'server')
                    assert code == 200 and b'redis_version:7.2.11' in frame
                    assert request('info', b'unknown-section') == (200, b'')
                else:
                    parser_checks(request)
                    assert request('version', headers={'X-Mode': 'version'}) == (200, b'1.6.45')
                    for mode in ('general', 'settings', 'items', 'slabs'):
                        code, frame = request('info', headers={'X-Mode': mode})
                        assert code == 200 and frame.endswith(b'END\r\n'), (mode, code, frame)
                        assert request('parse', frame)[0] == 200
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'), str(Path(args.testdata) / 'localhost_key.pem'))
        peer = InfoPeer(args.protocol, context)
        try:
            with gateway(peer.port) as request:
                if args.protocol == 'memcache':
                    parser_checks(request)
                for mode in (('ping', 'echo', 'info') if args.protocol == 'redis' else ('version', 'general', 'settings', 'items', 'slabs')):
                    for case in ('normal', 'fragments', 'wrong', 'extra', 'error', 'eof', 'timeout', 'truncated', 'null', 'nested'):
                        peer.case = case
                        before = len(peer.observed)
                        code, frame = request(mode if args.protocol == 'redis' or mode == 'version' else 'info', b'a\x00\xff\r\n' if mode == 'echo' else b'server', {'X-Mode': mode})
                        expected = 200 if case in ('normal', 'fragments') else (409 if case == 'error' else 502)
                        assert code == expected, (mode, case, code, frame)
                        expected_followup = case in ('normal', 'fragments') or (case == 'error' and args.protocol == 'redis')
                        assert len(peer.observed) == before + 1 + expected_followup
                    if mode not in ('ping', 'version'):
                        for case, expected in (('max', 200), ('large', 502)):
                            peer.case = case
                            assert request(mode if args.protocol == 'redis' or mode == 'version' else 'info', b'server', {'X-Mode': mode})[0] == expected
                if args.protocol == 'redis':
                    peer.case = 'normal'
                    before = len(peer.observed)
                    rejected = request('build', b'x' * 8192)
                    assert rejected[0] == 400, rejected
                    assert peer.observed[before:] == []
                assert not peer.errors, peer.errors
        finally:
            peer.close()
    print(f'PASS {args.protocol} diagnostics {args.backend} O{args.opt} TLS={args.tls} real={args.real}')


if __name__ == '__main__':
    main()
