#!/usr/bin/env python3
"""Finite cache invalidation: wire oracles and isolated pinned Redis/Memcached."""
import argparse
from pathlib import Path
import re
import socket
import ssl
import time

from test_redis_commands import Fixture, gateway as redis_gateway, packet, read_value, real_redis
from test_memcache_client import gateway as memcache_gateway, real_memcached

REDIS = r'''import "redis-client.rut"
func mode(_ lazy: bool) -> RedisDeleteMode {
    if lazy { RedisDeleteMode.lazy } else { RedisDeleteMode.blocking }
}
func status(_ result: RedisResult) -> i32 {
    match result {
        .reply(reply) => 200
        .serverError(data) => 409
        .requestFailure => 400
        _ => 502
    }
}
func integerData(_ reply: RedisReply) -> Bytes {
    guard let count = redisInteger(reply) else { b"bad" }
    guard let digits = formatInt(count) else { b"bad" }
    Bytes(digits)
}
func data(_ result: RedisResult) -> Bytes {
    match result {
        .reply(reply) => integerData(reply)
        _ => b""
    }
}
route POST "/build" {
    let keys = RedisKeys(arguments: req.bodyBytes, count: parseInt(req.header("X-Count").or("0")).or(0))
    guard let wire = resp2DeleteKeysRequest(keys, mode(req.header("X-Lazy").or("") == "yes")) else { return 400 }
    guard redisRequestValid(wire) else { return 400 }
    return response(200, body: wire)
}
route POST "/add" {
    guard let keys = redisKeysAdd(redisKeys(), req.bodyBytes) else { return 400 }
    guard let wire = resp2DeleteKeysRequest(keys, RedisDeleteMode.blocking) else { return 400 }
    return response(200, body: wire)
}
route POST "/batch" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let keys = RedisKeys(arguments: req.bodyBytes, count: parseInt(req.header("X-Count").or("0")).or(0))
    let result = redisDeleteKeys(connection, keys, mode(req.header("X-Lazy").or("") == "yes"))
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
MEMCACHE = r'''import "memcache-delete-batch.rut"
func status(_ result: MemcacheDeleteBatchResult) -> i32 {
    match result {
        .reply(reply) => 200
        .requestFailure => 400
        .serverError(data) => 409
        _ => 502
    }
}
func itemSuffix(_ deleted: bool) -> Bytes { if deleted { b":D" } else { b":M" } }
func itemData(_ reply: MemcacheDeleteBatchReply, _ index: i32) -> Bytes {
    guard let item = memcacheDeleteItem(reply, index) else { b"INVALID" }
    concatBytes(item.key, itemSuffix(item.deleted), 8192).or(b"bad")
}
func data(_ result: MemcacheDeleteBatchResult, _ index: i32) -> Bytes {
    match result {
        .reply(reply) => itemData(reply, index)
        _ => b""
    }
}
route POST "/build" {
    let keys = MemcacheKeys(bytes: req.bodyBytes, count: parseInt(req.header("X-Count").or("0")).or(0))
    guard let wire = memcacheDeleteBatchRequest(keys) else { return 400 }
    return response(200, body: wire)
}
route POST "/batch" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let keys = MemcacheKeys(bytes: req.bodyBytes, count: parseInt(req.header("X-Count").or("0")).or(0))
    let result = memcacheDeleteBatch(connection, keys)
    let sending = connection.send(b"get stable\r\n", 1000)
    let readback = connection.receive(8192, 1000)
    let closed = connection.close()
    guard status(result) == 502 || status(result) == 409 || closed else { return 500 }
    guard (status(result) != 502 && status(result) != 409) || !closed else { return 500 }
    guard status(result) != 502 else { return 502 }
    guard status(result) != 409 else { return 409 }
    guard status(result) != 400 else { return 400 }
    let payload = data(result, parseInt(req.header("X-Index").or("0")).or(-1))
    return response(200, body: payload)
}
route POST "/parse" {
    let reply = MemcacheDeleteBatchReply(frame: req.bodyBytes,
        keys: MemcacheKeys(bytes: Bytes(req.header("X-Keys").or("a b")), count: parseInt(req.header("X-Count").or("2")).or(0)))
    guard let item = memcacheDeleteItem(reply, parseInt(req.header("X-Index").or("0")).or(-1)) else { return 400 }
    guard let value = concatBytes(item.key, itemSuffix(item.deleted), 8192) else { return 400 }
    return response(200, body: value)
}
'''


def arguments(keys):
    return b''.join(b'$' + str(len(key)).encode() + b'\r\n' + key + b'\r\n' for key in keys)


class DeletePeer(Fixture):
    def __init__(self, protocol, context):
        self.protocol, self.case = protocol, 'normal'
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
                    if command == [b'GET', b'stable'] or command == b'get stable\r\n':
                        self.observed.append(command)
                        connection.sendall(b'$1\r\nx\r\n' if self.protocol == 'redis' else b'END\r\n')
                        continue
                    if self.protocol == 'memcache':
                        # The oracle cases send three commands. Read every request
                        # before responding, so tests can detect replay after failure.
                        commands = [command, stream.readline(), stream.readline()]
                        assert all(line.startswith(b'delete ') and line.endswith(b'\r\n') for line in commands)
                        self.observed.append(commands)
                        normal = b'DELETED\r\nNOT_FOUND\r\nDELETED\r\n'
                        replies = dict(normal=normal, fragments=normal,
                            wrong=b'STORED\r\n', extra=normal + b'DELETED\r\n',
                            error=b'SERVER_ERROR fixture\r\n', late=b'DELETED\r\nCLIENT_ERROR late\r\n',
                            truncated=b'DELETED\r\nNOT_FOU', negative=b'DELETED\n\r\n')
                    else:
                        self.observed.append(command)
                        assert command[0] in (b'DEL', b'UNLINK')
                        normal = b':2\r\n'
                        replies = dict(normal=normal, fragments=normal, wrong=b'+OK\r\n',
                            extra=normal + b':0\r\n', error=b'-CROSSSLOT fixture\r\n',
                            truncated=b':', negative=b':-1\r\n', excess=b':4\r\n')
                    case = self.case
                    if case == 'timeout':
                        self.stop.wait(1.3)
                        return
                    if case == 'eof':
                        return
                    if case == 'fragments':
                        reply = replies[case]
                        for chunk in (reply[:1], reply[1:4], reply[4:]):
                            if chunk:
                                connection.sendall(chunk)
                                time.sleep(.04)
                    else:
                        connection.sendall(replies[case])
                    if case == 'truncated':
                        return
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)


def builder_checks(request, protocol):
    for count in range(1, 9):
        keys = [f'key{i}'.encode() for i in range(count)]
        body = arguments(keys) if protocol == 'redis' else b' '.join(keys)
        for lazy in ('', 'yes') if protocol == 'redis' else ('',):
            headers = {'X-Count': str(count), 'X-Lazy': lazy}
            wire = packet([b'UNLINK' if lazy else b'DEL', *keys]) if protocol == 'redis' else b''.join(b'delete ' + key + b'\r\n' for key in keys)
            assert request('build', body, headers) == (200, wire)
    if protocol == 'redis':
        for key in (b'', b'a\x00\xff\r\nb'):
            assert request('add', key) == (200, packet([b'DEL', key]))
        assert request('build', arguments([b'a', b'a']), {'X-Count': '2'}) == (200, packet([b'DEL', b'a', b'a']))
        for body, count in ((b'', 1), (arguments([b'a']), 0), (arguments([b'a']), 2),
                            (arguments([b'a'] * 9), 9), (b'*0\r\n', 1), (b'$-1\r\n', 1),
                            (arguments([b'a']) + b'+EXTRA\r\n', 1)):
            assert request('build', body, {'X-Count': str(count)})[0] == 400
        # Header and one bulk argument consume 22 bytes at this payload width.
        low, high = 0, 8192
        while low < high:
            mid = (low + high + 1) // 2
            if request('build', arguments([b'x' * mid]), {'X-Count': '1'})[0] == 200:
                low = mid
            else:
                high = mid - 1
        assert len(request('build', arguments([b'x' * low]), {'X-Count': '1'})[1]) == 8192
        assert request('build', arguments([b'x' * (low + 1)]), {'X-Count': '1'})[0] == 400
    else:
        for body, count in ((b'', 0), (b'a a', 2), (b'a b', 1), (b'a b', 3), (b'a\r\nflush_all', 1), (b'x' * 251, 1), (b' '.join([b'a'] * 9), 9)):
            assert request('build', body, {'X-Count': str(count)})[0] == 400
        keys = [bytes([97 + i]) * 250 for i in range(8)]
        assert request('build', b' '.join(keys), {'X-Count': '8'}) == (200, b''.join(b'delete ' + key + b'\r\n' for key in keys))
        for frame, expected in ((b'DELETED\r\nNOT_FOUND\r\n', (200, b'a:D')),
                                (b'NOT_FOUND\r\nDELETED\r\n', (200, b'a:M'))):
            assert request('parse', frame) == expected
        for index in (-1, 2):
            assert request('parse', b'DELETED\r\nNOT_FOUND\r\n', {'X-Index': str(index)})[0] == 400
        for frame in (b'DELETED\r\n', b'DELETED\r\nNOT_FOUND\r\nDELETED\r\n', b'DELETED\r\nERROR\r\n', b'DELETED\r\nNOT_FOU'):
            assert request('parse', frame)[0] == 400


def composed_memcache_source(library):
    source = MEMCACHE.partition('\n')[2]
    names = set()
    for name in ('memcache-codec.rut', 'memcache-delete-batch.rut'):
        names.update(re.findall(r'^(?:func|struct|variant) (\w+)', Path(library, name).read_text(), re.M))
    source = re.sub(r'\b(' + '|'.join(sorted(names)) + r')\b', r'batch.\1', source)
    source = ('import * as base from "memcache-client.rut"\n'
              'import * as batch from "memcache-delete-batch.rut"\n' + source)
    probe = ('    let sending = connection.send(b"get stable\\r\\n", 1000)\n'
             '    let readback = connection.receive(8192, 1000)')
    assert probe in source, 'composition must replace the raw probe with the data client'
    return source.replace(probe, '    let readback = base.memcacheGet(connection, b"stable")')


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'library', 'backend', 'opt', 'protocol'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--compose', action='store_true')
    parser.add_argument('--real', action='store_true')
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--testdata')
    args = parser.parse_args()
    if args.compose and (args.protocol != "memcache" or args.opt != "0"):
        parser.error("--compose requires --protocol memcache --opt 0")
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
        return memcache_gateway(args, endpoint, program_factory=lambda: composed_memcache_source(args.library) if args.compose else MEMCACHE,
            extra_libraries=('memcache-delete-batch.rut',), entrypoint='memcache-delete-batch.rut')
    if args.real:
        manager = real_redis(args) if args.protocol == 'redis' else real_memcached(args)
        with manager as server:
            port = server[0] if args.protocol == 'redis' else server
            def mc(wire):
                connection = socket.create_connection(('127.0.0.1', port), timeout=2)
                if args.tls:
                    connection = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem')).wrap_socket(connection, server_hostname='localhost')
                with connection, connection.makefile('rb') as stream:
                    connection.sendall(wire)
                    return stream.readline()
            with gateway(port) as request:
                builder_checks(request, args.protocol)
                for count in (1, 3, 8):
                    keys = [f'key{i}'.encode() for i in range(count)]
                    for lazy in ('', 'yes') if args.protocol == 'redis' else ('',):
                        for key in keys:
                            if args.protocol == 'redis':
                                assert server[1](b'SET', key, b'value') == b'OK'
                            else:
                                assert mc(b'set ' + key + b' 0 0 1\r\nx\r\n') == b'STORED\r\n'
                        body = arguments(keys) if args.protocol == 'redis' else b' '.join(keys)
                        headers = {'X-Count': str(count), 'X-Lazy': lazy, 'X-Index': str(count - 1)}
                        assert request('batch', body, headers) == (200, str(count).encode() if args.protocol == 'redis' else keys[-1] + b':D')
                        assert request('batch', body, headers) == (200, b'0' if args.protocol == 'redis' else keys[-1] + b':M')
                        for key in keys:
                            assert (server[1](b'GET', key) if args.protocol == 'redis' else mc(b'get ' + key + b'\r\n')) in (None, b'END\r\n')
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'), str(Path(args.testdata) / 'localhost_key.pem'))
        peer = DeletePeer(args.protocol, context)
        try:
            with gateway(peer.port) as request:
                builder_checks(request, args.protocol)
                body = arguments([b'a', b'b', b'c']) if args.protocol == 'redis' else b'a b c'
                cases = ('normal', 'fragments', 'wrong', 'extra', 'error', 'negative', 'truncated', 'eof', 'timeout') + (('excess',) if args.protocol == 'redis' else ('late',))
                for case in cases:
                    peer.case = case
                    before = len(peer.observed)
                    code, value = request('batch', body, {'X-Count': '3', 'X-Index': '1'})
                    expected = 200 if case in ('normal', 'fragments') else (409 if case in ('error', 'late') else 502)
                    assert code == expected, (case, code, value)
                    if code == 200:
                        assert value == (b'2' if args.protocol == 'redis' else b'b:M')
                    followup = code == 200 or (case == 'error' and args.protocol == 'redis')
                    assert len(peer.observed) == before + 1 + followup, 'one batch send, no replay'
                peer.case = 'normal'
                before = len(peer.observed)
                assert request('batch', b'bad', {'X-Count': '0'})[0] == 400
                assert len(peer.observed) == before + 1, 'invalid batch must only send the later read'
        finally:
            peer.close()
    print(f'PASS {args.protocol} invalidation {args.backend} O{args.opt} TLS={args.tls} real={args.real}')


if __name__ == '__main__':
    main()
