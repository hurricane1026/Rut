#!/usr/bin/env python3
"""RESP3 types, attribute roots, coalesced pushes and real HELLO 3."""
import argparse
from pathlib import Path
import ssl

from test_redis_commands import Fixture, gateway, packet, read_value, real_redis


PROGRAM = r'''import "redis-resp3.rut"
func r3Event(_ result: RedisResp3Result) -> RedisResp3Event {
    match result {
        .reply(event) => event
        .push(event) => event
        .serverError(event) => event
        _ => nil
    }
}
func r3Kind(_ result: RedisResp3Result) -> Bytes {
    match result {
        .reply(event) => b"R:"
        .push(event) => b"P:"
        .serverError(event) => b"E:"
        _ => b""
    }
}
func r3Output(_ result: RedisResp3Result) -> Bytes {
    guard let event = r3Event(result) else { nil }
    concatBytes(r3Kind(result), event.frame, 8192)
}
func r3Hello(_ connection: TcpConnection, _ enabled: bool) -> bool {
    if enabled {
        let result = redisHello3(connection)
        match result {
            .reply(event) => true
            _ => false
        }
    } else { true }
}
route POST "/decode" {
    guard let values = decodeResp3(req.bodyBytes) else { return 422 }
    guard let value = values.get(parseInt(req.header("X-Index").or("0")).or(-1)) else { return 404 }
    guard value.kind == parseInt(req.header("X-Kind").or("1")).or(-1) else { return 500 }
    let body = value.data
    return response(200, body: body)
}
route POST "/frame" {
    guard let frame = resp3Frame(req.bodyBytes) else { return 422 }
    guard frame.root.kind == parseInt(req.header("X-Kind").or("1")).or(-1) else { return 500 }
    let body = frame.rest
    return response(200, body: body)
}
route POST "/execute" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let negotiated = r3Hello(connection, req.header("X-Hello").or("") == "yes")
    guard negotiated else { return 500 }
    let result = redisResp3Execute(connection, req.bodyBytes)
    let closed = connection.close()
    guard let body = r3Output(result) else { return 502 }
    return response(200, body: body)
}
route POST "/next" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let first = redisResp3Execute(connection, req.bodyBytes)
    guard let event = r3Event(first) else { return 502 }
    let second = redisResp3Next(connection, event.rest)
    let closed = connection.close()
    guard let one = r3Output(first) else { return 502 }
    guard let two = r3Output(second) else { return 502 }
    guard let body = concatBytes(one, two, 8192) else { return 500 }
    return response(200, body: body)
}
route POST "/hello" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisHello3(connection)
    let closed = connection.close()
    guard let body = r3Output(result) else { return 502 }
    return response(200, body: body)
}
'''


def pure_checks(request):
    cases = [(b'+OK\r\n', 1, b'OK'), (b'-ERR no\r\n', 2, b'ERR no'),
             (b':-9223372036854775808\r\n', 3, b'-9223372036854775808'),
             (b'$4\r\na\x00\xffb\r\n', 4, b'a\x00\xffb'), (b'*0\r\n', 5, b''),
             (b'$-1\r\n', 6, b''), (b'*-1\r\n', 7, b''), (b'_\r\n', 8, b''),
             (b'#t\r\n', 9, b't'), (b'#f\r\n', 9, b'f'),
             (b',-1.25e+100\r\n', 10, b'-1.25e+100'),
             (b',inf\r\n', 10, b'inf'), (b',-inf\r\n', 10, b'-inf'), (b',nan\r\n', 10, b'nan'),
             (b'(' + b'9' * 64 + b'\r\n', 11, b'9' * 64),
             (b'!7\r\nERR bad\r\n', 12, b'ERR bad'), (b'=7\r\ntxt:abc\r\n', 13, b'txt:abc'),
             (b'%1\r\n+k\r\n#t\r\n', 14, b''), (b'~2\r\n:1\r\n:2\r\n', 16, b''),
             (b'>2\r\n+invalidate\r\n*0\r\n', 17, b'')]
    for frame, kind, value in cases:
        assert request('decode', frame, {'X-Kind': str(kind)}) == (200, value), frame
        assert request('frame', frame + b'+NEXT\r\n', {'X-Kind': str(kind)}) == (200, b'+NEXT\r\n')
        assert request('decode', frame + b'+NEXT\r\n')[0] == 422
    attribute = b'|1\r\n+ttl\r\n:5\r\n'
    assert request('decode', attribute + b'#t\r\n', {'X-Kind': '15'}) == (200, b'')
    assert request('frame', attribute + b'>1\r\n+x\r\n', {'X-Kind': '17'}) == (200, b'')
    assert request('frame', b'%1\r\n+k\r\n' + attribute + b'~1\r\n#f\r\n', {'X-Kind': '14'}) == (200, b'')
    assert request('decode', b'*63\r\n' + b':1\r\n' * 63, {'X-Kind': '5'})[0] == 200
    invalid = [b'_x\r\n', b'#true\r\n', b'#\r\n', b',1x\r\n', b',1e\r\n', b',1.2.3\r\n',
               b',1e2E3\r\n', b'(\r\n', b'(--1\r\n', b'(' + b'9' * 65 + b'\r\n',
               b'!2\r\na\r\n', b'=3\r\ntxt\r\n', b'=4\r\ntxt!\r\n', b'%1\r\n+k\r\n',
               b'~1\r\n', b'>1\r\n', attribute, b'|0\r\n', b'%32\r\n', b'~64\r\n',
               b'*64\r\n' + b':1\r\n' * 64, b':9223372036854775808\r\n', b'+bad\nline\r\n']
    for frame in invalid:
        assert request('decode', frame)[0] == 422, frame


class Resp3Fixture(Fixture):
    hello = b'%1\r\n$5\r\nproto\r\n:3\r\n'

    def serve(self, connection):
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                while not self.stop.is_set():
                    command = read_value(stream)
                    self.observed.append(command)
                    if command == [b'HELLO', b'3']:
                        connection.sendall(self.hello)
                        continue
                    assert command[0] == b'FIXTURE', command
                    reply = command[1]
                    mode = command[2] if len(command) > 2 else b'whole'
                    if mode == b'timeout':
                        self.stop.wait(1.3)
                    elif mode == b'fragments':
                        cut = max(1, len(reply) // 2)
                        connection.sendall(reply[:cut])
                        self.stop.wait(.04)
                        connection.sendall(reply[cut:])
                    else:
                        connection.sendall(reply)
                        if mode == b'eof':
                            return
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)


def fixture_checks(request, peer):
    pure_checks(request)
    for frame in (b'%1\r\n+k\r\n#t\r\n', b'~1\r\n:1\r\n', b'!7\r\nERR bad\r\n'):
        prefix = b'E:' if frame.startswith(b'!') else b'R:'
        assert request('execute', packet([b'FIXTURE', frame])) == (200, prefix + frame)
    push = b'>2\r\n+invalidate\r\n*1\r\n$1\r\nx\r\n'
    for leading in (b'', b'|1\r\n+meta\r\n:1\r\n'):
        assert request('next', packet([b'FIXTURE', leading + push + b'+OK\r\n'])) == (
            200, b'P:' + leading + push + b'R:+OK\r\n')
    assert request('execute', packet([b'FIXTURE', b'%1\r\n+k\r\n#f\r\n', b'fragments']))[0] == 200
    for frame in (b'#bad\r\n', b'%1\r\n+x\r\n', b'$8192\r\n'):
        assert request('execute', packet([b'FIXTURE', frame, b'eof']))[0] == 502
    assert request('execute', packet([b'FIXTURE', b'', b'timeout']))[0] == 502
    assert request('execute', b'*0\r\n')[0] == 502
    valid_hello = [b'%1\r\n+proto\r\n:3\r\n',
                   b'%2\r\n+other\r\n*2\r\n+proto\r\n:2\r\n+proto\r\n:3\r\n',
                   b'|1\r\n+meta\r\n:7\r\n%1\r\n+proto\r\n:3\r\n',
                   b'%1\r\n|1\r\n+tag\r\n:4\r\n+proto\r\n:3\r\n']
    for reply in valid_hello:
        peer.hello = reply
        assert request('hello') == (200, b'R:' + reply), reply
    for reply in (b'%0\r\n', b'%1\r\n+proto\r\n:2\r\n',
                  b'%1\r\n+proto\r\n$1\r\n3\r\n',
                  b'%1\r\n+nested\r\n%1\r\n+proto\r\n:3\r\n',
                  b'%2\r\n+proto\r\n:3\r\n+proto\r\n:3\r\n', b'+OK\r\n'):
        peer.hello = reply
        assert request('hello')[0] == 502, reply


def real_checks(request, command):
    pure_checks(request)
    status, body = request('hello')
    assert status == 200 and body.startswith(b'R:%') and b'$5\r\nproto\r\n:3\r\n' in body
    assert command(b'HSET', b'resp3-hash', b'field', b'value') in (0, 1)
    assert request('execute', packet([b'HGETALL', b'resp3-hash']), {'X-Hello': 'yes'}) == (
        200, b'R:%1\r\n$5\r\nfield\r\n$5\r\nvalue\r\n')
    assert request('execute', packet([b'GET', b'resp3-missing']), {'X-Hello': 'yes'}) == (200, b'R:_\r\n')
    assert command(b'SADD', b'resp3-set', b'one') in (0, 1)
    assert request('execute', packet([b'SMEMBERS', b'resp3-set']), {'X-Hello': 'yes'}) == (200, b'R:~1\r\n$3\r\none\r\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--real-redis', action='store_true')
    args = parser.parse_args()
    def policy(port):
        value = dict(address='127.0.0.1', port=port)
        if args.tls:
            value.update(tls=True, caFile=str(Path(args.testdata) / 'localhost_cert.pem'), serverName='localhost')
        return value
    def run(port, check):
        with gateway(args, policy(port), lambda real: PROGRAM,
                     ('resp3.rut', 'redis-resp3.rut'), 'redis-resp3.rut') as request:
            check(request)
    if args.real_redis:
        with real_redis(args) as (port, command):
            run(port, lambda request: real_checks(request, command))
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                                    str(Path(args.testdata) / 'localhost_key.pem'))
        peer = Resp3Fixture(context)
        try:
            run(peer.port, lambda request: fixture_checks(request, peer))
        finally:
            peer.close()
    print(f'Redis RESP3 passed ({args.backend}, O{args.opt}, tls={args.tls}, real={args.real_redis})')


if __name__ == '__main__':
    main()
