#!/usr/bin/env python3
"""Typed SET GET outcomes, independent RESP2 wire peer and pinned real Redis."""
import argparse
from pathlib import Path
import ssl
import time

from test_redis_commands import Fixture, gateway, packet, read_value, real_redis


class SetGetFixture(Fixture):
    def serve(self, connection):
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                while not self.stop.is_set():
                    command = read_value(stream)
                    self.observed.append(command)
                    if command == [b'GET', b'stable']:
                        connection.sendall(b'$4\r\na\x00\xffb\r\n')
                    elif command[0] == b'SET' and b'GET' in command[3:]:
                        key = command[1]
                        if key == b'get-timeout':
                            self.stop.wait(1.3)
                            continue
                        if key == b'get-eof':
                            return
                        if key == b'get-truncated':
                            connection.sendall(b'$4\r\nab')
                            return
                        replies = {
                            b'get-old': b'$7\r\nold\x00\xff\r\n\r\n', b'get-empty': b'$0\r\n\r\n',
                            b'get-missing': b'$-1\r\n', b'get-error': b'-WRONGTYPE fixture\r\n',
                            b'get-ok': b'+OK\r\n', b'get-integer': b':1\r\n', b'get-array': b'*0\r\n',
                            b'get-extra': b'$1\r\nx\r\n+EXTRA\r\n',
                            b'get-max': b'$8183\r\n' + b'x' * 8183 + b'\r\n',
                            b'get-too-large': b'$8184\r\n' + b'x' * 8184 + b'\r\n',
                        }
                        if key == b'get-fragments':
                            for chunk in (b'$4\r', b'\nz\x00', b'\xffb\r\n'):
                                connection.sendall(chunk)
                                time.sleep(.04)
                        else:
                            connection.sendall(replies[key])
                    else:
                        raise AssertionError(command)
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)


PROGRAM = r'''import "redis-client.rut"
func condition(_ name: str) -> RedisSetCondition {
    match name { "NX" => RedisSetCondition.absent
        "XX" => RedisSetCondition.present _ => RedisSetCondition.always }
}
func expiry(_ name: str, _ amount: i32) -> RedisSetExpiry {
    match name { "EX" => RedisSetExpiry.seconds(amount)
        "PX" => RedisSetExpiry.milliseconds(amount)
        "KEEPTTL" => RedisSetExpiry.keepTtl _ => RedisSetExpiry.none }
}
func requestKey(_ duplicate: bool, _ body: Bytes, _ fallback: Bytes) -> Bytes {
    if duplicate { body } else { fallback }
}
func setGetStatus(_ result: RedisSetGetResult) -> i32 {
    match result {
        .requestFailure => 413
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        .replyFailure => 502
        _ => 200
    }
}
func setGetPrefix(_ result: RedisSetGetResult) -> Bytes {
    match result {
        .stored(previous) => if previous.found { b"S1:" } else { b"S0:" }
        .notStored(previous) => if previous.found { b"N1:" } else { b"N0:" }
        .serverError(data) => b"E:"
        _ => b""
    }
}
func setGetData(_ result: RedisSetGetResult) -> Bytes {
    match result {
        .stored(previous) => previous.data
        .notStored(previous) => previous.data
        .serverError(data) => data
        _ => b""
    }
}
route POST "/set-get" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisSetGet(connection, requestKey(req.header("X-Duplicate").or("") == "yes", req.bodyBytes,
        Bytes(req.header("X-Key").or("get-options"))), req.bodyBytes,
        condition(req.header("X-Condition").or("")),
        expiry(req.header("X-Expiry").or(""), parseInt(req.header("X-Amount").or("0")).or(0)))
    // The returned Bytes must survive another receive and connection close.
    let readback = redisGet(connection, b"stable")
    let closed = connection.close()
    let status = setGetStatus(result)
    guard status != 502 || !closed else { return 500 }
    guard status != 502 else { return 502 }
    guard status != 504 else { return 504 }
    guard status != 413 else { return 413 }
    guard closed else { return 500 }
    // S/N encode stored/notStored; 1/0 distinguish an old string from missing.
    guard let data = concatBytes(setGetPrefix(result), setGetData(result), 8192) else { return 500 }
    return response(200, body: data)
}
route POST "/build-get" {
    guard let value = resp2SetGetRequest(requestKey(req.header("X-Duplicate").or("") == "yes", req.bodyBytes,
        Bytes(req.header("X-Key").or("options"))), req.bodyBytes,
        condition(req.header("X-Condition").or("")),
        expiry(req.header("X-Expiry").or(""), parseInt(req.header("X-Amount").or("0")).or(0))) else { return 413 }
    return response(200, body: value)
}
'''


def oracle_checks(request, peer):
    for condition in ('', 'NX', 'XX'):
        for key, previous in (('get-old', b'old\x00\xff\r\n'), ('get-empty', b''), ('get-missing', None)):
            stored = condition != ('XX' if previous is None else 'NX')
            prefix = (b'S' if stored else b'N') + (b'0:' if previous is None else b'1:')
            assert request('set-get', b'new\x00\xff', {'X-Key': key, 'X-Condition': condition}) == (
                200, prefix + (previous if previous is not None else b''))
    assert request('set-get', b'value', {'X-Key': 'get-fragments'}) == (200, b'S1:z\x00\xffb')
    assert request('set-get', b'value', {'X-Key': 'get-max'}) == (200, b'S1:' + b'x' * 8183)
    assert request('set-get', b'value', {'X-Key': 'get-error'}) == (200, b'E:WRONGTYPE fixture')
    for key in ('get-ok', 'get-integer', 'get-array', 'get-extra', 'get-too-large',
                'get-truncated', 'get-eof', 'get-timeout'):
        assert request('set-get', b'value', {'X-Key': key})[0] == (504 if key == 'get-timeout' else 502)
        assert sum(command[0] == b'SET' and command[1] == key.encode() for command in peer.observed) == 1


def builder_checks(request):
    for condition in ('', 'NX', 'XX'):
        for expiry in ('', 'EX', 'PX', 'KEEPTTL'):
            headers = {'X-Key': 'options', 'X-Condition': condition, 'X-Expiry': expiry, 'X-Amount': '10000'}
            arguments = [b'SET', b'options', b'a\x00\xff\r\n']
            if condition:
                arguments.append(condition.encode())
            if expiry:
                arguments.append(expiry.encode())
            if expiry in ('EX', 'PX'):
                arguments.append(b'10000')
            assert request('build-get', arguments[2], headers) == (200, packet(arguments + [b'GET']))
    for expiry in ('EX', 'PX'):
        headers = {'X-Expiry': expiry, 'X-Amount': '2147483647'}
        assert request('build-get', b'value', headers) == (
            200, packet([b'SET', b'options', b'value', expiry.encode(), b'2147483647', b'GET']))
        for amount in ('0', '-1', '-2147483648'):
            headers = {'X-Expiry': expiry, 'X-Amount': amount}
            assert request('build-get', b'value', headers)[0] == 413
            assert request('set-get', b'value', headers)[0] == 413
    for expiry, tail in (('PX', [b'PX', b'1', b'GET']), ('KEEPTTL', [b'KEEPTTL', b'GET'])):
        headers = {'X-Condition': 'NX', 'X-Expiry': expiry, 'X-Amount': '1', 'X-Duplicate': 'yes'}
        maximum = max(n for n in range(4200)
                      if len(packet([b'SET', b'x' * n, b'x' * n, b'NX'] + tail)) <= 8192)
        assert request('build-get', b'x' * maximum, headers) == (
            200, packet([b'SET', b'x' * maximum, b'x' * maximum, b'NX'] + tail))
        assert request('build-get', b'x' * (maximum + 1), headers)[0] == 413
        assert request('set-get', b'x' * (maximum + 1), headers)[0] == 413


def real_set_get_checks(request, command):
    key, value = b'get-options', b'new\x00\xff\r\n'
    for condition in ('', 'NX', 'XX'):
        for expiry in ('', 'EX', 'PX', 'KEEPTTL'):
            for initial in ('missing', 'expired', 'empty', 'binary'):
                command(b'DEL', key)
                previous = b'' if initial == 'empty' else b'old\x00\xff\r\n'
                if initial != 'missing':
                    assert command(b'SET', key, previous, b'PX', b'300000') == b'OK'
                if initial == 'expired':
                    assert command(b'PEXPIREAT', key, b'1') == 1
                if initial in ('missing', 'expired'):
                    previous = None
                deadline = command(b'PEXPIRETIME', key)
                headers = {'X-Condition': condition, 'X-Expiry': expiry, 'X-Amount': '120'}
                if expiry == 'PX':
                    headers['X-Amount'] = '120000'
                stored = condition != ('XX' if previous is None else 'NX')
                prefix = (b'S' if stored else b'N') + (b'0:' if previous is None else b'1:')
                assert request('set-get', value, headers) == (
                    200, prefix + (previous if previous is not None else b'')), (condition, expiry, initial)
                assert command(b'GET', key) == (value if stored else previous)
                if not stored or expiry == 'KEEPTTL' and previous is not None:
                    assert command(b'PEXPIRETIME', key) == deadline
                elif expiry in ('EX', 'PX'):
                    assert 0 < command(b'PTTL', key) <= 120000
                else:
                    assert command(b'PTTL', key) == -1
    for condition in ('', 'NX', 'XX'):
        for expiry in ('', 'EX', 'PX', 'KEEPTTL'):
            command(b'DEL', key)
            assert command(b'RPUSH', key, b'unchanged\x00\xff') == 1
            assert command(b'PEXPIRE', key, b'300000') == 1
            deadline = command(b'PEXPIRETIME', key)
            result = request('set-get', value, {
                'X-Condition': condition, 'X-Expiry': expiry, 'X-Amount': '120000'})
            assert result[0] == 200 and result[1].startswith(b'E:WRONGTYPE'), result
            assert command(b'LRANGE', key, b'0', b'-1') == [b'unchanged\x00\xff']
            assert command(b'PEXPIRETIME', key) == deadline
    assert command(b'DEL', key) == 1
    key = value
    assert command(b'SET', key, b'previous\x00\xff', b'PX', b'300000') == b'OK'
    deadline = command(b'PEXPIRETIME', key)
    assert request('set-get', value, {'X-Duplicate': 'yes', 'X-Expiry': 'KEEPTTL'}) == (200, b'S1:previous\x00\xff')
    assert command(b'GET', key) == value and command(b'PEXPIRETIME', key) == deadline
    assert command(b'DEL', key) == 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--real-redis', action='store_true')
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--testdata')
    args = parser.parse_args()
    if args.tls and not args.testdata:
        parser.error('--tls requires --testdata')
    def policy(port):
        endpoint = dict(address='127.0.0.1', port=port, poolIdleMs=5000)
        if args.tls:
            endpoint.update(tls=True, caFile=str(Path(args.testdata).resolve() / 'localhost_cert.pem'),
                            serverName='localhost')
        return endpoint
    if args.real_redis:
        with real_redis(args) as (port, command):
            with gateway(args, policy(port), program_factory=lambda _: PROGRAM) as request:
                builder_checks(request)
                real_set_get_checks(request, command)
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                                    str(Path(args.testdata) / 'localhost_key.pem'))
        peer = SetGetFixture(context)
        try:
            with gateway(args, policy(peer.port), program_factory=lambda _: PROGRAM) as request:
                builder_checks(request)
                oracle_checks(request, peer)
        finally:
            peer.close()
    print(f'PASS Redis SET GET {args.backend} O{args.opt} TLS={args.tls}; ' + ('Redis 7.2.11' if args.real_redis else 'wire oracle'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
