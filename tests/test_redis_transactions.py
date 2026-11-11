#!/usr/bin/env python3
"""MULTI acknowledgement gate, queue errors, EXEC outcomes and watch conflicts."""
import argparse
from pathlib import Path
import ssl
import time

from test_redis_commands import Fixture, assert_ack_boundary, gateway, packet, read_value, real_redis


PROGRAM = r'''import "redis-transaction.rut"
func txStatus(_ result: RedisTransactionResult) -> i32 {
    match result {
        .executed(bytes) => 200
        .watchAborted => 412
        .queueError(detail) => 409
        .serverError(detail) => 403
        .requestFailure => 413
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        .replyFailure => 502
    }
}
func txBody(_ result: RedisTransactionResult) -> Bytes {
    match result {
        .executed(bytes) => bytes
        .queueError(detail) => detail
        .serverError(detail) => detail
        _ => b""
    }
}
func watchReady(_ result: RedisWatchResult) -> bool {
    match result {
        .ok => true
        _ => false
    }
}
func txWatch(_ connection: TcpConnection, _ key: Bytes) -> bool {
    if key.count > 0 {
        let result = redisWatch(connection, key)
        watchReady(result)
    } else { true }
}
route POST "/execute" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let watching = txWatch(connection, Bytes(req.header("X-Watch").or("")))
    guard watching else { return 500 }
    let batch = RedisTransaction(request: req.bodyBytes, count: parseInt(req.header("X-Count").or("2")).or(-1))
    let result = redisTransactionExecute(connection, batch)
    let closed = connection.close()
    let status = txStatus(result)
    let body = txBody(result)
    guard status != 413 else { return 413 }
    guard status != 412 else { return 412 }
    guard status != 403 else { return 403 }
    guard status != 409 else { return 409 }
    guard status != 504 else { return 504 }
    guard status != 502 else { return 502 }
    return response(200, body: body)
}
route POST "/parse" {
    let result = redisTransactionParse(req.bodyBytes, parseInt(req.header("X-Count").or("2")).or(-1))
    let status = txStatus(result)
    let body = txBody(result)
    guard status != 412 else { return 412 }
    guard status != 409 else { return 409 }
    guard status == 200 else { return 502 }
    return response(200, body: body)
}
route POST "/build" {
    guard let batch = redisTransactionAdd(redisTransaction(), req.bodyBytes) else { return 413 }
    guard let twice = redisTransactionAdd(batch, req.bodyBytes) else { return 413 }
    guard batch.count == 1 && twice.count == 2 else { return 500 }
    let body = twice.request
    return response(200, body: body)
}
route POST "/unwatch" {
    let key = req.bodyBytes
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let watching = redisWatch(connection, key)
    let clearing = redisUnwatch(connection)
    let closed = connection.close()
    guard watchReady(watching) && watchReady(clearing) && closed else { return 500 }
    return 204
}
route POST "/discard" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let beginning = redisTransactionBegin(connection)
    let clearing = redisDiscard(connection)
    let closed = connection.close()
    guard txStatus(beginning) == 200 && watchReady(clearing) && closed else { return 500 }
    return 204
}
route POST "/conflict" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let watching = redisWatch(connection, b"tx-conflict")
    guard watchReady(watching) else { return 500 }
    let sending = connection.send(b"*3\r\n$3\r\nSET\r\n$11\r\ntx-conflict\r\n$7\r\nchanged\r\n", 1000)
    guard let sent = sending else { return 500 }
    let reading = connection.readLine(64, 1000)
    guard let changed = reading else { return 500 }
    let result = redisTransactionExecute(connection,
        RedisTransaction(request: b"*1\r\n$4\r\nPING\r\n", count: 1))
    let closed = connection.close()
    guard changed == b"+OK\r\n" && txStatus(result) == 412 && closed else { return 500 }
    return 204
}
route POST "/valid" {
    let batch = RedisTransaction(request: req.bodyBytes, count: parseInt(req.header("X-Count").or("1")).or(-1))
    guard redisTransactionValid(batch) else { return 413 }
    return 204
}
route POST "/poison" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisTransactionExecute(connection, RedisTransaction(request: req.bodyBytes, count: 2))
    let status = txStatus(result)
    guard status == 502 || status == 504 else { return 500 }
    let stale = connection.send(b"ILLEGAL", 1000)
    guard stale == nil && netError() == -4 else { return 500 }
    return 204
}
'''


class TransactionFixture(Fixture):
    def serve(self, connection):
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                queued, watch, multi, acknowledgements = [], b'', False, b''
                while not self.stop.is_set():
                    command = read_value(stream)
                    self.observed.append(command)
                    if command[0] == b'WATCH':
                        watch = command[1]
                        connection.sendall(b'+OK\r\n')
                    elif command[0] == b'UNWATCH':
                        watch = b''
                        connection.sendall(b'+OK\r\n')
                    elif command[0] == b'MULTI':
                        # If a client pipelines business writes before this
                        # acknowledgement, they are visible here on the socket.
                        assert_ack_boundary(connection, stream, 'business bytes preceded MULTI acknowledgement')
                        if watch == b'begin-error':
                            connection.sendall(b'-NOPERM no multi\r\n')
                        elif watch == b'begin-wrong':
                            connection.sendall(b':1\r\n')
                        else:
                            multi = True
                            connection.sendall(b'+OK\r\n')
                    elif command[0] == b'DISCARD':
                        assert multi
                        multi, queued, watch = False, [], b''
                        connection.sendall(b'+OK\r\n')
                    elif command[0] == b'EXEC':
                        assert multi and queued
                        # Gate replies on the complete batch, as a real Redis
                        # event-loop read may do. Fragment the entire reply,
                        # rather than exceeding the four-read profile by
                        # separately flushing every queue acknowledgement.
                        mode = queued[0][1] if len(queued[0]) > 1 else b''
                        if mode == b'timeout':
                            self.stop.wait(1.3)
                            continue
                        if mode == b'eof':
                            return
                        reply = b'*%d\r\n' % len(queued) + b'$4\r\na\x00\xffb\r\n' * len(queued)
                        if watch == b'conflict':
                            reply = b'*-1\r\n'
                        elif any(len(c) == 1 and c[0] == b'GET' for c in queued):
                            reply = b'-EXECABORT Transaction discarded because of previous errors.\r\n'
                        elif mode == b'runtime-error':
                            reply = b'*2\r\n-WRONGTYPE fixture\r\n+OK\r\n'
                        elif mode == b'wrong-count':
                            reply = b'*1\r\n+OK\r\n'
                        elif mode == b'truncated':
                            connection.sendall(b'*2\r\n$4\r\nab')
                            return
                        elif mode == b'extra':
                            reply += b'+EXTRA\r\n'
                        elif mode == b'malformed':
                            reply = b':abc\r\n'
                        reply = acknowledgements + reply
                        acknowledgements = b''
                        if mode == b'fragmented':
                            for chunk in (reply[:1], reply[1:5], reply[5:]):
                                connection.sendall(chunk)
                                time.sleep(.04)
                        else:
                            connection.sendall(reply)
                        multi, queued, watch = False, [], b''
                    else:
                        assert multi, 'business command arrived outside MULTI'
                        queued.append(command)
                        acknowledgements += b'-ERR wrong arguments\r\n' if command == [b'GET'] else b'+QUEUED\r\n'
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)


def pure_checks(request):
    batch = packet([b'GET', b'x']) * 2
    assert request('build', packet([b'GET', b'x'])) == (200, batch)
    assert request('valid', packet([b'GET', b'x' * 8170]))[0] == 413
    assert request('valid', packet([b'GET', b'x']) * 8, {'X-Count': '8'})[0] == 204
    for name in (b'MULTI', b'EXEC', b'DISCARD', b'WATCH', b'UNWATCH', b'RESET', b'QUIT',
                 b'HELLO', b'AUTH', b'SELECT', b'SUBSCRIBE', b'CLIENT', b'multi', b'MuLtI'):
        assert request('build', packet([name]))[0] == 413
    queued = b'+QUEUED\r\n' * 2
    for result in (b'*2\r\n:1\r\n$0\r\n\r\n', b'*2\r\n-ERR nested\r\n*0\r\n'):
        assert request('parse', queued + result) == (200, result)
    assert request('parse', queued + b'*-1\r\n')[0] == 412
    for error in (b'ERR failed', b''):
        actual = request('parse', b'-' + error + b'\r\n+QUEUED\r\n-EXECABORT bad\r\n')
        assert actual[0] == 409, (error, actual)
    for frame in (queued + b'*1\r\n:1\r\n', queued + b'*2\r\n:1\r\n',
                  queued + b'$-1\r\n', queued + b'-OTHER error\r\n',
                  queued + b'*2\r\n:1\r\n:2\r\n+EXTRA\r\n',
                  b'+OK\r\n+QUEUED\r\n*2\r\n:1\r\n:2\r\n',
                  b'-ERR queue\r\n+QUEUED\r\n*2\r\n:1\r\n:2\r\n'):
        assert request('parse', frame)[0] == 502, frame
    for count in ('0', '-1', '9', '2147483647'):
        assert request('parse', queued + b'*-1\r\n', {'X-Count': count})[0] == 502


def fixture_checks(request, peer):
    pure_checks(request)
    batch = packet([b'GET', b'value']) * 2
    assert request('execute', batch) == (200, b'*2\r\n$4\r\na\x00\xffb\r\n$4\r\na\x00\xffb\r\n')
    assert request('execute', batch, {'X-Watch': 'conflict'})[0] == 412
    assert request('execute', packet([b'GET']) + packet([b'SET', b'x', b'y']))[0] == 409
    assert request('execute', packet([b'GET', b'runtime-error']) * 2) == (200, b'*2\r\n-WRONGTYPE fixture\r\n+OK\r\n')
    assert request('execute', packet([b'GET', b'fragmented']) * 2)[0] == 200
    assert request('unwatch', b'x')[0] == 204
    assert request('discard')[0] == 204
    for mode in ('begin-error', 'begin-wrong'):
        before = len(peer.observed)
        assert request('execute', batch, {'X-Watch': mode})[0] == (403 if mode == 'begin-error' else 502)
        assert peer.observed[before:] == [[b'WATCH', mode.encode()], [b'MULTI']]
    for mode in ('wrong-count', 'truncated', 'extra', 'malformed', 'eof', 'timeout'):
        command = packet([b'GET', mode.encode()])
        assert request('execute', command * 2)[0] == (504 if mode == 'timeout' else 502), mode
        assert peer.observed.count([b'GET', mode.encode()]) == 2, 'transaction was replayed'
    assert request('poison', packet([b'GET', b'truncated']) * 2)[0] == 204
    before = len(peer.observed)
    for body, count in ((batch, 1), (batch, 3), (b'', 0), (packet([b'RESET']), 1),
                        (packet([b'MULTI']), 1), (packet([b'GET', b'x']) * 9, 9)):
        actual = request('execute', body, {'X-Count': str(count)})
        assert actual[0] == 413, (len(body), count, actual)
    assert len(peer.observed) == before, 'invalid batch sent bytes'
    assert request('execute', packet([b'GET', b'x']) * 8, {'X-Count': '8'})[0] == 200


def real_checks(request, command):
    pure_checks(request)
    assert command(b'DEL', b'tx-key') in (0, 1)
    batch = packet([b'SET', b'tx-key', b'a\x00\xffb']) + packet([b'GET', b'tx-key'])
    assert request('execute', batch) == (200, b'*2\r\n+OK\r\n$4\r\na\x00\xffb\r\n')
    assert request('execute', packet([b'GET']) + packet([b'SET', b'tx-key', b'must-not-write']))[0] == 409
    assert command(b'GET', b'tx-key') == b'a\x00\xffb'
    mixed = packet([b'LPUSH', b'tx-key', b'x']) + packet([b'SET', b'tx-after-error', b'yes'])
    status, body = request('execute', mixed)
    assert status == 200 and b'-WRONGTYPE ' in body and body.endswith(b'+OK\r\n')
    assert command(b'GET', b'tx-after-error') == b'yes', 'runtime errors must not imply rollback'
    assert request('execute', batch, {'X-Watch': 'tx-key'})[0] == 200
    assert request('unwatch', b'tx-key')[0] == 204
    assert request('discard')[0] == 204
    assert request('conflict')[0] == 204
    assert request('execute', packet([b'PING']) * 8, {'X-Count': '8'}) == (200, b'*8\r\n' + b'+PONG\r\n' * 8)


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
        result = dict(address='127.0.0.1', port=port, poolIdleMs=5000)
        if args.tls:
            result.update(tls=True, caFile=str(Path(args.testdata) / 'localhost_cert.pem'), serverName='localhost')
        return result
    def run(port, check):
        with gateway(args, policy(port), lambda real: PROGRAM,
                     ('redis-transaction.rut',), 'redis-transaction.rut') as request:
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
        peer = TransactionFixture(context)
        try:
            run(peer.port, lambda request: fixture_checks(request, peer))
        finally:
            peer.close()
    print(f'Redis transactions passed ({args.backend}, O{args.opt}, tls={args.tls}, real={args.real_redis})')


if __name__ == '__main__':
    main()
