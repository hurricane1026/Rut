#!/usr/bin/env python3
"""Dedicated finite subscriptions, coalesced messages and unsubscribe races."""
import argparse
from pathlib import Path
import ssl
import threading
import time

from test_redis_commands import Fixture, gateway, packet, read_value, real_redis


PROGRAM = r'''import "redis-pubsub.rut"
func subPayload(_ result: RedisPubSubResult) -> Bytes {
    match result {
        .message(frame) => redisPubSubData(frame)
        _ => nil
    }
}
func subOutput(_ result: RedisPubSubResult, _ origin: bool) -> Bytes {
    match result {
        .message(frame) => if origin { redisPubSubOrigin(frame) } else { redisPubSubData(frame) }
        _ => nil
    }
}
func subEnded(_ result: RedisPubSubResult) -> bool {
    match result {
        .unsubscribed => true
        _ => false
    }
}
func subFailed(_ result: RedisPubSubResult) -> bool {
    match result {
        .replyFailure => true
        .transportFailure(code) => true
        .serverError(data) => true
        _ => false
    }
}
func subFinish(_ connection: TcpConnection, _ state: RedisSubscription, _ result: RedisPubSubResult) -> RedisPubSubResult {
    match result {
        .message(frame) => redisSubscriptionNext(connection, state, frame.rest)
        _ => result
    }
}
func subSetupReply(_ state: RedisSubscription) -> Bytes {
    if state.channel == b"quiet" {
        if state.mode == 2 { b"\x2a\x33\x0d\x0a\x24\x31\x30\x0d\x0a\x70\x73\x75\x62\x73\x63\x72\x69\x62\x65\x0d\x0a\x24\x35\x0d\x0a\x71\x75\x69\x65\x74\x0d\x0a\x3a\x31\x0d\x0a" } else {
            if state.mode == 3 { b"\x2a\x33\x0d\x0a\x24\x31\x30\x0d\x0a\x73\x73\x75\x62\x73\x63\x72\x69\x62\x65\x0d\x0a\x24\x35\x0d\x0a\x71\x75\x69\x65\x74\x0d\x0a\x3a\x31\x0d\x0a" } else { b"\x2a\x33\x0d\x0a\x24\x39\x0d\x0a\x73\x75\x62\x73\x63\x72\x69\x62\x65\x0d\x0a\x24\x35\x0d\x0a\x71\x75\x69\x65\x74\x0d\x0a\x3a\x31\x0d\x0a" }
        }
    } else {
        if state.mode == 2 { b"\x2a\x33\x0d\x0a\x24\x31\x30\x0d\x0a\x70\x73\x75\x62\x73\x63\x72\x69\x62\x65\x0d\x0a\x24\x31\x0d\x0a\x78\x0d\x0a\x3a\x31\x0d\x0a\x2a\x34\x0d\x0a\x24\x38\x0d\x0a\x70\x6d\x65\x73\x73\x61\x67\x65\x0d\x0a\x24\x31\x0d\x0a\x78\x0d\x0a\x24\x31\x34\x0d\x0a\x61\x63\x74\x75\x61\x6c\x2d\x63\x68\x61\x6e\x6e\x65\x6c\x0d\x0a\x24\x36\x0d\x0a\x61\x00\xff\x0d\x0a\x62\x0d\x0a" } else {
            if state.mode == 3 { b"\x2a\x33\x0d\x0a\x24\x31\x30\x0d\x0a\x73\x73\x75\x62\x73\x63\x72\x69\x62\x65\x0d\x0a\x24\x31\x0d\x0a\x78\x0d\x0a\x3a\x31\x0d\x0a\x2a\x33\x0d\x0a\x24\x38\x0d\x0a\x73\x6d\x65\x73\x73\x61\x67\x65\x0d\x0a\x24\x31\x0d\x0a\x78\x0d\x0a\x24\x36\x0d\x0a\x61\x00\xff\x0d\x0a\x62\x0d\x0a" } else { b"\x2a\x33\x0d\x0a\x24\x39\x0d\x0a\x73\x75\x62\x73\x63\x72\x69\x62\x65\x0d\x0a\x24\x31\x0d\x0a\x78\x0d\x0a\x3a\x31\x0d\x0a\x2a\x33\x0d\x0a\x24\x37\x0d\x0a\x6d\x65\x73\x73\x61\x67\x65\x0d\x0a\x24\x31\x0d\x0a\x78\x0d\x0a\x24\x36\x0d\x0a\x61\x00\xff\x0d\x0a\x62\x0d\x0a" }
        }
    }
}
route POST "/one" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let state = RedisSubscription(channel: req.bodyBytes, mode: parseInt(req.header("X-Mode").or("1")).or(0), closing: false)
    let result = redisSubscribeOnce(connection, state)
    let stale = connection.send(b"ILLEGAL", 1000)
    guard stale == nil && netError() == -4 else { return 500 }
    guard let body = subPayload(result) else { return 500 }
    return response(200, body: body)
}
route POST "/cancel" {
    let state = RedisSubscription(channel: req.bodyBytes, mode: parseInt(req.header("X-Mode").or("1")).or(0), closing: false)
    guard let expected = subSetupReply(state) else { return 400 }
    guard let request = resp2KeyRequest(redisPubSubName(state.mode, false), state.channel) else { return 400 }
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let sending = connection.send(request, 1000)
    guard let sent = sending else { return 502 }
    let reading = connection.readExactly(expected.count, 1000)
    guard let setup = reading else { return 502 }
    guard setup == expected else { return 500 }
    let result = redisUnsubscribe(connection, state, b"")
    let closing = RedisSubscription(channel: req.bodyBytes, mode: state.mode, closing: true)
    let ended = subFinish(connection, closing, result)
    guard subEnded(ended) else { return 500 }
    let stale = connection.send(b"ILLEGAL", 1000)
    guard stale == nil && netError() == -4 else { return 500 }
    return 204
}
route POST "/poison" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisSubscribe(connection, RedisSubscription(channel: req.bodyBytes, mode: 1, closing: false))
    guard subFailed(result) else { return 500 }
    let stale = connection.send(b"ILLEGAL", 1000)
    guard stale == nil && netError() == -4 else { return 500 }
    return 204
}
route POST "/decode" {
    guard let frame = redisPubSubFrame(req.bodyBytes) else { return 422 }
    let state = RedisSubscription(channel: Bytes(req.header("X-Channel").or("x")),
        mode: parseInt(req.header("X-Mode").or("1")).or(0), closing: req.header("X-Closing").or("") == "yes")
    let result = redisPubSubParse(frame, state, req.header("X-Start").or("") == "yes")
    guard let body = subOutput(result, req.header("X-Origin").or("") == "yes") else { return 422 }
    return response(200, body: body)
}
'''


def acknowledgement(name, channel, count, push=False):
    return (b'>3\r\n' if push else b'*3\r\n') + packet([name, channel])[4:] + b':%d\r\n' % count


class SubscriptionFixture(Fixture):
    def serve(self, connection):
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                while not self.stop.is_set():
                    command = read_value(stream)
                    self.observed.append(command)
                    name, channel = command
                    if name.endswith(b'subscribe') and not name.endswith(b'unsubscribe'):
                        if channel == b'timeout':
                            self.stop.wait(1.3)
                            continue
                        if channel == b'eof':
                            return
                        reply = acknowledgement(name, channel, 1, channel == b'push')
                        if channel == b'wrong-channel':
                            reply = acknowledgement(name, b'other', 1)
                        elif channel == b'wrong-count':
                            reply = acknowledgement(name, channel, 2)
                        elif channel == b'wrong-type':
                            reply = b'+OK\r\n'
                        elif channel == b'server-error':
                            reply = b'-ERR denied\r\n'
                        elif channel == b'quiet':
                            pass
                        else:
                            payload = b'a\x00\xff\r\nb'
                            message = packet([b'message', channel, payload])
                            if name == b'psubscribe':
                                message = packet([b'pmessage', channel, b'actual-channel', payload])
                            elif name == b'ssubscribe':
                                message = packet([b'smessage', channel, payload])
                            reply += message
                        connection.sendall(reply)
                    elif name.endswith(b'unsubscribe'):
                        late = packet([b'message', channel, b'late'])
                        if name == b'punsubscribe':
                            late = packet([b'pmessage', channel, b'late-channel', b'late'])
                        elif name == b'sunsubscribe':
                            late = packet([b'smessage', channel, b'late'])
                        connection.sendall((b'' if channel == b'quiet' else late) + acknowledgement(name, channel, 0))
                    else:
                        raise AssertionError(command)
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)


def pure_checks(request):
    data = b'a\x00\xff'
    assert request('decode', packet([b'message', b'x', data])) == (200, data)
    assert request('decode', b'>' + packet([b'message', b'x', data])[1:]) == (200, data)
    assert request('decode', packet([b'pmessage', b'x', b'origin', data]), {'X-Mode': '2'}) == (200, data)
    assert request('decode', packet([b'pmessage', b'x', b'\x00\xfforigin', data]), {'X-Mode': '2', 'X-Origin': 'yes'}) == (200, b'\x00\xfforigin')
    assert request('decode', packet([b'smessage', b'x', data]), {'X-Mode': '3'}) == (200, data)
    for frame in (packet([b'message', b'wrong', data]), packet([b'message', b'x']),
                  packet([b'other', b'x', data]), b'*3\r\n+message\r\n$1\r\nx\r\n$1\r\na\r\n',
                  b'*3\r\n$7\r\nmessage\r\n$1\r\nx\r\n:1\r\n'):
        assert request('decode', frame)[0] == 422


def fixture_checks(request, peer):
    pure_checks(request)
    for mode in (1, 2, 3):
        assert request('one', b'x', {'X-Mode': str(mode)}) == (200, b'a\x00\xff\r\nb')
    assert request('one', b'push') == (200, b'a\x00\xff\r\nb')
    for mode in (1, 2, 3):
        assert request('cancel', b'x', {'X-Mode': str(mode)})[0] == 204
        assert request('cancel', b'quiet', {'X-Mode': str(mode)})[0] == 204
    for channel in (b'wrong-channel', b'wrong-count', b'wrong-type', b'server-error', b'eof', b'timeout'):
        assert request('poison', channel)[0] == 204, channel
        assert sum(command == [b'subscribe', channel] for command in peer.observed) == 1
    assert not any(command[0] == b'ILLEGAL' for command in peer.observed)


def real_checks(request, command):
    pure_checks(request)
    for mode in (1, 2, 3):
        assert request('cancel', b'quiet', {'X-Mode': str(mode)})[0] == 204
    # Repeated publications avoid a scheduling assumption about subscription
    # startup. Data is observed once by this finite subscriber, never replayed.
    for mode, channel, publication in ((1, b'pubsub-channel', b'PUBLISH'),
                                        (2, b'pubsub-*', b'PUBLISH'),
                                        (3, b'sharded-channel', b'SPUBLISH')):
        result = []
        worker = threading.Thread(target=lambda: result.append(request('one', channel, {'X-Mode': str(mode)})))
        worker.start()
        target = b'pubsub-actual' if mode == 2 else channel
        deadline = time.monotonic() + 5
        while worker.is_alive() and time.monotonic() < deadline:
            command(publication, target, b'a\x00\xff\r\nb')
            time.sleep(.04)
        worker.join(10)
        assert result == [(200, b'a\x00\xff\r\nb')], (mode, result)


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
        value = dict(address='127.0.0.1', port=port, poolIdleMs=5000)
        if args.tls:
            value.update(tls=True, caFile=str(Path(args.testdata) / 'localhost_cert.pem'), serverName='localhost')
        return value
    def run(port, check):
        with gateway(args, policy(port), lambda real: PROGRAM, ('redis-pubsub.rut',), 'redis-pubsub.rut') as request:
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
        peer = SubscriptionFixture(context)
        try:
            run(peer.port, lambda request: fixture_checks(request, peer))
        finally:
            peer.close()
    print(f'Redis Pub/Sub passed ({args.backend}, O{args.opt}, tls={args.tls}, real={args.real_redis})')


if __name__ == '__main__':
    main()
