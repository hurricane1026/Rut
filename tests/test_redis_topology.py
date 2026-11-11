#!/usr/bin/env python3
"""Independent CRC16 oracle, MOVED/ASK gating and Sentinel role checks."""
import argparse
import binascii
import contextlib
import json
import os
from pathlib import Path
import random
import socket
import ssl
import subprocess
import tempfile
import time
import uuid

from test_redis_commands import Fixture, REDIS_IMAGE, gateway, packet, read_value, real_redis


PROGRAM = r'''import "redis-topology.rut"
func topBody(_ result: RedisTopologyResult) -> Bytes {
    match result {
        .reply(bytes) => concatBytes(b"R:", bytes, 8192)
        .redirect(node) => concatBytes(b"D:", node.endpoint, 8192)
        .serverError(data) => concatBytes(b"E:", data, 8192)
        _ => nil
    }
}
func topFollow(_ node: RedisRedirect, _ request: Bytes, _ key: Bytes) -> RedisTopologyResult {
    guard let resolved = redisRedirectResolve(node, Bytes(env("REDIS_SEED_ADDRESS"))) else { RedisTopologyResult.replyFailure }
    guard redisRedirectNode(resolved, Bytes(env("REDIS_TARGET_NAME")), b"", b"") == 0 else { RedisTopologyResult.redirect(resolved) }
    let opening = tcp(env("REDIS_TARGET_ENDPOINT"), 1000)
    guard let connection = opening else { RedisTopologyResult.transportFailure(netError()) }
    let result = redisClusterFollow(connection, request, key, resolved)
    let closed = connection.close()
    result
}
func topMaybeFollow(_ result: RedisTopologyResult, _ request: Bytes, _ key: Bytes) -> RedisTopologyResult {
    match result {
        .redirect(node) => topFollow(node, request, key)
        _ => result
    }
}
func masterRecord(_ result: RedisSentinelResult) -> RedisMaster {
    match result {
        .master(node) => node
        _ => nil
    }
}
func masterReady(_ connection: TcpConnection, _ result: RedisTopologyResult, _ request: Bytes) -> RedisTopologyResult {
    match result {
        .reply(bytes) => redisTopologyWire(connection, request)
        _ => result
    }
}
route POST "/slot" {
    guard let slot = redisClusterSlot(req.bodyBytes) else { return 413 }
    guard let digits = formatInt(slot) else { return 500 }
    let body = Bytes(digits)
    return response(200, body: body)
}
route POST "/redirect" {
    guard let node = redisRedirect(req.bodyBytes) else { return 422 }
    guard node.slot == parseInt(req.header("X-Slot").or("0")).or(-1) else { return 500 }
    guard node.asking == (req.header("X-Asking").or("") == "yes") else { return 500 }
    guard let resolved = redisRedirectResolve(node, b"127.0.0.1") else { return 422 }
    let body = resolved.endpoint
    return response(200, body: body)
}
route POST "/execute" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let key = Bytes(req.header("X-Key").or("x"))
    let first = redisClusterExecute(connection, req.bodyBytes, key)
    let closed = connection.close()
    let result = topMaybeFollow(first, req.bodyBytes, key)
    guard let body = topBody(result) else { return 502 }
    return response(200, body: body)
}
route POST "/sentinel" {
    let opening = tcp(env("REDIS_SENTINEL_ENDPOINT"), 1000)
    guard let sentinel = opening else { return 503 }
    let discovery = redisSentinelDiscover(sentinel, b"rutmaster")
    let discarded = sentinel.close()
    guard let node = masterRecord(discovery) else { return 404 }
    guard redisMasterMatches(node, Bytes(env("REDIS_TARGET_ADDRESS")), parseInt(env("REDIS_TARGET_PORT")).or(0)) else { return 403 }
    let connecting = tcp(env("REDIS_TARGET_ENDPOINT"), 1000)
    guard let master = connecting else { return 503 }
    let verified = redisSentinelVerifyMaster(master)
    let result = masterReady(master, verified, req.bodyBytes)
    let closed = master.close()
    guard let body = topBody(result) else { return 502 }
    return response(200, body: body)
}
route POST "/recover" {
    let result = RedisTopologyResult.transportFailure(-1)
    let action = redisRecovery(result, req.header("X-Read").or("") == "yes")
    match action {
        .reconnectRead => { return 204 }
        .unknownWrite => { return 409 }
        _ => { return 500 }
    }
}
'''


def slot(key):
    start = key.find(b'{')
    if start >= 0:
        end = key.find(b'}', start + 1)
        if end > start + 1:
            key = key[start + 1:end]
    return binascii.crc_hqx(key, 0) % 16384


class TopologyFixture(Fixture):
    def __init__(self, tls_context=None, target=None, sentinel=False):
        self.target = target
        self.sentinel = sentinel
        self.discovery = None
        self.role = b'*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n'
        self.asking_ack = b'+OK\r\n'
        super().__init__(tls_context)

    def serve(self, connection):
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                asking = False
                while not self.stop.is_set():
                    command = read_value(stream)
                    self.observed.append(command)
                    name = command[0]
                    if name == b'ASKING':
                        import select
                        if isinstance(connection, ssl.SSLSocket):
                            assert not connection.pending(), 'business preceded ASKING acknowledgement'
                        else:
                            assert not select.select([connection], [], [], .01)[0], 'business preceded ASKING acknowledgement'
                        asking = True
                        connection.sendall(self.asking_ack)
                    elif name == b'SENTINEL':
                        assert command == [b'SENTINEL', b'get-master-addr-by-name', b'rutmaster']
                        connection.sendall(self.discovery if self.discovery is not None else packet([b'127.0.0.1', str(self.target).encode()]))
                    elif name == b'ROLE':
                        connection.sendall(self.role)
                    elif name in (b'GET', b'SET'):
                        key = command[1]
                        if self.target is not None and not self.sentinel:
                            if key == b'unknown':
                                connection.sendall(b'-MOVED %d 127.0.0.1:1\r\n' % slot(key))
                            elif key == b'wrong-slot':
                                connection.sendall(b'-MOVED %d 127.0.0.1:%d\r\n' % ((slot(key) + 1) % 16384, self.target))
                            elif key == b'eof':
                                return
                            else:
                                kind = b'ASK' if key == b'ask' else b'MOVED'
                                connection.sendall(b'-' + kind + b' %d 127.0.0.1:%d\r\n' % (slot(key), self.target))
                        else:
                            assert key != b'ask' or asking, 'ASKING must precede the redirected business command'
                            asking = False
                            connection.sendall(b'$4\r\na\x00\xffb\r\n' if name == b'GET' else b'+OK\r\n')
                    else:
                        raise AssertionError(command)
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)


def pure_checks(request):
    keys = [b'', b'123456789', b'foo', b'bar', b'{user1000}.following', b'{user1000}.followers',
            b'foo{}{bar}', b'foo{{bar}}zap', b'foo{bar}{zap}', b'\x00\xff', bytes(range(256)),
            b'A' * 256, b'\xff' * 256]
    rng = random.Random(1042)
    keys += [rng.randbytes(size) for size in (1, 63, 64, 65, 127, 128, 129, 255, 256)]
    for key in keys:
        assert request('slot', key) == (200, str(slot(key)).encode()), key
    assert request('slot', b'x' * 257)[0] == 413
    assert request('slot', b'x' * 1000 + b'{short}') == (200, str(slot(b'short')).encode())
    for name, asking in ((b'MOVED', False), (b'ASK', True)):
        for number in (0, 16383):
            headers = {'X-Slot': str(number), 'X-Asking': 'yes' if asking else ''}
            for endpoint, expected in ((b'127.0.0.1:6379', b'127.0.0.1:6379'), (b':6380', b'127.0.0.1:6380')):
                assert request('redirect', name + b' %d ' % number + endpoint, headers) == (200, expected)
    for data in (b'MOVED -1 127.0.0.1:1', b'ASK +1 127.0.0.1:1', b'MOVED 16384 127.0.0.1:1',
                 b'MOVED 0 ', b'MOVED 0 host:0', b'MOVED 0 host:65536', b'MOVED 0 host:+1',
                 b'MOVED 0 host:1 extra', b'MOVED 0 host:1\r\n', b'ASK 0 host:1\x00', b'ERR other'):
        assert request('redirect', data)[0] == 422, data
    assert request('recover')[0] == 409
    assert request('recover', headers={'X-Read': 'yes'})[0] == 204


@contextlib.contextmanager
def configured_gateway(args, seed, target, sentinel, target_address='127.0.0.1', seed_address='127.0.0.1'):
    def policy(address, port):
        value = dict(address=address, port=port)
        if args.tls:
            value.update(tls=True, caFile=str(Path(args.testdata) / 'localhost_cert.pem'), serverName='localhost')
        return value
    saved = {name: os.environ.get(name) for name in ('REDIS_TARGET_NAME', 'REDIS_TARGET_ADDRESS',
             'REDIS_TARGET_PORT', 'REDIS_TARGET_ENDPOINT', 'REDIS_SENTINEL_ENDPOINT', 'REDIS_SEED_ADDRESS')}
    os.environ.update(REDIS_SEED_ADDRESS=seed_address, REDIS_TARGET_NAME=f'{target_address}:{target}', REDIS_TARGET_ADDRESS=target_address,
                      REDIS_TARGET_PORT=str(target), REDIS_TARGET_ENDPOINT=json.dumps(policy(target_address, target)),
                      REDIS_SENTINEL_ENDPOINT=json.dumps(policy('127.0.0.1', sentinel)))
    try:
        with gateway(args, policy(seed_address, seed), lambda real: PROGRAM,
                     ('redis-topology.rut',), 'redis-topology.rut') as request:
            yield request
    finally:
        for name, previous in saved.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous


@contextlib.contextmanager
def real_sentinel(args, master_port):
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    name = 'rut-sentinel-' + uuid.uuid4().hex
    config = f'bind 127.0.0.1\nport {port}\nprotected-mode no\ndir /tmp\nsentinel monitor rutmaster 127.0.0.1 {master_port} 1\nsentinel down-after-milliseconds rutmaster 5000\n'
    if args.tls:
        config = config.replace(f'port {port}\n', f'port 0\ntls-port {port}\n', 1)
        config += 'tls-auth-clients no\ntls-replication yes\ntls-cert-file /tmp/localhost_cert.pem\ntls-key-file /tmp/localhost_key.pem\ntls-ca-cert-file /tmp/localhost_cert.pem\n'
    try:
        # Host networking lets this isolated test daemon monitor the master's
        # existing loopback-only published port. Only our own container is removed.
        subprocess.run(['docker', 'create', '--name', name, '--network', 'host', '--user', '0',
                        '--entrypoint', 'redis-server', REDIS_IMAGE, '/tmp/sentinel.conf', '--sentinel'],
                       check=True, capture_output=True)
        with tempfile.TemporaryDirectory(prefix='rut-sentinel-') as directory:
            path = Path(directory) / 'sentinel.conf'
            path.write_text(config)
            subprocess.run(['docker', 'cp', str(path), name + ':/tmp/sentinel.conf'], check=True, capture_output=True)
        if args.tls:
            for filename in ('localhost_cert.pem', 'localhost_key.pem'):
                subprocess.run(['docker', 'cp', str(Path(args.testdata) / filename), name + ':/tmp/' + filename], check=True, capture_output=True)
        subprocess.run(['docker', 'start', name], check=True, capture_output=True)
        context = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem')) if args.tls else None
        for _ in range(200):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2) as connection:
                    if context:
                        connection = context.wrap_socket(connection, server_hostname='localhost')
                    with connection, connection.makefile('rb') as stream:
                        connection.sendall(packet([b'SENTINEL', b'get-master-addr-by-name', b'rutmaster']))
                        assert read_value(stream) == [b'127.0.0.1', str(master_port).encode()]
                break
            except OSError:
                time.sleep(.025)
        else:
            raise AssertionError(subprocess.check_output(['docker', 'logs', name], stderr=subprocess.STDOUT))
        yield port
    finally:
        subprocess.run(['docker', 'rm', '-fv', name], check=False, capture_output=True)


@contextlib.contextmanager
def real_cluster(args):
    run = uuid.uuid4().hex
    network = 'rut-redis-cluster-' + run
    names = []
    addresses = []
    context = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem')) if args.tls else None
    def command(index, *arguments):
        with socket.create_connection((addresses[index], 6379), timeout=2) as connection:
            if context:
                connection = context.wrap_socket(connection, server_hostname='localhost')
            with connection, connection.makefile('rb') as stream:
                connection.sendall(packet(list(arguments)))
                return read_value(stream)
    try:
        subprocess.run(['docker', 'network', 'create', '--internal', '--label',
                        'rut.test.suite=redis-topology', network], check=True, capture_output=True)
        for index in range(3):
            name = network + '-' + str(index)
            names.append(name)
            settings = ['--bind', '0.0.0.0', '--protected-mode', 'no', '--save', '',
                        '--appendonly', 'no', '--maxmemory', '32mb', '--cluster-enabled', 'yes',
                        '--cluster-config-file', '/tmp/nodes.conf', '--cluster-node-timeout', '1000']
            if args.tls:
                settings += ['--port', '0', '--tls-port', '6379', '--tls-cluster', 'yes',
                             '--tls-replication', 'yes', '--tls-auth-clients', 'no',
                             '--tls-cert-file', '/tmp/localhost_cert.pem', '--tls-key-file', '/tmp/localhost_key.pem',
                             '--tls-ca-cert-file', '/tmp/localhost_cert.pem']
            subprocess.run(['docker', 'create', '--name', name, '--network', network, '--label',
                            'rut.test.suite=redis-topology', REDIS_IMAGE, 'redis-server', *settings],
                           check=True, capture_output=True)
            if args.tls:
                for filename in ('localhost_cert.pem', 'localhost_key.pem'):
                    subprocess.run(['docker', 'cp', str(Path(args.testdata) / filename),
                                    name + ':/tmp/' + filename], check=True, capture_output=True)
            subprocess.run(['docker', 'start', name], check=True, capture_output=True)
            info = json.loads(subprocess.check_output(['docker', 'inspect', name]))[0]
            addresses.append(info['NetworkSettings']['Networks'][network]['IPAddress'])
            for _ in range(200):
                try:
                    assert command(index, b'PING') == b'PONG'
                    break
                except OSError:
                    time.sleep(.025)
            else:
                raise AssertionError(subprocess.check_output(['docker', 'logs', name], stderr=subprocess.STDOUT))
        for index in (1, 2):
            assert command(0, b'CLUSTER', b'MEET', addresses[index].encode(), b'6379') == b'OK'
        for index, (start, end) in enumerate(((0, 5461), (5461, 10923), (10923, 16384))):
            assert command(index, b'CLUSTER', b'ADDSLOTS', *(str(value).encode() for value in range(start, end))) == b'OK'
        for _ in range(200):
            if all(b'cluster_state:ok' in command(index, b'CLUSTER', b'INFO') for index in range(3)):
                break
            time.sleep(.05)
        else:
            raise AssertionError([command(index, b'CLUSTER', b'INFO') for index in range(3)])
        yield addresses, command
    finally:
        for name in reversed(names):
            subprocess.run(['docker', 'rm', '-fv', name], check=False, capture_output=True)
        subprocess.run(['docker', 'network', 'rm', network], check=False, capture_output=True)


def real_cluster_checks(args):
    with real_cluster(args) as (addresses, command):
        moved = next(b'cluster-' + str(i).encode() for i in range(1000)
                     if 5461 <= slot(b'cluster-' + str(i).encode()) < 10923)
        asking = next(b'ask-' + str(i).encode() for i in range(1000)
                      if slot(b'ask-' + str(i).encode()) < 5461)
        unknown = next(b'unknown-' + str(i).encode() for i in range(1000)
                       if slot(b'unknown-' + str(i).encode()) >= 10923)
        assert command(1, b'SET', moved, b'a\x00\xffb') == b'OK'
        owner = command(0, b'CLUSTER', b'MYID')
        target = command(1, b'CLUSTER', b'MYID')
        number = str(slot(asking)).encode()
        assert command(1, b'CLUSTER', b'SETSLOT', number, b'IMPORTING', owner) == b'OK'
        assert command(0, b'CLUSTER', b'SETSLOT', number, b'MIGRATING', target) == b'OK'
        with configured_gateway(args, 6379, 6379, 1, addresses[1], addresses[0]) as request:
            pure_checks(request)
            assert command(0, b'CLUSTER', b'KEYSLOT', moved) == slot(moved)
            assert request('execute', packet([b'GET', moved]), {'X-Key': moved.decode()}) == (200, b'R:$4\r\na\x00\xffb\r\n')
            assert request('execute', packet([b'GET', unknown]), {'X-Key': unknown.decode()}) == (
                200, b'D:' + addresses[2].encode() + b':6379')
            assert request('execute', packet([b'SET', asking, b'a\x00\xffb']), {'X-Key': asking.decode()}) == (200, b'R:+OK\r\n')
            assert request('execute', packet([b'GET', asking]), {'X-Key': asking.decode()}) == (200, b'R:$4\r\na\x00\xffb\r\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--real-redis', action='store_true')
    parser.add_argument('--real-cluster', action='store_true')
    args = parser.parse_args()
    if args.real_cluster:
        real_cluster_checks(args)
        print(f'Redis Cluster passed ({args.backend}, O{args.opt}, tls={args.tls})')
        return
    context = None
    if args.tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'), str(Path(args.testdata) / 'localhost_key.pem'))
    if args.real_redis:
        with real_redis(args) as (port, command), real_sentinel(args, port) as sentinel:
            seed = TopologyFixture(context, target=port)
            try:
                with configured_gateway(args, seed.port, port, sentinel) as request:
                    pure_checks(request)
                    assert request('sentinel', packet([b'GET', b'topology-missing'])) == (200, b'R:$-1\r\n')
                    assert command(b'SET', b'topology-key', b'a\x00\xffb') == b'OK'
                    assert request('sentinel', packet([b'GET', b'topology-key'])) == (200, b'R:$4\r\na\x00\xffb\r\n')
                    assert request('execute', packet([b'GET', b'topology-key']), {'X-Key': 'topology-key'}) == (200, b'R:$4\r\na\x00\xffb\r\n')
                    assert request('execute', packet([b'GET', b'ask']), {'X-Key': 'ask'}) == (200, b'R:$-1\r\n')
            finally:
                seed.close()
    else:
        target = TopologyFixture(context)
        seed = TopologyFixture(context, target=target.port)
        sentinel = TopologyFixture(context, target=target.port, sentinel=True)
        try:
            with configured_gateway(args, seed.port, target.port, sentinel.port) as request:
                pure_checks(request)
                for key in (b'x', b'ask'):
                    assert request('execute', packet([b'GET', key]), {'X-Key': key.decode()}) == (200, b'R:$4\r\na\x00\xffb\r\n')
                assert request('execute', packet([b'GET', b'unknown']), {'X-Key': 'unknown'}) == (200, b'D:127.0.0.1:1')
                assert request('execute', packet([b'GET', b'wrong-slot']), {'X-Key': 'wrong-slot'})[0] == 502
                assert request('sentinel', packet([b'GET', b'x'])) == (200, b'R:$4\r\na\x00\xffb\r\n')
                assert sentinel.observed == [[b'SENTINEL', b'get-master-addr-by-name', b'rutmaster']]
                before = len(seed.observed)
                assert request('execute', packet([b'RESET']))[0] == 502
                assert len(seed.observed) == before
                assert target.observed.count([b'GET', b'ask']) == 1
                assert [b'ASKING'] in target.observed
                # A ROLE failure or unadmitted discovery cannot send business data.
                for reply in (b'*3\r\n$5\r\nslave\r\n:0\r\n*0\r\n',
                              b'*3\r\n$6\r\nmaster\r\n:-1\r\n*0\r\n',
                              b'-ERR denied\r\n', b'+OK\r\n'):
                    target.role = reply
                    before = len(target.observed)
                    outcome = request('sentinel', packet([b'GET', b'x']))
                    if reply.startswith(b'-'):
                        assert outcome == (200, b'E:ERR denied')
                    else:
                        assert outcome[0] == 502, (reply, outcome)
                    assert target.observed[before:] == [[b'ROLE']]
                target.role = b'*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n'
                for reply, status in ((b'*-1\r\n', 404), (b'*0\r\n', 404),
                                      (packet([b'127.0.0.1', b'1']), 403),
                                      (packet([b'127.0.0.1', b'+1']), 404)):
                    sentinel.discovery = reply
                    before = len(target.observed)
                    assert request('sentinel', packet([b'GET', b'x']))[0] == status
                    assert len(target.observed) == before
                before = len(target.observed)
                target.asking_ack = b'-ERR denied\r\n'
                assert request('execute', packet([b'SET', b'ask', b'value']), {'X-Key': 'ask'})[0] == 502
                assert target.observed[before:] == [[b'ASKING']]
                assert request('execute', packet([b'SET', b'eof', b'value']), {'X-Key': 'eof'})[0] == 502
                assert seed.observed.count([b'SET', b'eof', b'value']) == 1
        finally:
            seed.close()
            sentinel.close()
            target.close()
    print(f'Redis topology passed ({args.backend}, O{args.opt}, tls={args.tls}, real={args.real_redis})')


if __name__ == '__main__':
    main()
