#!/usr/bin/env python3
"""Authenticated RESP3 negotiation and challenge-gated Memcached text sessions."""
import argparse
import contextlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from test_redis_commands import Fixture, gateway as redis_gateway, packet, read_value, real_redis
from test_memcache_client import MEMCACHED_IMAGE, gateway as memcache_gateway, real_memcached
REDIS = r'''import "redis-resp3.rut"
func name(_ enabled: bool, _ value: Bytes) -> RedisClientName {
    if enabled { RedisClientName.value(value) } else { RedisClientName.unchanged }
}
func status(_ result: RedisResp3Result) -> i32 {
    match result {
        .reply(event) => 200
        .requestFailure => 400
        .serverError(event) => 401
        _ => 502
    }
}
func frame(_ result: RedisResp3Result) -> Bytes {
    match result { .reply(event) => event.frame
        _ => b"" }
}
route POST "/build" {
    guard let wire = resp2Hello3AuthRequest(Bytes(req.header("X-User").or("user")), req.bodyBytes,
        name(req.header("X-Named").or("") == "yes", Bytes(req.header("X-Name").or("client")))) else { return 400 }
    return response(200, body: wire)
}
route POST "/auth" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisHello3Auth(connection, Bytes(req.header("X-User").or("user")),
        Bytes(req.header("X-Password").or("p a:ss")),
        name(req.header("X-Named").or("") == "yes", Bytes(req.header("X-Name").or("client"))))
    let sending = connection.send(b"*2\r\n$6\r\nCLIENT\r\n$7\r\nGETNAME\r\n", 1000)
    let reading = connection.receive(8192, 1000)
    let closed = connection.close()
    guard status(result) != 200 || closed else { return 500 }
    guard status(result) == 200 || !closed else { return 500 }
    guard status(result) != 400 else { return 400 }
    guard status(result) != 401 else { return 401 }
    guard status(result) != 502 else { return 502 }
    guard let prefix = concatBytes(frame(result), b"\nPROBE\n", 8192) else { return 500 }
    guard let value = concatBytes(prefix, reading.or(b""), 8192) else { return 500 }
    return response(200, body: value)
}
'''
MEMCACHE = r'''import "memcache-auth.rut"
func status(_ result: MemcacheAuthResult) -> i32 {
    match result {
        .authenticated => 200
        .requestFailure => 400
        .challengeFailure => 412
        .rejected(message) => 401
        _ => 502
    }
}
func sessionStatus(_ result: MemcacheAuthSessionResult) -> i32 {
    match result {
        .value(item) => 200
        .missing => 404
        .stored => 200
        .notStored => 409
        .authError(message) => 401
        .challengeFailure => 412
        .requestFailure => 400
        _ => 502
    }
}
func sessionData(_ result: MemcacheAuthSessionResult) -> Bytes {
    match result { .value(item) => item.data
        .stored => b"STORED"
        _ => b"" }
}
route POST "/build" {
    guard let wire = memcacheAuthRequest(Bytes(req.header("X-User").or("user")), req.bodyBytes) else { return 400 }
    return response(200, body: wire)
}
route POST "/auth" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheAuthenticate(connection, Bytes(req.header("X-User").or("user")), Bytes(req.header("X-Password").or("p a:ss")))
    let sending = connection.send(b"get stable\r\n", 1000)
    let reading = connection.receive(8192, 1000)
    let closed = connection.close()
    guard status(result) == 200 || status(result) == 400 || !closed else { return 500 }
    guard (status(result) != 200 && status(result) != 400) || closed else { return 500 }
    guard status(result) != 400 else { return 400 }
    guard status(result) != 401 else { return 401 }
    guard status(result) != 412 else { return 412 }
    guard status(result) != 502 else { return 502 }
    let value = reading.or(b"")
    return response(200, body: value)
}
route POST "/get" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheSessionGet(connection, Bytes(req.header("X-User").or("user")),
        Bytes(req.header("X-Password").or("p a:ss")), req.bodyBytes)
    let closed = connection.close()
    guard !closed else { return 500 }
    guard sessionStatus(result) != 400 else { return 400 }
    guard sessionStatus(result) != 401 else { return 401 }
    guard sessionStatus(result) != 404 else { return 404 }
    guard sessionStatus(result) != 412 else { return 412 }
    guard sessionStatus(result) != 502 else { return 502 }
    let value = sessionData(result)
    return response(200, body: value)
}
route POST "/set" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheSessionSet(connection, Bytes(req.header("X-User").or("user")),
        Bytes(req.header("X-Password").or("p a:ss")), b"session", req.bodyBytes, MemcacheOptions(flags: b"0", expirySeconds: 0))
    let closed = connection.close()
    guard !closed else { return 500 }
    guard sessionStatus(result) != 400 else { return 400 }
    guard sessionStatus(result) != 401 else { return 401 }
    guard sessionStatus(result) != 412 else { return 412 }
    guard sessionStatus(result) != 502 else { return 502 }
    let value = sessionData(result)
    return response(200, body: value)
}
route POST "/reauth" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let first = memcacheAuthenticate(connection, b"user", b"p a:ss")
    let second = memcacheAuthenticate(connection, b"user", b"p a:ss")
    let closed = connection.close()
    guard status(first) == 200 && status(second) == 412 && !closed else { return 500 }
    return 200
}
route POST "/anonymous" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let sending = connection.send(b"get stable\r\n", 1000)
    let reading = connection.receive(8192, 1000)
    let closed = connection.close()
    let value = reading.or(b"")
    return response(200, body: value)
}
'''

class AuthPeer(Fixture):

    def __init__(self, protocol, context):
        self.protocol, self.case = (protocol, 'normal')
        self.connections = []
        super().__init__(context)

    def serve(self, connection):
        ident = len(self.connections)
        self.connections.append(ident)
        authenticated = False
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                while not self.stop.is_set():
                    case = self.case
                    if self.protocol == 'redis':
                        command = read_value(stream)
                        self.observed.append((ident, command))
                        if command[:3] == [b'HELLO', b'3', b'AUTH']:
                            assert len(command) in (5, 7)
                            replies = dict(normal=b'%1\r\n$5\r\nproto\r\n:3\r\n', wrong=b'+OK\r\n', proto=b'%1\r\n$5\r\nproto\r\n:2\r\n', duplicate=b'%2\r\n$5\r\nproto\r\n:3\r\n$5\r\nproto\r\n:3\r\n', error=b'-WRONGPASS fixture\r\n', push=b'>1\r\n+x\r\n', extra=b'%1\r\n$5\r\nproto\r\n:3\r\n+EXTRA\r\n', truncated=b'%1\r\n$5\r\npro')
                            reply = replies.get(case, replies['normal'])
                            authenticated = command[4] == b'p a:ss'
                            if not authenticated:
                                reply = replies['error']
                        else:
                            assert command == [b'CLIENT', b'GETNAME'] and authenticated
                            reply = b'$6\r\nclient\r\n'
                    else:
                        line = stream.readline()
                        if not line:
                            return
                        if line.startswith(b'set '):
                            payload = stream.read(int(line.split()[4]) + 2)
                            assert payload.endswith(b'\r\n')
                            self.observed.append((ident, line, payload))
                            if not authenticated:
                                authenticated = payload == b'user p a:ss\r\n'
                                reply = b'STORED\r\n' if authenticated else b'CLIENT_ERROR authentication failure\r\n'
                                if case == 'badack':
                                    reply = b'NOT_STORED\r\n'
                                if case == 'auth-extra':
                                    reply += b'END\r\n'
                                if case == 'auth-eof':
                                    return
                            else:
                                if case == 'write-eof':
                                    return
                                reply = b'STORED\r\n'
                        else:
                            self.observed.append((ident, line))
                            if line == b'version\r\n':
                                reply = b'VERSION 1.6.45\r\n' if authenticated else b'CLIENT_ERROR unauthenticated\r\n'
                                if case == 'unsupported':
                                    reply = b'VERSION 1.6.45\r\n'
                                if case == 'challenge-wrong':
                                    reply = b'STORED\r\n'
                                if case == 'challenge-other':
                                    reply = b'CLIENT_ERROR other\r\n'
                                if case == 'challenge-extra':
                                    reply += b'STORED\r\n'
                            else:
                                assert line.startswith(b'get ')
                                if not authenticated:
                                    reply = b'CLIENT_ERROR unauthenticated\r\n'
                                elif line == b'get missing\r\n':
                                    reply = b'END\r\n'
                                else:
                                    reply = b'VALUE stable 0 4\r\na\x00\xffb\r\nEND\r\n'
                    if case == 'eof':
                        return
                    if case == 'timeout':
                        self.stop.wait(1.3)
                        return
                    if case == 'fragments':
                        for chunk in (reply[:2], reply[2:]):
                            connection.sendall(chunk)
                            time.sleep(0.04)
                    else:
                        connection.sendall(reply)
                    if case == 'truncated':
                        return
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)

def builders(request, protocol):
    for password in (b'p a:ss', b'x' * 250, b'x' * 4096):
        if protocol == 'redis':
            for named in ('', 'yes'):
                args = [b'HELLO', b'3', b'AUTH', b'user', password]
                if named:
                    args += [b'SETNAME', b'client']
                assert request('build', password, {'X-Named': named}) == (200, packet(args))
            for password in (b'', b'p\x00\xff\r\n'):
                assert request('build', password) == (200, packet([b'HELLO', b'3', b'AUTH', b'user', password]))
        else:
            payload = b'user ' + password
            assert request('build', password) == (200, b'set __rut_auth 0 0 ' + str(len(payload)).encode() + b'\r\n' + payload + b'\r\n')
    if protocol == 'redis':
        assert request('build', b'x' * 8192)[0] == 400
        assert request('build', b'password', {'X-Named': 'yes', 'X-Name': ''}) == (200, packet([b'HELLO', b'3', b'AUTH', b'user', b'password', b'SETNAME', b'']))
    else:
        for password in (b'', b'x' * 4097, b'p\x00', b'p\r\n'):
            assert request('build', password)[0] == 400
        for user in ('', 'a b', 'x' * 251):
            assert request('build', b'pass', {'X-User': user})[0] == 400

@contextlib.contextmanager
def protected_memcached(args):
    name = 'rut-memcache-auth-' + uuid.uuid4().hex
    settings = ['memcached', '-m', '16', '-U', '0', '-Y', '/tmp/users']
    if args.tls:
        settings += ['-Z', '-o', 'ssl_chain_cert=/tmp/localhost_cert.pem,ssl_key=/tmp/localhost_key.pem']
    try:
        subprocess.run(['docker', 'create', '--name', name, '-p', '127.0.0.1::11211', MEMCACHED_IMAGE, *settings], check=True, capture_output=True)
        with tempfile.TemporaryDirectory(prefix='rut-memcache-auth-') as directory:
            users = Path(directory, 'users')
            users.write_text('user:p a:ss\n')
            subprocess.run(['docker', 'cp', str(users), name + ':/tmp/users'], check=True, capture_output=True)
        if args.tls:
            for filename in ('localhost_cert.pem', 'localhost_key.pem'):
                subprocess.run(['docker', 'cp', str(Path(args.testdata) / filename), name + ':/tmp/' + filename], check=True, capture_output=True)
        subprocess.run(['docker', 'start', name], check=True, capture_output=True)
        info = json.loads(subprocess.check_output(['docker', 'inspect', name]))[0]
        port = int(info['NetworkSettings']['Ports']['11211/tcp'][0]['HostPort'])
        connection = None
        for _ in range(200):
            try:
                connection = socket.create_connection(('127.0.0.1', port), timeout=2)
                if args.tls:
                    connection = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem')).wrap_socket(connection, server_hostname='localhost')
                break
            except OSError:
                time.sleep(0.025)
        assert connection is not None
        with connection, connection.makefile('rb') as stream:

            def command(wire):
                connection.sendall(wire)
                line = stream.readline()
                if line.startswith(b'VALUE '):
                    value = stream.read(int(line.split()[3]))
                    assert stream.read(2) == b'\r\n' and stream.readline() == b'END\r\n'
                    return value
                return line
            payload = b'user p a:ss'
            assert command(b'set auth 0 0 ' + str(len(payload)).encode() + b'\r\n' + payload + b'\r\n') == b'STORED\r\n'
            assert command(b'set stable 0 0 4\r\na\x00\xffb\r\n') == b'STORED\r\n'
            assert command(b'set __rut_auth 0 0 8\r\noriginal\r\n') == b'STORED\r\n'
            yield (port, command)
    finally:
        subprocess.run(['docker', 'rm', '-fv', name], check=False, capture_output=True)

def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'library', 'backend', 'opt', 'protocol'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--testdata')
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--real', action='store_true')
    args = parser.parse_args()
    args.real_redis = args.real
    args.real_memcached = args.real
    args.example = None
    if args.tls and (not args.testdata):
        parser.error('--tls requires --testdata')

    def gateway(port):
        endpoint = dict(address='127.0.0.1', port=port, poolIdleMs=5000)
        if args.tls:
            endpoint.update(tls=True, caFile=str(Path(args.testdata).resolve() / 'localhost_cert.pem'), serverName='localhost')
        if args.protocol == 'redis':
            return redis_gateway(args, endpoint, program_factory=lambda _: REDIS, extra_libraries=('resp3.rut', 'redis-resp3.rut'), entrypoint='redis-resp3.rut')
        return memcache_gateway(args, endpoint, program_factory=lambda: MEMCACHE, extra_libraries=('memcache-auth.rut',), entrypoint='memcache-auth.rut')
    if args.real:
        if args.protocol == 'redis':
            with real_redis(args) as (port, command), gateway(port) as request:
                assert command(b'ACL', b'SETUSER', b'user', b'on', b'>p a:ss', b'~*', b'+@all') == b'OK'
                builders(request, args.protocol)
                for named, name in (('', 'client'), ('yes', 'client'), ('yes', '')):
                    code, body = request('auth', headers={'X-Named': named, 'X-Name': name})
                    assert code == 200 and body.startswith(b'%'), (code, body)
                    hello, probe = body.split(b'\nPROBE\n')
                    assert b'proto' in hello
                    assert probe == (b'_\r\n' if not named or not name else b'$6\r\nclient\r\n'), probe
                assert request('auth', headers={'X-Password': 'wrong'})[0] == 401
                assert request('auth', headers={'X-Named': 'yes', 'X-Name': 'bad name'})[0] == 401
        else:
            with protected_memcached(args) as (port, command), gateway(port) as request:
                builders(request, args.protocol)
                assert request('auth')[0] == 200
                assert request('get', b'stable') == (200, b'a\x00\xffb')
                assert request('get', b'missing')[0] == 404
                assert request('set', b'new\x00\xff') == (200, b'STORED')
                assert command(b'get session\r\n') == b'new\x00\xff'
                assert request('reauth')[0] == 200
                assert command(b'get __rut_auth\r\n') == b'original'
                assert request('get', b'stable', {'X-Password': 'wrong'})[0] == 401
                assert request('anonymous') == (200, b'CLIENT_ERROR unauthenticated\r\n')
            with real_memcached(args) as port, gateway(port) as request:
                assert request('auth')[0] == 412
                connection = socket.create_connection(('127.0.0.1', port), timeout=2)
                if args.tls:
                    connection = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem')).wrap_socket(connection, server_hostname='localhost')
                with connection, connection.makefile('rb') as stream:
                    connection.sendall(b'get __rut_auth\r\n')
                    assert stream.readline() == b'END\r\n', 'credentials must never become a cache item'
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'), str(Path(args.testdata) / 'localhost_key.pem'))
        peer = AuthPeer(args.protocol, context)
        try:
            with gateway(peer.port) as request:
                builders(request, args.protocol)
                cases = ('normal', 'fragments', 'wrong', 'proto', 'duplicate', 'error', 'push', 'extra', 'truncated', 'eof', 'timeout') if args.protocol == 'redis' else ('normal', 'fragments', 'unsupported', 'challenge-wrong', 'challenge-other', 'challenge-extra', 'badack', 'auth-extra', 'auth-eof', 'eof', 'timeout')
                for case in cases:
                    peer.case = case
                    before = len(peer.observed)
                    code, body = request('auth')
                    expected = 200 if case in ('normal', 'fragments') else 401 if case == 'error' else 412 if case.startswith('challenge-') or case in ('unsupported', 'eof') else 502
                    if args.protocol == 'redis' and case == 'eof':
                        expected = 502
                    if args.protocol == 'memcache' and case == 'eof':
                        # Native TLS EOF can carry a transport code; neither path
                        # may authorize sending the credential payload.
                        assert code in (412, 502), (case, code, body)
                    else:
                        assert code == expected, (case, code, body)
                    commands = peer.observed[before:]
                    if args.protocol == 'memcache' and case in ('unsupported', 'challenge-wrong', 'challenge-other', 'challenge-extra', 'eof', 'timeout'):
                        assert len(commands) == 1 and len(commands[0]) == 2, 'credentials must not follow an unverified challenge'
                    if args.protocol == 'redis':
                        assert sum((c[1][:1] == [b'HELLO'] for c in commands)) == 1, 'no fallback or retry'
                if args.protocol == 'memcache':
                    peer.case = 'normal'
                    before = len(peer.observed)
                    assert request('reauth')[0] == 200
                    commands = peer.observed[before:]
                    assert len(commands) == 3 and len({item[0] for item in commands}) == 1
                    assert sum(len(item) == 3 for item in commands) == 1, 'reauthentication must not send another credential SET'
                    for _ in range(2):
                        assert request('get', b'stable') == (200, b'a\x00\xffb')
                    assert request('anonymous') == (200, b'CLIENT_ERROR unauthenticated\r\n')
                    peer.case = 'write-eof'
                    before = len(peer.observed)
                    assert request('set', b'new')[0] == 502
                    writes = [c for c in peer.observed[before:] if len(c) == 3 and c[1].startswith(b'set session ')]
                    assert len(writes) == 1, 'unknown write outcome must not be replayed'
                    peer.case = 'normal'
                    before = len(peer.observed)
                    assert request('get', b'bad key')[0] == 400
                    assert len(peer.observed) == before, 'invalid business request must not authenticate'
                    assert request('set', b'new', {'X-Password': ''})[0] == 400
                    assert len(peer.observed) == before, 'invalid credentials must not send any command'
        finally:
            peer.close()
    print(f'PASS {args.protocol} auth {args.backend} O{args.opt} TLS={args.tls} real={args.real}')
if __name__ == '__main__':
    main()
