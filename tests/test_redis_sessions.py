#!/usr/bin/env python3
"""Stateful independent RESP2 peer verifies AUTH/SELECT/RESET and lease isolation."""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time


PROGRAM = r'''
import "padding.rut"
import "redis-client.rut"
func initCode(_ result: RedisInitializeResult) -> i32 {
    match result {
        .ready => 204
        .authError(data) => 401
        .databaseError(data) => 409
        .requestFailure => 413
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        .replyFailure => 422
    }
}
func commandCode(_ result: RedisCommandResult) -> i32 {
    match result {
        .ok => 204
        .serverError(data) => 403
        .requestFailure => 413
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        .replyFailure => 422
    }
}
func resultFailureCode(_ result: RedisSessionResult) -> i32 {
    match result {
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        .replyFailure => 422
        .resetError(data) => 424
        .cleanupFailure(code) => if code == -2 { 504 } else { 425 }
        _ => 500
    }
}
func resultCode(_ result: RedisSessionResult) -> i32 {
    match result {
        .value(data) => 200
        .missing => 404
        .ok => 204
        .authError(data) => 401
        .databaseError(data) => 409
        .serverError(data) => 403
        .requestFailure => 413
        _ => resultFailureCode(result)
    }
}
func resultData(_ result: RedisSessionResult) -> Bytes {
    match result {
        .value(data) => data
        .authError(data) => data
        .databaseError(data) => data
        .serverError(data) => data
        .resetError(data) => data
        _ => b""
    }
}
func requestBytes(_ duplicate: bool, _ body: Bytes, _ fallback: Bytes) -> Bytes {
    if duplicate { body } else { fallback }
}
func resultWire(_ result: RedisSessionResult) {
    guard let code = formatInt(resultCode(result)) else { nil }
    guard let prefix = concatBytes(Bytes(code), b":", 8192) else { nil }
    concatBytes(prefix, resultData(result), 8192)
}
route POST "/session-get" {
    guard let db = parseInt(req.header("X-DB").or("1")) else { return 400 }
    let opening = tcp(env("PEER"), 1000)
    guard let connection = opening else { return 503 }
    let user = requestBytes(req.header("X-Duplicate").or("") == "yes", req.bodyBytes,
        Bytes(req.header("X-User").or("alice")))
    let result = redisSessionGet(connection, user,
        req.bodyBytes, db, Bytes(req.header("X-Key").or("key")))
    guard let wire = resultWire(result) else { return 500 }
    return response(200, body: wire)
}
route POST "/session-set" {
    guard let db = parseInt(req.header("X-DB").or("1")) else { return 400 }
    let opening = tcp(env("PEER"), 1000)
    guard let connection = opening else { return 503 }
    let key = requestBytes(req.header("X-Duplicate").or("") == "yes", req.bodyBytes,
        Bytes(req.header("X-Key").or("key")))
    let result = redisSessionSet(connection, Bytes(req.header("X-User").or("alice")),
        Bytes(req.header("X-Password").or("secret-a")), db,
        key, req.bodyBytes)
    guard let wire = resultWire(result) else { return 500 }
    return response(200, body: wire)
}
route POST "/raw-get" {
    let opening = tcp(env("PEER"), 1000)
    guard let connection = opening else { return 503 }
    let reply = redisGet(connection, b"key")
    let closed = connection.close()
    guard let wire = resultWire(redisSessionFromGet(reply)) else { return 500 }
    return response(200, body: wire)
}
route POST "/build-auth" {
    guard let packet = resp2AuthRequest(req.bodyBytes) else { return 413 }
    return response(200, body: packet)
}
route POST "/build-auth-user" {
    guard let cut = parseInt(req.header("X-Cut").or("0")) else { return 400 }
    guard let user = req.bodyBytes.slice(0, cut) else { return 400 }
    guard let password = req.bodyBytes.slice(cut, req.bodyBytes.count) else { return 400 }
    guard let packet = resp2AuthUserRequest(user, password) else { return 413 }
    return response(200, body: packet)
}
route POST "/build-select" {
    guard let db = parseInt(req.bodyBytes) else { return 400 }
    guard let packet = resp2SelectRequest(db) else { return 413 }
    return response(200, body: packet)
}
route POST "/classify" {
    guard let stream = redisInitializeFeed(redisInitializeStream(), req.bodyBytes) else { return 500 }
    let result = redisInitializeValidate(stream)
    guard let code = formatInt(initCode(result)) else { return 500 }
    let bytes = Bytes(code)
    return response(200, body: bytes)
}
'''


def packet(arguments):
    return (b'*' + str(len(arguments)).encode() + b'\r\n' +
            b''.join(b'$' + str(len(x)).encode() + b'\r\n' + x + b'\r\n' for x in arguments))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--example', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--tls', action='store_true')
    args = parser.parse_args()
    lock = threading.Lock()
    stopped = threading.Event()
    observed, errors, workers = [], [], []
    active = set()
    serial = [0]
    store = {(1, b'key'): b'one\x00\xff', (2, b'key'): b'two\x00\xfe'}
    passwords = {b'alice': b'secret-a', b'bob': b'secret-b', b'default': b'default-secret', b'binary': b'\x00\xff\r\n'}
    special = {b'fragment', b'bad-auth', b'bad-select', b'trailing', b'too-fragmented',
               b'reset-error', b'reset-wrong', b'reset-trailing', b'reset-timeout',
               b'reset-fragment', b'auth-timeout', b'auth-eof'}
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(32)
    listener.settimeout(.1)
    context = None
    cert = Path(args.testdata) / 'localhost_cert.pem'
    if args.tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(Path(args.testdata) / 'localhost_key.pem'))

    def serve(connection, identity):
        user, database, mode = None, 0, b''
        connection.settimeout(4)
        stream = connection.makefile('rb', buffering=0)
        def exact(size):
            data = b''
            while len(data) < size:
                chunk = stream.read(size - len(data))
                assert chunk, 'truncated fixture request'
                data += chunk
            return data
        with lock:
            active.add(identity)
        try:
            while not stopped.is_set():
                line = stream.readline(64)
                if not line:
                    break
                assert re.fullmatch(rb'\*[1-9][0-9]*\r\n', line)
                count = int(line[1:])
                assert 1 <= count <= 63
                arguments = []
                wire = line
                for _ in range(count):
                    length_line = stream.readline(64)
                    assert re.fullmatch(rb'\$[0-9]+\r\n', length_line)
                    length = int(length_line[1:])
                    assert length <= 8192
                    value = exact(length)
                    ending = exact(2)
                    assert len(value) == length and ending == b'\r\n'
                    arguments.append(value)
                    wire += length_line + value + ending
                assert wire == packet(arguments)
                name = arguments[0]
                with lock:
                    observed.append((identity, user, database, tuple(arguments)))
                if name == b'AUTH':
                    assert count in (2, 3)
                    wanted, password = (b'default', arguments[1]) if count == 2 else arguments[1:]
                    mode = wanted if wanted in special else b''
                    if mode == b'auth-timeout':
                        time.sleep(1.3)
                        return
                    if mode == b'auth-eof':
                        connection.sendall(b'+O')
                        return
                    if passwords.get(wanted, b'fixture-special') == password:
                        user = wanted
                        reply = b'+OK\r\n'
                    else:
                        reply = b'-WRONGPASS fixture\r\n'
                    if mode == b'bad-auth':
                        reply = b'$2\r\nOK\r\n'
                elif name == b'SELECT':
                    assert count == 2 and re.fullmatch(rb'[0-9]+', arguments[1])
                    selected = int(arguments[1])
                    if user is None:
                        reply = b'-NOAUTH fixture\r\n'
                    elif selected > 15:
                        reply = b'-ERR invalid database\r\n'
                    else:
                        database = selected
                        reply = b'+OK\r\n'
                    if mode == b'bad-select':
                        reply = b':1\r\n'
                    if mode == b'trailing':
                        reply += b'+PONG\r\n'
                elif name == b'RESET':
                    assert count == 1
                    if mode == b'reset-timeout':
                        time.sleep(1.3)
                        return
                    if mode == b'reset-error':
                        reply = b'-ERR RESET unavailable\r\n'
                    else:
                        user, database = None, 0
                        reply = b'+RESET\r\n'
                    if mode == b'reset-wrong':
                        reply = b'+OK\r\n'
                    if mode == b'reset-trailing':
                        reply += b'+EXTRA\r\n'
                elif name in (b'GET', b'SET'):
                    assert count == (2 if name == b'GET' else 3)
                    if user is None:
                        reply = b'-NOAUTH fixture\r\n'
                    elif arguments[1] == b'__error':
                        reply = b'-WRONGTYPE fixture\r\n'
                    elif name == b'SET':
                        with lock:
                            store[database, arguments[1]] = arguments[2]
                        reply = b'+OK\r\n'
                    else:
                        with lock:
                            value = store.get((database, arguments[1]))
                        reply = b'$-1\r\n' if value is None else b'$'+str(len(value)).encode()+b'\r\n'+value+b'\r\n'
                else:
                    raise AssertionError('unexpected command name')
                # AUTH/SELECT are queued in one write. Coalesce their replies so
                # the independent peer controls the exact framing, then test splits.
                if name == b'AUTH' and ((isinstance(connection, ssl.SSLSocket) and connection.pending()) or select.select([connection], [], [], .03)[0]):
                    auth_reply = reply
                    line = stream.readline(64)
                    assert line == b'*2\r\n'
                    fields = []
                    for _ in range(2):
                        length_line = stream.readline(64)
                        assert re.fullmatch(rb'\$[0-9]+\r\n', length_line)
                        value = exact(int(length_line[1:]))
                        assert exact(2) == b'\r\n'
                        fields.append(value)
                    assert fields[0] == b'SELECT' and re.fullmatch(rb'[0-9]+', fields[1])
                    with lock:
                        observed.append((identity, user, database, tuple(fields)))
                    selected = int(fields[1])
                    if user is None:
                        selected_reply = b'-NOAUTH fixture\r\n'
                    elif selected > 15:
                        selected_reply = b'-ERR invalid database\r\n'
                    else:
                        database = selected
                        selected_reply = b'+OK\r\n'
                    if mode == b'bad-select':
                        selected_reply = b':1\r\n'
                    reply = auth_reply + selected_reply
                    if mode == b'trailing':
                        reply += b'+PONG\r\n'
                    if mode == b'too-fragmented':
                        for part in (reply[:1], reply[1:6], reply[6:]):
                            connection.sendall(part)
                            time.sleep(.06)
                        continue
                if ((mode == b'fragment' and name == b'AUTH') or
                        (mode == b'reset-fragment' and name == b'RESET')):
                    connection.sendall(reply[:1])
                    time.sleep(.06)
                    connection.sendall(reply[1:])
                else:
                    connection.sendall(reply)
        except (OSError, ssl.SSLError):
            pass
        except Exception as error:
            errors.append(error)
        finally:
            stream.close()
            connection.close()
            with lock:
                active.discard(identity)

    def accept():
        while not stopped.is_set():
            try:
                connection, _ = listener.accept()
                if context:
                    connection = context.wrap_socket(connection, server_side=True)
            except socket.timeout:
                continue
            except OSError:
                return
            with lock:
                serial[0] += 1
                identity = serial[0]
            worker = threading.Thread(target=serve, args=(connection, identity), daemon=True)
            workers.append(worker)
            worker.start()

    accepting = threading.Thread(target=accept, daemon=True)
    accepting.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-redis-session-') as directory:
            root = Path(directory)
            for name in ('resp2.rut', 'resp2-command.rut', 'redis-client.rut'):
                shutil.copyfile(Path(args.library) / name, root / name)
            (root/'padding.rut').write_text('struct Padding { marker: i32 }\nvariant PaddingKind { absent }\n')
            program = PROGRAM
            for route, expression in (
                ('auth', 'redisAuth(connection, req.bodyBytes)'),
                ('auth-user', 'redisAuthUser(connection, Bytes(req.header("X-User").or("alice")), req.bodyBytes)'),
                ('select', 'redisSelect(connection, parseInt(req.bodyBytes).or(-1))'),
                ('reset', 'redisReset(connection)'),
            ):
                program += f'''
route POST "/{route}" {{
    let opening = tcp(env("PEER"), 1000)
    guard let connection = opening else {{ return 503 }}
    let result = {expression}
    let closed = connection.close()
    guard closed == redisCommandSucceeded(result) else {{ return 500 }}
    guard let code = formatInt(commandCode(result)) else {{ return 500 }}
    let bytes = Bytes(code)
    return response(200, body: bytes)
}}
'''
            for route, expression in (
                ('initialize', 'redisInitialize(connection, Bytes(req.header("X-User").or("alice")), req.bodyBytes, parseInt(req.header("X-DB").or("1")).or(-1))'),
                ('initialize-default', 'redisInitializeDefault(connection, req.bodyBytes, 1)'),
            ):
                program += f'''
route POST "/{route}" {{
    let opening = tcp(env("PEER"), 1000)
    guard let connection = opening else {{ return 503 }}
    let result = {expression}
    let closed = connection.close()
    guard closed == redisInitializeSucceeded(result) else {{ return 500 }}
    guard let code = formatInt(initCode(result)) else {{ return 500 }}
    let bytes = Bytes(code)
    return response(200, body: bytes)
}}
'''
            example = Path(args.example).read_text().replace('import "clients/redis-client.rut"', '')
            program += example
            if args.opt == '2':
                program = program.replace('import "redis-client.rut"', 'import * as client from "redis-client.rut"')
                program = re.sub(r'\b(redis[A-Z]\w*|resp2[A-Z]\w*)\(', r'client.\1(', program)
                for typename in ('RedisInitializeResult', 'RedisCommandResult', 'RedisSessionResult'):
                    program = program.replace(typename, 'client.' + typename)
            source, log = root/'session.rut', root/'server.log'
            source.write_text(program)
            policy = dict(address='127.0.0.1', port=listener.getsockname()[1], poolIdleMs=5000)
            if args.tls:
                policy.update(tls=True, caFile=str(cert), serverName='localhost')
            env = dict(os.environ, PEER=json.dumps(policy), REDIS_ENDPOINT=json.dumps(policy),
                       REDIS_USERNAME='alice', REDIS_PASSWORD='secret-a', REDIS_DATABASE='1')
            with log.open('wb') as output:
                process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                                            '--opt', args.opt, '--no-pin', '--shards', '1', '--drain', '0'],
                                           env=env, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 240
                port = None
                while time.monotonic() < deadline:
                    data = log.read_bytes()
                    found = re.search(rb'Listening on port ([0-9]+) with', data)
                    if found:
                        port = int(found[1])
                        break
                    if process.poll() is not None:
                        if args.backend == 'io_uring' and b'io_uring is unavailable' in data:
                            return 77
                        raise AssertionError((process.returncode, data.decode(errors='replace')))
                    time.sleep(.025)
                assert port, log.read_text(errors='replace')
                for path in root.glob('*.rut'):
                    path.unlink()
                requests = [0]

                def request(path, body=b'', headers=None):
                    requests[0] += 1
                    client = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    try:
                        client.request('POST', '/' + path, body, headers or {})
                        response = client.getresponse()
                        return response.status, response.read()
                    finally:
                        client.close()

                def session(user='alice', password=b'secret-a', database=1, key='key'):
                    response = request('session-get', password,
                                       {'X-User':user, 'X-DB':str(database), 'X-Key':key})
                    assert response[0] == 200, response
                    return response[1]

                assert request('build-auth', b'') == (200, packet([b'AUTH', b'']))
                maximum = max(n for n in range(8193) if len(packet([b'AUTH', b'x' * n])) <= 8192)
                assert request('build-auth', b'x' * maximum) == (200, packet([b'AUTH', b'x' * maximum]))
                assert request('build-auth', b'x' * (maximum + 1))[0] == 413
                assert request('build-auth', b'\x00\xff\r\n') == (200, packet([b'AUTH', b'\x00\xff\r\n']))
                assert request('build-auth-user', b'al\x00\xffpass', {'X-Cut':'3'}) == (200, packet([b'AUTH', b'al\x00', b'\xffpass']))
                for value in (0, 1, 15, 2147483647):
                    assert request('build-select', str(value).encode()) == (200, packet([b'SELECT',str(value).encode()]))
                assert request('build-select', b'-1')[0] == 413
                for raw, code in ((b'+OK\r\n+OK\r\n', b'204'),
                                  (b'-WRONGPASS x\r\n-NOAUTH x\r\n', b'401'),
                                  (b'+OK\r\n-ERR db\r\n', b'409'),
                                  (b'+PONG\r\n+OK\r\n', b'422'),
                                  (b'+OK\r\n$2\r\nOK\r\n', b'422'),
                                  (b'+OK\r\n+OK\r\n+EXTRA\r\n', b'422'),
                                  (b'+OK\r\n', b'422'), (b'*0\r\n+OK\r\n', b'422')):
                    assert request('classify', raw) == (200, code)
                assert request('auth', b'default-secret') == (200, b'204')
                assert request('auth-user', b'secret-a') == (200, b'204')
                assert request('auth-user', b'wrong') == (200, b'403')
                assert request('auth-user', b'\x00\xff\r\n', {'X-User':'binary'}) == (200, b'204')
                assert request('select', b'1') == (200, b'403')  # unauthenticated peer
                before = len(observed)
                assert request('select', b'-1') == (200, b'413')
                assert len(observed) == before
                assert request('reset') == (200, b'204')
                assert request('initialize', b'secret-a') == (200, b'204')
                assert request('initialize-default', b'default-secret') == (200, b'204')
                assert session() == b'200:one\x00\xff'
                with lock:
                    first_identity = observed[-1][0]
                    assert observed[-1][3] == (b'RESET',)
                assert session('bob', b'secret-b', 2) == b'200:two\x00\xfe'
                with lock:
                    assert observed[-1][0] == first_identity, 'clean transport must be reused across users/databases'
                    gets = [x for x in observed if x[3][0] == b'GET']
                    assert gets[-1][1:3] == (b'bob', 2)
                assert session() == b'200:one\x00\xff'
                assert request('raw-get') == (200, b'403:NOAUTH fixture'), 'RESET must deauthenticate before generic pool reuse'
                assert session('binary', b'\x00\xff\r\n') == b'200:one\x00\xff'
                for value in (b'', b'a\x00\xff\r\n*2', bytes(range(256))):
                    assert request('session-set', value) == (200, b'204:')
                    assert session() == b'200:' + value
                assert session(key='missing') == b'404:'
                assert session(key='__error') == b'403:WRONGTYPE fixture'
                before = len(observed)
                assert session(password=b'wrong') == b'401:WRONGPASS fixture'
                with lock:
                    assert [x[3][0] for x in observed[before:]] == [b'AUTH', b'SELECT'], 'business command sent after AUTH failure'
                before = len(observed)
                assert session(database=99) == b'409:ERR invalid database'
                with lock:
                    assert [x[3][0] for x in observed[before:]] == [b'AUTH', b'SELECT']
                before = len(observed)
                assert session(database=-1) == b'413:'
                assert len(observed) == before, 'invalid initialization wrote bytes'
                combined = max(n for n in range(8193)
                               if len(packet([b'AUTH', b'x' * n, b'x' * n])) +
                               len(packet([b'SELECT', b'1'])) <= 8192)
                before = len(observed)
                assert request('session-get', b'x' * (combined + 1), {'X-Duplicate':'yes'}) == (200, b'413:')
                assert len(observed) == before, 'oversized initialization wrote a partial AUTH'
                before = len(observed)
                assert request('session-set', b'x' * 4200, {'X-Duplicate':'yes'}) == (200, b'413:')
                with lock:
                    assert [x[3][0] for x in observed[before:]] == [b'AUTH', b'SELECT', b'RESET']
                assert session() == b'200:' + bytes(range(256)), 'oversized SET changed the stored value'
                for user, expected in (('bad-auth', b'422:'), ('bad-select', b'422:'),
                                       ('trailing', b'422:'), ('too-fragmented', b'422:'),
                                       ('auth-timeout', b'504:'), ('auth-eof', b'422:')):
                    before = len(observed)
                    actual = session(user, b'fixture-special')
                    if user == 'auth-eof':
                        # A peer closing with queued SELECT bytes can produce RST
                        # rather than clean EOF; either failure must stop GET.
                        assert actual in (b'422:', b'502:'), (user, actual)
                    else:
                        assert actual == expected, (user, actual)
                    with lock:
                        assert not any(x[3][0] in (b'GET',b'SET') for x in observed[before:]), user
                assert session('fragment', b'fixture-special').startswith(b'200:')
                assert session('reset-fragment', b'fixture-special').startswith(b'200:')
                for user, expected in (('reset-error', b'424:ERR RESET unavailable'),
                                       ('reset-wrong', b'425:'), ('reset-trailing', b'425:'),
                                       ('reset-timeout', b'504:')):
                    actual = session(user, b'fixture-special')
                    assert actual == expected, (user, actual)
                    with lock:
                        poisoned = observed[-1][0]
                    assert session().startswith(b'200:')
                    with lock:
                        assert observed[-1][0] != poisoned, 'failed RESET transport was pooled'
                before = len(observed)
                assert request('session-set', b'executed-once',
                               {'X-User':'reset-timeout', 'X-Password':'fixture-special',
                                'X-Key':'once'}) == (200, b'504:')
                with lock:
                    writes = [x for x in observed[before:] if x[3][0] == b'SET']
                    assert len(writes) == 1, 'cleanup failure replayed a completed SET'
                    assert store[1, b'once'] == b'executed-once'
                assert request('set', b'example\x00\xff')[0] == 204
                assert request('get', b'example-key') == (200, b'example\x00\xff')
                assert not errors, errors
                print(f'PASS Redis sessions {args.backend} O{args.opt} TLS={args.tls}: '
                      f'{requests[0]} requests')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                stopped.set()
                listener.close()
                accepting.join(timeout=2)
                for worker in workers:
                    worker.join(timeout=2)
                with lock:
                    assert not active, 'shutdown leaked active or pooled peer connections'
    finally:
        stopped.set()
        listener.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
