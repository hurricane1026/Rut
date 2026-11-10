#!/usr/bin/env python3
"""Bounded Redis commands: independent wire oracle or pinned real Redis."""
import argparse
import contextlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid


# Immutable official 7.2.11 Alpine manifest. Redis is a test-only peer.
REDIS_IMAGE = 'redis@sha256:1a34bdba051ecd8a58ec8a3cc460acef697a1605e918149cc53d920673c1a0a7'


def packet(arguments):
    return b'*%d\r\n' % len(arguments) + b''.join(
        b'$%d\r\n' % len(arg) + arg + b'\r\n' for arg in arguments)


def read_value(stream):
    line = stream.readline(16385)
    if not line:
        raise EOFError
    assert line.endswith(b'\r\n'), line
    kind, value = line[:1], line[1:-2]
    if kind == b'*':
        return [read_value(stream) for _ in range(int(value))]
    if kind == b'$':
        size = int(value)
        if size == -1:
            return None
        data = stream.read(size)
        assert len(data) == size and stream.read(2) == b'\r\n'
        return data
    if kind == b':':
        return int(value)
    if kind == b'-':
        return ('error', value)
    assert kind == b'+', line
    return value


class Fixture:
    def __init__(self, tls_context=None):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.observed = []
        self.errors = []
        self.sockets = []
        self.workers = []
        self.tls_context = tls_context
        self.acceptor = threading.Thread(target=self.accept, daemon=True)
        self.acceptor.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.sockets.append(connection)
            worker = threading.Thread(target=self.serve, args=(connection,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, connection):
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                while not self.stop.is_set():
                    command = read_value(stream)
                    self.observed.append(command)
                    if command[0] == b'FIXTURE':
                        mode = command[2] if len(command) > 2 else b'whole'
                        if mode == b'timeout':
                            self.stop.wait(1.3)
                            continue
                        if mode == b'eof':
                            return
                        reply = command[1]
                        if mode == b'max-frame':
                            reply = b'$8183\r\n' + b'x' * 8183 + b'\r\n'
                        if mode == b'too-large':
                            reply = b'$8184\r\n' + b'x' * 8184 + b'\r\n'
                        if mode == b'read-budget':
                            for chunk in (b'$', b'1', b'\r', b'\n', b'x\r\n'):
                                connection.sendall(chunk)
                                time.sleep(.1)
                            continue
                        if mode == b'fragments':
                            cuts = [1, 4, len(reply) // 2]
                            chunks = [reply[a:b] for a, b in zip([0] + cuts, cuts + [len(reply)])]
                            for chunk in chunks:
                                connection.sendall(chunk)
                                time.sleep(.04)
                        else:
                            connection.sendall(reply)
                    elif command == [b'GET', b'stable']:
                        connection.sendall(b'$4\r\na\x00\xffb\r\n')
                    elif command[0] == b'SET' and command[1] == b'null-reply':
                        connection.sendall(b'$-1\r\n')
                    elif command[0] == b'SET' and command[1] == b'ok-reply':
                        connection.sendall(b'+OK\r\n')
                    elif command[0] == b'SET' and command[1] == b'error-reply':
                        connection.sendall(b'-ERR fixture\r\n')
                    else:
                        # A convenience wrapper must reject a well-framed wrong type.
                        connection.sendall(b'+WRONG\r\n')
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)

    def close(self):
        self.stop.set()
        self.listener.close()
        for connection in self.sockets:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
        self.acceptor.join(2)
        for worker in self.workers:
            worker.join(2)
        assert not self.errors, self.errors


PROGRAM = r'''import "redis-client.rut"
func resultReply(_ result: RedisResult) -> RedisReply {
    match result { .reply(value) => value _ => nil }
}
func resultStatus(_ result: RedisResult) -> i32 {
    match result {
        .reply(value) => 200
        .serverError(data) => 409
        .requestFailure => 413
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        .replyFailure => 502
    }
}
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
func setStatus(_ result: RedisSetOptionsResult) -> i32 {
    match result {
        .ok => 204
        .notSet => 412
        .serverError(data) => 409
        .requestFailure => 413
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        .replyFailure => 502
    }
}
func indexedBytes(_ reply: RedisReply, _ index: i32) -> Bytes {
    guard let values = redisValues(reply) else { nil }
    guard let token = values.get(index) else { nil }
    token.data
}
func outputBytes(_ reply: RedisReply, _ mode: str, _ index: i32) -> Bytes {
    match mode {
        "integer" => {
            guard let number = redisInteger(reply) else { nil }
            guard let digits = formatInt(number) else { nil }
            Bytes(digits)
        }
        "values" => indexedBytes(reply, index)
        _ => reply.frame
    }
}
route POST "/execute" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisExecute(connection, req.bodyBytes)
    let closed = connection.close()
    let status = resultStatus(result)
    guard status != 409 else { return 409 }
    guard status != 413 else { return 413 }
    guard status != 504 else { return 504 }
    guard let reply = resultReply(result) else { return 502 }
    guard let data = outputBytes(reply, req.header("X-Mode").or(""),
        parseInt(req.header("X-Index").or("0")).or(-1)) else { return 422 }
    return response(200, body: data)
}
// One initialized business command, acknowledged RESET and pool return still
// fit the existing sixteen-operation profile. Observe the reply after cleanup.
route POST "/authenticated" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let initialized = redisInitialize(connection, b"alice", b"secret", 2)
    guard redisInitializeSucceeded(initialized) else { return 502 }
    let result = redisExecute(connection, req.bodyBytes)
    let reset = redisReset(connection)
    let returned = connection.release()
    guard redisCommandSucceeded(reset) && netError() == 0 else { return 502 }
    guard let reply = resultReply(result) else { return 502 }
    let data = reply.frame
    return response(200, body: data)
}
route POST "/set-options" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisSetWithOptions(connection, requestKey(req.header("X-Duplicate").or("") == "yes", req.bodyBytes,
        Bytes(req.header("X-Key").or("options"))), req.bodyBytes,
        condition(req.header("X-Condition").or("")),
        expiry(req.header("X-Expiry").or(""), parseInt(req.header("X-Amount").or("0")).or(0)))
    let closed = connection.close()
    let status = setStatus(result)
    guard status != 502 || !closed else { return 500 }
    guard status != 204 else { return 204 }
    guard status != 412 else { return 412 }
    guard status != 409 else { return 409 }
    guard status != 413 else { return 413 }
    guard status != 504 else { return 504 }
    return 502
}
route POST "/build-options" {
    guard let value = resp2SetOptionsRequest(requestKey(req.header("X-Duplicate").or("") == "yes", req.bodyBytes,
        Bytes(req.header("X-Key").or("options"))), req.bodyBytes,
        condition(req.header("X-Condition").or("")),
        expiry(req.header("X-Expiry").or(""), parseInt(req.header("X-Amount").or("0")).or(0))) else { return 413 }
    return response(200, body: value)
}
route POST "/poison" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let alias = connection
    let result = redisExecute(connection, req.bodyBytes)
    guard resultStatus(result) == 502 || resultStatus(result) == 504 else { return 500 }
    let sending = alias.send(b"must-not-arrive", 1000)
    guard sending == nil && netError() == -4 else { return 500 }
    return 204
}
func foundBytes(_ result: RedisGetResult) -> Bytes {
    match result { .value(data) => data _ => nil }
}
route POST "/recover" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisExecute(connection, req.bodyBytes)
    guard resultStatus(result) == parseInt(req.header("X-Status").or("409")).or(0) else { return 500 }
    let found = redisGet(connection, b"stable")
    let closed = connection.close()
    guard let data = foundBytes(found) else { return 500 }
    return response(200, body: data)
}
'''


def program(include_session):
    text = PROGRAM
    if not include_session:
        start = text.index('// One initialized business command')
        end = text.index('route POST "/set-options"', start)
        text = text[:start] + text[end:]
    for name in ('Del', 'Exists', 'Ttl', 'Pttl', 'Incr', 'Decr', 'Expire', 'Pexpire'):
        suffix = ', parseInt(req.header("X-Amount").or("0")).or(0)' if name in ('Expire', 'Pexpire') else ''
        text += f'''
route POST "/{name.lower()}" {{
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else {{ return 503 }}
    let result = redis{name}(connection, req.bodyBytes{suffix})
    let aliasSend = connection.close()
    let status = resultStatus(result)
    guard status != 502 || !aliasSend else {{ return 500 }}
    guard status != 409 else {{ return 409 }}
    guard status != 413 else {{ return 413 }}
    guard status != 504 else {{ return 504 }}
    guard let reply = resultReply(result) else {{ return 502 }}
    guard let number = redisInteger(reply) else {{ return 500 }}
    guard let digits = formatInt(number) else {{ return 500 }}
    let bytes = Bytes(digits)
    return response(200, body: bytes)
}}
'''
    return text


@contextlib.contextmanager
def gateway(args, endpoint, program_factory=program):
    with tempfile.TemporaryDirectory(prefix='rut-redis-commands-') as directory:
        root = Path(directory)
        for name in ('resp2.rut', 'resp2-command.rut', 'redis-client.rut'):
            shutil.copyfile(Path(args.library) / name, root / name)
        source, log = root / 'gateway.rut', root / 'server.log'
        text = program_factory(args.real_redis)
        if args.opt == '2':
            text = text.replace('import "redis-client.rut"', 'import * as client from "redis-client.rut"')
            names = set()
            for path in root.glob('*.rut'):
                names.update(re.findall(r'^(?:func|struct|variant) (\w+)', path.read_text(), re.M))
            text = re.sub(r'\b(' + '|'.join(sorted(names)) + r')\b', r'client.\1', text)
        source.write_text(text)
        env = dict(os.environ, REDIS_ENDPOINT=json.dumps(endpoint))
        with log.open('wb') as output:
            process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                                        '--opt', args.opt, '--no-pin', '--shards', '1', '--drain', '0'],
                                       env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                data = log.read_bytes()
                found = re.search(rb'Listening on port ([0-9]+) with', data)
                if found:
                    port = int(found[1])
                    break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and b'io_uring is unavailable' in data:
                        raise SystemExit(77)
                    raise AssertionError(data.decode(errors='replace'))
                time.sleep(.025)
            else:
                raise AssertionError(log.read_text(errors='replace'))
            for path in root.glob('*.rut'):
                path.unlink()
            def request(path, body=b'', headers=None):
                if path in ('integer', 'values'):
                    headers = dict(headers or {}, **{'X-Mode': path})
                    path = 'execute'
                client = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                try:
                    client.request('POST', '/' + path, body, headers or {})
                    response = client.getresponse()
                    return response.status, response.read()
                finally:
                    client.close()
            yield request
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def fixture_checks(request, peer):
    frames = [b'+OK\r\n', b'$0\r\n\r\n', b'$-1\r\n', b'*-1\r\n', b'*0\r\n',
              b'*3\r\n$4\r\na\x00\xffb\r\n*2\r\n:9223372036854775807\r\n-ERR nested\r\n$-1\r\n',
              b'*63\r\n' + b':1\r\n' * 63, b'*1\r\n' * 63 + b':0\r\n']
    for frame in frames:
        assert request('execute', packet([b'FIXTURE', frame])) == (200, frame), frame[:80]
    nested = frames[5]
    assert request('values', packet([b'FIXTURE', nested]), {'X-Index': '4'}) == (200, b'ERR nested')
    assert request('values', packet([b'FIXTURE', nested]), {'X-Index': '-1'})[0] == 422
    assert request('values', packet([b'FIXTURE', nested]), {'X-Index': '6'})[0] == 422
    assert request('execute', packet([b'FIXTURE', nested, b'fragments'])) == (200, nested)
    maximum = b'$8183\r\n' + b'x' * 8183 + b'\r\n'
    assert request('execute', packet([b'FIXTURE', b'', b'max-frame'])) == (200, maximum)
    for mode in (b'too-large', b'read-budget'):
        assert request('poison', packet([b'FIXTURE', b'', mode]))[0] == 204
    assert request('execute', packet([b'FIXTURE', b'+OK\r\n'] + [b''] * 61)) == (200, b'+OK\r\n')
    for number in (-(1 << 63), -2, -1, 0, (1 << 63) - 1):
        value = str(number).encode()
        assert request('integer', packet([b'FIXTURE', b':' + value + b'\r\n'])) == (200, value)
    assert request('integer', packet([b'FIXTURE', b'$1\r\n1\r\n']))[0] == 422
    malformed = [b':9223372036854775808\r\n', b':-9223372036854775809\r\n',
                 b':x\r\n', b'$1\r\nxXX', b'+bad\nline\r\n', b'$-2\r\n',
                 b'*64\r\n' + b':1\r\n' * 64, b'*2\r\n:1\r\n',
                 b'+OK\r\n+EXTRA\r\n', b'$8192\r\n']
    for frame in malformed:
        assert request('poison', packet([b'FIXTURE', frame]))[0] == 204, frame[:80]
    before = len(peer.observed)
    invalid = [b'', b'*0\r\n', b'*1\r\n$-1\r\n', b'*1\r\n:1\r\n',
               b'*1\r\n*1\r\n$4\r\nPING\r\n', packet([b'PING']) * 2,
               b'*64\r\n' + b'$1\r\nx\r\n' * 64]
    for frame in invalid:
        result = request('execute', frame)
        assert result[0] == 413, (frame[:80], result)
    assert len(peer.observed) == before, 'invalid request reached the socket'
    assert request('recover', b'*0\r\n', {'X-Status': '413'}) == (200, b'a\x00\xffb')
    assert request('recover', packet([b'FIXTURE', b'-ERR recoverable\r\n'])) == (200, b'a\x00\xffb')
    for mode, expected in ((b'timeout', 504), (b'eof', 502)):
        command = [b'FIXTURE', b'', mode]
        assert request('execute', packet(command))[0] == expected
        assert peer.observed.count(command) == 1, 'command was replayed'
    for name in ('del', 'exists', 'ttl', 'pttl', 'incr', 'decr', 'expire', 'pexpire'):
        assert request(name, b'wrong-type')[0] == 502
    assert request('set-options', b'wrong-type')[0] == 502
    assert request('set-options', b'value', {'X-Key': 'null-reply'})[0] == 502
    for condition in ('NX', 'XX'):
        assert request('set-options', b'value', {'X-Key': 'null-reply', 'X-Condition': condition})[0] == 412
    assert request('set-options', b'value', {'X-Key': 'ok-reply'})[0] == 204
    assert request('set-options', b'value', {'X-Key': 'error-reply'})[0] == 409


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
            assert request('build-options', arguments[2], headers) == (200, packet(arguments))
    for expiry in ('EX', 'PX'):
        headers = {'X-Expiry': expiry, 'X-Amount': '2147483647'}
        assert request('build-options', b'value', headers) == (
            200, packet([b'SET', b'options', b'value', expiry.encode(), b'2147483647']))
        for amount in ('0', '-1', '-2147483648'):
            headers = {'X-Expiry': expiry, 'X-Amount': amount}
            assert request('build-options', b'value', headers)[0] == 413
            assert request('set-options', b'value', headers)[0] == 413
    for expiry, tail in (('PX', [b'PX', b'1']), ('KEEPTTL', [b'KEEPTTL'])):
        headers = {'X-Condition': 'NX', 'X-Expiry': expiry, 'X-Amount': '1', 'X-Duplicate': 'yes'}
        maximum = max(n for n in range(4200)
                      if len(packet([b'SET', b'x' * n, b'x' * n, b'NX'] + tail)) <= 8192)
        assert request('build-options', b'x' * maximum, headers) == (
            200, packet([b'SET', b'x' * maximum, b'x' * maximum, b'NX'] + tail))
        assert request('build-options', b'x' * (maximum + 1), headers)[0] == 413
        assert request('set-options', b'x' * (maximum + 1), headers)[0] == 413


@contextlib.contextmanager
def real_redis(args):
    name = 'rut-redis-' + uuid.uuid4().hex
    docker = ['docker', 'create', '--name', name, '-p', '127.0.0.1::6379']
    settings = ['--save', '', '--appendonly', 'no']
    context = None
    if args.tls:
        settings += ['--port', '0', '--tls-port', '6379', '--tls-auth-clients', 'no',
                     '--tls-cert-file', '/tmp/localhost_cert.pem',
                     '--tls-key-file', '/tmp/localhost_key.pem',
                     '--tls-ca-cert-file', '/tmp/localhost_cert.pem']
        context = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem'))
    try:
        subprocess.run(docker + [REDIS_IMAGE, 'redis-server'] + settings, check=True, capture_output=True)
        if args.tls:
            # Copy public fixture material before startup. No host bind mounts
            # or host security-label changes are needed on SELinux systems.
            for filename in ('localhost_cert.pem', 'localhost_key.pem'):
                subprocess.run(['docker', 'cp', str(Path(args.testdata) / filename),
                                name + ':/tmp/' + filename], check=True, capture_output=True)
        subprocess.run(['docker', 'start', name], check=True, capture_output=True)
        info = json.loads(subprocess.check_output(['docker', 'inspect', name]))[0]
        assert info['State']['Running'] and info['NetworkSettings']['Ports'].get('6379/tcp'), (
            subprocess.check_output(['docker', 'logs', name], stderr=subprocess.STDOUT).decode(errors='replace'))
        port = int(info['NetworkSettings']['Ports']['6379/tcp'][0]['HostPort'])
        deadline = time.monotonic() + 15
        while True:
            try:
                connection = socket.create_connection(('127.0.0.1', port), timeout=2)
                if context:
                    connection = context.wrap_socket(connection, server_hostname='localhost')
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.05)
        with connection, connection.makefile('rb') as stream:
            def command(*arguments):
                connection.sendall(packet(list(arguments)))
                return read_value(stream)
            assert command(b'PING') == b'PONG'
            yield port, command
    finally:
        subprocess.run(['docker', 'rm', '-fv', name], check=False, capture_output=True)


def real_checks(request, command):
    keep_key = b'keep-ttl'
    for condition in ('', 'NX', 'XX'):
        assert command(b'SET', keep_key, b'original', b'PX', b'300000') == b'OK'
        deadline = command(b'PEXPIRETIME', keep_key)
        headers = {'X-Key': keep_key.decode(), 'X-Condition': condition, 'X-Expiry': 'KEEPTTL'}
        assert request('set-options', b'updated\x00\xff', headers)[0] == (412 if condition == 'NX' else 204)
        assert command(b'GET', keep_key) == (b'original' if condition == 'NX' else b'updated\x00\xff')
        assert command(b'PEXPIRETIME', keep_key) == deadline
        assert 0 < command(b'PTTL', keep_key) <= 300000
    assert request('set-options', b'persistent', {'X-Key': keep_key.decode()})[0] == 204
    assert command(b'PTTL', keep_key) == -1
    assert request('set-options', b'still-persistent', {
        'X-Key': keep_key.decode(), 'X-Expiry': 'KEEPTTL'})[0] == 204
    assert command(b'PTTL', keep_key) == -1
    assert command(b'DEL', keep_key) == 1
    assert request('set-options', b'missing', {
        'X-Key': keep_key.decode(), 'X-Condition': 'XX', 'X-Expiry': 'KEEPTTL'})[0] == 412
    assert command(b'EXISTS', keep_key) == 0
    for condition in ('', 'NX'):
        assert request('set-options', b'created', {
            'X-Key': keep_key.decode(), 'X-Condition': condition, 'X-Expiry': 'KEEPTTL'})[0] == 204
        assert command(b'GET', keep_key) == b'created'
        assert command(b'PTTL', keep_key) == -1
        assert command(b'DEL', keep_key) == 1
    key, value = b'options', b'a\x00\xff\r\n'
    assert request('set-options', value, {'X-Condition': 'NX', 'X-Expiry': 'EX', 'X-Amount': '100'})[0] == 204
    assert command(b'GET', key) == value
    assert 0 < command(b'TTL', key) <= 100
    assert request('set-options', b'rejected', {'X-Condition': 'NX'})[0] == 412
    assert command(b'GET', key) == value
    assert request('set-options', value, {'X-Condition': 'XX', 'X-Expiry': 'PX', 'X-Amount': '90000'})[0] == 204
    assert 0 < command(b'PTTL', key) <= 90000
    assert request('exists', key) == (200, b'1')
    assert request('pexpire', key, {'X-Amount': '60000'}) == (200, b'1')
    assert 0 < int(request('pttl', key)[1]) <= 60000
    assert request('expire', key, {'X-Amount': '80'}) == (200, b'1')
    assert 0 < int(request('ttl', key)[1]) <= 80
    assert request('set-options', b'persistent')[0] == 204
    assert request('ttl', key) == (200, b'-1')
    assert request('expire', key, {'X-Amount': '0'}) == (200, b'1')
    assert request('ttl', key) == (200, b'-2')
    assert request('set-options', b'missing', {'X-Condition': 'XX'})[0] == 412
    assert request('exists', key) == (200, b'0')
    assert request('expire', key, {'X-Amount': '-1'}) == (200, b'0')
    assert request('del', key) == (200, b'0')
    assert command(b'SET', key, b'2147483647') == b'OK'
    assert request('incr', key) == (200, b'2147483648')
    assert request('decr', key) == (200, b'2147483647')
    assert command(b'SET', key, b'9223372036854775807') == b'OK'
    assert request('incr', key)[0] == 409
    assert command(b'GET', key) == b'9223372036854775807'
    assert command(b'SET', key, b'-9223372036854775808') == b'OK'
    assert request('decr', key)[0] == 409
    assert command(b'GET', key) == b'-9223372036854775808'
    assert request('del', key) == (200, b'1')
    binary = b'key\x00\xff\r\n'
    assert request('execute', packet([b'SET', binary, value])) == (200, b'+OK\r\n')
    assert request('execute', packet([b'MGET', binary, b'absent'])) == (200, b'*2\r\n$5\r\na\x00\xff\r\n\r\n$-1\r\n')
    assert request('values', packet([b'MGET', binary, b'absent']), {'X-Index': '1'}) == (200, value)
    assert request('execute', packet([b'EVAL', b'return {1,{2,false},"x"}', b'0'])) == (
        200, b'*3\r\n:1\r\n*2\r\n:2\r\n$-1\r\n$1\r\nx\r\n')
    def clients():
        rows = [dict(field.split(b'=', 1) for field in line.split())
                for line in command(b'CLIENT', b'LIST').splitlines()]
        return {row[b'id']: row for row in rows}
    def wait_clients(predicate):
        deadline = time.monotonic() + 2
        while True:
            rows = clients()
            if predicate(rows):
                return rows
            assert time.monotonic() < deadline, rows
            time.sleep(.01)
    baseline = {str(command(b'CLIENT', b'ID')).encode()}
    wait_clients(lambda rows: set(rows) == baseline)
    assert command(b'ACL', b'SETUSER', b'alice', b'on', b'>secret', b'~*', b'+@all') == b'OK'
    assert request('authenticated', packet([b'SET', b'auth-key', value])) == (200, b'+OK\r\n')
    returned = wait_clients(lambda rows: len(rows) == 2)
    pooled = set(returned) - baseline
    assert len(pooled) == 1, returned
    identity = pooled.pop()
    assert returned[identity][b'user'] == b'default' and returned[identity][b'db'] == b'0'
    assert command(b'SELECT', b'2') == b'OK'
    assert command(b'GET', b'auth-key') == value
    assert command(b'SELECT', b'0') == b'OK'
    assert request('execute', packet([b'CLIENT', b'ID'])) == (200, b':' + identity + b'\r\n')
    wait_clients(lambda rows: identity not in rows)
    assert request('execute', packet([b'GET', b'auth-key'])) == (200, b'$-1\r\n')
    assert request('authenticated', packet([b'ACL', b'WHOAMI'])) == (200, b'$5\r\nalice\r\n')
    returned = wait_clients(lambda rows: len(rows) == 2)
    identity = (set(returned) - baseline).pop()
    assert returned[identity][b'user'] == b'default' and returned[identity][b'db'] == b'0'
    assert request('authenticated', packet([b'CLIENT', b'ID'])) == (200, b':' + identity + b'\r\n')
    assert identity in clients(), 'authenticated session did not reuse the idle physical connection'
    assert request('execute', packet([b'ACL', b'WHOAMI'])) == (200, b'$7\r\ndefault\r\n')
    wait_clients(lambda rows: identity not in rows)


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
            with gateway(args, policy(port)) as request:
                builder_checks(request)
                real_checks(request, command)
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                                    str(Path(args.testdata) / 'localhost_key.pem'))
        peer = Fixture(context)
        try:
            with gateway(args, policy(peer.port)) as request:
                builder_checks(request)
                fixture_checks(request, peer)
        finally:
            peer.close()
    print(f'PASS Redis commands {args.backend} O{args.opt} TLS={args.tls}; ' + ('Redis 7.2.11' if args.real_redis else 'wire oracle'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
