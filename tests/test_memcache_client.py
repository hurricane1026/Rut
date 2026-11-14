#!/usr/bin/env python3
"""Memcached client: independent hostile TCP/TLS peer and pinned real server."""
import argparse
import contextlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import uuid


# Official 1.6.45-alpine multi-platform manifest, resolved 2026-11-10.
# Test-only peer; the runtime and client library acquire no new dependency.
MEMCACHED_IMAGE = 'memcached@sha256:084fb554292d1447bc2c68b80c2331b98834514f56c866bc21a61be3c2ee376d'

PROGRAM = r'''import "memcache-client.rut"
func testKey(_ body: Bytes, _ text: str, _ useBody: bool) -> Bytes {
    if useBody { body } else { Bytes(text) }
}
func testValue(_ body: Bytes, _ duplicate: bool) {
    if duplicate { concatBytes(body, body, 8192) } else { body }
}
func testMode(_ name: str) -> MemcacheStoreMode {
    match name {
        "add" => MemcacheStoreMode.add
        "replace" => MemcacheStoreMode.replace
        _ => MemcacheStoreMode.set
    }
}
func getStatus(_ result: MemcacheGetResult) -> i32 {
    match result {
        .value(item) => 200
        .missing => 404
        .serverError(data) => 200
        .requestFailure => 400
        .replyFailure => 502
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
    }
}
func getBody(_ result: MemcacheGetResult) -> Bytes {
    match result {
        .value(item) => item.data
        .serverError(data) => data
        _ => b""
    }
}
func getFlags(_ result: MemcacheGetResult) -> Bytes {
    match result {
        .value(item) => item.flags
        .serverError(data) => b"E"
        _ => b""
    }
}
func finishGet(_ connection: TcpConnection, _ result: MemcacheGetResult) -> bool {
    if memcacheGetMustClose(result) { !connection.close() } else {
        let released = connection.release()
        true
    }
}
func storeStatus(_ result: MemcacheStoreResult) -> i32 {
    match result {
        .stored => 200
        .notStored => 409
        .serverError(data) => 200
        .requestFailure => 400
        .replyFailure => 502
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
    }
}
func storeBody(_ result: MemcacheStoreResult) -> Bytes {
    match result {
        .stored => b"STORED"
        .notStored => b"NOT_STORED"
        .serverError(data) => data
        _ => b""
    }
}
func finishStore(_ connection: TcpConnection, _ result: MemcacheStoreResult) -> bool {
    if memcacheStoreMustClose(result) { !connection.close() } else {
        let released = connection.release()
        true
    }
}
func commandStatus(_ result: MemcacheCommandResult) -> i32 {
    match result {
        .ok => 200
        .missing => 404
        .serverError(data) => 200
        .requestFailure => 400
        .replyFailure => 502
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
    }
}
func commandBody(_ result: MemcacheCommandResult) -> Bytes {
    match result {
        .ok => b"OK"
        .serverError(data) => data
        _ => b""
    }
}
func finishCommand(_ connection: TcpConnection, _ result: MemcacheCommandResult) -> bool {
    if memcacheCommandMustClose(result) { !connection.close() } else {
        let released = connection.release()
        true
    }
}
func commandExecute(_ connection: TcpConnection, _ mode: str, _ key: Bytes, _ seconds: i32) -> MemcacheCommandResult {
    if mode == "touch" { memcacheTouch(connection, key, seconds) }
    else { memcacheDelete(connection, key) }
}
func buildRequest(_ name: str, _ key: Bytes, _ value: Bytes, _ settings: MemcacheOptions) {
    match name {
        "get" => memcacheGetRequest(key)
        "delete" => memcacheDeleteRequest(key)
        "touch" => memcacheTouchRequest(key, settings.expirySeconds)
        _ => memcacheStoreRequest(testMode(name), key, value, settings)
    }
}
route POST "/get" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheGet(connection, testKey(req.bodyBytes, req.header("X-Key").or("key"),
        req.header("X-Key-Body").or("") == "yes"))
    let finished = finishGet(connection, result)
    let stale = connection.send(b"ILLEGAL\r\n", 1000)
    guard finished && stale == nil && netError() == -4 else { return 500 }
    let status = getStatus(result)
    guard status != 400 else { return 400 }
    guard status != 404 else { return 404 }
    guard status != 502 else { return 502 }
    guard status != 504 else { return 504 }
    guard let prefix = concatBytes(getFlags(result), b":", 8192) else { return 500 }
    guard let body = concatBytes(prefix, getBody(result), 8192) else { return 500 }
    return response(200, body: body)
}
route POST "/store" {
    guard let value = testValue(req.bodyBytes, req.header("X-Duplicate").or("") == "yes") else { return 400 }
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheStore(connection, testMode(req.header("X-Mode").or("set")),
        testKey(req.bodyBytes, req.header("X-Key").or("key"), req.header("X-Key-Body").or("") == "yes"),
        value, MemcacheOptions(flags: testKey(req.bodyBytes, req.header("X-Flags").or("0"),
            req.header("X-Flags-Body").or("") == "yes"),
            expirySeconds: parseInt(req.header("X-TTL").or("0")).or(-1)))
    let finished = finishStore(connection, result)
    guard finished else { return 500 }
    let status = storeStatus(result)
    guard status != 400 else { return 400 }
    guard status != 409 else { return response(409, body: "NOT_STORED") }
    guard status != 502 else { return 502 }
    guard status != 504 else { return 504 }
    let body = storeBody(result)
    return response(200, body: body)
}
route POST "/command" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let key = testKey(req.bodyBytes, req.header("X-Key").or("key"), req.header("X-Key-Body").or("") == "yes")
    let result = commandExecute(connection, req.header("X-Mode").or("delete"), key,
        parseInt(req.header("X-TTL").or("0")).or(-1))
    let finished = finishCommand(connection, result)
    guard finished else { return 500 }
    let status = commandStatus(result)
    guard status != 400 else { return 400 }
    guard status != 404 else { return 404 }
    guard status != 502 else { return 502 }
    guard status != 504 else { return 504 }
    let body = commandBody(result)
    return response(200, body: body)
}
route POST "/build" {
    guard let value = testValue(req.bodyBytes, req.header("X-Duplicate").or("") == "yes") else { return 400 }
    guard let packet = buildRequest(req.header("X-Mode").or("set"),
        testKey(req.bodyBytes, req.header("X-Key").or("key"), req.header("X-Key-Body").or("") == "yes"),
        value, MemcacheOptions(flags: testKey(req.bodyBytes, req.header("X-Flags").or("0"),
            req.header("X-Flags-Body").or("") == "yes"),
            expirySeconds: parseInt(req.header("X-TTL").or("0")).or(-1))) else { return 400 }
    return response(200, body: packet)
}
route POST "/sequence" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let first = memcacheGet(connection, b"fixture-binary")
    let second = memcacheGet(connection, b"fixture-empty")
    let closed = connection.close()
    guard getStatus(first) == 200 && getStatus(second) == 200 && closed else { return 500 }
    guard let prefix = concatBytes(getFlags(first), b":", 8192) else { return 500 }
    guard let body = concatBytes(prefix, getBody(first), 8192) else { return 500 }
    return response(200, body: body)
}
'''


def value_frame(key, data, flags=b'0'):
    return b'VALUE ' + key + b' ' + flags + b' %d\r\n' % len(data) + data + b'\r\nEND\r\n'


def store_packet(mode, key, data, flags=b'0', ttl=0):
    return mode + b' ' + key + b' ' + flags + b' %d %d\r\n' % (ttl, len(data)) + data + b'\r\n'


class Peer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, tls_context=None):
        self.tls_context = tls_context
        self.lock = threading.Lock()
        self.observed = []
        self.errors = []
        self.items = {}
        self.next_id = 0
        self.stopping = threading.Event()
        super().__init__(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def get_request(self):
        connection, address = super().get_request()
        if self.tls_context:
            connection = self.tls_context.wrap_socket(connection, server_side=True)
        return connection, address

    def close(self):
        self.stopping.set()
        self.shutdown()
        self.server_close()
        self.thread.join(2)
        assert not self.errors, self.errors


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        peer = self.server
        with peer.lock:
            peer.next_id += 1
            identity = peer.next_id
        self.connection.settimeout(8)
        try:
            while not peer.stopping.is_set():
                line = self.rfile.readline(8193)
                if not line:
                    return
                assert line.endswith(b'\r\n'), line
                parts = line[:-2].split(b' ')
                name, key = parts[:2]
                data = None
                if name in (b'set', b'add', b'replace'):
                    assert len(parts) == 5
                    data = self.rfile.read(int(parts[4]))
                    assert len(data) == int(parts[4]) and self.rfile.read(2) == b'\r\n'
                with peer.lock:
                    peer.observed.append((identity, parts, data))
                if key.startswith(b'fixture-'):
                    if not self.fixture(name, key, identity):
                        return
                    continue
                with peer.lock:
                    item = peer.items.get(key)
                    if item and item[2] and item[2] <= time.monotonic():
                        item = None
                        del peer.items[key]
                    if name == b'get':
                        reply = value_frame(key, item[0], item[1]) if item else b'END\r\n'
                    elif name in (b'set', b'add', b'replace'):
                        if name == b'add' and item or name == b'replace' and not item:
                            reply = b'NOT_STORED\r\n'
                        else:
                            ttl = int(parts[3])
                            peer.items[key] = (data, parts[2], time.monotonic() + ttl if ttl else 0)
                            reply = b'STORED\r\n'
                    elif name == b'delete':
                        reply = b'DELETED\r\n' if item else b'NOT_FOUND\r\n'
                        peer.items.pop(key, None)
                    elif name == b'touch':
                        reply = b'TOUCHED\r\n' if item else b'NOT_FOUND\r\n'
                        if item:
                            ttl = int(parts[2])
                            peer.items[key] = (*item[:2], time.monotonic() + ttl if ttl else 0)
                    else:
                        raise AssertionError(parts)
                self.connection.sendall(reply)
        except (OSError, ssl.SSLError):
            pass
        except Exception as error:
            peer.errors.append(error)

    def fixture(self, name, key, identity):
        if key == b'fixture-timeout':
            self.server.stopping.wait(1.3)
            return True
        if key == b'fixture-eof':
            return False
        if key == b'fixture-truncated':
            self.connection.sendall(b'VALUE fixture-truncated 0 4\r\na')
            return False
        binary = b'a\x00\xff\r\nEND\r\nz'
        reply = value_frame(key, binary, b'4294967295')
        if key == b'fixture-id':
            reply = value_frame(key, str(identity).encode())
        elif key == b'fixture-empty':
            reply = value_frame(key, b'')
        elif key == b'fixture-missing':
            reply = b'END\r\n' if name == b'get' else b'NOT_FOUND\r\n'
        elif key == b'fixture-error':
            reply = b'ERROR\r\n'
        elif key == b'fixture-client-error':
            reply = b'CLIENT_ERROR fixture\r\n'
        elif key == b'fixture-server-error':
            reply = b'SERVER_ERROR fixture\r\n'
        elif key == b'fixture-wrong-key':
            reply = value_frame(b'other', b'value')
        elif key == b'fixture-extra':
            reply += b'STORED\r\n'
        elif key == b'fixture-two-values':
            reply = reply[:-5] + reply
        elif key == b'fixture-wrong-type':
            reply = b'STORED\r\n' if name in (b'get', b'delete', b'touch') else b'END\r\n'
        elif key in (b'fixture-max', b'fixture-too-large'):
            size = max(n for n in range(8193) if len(value_frame(key, b'x' * n)) <= 8192)
            reply = value_frame(key, b'x' * (size + (key == b'fixture-too-large')))
        elif key in (b'fixture-negative-flags', b'fixture-plus-flags', b'fixture-overflow-flags'):
            flags = {b'fixture-negative-flags': b'-1', b'fixture-plus-flags': b'+1',
                     b'fixture-overflow-flags': b'4294967296'}[key]
            reply = value_frame(key, b'value', flags)
        elif key in (b'fixture-negative-size', b'fixture-plus-size', b'fixture-overflow-size', b'fixture-cas'):
            size = {b'fixture-negative-size': b'-1', b'fixture-plus-size': b'+1',
                    b'fixture-overflow-size': b'2147483648', b'fixture-cas': b'1 123'}[key]
            reply = b'VALUE ' + key + b' 0 ' + size + b'\r\nx\r\nEND\r\n'
        elif key == b'fixture-bare-lf':
            reply = b'VALUE ' + key + b'\n 0 1\r\nx\r\nEND\r\n'
        elif key == b'fixture-bad-terminator':
            reply = reply[:-7] + b'XXEND\r\n'
        if key == b'fixture-fragments':
            end = reply.index(b'\r\n')
            for chunk in (reply[:end + 1], reply[end + 1:-7], reply[-7:]):
                self.connection.sendall(chunk)
                time.sleep(.04)
        elif key == b'fixture-read-budget':
            for chunk in (b'V', b'A', b'L', b'U', reply[4:]):
                self.connection.sendall(chunk)
                time.sleep(.08)
        else:
            self.connection.sendall(reply)
        return True


@contextlib.contextmanager
def gateway(args, endpoint, program_factory=None, extra_libraries=(), entrypoint="memcache-client.rut"):
    with tempfile.TemporaryDirectory(prefix='rut-memcache-') as directory:
        root = Path(directory)
        for name in ('memcache-codec.rut', 'memcache-client.rut', *extra_libraries):
            shutil.copyfile(Path(args.library) / name, root / name)
        if program_factory is not None:
            program = program_factory()
        elif args.example:
            program = Path(args.example).read_text().replace('"clients/memcache-client.rut"',
                                                            '"memcache-client.rut"')
        else:
            program = PROGRAM
        if args.opt == '2':
            program = program.replace('import "' + entrypoint + '"',
                                      'import * as client from "' + entrypoint + '"')
            names = set()
            for path in root.glob('*.rut'):
                names.update(re.findall(r'^(?:func|struct|variant) (\w+)', path.read_text(), re.M))
            program = re.sub(r'\b(' + '|'.join(sorted(names)) + r')\b', r'client.\1', program)
        source, log = root / 'gateway.rut', root / 'server.log'
        source.write_text(program)
        env = dict(os.environ, MEMCACHE_ENDPOINT=json.dumps(endpoint))
        with log.open('wb') as output:
            process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                                        '--opt', args.opt, '--no-pin', '--shards', '1', '--drain', '0'],
                                       env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        children = {}
        peak_compiler_kib = 0

        def birth(pid):
            try:
                return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
            except FileNotFoundError:
                return None

        try:
            deadline = time.monotonic() + 270
            while time.monotonic() < deadline:
                child_file = Path(f'/proc/{process.pid}/task/{process.pid}/children')
                try:
                    child_ids = child_file.read_text().split()
                except FileNotFoundError:
                    child_ids = []
                for pid in child_ids:
                    children.setdefault(pid, birth(pid))
                    try:
                        status = Path(f'/proc/{pid}/status').read_text()
                    except FileNotFoundError:
                        continue
                    rss = re.search(r'^VmRSS:\s+(\d+) kB$', status, re.M)
                    if rss:
                        peak_compiler_kib = max(peak_compiler_kib, int(rss[1]))
                assert peak_compiler_kib <= 8 * 1024 * 1024, 'compiler startup exceeded 8 GiB RSS'
                text = log.read_bytes()
                found = re.search(rb'Listening on port ([0-9]+) with', text)
                if found:
                    port = int(found[1])
                    print(f'Gateway startup peak compiler RSS: {peak_compiler_kib} KiB', flush=True)
                    break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and b'io_uring is unavailable' in text:
                        raise SystemExit(77)
                    raise AssertionError(text.decode(errors='replace'))
                time.sleep(.025)
            else:
                raise AssertionError('gateway startup exceeded 270s:\n' + log.read_text(errors='replace'))
            for path in root.glob('*.rut'):
                path.unlink()

            def request(path, body=b'', headers=None):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                try:
                    connection.request('POST', '/' + path, body, headers or {})
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            yield request
        finally:
            for pid, started in children.items():
                if started is not None and birth(pid) == started:
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(int(pid), signal.SIGTERM)
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            for pid, started in children.items():
                if started is not None and birth(pid) == started:
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(int(pid), signal.SIGKILL)


def builder_checks(request):
    for mode in ('set', 'add', 'replace'):
        for flags in (b'0', b'4294967295'):
            for ttl in (0, 2592000):
                data = b'a\x00\xff\r\nEND\r\nz'
                headers = {'X-Mode': mode, 'X-Flags': flags.decode(), 'X-TTL': str(ttl)}
                assert request('build', data, headers) == (200, store_packet(mode.encode(), b'key', data, flags, ttl))
    for mode in ('get', 'delete', 'touch'):
        tail = b' 2592000' if mode == 'touch' else b''
        assert request('build', headers={'X-Mode': mode, 'X-TTL': '2592000'}) == (
            200, mode.encode() + b' key' + tail + b'\r\n')
    for key in (b'', b'x' * 251, *(b'x' * (i % 249) + bytes((i,)) + b'x' for i in (*range(33), 127))):
        headers = {'X-Mode': 'get', 'X-Key-Body': 'yes'}
        assert request('build', key, headers)[0] == 400, key
        assert request('get', key, headers)[0] == 400, key
    for key in (b'x' * 250, b'\x80\xffkey'):
        assert request('build', key, {'X-Mode': 'get', 'X-Key-Body': 'yes'}) == (200, b'get ' + key + b'\r\n')
    for position in (63, 64, 127, 128, 248, 249):
        for byte in (0, 32, 127):
            key = b'x' * position + bytes((byte,)) + b'x' * (249 - position)
            assert request('get', key, {'X-Key-Body': 'yes'})[0] == 400
    for flags in ('', '-1', '+1', '4294967296', '1 0', '1x'):
        assert request('build', b'v', {'X-Flags': flags})[0] == 400
        assert request('store', b'v', {'X-Flags': flags})[0] == 400
    for flags in (b'0\r\n', b'0\x00', b'\xff', b'0 1'):
        assert request('build', flags, {'X-Flags-Body': 'yes'})[0] == 400
        assert request('store', flags, {'X-Flags-Body': 'yes'})[0] == 400
    for ttl in ('-1', '2592001', '2147483647'):
        assert request('build', b'v', {'X-TTL': ttl})[0] == 400
        assert request('store', b'v', {'X-TTL': ttl})[0] == 400
        assert request('command', headers={'X-Mode': 'touch', 'X-TTL': ttl})[0] == 400
    for key in (b'limit', b'limits'):
        maximum = max(n for n in range(4097) if len(store_packet(b'set', key, b'x' * (2 * n))) <= 8192)
        headers = {'X-Key': key.decode(), 'X-Duplicate': 'yes'}
        assert request('build', b'x' * maximum, headers) == (200, store_packet(b'set', key, b'x' * (2 * maximum)))
        assert request('build', b'x' * (maximum + 1), headers)[0] == 400
        assert request('store', b'x' * (maximum + 1), headers)[0] == 400


def ordinary_checks(request):
    assert request('get')[0] == 404
    assert request('store', b'old\x00\xff', {'X-Flags': '4294967295'}) == (200, b'STORED')
    assert request('get') == (200, b'4294967295:old\x00\xff')
    assert request('store', b'other', {'X-Mode': 'add'}) == (409, b'NOT_STORED')
    assert request('get') == (200, b'4294967295:old\x00\xff')
    assert request('store', b'', {'X-Mode': 'replace'}) == (200, b'STORED')
    assert request('get') == (200, b'0:')
    assert request('command', headers={'X-Mode': 'touch'}) == (200, b'OK')
    assert request('command') == (200, b'OK')
    assert request('command')[0] == 404
    assert request('command', headers={'X-Mode': 'touch'})[0] == 404
    assert request('store', b'other', {'X-Mode': 'replace'}) == (409, b'NOT_STORED')
    assert request('store', b'a\x00\xff\r\nEND\r\nz', {'X-Mode': 'add', 'X-TTL': '2592000'}) == (200, b'STORED')
    assert request('get') == (200, b'0:a\x00\xff\r\nEND\r\nz')
    assert request('command') == (200, b'OK')
    key = b'\x80\xffkey'
    assert request('store', key, {'X-Key-Body': 'yes'}) == (200, b'STORED')
    assert request('get', key, {'X-Key-Body': 'yes'}) == (200, b'0:' + key)
    assert request('command', key, {'X-Key-Body': 'yes'}) == (200, b'OK')


def hostile_checks(request, peer):
    identity = request('get', headers={'X-Key': 'fixture-id'})
    assert identity[0] == 200
    assert request('get', headers={'X-Key': 'fixture-id'}) == identity
    assert request('sequence') == (200, b'4294967295:a\x00\xff\r\nEND\r\nz')
    assert peer.observed[-2][0] == peer.observed[-1][0]
    for name, expected in (('binary', b'4294967295:a\x00\xff\r\nEND\r\nz'),
                           ('empty', b'0:'), ('fragments', b'4294967295:a\x00\xff\r\nEND\r\nz')):
        assert request('get', headers={'X-Key': 'fixture-' + name}) == (200, expected)
    key = b'fixture-max'
    size = max(n for n in range(8193) if len(value_frame(key, b'x' * n)) <= 8192)
    assert request('get', headers={'X-Key': key.decode()}) == (200, b'0:' + b'x' * size)
    assert request('get', headers={'X-Key': 'fixture-missing'})[0] == 404
    for name, line in (('error', b'ERROR'), ('client-error', b'CLIENT_ERROR fixture'),
                       ('server-error', b'SERVER_ERROR fixture')):
        for operation in ('get', 'store', 'command'):
            key = 'fixture-' + name
            # Test-only 200 bodies expose the typed server-error bytes. The
            # executable user example maps this outcome to HTTP 503 instead.
            expected = b'E:' + line if operation == 'get' else line
            assert request(operation, b'value', {'X-Key': key}) == (200, expected)
    for name in ('wrong-key', 'extra', 'two-values', 'wrong-type', 'too-large', 'negative-flags',
                 'plus-flags', 'overflow-flags', 'negative-size', 'plus-size', 'overflow-size',
                 'cas', 'bare-lf', 'bad-terminator', 'read-budget', 'truncated', 'eof', 'timeout'):
        key = ('fixture-' + name).encode()
        before = sum(parts[1] == key for _, parts, _ in peer.observed)
        assert request('get', headers={'X-Key': key.decode()})[0] == (504 if name == 'timeout' else 502), name
        assert sum(parts[1] == key for _, parts, _ in peer.observed) == before + 1, name
    for operation, headers in (('store', {}), ('command', {}), ('command', {'X-Mode': 'touch'})):
        assert request(operation, b'value', dict(headers, **{'X-Key': 'fixture-wrong-type'}))[0] == 502
    assert request('get', headers={'X-Key': 'fixture-id'}) != identity
    assert not any(parts[0] == b'ILLEGAL' for _, parts, _ in peer.observed)
    assert not any(not parts[1] or len(parts[1]) > 250 or any(c <= 32 or c == 127 for c in parts[1])
                   for _, parts, _ in peer.observed)


@contextlib.contextmanager
def real_memcached(args):
    name = 'rut-memcache-' + uuid.uuid4().hex
    settings = ['memcached', '-m', '16', '-U', '0']
    if args.tls:
        settings += ['-Z', '-o', 'ssl_chain_cert=/tmp/localhost_cert.pem,ssl_key=/tmp/localhost_key.pem']
    try:
        subprocess.run(['docker', 'create', '--name', name, '-p', '127.0.0.1::11211',
                        MEMCACHED_IMAGE, *settings], check=True, capture_output=True)
        if args.tls:
            for filename in ('localhost_cert.pem', 'localhost_key.pem'):
                subprocess.run(['docker', 'cp', str(Path(args.testdata) / filename),
                                name + ':/tmp/' + filename], check=True, capture_output=True)
        subprocess.run(['docker', 'start', name], check=True, capture_output=True)
        info = json.loads(subprocess.check_output(['docker', 'inspect', name]))[0]
        port = int(info['NetworkSettings']['Ports']['11211/tcp'][0]['HostPort'])
        context = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem')) if args.tls else None
        for _ in range(200):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2) as connection:
                    if context:
                        connection = context.wrap_socket(connection, server_hostname='localhost')
                    with connection:
                        connection.sendall(b'version\r\n')
                        assert connection.recv(128).startswith(b'VERSION 1.6.45'), 'unexpected Memcached version'
                break
            except OSError:
                time.sleep(.025)
        else:
            raise AssertionError(subprocess.check_output(['docker', 'logs', name], stderr=subprocess.STDOUT))
        yield port
    finally:
        subprocess.run(['docker', 'rm', '-fv', name], check=False, capture_output=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--real-memcached', action='store_true')
    parser.add_argument('--example')
    args = parser.parse_args()
    context = None
    if args.tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                                str(Path(args.testdata) / 'localhost_key.pem'))

    def policy(port):
        result = dict(address='127.0.0.1', port=port, poolIdleMs=5000)
        if args.tls:
            result.update(tls=True, caFile=str(Path(args.testdata).resolve() / 'localhost_cert.pem'), serverName='localhost')
        return result

    if args.real_memcached:
        with real_memcached(args) as port, gateway(args, policy(port)) as request:
            builder_checks(request)
            ordinary_checks(request)
            assert request('store', b'v', {'X-Key': 'expiring', 'X-TTL': '2'})[0] == 200
            assert request('command', headers={'X-Key': 'expiring', 'X-Mode': 'touch', 'X-TTL': '2'})[0] == 200
            time.sleep(3.1)
            assert request('get', headers={'X-Key': 'expiring'})[0] == 404
    else:
        peer = Peer(context)
        try:
            with gateway(args, policy(peer.server_address[1])) as request:
                if args.example:
                    assert request('get', b'missing')[0] == 404
                    assert request('set', b'a\x00\xff\r\nEND\r\nz')[0] == 204
                    assert request('get', b'example-key') == (200, b'a\x00\xff\r\nEND\r\nz')
                    assert request('get', b'invalid key')[0] == 400
                    assert request('get', b'fixture-wrong-type')[0] == 502
                    assert request('get', b'fixture-server-error')[0] == 503
                else:
                    builder_checks(request)
                    ordinary_checks(request)
                    hostile_checks(request, peer)
        finally:
            peer.close()
    print(f'Memcached client passed ({args.backend}, O{args.opt}, tls={args.tls}, real={args.real_memcached})')


if __name__ == '__main__':
    main()
