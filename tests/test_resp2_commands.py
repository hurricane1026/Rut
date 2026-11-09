#!/usr/bin/env python3
"""Independent RESP2 command oracle and request-scoped Redis client fixture."""
import argparse
import http.client
import os
from pathlib import Path
import random
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time

PROGRAM = r'''import "padding.rut"
import "redis-client.rut"
func setOk(_ result: RedisSetResult) -> bool {
    match result { .ok => true _ => false }
}
func getValue(_ result: RedisGetResult) -> Bytes {
    match result { .value(bytes) => bytes _ => nil }
}
func getError(_ result: RedisGetResult) -> Bytes {
    match result { .serverError(bytes) => bytes _ => nil }
}
func replyFailed(_ result: RedisGetResult) -> bool {
    match result { .replyFailure => true _ => false }
}
route POST "/roundtrip" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let written = redisSet(connection, b"roundtrip\x00\xff", req.bodyBytes)
    guard setOk(written) else { return 502 }
    let found = redisGet(connection, b"roundtrip\x00\xff")
    guard let value = getValue(found) else { return 502 }
    let closed = connection.close()
    return response(200, body: value)
}
route POST "/poison" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let found = redisGet(connection, b"__bad_get")
    guard replyFailed(found) else { return 500 }
    let sending = connection.send(b"must-not-arrive", 1000)
    guard sending == nil && netError() == -4 else { return 500 }
    return 204
}
route POST "/recover" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let first = redisGet(connection, b"__error")
    let second = redisGet(connection, b"stable")
    guard let value = getValue(second) else { return 502 }
    guard let reason = getError(first) else { return 500 }
    guard reason == b"WRONGTYPE fixture" else { return 500 }
    let closed = connection.close()
    return response(200, body: value)
}
func setRequestFailed(_ result: RedisSetResult) -> bool {
    match result { .requestFailure => true _ => false }
}
route POST "/oversized" {
    let opening = tcp(env("REDIS_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = redisSet(connection, req.bodyBytes, req.bodyBytes)
    guard setRequestFailed(result) else { return 500 }
    let closed = connection.close()
    return 413
}
route POST "/build" {
    guard let key = req.bodyBytes.slice(0, parseInt(req.header("X-Cut").or("0")).or(-1)) else { return 400 }
    guard let value = req.bodyBytes.slice(key.count, req.bodyBytes.count) else { return 400 }
    guard let packet = resp2SetRequest(key, value) else { return 413 }
    return response(200, body: packet)
}
route POST "/builder" {
    guard let initial = resp2Command(parseInt(req.header("X-Count").or("1")).or(-1), parseInt(req.header("X-Limit").or("8192")).or(-1)) else { return 413 }
    guard resp2Request(initial) == nil else { return 500 }
    guard let first = resp2Argument(initial, req.bodyBytes) else { return 413 }
    guard let packet = resp2Request(first) else { return 409 }
    guard resp2Argument(first, b"extra") == nil else { return 500 }
    guard initial.packet == b"*1\r\n" else { return 500 }
    return response(200, body: packet)
}
route POST "/format" {
    guard let value = parseInt64(req.bodyBytes) else { return 400 }
    guard let text = formatInt(value) else { return 503 }
    let bytes = Bytes(text)
    return response(200, body: bytes)
}
route POST "/view" {
    let bytes = Bytes(req.body)
    guard Bytes(bytes) == req.bodyBytes else { return 500 }
    return response(200, body: bytes)
}
'''


def packet(arguments):
    return b'*' + str(len(arguments)).encode() + b'\r\n' + b''.join(
        b'$' + str(len(arg)).encode() + b'\r\n' + arg + b'\r\n' for arg in arguments)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--example', required=True)
    parser.add_argument('--backend', required=True)
    parser.add_argument('--opt', required=True)
    args = parser.parse_args()
    peer = socket.socket()
    peer.bind(('127.0.0.1', 0)); peer.listen(); peer.settimeout(.2)
    stopped = threading.Event()
    storage = {b'stable': b'retained\x00\xff'}
    lock = threading.Lock()
    errors, observed, threads = [], [], []
    def serve(connection):
        stream = connection.makefile('rb')
        try:
            connection.settimeout(4)
            while not stopped.is_set():
                header = stream.readline(64)
                if not header: break
                assert re.fullmatch(rb'\*[1-9][0-9]*\r\n', header), header
                count = int(header[1:]); assert 1 <= count <= 63
                wire, arguments = header, []
                for _ in range(count):
                    length_line = stream.readline(64)
                    assert re.fullmatch(rb'\$[0-9]+\r\n', length_line), length_line
                    length = int(length_line[1:]); assert length <= 8192
                    data = stream.read(length); ending = stream.read(2)
                    assert len(data) == length and ending == b'\r\n'
                    arguments.append(data); wire += length_line + data + ending
                assert wire == packet(arguments)
                with lock: observed.append(tuple(arguments))
                name, key = arguments[:2]
                if key == b'__timeout': time.sleep(1.3); return
                if key == b'__eof': connection.sendall(b'$3\r\nx'); return
                if key == b'__bad_get': reply = b'+OK\r\n'
                elif key == b'__bad_set': reply = b'+PONG\r\n'
                elif key == b'__nil_array': reply = b'*-1\r\n'
                elif key == b'__array': reply = b'*1\r\n$1\r\nx\r\n'
                elif key == b'__integer': reply = b':42\r\n'
                elif key == b'__bad_int': reply = b':9223372036854775808\r\n'
                elif key == b'__bulk_ok': reply = b'$2\r\nOK\r\n'
                elif key == b'__oversized': reply = b'$8192\r\n'
                elif key == b'__fragments': reply = b'$4\r\na\x00\xffb\r\n'
                elif key == b'__error': reply = b'-WRONGTYPE fixture\r\n'
                elif name == b'SET':
                    assert len(arguments) == 3
                    with lock: storage[key] = arguments[2]
                    reply = b'+OK\r\n'
                else:
                    assert name == b'GET' and len(arguments) == 2
                    with lock: value = storage.get(key)
                    reply = b'$-1\r\n' if value is None else b'$'+str(len(value)).encode()+b'\r\n'+value+b'\r\n'
                # Force a parser state to survive at least one more I/O wait.
                if key == b'__fragments':
                    for part in (reply[:1],reply[1:4],reply[4:7],reply[7:]):
                        connection.sendall(part); time.sleep(.04)
                else:
                    connection.sendall(reply[:1]); time.sleep(.04); connection.sendall(reply[1:])
        except (BrokenPipeError, ConnectionResetError, TimeoutError): pass
        except Exception as exc: errors.append(exc)
        finally:
            stream.close(); connection.close()
    def accept():
        while not stopped.is_set():
            try: connection, _ = peer.accept()
            except socket.timeout: continue
            except OSError: return
            worker = threading.Thread(target=serve, args=(connection,), daemon=True)
            threads.append(worker); worker.start()
    accepting = threading.Thread(target=accept, daemon=True); accepting.start()
    with tempfile.TemporaryDirectory(prefix='rut-resp2-commands-') as directory:
        root = Path(directory)
        for name in ('resp2.rut', 'resp2-command.rut', 'redis-client.rut'):
            shutil.copyfile(Path(args.library)/name, root/name)
        (root/'padding.rut').write_text('struct Padding { marker: i32 }\nvariant PaddingKind { absent }\n')
        example = Path(args.example).read_text().replace('import "clients/redis-client.rut"', '')
        example = example.replace('b"example-key", req.bodyBytes', 'Bytes(req.header("X-Key").or("example-key")), req.bodyBytes')
        source, log = root/'gateway.rut', root/'server.log'
        program = PROGRAM + example
        if args.opt == '2':
            program = program.replace('import "redis-client.rut"', 'import * as client from "redis-client.rut"')
            for name in ('RedisGetResult', 'RedisSetResult'):
                program = program.replace(name, 'client.'+name)
            for name in ('redisGet', 'redisSet', 'resp2SetRequest', 'resp2Command', 'resp2Request', 'resp2Argument'):
                program = program.replace(name+'(', 'client.'+name+'(')
        source.write_text(program)
        environment = dict(os.environ, REDIS_ENDPOINT='{"address":"127.0.0.1","port":%d}' % peer.getsockname()[1])
        with log.open('wb') as output:
            process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend, '--opt', args.opt,
                '--no-pin', '--shards', '1', '--drain', '0'], env=environment, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+180
            while time.monotonic() < deadline:
                data = log.read_bytes(); match = re.search(rb'Listening on port ([0-9]+) with', data)
                if match: port = int(match[1]); break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and b'io_uring is unavailable' in data: return 77
                    raise AssertionError(data.decode(errors='replace'))
                time.sleep(.025)
            else: raise AssertionError(log.read_text(errors='replace'))
            for path in root.glob('*.rut'): path.unlink()
            calls = 0
            def request(path, body=b'', headers=None):
                nonlocal calls
                calls += 1
                client = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                try:
                    client.request('POST', '/'+path, body, headers or {})
                    response = client.getresponse(); return response.status, response.read()
                finally: client.close()
            rng = random.Random(1050)
            for value in [0,1,-1,-(1<<63),(1<<63)-1]+[rng.randrange(-(1<<63),1<<63) for _ in range(80)]:
                assert request('format', str(value).encode()) == (200,str(value).encode())
            for key, value in [(b'',b''),(b'a\x00\xff',b'\r\n*2\r\n$3\r\nGET\r\n$1\r\nx\r\n')]+[
                (rng.randbytes(rng.randrange(80)),rng.randbytes(rng.randrange(512))) for _ in range(30)]:
                assert request('build', key+value, {'X-Cut':str(len(key))}) == (200,packet([b'SET',key,value]))
                assert request('view', key+value) == (200,key+value)
            assert request('builder',b'a\x00\xff') == (200,packet([b'a\x00\xff']))
            assert request('builder',b'',{'X-Count':'2'})[0] == 409
            for count in ('0','64','-1'):
                assert request('builder',b'',{'X-Count':count})[0] == 413
            assert request('builder',b'x',{'X-Limit':'4'})[0] == 413
            # Largest SET value for the fixed example key under the send cap.
            def size(n): return len(packet([b'SET',b'example-key',b'x'*n]))
            maximum = max(n for n in range(8193) if size(n) <= 8192)
            key = b'example-key'
            wire = packet([b'SET',key,b'x'*maximum])
            assert request('build',key+b'x'*maximum,{'X-Cut':str(len(key))}) == (200,wire)
            assert request('build',key+b'x'*(maximum+1),{'X-Cut':str(len(key))})[0] == 413
            assert request('set',b'x'*7000)[0] == 204
            before = len(observed)
            assert request('oversized',b'x'*4200)[0] == 413
            assert len(observed) == before, 'oversized construction wrote a command'
            for value in (b'',b'a\x00\xff',bytes(range(256)),rng.randbytes(1000)):
                assert request('roundtrip',value) == (200,value)
            assert request('get',b'absent')[0] == 404
            assert request('get',b'stable') == (200,b'retained\x00\xff')
            assert request('get',b'__error')[0] == 502
            assert request('get',b'__bad_get')[0] == 502
            for key in (b'__nil_array',b'__array',b'__integer',b'__bad_int',b'__oversized'):
                assert request('get',key)[0] == 502, key
            assert request('get',b'__fragments') == (200,b'a\x00\xffb')
            assert request('set',b'value',{'X-Key':'__bulk_ok'})[0] == 502
            assert request('poison')[0] == 204
            assert request('recover') == (200,b'retained\x00\xff')
            assert request('set',b'value',{'X-Key':'__error'})[0] == 502
            assert request('set',b'value',{'X-Key':'__bad_set'})[0] == 502
            assert request('set',b'value',{'X-Key':'__timeout'})[0] == 504
            assert request('set',b'value',{'X-Key':'__eof'})[0] == 502
            assert request('get',b'__timeout')[0] == 504
            assert request('get',b'__eof')[0] == 502
            with lock:
                assert sum(cmd == (b'GET',b'__timeout') for cmd in observed) == 1
                assert sum(cmd == (b'GET',b'__eof') for cmd in observed) == 1
                assert sum(cmd[:2] == (b'SET',b'__timeout') for cmd in observed) == 1
            assert not errors,errors
            print('PASS %s O%s: %d formatter/builder/client checks; source removal and same-connection SET/GET' % (args.backend,args.opt,calls))
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
            stopped.set(); peer.close(); accepting.join(timeout=2)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
