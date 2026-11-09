#!/usr/bin/env python3
"""Independent RESP2 split-point oracle and real TCP continuation checks."""
import argparse
import http.client
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from test_bounded_parsing import reference, encode

PROGRAM = r'''import "resp2-stream.rut"
route POST "/feed" {
    let cut = parseInt(req.header("X-Cut").or("0")).or(-1)
    let limit = parseInt(req.header("X-Limit").or("8192")).or(-1)
    guard let initial = resp2Stream(limit) else { return 413 }
    guard let stream = resp2Feed(initial, req.bodyBytes) else { return 413 }
    guard stream.cursor.status == parseInt(req.header("X-Status").or("1")).or(9) else { return 422 }
    guard stream.cursor.offset == parseInt(req.header("X-Consumed").or("0")).or(-1) else { return 423 }
    guard resp2Finished(stream) == (req.header("X-Finished").or("1") == "1") else { return 424 }
    let buffered = stream.bytes
    return response(200, body: buffered)
}
route POST "/item" {
    let cut = parseInt(req.header("X-Cut").or("0")).or(-1)
    guard let initial = resp2Stream(8192) else { return 500 }
    guard let stream = resp2Feed(initial, req.bodyBytes) else { return 413 }
    guard let values = resp2Result(stream) else { return 400 }
    guard values.count == parseInt(req.header("X-Count").or("0")).or(-1) else { return 422 }
    guard let token = values.get(parseInt(req.header("X-Index").or("0")).or(-1)) else { return 416 }
    guard token.kind == parseInt(req.header("X-Kind").or("0")).or(-1) &&
          token.next == parseInt(req.header("X-Next").or("0")).or(-1) &&
          token.children == parseInt(req.header("X-Children").or("0")).or(-1) else { return 422 }
    let payload = token.data
    return response(200, body: payload)
}
route POST "/remainder" {
    guard let initial = resp2Stream(8192) else { return 500 }
    guard let stream = resp2Feed(initial, req.bodyBytes) else { return 413 }
    guard let tail = resp2Remainder(stream) else { return 400 }
    return response(200, body: tail)
}
route POST "/auto" {
    let opening = tcp(env("RESP2_TEST_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let sending = connection.send(req.bodyBytes, 1000)
    guard let sent = sending else { return 502 }
    guard let initial = resp2Stream(8192) else { return 500 }
    let first = resp2Receive(connection, initial)
    guard let stream = first else { return 502 }
    let second = resp2Receive(connection, stream)
    guard let final = second else { return 502 }
    guard resp2Finished(final) else { return 400 }
    guard let values = resp2Result(final) else { return 422 }
    guard let token = values.get(0) else { return 500 }
    let closed = connection.close()
    let payload = token.data
    return response(200, body: payload)
}
route POST "/network" {
    let opening = tcp(env("RESP2_TEST_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let sending = connection.send(req.bodyBytes, 1000)
    guard let sent = sending else { return 502 }
    guard let initial = resp2Stream(8192) else { return 500 }
    let cut = parseInt(req.header("X-Cut").or("0")).or(-1)
    let size = parseInt(req.header("X-Size").or("0")).or(-1)
    let part1 = connection.readExactly(cut, 1000)
    guard let left = part1 else { return 502 }
    guard let first = resp2Feed(initial, left) else { return 413 }
    let part2 = connection.readExactly(size - cut, 1000)
    guard let right = part2 else { return 502 }
    let final = resp2Feed(first, right)
    guard let stream = final else { return 413 }
    guard resp2Finished(stream) && first.cursor.status == 0 else { return 400 }
    let closed = connection.close()
    let buffered = stream.bytes
    return response(200, body: buffered)
}

'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', required=True)
    parser.add_argument('--opt', required=True)
    args = parser.parse_args()
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    listener.settimeout(.2)
    stopped = threading.Event()
    errors = []
    def peer(connection):
        try:
            connection.settimeout(3)
            header = b''
            while not header.endswith(b'\n'):
                part = connection.recv(1)
                if not part: return
                header += part
            cut, length = map(int, header.split())
            wire = b''
            while len(wire) < length:
                part = connection.recv(length - len(wire))
                if not part: return
                wire += part
            if cut == -1:
                connection.sendall(wire[:1])
                time.sleep(1.2)
                return
            if cut == -2:
                connection.sendall(wire[:1])
                return
            connection.sendall(wire[:cut])
            if cut and cut < len(wire): time.sleep(.06)
            connection.sendall(wire[cut:])
            # A completed parser must not perform another receive or wait for EOF.
            connection.recv(1)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception as exc:
            errors.append(exc)
        finally:
            connection.close()
    def serve():
        while not stopped.is_set():
            try: connection, _ = listener.accept()
            except socket.timeout: continue
            except OSError: return
            threading.Thread(target=peer, args=(connection,), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='rut-stream-resp2-') as directory:
        root = Path(directory)
        source, log = root / 'gateway.rut', root / 'server.log'
        source.write_text(PROGRAM)
        for name in ('resp2.rut', 'resp2-stream.rut'):
            shutil.copyfile(Path(args.library) / name, root / name)
        environment = dict(os.environ, RESP2_TEST_ENDPOINT='{"address":"127.0.0.1","port":%d}' % listener.getsockname()[1])
        with log.open('wb') as output:
            process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                '--opt', args.opt, '--no-pin', '--shards', '1', '--drain', '0'],
                env=environment, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                data = log.read_bytes()
                match = re.search(rb'Listening on port ([0-9]+) with', data)
                if match:
                    port = int(match[1]); break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and b'io_uring is unavailable' in data: return 77
                    raise AssertionError(data.decode(errors='replace'))
                time.sleep(.025)
            else: raise AssertionError(log.read_text(errors='replace'))
            source.unlink()
            for name in ('resp2.rut', 'resp2-stream.rut'): (root / name).unlink()
            calls = 0
            def request(path, wire, headers=None):
                nonlocal calls
                calls += 1
                client = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                try:
                    client.request('POST', '/' + path, wire, headers or {})
                    reply = client.getresponse()
                    return reply.status, reply.read()
                finally: client.close()
            samples = [b'+OK\r\n', b'-ERR test\r\n', b':-9223372036854775808\r\n',
                b':+00042\r\n', b'$-1\r\n', b'*-1\r\n', b'*0\r\n', b'$0\r\n\r\n',
                encode((5, [(4, b'a\x00\xff\r\n'), (5, [(3, -2), (6, None)])])),
                encode((5, [(3, n) for n in range(63)])), b'*1\r\n' * 63 + b'+\r\n']
            for wire in samples:
                records = reference(wire)
                assert request('feed', wire, {'X-Consumed': str(len(wire))}) == (200, wire), wire
                for cut in range(len(wire)):
                    command = ('%d %d\n' % (cut,len(wire))).encode()+wire
                    assert request('network', command, {'X-Cut': str(cut), 'X-Size': str(len(wire))}) == (200,wire), (wire,cut)
                for index, (kind, payload, after, children) in enumerate(records):
                    headers = {'X-Cut': str(len(wire)//2), 'X-Count': str(len(records)), 'X-Index': str(index),
                        'X-Kind': str(kind), 'X-Next': str(after), 'X-Children': str(children)}
                    assert request('item', wire, headers) == (200, payload), (wire, index)
            incomplete = b'*2\r\n$3\r\na\x00b\r\n:42\r\n'
            for end in range(len(incomplete)):
                prefix = incomplete[:end]
                # Probe consumed position is the start of the incomplete token.
                consumed = 0 if end < 4 else 4 if end < 13 else 13
                assert request('feed', prefix, {'X-Status': '0', 'X-Consumed': str(consumed), 'X-Finished': '0'}) == (200, prefix), end
            invalid = [b'?', b':x\r\n', b':9223372036854775808\r\n', b'$-2\r\n', b'*+1\r\n',
                b'$3\r\nabcXX', b'+a\nb\r\n', b'*64\r\n', b'$8192\r\n', b'$\r\n']
            for wire in invalid:
                assert request('feed', wire, {'X-Status': '-1', 'X-Finished': '0'}) == (200, wire), wire
            assert request('feed', b'+OK\r\n', {'X-Limit': '4'})[0] == 413
            assert request('feed', b'+OK', {'X-Limit': '3', 'X-Status': '-1', 'X-Finished': '0'}) == (200, b'+OK')
            pipeline = b'$3\r\na\x00b\r\n:42\r\n'
            assert request('remainder', pipeline) == (200, b':42\r\n')
            for cut in range(1, 10):
                wire = b'$4\r\na\x00\xffb\r\n'
                command = ('%d %d\n' % (cut, len(wire))).encode() + wire
                assert request('auto', command) == (200, b'a\x00\xffb'), cut
            wire = b'+OK\r\n'
            # Whole-frame first receive exercises the no-I/O complete branch.
            assert request('auto', ('%d %d\n' % (len(wire),len(wire))).encode()+wire) == (200,b'OK')
            for mode in (-1, -2):
                assert request('auto', ('%d %d\n' % (mode,len(wire))).encode()+wire)[0] == 502
            assert not errors, errors
            print('PASS %s O%s: %d split/oracle/TCP checks; sources removed' % (args.backend, args.opt, calls))
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
            stopped.set()
            listener.close()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
