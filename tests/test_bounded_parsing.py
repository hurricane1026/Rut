#!/usr/bin/env python3
"""Compare Rut's source RESP2 library with an independent Python wire parser."""
import argparse
import http.client
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile
import time


PROGRAM = r'''import "resp2.rut"
func octetStep(_ data: Bytes, _ offset: i32) -> (i32, i32, bool) {
    guard let byte = data[offset] else { nil }
    (offset + 1, byte, offset + 1 == data.count)
}
func stalledStep(_ data: Bytes, _ state: i32) -> (i32, Bytes, bool) {
    (state, data, false)
}
func repeatStep(_ data: Bytes, _ state: i32) -> (i32, Bytes, bool) {
    (state + 1, data, state == 63)
}
func wideStep(_ data: Bytes, _ state: i32) {
    guard let value = parseInt64(data) else { nil }
    (state, value, true)
}
func textStep(_ data: Bytes, _ state: i32) -> (i32, str, bool) {
    guard let byte = data[state] else { nil }
    (state + 1, "word", state + 1 == data.count)
}
func boolStep(_ data: Bytes, _ state: i32) -> (i32, bool, bool) {
    guard let byte = data[state] else { nil }
    (state + 1, byte > 127, state + 1 == data.count)
}
func firstValue(_ values: Collected<i32>) -> i32 {
    values.get(0).or(-1)
}
route POST "/validate" {
    guard let tokens = decodeResp2(req.bodyBytes) else { return 400 }
    guard tokens.count > 0 else { return 500 }
    return 204
}
route POST "/item" {
    guard let tokens = decodeResp2(req.bodyBytes) else { return 400 }
    guard let index = parseInt(req.header("X-Index").or("0")) else { return 400 }
    guard let token = tokens.get(index) else { return 416 }
    guard token.kind == parseInt(req.header("X-Kind").or("")).or(-1) &&
          token.children == parseInt(req.header("X-Children").or("")).or(-1) &&
          token.next == parseInt(req.header("X-Next").or("")).or(-1) &&
          tokens.count == parseInt(req.header("X-Count").or("")).or(-1) else { return 422 }
    let payload = token.data
    return response(200, body: payload)
}
route POST "/integer" {
    guard let tokens = decodeResp2(req.bodyBytes) else { return 400 }
    guard let root = tokens.get(0) else { return 500 }
    guard let value = resp2Integer(root) else { return 422 }
    guard let expected = parseInt64(req.header("X-Expected").or("")) else { return 400 }
    guard value == expected else { return 422 }
    return 204
}
route POST "/octets" {
    guard let values = collectBytes(req.bodyBytes, 0, 64, octetStep) else { return 400 }
    guard firstValue(values) == req.bodyBytes[0].or(-1) else { return 500 }
    guard values.get(-1) == nil && values.get(values.count) == nil else { return 500 }
    return 204
}
route POST "/stalled" {
    guard let values = collectBytes(req.bodyBytes, 0, 4, stalledStep) else { return 400 }
    return 500
}
route POST "/exhaust" {
    guard let values = collectBytes(req.bodyBytes, 0, 64, repeatStep) else { return 400 }
    return 204
}
route POST "/wide" {
    guard let values = collectBytes(req.bodyBytes, 0, 1, wideStep) else { return 400 }
    guard let value = values.get(0) else { return 500 }
    guard let expected = parseInt64(req.header("X-Expected").or("")) else { return 400 }
    guard value == expected else { return 422 }
    return 204
}
route POST "/text" {
    guard let words = collectBytes(req.bodyBytes, 0, 8, textStep) else { return 400 }
    guard let text = words.get(words.count - 1) else { return 500 }
    return response(200, body: text)
}
route POST "/bool" {
    guard let flags = collectBytes(req.bodyBytes, 0, 8, boolStep) else { return 400 }
    guard let flag = flags.get(0) else { return 500 }
    guard flag else { return 422 }
    return 204
}
'''


def reference(wire):
    records = []

    def parse(position):
        prefix = wire[position:position + 1]
        if prefix not in (b'+', b'-', b':', b'$', b'*'):
            raise ValueError('prefix')
        end = wire.index(b'\r\n', position + 1)
        text, after = wire[position + 1:end], end + 2
        if prefix in (b'+', b'-'):
            if b'\r' in text or b'\n' in text:
                raise ValueError('line')
            records.append((1 if prefix == b'+' else 2, text, after, 0))
            return after
        if prefix == b':':
            if not re.fullmatch(rb'[+-]?[0-9]+', text) or not -(1 << 63) <= int(text) < (1 << 63):
                raise ValueError('integer')
            records.append((3, text, after, 0))
            return after
        if text == b'-1':
            records.append((6 if prefix == b'$' else 7, b'', after, 0))
            return after
        if not re.fullmatch(rb'[0-9]+', text):
            raise ValueError('length')
        length = int(text)
        if prefix == b'$':
            stop = after + length
            if wire[stop:stop + 2] != b'\r\n':
                raise ValueError('bulk')
            records.append((4, wire[after:stop], stop + 2, 0))
            return stop + 2
        records.append((5, b'', after, length))
        for _ in range(length):
            after = parse(after)
        return after

    if parse(0) != len(wire) or len(records) > 64:
        raise ValueError('trailing/budget')
    return records


def encode(value):
    kind, data = value
    if kind == 1:
        return b'+' + data + b'\r\n'
    if kind == 2:
        return b'-' + data + b'\r\n'
    if kind == 3:
        return b':' + str(data).encode() + b'\r\n'
    if kind == 4:
        return b'$' + str(len(data)).encode() + b'\r\n' + data + b'\r\n'
    if kind == 5:
        return b'*' + str(len(data)).encode() + b'\r\n' + b''.join(map(encode, data))
    return b'$-1\r\n' if kind == 6 else b'*-1\r\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', type=int, choices=(0, 2), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rut-bounded-parser-') as directory:
        root = Path(directory)
        source, library, log = root / 'gateway.rut', root / 'resp2.rut', root / 'server.log'
        program = PROGRAM
        if args.opt == 2:
            program = program.replace('import "resp2.rut"', 'import * as wire from "resp2.rut"')
            program = program.replace("decodeResp2(", "wire.decodeResp2(").replace("resp2Integer(", "wire.resp2Integer(")
        source.write_text(program)
        shutil.copyfile(args.library, library)
        with log.open('wb') as output:
            process = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                                        '--opt', str(args.opt), '--no-pin', '--shards', '1', '--drain', '0'],
                                       stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                data = log.read_bytes()
                match = re.search(rb'Listening on port ([0-9]+) with', data)
                if match:
                    port = int(match[1])
                    break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and b'io_uring is unavailable' in data:
                        return 77
                    raise AssertionError(data.decode(errors='replace'))
                time.sleep(.025)
            else:
                raise AssertionError(log.read_text(errors='replace'))
            source.unlink()
            library.unlink()
            calls = 0

            def request(path, body, headers=None):
                nonlocal calls
                calls += 1
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                try:
                    connection.request('POST', '/' + path, body=body, headers=headers or {})
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            rng = random.Random(1049)

            def tree(depth=0):
                kind = rng.choice((1, 2, 3, 4, 6, 7) if depth > 4 else (1, 2, 3, 4, 5, 6, 7))
                if kind in (1, 2):
                    return kind, b'word ' + bytes([rng.randrange(65, 91)])
                if kind == 3:
                    return kind, rng.randrange(-(1 << 63), 1 << 63)
                if kind == 4:
                    return kind, rng.randbytes(rng.randrange(128))
                return (kind, [tree(depth + 1) for _ in range(rng.randrange(4))]) if kind == 5 else (kind, None)

            values = [(1, b''), (2, b'ERR bad'), (3, -(1 << 63)), (3, (1 << 63) - 1),
                      (4, b''), (4, bytes(range(256))), (5, []), (6, None), (7, None),
                      (5, [(4, b'a\x00\xff'), (5, [(3, -2), (6, None)])]),
                      (5, [(3, n) for n in range(63)])]
            chain = (6, None)
            for _ in range(63):
                chain = (5, [chain])
            values += [chain] + [tree() for _ in range(80)]
            for value in values:
                wire = encode(value)
                expected = reference(wire)
                assert request('validate', wire)[0] == 204, wire
                for index, (kind, payload, after, children) in enumerate(expected):
                    headers = {'X-Index': str(index), 'X-Kind': str(kind), 'X-Children': str(children),
                               'X-Next': str(after), 'X-Count': str(len(expected))}
                    assert request('item', wire, headers) == (200, payload), (wire, index)
                assert request('item', wire, {'X-Index': str(len(expected))})[0] == 416
            for number in (0, 1, -1, -(1 << 63), (1 << 63) - 1):
                wire = b':' + (b'+' if number >= 0 else b'-') + b'000' + str(abs(number)).encode() + b'\r\n'
                expected = {'X-Expected': str(number)}
                assert request('integer', wire, expected)[0] == 204
                assert request('wide', str(number).encode(), expected)[0] == 204
            malformed = [b'', b'?x\r\n', b'+bad\rtext\r\n', b'-bad\ntext\r\n', b':\r\n',
                         b':9223372036854775808\r\n', b':-9223372036854775809\r\n', b':1x\r\n',
                         b'$-2\r\n', b'$+1\r\nx\r\n', b'$1\r\nx\n', b'$99\r\nx\r\n',
                         b'*-2\r\n', b'*+1\r\n:1\r\n', b'*1\r\n', b'*2\r\n:1\r\n',
                         b'*64\r\n' + b':0\r\n' * 64, b'*1\r\n' * 64 + b'$-1\r\n',
                         b'+OK\r\n+extra\r\n', b'$0\r\n\r\ntrailing']
            sample = encode(values[9])
            malformed += [sample[:length] for length in range(len(sample))]
            for wire in malformed:
                assert request('validate', wire)[0] == 400, wire
            for length in (1, 3, 63, 64):
                assert request('octets', rng.randbytes(length))[0] == 204
            for length in (0, 65):
                assert request('octets', b'x' * length)[0] == 400
            assert request('text', b'abc') == (200, b'word')
            assert request('bool', b'\xff')[0] == 204
            assert request('bool', b'\x00')[0] == 422
            assert request('stalled', b'nonprogress')[0] == 400
            assert request('exhaust', b'x')[0] == 204
            assert request('exhaust', b'x' * 8192)[0] == 400
            print(f'PASS {args.backend} O{args.opt}: {calls} independent RESP2/collection checks; sources removed')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
