#!/usr/bin/env python3
"""Check built-in Bytes integer readers against Python's independent struct codec."""
import argparse
import http.client
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    args = parser.parse_args()
    readers = [
        ('U16', 'H', 16, False), ('I16', 'h', 16, True),
        ('U32', 'I', 32, False), ('I32', 'i', 32, True),
        ('I64', 'q', 64, True),
    ]
    source = ''
    offset_expression = '-1'
    for offset in (0, 1, 2, 3, 4, 8, -1, -2147483648, 2147483647):
        offset_expression = f'if text == "{offset}" {{ {offset} }} else {{ {offset_expression} }}'
    source += f'func offset(_ text: str) -> i32 {{ {offset_expression} }}\n'
    for kind, _, bits, _ in readers:
        for endian in ('BE', 'LE'):
            name = f'read{kind}{endian}'
            expression = 'i64(value)' if bits == 16 or kind == 'I32' else 'value'
            source += f'''
route POST "/{name}" {{
    guard let expectedJson = json.parse(req.header("X-Expected").or("")) else {{ return 400 }}
    guard let expected = json.int(expectedJson) else {{ return 400 }}
    let position = offset(req.header("X-Offset").or("0"))
    guard let value = req.bodyBytes.{name}(position) else {{ return 400 }}
    guard {expression} == expected else {{ return 422 }}
    return 204
}}
'''
    with tempfile.TemporaryDirectory(prefix='rut-binary-integers-') as directory:
        root = Path(directory)
        program, log = root / 'gateway.rut', root / 'gateway.log'
        program.write_text(source)
        with log.open('wb') as output:
            process = subprocess.Popen(
                [args.server, '0', str(program), '--backend', args.backend,
                 '--opt', str(args.opt), '--shards', '1', '--no-pin', '--drain', '0'],
                stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            port = None
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
                time.sleep(.02)
            assert port, log.read_text(errors='replace')
            # Built-in reads must keep working after the source is removed.
            program.unlink()

            def request(name, body, expected, offset=0):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                try:
                    connection.request('POST', '/' + name, body=body,
                                       headers={'X-Expected': str(expected), 'X-Offset': str(offset)})
                    reply = connection.getresponse()
                    status = reply.status
                    reply.read()
                    return status
                finally:
                    connection.close()

            rng = random.Random(1043)
            checked = 0
            for kind, format_code, bits, signed in readers:
                minimum = -(1 << (bits - 1)) if signed else 0
                maximum = (1 << (bits - (1 if signed else 0))) - 1
                values = [minimum, maximum, 0, 1, 255, 256, 300]
                if signed:
                    values += [-1, -256, -300]
                values += [rng.randint(minimum, maximum) for _ in range(24)]
                width = bits // 8
                for endian, marker in (('BE', '>'), ('LE', '<')):
                    name = f'read{kind}{endian}'
                    for value in values:
                        encoded = struct.pack(marker + format_code, value)
                        prefix = rng.randbytes(rng.randrange(4))
                        body = prefix + encoded + b'\xa5\x5a'
                        status = request(name, body, value, len(prefix))
                        assert status == 204, (name, value, body.hex(), status)
                        checked += 1
                    encoded = struct.pack(marker + format_code, 300)
                    assert request(name, encoded, 301) == 422, name
                    for length in range(width):
                        assert request(name, encoded[:length], 300) == 400, (name, length)
                    for offset in (-2147483648, -1, 1, width, 2147483647):
                        assert request(name, encoded, 300, offset) == 400, (name, offset)
                    assert request(name, b'\xff' + encoded, 300, 1) == 204, name
                    # A full unsigned 32-bit value must never be narrowed to signed i32.
                    if kind == 'U32':
                        assert request(name, b'\xff' * 4, 4294967295) == 204, name
            print(f'PASS: {args.backend} opt={args.opt}: {checked} struct reference cases, signed limits, '
                  'unsigned 32-bit range, offsets, truncation and native source removal')
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError('binary reader test server shutdown timed out')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
