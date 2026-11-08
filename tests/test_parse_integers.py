#!/usr/bin/env python3
"""Strict decimal parsing against Python's independent grammar and bigint oracle."""
import argparse
import http.client
from pathlib import Path
import random
import re
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    args = parser.parse_args()
    source = ''
    for bits in (32, 64):
        name = 'parseInt' if bits == 32 else 'parseInt64'
        for carrier, expression in (('bytes', 'req.bodyBytes'), ('text', 'req.body')):
            number = 'i64(value)' if bits == 32 else 'value'
            source += f'''
route POST "/{bits}/{carrier}" {{
    guard let value = {name}({expression}) else {{ return 400 }}
    guard let expectedJson = json.parse(req.header("X-Expected").or("")) else {{ return 500 }}
    guard let expected = json.int(expectedJson) else {{ return 500 }}
    guard {number} == expected else {{ return 422 }}
    return 204
}}
'''
    with tempfile.TemporaryDirectory(prefix='rut-parse-integers-') as directory:
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
            program.unlink()
            values = [b'', b'+', b'-', b'+-1', b'--1', b' 42', b'42 ', b'42\r\n',
                      b'4\x002', b'\xff42', '４２'.encode(), b'1.0', b'1e2', b'0x10',
                      b'0', b'-0', b'+0', b'+42', b'-42', b'0000000000000042',
                      b'0' * 512, b'0' * 512 + b'42', b'0' * 512 + b'x']
            for bits in (32, 64):
                for boundary in (-(1 << (bits - 1)), (1 << (bits - 1)) - 1):
                    for offset in (-1, 0, 1):
                        values.append(str(boundary + offset).encode())
            rng = random.Random(1045)
            for _ in range(128):
                value = rng.randrange(-(1 << 63), 1 << 63)
                values.append(str(value).encode())
                values.append((b'-' if value < 0 else b'+') + b'0' * rng.randrange(1, 64)
                              + str(abs(value)).encode())
            checked = 0
            for bits in (32, 64):
                for carrier in ('text', 'bytes'):
                    for text in values:
                        valid = re.fullmatch(rb'[+-]?[0-9]+', text) is not None
                        value = int(text) if valid else 0
                        valid = valid and -(1 << (bits - 1)) <= value < (1 << (bits - 1))
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                        try:
                            connection.request('POST', f'/{bits}/{carrier}', body=text,
                                               headers={'X-Expected': str(value if valid else 0)})
                            response = connection.getresponse()
                            response.read()
                            assert response.status == (204 if valid else 400), (
                                bits, carrier, text, response.status)
                            checked += 1
                        finally:
                            connection.close()
            print(f'{checked} strict integer parsing requests passed ({args.backend}, opt={args.opt})')
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
