#!/usr/bin/env python3
"""Check borrowed text slices against Python byte slicing over HTTP/1 and HTTP/2."""
import argparse
import http.client
from pathlib import Path
import random
import re
import socket
import subprocess
import tempfile
import time

import auth_h2_fixture


PREFIX = '''
    guard let start = parseInt(req.header("X-Start").or("")) else { return 400 }
    guard let end = parseInt(req.header("X-End").or("")) else { return 400 }
'''
PROGRAM = 'import "fields.rut"\n' + '\n'.join(
    f'route POST "/{name}" {{\n{PREFIX}'
    f'    guard let value = {expression} else {{ return 416 }}\n'
    '    return response(200, body: value)\n}'
    for name, expression in (
        ('member', 'req.body.slice(start, end)'),
        ('helper', 'field(req.body, start, end)'),
        ('pipe', 'req.body | field(_, start, end)'),
    )
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, choices=(0, 2), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rut-string-slice-') as directory:
        root = Path(directory)
        source, helper, log = root / 'gateway.rut', root / 'fields.rut', root / 'server.log'
        helper.write_text('func field(_ text: str, _ start: i32, _ end: i32) -> str => text.slice(start, end)\n')
        source.write_text(PROGRAM)
        with log.open('wb') as output:
            process = subprocess.Popen(
                [args.server, '0', str(source), '--backend', args.backend,
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
            helper.unlink()
            cases = [
                (b'', 0, 0), (b'abc', 0, 0), (b'abc', 3, 3),
                (b'abc', 0, 3), (b'abc', 1, 2),
                (b'a\0\xffz', 1, 3), (b'\xc3\xa9x', 1, 2), (b'a%2Cb+c', 1, 7),
                (b'abc', -1, 1), (b'abc', 2, 1), (b'abc', 0, 4), (b'abc', 4, 4),
                (b'abc', -(2**31), 1), (b'abc', 0, 2**31 - 1),
                (b'x' * 8193, 1, 8192),
            ]
            generator = random.Random(627)
            for _ in range(96):
                text = generator.randbytes(generator.randrange(0, 129))
                start = generator.randrange(-2, len(text) + 3)
                end = generator.randrange(-2, len(text) + 3)
                cases.append((text, start, end))
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            try:
                previous_socket = None
                for name in ('member', 'helper', 'pipe'):
                    for text, start, end in cases:
                        scenario = (name, len(text), start, end)
                        valid = 0 <= start <= end <= len(text)
                        status, expected = (200, text[start:end]) if valid else (416, b'')
                        fields = [('X-Start', str(start)), ('X-End', str(end))]
                        path = '/' + name
                        connection.request('POST', path, body=text, headers=dict(fields))
                        response = connection.getresponse()
                        body = response.read()
                        assert response.status == status, (name, len(text), start, end, response.status, body)
                        if valid:
                            assert body == expected, (name, start, end, body, expected)
                            assert response.getheader('Content-Length') == str(len(expected))
                        assert connection.sock is not None
                        if previous_socket is not None:
                            assert connection.sock is previous_socket, 'request failed to reuse connection'
                        previous_socket = connection.sock
                        code, body = auth_h2_fixture.request(port, path, fields, body=text, method='POST')
                        assert code == status, (name, len(text), start, end, 'h2', code, body)
                        if valid:
                            assert body == expected, (name, start, end, 'h2', body)
            finally:
                connection.close()
            with socket.create_connection(('127.0.0.1', port), timeout=10) as connection:
                connection.sendall(
                    b'POST /member HTTP/1.1\r\nHost: local\r\nX-Start: 0\r\nX-End: 3\r\nContent-Length: 6\r\n\r\noneend'
                    b'POST /helper HTTP/1.1\r\nHost: local\r\nX-Start: 0\r\nX-End: 3\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntwoend')
                wire = b''
                while True:
                    chunk = connection.recv(16384)
                    if not chunk:
                        break
                    wire += chunk
                headers, tail = wire.split(b'\r\n\r\n', 1)
                assert headers.startswith(b'HTTP/1.1 200'), wire
                assert tail.startswith(b'oneHTTP/1.1 200'), wire
                headers, body = tail[3:].split(b'\r\n\r\n', 1)
                assert b'Content-Length: 3' in headers, wire
                assert body == b'two', wire
            print(f'{args.backend} O{args.opt}: HTTP/1 + HTTP/2 string slice oracle, reuse and pipeline passed')
        except Exception as error:
            error.add_note(f"scenario: {locals().get('scenario')}; server log: {log.read_text(errors='replace')[-3000:]}")
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
