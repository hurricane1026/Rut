#!/usr/bin/env python3
"""Check exact string searches against Python bytes.find over HTTP/1 and HTTP/2."""
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


PREFIX = '\n'.join((
    '    guard let width = parseInt(req.header("X-Width").or("")) else { return 400 }',
    '    guard let start = parseInt(req.header("X-Start").or("")) else { return 400 }',
    '    guard let expected = parseInt(req.header("X-Expected").or("")) else { return 400 }',
    '    let body = req.body',
    '    guard let delimiter = body.slice(0, width) else { return 400 }',
    '    guard let text = body.slice(width, body.len) else { return 400 }',
)) + '\n'
PROGRAM = 'import "fields.rut"\n' + '\n'.join(
    f'route POST "/{name}" {{\n{PREFIX}'
    f'    guard let index = {expression} else {{ return 404 }}\n'
    '    guard index == expected else { return 422 }\n'
    '    guard let tail = text.slice(index, text.len) else { return 500 }\n'
    '    return response(200, body: tail)\n}'
    for name, expression in (
        ('member', 'text.find(delimiter, start)'),
        ('helper', 'locate(text, delimiter, start)'),
        ('pipe', 'text | locate(_, delimiter, start)'),
        ('default', 'text.find(delimiter)'),
    )
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, choices=(0, 2), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rut-string-find-') as directory:
        root = Path(directory)
        source, helper, log = root / 'gateway.rut', root / 'fields.rut', root / 'server.log'
        helper.write_text('func locate(_ text: str, _ delimiter: str, _ start: i32) -> i32 => text.find(delimiter, start)\n')
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
                (b'', b'', 0), (b'', b'x', 0), (b'abc', b'', 0),
                (b'abc', b'', 3), (b'abc', b'c', 3), (b'abc', b'abc', 0),
                (b'abc', b'b', 0), (b'abc', b'bc', 2), (b'abc', b'B', 0),
                (b'abc', b'abcd', 0), (b'aaaaa', b'aaa', 1),
                (b'ab:ab:', b':', 3), (b'a\0\xffz', b'\0\xff', 0),
                (b'\xc3\xa9x', b'\xa9', 0), (b'a%2Cb+c', b',', 0),
                (b'a%2Cb+c', b'+', 0), (b'abc', b'', -1), (b'abc', b'', 4),
                (b'abc', b'', -(2**31)), (b'abc', b'', 2**31 - 1),
                (b'x' * 8192 + b':tail', b':', 0),
                (b'a' * 8192 + b'b', b'a' * 255 + b'b', 0),
            ]
            generator = random.Random(1307)
            for _ in range(96):
                text = generator.randbytes(generator.randrange(0, 129))
                if text and generator.randrange(2):
                    left = generator.randrange(len(text))
                    delimiter = text[left:left + generator.randrange(0, 9)]
                else:
                    delimiter = generator.randbytes(generator.randrange(0, 9))
                start = generator.randrange(-2, len(text) + 3)
                cases.extend(((text, delimiter, start), (text, delimiter, 0)))
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            try:
                previous_socket = None
                for name in ('member', 'helper', 'pipe', 'default'):
                    for text, delimiter, start in cases:
                        if name == 'default' and start != 0:
                            continue
                        scenario = (name, len(text), delimiter, start)
                        index = text.find(delimiter, start) if 0 <= start <= len(text) else -1
                        valid = index >= 0
                        status, expected = (200, text[index:]) if valid else (404, b'')
                        fields = [('X-Width', str(len(delimiter))), ('X-Start', str(start)),
                                  ('X-Expected', str(index))]
                        path = '/' + name
                        connection.request('POST', path, body=delimiter + text, headers=dict(fields))
                        response = connection.getresponse()
                        body = response.read()
                        assert response.status == status, (name, len(text), delimiter, start, response.status, body)
                        if valid:
                            assert body == expected, (name, delimiter, start, body, expected)
                            assert response.getheader('Content-Length') == str(len(expected))
                        assert connection.sock is not None
                        if previous_socket is not None:
                            assert connection.sock is previous_socket, 'request failed to reuse connection'
                        previous_socket = connection.sock
                        code, body = auth_h2_fixture.request(port, path, fields, body=delimiter + text, method='POST')
                        assert code == status, (name, len(text), delimiter, start, 'h2', code, body)
                        if valid:
                            assert body == expected, (name, delimiter, start, 'h2', body)
            finally:
                connection.close()
            with socket.create_connection(('127.0.0.1', port), timeout=10) as connection:
                connection.sendall(
                    b'POST /member HTTP/1.1\r\nHost: local\r\nX-Width: 1\r\nX-Start: 0\r\nX-Expected: 2\r\nContent-Length: 7\r\n\r\n:xx:one'
                    b'POST /helper HTTP/1.1\r\nHost: local\r\nX-Width: 1\r\nX-Start: 0\r\nX-Expected: 2\r\nContent-Length: 7\r\nConnection: close\r\n\r\n:xx:two')
                wire = b''
                while True:
                    chunk = connection.recv(16384)
                    if not chunk:
                        break
                    wire += chunk
                headers, tail = wire.split(b'\r\n\r\n', 1)
                assert headers.startswith(b'HTTP/1.1 200'), wire
                assert tail.startswith(b':oneHTTP/1.1 200'), wire
                headers, body = tail[4:].split(b'\r\n\r\n', 1)
                assert b'Content-Length: 4' in headers, wire
                assert body == b':two', wire
            print(f'{args.backend} O{args.opt}: HTTP/1 + HTTP/2 string find oracle, reuse and pipeline passed')
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
