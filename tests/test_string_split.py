#!/usr/bin/env python3
"""Exercise bounded owned string fields over HTTP/1 and HTTP/2."""
import argparse
import http.client
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

import auth_h2_fixture


BODY = '''
    guard let parts = pending else { return 503 }
    guard parts.count == parseInt(req.header("X-Count").or("-1")).or(-1) else { return 409 }
    guard let index = parseInt(req.header("X-Index").or("0")) else { return 400 }
    guard let value = parts.get(index) else { return 404 }
    return response(200, body: value)
'''
PROGRAM = '\n'.join(
    f'route POST "/{name}" {{ let pending = {expression}\n{BODY}}}'
    for name, expression in (
        ('member', 'req.body.split(req.header("X-Separator").or(","))'),
        ('free', 'split(req.body, req.header("X-Separator").or(","))'),
        ('pipe', 'req.body | split(_, req.header("X-Separator").or(","))'),
    )
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, required=True, choices=(0, 2))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rut-string-split-') as directory:
        root = Path(directory)
        source, log = root / 'gateway.rut', root / 'server.log'
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
            cases = [
                (b'', ',', 0, 200),
                (b',a,,b,', ',', 0, 200),
                (b',a,,b,', ',', 2, 200),
                (b',a,,b,', ',', 4, 200),
                (b'a::b::c', '::', 1, 200),
                (b'aaaaa', 'aa', 2, 200),
                (b'abababa', 'aba', 1, 200),
                (b'a,b\0z,c', ',', 1, 200),
                (b'a%2Cb+c', ',', 0, 200),
                (b'a', 'long delimiter', 0, 200),
                (b'a', ',', -1, 404),
                (b'a', ',', 1, 404),
                (b','.join(str(i).encode() for i in range(64)), ',', 63, 200),
                (b',' * 64, ',', 0, 503),
                (b'x' * 8192, ',', 0, 200),
                (b'x' * 8193, ',', 0, 503),
                (b'a' + b'x' * 256 + b'b', 'x' * 256, 1, 200),
                (b'a', 'x' * 257, 0, 503),
                (b'a', '', 0, 503),
            ]
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            try:
                previous_socket = None
                for name in ('member', 'free', 'pipe'):
                    for text, separator, index, status in cases:
                        values = text.split(separator.encode()) if separator else []
                        expected = values[index] if status == 200 else b''
                        fields = [('X-Separator', separator), ('X-Index', str(index)),
                                  ('X-Count', str(len(values)))]
                        path = '/' + name
                        connection.request('POST', path, body=text, headers=dict(fields))
                        response = connection.getresponse()
                        body = response.read()
                        assert response.status == status, (name, len(text), separator, index, response.status, body)
                        if status == 200:
                            assert body == expected, (name, index, body, expected)
                            assert response.getheader('Content-Length') == str(len(expected))
                        assert connection.sock is not None
                        if previous_socket is not None:
                            assert connection.sock is previous_socket, 'request failed to reuse connection'
                        previous_socket = connection.sock
                        code, body = auth_h2_fixture.request(port, path, fields, body=text, method='POST')
                        assert code == status, (name, len(text), separator, index, 'h2', code, body)
                        if status == 200:
                            assert body == expected, (name, index, 'h2', body)
            finally:
                connection.close()
            with socket.create_connection(('127.0.0.1', port), timeout=10) as connection:
                connection.sendall(
                    b'POST /member HTTP/1.1\r\nHost: local\r\nX-Count: 2\r\nContent-Length: 7\r\n\r\none,end'
                    b'POST /free HTTP/1.1\r\nHost: local\r\nX-Count: 2\r\nContent-Length: 7\r\nConnection: close\r\n\r\ntwo,end')
                wire = b''
                while True:
                    chunk = connection.recv(16384)
                    if not chunk:
                        break
                    wire += chunk
                first_headers, tail = wire.split(b'\r\n\r\n', 1)
                assert first_headers.startswith(b'HTTP/1.1 200'), wire
                assert tail.startswith(b'oneHTTP/1.1 200'), wire
                second_headers, body = tail[3:].split(b'\r\n\r\n', 1)
                assert b'Content-Length: 3' in second_headers, wire
                assert body == b'two', wire
            print(f'{args.backend} O{args.opt}: HTTP/1 + HTTP/2 split matrix, reuse and pipeline passed')
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
