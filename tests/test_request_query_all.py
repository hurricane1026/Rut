#!/usr/bin/env python3
"""Check owned repeated query values through native HTTP/1 and HTTP/2 handlers."""
import argparse
import http.client
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

import auth_h2_fixture


PROGRAM = r'''route GET "/tags" {
    let pending = req.queryAll("tag")
    guard let tags = pending else { return 503 }
    guard let index = parseInt(req.header("X-Index").or("0")) else { return 400 }
    guard let value = tags.get(index) else { return 404 }
    return response(200, body: value)
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, required=True, choices=(0, 2))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rut-query-all-') as directory:
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
                ('', 0, 404, b''),
                ('?tag', 0, 200, b''),
                ('?tag=', 0, 200, b''),
                ('?tag=first&other=x&tag=last', 0, 200, b'first'),
                ('?tag=first&other=x&tag=last', 1, 200, b'last'),
                ('?tag=first&other=x&tag=last', 2, 404, b''),
                ('?tag=first', -1, 404, b''),
                ('?tag=one&TAG=wrong&tag=two', 1, 200, b'two'),
                ('?t%61g=wrong&tag=a%26b+c', 0, 200, b'a%26b+c'),
                ('?&&tag=&&tag=last&&', 0, 200, b''),
                ('?tag=a=b&tag==', 1, 200, b'='),
                ('?tag=a;tag=b', 0, 200, b'a;tag=b'),
                ('?' + '&'.join(f'tag={i}' for i in range(64)), 63, 200, b'63'),
                ('?' + '&'.join(f'tag={i}' for i in range(65)), 0, 503, b''),
                ('?' + 'other=x&' * 100 + 'tag=only', 0, 200, b'only'),
                ('?tag=' + 'x' * 4096, 0, 200, b'x' * 4096),
            ]
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
            try:
                previous_socket = None
                for query, index, expected_status, expected_body in cases:
                    path, fields = '/tags' + query, [('X-Index', str(index))]
                    connection.request('GET', path, headers=dict(fields))
                    response = connection.getresponse()
                    body = response.read()
                    assert response.status == expected_status, (query, index, response.status, body)
                    if expected_status == 200:
                        assert body == expected_body, (query, index, body)
                        assert response.getheader('Content-Length') == str(len(expected_body))
                    assert connection.sock is not None
                    if previous_socket is not None:
                        assert connection.sock is previous_socket, 'request failed to reuse connection'
                    previous_socket = connection.sock
                    code, body = auth_h2_fixture.request(port, path, fields)
                    assert code == expected_status, (query, index, 'h2', code, body)
                    if expected_status == 200:
                        assert body == expected_body, (query, index, 'h2', body)
            finally:
                connection.close()
            with socket.create_connection(('127.0.0.1', port), timeout=8) as connection:
                connection.sendall(
                    b'GET /tags?tag=one HTTP/1.1\r\nHost: local\r\n\r\n'
                    b'GET /tags?tag=two HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n')
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
            print(f'{args.backend} O{args.opt}: HTTP/1 + HTTP/2 query matrix, reuse and pipeline passed')
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
