#!/usr/bin/env python3
"""Check byte string transformations against independent Python bytes/re oracles over HTTP/1 and HTTP/2."""
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


PROGRAM = '\n'.join(
    f'route POST "/{name}" {{\n'
    f'    let pending = {expression}\n'
    '    guard let value = pending else { return 503 }\n'
    '    return response(200, body: value)\n}'
    for name, expression in (
        ('upper', 'req.body.upper()'),
        ('lower', 'req.body | lower(_)'),
        ('replace', 'replace(req.body, req.header("X-Old").or("aa"), req.header("X-New").or("X"))'),
        ('regex', 'req.body.replace(re"/+", req.header("X-New").or("X"))'),
    )
) + '\nroute POST "/trim" { let value = trim(req.body) return response(200, body: value) }\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, choices=(0, 2), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rut-string-core-') as directory:
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

            generator = random.Random(1307)
            cases = [b'', b' aBz\0\xff \t\r\n', b'aaaaa', b'//a///b/',
                     b' \r\n\t\v\f', bytes(range(256)), b'a' * 8192,
                     b'a' * 8193, b'/' * 64, b'/a' * 65]
            cases += [generator.randbytes(generator.randrange(0, 257)) for _ in range(64)]
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            try:
                previous_socket = None
                for name in ('upper', 'lower', 'replace', 'regex', 'trim'):
                    for text in cases:
                        scenario = (name, len(text))
                        old = b'aa' if len(text) % 2 else b'a'
                        replacement = b'' if len(text) % 3 else b'$1\\'
                        fields = {'X-Old': old.decode('ascii'),
                                  'X-New': replacement.decode('ascii')}
                        expected = (text.upper() if name == 'upper' else
                                    text.lower() if name == 'lower' else
                                    text.replace(old, replacement) if name == 'replace' else
                                    re.sub(rb'/+', lambda _: replacement, text) if name == 'regex' else
                                    text.strip(b' \t\n\r\v\f'))
                        valid = name == 'trim' or (len(text) <= 8192 and len(expected) <= 16384 and
                            (name != 'regex' or len(re.findall(rb'/+', text)) <= 64))
                        status = 200 if valid else 503
                        path = '/' + name
                        connection.request('POST', path, body=text, headers=fields)
                        response = connection.getresponse()
                        body = response.read()
                        assert response.status == status, (scenario, response.status, body)
                        if valid:
                            assert body == expected, (scenario, body[:100], expected[:100])
                            assert response.getheader('Content-Length') == str(len(expected))
                        assert connection.sock is not None
                        if previous_socket is not None:
                            assert connection.sock is previous_socket
                        previous_socket = connection.sock
                        code, body = auth_h2_fixture.request(port, path, list(fields.items()), body=text, method='POST')
                        assert code == status, (scenario, 'h2', code, body)
                        if valid:
                            assert body == expected, (scenario, 'h2', body[:100], expected[:100])
            finally:
                connection.close()
            with socket.create_connection(('127.0.0.1', port), timeout=10) as connection:
                connection.sendall(
                    b'POST /upper HTTP/1.1\r\nHost: local\r\nContent-Length: 3\r\n\r\none'
                    b'POST /lower HTTP/1.1\r\nHost: local\r\nContent-Length: 3\r\nConnection: close\r\n\r\nTWO')
                wire = b''
                while True:
                    chunk = connection.recv(16384)
                    if not chunk:
                        break
                    wire += chunk
                headers, tail = wire.split(b'\r\n\r\n', 1)
                assert headers.startswith(b'HTTP/1.1 200'), wire
                assert tail.startswith(b'ONEHTTP/1.1 200'), wire
                headers, body = tail[3:].split(b'\r\n\r\n', 1)
                assert b'Content-Length: 3' in headers, wire
                assert body == b'two', wire
            print(f'{args.backend} O{args.opt}: HTTP/1 + HTTP/2 string core oracle, reuse and pipeline passed')
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
