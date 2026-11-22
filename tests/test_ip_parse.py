#!/usr/bin/env python3
"""Exercise typed IPv4 parsing and network-order keys on native HTTP/1 and HTTP/2."""
import argparse
import http.client
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

import auth_h2_fixture


PROGRAM = r'''let seen = Cache<IP, i64>(capacity: 64)
func parseAddress(_ text: str) -> IP { IP.parse(text) }
route POST "/parse" {
    let pending = parseAddress(req.body)
    guard let address = pending else { return 400 }
    guard let expected = IP.parse(req.header("X-Expected").or("")) else { return 422 }
    guard address == expected else { return 409 }
    return 204
}
route POST "/peer" {
    guard let address = IP.parse(req.body) else { return 400 }
    guard address == req.remoteAddr else { return 403 }
    return 204
}
route POST "/cache" {
    let address = IP.parse(req.body).or(req.remoteAddr)
    let prior = seen.get(address).or(0)
    seen.set(address, prior + 1)
    if prior == 0 { return 201 } else { return 202 }
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, required=True, choices=(0, 2))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rut-ip-parse-') as directory:
        root = Path(directory)
        source, log = root / 'gateway.rut', root / 'server.log'
        source.write_text(PROGRAM)
        with log.open('wb') as output:
            process = subprocess.Popen(
                [args.server, '0', str(source), '--backend', args.backend, '--opt', str(args.opt),
                 '--no-pin', '--shards', '1', '--drain', '0'],
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
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
            try:
                def request(path, body, expected, headers=None, h2=False):
                    fields = list((headers or {}).items())
                    if h2:
                        status, content = auth_h2_fixture.request(port, path, fields, body, 'POST')
                    else:
                        previous_socket = connection.sock
                        connection.request('POST', path, body=body, headers=headers or {})
                        response = connection.getresponse()
                        status, content = response.status, response.read()
                        assert connection.sock is not None
                        if previous_socket is not None:
                            assert connection.sock is previous_socket, 'connection was not reused'
                    assert status == expected, (path, body, h2, status, content)

                for h2 in (False, True):
                    for address in ('0.0.0.0', '255.255.255.255', '1.2.3.4', '192.168.10.42'):
                        request('/parse', address.encode(), 204, {'X-Expected': address}, h2)
                    request('/parse', b'1.2.3.4', 409, {'X-Expected': '4.3.2.1'}, h2)
                    request('/parse', b'1.2.3.4', 422, {}, h2)
                    invalid = [b'', b'01.2.3.4', b'1.2.3.04', b'256.2.3.4', b'127.1',
                               b'2130706433', b'0x7f.0.0.1', b'+1.2.3.4', b'-1.2.3.4',
                               b' 1.2.3.4', b'1.2.3.4 ', b'1.2.3.4\r\n', b'1.2.3.4\0',
                               b'1.2\0.3.4', b'1.2.3.4:80', b'1.2.3.4/24', b'::1',
                               b'::ffff:127.0.0.1', b'fe80::1%lo', '１.2.3.4'.encode()]
                    for body in invalid:
                        request('/parse', body, 400, {'X-Expected': '1.2.3.4'}, h2)
                    request('/peer', b'127.0.0.1', 204, h2=h2)
                    request('/peer', b'1.2.3.4', 403, h2=h2)
                    request('/peer', b'127.1', 400, h2=h2)
                # Invalid input falls back to the actual peer; a parsed zero address
                # must remain distinct, and repeated parsed keys reuse their bucket.
                for body, expected in [(b'127.0.0.1', 201), (b'invalid', 202),
                                       (b'0.0.0.0', 201), (b'0.0.0.0', 202),
                                       (b'1.2.3.4', 201), (b'1.2.3.4', 202), (b'4.3.2.1', 201)]:
                    request('/cache', body, expected)
                for body in (b'127.0.0.1', b'0.0.0.0', b'1.2.3.4', b'4.3.2.1'):
                    request('/cache', body, 202, h2=True)
            finally:
                connection.close()
            with socket.create_connection(('127.0.0.1', port), timeout=8) as connection:
                connection.sendall(
                    b'POST /peer HTTP/1.1\r\nHost: local\r\nContent-Length: 9\r\n\r\n127.0.0.1'
                    b'POST /peer HTTP/1.1\r\nHost: local\r\nContent-Length: 7\r\nConnection: close\r\n\r\n1.2.3.4')
                wire = b''
                while True:
                    chunk = connection.recv(16384)
                    if not chunk:
                        break
                    wire += chunk
                assert wire.startswith(b'HTTP/1.1 204'), wire
                first_headers, remainder = wire.split(b'\r\n\r\n', 1)
                assert remainder.startswith(b'HTTP/1.1 403'), wire
            print(f'{args.backend} O{args.opt}: IPv4 parsing, peer equality, typed cache keys and HTTP/1+2 passed')
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
