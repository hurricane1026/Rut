#!/usr/bin/env python3
"""Byte field extraction against Python slicing/find, including network continuation ownership."""
import argparse
import http.client
from pathlib import Path
import random
import re
import socket
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    args = parser.parse_args()
    with socket.socket() as peer, tempfile.TemporaryDirectory(prefix='rut-bytes-fields-') as directory:
        peer.bind(('127.0.0.1', 0))
        peer.listen()
        peer.settimeout(30)
        failures = []

        def serve():
            try:
                connection, _ = peer.accept()
                with connection:
                    # First framing read must tolerate a split delimiter. A later
                    # read must not invalidate a field view retained across it.
                    connection.sendall(b'$123\r')
                    time.sleep(.02)
                    connection.sendall(b'\nnext\r\n')
            except Exception as error:
                failures.append(error)

        root = Path(directory)
        helper = root / 'fields.rut'
        helper.write_text('func field(_ data: Bytes, _ start: i32, _ end: i32) -> Bytes => '
                          'data.slice(start, end)\n')
        source = '''import "fields.rut"
route POST "/slice" {
    guard let start = parseInt(req.header("X-Start").or("")) else { return 500 }
    guard let end = parseInt(req.header("X-End").or("")) else { return 500 }
    guard let value = field(req.bodyBytes, start, end) else { return 400 }
    return response(200, body: value)
}
route POST "/find" {
    guard let width = parseInt(req.header("X-Width").or("")) else { return 500 }
    guard let start = parseInt(req.header("X-Start").or("")) else { return 500 }
    guard let expected = parseInt(req.header("X-Expected").or("")) else { return 500 }
    let body = req.bodyBytes
    guard let delimiter = body.slice(0, width) else { return 500 }
    guard let data = body.slice(width, body.count) else { return 500 }
    guard let index = data.find(delimiter, start) else { return 400 }
    guard index == expected else { return 422 }
    return 204
}
route POST "/number" {
    let data = req.bodyBytes
    guard data[0].or(-1) == 36 else { return 400 }
    guard let end = data.find(b"\\r\\n") else { return 400 }
    guard let field = data.slice(1, end) else { return 400 }
    guard let value = parseInt(field) else { return 400 }
    guard value == 123 else { return 422 }
    return response(200, body: field)
}
route GET "/network" {
    let opening = tcp("ENDPOINT", 1000)
    guard let connection = opening else { return 500 }
    let reading = connection.readLine(128, 1000)
    guard let line = reading else { return 500 }
    guard let end = line.find(b"\\r\\n") else { return 500 }
    guard let field = line.slice(1, end) else { return 500 }
    let readingAgain = connection.readLine(128, 1000)
    guard let second = readingAgain else { return 500 }
    guard second == b"next\\r\\n" else { return 500 }
    guard parseInt(field).or(-1) == 123 else { return 500 }
    guard netError() == 0 else { return 500 }
    let closed = connection.close()
    return response(200, body: field)
}
'''.replace('ENDPOINT', '{\\"address\\":\\"127.0.0.1\\",\\"port\\":' +
            str(peer.getsockname()[1]) + '}')
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
            helper.unlink()

            def request(path, data=b'', **headers):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                try:
                    connection.request('GET' if path == 'network' else 'POST', '/' + path,
                                       body=data, headers={'X-' + k: str(v) for k, v in headers.items()})
                    reply = connection.getresponse()
                    return reply.status, reply.read()
                finally:
                    connection.close()

            rng = random.Random(1047)
            cases = 0
            for data in (b'', b'abc', b'\x00\xff\x80abc\x00', bytes(range(256)), b'x' * 8192):
                bounds = (-2147483648, -1, 0, 1, len(data) // 2, len(data), len(data) + 1, 2147483647)
                for start in bounds:
                    for end in bounds:
                        valid = 0 <= start <= end <= len(data)
                        status, result = request('slice', data, Start=start, End=end)
                        assert status == (200 if valid else 400), (len(data), start, end, status)
                        if valid:
                            assert result == data[start:end], (len(data), start, end, result)
                        cases += 1
            for _ in range(160):
                data = rng.randbytes(rng.randrange(100))
                delimiter = (data[rng.randrange(len(data)):][:rng.randrange(1, 9)]
                             if data and rng.randrange(2) else rng.randbytes(rng.randrange(12)))
                start = rng.choice((-2147483648, -1, 0, rng.randrange(len(data) + 2),
                                    len(data), len(data) + 1, 2147483647))
                expected = data.find(delimiter, start) if 0 <= start <= len(data) else -1
                status, _ = request('find', delimiter + data, Width=len(delimiter),
                                    Start=start, Expected=expected)
                assert status == (204 if expected >= 0 else 400), (
                    data, delimiter, start, expected, status)
                cases += 1
            for data, delimiter, start in ((b'aaaaa', b'aaa', 1), (b'', b'', 0),
                                            (b'\xff\x00\xff', b'\x00\xff', 0),
                                            (b'abc', b'', 3), (b'abc', b'c', 2),
                                            (b'abc', b'abcd', 0)):
                expected = data.find(delimiter, start)
                status, _ = request('find', delimiter + data, Width=len(delimiter),
                                    Start=start, Expected=expected)
                assert status == (204 if expected >= 0 else 400)
                cases += 1
            assert request('number', b'$123\r\nrest') == (200, b'123')
            assert request('number', b'$-12\r\n')[0] == 422
            for data in (b'', b'$\r\n', b'$12x\r\n', b'$123\n', b'$2147483648\r\n'):
                assert request('number', data)[0] == 400, data
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            assert request('network') == (200, b'123')
            worker.join(timeout=5)
            assert not worker.is_alive(), 'TCP fixture did not finish'
            assert not failures, failures
            print(f'PASS {args.backend} opt={args.opt}: {cases} Python oracle cases, '
                  'RESP decimal extraction and slice retained across TCP suspension')
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
