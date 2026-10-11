#!/usr/bin/env python3
"""Check synthetic routes across successive requests on one HTTP connection."""
import http.client
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


def payload(size):
    result = bytearray()
    for block in range((size + 4095) // 4096):
        result.extend(block.to_bytes(4, 'little'))
        result.extend((block * 17 + i * 29) & 255 for i in range(4092))
    return bytes(result[:size])


def main():
    binary = sys.argv[1]
    backend = sys.argv[2]
    with tempfile.TemporaryDirectory() as directory:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        source = pathlib.Path(directory) / 'workloads.rut'
        source.write_text(f'listen 127.0.0.1:{port}\n'
                          'route GET "/small" { return workload(bytes: 4097) }\n'
                          'route GET "/large" { return workload(bytes: 1048576) }\n'
                          'route GET "/api" { wait(20ms) return workload(bytes: 4096) }\n')
        with open(pathlib.Path(directory) / 'server.log', 'w+') as log:
            proc = subprocess.Popen([binary, str(source), '--backend', backend,
                                     '--shards', '1', '--no-pin', '--drain', '0'],
                                    stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                        conn.connect()
                        break
                    except OSError:
                        if proc.poll() is not None or time.monotonic() > deadline:
                            log.seek(0)
                            raise AssertionError(log.read())
                        time.sleep(0.05)
                sock = conn.sock
                for route, size in [('small', 4097), ('large', 1048576), ('api', 4096),
                                    ('small', 4097)]:
                    start = time.monotonic()
                    conn.request('GET', '/' + route)
                    response = conn.getresponse()
                    assert response.status == 200
                    assert response.getheader('Content-Type') == 'application/octet-stream'
                    assert response.read() == payload(size)
                    assert conn.sock is sock, 'connection was not retained'
                    if route == 'api':
                        assert time.monotonic() - start >= 0.01
                conn.close()
            finally:
                proc.terminate()
                proc.wait(timeout=10)


if __name__ == '__main__':
    main()
