#!/usr/bin/env python3
"""Exercise the Rut Kafka and S3 clients against local protocol fixtures."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time


class BackendUnavailable(Exception):
    pass


@contextmanager
def run_rut(args, source, **settings):
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            [args.server, '0', str(source), '--backend', args.backend,
             '--shards', '1', '--no-pin', '--drain', '0', '--max-connections-per-shard', '32'],
            env=dict(os.environ, **settings), stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                startup = os.pread(log.fileno(), 65536, 0)
                match = re.search(rb'Listening on port ([0-9]+) with', startup)
                if match:
                    yield int(match.group(1))
                    return
                if process.poll() is not None:
                    if args.backend == 'io_uring' and b'io_uring is unavailable' in startup:
                        raise BackendUnavailable
                    break
                time.sleep(.02)
            raise AssertionError(os.pread(log.fileno(), 65536, 0).decode())
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def request(port, method, path, body=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
    try:
        conn.request(method, path, body, {'Authorization': 'Bearer incoming'})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def kafka_broker(listener, exchanges):
    for api, version, correlation, body, reply in exchanges:
        conn, _ = listener.accept()
        with conn, conn.makefile('rb') as incoming:
            conn.settimeout(5)
            expected = struct.pack('>hhih', api, version, correlation, 3) + b'rut' + body
            assert incoming.read(4) == struct.pack('>i', len(expected))
            assert incoming.read(len(expected)) == expected
            # Split the size and payload across writes to exercise readExactly.
            for part in (reply[:2], reply[2:5], reply[5:]):
                conn.sendall(part)
                time.sleep(.015)
            assert incoming.read(1) == b''


def framed(correlation, payload):
    return struct.pack('>ii', len(payload) + 4, correlation) + payload


def test_kafka(args, source):
    topic = b'orders'
    name = struct.pack('>h', len(topic)) + topic
    versions = struct.pack('>hihhh', 0, 1, 3, 0, 4)
    metadata = struct.pack('>iihii', 0, 0, -1, -1, 1)
    metadata += struct.pack('>h', 3) + name + struct.pack('>?i', False, 0)
    offset = (1 << 40) + 9
    offset_reply = struct.pack('>i', 1) + name + struct.pack('>iihqq', 1, 7, 0, -1, offset)
    offset_query = struct.pack('>ii', -1, 1) + name + struct.pack('>iiq', 1, 7, -1)
    exchanges = [
        (18, 0, 1, b'', framed(1, versions)),
        (3, 4, 2, struct.pack('>i', 1) + name + b'\0', framed(2, metadata)),
        (2, 1, 3, offset_query, framed(3, offset_reply)),
        (2, 1, 3, offset_query, framed(4, offset_reply)),
        (2, 1, 3, offset_query, framed(3, offset_reply[:-1])),
        (2, 1, 3, offset_query, framed(3, struct.pack('>i', 1) + name
                                     + struct.pack('>iihqq', 1, 7, 6, -1, -1))),
        (18, 0, 1, b'', struct.pack('>i', 8193)),
    ]
    with socket.create_server(('127.0.0.1', 0)) as listener:
        listener.settimeout(5)
        endpoint = json.dumps(dict(address='127.0.0.1', port=listener.getsockname()[1]))
        with run_rut(args, source, KAFKA_ENDPOINT=endpoint, KAFKA_TOPIC=topic.decode()) as port:
            with ThreadPoolExecutor(max_workers=1) as executor:
                broker = executor.submit(kafka_broker, listener, exchanges)
                assert request(port, 'GET', '/versions') == (200, versions)
                assert request(port, 'GET', '/metadata') == (200, metadata)
                assert request(port, 'GET', '/offset/-1')[0] == 400
                assert request(port, 'GET', '/offset/7') == (200, str(offset).encode())
                for _ in range(3):
                    assert request(port, 'GET', '/offset/7')[0] == 502
                assert request(port, 'GET', '/versions')[0] == 502
                broker.result(timeout=6)


def test_s3(args, source):
    get_path, put_path, delete_path = (
        f'/bucket/a%20b?X-Amz-Signature={verb}&X-Amz-Credential=key%2Fscope'
        for verb in ('get', 'put', 'delete')
    )
    list_path = '/bucket?list-type=2&X-Amz-Signature=listing'
    output = b'<ListBucketResult/>'
    uploaded = 'hello "Rut"\n世界'.encode()
    received = []
    responses = iter([(200, uploaded), (200, b''), (204, b''), (200, output),
                      (404, b''), (307, b'')])

    class Origin(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def reply(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            received.append((self.command, self.path, self.headers['Host'],
                             self.headers.get('Authorization'), body))
            status, data = next(responses)
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            if status == 307:
                self.send_header('Location', '/must-not-follow')
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_PUT = do_DELETE = reply

        def log_message(self, *_args):
            pass

    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin) as origin:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert = Path(args.testdata) / 'localhost_cert.pem'
        context.load_cert_chain(cert, Path(args.testdata) / 'localhost_key.pem')
        origin.socket = context.wrap_socket(origin.socket, server_side=True)
        thread = threading.Thread(target=origin.serve_forever)
        thread.start()
        try:
            endpoint = dict(address='127.0.0.1', port=origin.server_port,
                            serverName='localhost', caFile=str(cert.resolve()))
            settings = {
                f'S3_{operation}_ENDPOINT': json.dumps(dict(endpoint, path=path))
                for operation, path in zip(('GET', 'PUT', 'DELETE', 'LIST'),
                                           (get_path, put_path, delete_path, list_path))
            }
            with run_rut(args, source, **settings) as port:
                assert request(port, 'GET', '/object') == (200, uploaded)
                assert request(port, 'PUT', '/object', uploaded) == (204, b'')
                assert request(port, 'DELETE', '/object') == (204, b'')
                assert request(port, 'GET', '/objects') == (200, output)
                assert request(port, 'GET', '/object')[0] == 404
                assert request(port, 'PUT', '/object', b'x' * 4097)[0] == 413
                assert request(port, 'GET', '/object')[0] == 502
            host = f'localhost:{origin.server_port}'
            assert received == [
                ('GET', get_path, host, None, b''),
                ('PUT', put_path, host, None, uploaded),
                ('DELETE', delete_path, host, None, b''),
                ('GET', list_path, host, None, b''),
                ('GET', get_path, host, None, b''),
                ('GET', get_path, host, None, b''),
            ]
        finally:
            origin.shutdown()
            thread.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    args = parser.parse_args()
    examples = Path(__file__).resolve().parents[1] / 'examples'
    try:
        test_kafka(args, examples / 'kafka-client.rut')
        test_s3(args, examples / 's3-client.rut')
    except BackendUnavailable:
        return 77
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
