#!/usr/bin/env python3
"""Live H1/H2 consistent hashing, checked against an independent Python oracle."""
import argparse
import hashlib
import hmac
import http.client
import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time
from auth_h2_fixture import request as h2_request, frame, string, status

SEED = '0123456789abcdef0123456789abcdef'


def winner(key, ports, weights, tag=1):
    digest = hmac.digest(bytes.fromhex(SEED), b'rut-lb-key-v1' + bytes([tag]) +
                         len(key).to_bytes(4, 'big') + key, 'sha256')
    best = None
    for i, (port, weight) in enumerate(zip(ports, weights)):
        if weight == 0:
            continue
        endpoint = b'\x04\x7f\x00\x00\x01' + port.to_bytes(2, 'big')
        value = max(1, int.from_bytes(hashlib.sha256(b'rut-lb-hrw-v1' + digest + endpoint).digest()[:8], 'big'))
        n = value.bit_length() - 1
        x, fraction = value << (63 - n), 0
        for bit in range(1, 33):
            x = x * x >> 63
            if x >= 1 << 64:
                x >>= 1
                fraction |= 1 << (32 - bit)
        cost = ((64 - n) << 32) - fraction
        if best is None or cost * best[1] < best[0] * weight or (
                cost * best[1] == best[0] * weight and endpoint < best[2]):
            best = cost, weight, endpoint, i
    return best[3]


def kong_properties(ports):
    """Optional semantic comparison; the two algorithms need not pick the same node."""
    from test_kong_differential import available_port, wait_for_kong
    image = next(line.strip() for line in (Path(__file__).parent / 'pinned-kong-image.txt').read_text().splitlines()
                 if line.strip() and not line.startswith('#'))
    name = 'rut-consistent-hash-' + uuid.uuid4().hex[:12]
    port = available_port()
    targets = [{'target': f'127.0.0.1:{p}', 'weight': w} for p, w in zip(ports, (1, 3, 0))]
    def configuration(items):
        return {'_format_version': '3.0', 'upstreams': [{'name': 'api', 'algorithm': 'consistent-hashing',
                 'hash_on': 'header', 'hash_on_header': 'key', 'targets': items}],
                'services': [{'name': 'svc', 'host': 'api', 'port': 80, 'routes': [
                    {'name': 'route', 'paths': ['/'], 'strip_path': False}]}]}
    def mapping(items):
        subprocess.run(['docker', 'run', '--detach', '--name', name, '--network', 'host',
            '--pull', 'never', '--ulimit', 'nofile=4096:4096', '--env', 'KONG_DATABASE=off',
            '--env', 'KONG_DECLARATIVE_CONFIG_STRING=' + json.dumps(configuration(items)),
            '--env', f'KONG_PROXY_LISTEN=127.0.0.1:{port}', '--env', 'KONG_ADMIN_LISTEN=off',
            '--env', 'KONG_STATUS_LISTEN=off', '--env', 'KONG_NGINX_WORKER_PROCESSES=1',
            '--env', 'KONG_PROXY_ACCESS_LOG=off', image], check=True, stdout=subprocess.DEVNULL)
        try:
            wait_for_kong(port, name)
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            values = []
            try:
                for i in range(500):
                    connection.request('GET', '/', headers={'Key': hashlib.sha256(str(i).encode()).hexdigest()})
                    response = connection.getresponse()
                    body = response.read()
                    assert response.status == 200, (response.status, body)
                    values.append(body)
            finally:
                connection.close()
            return values
        finally:
            subprocess.run(['docker', 'rm', '-f', name], check=True, stdout=subprocess.DEVNULL)
    original = mapping(targets)
    assert original == mapping(list(reversed(targets)))
    assert all(v in (b'0', b'1') for v in original)
    assert 300 < original.count(b'1') < 450, original.count(b'1')
    added = mapping([{**t, 'weight': 1} if t['weight'] == 0 else t for t in targets])
    assert b'2' in added and all(v in (b'0', b'1', b'2') for v in added)
    old_to_old = sum(new != old and new != b'2' for old, new in zip(original, added))
    print('Pinned Kong: header affinity, weighted distribution, zero disablement and reorder passed; '
          f'addition moved {old_to_old}/500 keys between old targets (Ketama/HRW difference)')


def multiplex(port, keys):
    """Different stream keys share an H2 connection, within its proxy capacity."""
    with socket.create_connection(('127.0.0.1', port), timeout=8) as connection:
        wire = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0)
        connection.sendall(wire)
        def send_stream(i):
            headers = (b'\x82\x86\x04' + string('/hash-close') + b'\x01' + string('localhost') +
                       b'\x00' + string('x-key') + string(keys[i]))
            connection.sendall(frame(1, 5, 2 * i + 1, headers))
        send_stream(0)
        replies, codes, done = {}, {}, set()
        def exact(length):
            value = b''
            while len(value) < length:
                chunk = connection.recv(length - len(value))
                assert chunk, 'multiplexed response closed early'
                value += chunk
            return value
        while len(done) < len(keys):
            header = exact(9)
            payload = exact(int.from_bytes(header[:3], 'big'))
            kind, flags = header[3:5]
            stream = int.from_bytes(header[5:], 'big') & 0x7fffffff
            assert kind not in (3, 7), (kind, payload)
            if kind == 4 and not flags & 1:
                connection.sendall(frame(4, 1, 0))
            if stream and kind == 1:
                codes[stream] = status(payload)
            if stream and kind == 0:
                replies[stream] = replies.get(stream, b'') + payload
            if stream and kind in (0, 1) and flags & 1:
                done.add(stream)
                if len(done) < len(keys):
                    send_stream(len(done))
        return [(codes[2*i+1], replies.get(2*i+1, b'')) for i in range(len(keys))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    parser.add_argument('--kong', action='store_true', help='also check pinned Kong semantic properties')
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    servers, processes = [], []
    observed = [0, 0, 0]
    try:
        for i in range(3):
            def handler(identity):
                class Origin(BaseHTTPRequestHandler):
                    protocol_version = 'HTTP/1.1'
                    def do_GET(self):
                        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        observed[identity] += 1
                        body = str(identity).encode()
                        self.send_response(200)
                        self.send_header('Content-Length', '1')
                        if self.path == '/hash-close':
                            self.send_header('Connection', 'close')
                        self.end_headers()
                        self.wfile.write(body)
                    def log_message(self, *unused):
                        pass
                return Origin
            origin = ThreadingHTTPServer(('127.0.0.1', 0), handler(i))
            threading.Thread(target=origin.serve_forever, daemon=True).start()
            servers.append(origin)
        ports = [s.server_port for s in servers]
        if args.kong:
            kong_properties(ports)
            observed[:] = [0, 0, 0]
        with tempfile.TemporaryDirectory(prefix='rut-consistent-hash-') as directory:
            root = Path(directory)
            gateway_ports = []
            for reorder, shards in ((False, 1), (True, 2)):
                endpoints = list(zip(ports, (1, 3, 0)))
                if reorder:
                    endpoints.reverse()
                addresses = ', '.join(f'"127.0.0.1:{p}": {w}' for p, w in endpoints)
                off = ', '.join(f'"127.0.0.1:{p}": 0' for p in ports)
                source = f'''upstream api {{ backends: [{addresses}] }}
upstream off {{ backends: [{off}] }}
route GET "/hash" {{ return forward(api, load_balance: .consistentHash,
    hash_key: req.header("X-Key").or(""), hash_seed: env("RUT_HASH_TEST_SEED")) }}
route GET "/hash-close" {{ return forward(api, load_balance: .consistentHash,
    hash_key: req.header("X-Key").or(""), hash_seed: "{SEED}") }}
route GET "/ip" {{ return forward(api, load_balance: .consistentHash,
    hash_key: req.remoteAddr, hash_seed: "{SEED}") }}
route GET "/off" {{ return forward(off, load_balance: .consistentHash,
    hash_key: "fixed", hash_seed: "{SEED}") }}
'''
                program, log = root / f'{shards}.rut', root / f'{shards}.log'
                program.write_text(source)
                with log.open('wb') as output:
                    process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                                '--no-pin', '--shards', str(shards), '--drain', '0'],
                                               stdout=output, stderr=subprocess.STDOUT,
                                               env={**os.environ, "RUT_HASH_TEST_SEED": SEED})
                processes.append(process)
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    text = log.read_text(errors='replace')
                    match = re.search(r'Listening on port ([0-9]+) with', text)
                    if match:
                        gateway_ports.append(int(match[1]))
                        break
                    if process.poll() is not None:
                        if args.backend == 'io_uring' and 'io_uring is unavailable' in text:
                            return 77
                        raise AssertionError(text)
                    time.sleep(.025)
                else:
                    raise AssertionError(log.read_text())
            for port in gateway_ports:
                keys = [f'tenant-{i}' for i in range(2)]
                expected = [(200, str(winner(k.encode(), ports, (1, 3, 0))).encode()) for k in keys]
                replies = multiplex(port, keys)
                assert replies == expected, (args.backend, port, keys, replies, expected)
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
                def h1(path, headers):
                    connection.request('GET', path, headers=dict(headers))
                    response = connection.getresponse()
                    return response.status, response.read()
                try:
                    for request in (h1, lambda path, headers: h2_request(port, path, headers)):
                        # Reused H1 connections, cold H2 connections and different shard counts.
                        for k in range(100):
                            key = f'tenant-{k}'.encode()
                            expected = str(winner(key, ports, (1, 3, 0))).encode()
                            assert request('/hash', [('X-Key', key.decode())]) == (200, expected)
                        expected = str(winner(socket.inet_aton('127.0.0.1'), ports, (1, 3, 0), 2)).encode()
                        assert request('/ip', []) == (200, expected)
                        before = sum(observed)
                        for headers in ([], [('X-Key', 'x' * 4097)]):
                            code, body = request('/hash', headers)
                            assert code == 400, (code, body)
                        assert sum(observed) == before
                        assert request('/off', [])[0] == 503
                finally:
                    connection.close()
            assert observed[2] == 0, observed
            print(f'Consistent hash oracle, H1/H2, reorder, shards, invalid keys passed: {args.backend}')
            return 0
    finally:
        for process in processes:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for origin in servers:
            origin.shutdown()
            origin.server_close()


if __name__ == '__main__':
    raise SystemExit(main())
