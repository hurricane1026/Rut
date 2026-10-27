#!/usr/bin/env python3
"""Exercise compiled CORS policy on HTTP/2 ordinary upstream timeouts."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time


def frame(kind, flags, stream, payload=b''):
    return len(payload).to_bytes(3, 'big') + bytes([kind, flags]) + stream.to_bytes(4, 'big') + payload


def request(port, origins, method, path='/timeout', peers=None, backend=None):
    path_bytes = path.encode()
    headers = bytes([0x86, 0x04, len(path_bytes)]) + path_bytes + bytes([0x01, 9]) + b'localhost'
    for name, value in [(':method', method)] + [('origin', o) for o in origins]:
        name, value = name.encode(), value.encode()
        headers += bytes([0, len(name)]) + name + bytes([len(value)]) + value
    with socket.create_connection(('127.0.0.1', port), timeout=40) as sock:
        sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) + frame(1, 5, 1, headers))
        def exact(size):
            result = b''
            while len(result) < size:
                part = sock.recv(size - len(result))
                assert part, 'incomplete HTTP/2 frame'
                result += part
            return result
        target_stream = 1
        dynamic = []
        attempts = 0
        while True:
            head = exact(9)
            payload = exact(int.from_bytes(head[:3], 'big'))
            kind, flags = head[3:5]
            stream = int.from_bytes(head[5:], 'big') & 0x7fffffff
            assert kind not in (3, 7), (kind, payload)
            if kind == 4 and not flags & 1:
                sock.sendall(frame(4, 1, 0))
            if stream == target_stream and kind == 1:
                # Fresh connection: these two names are HPACK static indices 8 and 20.
                # Parse field boundaries so an origin value in another field cannot pass.
                def integer(pos, bits):
                    limit = (1 << bits) - 1
                    value = payload[pos] & limit
                    pos += 1
                    if value == limit:
                        shift = 0
                        while True:
                            byte = payload[pos]
                            pos += 1
                            value += (byte & 127) << shift
                            if not byte & 128:
                                break
                            shift += 7
                    return value, pos
                def string(pos):
                    huffman = bool(payload[pos] & 128)
                    size, pos = integer(pos, 7)
                    return (huffman, payload[pos:pos + size]), pos + size
                fields = {}
                pos = 0
                while pos < len(payload):
                    byte = payload[pos]
                    if byte & 128:
                        index, pos = integer(pos, 7)
                        assert 62 <= index < 62 + len(dynamic), payload
                        name, value = dynamic[index - 62]
                        fields.setdefault(name, []).append(value)
                        continue
                    index, pos = integer(pos, 6 if byte & 64 else 4)
                    if index == 0:
                        _, pos = string(pos)
                    value, pos = string(pos)
                    fields.setdefault(index, []).append(value)
                    if byte & 64:
                        dynamic.insert(0, (index, value))
                status = fields.get(8)
                if path == '/timeout' and target_stream > 1 and status in ([(False, b'502')], [(True, bytes.fromhex('6c02'))]):
                    # io_uring can reject while the previous recv terminal drains.
                    assert fields.get(20) is None, fields
                    attempts += 1
                    if attempts == 1 and backend == 'io_uring':
                        peers['/timeout-100'].shutdown(socket.SHUT_RDWR)
                        peers['/timeout-100'].close()
                    assert attempts < 8, fields
                    target_stream += 2
                    sock.sendall(frame(1, 5, target_stream, headers))
                    continue
                assert status in ([(False, b'504')], [(True, bytes.fromhex('6c0d7f'))]), fields
                # RFC 7541 Huffman encoding of the allowed origin.
                encoded_origin = bytes.fromhex('9d29ad17186075d6b97c8e9ae82ae43d3f')
                if target_stream > 1 and backend == 'io_uring':
                    assert attempts > 0, 'expected a 502 while the old recv remains armed'
                expected = [(True, encoded_origin)] if origins == ['https://app.example.com'] and path == '/timeout' else None
                assert fields.get(20) == expected, (path, target_stream, origins, fields)
                assert flags & 1, (flags, payload)
                if path == '/timeout-100':
                    # Close the old peer so its outstanding io_uring recv can retire.
                    if backend != 'io_uring':
                        peers['/timeout-100'].shutdown(socket.SHUT_RDWR)
                        peers['/timeout-100'].close()
                    # A new stream must not inherit the previous episode's seen flag.
                    path = '/timeout'
                    target_stream = 3
                    headers = bytes([0x86, 0x04, 8]) + b'/timeout' + bytes([0x01, 9]) + b'localhost'
                    headers += bytes([0, 7]) + b':method' + bytes([3]) + b'GET'
                    headers += bytes([0, 6]) + b'origin' + bytes([23]) + b'https://app.example.com'
                    sock.sendall(frame(1, 5, target_stream, headers))
                    continue
                return


def main():
    binary, backend = sys.argv[1:]
    root = Path(__file__).resolve().parent.parent
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(16)
    listener.settimeout(0.2)
    clients = []
    peers = {}
    stop = threading.Event()
    def accept():
        while not stop.is_set():
            try:
                client = listener.accept()[0]
                clients.append(client)
                def serve(client):
                    try:
                        client.settimeout(5)
                        request_bytes = b''
                        while b'\r\n\r\n' not in request_bytes:
                            part = client.recv(4096)
                            if not part:
                                return
                            request_bytes += part
                        for code in (100, 103):
                            if f'/timeout-{code} '.encode() in request_bytes:
                                peers[f'/timeout-{code}'] = client
                                client.sendall(f'HTTP/1.1 {code} Informational\r\n\r\n'.encode())
                    except OSError:
                        pass
                threading.Thread(target=serve, args=(client,), daemon=True).start()
            except socket.timeout:
                pass
            except OSError:
                return
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-cors-h2-') as directory:
            path = Path(directory)
            (path / 'middleware').mkdir()
            (path / 'middleware/cors.rut').write_text((root / 'examples/middleware/cors.rut').read_text())
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                port = s.getsockname()[1]
            source = (root / 'examples/cors.rut').read_text()
            source = source.replace('upstream api at "127.0.0.1:9000"',
                                    f'upstream api at "127.0.0.1:{listener.getsockname()[1]}"')
            source = source.replace('listen 127.0.0.1:8080', '')
            source += '\nchain timeout_cors { after applyPolicy(req, resp, browserPolicy()) }\n'
            for method in ('GET', 'HEAD'):
                for route in ('/timeout', '/timeout-100', '/timeout-103'):
                    source += f'route {method} "{route}" use chain timeout_cors {{ return forward(api, load_balance: .roundRobin) }}\n'
            source += f'\nlisten 127.0.0.1:{port}\n'
            (path / 'main.rut').write_text(source)
            with (path / 'runtime.log').open('w+') as log:
                process = subprocess.Popen([binary, str(path / 'main.rut'), '--backend', backend,
                                            '--shards', '1', '--no-pin', '--max-connections-per-shard', '128'], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            log.seek(0)
                            output = log.read()
                            if backend == 'io_uring' and 'io_uring is unavailable' in output:
                                return 77
                            raise RuntimeError(output)
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                                break
                        except OSError:
                            time.sleep(0.05)
                    else:
                        raise RuntimeError('gateway startup timeout')
                    cases = [(['https://app.example.com'], 'GET'), (['https://evil.example'], 'GET'),
                             ([], 'GET'), (['https://app.example.com', 'https://app.example.com'], 'GET'),
                             (['https://app.example.com'], 'HEAD'),
                             (['https://app.example.com'], 'GET', '/timeout-100'),
                             (['https://app.example.com'], 'GET', '/timeout-103')]
                    with ThreadPoolExecutor(max_workers=len(cases)) as pool:
                        for future in [pool.submit(request, port, *case, peers=peers, backend=backend) for case in cases]:
                            future.result()
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)
        for client in clients:
            client.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
