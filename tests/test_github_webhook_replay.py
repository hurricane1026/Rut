#!/usr/bin/env python3
"""GitHub webhook authentication plus atomic X-GitHub-Delivery replay claims."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import traceback

SECRET = 'github-webhook-fixture-0123456789'
DELIVERY = '72d3162e-cc78-11e3-81ab-4c9367dc0958'


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.claims = {}
        self.commands = []
        self.mode = 'normal'
        self.errors = []
        self.workers = []
        self.stopping = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(64)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self.serve, args=(connection,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, connection):
        try:
            connection.settimeout(3)
            with connection, connection.makefile('rb') as stream:
                authenticated, selected = False, False
                while True:
                    line = stream.readline(64)
                    if not line:
                        return
                    assert line.startswith(b'*'), line
                    count = int(line[1:])
                    assert 1 <= count <= 6
                    args = []
                    for _ in range(count):
                        line = stream.readline(64)
                        assert line.startswith(b'$')
                        length = int(line[1:])
                        assert 0 <= length <= 8192
                        args.append(stream.read(length))
                        assert stream.read(2) == b'\r\n'
                    with self.lock:
                        mode = self.mode
                        self.commands.append(args)
                    if args[0] == b'AUTH':
                        assert args == [b'AUTH', b'gateway', b'service-password']
                        authenticated = mode != 'auth-error'
                        reply = b'+OK\r\n' if authenticated else b'-WRONGPASS\r\n'
                    elif args[0] == b'SELECT':
                        assert args == [b'SELECT', b'1']
                        selected = authenticated and mode != 'select-error'
                        reply = b'+OK\r\n' if selected else b'-ERR\r\n'
                    elif args[0] == b'SET':
                        assert authenticated and selected
                        assert args[2:] == [b'claimed', b'NX', b'EX', b'601'], args
                        assert args[1].startswith(b'replay:github:'), args[1]
                        assert len(args[1].split(b':')[-1]) == 64
                        with self.lock:
                            duplicate = self.claims.get(args[1], 0) > time.monotonic()
                            if not duplicate and mode != 'set-error':
                                self.claims[args[1]] = time.monotonic() + 601
                        reply = b'$-1\r\n' if duplicate else b'+OK\r\n'
                        if mode == 'set-error':
                            reply = b'-ERR full\r\n'
                    elif args[0] == b'RESET':
                        authenticated, selected = False, False
                        reply = b'-ERR\r\n' if mode == 'reset-error' else b'+RESET\r\n'
                    else:
                        raise AssertionError(args)
                    connection.sendall(reply)
        except (OSError, ValueError):
            pass
        except Exception:
            with self.lock:
                self.errors.append(traceback.format_exc())

    def close(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(2)
        for worker in self.workers:
            worker.join(4)
        assert not self.errors, self.errors


def signature(body, key=SECRET):
    return 'sha256=' + hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def exchange(port, delivery, body=b'{"action":"opened"}', key=SECRET,
             omit_delivery=False, duplicate_delivery=False):
    headers = ''
    if not omit_delivery:
        headers += f'X-GitHub-Delivery: {delivery}\r\n'
    if duplicate_delivery:
        headers += f'X-GitHub-Delivery: {delivery}\r\n'
    headers += f'X-Hub-Signature-256: {signature(body, key)}\r\nContent-Type: application/json\r\n'
    wire = (f'POST /webhooks/github HTTP/1.1\r\nHost: local\r\nConnection: close\r\n' +
            headers + f'Content-Length: {len(body)}\r\n\r\n').encode() + body
    with socket.create_connection(('127.0.0.1', port), timeout=8) as connection:
        connection.sendall(wire)
        data = b''
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            data += chunk
    return int(data.split(b' ', 2)[1])


@contextmanager
def gateway(args, source, store, directory):
    root = directory / str(time.monotonic_ns())
    root.mkdir()
    shutil.copytree(source.parent / 'clients', root / 'clients')
    shutil.copytree(source.parent / 'middleware', root / 'middleware')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    path = root / 'auth.rut'
    path.write_text(source.read_text().replace('listen :8080', f'listen :{port}'))
    endpoint = dict(address='127.0.0.1', port=store.port, poolIdleMs=5000)
    env = dict(os.environ,
               GITHUB_WEBHOOK_SECRET=SECRET,
               REPLAY_NAMESPACE='replay:github',
               REDIS_ENDPOINT=json.dumps(endpoint),
               REDIS_USERNAME='gateway',
               REDIS_PASSWORD='service-password',
               REDIS_DATABASE='1')
    log = root / 'gateway.log'
    with log.open('w') as output:
        process = subprocess.Popen(
            [args.server, str(path), '--backend', args.backend, '--opt', str(args.opt),
             '--no-pin', '--shards', '2', '--drain', '0',
             '--max-connections-per-shard', '128'],
            env=env, stdout=output, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 60
        while True:
            if process.poll() is not None:
                if args.backend == 'io_uring' and 'io_uring is unavailable' in log.read_text():
                    raise SystemExit(77)
                raise AssertionError(log.read_text())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(.025)
        path.unlink()
        shutil.rmtree(root / 'clients')
        shutil.rmtree(root / 'middleware')
        yield port
    finally:
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        assert SECRET not in log.read_text() and 'service-password' not in log.read_text()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', required=True)
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    args = parser.parse_args()
    store = Store()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-github-replay-') as tmp:
            with gateway(args, Path(args.source).resolve(), store, Path(tmp)) as port:
                for name, options in [('wrong-key', dict(key='wrong')),
                                      ('missing-delivery', dict(omit_delivery=True)),
                                      ('duplicate-delivery', dict(duplicate_delivery=True))]:
                    before = len(store.commands)
                    assert exchange(port, name, **options) == (400 if name != 'wrong-key' else 401), name
                    assert len(store.commands) == before, name
                body = b'{"action":"opened"}'
                assert exchange(port, DELIVERY, body=body) == 204
                # X-GitHub-Delivery is not signed: changing it must not re-admit
                # the same signed body.
                assert exchange(port, 'other-delivery', body=body) == 409
                assert exchange(port, 'third-delivery', body=body) == 409
                # A different signed body is a different message even when the
                # unsigned delivery header is reused.
                assert exchange(port, DELIVERY, body=b'{"action":"closed"}') == 204
                assert exchange(port, DELIVERY, body=b'{"action":"closed"}') == 409
                with ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(
                        lambda _: exchange(port, 'concurrent-delivery',
                                           body=b'{"action":"concurrent"}'), range(12)))
                assert results.count(204) == 1 and results.count(409) == 11, results
                for mode, expected in [('auth-error', 503), ('select-error', 503),
                                       ('set-error', 503), ('reset-error', 503)]:
                    with store.lock:
                        store.mode = mode
                    assert exchange(port, mode, body=mode.encode()) == expected, mode
                with store.lock:
                    store.mode = 'normal'
                # A SET applied before an uncertain cleanup stays claimed.
                assert exchange(port, 'reset-error', body=b'reset-error') == 409
            # The authoritative store survives a gateway restart.
            with gateway(args, Path(args.source).resolve(), store, Path(tmp)) as port:
                assert exchange(port, DELIVERY) == 409
                assert exchange(port, 'new-after-restart',
                                body=b'{"action":"after-restart"}') == 204
        print('PASS: GitHub delivery authentication, atomic claim, concurrency and restart')
    finally:
        store.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
