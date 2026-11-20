#!/usr/bin/env python3
"""A fixed subject cutoff runs after verification and before Redis."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
from test_jwt_sessions import KEY, NAMESPACE, Peer, exchange, permit_key, signed


def main():
    parser = argparse.ArgumentParser()
    for arg in ('server', 'source', 'testdata', 'backend', 'opt'):
        parser.add_argument('--' + arg, required=True)
    args = parser.parse_args()
    peer = Peer(Path(args.testdata), False)
    try:
        now = int(time.time())
        claims = dict(sub='alice', iss='issuer', aud='gateway', iat=now, exp=now + 600)
        cases = [(claims, 200), (dict(claims, iat=now - 1), 401),
                 (dict(claims, sub='bob'), 401), (dict(claims, iat=now + 120), 401),
                 (dict(claims, iat='bad'), 401), ({k: v for k, v in claims.items() if k != 'iat'}, 401)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = Path(args.source).resolve()
            shutil.copytree(original.parent / 'clients', root / 'clients')
            shutil.copytree(original.parent / 'middleware', root / 'middleware')
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            source = root / 'source.rut'
            source.write_text(original.read_text().replace('listen :8080', f'listen :{port}').replace('1700000000', str(now)))
            env = dict(os.environ, JWT_SECRET=KEY, JWT_PREVIOUS_SECRET='', JWT_ISSUER='issuer', JWT_AUDIENCE='gateway', JWT_SESSION_NAMESPACE=NAMESPACE,
                       REDIS_ENDPOINT=json.dumps(dict(address='127.0.0.1', port=peer.port)), REDIS_USERNAME='gateway', REDIS_PASSWORD='service-password', REDIS_DATABASE='1')
            log = root / 'log'
            with log.open('w') as output:
                process = subprocess.Popen([args.server, str(source), '--backend', args.backend, '--opt', args.opt, '--no-pin', '--shards', '1', '--drain', '0'], env=env, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        data = log.read_text()
                        if args.backend == 'io_uring' and 'io_uring is unavailable' in data:
                            return 77
                        raise AssertionError(data)
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, log.read_text()
                        time.sleep(.025)
                for payload, expected in cases:
                    token = signed(payload)
                    with peer.lock:
                        peer.store[permit_key(token)] = b'active'
                        before = len(peer.commands)
                    status, body, _, _ = exchange(port, 'HTTP/1.1', token)
                    assert status == expected, (payload, status, body, log.read_text())
                    if expected == 401:
                        with peer.lock:
                            assert len(peer.commands) == before
            finally:
                process.terminate()
                process.wait(5)
    finally:
        peer.close()
    print('PASS cutoff', args.backend)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
