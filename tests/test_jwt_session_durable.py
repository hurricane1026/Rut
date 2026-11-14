#!/usr/bin/env python3
"""Exact-token durable logout: independent wire faults and pinned Redis recovery."""
import argparse
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from test_auth_replay_durable import DurableStore
from test_jwt_sessions import ISSUE_KEY, KEY, NAMESPACE, Peer, exchange, permit_key, signed


@contextmanager
def gateway(args, store, directory):
    source = Path(args.source).resolve()
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
    if args.tls:
        endpoint.update(tls=True, caFile=str(Path(args.testdata) / 'localhost_cert.pem'),
                        serverName='localhost')
    env = dict(os.environ, JWT_SECRET=KEY, JWT_PREVIOUS_SECRET='', JWT_ISSUER='issuer',
               JWT_AUDIENCE='gateway', JWT_SESSION_NAMESPACE=NAMESPACE,
               REDIS_ENDPOINT=json.dumps(endpoint), REDIS_USERNAME='gateway',
               REDIS_PASSWORD='service-password', REDIS_DATABASE='1',
               SESSION_ISSUE_KEY=ISSUE_KEY, SESSION_SUBJECT='alice', SESSION_SCOPES='orders:read')
    log = root / 'gateway.log'
    with log.open('w') as output:
        process = subprocess.Popen([args.server, str(path), '--backend', args.backend,
                                    '--opt', str(args.opt), '--no-pin', '--shards', '1',
                                    '--drain', '0', '--max-connections-per-shard', '128'],
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
        assert KEY not in log.read_text() and 'service-password' not in log.read_text()


def token(lifetime=240, **extra):
    now = int(time.time())
    return signed(dict(sub='alice', iss='issuer', aud='gateway', iat=now,
                       exp=now + lifetime, jti='same-jti', **extra))


def revoke(port, value, expected=204, version='HTTP/1.1', **kwargs):
    status, body, challenges, cache = exchange(port, version, value, method='POST',
                                              path='/logout-durable', **kwargs)
    assert status == expected, (status, expected, body)
    if expected == 204:
        assert body == b'' and cache == ['no-store']
    if expected == 503:
        assert challenges == []


def wire(args, root):
    peer = Peer(Path(args.testdata), args.tls)
    try:
        with gateway(args, peer, root) as port:
            first, other = token(), token(nonce='other')
            with peer.lock:
                peer.store[permit_key(first)] = peer.store[permit_key(other)] = b'active'
            assert exchange(port, 'HTTP/1.1', first)[0] == 200
            for version in ('HTTP/1.0', 'HTTP/1.1'):
                with peer.lock:
                    before = len(peer.commands)
                revoke(port, first, version=version, fallback_token=other)
                with peer.lock:
                    commands = peer.commands[before:]
                    assert [c[0] for c in commands] == [b'AUTH', b'SELECT', b'SET', b'WAITAOF', b'RESET'], commands
                    assert peer.store[permit_key(first)] == b'revoked'
                    assert peer.store[permit_key(other)] == b'active'
                    assert peer.expiries[permit_key(first)] == json.loads(
                        base64.urlsafe_b64decode(first.split('.')[1] + '=='))['exp']
                assert exchange(port, version, first)[0] == 401
                assert exchange(port, version, other)[0] == 200
            revoke(port, token(nonce='absent'))  # An absent permit also gets a real write.
            with peer.lock:
                before = len(peer.commands)
            for invalid in (None, '', 'bad', token(lifetime=-1)):
                revoke(port, invalid, 401, fallback_token=other)
            revoke(port, other, 401, duplicate=True)
            assert exchange(port, 'HTTP/1.1', other, path='/logout-durable')[0] == 404
            with peer.lock:
                assert len(peer.commands) == before
            for mode in ('auth-error', 'select-error', 'set-error', 'set-bulk', 'set-integer',
                         'set-trailing', 'set-eof', 'set-timeout', 'aof-error', 'aof-timeout',
                         'aof-type', 'aof-local', 'aof-negative', 'aof-overflow', 'aof-arity',
                         'aof-trailing', 'aof-short', 'aof-eof', 'aof-hang', 'reset-error', 'reset-wrong'):
                with peer.lock:
                    peer.mode = mode
                revoke(port, token(nonce=mode), 503)
                with peer.lock:
                    peer.mode = 'normal'
                # Each poisoned lease must leave a subsequent initialized session usable.
                assert exchange(port, 'HTTP/1.1', other)[0] == 200
            for mode in ('set-fragmented', 'aof-fragmented', 'aof-delayed'):
                with peer.lock:
                    peer.mode = mode
                started = time.monotonic()
                revoke(port, token(nonce=mode))
                if mode == 'aof-delayed':
                    assert time.monotonic() - started >= .28
    finally:
        peer.close()



class SessionStore(DurableStore):
    def start(self):
        super().start()
        # Test ACL changes are in-memory; reinstall after every crash/restart.
        assert self.command(b'ACL', b'SETUSER', b'gateway',
                            ('~' + NAMESPACE + ':*').encode(), b'+get') == b'OK'


def live(args, root):
    store = SessionStore(args)
    try:
        first, other = token(), token(nonce='other')
        expiry = str(int(time.time()) + 240).encode()
        for value in (first, other):
            assert store.command(b'SET', permit_key(value), b'active', b'EXAT', expiry) == b'OK'
        with gateway(args, store, root) as port:
            assert exchange(port, 'HTTP/1.1', first)[0] == 200
            revoke(port, first)
            revoke(port, first)  # Repeated writes retain the exact signed expiry.
            ttl = store.command(b'PTTL', permit_key(first))
            assert 0 < ttl <= 240000
            store.kill()
            assert exchange(port, 'HTTP/1.1', first)[0] == 503
            store.start()
            assert store.command(b'GET', permit_key(first)) == b'revoked'
            assert 0 < store.command(b'PTTL', permit_key(first)) < ttl
            assert exchange(port, 'HTTP/1.1', first)[0] == 401
            assert exchange(port, 'HTTP/1.1', other)[0] == 200
        with gateway(args, store, root) as port:
            assert exchange(port, 'HTTP/1.1', first)[0] == 401
            assert store.command(b'ACL', b'SETUSER', b'gateway', b'-waitaof') == b'OK'
            revoke(port, other, 503)
            assert store.command(b'GET', permit_key(other)) == b'revoked'
            assert store.command(b'ACL', b'SETUSER', b'gateway', b'+waitaof') == b'OK'
            revoke(port, other)
            assert store.command(b'CONFIG', b'SET', b'maxmemory', b'1') == b'OK'
            revoke(port, token(nonce='full'), 503)
            assert store.command(b'CONFIG', b'SET', b'maxmemory', b'0') == b'OK'
            assert store.command(b'REPLICAOF', b'127.0.0.1', b'1') == b'OK'
            revoke(port, token(nonce='replica'), 503)
            assert store.command(b'REPLICAOF', b'NO', b'ONE') == b'OK'
            short = token(lifetime=3, nonce='expires')
            revoke(port, short)
            time.sleep(3.1)
            assert store.command(b'GET', permit_key(short)) is None
            assert exchange(port, 'HTTP/1.1', short)[0] == 401
            assert store.command(b'CONFIG', b'SET', b'appendonly', b'no') == b'OK'
            revoke(port, token(nonce='aof-disabled'), 503)
    finally:
        store.close()



def cleanup_recovery(args, root):
    store = SessionStore(args, disable_reset=True)
    try:
        value = token(nonce='cleanup-failed')
        with gateway(args, store, root) as port:
            revoke(port, value, 503)
            assert store.command(b'GET', permit_key(value)) == b'revoked'
            store.kill()
            store.start()
            assert store.command(b'GET', permit_key(value)) == b'revoked'
            # Cleanup remains unavailable: never publish an allow or an ack.
            assert exchange(port, 'HTTP/1.1', value)[0] == 503
            revoke(port, value, 503)
    finally:
        store.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rut-jwt-durable-') as directory:
        (live if args.live else wire)(args, Path(directory))
        if args.live:
            cleanup_recovery(args, Path(directory))
    print('PASS: durable exact-token logout, fail-closed replies and recovery' if args.live else
          'PASS: durable exact-token logout, wire faults and acknowledgement ordering')


if __name__ == '__main__':
    main()
