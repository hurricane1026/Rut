#!/usr/bin/env python3
"""Confirmed replay admission against pinned Redis, including SIGKILL/AOF recovery."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import uuid

from test_auth_replay import exchange, gateway
from test_redis_commands import REDIS_IMAGE, packet, read_value


class DurableStore:
    def __init__(self, args, disable_reset=False):
        self.name = 'rut-auth-replay-' + uuid.uuid4().hex
        self.context = None
        if args.tls:
            self.context = ssl.create_default_context(
                cafile=str(Path(args.testdata) / 'localhost_cert.pem'))
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            self.port = probe.getsockname()[1]
        settings = ['--save', '', '--appendonly', 'yes', '--appendfsync', 'always',
                    '--aof-use-rdb-preamble', 'no', '--maxmemory-policy', 'noeviction',
                    '--user', 'default', 'on', '>service-password', '~*', '+@all',
                    '--user', 'gateway', 'on', '>service-password', '~replay:billing:*',
                    '+auth', '+select', '+set', '+waitaof', '+reset']
        if disable_reset:
            settings += ['--rename-command', 'RESET', '']
        if args.tls:
            settings += ['--port', '0', '--tls-port', '6379', '--tls-auth-clients', 'no',
                         '--tls-cert-file', '/tmp/localhost_cert.pem',
                         '--tls-key-file', '/tmp/localhost_key.pem',
                         '--tls-ca-cert-file', '/tmp/localhost_cert.pem']
        try:
            self.docker('create', '--name', self.name, '--label',
                        'rut.test.suite=auth-durable-replay', '-p', f'127.0.0.1:{self.port}:6379',
                        REDIS_IMAGE, 'redis-server', *settings)
            if args.tls:
                for filename in ('localhost_cert.pem', 'localhost_key.pem'):
                    self.docker('cp', str(Path(args.testdata) / filename),
                                self.name + ':/tmp/' + filename)
            self.start()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def docker(*arguments):
        return subprocess.check_output(['docker', *arguments], stderr=subprocess.STDOUT, timeout=30)

    def start(self):
        self.docker('start', self.name)
        deadline = time.monotonic() + 15
        while True:
            try:
                assert self.command(b'PING') == b'PONG'
                return
            except (OSError, EOFError):
                assert time.monotonic() < deadline, self.docker('logs', self.name)
                time.sleep(.05)

    def kill(self):
        self.docker('kill', '--signal', 'KILL', self.name)
        self.docker('wait', self.name)

    def command(self, *arguments):
        connection = socket.create_connection(('127.0.0.1', self.port), timeout=2)
        if self.context:
            connection = self.context.wrap_socket(connection, server_hostname='localhost')
        with connection, connection.makefile('rb') as stream:
            connection.sendall(packet([b'AUTH', b'service-password']) +
                               packet([b'SELECT', b'1']) + packet(list(arguments)))
            assert read_value(stream) == b'OK'
            assert read_value(stream) == b'OK'
            return read_value(stream)

    def close(self):
        subprocess.run(['docker', 'rm', '-fv', self.name], capture_output=True, timeout=30)


def key(message):
    return b'replay:billing:' + hashlib.sha256(message.encode()).hexdigest().encode()


def cleanup_failure_recovery(args, root):
    # RESET is an unauthenticated recovery command; ordinary ACL denial does
    # not disable it. An isolated instance removes the command at startup.
    store = DurableStore(args, disable_reset=True)
    try:
        with gateway(args, Path(args.source).resolve(), store, root) as port:
            name = 'persisted-before-cleanup-error'
            assert exchange(port, name) == 503
            assert store.command(b'GET', key(name)) == b'claimed'
            ttl = store.command(b'PTTL', key(name))
            store.kill()
            store.start()
            assert store.command(b'GET', key(name)) == b'claimed'
            remaining = store.command(b'PTTL', key(name))
            assert 0 < remaining < ttl
            assert exchange(port, name) == 503  # Cleanup still unavailable.
            assert 0 < store.command(b'PTTL', key(name)) <= remaining
    finally:
        store.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    args = parser.parse_args()
    store = DurableStore(args)
    try:
        assert store.command(b'CONFIG', b'GET', b'appendonly') == [b'appendonly', b'yes']
        assert store.command(b'CONFIG', b'GET', b'appendfsync') == [b'appendfsync', b'always']
        assert store.command(b'CONFIG', b'GET', b'maxmemory-policy') == [b'maxmemory-policy', b'noeviction']
        with tempfile.TemporaryDirectory(prefix='rut-auth-durable-') as directory:
            root = Path(directory)
            with gateway(args, Path(args.source).resolve(), store, root) as port:
                assert exchange(port, 'persisted') == 204
                assert exchange(port, 'persisted', h2=True) == 409
                assert store.command(b'GET', key('persisted')) == b'claimed'
                ttl = store.command(b'PTTL', key('persisted'))
                assert 590000 < ttl <= 601000
                with ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(lambda _: exchange(port, 'concurrent'), range(12)))
                assert results.count(204) == 1 and results.count(409) == 11, results
                # There is no graceful shutdown or final save. Recovery must use
                # the exact data volume retained by this container's AOF.
                store.kill()
                assert exchange(port, 'persisted') == 503
                assert exchange(port, 'while-down') == 503
                store.start()
                assert store.command(b'GET', key('persisted')) == b'claimed'
                assert 0 < store.command(b'PTTL', key('persisted')) < ttl
                assert exchange(port, 'persisted') == 409
                assert exchange(port, 'concurrent', h2=True) == 409
                assert exchange(port, 'while-down') == 204
            with gateway(args, Path(args.source).resolve(), store, root) as port:
                assert exchange(port, 'persisted') == 409
                assert exchange(port, 'after-both-restarts', h2=True) == 204
                # An applied SET cannot allow if the principal cannot confirm
                # persistence. Restoring the permission reveals the kept claim.
                assert store.command(b'ACL', b'SETUSER', b'gateway', b'-waitaof') == b'OK'
                assert exchange(port, 'denied-barrier') == 503
                assert store.command(b'GET', key('denied-barrier')) == b'claimed'
                assert store.command(b'ACL', b'SETUSER', b'gateway', b'+waitaof') == b'OK'
                assert exchange(port, 'denied-barrier') == 409
                assert store.command(b'CONFIG', b'SET', b'maxmemory', b'1') == b'OK'
                assert exchange(port, 'full-store') == 503
                assert store.command(b'GET', key('full-store')) is None
                assert store.command(b'CONFIG', b'SET', b'maxmemory', b'0') == b'OK'
                assert exchange(port, 'full-store') == 204
                # A fixed endpoint that becomes a read-only replica must fail
                # closed. No stale read can turn a missing claim into admission.
                assert store.command(b'REPLICAOF', b'127.0.0.1', b'1') == b'OK'
                assert exchange(port, 'replica-role') == 503
                assert store.command(b'REPLICAOF', b'NO', b'ONE') == b'OK'
                assert exchange(port, 'replica-role') == 204
                assert store.command(b'CONFIG', b'SET', b'appendonly', b'no') == b'OK'
                assert exchange(port, 'aof-disabled') == 503
                assert store.command(b'GET', key('aof-disabled')) == b'claimed'
                assert exchange(port, 'aof-disabled') == 503
            cleanup_failure_recovery(args, root)
        print('PASS: confirmed local AOF replay, SIGKILL recovery, TTL, concurrency and fail-closed service policy')
    finally:
        store.close()


if __name__ == '__main__':
    main()
