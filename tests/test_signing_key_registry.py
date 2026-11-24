#!/usr/bin/env python3
"""Bounded multi-key signed-request and Standard Webhooks registry."""
import argparse
import base64
from email.utils import formatdate
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time


def registry_env(slots):
    env = {}
    for index in range(1, 9):
        values = slots.get(index, {})
        env[f'KEY_ID_{index}'] = values.get('keyId', '')
        env[f'KEY_{index}'] = values.get('key', '')
        env[f'CONSUMER_{index}'] = values.get('consumer', '')
        env[f'CREDENTIAL_{index}'] = values.get('credential', '')
    return env


def signed_request(port, key_id, secret, method='POST', target='/signed',
                   body=b'payload', now=None):
    date = formatdate(int(time.time()) if now is None else now, usegmt=True)
    digest = 'SHA-256=' + base64.b64encode(hashlib.sha256(body).digest()).decode()
    canonical = (f'{key_id}\n{method} {target}\n'
                 f'date: {date}\ndigest: {digest}\n').encode()
    signature = base64.b64encode(hmac.new(secret.encode(), canonical,
                                          hashlib.sha256).digest()).decode()
    authorization = (f'Signature keyId="{key_id}",algorithm="hmac-sha256",'
                     f'headers="@request-target date digest",signature="{signature}"')
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=6)
    connection.request(method, target, body,
                       {'Authorization': authorization, 'Date': date,
                        'Digest': digest, 'Content-Type': 'application/octet-stream'})
    response = connection.getresponse()
    status, content = response.status, response.read()
    connection.close()
    return status, content


def webhook_request(port, secret, body=b'event', identifier='evt-1', now=None):
    timestamp = str(int(time.time()) if now is None else now)
    signature = base64.b64encode(
        hmac.new(secret.encode(), f'{identifier}.{timestamp}.'.encode() + body,
                 hashlib.sha256).digest()).decode()
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=6)
    connection.request('POST', '/webhook', body,
                       {'webhook-id': identifier, 'webhook-timestamp': timestamp,
                        'webhook-signature': 'v1,' + signature,
                        'Content-Type': 'application/octet-stream'})
    response = connection.getresponse()
    status, content = response.status, response.read()
    connection.close()
    return status, content


class Gateway:
    def __init__(self, server, source, env, backend):
        self.server = server
        self.env = env
        self.directory = tempfile.TemporaryDirectory(prefix='rut-signing-registry-')
        root = Path(self.directory.name)
        shutil.copytree(Path(source).resolve().parent / 'middleware', root / 'middleware')
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            self.port = probe.getsockname()[1]
        self.source = root / 'gateway.rut'
        self.source.write_text(Path(source).read_text().replace(
            'listen :8080', f'listen :{self.port}'))
        self.log = root / 'gateway.log'
        self.backend = backend
        self.process = None

    def start(self):
        with self.log.open('w') as output:
            self.process = subprocess.Popen(
                [self.server, str(self.source), '--backend', self.backend, '--no-pin',
                 '--shards', '2', '--drain', '0'],
                env=dict(os.environ, **self.env), stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while True:
            if self.process.poll() is not None:
                if self.backend == 'io_uring' and 'io_uring is unavailable' in self.log.read_text():
                    raise SystemExit(77)
                raise AssertionError(self.log.read_text())
            try:
                connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=.2)
                connection.request('GET', '/ready')
                response = connection.getresponse()
                response.read()
                connection.close()
                if response.status == 204:
                    return self
            except OSError:
                pass
            assert time.monotonic() < deadline, self.log.read_text()
            time.sleep(.025)

    def close(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None
        self.directory.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', required=True)
    args = parser.parse_args()
    slots = {
        3: dict(keyId='key-3', key='secret-3', consumer='consumer-3', credential='credential-3'),
        7: dict(keyId='key-7', key='secret-7', consumer='consumer-7', credential='credential-7'),
    }
    gateway = Gateway(args.server, args.source, registry_env(slots), args.backend)
    try:
        gateway.start()
        port = gateway.port
        assert signed_request(port, 'key-3', 'secret-3') == (200, b'consumer-3')
        assert signed_request(port, 'key-7', 'secret-7') == (200, b'consumer-7')
        assert signed_request(port, 'key-3', 'secret-7')[0] == 401
        assert signed_request(port, 'unknown', 'secret-3')[0] == 401
        assert webhook_request(port, 'secret-3') == (200, b'consumer-3')
        assert webhook_request(port, 'secret-7', identifier='evt-7') == (200, b'consumer-7')
        assert webhook_request(port, 'secret-other')[0] == 401
        assert webhook_request(port, 'secret-3', now=int(time.time()) - 900)[0] == 401
        gateway.close()

        # A duplicate key ID is a configuration error and fails closed.
        duplicate = dict(slots)
        duplicate[7] = dict(keyId='key-3', key='secret-7', consumer='consumer-7',
                            credential='credential-7')
        with_duplicate = Gateway(args.server, args.source, registry_env(duplicate), args.backend)
        with_duplicate.start()
        try:
            assert signed_request(with_duplicate.port, 'key-3', 'secret-3')[0] == 503
            assert webhook_request(with_duplicate.port, 'secret-3')[0] == 503
        finally:
            with_duplicate.close()

        # Duplicate secrets are ambiguous and also fail closed.
        duplicate_secret = dict(slots)
        duplicate_secret[7] = dict(keyId='key-7', key='secret-3', consumer='consumer-7',
                                   credential='credential-7')
        with_duplicate_secret = Gateway(args.server, args.source,
                                        registry_env(duplicate_secret), args.backend)
        with_duplicate_secret.start()
        try:
            assert signed_request(with_duplicate_secret.port, 'key-3', 'secret-3')[0] == 503
            assert webhook_request(with_duplicate_secret.port, 'secret-3')[0] == 503
        finally:
            with_duplicate_secret.close()

        # All eight slots are usable, including the last one.
        full = {index: dict(keyId=f'key-{index}', key=f'secret-{index}',
                            consumer=f'consumer-{index}', credential=f'credential-{index}')
                for index in range(1, 9)}
        full_gateway = Gateway(args.server, args.source, registry_env(full), args.backend)
        full_gateway.start()
        try:
            assert signed_request(full_gateway.port, 'key-1', 'secret-1') == (200, b'consumer-1')
            assert signed_request(full_gateway.port, 'key-8', 'secret-8') == (200, b'consumer-8')
            assert webhook_request(full_gateway.port, 'secret-8', identifier='evt-full') == (
                200, b'consumer-8')
        finally:
            full_gateway.close()

        # No enabled slot is also a configuration error.
        empty = Gateway(args.server, args.source, registry_env({}), args.backend)
        empty.start()
        try:
            assert signed_request(empty.port, 'key-3', 'secret-3')[0] == 503
            assert webhook_request(empty.port, 'secret-3')[0] == 503
        finally:
            empty.close()

        # Replacing the snapshot removes the old key and admits the next one.
        rotated = dict(slots)
        rotated.pop(3)
        rotated[8] = dict(keyId='key-8', key='secret-8', consumer='consumer-8',
                          credential='credential-8')
        replacement = Gateway(args.server, args.source, registry_env(rotated), args.backend)
        replacement.start()
        try:
            assert signed_request(replacement.port, 'key-3', 'secret-3')[0] == 401
            assert signed_request(replacement.port, 'key-8', 'secret-8') == (200, b'consumer-8')
            assert webhook_request(replacement.port, 'secret-3')[0] == 401
            assert webhook_request(replacement.port, 'secret-8', identifier='evt-8') == (
                200, b'consumer-8')
        finally:
            replacement.close()
    finally:
        if gateway.process is not None:
            gateway.close()
    print('PASS: bounded signed-request/webhook key registry and snapshot rotation')


if __name__ == '__main__':
    raise SystemExit(main())
