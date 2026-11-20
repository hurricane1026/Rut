#!/usr/bin/env python3
"""Verify that actual authenticated method separates atomic replay claims."""
import argparse
import base64
from email.utils import formatdate
import hashlib
import hmac
from pathlib import Path
import socket
import tempfile
import time
from test_auth_replay import Store, gateway, KEY


def exchange(port, method, signed_method, date, body=b'event'):
    target = '/signed?event=method'
    digest = 'SHA-256=' + base64.b64encode(hashlib.sha256(body).digest()).decode()
    canonical = f'billing-key\n{signed_method} {target}\ndate: {date}\ndigest: {digest}\n'
    signature = base64.b64encode(hmac.new(KEY.encode(), canonical.encode(), hashlib.sha256).digest()).decode()
    wire = (f'{method} {target} HTTP/1.1\r\nHost: local\r\nConnection: close\r\n'
            f'Authorization: Signature keyId="billing-key",algorithm="hmac-sha256",headers="@request-target date digest",signature="{signature}"\r\n'
            f'Date: {date}\r\nDigest: {digest}\r\nContent-Length: {len(body)}\r\n\r\n').encode() + body
    with socket.create_connection(('127.0.0.1', port), timeout=5) as conn:
        conn.sendall(wire)
        return int(conn.recv(4096).split(b' ')[1])


def main():
    p = argparse.ArgumentParser()
    for arg in ('server', 'source', 'testdata', 'backend'):
        p.add_argument('--' + arg, required=True)
    p.add_argument('--opt', type=int, default=2)
    args = p.parse_args()
    args.tls = False
    store = Store(Path(args.testdata), False)
    try:
        with tempfile.TemporaryDirectory() as directory:
            with gateway(args, Path(args.source).resolve(), store, Path(directory)) as port:
                date = formatdate(int(time.time()), usegmt=True)
                assert exchange(port, 'PUT', 'POST', date) == 401
                assert not store.commands
                assert exchange(port, 'POST', 'POST', date) == 204
                assert exchange(port, 'POST', 'POST', date) == 409
                assert exchange(port, 'PUT', 'PUT', date) == 204
                assert exchange(port, 'PUT', 'PUT', date) == 409
                keys = [command[1] for command in store.commands if command[0] == b'SET']
                assert keys[0] == keys[1] and keys[2] == keys[3] and keys[0] != keys[2], keys
            # Simulate an absent deployment namespace without touching the
            # shared fixture's hard-coded valid environment.
            empty_root = Path(directory) / 'empty-config'
            empty_root.mkdir()
            source = Path(args.source).resolve()
            (empty_root / 'clients').symlink_to(source.parent / 'clients', target_is_directory=True)
            (empty_root / 'middleware').symlink_to(source.parent / 'middleware', target_is_directory=True)
            empty_source = empty_root / 'empty.rut'
            empty_source.write_text(source.read_text().replace('env("REPLAY_NAMESPACE")', '""'))
            before = len(store.commands)
            with gateway(args, empty_source, store, Path(directory)) as port:
                assert exchange(port, 'POST', 'POST', date) == 503
                assert exchange(port, 'PUT', 'PUT', date) == 503
                assert len(store.commands) == before
    finally:
        store.close()
    print('signed method replay checks passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
