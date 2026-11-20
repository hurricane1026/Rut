#!/usr/bin/env python3
"""Rotation shares a replay identity across signing key generations."""
import argparse
import os
from pathlib import Path
import tempfile
from test_auth_replay import KEY, Store, exchange, gateway

PREVIOUS = 'previous-webhook-fixture-0123456789'


def main():
    parser = argparse.ArgumentParser()
    for option in ('server', 'source', 'testdata', 'backend', 'opt'):
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    args.tls = False
    store = Store(Path(args.testdata), False)
    try:
        with tempfile.TemporaryDirectory(prefix='rut-rotation-replay-') as directory:
            root = Path(directory)
            os.environ['STANDARD_WEBHOOK_PREVIOUS_RAW_KEY'] = PREVIOUS
            with gateway(args, Path(args.source).resolve(), store, root) as port:
                for h2 in (False, True):
                    suffix = '-h2' if h2 else '-h1'
                    assert exchange(port, 'same' + suffix, key=PREVIOUS, h2=h2) == 204
                    assert exchange(port, 'same' + suffix, key=KEY, h2=h2) == 409
                    assert exchange(port, 'current' + suffix, key=KEY, h2=h2) == 204
                    assert exchange(port, 'previous' + suffix, key=PREVIOUS, h2=h2) == 204
                    with store.lock:
                        before = len(store.commands)
                    assert exchange(port, 'invalid' + suffix, key='wrong', h2=h2) == 401
                    with store.lock:
                        assert len(store.commands) == before
            os.environ['STANDARD_WEBHOOK_PREVIOUS_RAW_KEY'] = ''
            with gateway(args, Path(args.source).resolve(), store, root) as port:
                with store.lock:
                    before = len(store.commands)
                assert exchange(port, 'removed', key=PREVIOUS) == 401
                with store.lock:
                    assert len(store.commands) == before
                assert exchange(port, 'still-current', key=KEY) == 204
            args.namespace = ''
            with gateway(args, Path(args.source).resolve(), store, root) as port:
                with store.lock:
                    before = len(store.commands)
                assert exchange(port, 'no-namespace', key=KEY) == 503
                with store.lock:
                    assert len(store.commands) == before
    finally:
        store.close()
        os.environ.pop('STANDARD_WEBHOOK_PREVIOUS_RAW_KEY', None)
    print('PASS webhook rotation and replay', args.backend)


if __name__ == '__main__':
    main()
