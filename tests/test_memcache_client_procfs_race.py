#!/usr/bin/env python3
"""Exercise process-exit races in the Memcached compiler monitor."""
import argparse
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_memcache_client import gateway


FAKE_PID = '2147483647'
PROGRAM = 'route POST "/probe" { return 204 }\n'


def run_gateway(gateway_args, endpoint, reader):
    with patch.object(Path, 'read_text', reader):
        with gateway(gateway_args, endpoint, program_factory=lambda: PROGRAM) as request:
            assert request('probe') == (204, b'')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    gateway_args = SimpleNamespace(server=args.server, library=args.library,
                                   example=None, opt='2', backend=args.backend)
    endpoint = {'address': '127.0.0.1', 'port': 1, 'poolIdleMs': 5000}
    original_read_text = Path.read_text

    children_seen = False

    def parent_children_reader(path, *read_args, **read_kwargs):
        nonlocal children_seen
        path_text = str(path)
        if path_text.startswith('/proc/') and path_text.endswith('/children') and not children_seen:
            children_seen = True
            raise ProcessLookupError(3, 'No such process', path_text)
        return original_read_text(path, *read_args, **read_kwargs)

    run_gateway(gateway_args, endpoint, parent_children_reader)
    assert children_seen, 'did not inject parent children-snapshot ESRCH'

    birth_seen = False

    def child_birth_reader(path, *read_args, **read_kwargs):
        nonlocal birth_seen
        path_text = str(path)
        if path_text.startswith('/proc/') and path_text.endswith('/children'):
            child_ids = original_read_text(path, *read_args, **read_kwargs).split()
            return ' '.join((*child_ids, FAKE_PID))
        if path_text == f'/proc/{FAKE_PID}/stat' and not birth_seen:
            birth_seen = True
            raise ProcessLookupError(3, 'No such process', path_text)
        return original_read_text(path, *read_args, **read_kwargs)

    run_gateway(gateway_args, endpoint, child_birth_reader)
    assert birth_seen, 'did not inject child birth-time ESRCH'

    status_seen = False

    def child_status_reader(path, *read_args, **read_kwargs):
        nonlocal status_seen
        path_text = str(path)
        if path_text.startswith('/proc/') and path_text.endswith('/children'):
            child_ids = original_read_text(path, *read_args, **read_kwargs).split()
            return ' '.join((*child_ids, FAKE_PID))
        if path_text == f'/proc/{FAKE_PID}/status':
            status_seen = True
            raise ProcessLookupError(3, 'No such process', path_text)
        return original_read_text(path, *read_args, **read_kwargs)

    run_gateway(gateway_args, endpoint, child_status_reader)
    assert status_seen, 'did not inject child status ESRCH'

    permission_seen = False

    def permission_reader(path, *read_args, **read_kwargs):
        nonlocal permission_seen
        path_text = str(path)
        if path_text.startswith('/proc/') and path_text.endswith('/children'):
            child_ids = original_read_text(path, *read_args, **read_kwargs).split()
            if child_ids:
                return ' '.join((*child_ids, FAKE_PID))
            return ''
        if path_text == f'/proc/{FAKE_PID}/stat':
            permission_seen = True
            raise PermissionError(13, 'Permission denied', path_text)
        return original_read_text(path, *read_args, **read_kwargs)

    try:
        with patch.object(Path, 'read_text', permission_reader):
            with gateway(gateway_args, endpoint, program_factory=lambda: PROGRAM):
                raise AssertionError('gateway unexpectedly ignored procfs permission failure')
    except PermissionError:
        pass
    assert permission_seen, 'did not check propagation of unrelated procfs OSError'
    print('PASS: Memcached gateway tolerates procfs ESRCH races and propagates unrelated errors')


if __name__ == '__main__':
    main()
