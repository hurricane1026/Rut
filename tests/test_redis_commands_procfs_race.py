#!/usr/bin/env python3
"""Deterministically exercise procfs races during compiler-child monitoring."""
import argparse
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_redis_commands import gateway


FAKE_PID = '2147483647'
PROGRAM = 'route POST "/probe" { return 204 }\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    args = parser.parse_args()
    gateway_args = SimpleNamespace(server=args.server, library=args.library,
                                   real_redis=False, opt='2', backend='io_uring')
    original_read_text = Path.read_text

    children_seen = False

    def parent_race_read_text(path, *read_args, **read_kwargs):
        nonlocal children_seen
        path_text = str(path)
        if path_text.startswith('/proc/') and path_text.endswith('/children'):
            if not children_seen:
                children_seen = True
                raise ProcessLookupError(3, 'No such process', path_text)
        return original_read_text(path, *read_args, **read_kwargs)

    endpoint = {'address': '127.0.0.1', 'port': 1, 'poolIdleMs': 5000}
    with patch.object(Path, 'read_text', parent_race_read_text):
        with gateway(gateway_args, endpoint, program_factory=lambda _: PROGRAM,
                     entrypoint='redis-client.rut', startup_timeout=60) as request:
            assert request('probe') == (204, b'')
    assert children_seen, 'did not inject parent children-snapshot ESRCH'

    status_seen = False

    def child_race_read_text(path, *read_args, **read_kwargs):
        nonlocal status_seen
        path_text = str(path)
        if path_text.startswith('/proc/') and path_text.endswith('/children'):
            return FAKE_PID
        if path_text == f'/proc/{FAKE_PID}/status':
            status_seen = True
            raise ProcessLookupError(3, 'No such process', path_text)
        return original_read_text(path, *read_args, **read_kwargs)

    with patch.object(Path, 'read_text', child_race_read_text):
        with gateway(gateway_args, endpoint, program_factory=lambda _: PROGRAM,
                     entrypoint='redis-client.rut', startup_timeout=60) as request:
            assert request('probe') == (204, b'')
    assert status_seen, 'did not inject vanished compiler-child status ESRCH'

    permission_seen = False

    def permission_read_text(path, *read_args, **read_kwargs):
        nonlocal permission_seen
        path_text = str(path)
        if path_text.startswith('/proc/') and path_text.endswith('/children'):
            return FAKE_PID
        if path_text == f'/proc/{FAKE_PID}/status':
            permission_seen = True
            raise PermissionError(13, 'Permission denied', path_text)
        return original_read_text(path, *read_args, **read_kwargs)

    with patch.object(Path, 'read_text', permission_read_text):
        try:
            with gateway(gateway_args, endpoint, program_factory=lambda _: PROGRAM,
                         entrypoint='redis-client.rut', startup_timeout=60):
                raise AssertionError('gateway unexpectedly ignored procfs permission failure')
        except PermissionError:
            pass
    assert permission_seen, 'did not check propagation of unrelated procfs OSError'
    print('PASS: gateway startup tolerates deterministic procfs ESRCH races and propagates unrelated errors')


if __name__ == '__main__':
    main()
