#!/usr/bin/env python3
"""Verify explicit runtime backend selection and strict option validation."""
import os
import select
import signal
import subprocess
import sys
import time


def rejected(binary, options):
    result = subprocess.run([binary, '0', *options], capture_output=True, text=True, timeout=5)
    output = result.stdout + result.stderr
    assert result.returncode != 0 and '--backend' in output, output
    assert 'Listening on port ' not in output, output


def smoke(binary, backend):
    proc = subprocess.Popen([binary, '0', '--shards', '1', '--no-pin', '--drain', '0',
                             '--backend', backend], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, start_new_session=True)
    output = bytearray()
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
            if ready:
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                output.extend(chunk)
                if b'Listening on port ' in output:
                    break
        text = output.decode(errors='replace')
        if backend == 'io_uring' and '--backend io_uring requested, but io_uring is unavailable' in text:
            assert proc.wait(timeout=3) != 0 and 'Backend: epoll' not in text, text
            print('io_uring unavailable: verified explicit selection rejects fallback')
            return
        assert b'Listening on port ' in output, text
        if backend != 'auto':
            assert f'Backend: {backend}\n' in text, text
        os.killpg(proc.pid, signal.SIGTERM)
        assert proc.wait(timeout=5) == 0, text
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=3)
        proc.stdout.close()


def main():
    binary = sys.argv[1]
    for options in [['--backend'], ['--backend', ''], ['--backend', '--shards', '1'],
                    ['--backend', 'invalid'], ['--backend', 'EPOLL'],
                    ['--backend', 'epoll', '--backend', 'auto']]:
        rejected(binary, options)
    for backend in ['auto', 'epoll', 'io_uring']:
        smoke(binary, backend)
    print('backend CLI validation passed')


if __name__ == '__main__':
    main()
