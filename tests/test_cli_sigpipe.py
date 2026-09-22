#!/usr/bin/env python3
"""The rut process must ignore SIGPIPE: a client disconnecting mid-response
cannot be allowed to kill the server on write paths without MSG_NOSIGNAL."""

import os
import select
import signal
import subprocess
import sys
import time


READINESS = "Listening on port "
SIGPIPE_BIT = 1 << (signal.SIGPIPE - 1)


def ignored_signals(pid):
    with open(f"/proc/{pid}/status", encoding="ascii") as status:
        for line in status:
            if line.startswith("SigIgn:"):
                return int(line.split()[1], 16)
    raise AssertionError(f"no SigIgn line for pid {pid}")


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <rut-binary>", file=sys.stderr)
        return 2
    # restore_signals (the default) gives the child SIGPIPE's default action,
    # so an ignored SIGPIPE below can only come from rut itself.
    process = subprocess.Popen(
        [sys.argv[1], "0", "--shards", "1", "--no-pin", "--drain", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        start_new_session=True,
        restore_signals=True,
    )
    output = bytearray()
    try:
        deadline = time.monotonic() + 8
        while READINESS.encode() not in output and time.monotonic() < deadline:
            ready, _, _ = select.select([process.stdout], [], [], 0.25)
            if ready:
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                output.extend(chunk)
            if process.poll() is not None:
                break
        if READINESS.encode() not in output:
            raise AssertionError(f"rut did not reach readiness: {bytes(output)!r}")
        if not ignored_signals(process.pid) & SIGPIPE_BIT:
            raise AssertionError("rut does not ignore SIGPIPE")
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
        if process.returncode != 0:
            raise AssertionError(f"rut exited with {process.returncode}: {bytes(output)!r}")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        process.stdout.close()
    print("rut ignores SIGPIPE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
