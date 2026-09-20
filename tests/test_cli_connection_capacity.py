#!/usr/bin/env python3
"""Subprocess coverage for the CLI connection-capacity option."""

import os
import select
import signal
import subprocess
import sys
import time


OPTION = "--max-connections-per-shard"
READINESS = "Listening on port "


def run_rejected(binary, value):
    args = [binary, "0", "--shards", "1", "--no-pin", "--drain", "0", OPTION]
    if value is not None:
        args.append(value)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=3)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"invalid capacity {value!r} did not exit promptly") from exc
    output = result.stdout + result.stderr
    if result.returncode == 0:
        raise AssertionError(f"invalid capacity {value!r} was accepted: {output!r}")
    if OPTION not in output or "capacity" not in output.lower():
        raise AssertionError(f"invalid capacity {value!r} lacked a clear error: {output!r}")
    if READINESS in output:
        raise AssertionError(f"invalid capacity {value!r} started the server: {output!r}")


def run_smoke(binary, value):
    args = [binary, "0", "--shards", "1", "--no-pin", "--drain", "0"]
    if value is not None:
        args.extend([OPTION, str(value)])
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        start_new_session=True,
    )
    output = bytearray()
    deadline = time.monotonic() + 8
    try:
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select([process.stdout], [], [], min(0.25, remaining))
            if ready:
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                output.extend(chunk)
                if READINESS.encode() in output:
                    break
            if process.poll() is not None:
                break
        if READINESS.encode() not in output:
            raise AssertionError(
                f"capacity {value} did not reach readiness (rc={process.poll()}): {bytes(output)!r}"
            )
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"capacity {value} did not stop after SIGTERM") from exc
        if process.returncode != 0:
            raise AssertionError(
                f"capacity {value} exited with {process.returncode}: {bytes(output)!r}"
            )
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        process.stdout.close()


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} RUT_BINARY")
    binary = sys.argv[1]
    for invalid in (None, "", "0", "-1", "+1", "3x", "999999999999999999999999", "16777214"):
        run_rejected(binary, invalid)
    for valid in (None, "16384", "3", "32768"):
        run_smoke(binary, valid)


if __name__ == "__main__":
    main()
