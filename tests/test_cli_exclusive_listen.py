#!/usr/bin/env python3
"""Verify single-shard exclusive binding and multi-shard reuse through the CLI."""

import errno
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


def arguments(binary, port, shards):
    return [
        binary, str(port), "--shards", str(shards), "--no-pin", "--drain", "0",
        "--max-connections-per-shard", "1024", "--pool-prealloc", "64",
    ]


def read_log(log):
    return os.pread(log.fileno(), 65536, 0).decode(errors="replace")


def check_server(binary, shards):
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(arguments(binary, 0, shards), stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                output = read_log(log)
                if process.poll() is not None:
                    raise AssertionError(f"server exited before readiness: {output}")
                match = re.search(r"Listening on port (\d+) with (\d+) shard\(s\)\n", output)
                if match:
                    break
                time.sleep(0.05)
            else:
                raise AssertionError(f"server did not reach readiness: {read_log(log)}")
            port = int(match[1])
            assert port != 0 and int(match[2]) == shards, output

            for reuse_port in (False, True):
                with socket.socket() as competitor:
                    competitor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if reuse_port:
                        competitor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    try:
                        competitor.bind(("0.0.0.0", port))
                        competitor.listen()
                    except OSError as exc:
                        assert exc.errno == errno.EADDRINUSE, exc
                        assert shards == 1 or not reuse_port, (shards, reuse_port, exc)
                    else:
                        assert shards > 1 and reuse_port, "single-shard port admitted a competitor"

            if shards == 1:
                second = subprocess.run(
                    arguments(binary, port, 1), capture_output=True, text=True, timeout=10,
                )
                output = second.stdout + second.stderr
                assert second.returncode == 1, output
                assert f"errno={errno.EADDRINUSE}" in output, output
                assert "Listening on port" not in output, output

            process.send_signal(signal.SIGTERM)
            process.wait(timeout=5)
            assert process.returncode == 0, read_log(log)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} RUT_BINARY")
    for shards in (1, 2):
        check_server(sys.argv[1], shards)


if __name__ == "__main__":
    main()
