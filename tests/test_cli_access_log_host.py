#!/usr/bin/env python3
"""Exercise SourceLive downstreamHost through the production CLI on real sockets."""
import errno
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time


def known_io_uring_environment_failure(output):
    if "--backend io_uring requested, but io_uring is unavailable" in output:
        return True
    match = re.search(
        r"Failed to init shard \d+ \(errno=(\d+), source=2\)\n"
        r"io_uring startup initialization failed \(detail=(QueueSetup|"
        r"QueueSetupFeatureFlagsUnsupported|ProvidedBufferRingRegistration|"
        r"ProvidedBufferRingUnsupported)\)",
        output,
    )
    return match is not None and int(match.group(1)) in {
        errno.EPERM,
        errno.EACCES,
        errno.ENOMEM,
        errno.EINVAL,
        errno.ENOSYS,
        errno.EOPNOTSUPP,
    }


def read_response_headers(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        assert chunk, "server closed before completing response headers"
        data.extend(chunk)
        assert len(data) <= 16384, "response headers exceeded bounded test buffer"
    return bytes(data)


def exercise(binary, backend):
    with tempfile.TemporaryDirectory(prefix="rut_cli_host_") as temp_name:
        directory = Path(temp_name)
        log_path = directory / "host.log"
        source_path = directory / "app.rut"
        source_path.write_text(
            f'accessLog {{ path: "{log_path}", format: downstreamHost, '
            "publication: live }\nlisten :0\nroute GET \"/host\" { return 204 }\n",
            encoding="utf-8",
        )
        proc = subprocess.Popen(
            [str(binary), "0", str(source_path), "--shards", "1", "--no-pin", "--drain", "0",
             "--backend", backend],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        output = bytearray()
        try:
            deadline = time.monotonic() + 15
            port = None
            while time.monotonic() < deadline:
                ready, _, _ = select.select([proc.stdout], [], [], 0.1)
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    output.extend(chunk)
                    match = re.search(rb"Listening on port (\d+) with 1 shard", output)
                    if match:
                        port = int(match.group(1))
                        break
                if proc.poll() is not None:
                    break
            text = output.decode(errors="replace")
            if port is None and backend == "io_uring" and known_io_uring_environment_failure(text):
                assert proc.wait(timeout=3) != 0, text
                print("io_uring host-log CLI skipped: unavailable in this environment")
                return
            assert port is not None, text or "server startup timed out"
            assert f"Backend: {backend}\n" in text, text

            first = b"GET /host HTTP/1.1\r\nHost: FIRST.example:80\r\n\r\n"
            second = (b"GET /host HTTP/1.1\r\nhOsT: second.test\r\n"
                      b"Connection: close\r\n\r\n")
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.settimeout(5)
                client.sendall(first)
                assert read_response_headers(client).startswith(b"HTTP/1.1 204"), text
                client.sendall(second)
                assert read_response_headers(client).startswith(b"HTTP/1.1 204"), text
                assert client.recv(1) == b"", "Connection: close did not close the reused socket"

            os.killpg(proc.pid, signal.SIGTERM)
            assert proc.wait(timeout=15) == 0, output.decode(errors="replace")
            lines = log_path.read_text(encoding="ascii").splitlines()
            first_hex = first.split(b"Host: ", 1)[1].split(b"\r", 1)[0].hex()
            second_hex = b"second.test".hex()
            expected = [
                f"host1 request_bytes={len(first)} status=204 host_state=complete "
                f"host_length={len(b'FIRST.example:80')} host_hex={first_hex} "
                "upstream_history=unavailable",
                f"host1 request_bytes={len(second)} status=204 host_state=complete "
                f"host_length=11 host_hex={second_hex} upstream_history=unavailable",
            ]
            assert lines == expected, f"{lines!r} != {expected!r}"
            print(f"{backend} SourceLive Host CLI output verified")
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            if proc.stdout is not None:
                proc.stdout.close()


def main():
    binary = Path(sys.argv[1]).resolve()
    exercise(binary, "epoll")
    exercise(binary, "io_uring")


if __name__ == "__main__":
    main()
