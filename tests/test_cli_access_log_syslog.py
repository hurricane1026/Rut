#!/usr/bin/env python3
"""Check access log syslog output through the CLI and real datagram sockets."""
from contextlib import contextmanager
import errno
import http.client
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

from test_cli_access_log_host import known_io_uring_environment_failure


class BackendUnavailable(Exception):
    pass


def clean_env():
    return {key: value for key, value in os.environ.items() if key != "RUE_ACCESS_LOG_COMPRESS"}


@contextmanager
def serve(binary, source, backend, endpoint, *extra, expect_send_failure=False):
    command = [binary, "0", str(source), "--shards", "1", "--no-pin", "--drain", "0",
               "--backend", backend, "--access-log-syslog", endpoint, *extra]
    with tempfile.TemporaryFile() as log, subprocess.Popen(
        command, stdout=log, stderr=subprocess.STDOUT, env=clean_env()
    ) as server:
        listening = False
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                output = os.pread(log.fileno(), 65536, 0)
                if match := re.search(rb"Listening on port (\d+) with 1 shard", output):
                    listening = True
                    yield int(match[1])
                    break
                if server.poll() is not None:
                    if backend == "io_uring" and known_io_uring_environment_failure(
                        output.decode(errors="replace")
                    ):
                        raise BackendUnavailable
                    raise AssertionError(output.decode(errors="replace"))
                time.sleep(0.025)
            else:
                raise AssertionError(os.pread(log.fileno(), 65536, 0).decode(errors="replace"))
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
            if listening:
                output = os.pread(log.fileno(), 65536, 0)
                assert server.returncode == 0, output
                if expect_send_failure:
                    assert b"Access log syslog send failures: 1" in output, output


def hit(port, target):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
    try:
        client.request("GET", target, headers={"Connection": "close"})
        response = client.getresponse()
        assert response.status == 204
        response.read()
    finally:
        client.close()


def verify_message(receiver, route, envelope):
    message = receiver.recv(1024)
    assert re.match(envelope, message), message
    assert b"\n" not in message and b"\0" not in message, message
    assert b" GET " + route + b" 204 " in message, message


RFC5424 = rb"<134>1 \d{4}-\d\d-\d\dT\S+ \S+ rut-access \d+ - - "
LOCAL_SYSLOG = rb"<134>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d rut-access\[\d+\]: "
REMOTE_SYSLOG = rb"<134>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ rut-access\[\d+\]: "


def exercise(binary, source, backend, directory):
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
        path = directory / "log.sock"
        receiver.bind(str(path))
        receiver.settimeout(4)
        with serve(binary, source, backend, f"unix:{path}") as port:
            hit(port, "/test?secret=kept")
            verify_message(receiver, b"/test?secret=kept", LOCAL_SYSLOG)
            receiver.close()
            path.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as restarted:
                restarted.bind(str(path))
                restarted.settimeout(4)
                hit(port, "/test?after=restart")
                verify_message(restarted, b"/test?after=restart", LOCAL_SYSLOG)
        path.unlink()

    # Logging can fail while the receiver is down. Traffic and shutdown still succeed.
    with serve(binary, source, backend, f"unix:{path}", expect_send_failure=True) as port:
        hit(port, "/test")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(4)
        endpoint = f"udp://127.0.0.1:{receiver.getsockname()[1]}"
        with serve(binary, source, backend, endpoint, "--access-log-path-only") as port:
            hit(port, "/test?secret=stripped")
            hit(port, "/test")
            for _ in range(2):
                verify_message(receiver, b"/test", RFC5424)
        with serve(binary, source, backend, endpoint, "--access-log-syslog-format", "rfc3164") as port:
            hit(port, "/test")
            verify_message(receiver, b"/test", REMOTE_SYSLOG)


    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("::1", 0))
            receiver.settimeout(4)
            endpoint = f"udp://[::1]:{receiver.getsockname()[1]}"
            with serve(binary, source, backend, endpoint) as port:
                hit(port, "/test")
                verify_message(receiver, b"/test", RFC5424)
    except OSError as exc:
        if exc.errno not in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            raise


def reject_invalid_options(binary, source):
    for args, error in [
        (["--access-log-syslog"], b"requires an argument"),
        (["--access-log-syslog-format", "rfc5424"], b"requires --access-log-syslog"),
        (["--access-log-syslog", "udp://127.0.0.1:65536"], b"Invalid or unavailable"),
        (["--access-log-syslog", "unix:relative"], b"Invalid or unavailable"),
        (["--access-log-syslog", "unix:/dev/log", "--access-log-compress"], b"compression options"),
        (["--access-log-syslog", "unix:/dev/log", "--access-log", "access.log"], b"conflicts"),
    ]:
        exited = subprocess.run(
            [binary, "0", str(source), "--shards", "1", "--backend", "epoll", *args],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=8, env=clean_env(),
        )
        assert exited.returncode != 0 and error in exited.stdout, exited.stdout


def main():
    binary, backend = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="rut-syslog-") as name:
        directory = Path(name)
        source = directory / "test.rut"
        source.write_text('route GET "/test" { return 204 }\n')
        try:
            exercise(binary, source, backend, directory)
        except BackendUnavailable:
            return 77
        if backend == "epoll":
            reject_invalid_options(binary, source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
