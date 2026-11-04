#!/usr/bin/env python3
"""Offline provisioning, byte bounds, atomic no-replace files and terminal cleanup."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import pty
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import termios
import time


def run(tool, *args, password=b"password", **kwargs):
    return subprocess.run([tool, *map(str, args)], input=password, capture_output=True,
                          timeout=15, **kwargs)


def check_record(record, password):
    match = re.fullmatch(rb"\$rut-pbkdf2-sha256\$600000\$([0-9a-f]{32})\$([0-9a-f]{64})\n", record)
    assert match, record
    salt, key = [bytes.fromhex(value.decode()) for value in match.groups()]
    assert key == hashlib.pbkdf2_hmac("sha256", password, salt, 600000, 32)


def write_all(fd, data):
    os.set_blocking(fd, False)
    deadline = time.monotonic() + 5
    while data:
        try:
            written = os.write(fd, data)
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "terminal write timed out before the input reader drained it"
            select.select([], [fd], [], min(0.05, remaining))
            continue
        assert written > 0, "terminal write made no progress"
        data = data[written:]


def terminal_cc(index):
    master, slave = pty.openpty()
    try:
        value = termios.tcgetattr(slave)[6][index]
        return bytes([value]) if isinstance(value, int) else value
    finally:
        os.close(master)
        os.close(slave)


def terminal_case(tool, password, cancel=False, typed=None, terminator=b"\n"):
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    process = subprocess.Popen([tool, "hash"], stdin=slave, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL | termios.ICANON):
            assert process.poll() is None, "process exited before hiding terminal echo"
            assert time.monotonic() < deadline, "terminal echo was never disabled"
            time.sleep(0.005)
        prompt = b""
        while b"Password: " not in prompt:
            assert time.monotonic() < deadline, "password prompt was not written"
            if select.select([process.stderr], [], [], 0.05)[0]:
                chunk = os.read(process.stderr.fileno(), 4096)
                assert chunk, "process exited before prompting"
                prompt += chunk
        if cancel:
            process.send_signal(signal.SIGINT)
        else:
            write_all(master, (password if typed is None else typed) + terminator)
        output, error = process.communicate(timeout=15)
        error = prompt + error
        assert termios.tcgetattr(slave) == original, "terminal settings were not restored"
        assert b"Password: " in error
        if select.select([master], [], [], 0)[0]:
            assert password not in os.read(master, 4096), "password was echoed"
        if cancel or len(password) > 1024:
            assert process.returncode == 2 and not output, (process.returncode, output, error)
        else:
            assert process.returncode == 0, error
            assert password not in error
            check_record(output, password)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)


def terminal_oversize_delayed_tail_case(tool):
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    process = subprocess.Popen([tool, "hash"], stdin=slave, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL | termios.ICANON):
            assert process.poll() is None, "process exited before hiding terminal echo"
            assert time.monotonic() < deadline, "terminal mode was not switched"
            time.sleep(0.005)
        prompt = b""
        while b"Password: " not in prompt:
            assert time.monotonic() < deadline, "password prompt was not written"
            if select.select([process.stderr], [], [], 0.05)[0]:
                chunk = os.read(process.stderr.fileno(), 4096)
                assert chunk, "process exited before prompting"
                prompt += chunk

        write_all(master, b"a" * 1025)
        time.sleep(0.05)
        assert process.poll() is None, "oversized input returned before its line terminator"
        hidden = termios.tcgetattr(slave)[3]
        assert not hidden & (termios.ECHO | termios.ECHONL | termios.ICANON)

        tail = b"private-terminal-tail"
        write_all(master, tail + b"\n")
        output, error = process.communicate(timeout=15)
        error = prompt + error
        assert termios.tcgetattr(slave) == original, "terminal settings were not restored"
        assert process.returncode == 2 and not output, (process.returncode, output, error)
        echoed = bytearray()
        while select.select([master], [], [], 0.05)[0]:
            try:
                echoed.extend(os.read(master, 4096))
            except BlockingIOError:
                break
        assert tail not in echoed, "oversized terminal tail was echoed"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)


def main(tool):
    assert run(tool, "--help").returncode == 0
    for args in [[], ["hash", "password"], ["verify"], ["hash", "--output"], ["unknown"]]:
        result = run(tool, *args)
        assert result.returncode == 2 and not result.stdout
    with tempfile.TemporaryDirectory(prefix="rut-password-cli-") as directory:
        root = Path(directory)
        record_path = root / "credential.record"
        password = b" leading\x00binary\xff\ntrailing "
        result = run(tool, "hash", password=password)
        assert result.returncode == 0 and not result.stderr
        check_record(result.stdout, password)
        record_path.write_bytes(result.stdout)
        assert run(tool, "verify", record_path, password=password).returncode == 0
        assert run(tool, "verify", record_path, password=password[:-1]).returncode == 1
        record_path.write_bytes(result.stdout[:-1])
        assert run(tool, "verify", record_path, password=password).returncode == 0
        for malformed in [result.stdout + b"\n", result.stdout[:-1] + b"\r\n",
                          result.stdout.replace(b"600000", b"600001"), b"x" * 125]:
            record_path.write_bytes(malformed)
            assert run(tool, "verify", record_path).returncode == 2
        record_path.write_bytes(result.stdout)
        link = root / "link"
        link.symlink_to(record_path)
        fifo = root / "fifo"
        os.mkfifo(fifo)
        for invalid in [link, fifo, root, root / "absent"]:
            assert run(tool, "verify", invalid).returncode == 2
        for valid in [b"\n", b"a" * 1024]:
            result = run(tool, "hash", password=valid)
            assert result.returncode == 0
            check_record(result.stdout, valid)
        for invalid in [b"", b"x" * 1025]:
            target = root / "invalid.record"
            result = run(tool, "hash", "--output", target, password=invalid)
            assert result.returncode == 2 and not result.stdout and not target.exists()

        created = root / "new.record"
        result = run(tool, "hash", "--output", created, password=password, umask=0)
        assert result.returncode == 0 and not result.stdout and not result.stderr
        assert stat.S_IMODE(created.stat().st_mode) == 0o600
        check_record(created.read_bytes(), password)
        existing = created.read_bytes()
        for occupied in [created, link, fifo]:
            result = run(tool, "hash", "--output", occupied)
            assert result.returncode == 2 and not result.stdout
            assert created.read_bytes() == existing and link.is_symlink() and fifo.is_fifo()
        assert not list(root.glob(".rut-password-*"))

        shared = root / "shared"
        shared.mkdir(mode=0o700)
        shared.chmod(0o770)
        assert run(tool, "hash", "--output", shared / "record").returncode == 2
        assert not list(shared.iterdir())

        raced = root / "raced.record"
        def create(value):
            return run(tool, "hash", "--output", raced, password=value).returncode
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(create, [b"first", b"second"]))
        assert sorted(results) == [0, 2], results
        check_record(raced.read_bytes(), [b"first", b"second"][results.index(0)])
        assert not list(root.glob(".rut-password-*"))

        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            result = subprocess.run([tool, "hash"], input=b"password", stdout=write_end,
                                    stderr=subprocess.PIPE, timeout=15)
            assert result.returncode == 2, result.returncode
        finally:
            os.close(write_end)

    terminal_case(tool, b"hidden-password")
    terminal_case(tool, b"not-entered", cancel=True)
    terminal_case(tool, b"a" * 1024)
    erase = terminal_cc(termios.VERASE)
    terminal_case(tool, b"wronpassword", typed=b"wrong" + erase + b"password")
    kill = terminal_cc(termios.VKILL)
    terminal_case(tool, b"final-password", typed=b"discard" + kill + b"final-password")
    eof = terminal_cc(termios.VEOF)
    terminal_case(tool, b"eof-password", terminator=eof)
    terminal_case(tool, b"a" * 1025)
    terminal_oversize_delayed_tail_case(tool)
    print("password CLI: independent PBKDF2, binary bounds, private atomic files and terminal cleanup passed")


if __name__ == "__main__":
    main(sys.argv[1])
