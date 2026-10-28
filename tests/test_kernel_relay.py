#!/usr/bin/env python3
"""Black-box lifecycle tests for the isolated copy/splice mechanism probe."""
import concurrent.futures
import errno
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = Path(sys.argv.pop(1)).resolve()


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive(sock, length):
    parts = []
    total = 0
    while total < length:
        block = sock.recv(min(65536, length - total))
        if not block:
            raise AssertionError(f"early EOF at {total}/{length}")
        parts.append(block)
        total += len(block)
    return b"".join(parts)


class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modes = ("copy", "splice")
        cls.ebpf_error = ""
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen([str(BINARY), "ebpf", str(available_port()),
                                        str(available_port())], stderr=log)
            deadline = time.monotonic() + 5
            while True:
                log.seek(0)
                text = log.read().decode()
                if "READY" in text:
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=3) == 0, text
                    cls.modes += ("ebpf",)
                    break
                if process.poll() is not None:
                    assert process.returncode == 1, text
                    match = re.search(r"eBPF tunnel ([a-z_]+): errno=(\d+):", text)
                    assert match, text
                    assert match.group(1) in {
                        "tunnel_attach_type", "source_map", "target_map", "state_map",
                        "command_map", "ring_size", "ring_map", "ring_consumer",
                        "ring_producer", "instruction_template", "parser_load",
                        "verdict_load", "commit_load", "parser_attach", "verdict_attach",
                    }, text
                    assert int(match.group(2)) in {
                        errno.EPERM, errno.EACCES, errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP
                    }, text
                    cls.ebpf_error = text
                    break
                if time.monotonic() > deadline:
                    process.kill()
                    process.wait()
                    raise AssertionError("eBPF capability probe did not finish")
                time.sleep(0.02)

    def test_ebpf_capability_is_explicit(self):
        self.assertTrue("ebpf" in self.modes or self.ebpf_error)

    def test_refused_upstream_reclaims_resources_and_allows_successor(self):
        for mode in self.modes:
            with self.subTest(mode=mode), socket.socket() as origin, tempfile.TemporaryFile() as log:
                origin.bind(("127.0.0.1", 0))  # bound, deliberately not listening yet
                front = available_port()
                process = subprocess.Popen([str(BINARY), mode, str(front), str(origin.getsockname()[1])], stderr=log)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        log.seek(0)
                        if b"READY" in log.read():
                            break
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail("relay did not become ready")
                        time.sleep(0.02)
                    baseline_fds = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
                    with socket.create_connection(("127.0.0.1", front), timeout=5) as client:
                        try:
                            self.assertEqual(client.recv(1), b"")
                        except ConnectionResetError:
                            pass
                    deadline = time.monotonic() + 3
                    while len(list(Path(f"/proc/{process.pid}/fd").iterdir())) != baseline_fds:
                        if time.monotonic() > deadline:
                            self.fail("failed connect left sockets or pipes behind")
                        time.sleep(0.02)
                    origin.listen(2)
                    origin.settimeout(5)
                    def serve():
                        with origin.accept()[0] as peer:
                            peer.settimeout(5)
                            self.assertEqual(receive(peer, 3), b"new")
                            peer.sendall(b"ok")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(serve)
                        with socket.create_connection(("127.0.0.1", front), timeout=5) as client:
                            client.sendall(b"new")
                            self.assertEqual(receive(client, 2), b"ok")
                        future.result(timeout=5)
                finally:
                    process.send_signal(signal.SIGTERM)
                    try:
                        code = process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        self.fail("relay did not stop")
                    self.assertEqual(code, 1)  # exactly the injected setup failure

    def test_both_modes_keepalive_half_close_backpressure_reset_and_reclaim(self):
        for mode in self.modes:
            with self.subTest(mode=mode), socket.socket() as origin, tempfile.TemporaryFile() as log:
                origin.bind(("127.0.0.1", 0))
                origin.listen(8)
                origin.settimeout(5)
                front = available_port()
                process = subprocess.Popen([str(BINARY), mode, str(front), str(origin.getsockname()[1])], stderr=log)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        log.seek(0)
                        if b"READY" in log.read():
                            break
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail("relay did not become ready")
                        time.sleep(0.02)
                    baseline_fds = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
                    payload = bytes(range(256)) * 8192
                    response = payload * 4

                    def serve():
                        with origin.accept()[0] as peer:
                            peer.settimeout(5)
                            for _ in range(3):
                                self.assertEqual(receive(peer, len(payload)), payload)
                                peer.sendall(payload)
                            self.assertEqual(peer.recv(1), b"")
                            peer.sendall(response)
                            peer.shutdown(socket.SHUT_WR)

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(serve)
                        with socket.create_connection(("127.0.0.1", front), timeout=5) as client:
                            for _ in range(3):
                                client.sendall(payload)
                                self.assertEqual(receive(client, len(payload)), payload)
                            client.shutdown(socket.SHUT_WR)
                            time.sleep(0.1)  # queued relay output must survive a blocked reader
                            self.assertEqual(receive(client, len(response)), response)
                            self.assertEqual(client.recv(1), b"")
                        future.result(timeout=5)

                    def send_until_reset():
                        with origin.accept()[0] as peer:
                            peer.settimeout(5)
                            self.assertEqual(receive(peer, 1), b"x")
                            try:
                                for _ in range(32):
                                    peer.sendall(payload)
                            except (BrokenPipeError, ConnectionResetError):
                                pass

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(send_until_reset)
                        with socket.create_connection(("127.0.0.1", front), timeout=5) as client:
                            client.sendall(b"x")
                            self.assertTrue(client.recv(1024))
                            client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                        future.result(timeout=5)

                    # Reuse a slot after reset: stale events may not corrupt its bytes.
                    def fresh():
                        with origin.accept()[0] as peer:
                            peer.settimeout(5)
                            self.assertEqual(receive(peer, len(payload)), payload)
                            peer.sendall(payload)

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(fresh)
                        with socket.create_connection(("127.0.0.1", front), timeout=5) as client:
                            client.sendall(payload)
                            self.assertEqual(receive(client, len(payload)), payload)
                        future.result(timeout=5)
                    deadline = time.monotonic() + 3
                    while len(list(Path(f"/proc/{process.pid}/fd").iterdir())) != baseline_fds:
                        if time.monotonic() > deadline:
                            self.fail("socket/pipe descriptors were not reclaimed")
                        time.sleep(0.02)
                finally:
                    process.send_signal(signal.SIGTERM)
                    try:
                        code = process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        self.fail("relay did not stop")
                    self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
