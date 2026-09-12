"""Loopback integration controls for scripts/acquire_tla2tools.py.

These tests exercise the real curl process and never contact an outside host.
"""

from __future__ import annotations

import hashlib
import http.server
import os
import pathlib
import socketserver
import subprocess
import tempfile
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scripts"))
from acquire_tla2tools import AcquisitionError, ChecksumError, acquire  # noqa: E402


PAYLOAD = b"tla2tools loopback payload\n"


class Fixture(http.server.BaseHTTPRequestHandler):
    payload = PAYLOAD
    mode = "valid"
    requests = 0
    lock = threading.Lock()
    stall_release = threading.Event()

    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        with self.lock:
            type(self).requests += 1
        if self.mode == "retry":
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.mode == "stall":
            self.send_response(200)
            self.send_header("Content-Length", str(len(self.payload) + 1))
            self.end_headers()
            self.wfile.write(self.payload[:1])
            self.wfile.flush()
            type(self).stall_release.wait(timeout=30)
            return
        self.send_response(200)
        if self.mode == "truncated-then-valid" and type(self).requests > 1:
            body = self.payload
        else:
            body = self.payload if self.mode == "valid" else self.payload[:-3]
        self.send_header("Content-Length", str(len(self.payload)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()


class Loopback(unittest.TestCase):
    def setUp(self) -> None:
        self._proxy_environment = {
            key: os.environ.get(key)
            for key in ("NO_PROXY", "no_proxy")
        }
        self.addCleanup(self._restore_proxy_environment)
        os.environ["NO_PROXY"] = "127.0.0.1,localhost"
        os.environ["no_proxy"] = "127.0.0.1,localhost"
        Fixture.mode = "valid"
        Fixture.requests = 0
        Fixture.stall_release = threading.Event()
        self.server = socketserver.TCPServer(("127.0.0.1", 0), Fixture)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/artifact"
        self.tmp_handle = tempfile.TemporaryDirectory(prefix="tla2tools-test-")
        self.tmp = pathlib.Path(self.tmp_handle.name)

    def tearDown(self) -> None:
        Fixture.stall_release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.assertFalse(self.thread.is_alive())
        self.tmp_handle.cleanup()

    def _restore_proxy_environment(self) -> None:
        for key, value in self._proxy_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_valid_download_publishes_atomically(self) -> None:
        destination = self.tmp / "tools.jar"
        acquire(self.url, destination, hashlib.sha256(PAYLOAD).hexdigest())
        self.assertEqual(destination.read_bytes(), PAYLOAD)
        self.assertEqual(Fixture.requests, 1)
        self.assertEqual(list(self.tmp.glob("*.part")), [])

    def test_wrong_hash_and_truncated_transfer_preserve_destination(self) -> None:
        destination = self.tmp / "tools.jar"
        destination.write_bytes(b"old artifact")
        with self.assertRaises(ChecksumError):
            acquire(self.url, destination, "0" * 64)
        self.assertEqual(destination.read_bytes(), b"old artifact")
        self.assertEqual(Fixture.requests, 1)
        Fixture.requests = 0
        Fixture.mode = "truncated"
        with self.assertRaises(AcquisitionError):
            acquire(self.url, destination, hashlib.sha256(PAYLOAD).hexdigest())
        self.assertEqual(destination.read_bytes(), b"old artifact")
        self.assertEqual(list(self.tmp.glob("*.part")), [])

    def test_absent_destination_is_not_published_on_wrong_hash(self) -> None:
        destination = self.tmp / "missing.jar"
        with self.assertRaises(ChecksumError):
            acquire(self.url, destination, "0" * 64, retries=0)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.tmp.glob("*.part")), [])

    def test_truncated_retry_replaces_staging_instead_of_concatenating(self) -> None:
        Fixture.mode = "truncated-then-valid"
        destination = self.tmp / "tools.jar"
        acquire(
            self.url,
            destination,
            hashlib.sha256(PAYLOAD).hexdigest(),
            retries=1,
        )
        self.assertEqual(destination.read_bytes(), PAYLOAD)
        self.assertEqual(Fixture.requests, 2)

    def test_retry_policy_exhausts_at_most_four_requests(self) -> None:
        tls_server = socketserver.TCPServer(("127.0.0.1", 0), TLSReset)
        tls_thread = threading.Thread(target=tls_server.serve_forever, daemon=True)
        tls_thread.start()
        tls_url = f"https://127.0.0.1:{tls_server.server_address[1]}/artifact"
        try:
            old = subprocess.run(
                [
                    "curl", "--fail", "--location", "--retry", "3",
                    "--connect-timeout", "10", "--max-time", "30",
                    "--output", "/dev/null", tls_url,
                ],
                check=False,
            )
            self.assertEqual(old.returncode, 35)
            self.assertEqual(TLSReset.requests, 1)
            TLSReset.requests = 0
            with self.assertRaises(AcquisitionError) as failure:
                acquire(tls_url, self.tmp / "tools.jar", "0" * 64)
            self.assertEqual(failure.exception.returncode, 35)
            self.assertEqual(TLSReset.requests, 4)
        finally:
            tls_server.shutdown()
            tls_server.server_close()
            tls_thread.join(timeout=2)
            self.assertFalse(tls_thread.is_alive())

    def test_stalled_transfer_has_short_bound_and_cleans_staging(self) -> None:
        Fixture.mode = "stall"
        started = time.monotonic()
        with self.assertRaises(AcquisitionError):
            acquire(
                self.url,
                self.tmp / "tools.jar",
                hashlib.sha256(PAYLOAD).hexdigest(),
                connect_timeout=0.2,
                max_time=0.5,
                retries=0,
            )
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(Fixture.requests, 1)
        self.assertEqual(list(self.tmp.glob("*.part")), [])

    def test_cli_preserves_terminal_curl_status(self) -> None:
        import acquire_tla2tools

        with mock.patch.object(
            acquire_tla2tools, "acquire", side_effect=AcquisitionError("curl failed", 35)
        ), mock.patch.object(sys, "argv", ["acquire_tla2tools.py", str(self.tmp / "x")]):
            self.assertEqual(acquire_tla2tools.main(), 35)


class TLSReset(socketserver.BaseRequestHandler):
    requests = 0
    lock = threading.Lock()

    def handle(self) -> None:
        with type(self).lock:
            type(self).requests += 1
        self.request.sendall(b"\x15\x03\x03\x00\x02\x02\x28")


if __name__ == "__main__":
    unittest.main()
