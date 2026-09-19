"""Checks for evidence gating and HTTP-close handling; no Docker required."""

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import run

from run import (
    Harness,
    connection_header,
    expected_body,
    request_bytes,
    response,
    response_head,
)
from summarize import aggregate, render
from matrix import assess


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    def sendall(self, _request):
        pass

    def recv(self, _size):
        return next(self.chunks, b"")


class ToolsTest(unittest.TestCase):
    def test_invalid_tls_certificate_retains_failed_status(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            cert = out / "invalid.pem"
            cert.write_text("not a PEM certificate\n")
            args = SimpleNamespace(output=out, tls_cert=cert)
            with mock.patch.object(run, "arguments", return_value=args), \
                    mock.patch.object(Harness, "prepare") as prepare, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run.main(), 2)
            prepare.assert_not_called()
            status = json.loads((out / "status.json").read_text())
            self.assertFalse(status["complete"])
            self.assertFalse(status["valid"])
            self.assertIn("SSLError", status["error"])

    def test_static_body_bound_rejected_before_external_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario, size, rejected in (
                ("static-close", run.STATIC_BODY_LIMIT, False),
                ("static-keepalive", run.STATIC_BODY_LIMIT + 1, True),
                ("static-close", 1048576, True),
                ("static-close", None, False),
                ("proxy-close", 1048576, False),
            ):
                with self.subTest(scenario=scenario, size=size):
                    harness = Harness(SimpleNamespace(
                        output=Path(directory), scenarios=[scenario], body_size=size))
                    with mock.patch.object(harness, "command", side_effect=RuntimeError("external")) as command:
                        if rejected:
                            with self.assertRaisesRegex(ValueError, "this matrix cell has NOT passed"):
                                harness.prepare()
                            command.assert_not_called()
                        else:
                            with self.assertRaisesRegex(RuntimeError, "external"):
                                harness.prepare()
                            command.assert_called_once()

    def test_matrix_interrupt_allows_child_cleanup_once(self):
        tools_dir = Path(__file__).resolve().parent
        for group_signal in (True, False):
            with self.subTest(group_signal=group_signal), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                child_script = out / "child.py"
                child_script.write_text(
                    "import os,signal,time\nfrom pathlib import Path\n"
                    "def interrupt(sig,frame):\n"
                    "    with Path('signals').open('a') as f: f.write(str(sig)+'\\n')\n"
                    "    raise KeyboardInterrupt\n"
                    "signal.signal(signal.SIGTERM,interrupt)\n"
                    "signal.signal(signal.SIGINT,interrupt)\n"
                    "Path('child.pid').write_text(str(os.getpid()))\n"
                    "try:\n"
                    "    Path('ready').touch()\n"
                    "    time.sleep(20)\n"
                    "except KeyboardInterrupt:\n"
                    "    Path('cleaning').touch()\n"
                    "    time.sleep(0.5)\n"
                    "    Path('cleaned').touch()\n"
                )
                parent_code = (
                    "import signal,sys\nfrom pathlib import Path\n"
                    f"sys.path.insert(0,{str(tools_dir)!r})\n"
                    "from matrix import run_cell\n"
                    "def interrupt(sig,frame): raise KeyboardInterrupt\n"
                    "signal.signal(signal.SIGTERM,interrupt)\n"
                    "try:\n"
                    "    with open('child.log','w') as log:\n"
                    "        run_cell([sys.executable,'child.py'],log)\n"
                    "except KeyboardInterrupt:\n"
                    "    Path('interrupted').touch()\n"
                )

                def wait_for(name, parent):
                    deadline = time.monotonic() + 5
                    while not (out / name).exists():
                        self.assertIsNone(parent.poll(), 'parent exited before ' + name)
                        self.assertLess(time.monotonic(), deadline, 'timed out waiting for ' + name)
                        time.sleep(0.01)

                with (out / "parent.log").open("w") as log:
                    parent = subprocess.Popen([sys.executable, "-c", parent_code],
                                              cwd=out, stdout=log, stderr=log,
                                              start_new_session=True)
                    try:
                        wait_for("ready", parent)
                        if group_signal:
                            os.killpg(parent.pid, signal.SIGINT)
                        else:
                            parent.terminate()
                        wait_for("cleaning", parent)
                        # A second terminal interruption must not interrupt the
                        # child's resource cleanup while the parent waits.
                        os.killpg(parent.pid, signal.SIGTERM)
                        self.assertEqual(parent.wait(timeout=5), 0)
                        self.assertTrue((out / "cleaned").exists())
                        self.assertTrue((out / "interrupted").exists())
                        self.assertEqual((out / "signals").read_text(), f"{signal.SIGTERM}\n")
                    finally:
                        if parent.poll() is None:
                            parent.kill()
                            parent.wait()
                        child_pid_file = out / "child.pid"
                        if child_pid_file.exists() and not (out / "cleaned").exists():
                            with contextlib.suppress(ProcessLookupError):
                                os.kill(int(child_pid_file.read_text()), signal.SIGKILL)

    def test_large_body_preflight_is_exact_and_bounded(self):
        size = 1048576
        head = f"HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n".encode()
        chunks = [head] + [b"x" * 4096] * (size // 4096)
        raw, closed = response(FakeSocket(chunks), "proxy", True, body_size=size)
        self.assertTrue(raw.endswith(b"x" * size))
        with self.assertRaises(ValueError):
            response_head(head)
        with self.assertRaises(ValueError):
            response(FakeSocket(chunks[:-1]), "proxy", True, body_size=size)
        with self.assertRaises(ValueError):
            response(FakeSocket([head, b"y" * size]), "proxy", True, body_size=size)

    def test_matrix_missing_wrong_shape_errors_and_smoke_never_pass(self):
        import copy
        rows = []
        for engine, rps in (("nginx", 100), ("rut", 120)):
            for rep in (1, 2, 3):
                rows.append(dict(workload="proxy", connection="close", transport="https",
                                 body_size=65536, concurrency=32, engine=engine, rep=rep,
                                 requests=500, rps=rps, valid=True,
                                 errors=dict(connect=0, read=0, write=0, status=0, timeout=0),
                                 warmup_errors=dict(connect=0, read=0, write=0, status=0, timeout=0)))
        def evaluate(data, duration=5):
            return assess(data, "proxy-close", "https", 65536, 32, 3, duration)
        self.assertTrue(evaluate(rows)["target_met"])
        self.assertFalse(evaluate(rows[:-1])["target_met"])
        self.assertFalse(evaluate(rows, duration=1)["target_met"])
        for key, value in (("body_size", 16), ("transport", "http"), ("rep", 99),
                           ("valid", False), ("errors", {"timeout": 1}), ("rps", 105)):
            bad = copy.deepcopy(rows)
            for row in bad:
                if row["engine"] == "rut":
                    row[key] = value
            self.assertFalse(evaluate(bad)["target_met"], key)

    def test_keepalive_wire_profiles_preserve_original_and_default_persistence(self):
        explicit = request_bytes("proxy", False)
        self.assertIn(b"Connection: keep-alive\r\n", explicit)
        implicit = request_bytes("proxy", False, "implicit")
        self.assertEqual(implicit, b"GET /proxy HTTP/1.1\r\nHost: client.example\r\n\r\n")
        self.assertIsNone(connection_header(False, "implicit"))
        self.assertEqual(
            request_bytes("proxy", True, "implicit"),
            request_bytes("proxy", True, "explicit"),
        )

    def test_fragmented_body_and_normal_close(self):
        sock = FakeSocket(
            [
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n"
                    b"Connection: close\r\nDate: today\r\n\r\nhello "
                ),
                b"from nginx",
                b"",
            ]
        )
        raw, closed = response(sock, "static", True)
        self.assertTrue(closed)
        self.assertIn(b"Date: NORMALIZED", raw)
        self.assertTrue(raw.endswith(expected_body("static")))

    def test_server_declared_close_even_when_client_requests_keepalive(self):
        length, closed = response_head(
            b"HTTP/1.1 200 OK\r\ncontent-length: 16\r\nconnection: Close"
        )
        self.assertEqual(length, 16)
        self.assertTrue(closed)

    def test_truncated_or_mismatched_responses_reject(self):
        for payload in (
            b"",
            b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nshort",
            b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nhello from nginxEXTRA",
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                response(FakeSocket([payload]), "static", True)

    @staticmethod
    def sample(engine="rut", valid=True):
        return {
            "workload": "static",
            "connection": "close",
            "concurrency": 1,
            "engine": engine,
            "rep": 1,
            "valid": valid,
            "errors": {"read": 0},
            "warmup_errors": {"read": 0},
            "rps": 10,
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
            "server_cpu_pct": 20,
            "origin_cpu_pct": 0,
            "server_rss_bytes": 100,
            "client_cpu_seconds": 1,
            "seconds": 2,
        }

    def test_invalid_nginx_is_not_published_as_valid_baseline(self):
        groups = aggregate([self.sample("nginx", False), self.sample()], 1, True)
        line = render(groups).splitlines()[6]
        self.assertIn("INVALID / INCOMPLETE", line)
        self.assertNotIn("1.00×", line)

    def test_partial_and_duplicate_repeats_do_not_get_capacity_ratio(self):
        for rows, repeats, complete in (
            ([self.sample()], 2, True),
            ([self.sample(), self.sample()], 2, True),
            ([self.sample()], 1, False),
        ):
            with self.subTest(rows=rows, complete=complete):
                self.assertFalse(
                    next(iter(aggregate(rows, repeats, complete).values()))["valid"]
                )

    def test_timeout_stops_wrapper_and_load_child(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            child_file = out / "child.pid"
            harness = Harness(SimpleNamespace(output=out))
            code = (
                "import subprocess,sys,time; from pathlib import Path; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                "Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(30)"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                harness.command(
                    [sys.executable, "-c", code, str(child_file)], timeout=1
                )
            stat = Path(f"/proc/{int(child_file.read_text())}/stat")
            try:
                state = stat.read_text().rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                pass  # Already reaped by init.
            else:
                self.assertEqual(state, "Z")
            self.assertTrue((out / "command-failure-1.log").exists())

    def test_valid_ratio_and_warmup_error_totals(self):
        nginx, rut = self.sample("nginx"), self.sample()
        self.assertIn("1.00×", render(aggregate([nginx, rut], 1, True)))
        rut.update(warmup_errors={"read": 7})
        group = aggregate([rut], 1, True)[("static", "close", 1, "rut")]
        self.assertFalse(group["valid"])
        self.assertEqual(group["warmup_errors"], 7)


if __name__ == "__main__":
    unittest.main()
