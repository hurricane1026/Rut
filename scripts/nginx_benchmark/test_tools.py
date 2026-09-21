"""Checks for evidence gating and HTTP-close handling; no Docker required."""

import contextlib
import argparse
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
import matrix

from run import (
    Harness,
    connection_header,
    expected_body,
    request_bytes,
    response,
    response_head,
    origin_reuse_records,
    valid_origin_reuse,
    validate_proxy_profile,
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
    def test_native_streaming_payload_and_reuse_evidence_reject_corruption(self):
        wanted = expected_body("proxy", native_streaming=True)
        self.assertEqual(len(wanted), 256 * 1024)
        self.assertNotEqual(wanted[:4096], wanted[4096:8192])
        head = (b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n"
                b"Content-Type: application/octet-stream\r\n\r\n")
        raw, closed = response(
            FakeSocket([head, wanted]), "proxy", False,
            keepalive_header="implicit", native_streaming=True,
        )
        self.assertFalse(closed)
        self.assertTrue(raw.endswith(wanted))
        with self.assertRaisesRegex(ValueError, "complete body"):
            response(FakeSocket([head, wanted[:-1]]), "proxy", False,
                     keepalive_header="implicit", native_streaming=True)
        reordered = wanted[4096:8192] + wanted[:4096] + wanted[8192:]
        with self.assertRaisesRegex(ValueError, "unexpected body"):
            response(FakeSocket([head, reordered]), "proxy", False,
                     keepalive_header="implicit", native_streaming=True)
        with self.assertRaisesRegex(ValueError, "bounded Content-Length"):
            response(FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 262143\r\n"
                                 b"Content-Type: application/octet-stream\r\n"
                                 b"Transfer-Encoding: chunked\r\n\r\n", wanted]),
                     "proxy", False, keepalive_header="implicit", native_streaming=True)
        with self.assertRaisesRegex(ValueError, "unexpected body"):
            response(FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 262143\r\n"
                                 b"Content-Type: application/octet-stream\r\n\r\n", wanted]),
                     "proxy", False, keepalive_header="implicit", native_streaming=True)
        with self.assertRaisesRegex(ValueError, "Content-Type"):
            response(FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n"
                                 b"Content-Type: text/plain\r\n\r\n", wanted]),
                     "proxy", False, keepalive_header="implicit", native_streaming=True)
        for duplicated in (
            b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\nContent-Length: 262144\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n"
            b"Content-Type: application/octet-stream\r\nContent-Type: application/octet-stream\r\n\r\n",
        ):
            with self.subTest(duplicated=duplicated), self.assertRaisesRegex(ValueError, "duplicate header"):
                response(FakeSocket([duplicated, wanted]), "proxy", False,
                         keepalive_header="implicit", native_streaming=True)
        with self.assertRaisesRegex(ValueError, "keepalive semantics"):
            response(FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n"
                                 b"Content-Type: application/octet-stream\r\n"
                                 b"Connection: close\r\n\r\n", wanted]),
                     "proxy", False, keepalive_header="implicit", native_streaming=True)

        markers = [f"sample-r1-nginx-keepalive-{n}" for n in range(3)]
        complete = "\n".join(
            f"marker={marker_prefix} connection=91 requests={i + 8}"
            for i, marker_prefix in enumerate(markers)
        )
        rows = origin_reuse_records(complete, markers)
        self.assertEqual(len(rows), 3)
        self.assertEqual(len({row[1] for row in rows}), 1)
        self.assertTrue(valid_origin_reuse(rows, markers))
        reconnect = complete.replace("connection=91 requests=9", "connection=92 requests=1")
        self.assertFalse(valid_origin_reuse(origin_reuse_records(reconnect, markers), markers))
        out_of_order = complete.replace("requests=9", "requests=11").replace("requests=10", "requests=9")
        self.assertFalse(valid_origin_reuse(origin_reuse_records(out_of_order, markers), markers))
        missing = "\n".join(complete.splitlines()[:-1])
        self.assertFalse(valid_origin_reuse(origin_reuse_records(missing, markers), markers))

    def test_native_streaming_profile_rejects_unsupported_matrix_shapes(self):
        parser = argparse.ArgumentParser()
        baseline = dict(proxy_profile="native-streaming", body_size=None,
                        scenarios=["proxy-keepalive"], concurrency=[1, 32],
                        keepalive_header="implicit")
        args = SimpleNamespace(**baseline)
        validate_proxy_profile(parser, args)
        self.assertEqual(args.body_size, 256 * 1024)
        single = SimpleNamespace(**(baseline | {"concurrency": [32]}))
        validate_proxy_profile(parser, single)
        self.assertEqual(single.body_size, 256 * 1024)
        for key, value in (("scenarios", ["proxy-close"]),
                           ("concurrency", [8]),
                           ("concurrency", []),
                           ("body_size", 65536),
                           ("keepalive_header", "explicit")):
            with self.subTest(key=key), self.assertRaises(SystemExit):
                validate_proxy_profile(parser, SimpleNamespace(**(baseline | {key: value})))

    def test_default_proxy_profile_leaves_arguments_unchanged(self):
        args = SimpleNamespace(proxy_profile="converter-strict", body_size=None,
                               scenarios=["proxy-close"], concurrency=[1],
                               keepalive_header="explicit")
        validate_proxy_profile(argparse.ArgumentParser(), args)
        self.assertIsNone(args.body_size)

    def test_matrix_keeps_valid_groups_only_after_completed_child(self):
        cases = (
            # One failed concurrency must not erase its valid siblings.
            (1, True, True, [True, True, False], 2),
            (0, True, False, [True, True, True], 0),
            # Setup errors, signals and missing/incomplete completion evidence
            # invalidate all groups even if results.json already has good rows.
            (2, True, False, [False, False, False], 2),
            (-signal.SIGTERM, True, False, [False, False, False], 2),
            (1, False, False, [False, False, False], 2),
            (1, None, False, [False, False, False], 2),
            (0, False, False, [False, False, False], 2),
        )
        for returncode, complete, bad_sample, expected, expected_exit in cases:
            with self.subTest(returncode=returncode, complete=complete, bad_sample=bad_sample), \
                    tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "matrix"
                argv = ["matrix.py", "--output", str(output),
                        "--tls-cert", "unused.pem", "--tls-key", "unused.key",
                        "--transports", "http", "--body-sizes", "16",
                        "--scenarios", "static-close", "--concurrency", "1", "32", "128",
                        "--duration", "5", "--repeats", "3"]

                def child_run(command, _log):
                    folder = Path(command[command.index("--output") + 1])
                    folder.mkdir()
                    rows = []
                    for concurrency in (1, 32, 128):
                        for engine, rps in (("nginx", 100), ("rut", 120)):
                            for rep in (1, 2, 3):
                                invalid = bad_sample and concurrency == 128 and engine == "rut" and rep == 1
                                rows.append(dict(
                                    workload="static", connection="close", transport="http",
                                    body_size=16, concurrency=concurrency, engine=engine,
                                    rep=rep, requests=500, rps=rps, seconds=5, valid=not invalid,
                                    errors=dict(connect=0, read=int(invalid), write=0, status=0, timeout=0),
                                    warmup_errors=dict(connect=0, read=0, write=0, status=0, timeout=0)))
                    run.save_json(folder / "results.json", rows)
                    if complete is not None:
                        run.save_json(folder / "status.json",
                                      {"complete": complete, "valid": not bad_sample})
                    return returncode

                previous_sigterm = signal.getsignal(signal.SIGTERM)
                try:
                    with mock.patch.object(sys, "argv", argv), \
                            mock.patch.object(matrix, "run_cell", side_effect=child_run), \
                            contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(matrix.main(), expected_exit)
                finally:
                    signal.signal(signal.SIGTERM, previous_sigterm)
                report = json.loads((output / "matrix.json").read_text())
                self.assertTrue(report["complete"])
                self.assertEqual(report["target_met"], all(expected))
                self.assertEqual([c["measurement_valid"] for c in report["cells"]], expected)
                self.assertEqual([c["target_met"] for c in report["cells"]], expected)
                self.assertTrue(all(c["exit_code"] == returncode for c in report["cells"]))

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
                                 requests=500, rps=rps, seconds=5, valid=True,
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

    def test_matrix_requires_actual_measurement_duration(self):
        import copy
        rows = [dict(workload="static", connection="close", transport="http",
                     body_size=16, concurrency=1, engine=engine, rep=rep,
                     requests=500, rps=rps, seconds=5, valid=True,
                     errors=dict.fromkeys(run.ERROR_NAMES, 0),
                     warmup_errors=dict.fromkeys(run.ERROR_NAMES, 0))
                for engine, rps in (("nginx", 100), ("rut", 120)) for rep in (1, 2, 3)]
        self.assertTrue(assess(rows, "static-close", "http", 16, 1, 3, 5)["target_met"])
        for engine in ("nginx", "rut"):
            for seconds in (4.999, 0, -1, None, "5", True, float("nan"), float("inf")):
                with self.subTest(engine=engine, seconds=seconds):
                    bad = copy.deepcopy(rows)
                    next(r for r in bad if r["engine"] == engine)["seconds"] = seconds
                    result = assess(bad, "static-close", "http", 16, 1, 3, 10)
                    self.assertFalse(result["performance_eligible"])
                    self.assertFalse(result["target_met"])
                    if seconds == 4.999:
                        self.assertTrue(result["measurement_valid"])
        missing = copy.deepcopy(rows)
        del missing[0]["seconds"]
        self.assertFalse(assess(missing, "static-close", "http", 16, 1, 3, 10)["target_met"])

    def test_matrix_continues_after_bad_evidence(self):
        cases = (
            ("results.json", b"[", "truncated rows"),
            ("status.json", b"{", "truncated status"),
            ("results.json", b"\xff", "invalid UTF-8"),
            ("results.json", b"[" * 2000 + b"]" * 2000, "excessive JSON nesting"),
            ("results.json", b"{}", "rows object"),
            ("results.json", b"[null]", "non-object row"),
            ("results.json", b"[{}]", "missing fields"),
            ("status.json", b"[]", "status array"),
            ("status.json", b'{"complete": "true", "valid": true}', "non-boolean completion"),
            ("status.json", None, "missing status"),
            ("results.json", None, "missing rows"),
            ("results.json", b"DIRECTORY", "unreadable rows path"),
        )
        for filename, payload, label in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "matrix"
                argv = ["matrix.py", "--output", str(output),
                        "--tls-cert", "unused.pem", "--tls-key", "unused.key",
                        "--transports", "http", "--body-sizes", "16", "32",
                        "--scenarios", "static-close", "--concurrency", "1",
                        "--duration", "5", "--repeats", "3"]

                def child_run(command, _log):
                    folder = Path(command[command.index("--output") + 1])
                    size = int(command[command.index("--body-size") + 1])
                    folder.mkdir()
                    rows = [dict(workload="static", connection="close", transport="http",
                                 body_size=size, concurrency=1, engine=engine, rep=rep,
                                 requests=500, rps=rps, seconds=5, valid=True,
                                 errors=dict.fromkeys(run.ERROR_NAMES, 0),
                                 warmup_errors=dict.fromkeys(run.ERROR_NAMES, 0))
                            for engine, rps in (("nginx", 100), ("rut", 120)) for rep in (1, 2, 3)]
                    run.save_json(folder / "results.json", rows)
                    run.save_json(folder / "status.json", {"complete": True, "valid": True})
                    if size == 16:
                        artifact = folder / filename
                        if payload is None:
                            artifact.unlink()
                        elif payload == b"DIRECTORY":
                            artifact.unlink()
                            artifact.mkdir()
                        else:
                            artifact.write_bytes(payload)
                    return 0

                previous_sigterm = signal.getsignal(signal.SIGTERM)
                try:
                    with mock.patch.object(sys, "argv", argv), \
                            mock.patch.object(matrix, "run_cell", side_effect=child_run) as child, \
                            contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(matrix.main(), 2)
                        self.assertEqual(child.call_count, 2)
                finally:
                    signal.signal(signal.SIGTERM, previous_sigterm)
                report = json.loads((output / "matrix.json").read_text())
                self.assertTrue(report["complete"])
                self.assertFalse(report["target_met"])
                first, second = report["cells"]
                self.assertFalse(first["measurement_valid"])
                self.assertFalse(first["target_met"])
                self.assertTrue(first["evidence_error"])
                self.assertTrue(second["measurement_valid"])
                self.assertTrue(second["target_met"])

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

    def test_first_engine_option_and_alternating_repeat_order(self):
        parser = run.argparse.ArgumentParser()
        run.add_first_engine_argument(parser)
        self.assertEqual(parser.parse_args([]).first_engine, "nginx")
        self.assertEqual(parser.parse_args(["--first-engine", "rut"]).first_engine, "rut")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["--first-engine", "other"])

    def test_benchmark_engine_start_order_matches_recorded_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            for first_engine in ("nginx", "rut"):
                out = Path(directory) / first_engine
                out.mkdir()
                tools = {}
                for name in ("rut", "converter", "wrk"):
                    path = out / name
                    path.write_text("mock executable\n")
                    path.chmod(0o755)
                    tools[name] = path
                args = SimpleNamespace(
                    output=out,
                    rut=tools["rut"],
                    converter=tools["converter"],
                    wrk=tools["wrk"],
                    tls_cert=None,
                    tls_key=None,
                    body_size=None,
                    mode="benchmark",
                    server_cpu=2,
                    origin_cpu=3,
                    client_cpus="4,5",
                    keepalive_header="implicit",
                    front_port=8087,
                    origin_port=9087,
                    concurrency=[1],
                    duration=1,
                    warmup=1,
                    repeats=4,
                    first_engine=first_engine,
                    scenarios=["proxy-close"],
                )
                harness = Harness(args)

                def fake_command(argv, timeout=20):
                    if argv == ["docker", "context", "inspect"]:
                        stdout = '[{"Endpoints":{"docker":{"Host":"unix:///mock.sock"}}}]'
                    elif argv[:2] == ["docker", "info"]:
                        stdout = "mock docker"
                    elif argv[:3] == ["docker", "image", "inspect"]:
                        stdout = '[{"Id":"mock-image"}]'
                    elif argv[0] == "git":
                        stdout = "" if "status" in argv else "mock-head"
                    elif argv == ["lscpu"]:
                        stdout = "mock cpu topology"
                    elif str(argv[0]) == str(tools["converter"]):
                        stdout = f"listen 127.0.0.1:{args.front_port}\nmock config\n"
                    else:
                        raise AssertionError(f"unexpected external command: {argv!r}")
                    return subprocess.CompletedProcess(argv, 0, stdout, "")

                with mock.patch.object(harness, "command", side_effect=fake_command):
                    harness.prepare()
                metadata = json.loads((out / "environment.json").read_text())

                started = []

                @contextlib.contextmanager
                def mock_frontend(engine, _work, _label):
                    started.append(engine)
                    yield 123

                harness.frontend = mock_frontend
                harness.validate = lambda *_args: None
                sample = {
                    "requests": 1,
                    "seconds": 1.0,
                    "rps": 1.0,
                    "p50_us": 1.0,
                    "p95_us": 1.0,
                    "p99_us": 1.0,
                    "errors": dict.fromkeys(run.ERROR_NAMES, 0),
                    "client_cpu_seconds": 0.0,
                }
                harness.wrk = lambda *_args: dict(sample)
                with mock.patch.object(run, "proc_usage", return_value=(0.0, 0)), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertTrue(harness.benchmark(456))

                metadata_order = metadata["engine_order_by_scenario_and_repeat"]
                self.assertEqual([entry["repeat"] for entry in metadata_order], [1, 2, 3, 4])
                self.assertEqual({entry["scenario"] for entry in metadata_order}, {"proxy-close"})
                expected = (
                    ["nginx", "rut", "rut", "nginx", "nginx", "rut", "rut", "nginx"]
                    if first_engine == "nginx"
                    else ["rut", "nginx", "nginx", "rut", "rut", "nginx", "nginx", "rut"]
                )
                self.assertEqual(started, expected)
                self.assertEqual(started, [engine for entry in metadata_order
                                           for engine in entry["engines"]])

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
