"""Unprivileged checks of evidence gating and target lifecycle handling."""

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import trace
import smoke


class TraceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        kernel = mock.patch.object(trace.platform, "release", return_value="6.1.0")
        kernel.start()
        self.addCleanup(kernel.stop)
        self.root = Path(self.tmp.name)
        self.fake = self.root / "bpftrace"
        self.fake.write_text('''#!/usr/bin/env python3
import json, os, signal, sys, time
if "--version" in sys.argv:
    print("bpftrace v0.27.0")
    sys.exit(0)
mode = os.environ.get("TRACE_TEST_MODE", "ok")
if mode == "hang":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    with open(os.environ["TRACE_TEST_PID_FILE"], "w") as f:
        f.write(str(os.getpid()))
    while True:
        time.sleep(1)
if mode == "attach-failure":
    print("probe unavailable", file=sys.stderr)
    sys.exit(1)
if "--dry-run" in sys.argv:
    sys.exit(0)
if mode != "no-attachment":
    print(json.dumps({"type":"attached_probes", "data":{"probes":1}}), flush=True)
    armed = False
    def arm(*_):
        global armed
        armed = True
        print(json.dumps({"type":"printf", "data":"RUT_TRACE_ARMED\\n"}), flush=True)
    signal.signal(signal.SIGUSR1, arm)
    if mode not in ("no-arm", "early-exit"):
        while not armed:
            time.sleep(0.01)
print(json.dumps({"type":"printf", "data":"RUT_TRACE_READY\\n"}))
if mode == "warning":
    print("WARNING: probe information incomplete")
if mode == "lost":
    print(json.dumps({"type":"lost_events", "data":{"lost":3}}))
if mode == "exec":
    print(json.dumps({"type":"map", "data":{"@target_execs":{"123":1}}}))
print(json.dumps({"type":"map", "data":{"@tcp_completed_calls":{"123,1,2":2}}}))
print(json.dumps({"type":"map", "data":{"@tcp_elapsed_ns":{"123,1,2":6000}}}))
print(json.dumps({"type":"hist", "data":{"@tcp_latency_us":{"123,1,2":[{"min":2,"max":3,"count":2}]}}}))
if mode != "truncated":
    print(json.dumps({"type":"printf", "data":"RUT_TRACE_END\\n"}))
''')
        self.fake.chmod(0o755)

    def run_trace(self, mode="ok", extra=()):
        out = self.root / mode
        with mock.patch.dict(os.environ, {"TRACE_TEST_MODE": mode}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = trace.main(["--pid", str(os.getpid()), "--bpftrace", str(self.fake),
                             "--output", str(out), *extra])
        return rc, json.loads((out / "status.json").read_text()), out

    def test_completed_trace_preserves_histograms_and_labels(self):
        rc, status, out = self.run_trace()
        self.assertEqual(rc, 0)
        self.assertTrue(status["usable"])
        self.assertTrue(status["attached"])
        self.assertTrue(status["armed"])
        result = json.loads((out / "summary.json").read_text())
        self.assertEqual(result["maps"]["@tcp_latency_us"]["123,1,2"][0]["count"], 2)
        self.assertEqual(result["tcp"][0]["side"], "upstream")
        self.assertEqual(result["tcp"][0]["mean_elapsed_us"], 3)

    def test_loss_warning_exec_and_missing_end_cannot_pass(self):
        for mode in ("lost", "warning", "exec", "truncated", "attach-failure"):
            with self.subTest(mode=mode):
                rc, status, _ = self.run_trace(mode)
                self.assertEqual(rc, 1)
                self.assertFalse(status["usable"])

    def test_begin_marker_without_attached_event_is_not_ready(self):
        raw = self.root / "premature.jsonl"
        raw.write_text(json.dumps({"type": "printf", "data": "RUT_TRACE_READY\\n"}) + "\n")
        result = trace.read_results(raw)
        self.assertFalse(result["attached"])
        self.assertFalse(result["ready"])

    def test_generated_program_has_no_premature_ready_marker(self):
        program = trace.generate([123], 1, 8987, 9987, ["tcp", "sched"])
        self.assertNotIn("RUT_TRACE_READY", program)
        self.assertIn("self:signal:SIGUSR1", program)
        self.assertIn('@armed = 1', program)
        self.assertIn('@stop_ns = nsecs + 1 * 1000000000', program)
        self.assertIn('interval:ms:100 /@armed && nsecs >= @stop_ns/', program)
        self.assertNotIn('interval:s:1 /@armed/', program)
        self.assertIn('/@armed && @targets[pid]/', program)
        self.assertIn('if (@targets[$task->tgid]) {', program)
        self.assertIn('if (@targets[$task->tgid] || @target_execs[$task->tgid]) {', program)
        self.assertIn('if (@exiting[$prev->pid]) {', program)
        self.assertIn('!@exiting[$next->pid]', program)
        self.assertNotIn('if (@armed && @targets[$task->tgid]) {', program)

    def test_arm_ack_is_strict_and_missing_arm_fails(self):
        raw = self.root / "armed.jsonl"
        raw.write_text(json.dumps({"type": "printf", "data": "RUT_TRACE_ARMED extra"}) + "\n")
        self.assertFalse(trace.read_results(raw)["armed"])
        for mode in ("no-arm", "early-exit"):
            with self.subTest(mode=mode):
                rc, status, _ = self.run_trace(mode)
                self.assertEqual(rc, 1)
                self.assertFalse(status["completed"])
                self.assertTrue(status["attached"])
                self.assertFalse(status["armed"])

    def test_evidence_permissions_are_private_under_umask(self):
        previous = os.umask(0o022)
        try:
            _, _, out = self.run_trace()
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
        for path in out.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)

    def test_smoke_waits_for_attached_event_and_tolerates_partial_tail(self):
        raw = self.root / "partial.jsonl"
        raw.write_text('{"type":"printf","data":"RUT_TRACE_READY\\n"}\n{"type":')
        self.assertFalse(smoke.attached(raw))
        raw.write_text(raw.read_text() + '\n{"type":"attached_probes","count":1,"data":{"probes":1}}\n')
        self.assertTrue(smoke.attached(raw))
        raw.write_text(json.dumps({"type": "printf", "data": "RUT_TRACE_ARMED\n"}) + "\n")
        self.assertTrue(smoke.armed(raw))

    def test_attached_event_requires_positive_probe_count_and_object_data(self):
        raw = self.root / "invalid-attached.jsonl"
        for event in ({"type": "attached_probes", "data": {"probes": 0}},
                      {"type": "attached_probes", "data": {"probes": True}},
                      {"type": "attached_probes", "data": {}},
                      {"type": "attached_probes", "data": 1},
                      ["attached_probes"], 1, None):
            raw.write_text(json.dumps(event) + "\n")
            self.assertFalse(smoke.attached(raw))
        raw.write_text(json.dumps({"type": "attached_probes", "data": {"probes": 1}}) + "\n")
        self.assertTrue(smoke.attached(raw))

        for event in ({"type": "attached_probes", "data": {"probes": 0}},
                      {"type": "attached_probes", "data": {"probes": "1"}},
                      {"type": "attached_probes", "data": []},
                      ["attached_probes"], 1):
            raw.write_text(json.dumps(event) + "\n")
            self.assertFalse(trace.read_results(raw)["attached"])
        raw.write_text(json.dumps({"type": "attached_probes", "data": {"probes": 1}}) + "\n")
        self.assertTrue(trace.read_results(raw)["attached"])

    def test_trace_without_attachment_cannot_be_completed(self):
        rc, status, _ = self.run_trace("no-attachment")
        self.assertEqual(rc, 1)
        self.assertFalse(status["completed"])
        self.assertFalse(status["usable"])

    def test_pid_reuse_rejects_an_otherwise_complete_trace(self):
        before = trace.process_identity(os.getpid())
        after = dict(before, start_ticks=before["start_ticks"] + 1)
        with mock.patch.object(trace, "process_identity", side_effect=[before, after]):
            rc, status, _ = self.run_trace("reuse")
        self.assertEqual(rc, 1)
        self.assertFalse(status["targets_unchanged"])

    def test_target_exit_is_partial_evidence(self):
        before = trace.process_identity(os.getpid())
        with mock.patch.object(trace, "process_identity", side_effect=[before, FileNotFoundError()]):
            rc, status, _ = self.run_trace("exit")
        self.assertEqual(rc, 1)
        self.assertTrue(status["completed"])
        self.assertFalse(status["usable"])

    def test_check_is_not_a_measurement(self):
        rc, status, _ = self.run_trace("check", ["--check"])
        self.assertEqual(rc, 0)
        self.assertTrue(status["completed"])
        self.assertFalse(status["usable"])

    def test_sigterm_stops_only_own_tracer(self):
        out = self.root / "interrupted"
        pid_file = self.root / "tracer.pid"
        env = dict(os.environ, TRACE_TEST_MODE="hang", TRACE_TEST_PID_FILE=str(pid_file))
        # Run main in a separate process so real signals exercise its cleanup.
        code = ("import platform, sys; platform.release = lambda: '6.1.0'; "
                "import trace; sys.exit(trace.main(sys.argv[1:]))")
        proc = subprocess.Popen(
            [sys.executable, "-c", code, "--pid", str(os.getpid()),
             "--bpftrace", str(self.fake), "--output", str(out)],
            cwd=Path(trace.__file__).parent, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tracer_pid = None
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if pid_file.exists() and pid_file.read_text():
                    tracer_pid = int(pid_file.read_text())
                    break
                time.sleep(0.02)
            self.assertIsNotNone(tracer_pid, "fake tracer did not start")
            proc.send_signal(signal.SIGTERM)
            self.assertEqual(proc.wait(timeout=5), 1)
            status = json.loads((out / "status.json").read_text())
            self.assertFalse(status["usable"])
            self.assertIn("error", status)
            with self.assertRaises(ProcessLookupError):
                os.kill(tracer_pid, 0)
            os.kill(os.getpid(), 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if tracer_pid is not None:
                try:
                    os.kill(tracer_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_existing_evidence_is_not_overwritten(self):
        self.run_trace()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            trace.main(["--pid", str(os.getpid()), "--output", str(self.root / "ok")])
        self.assertTrue(json.loads((self.root / "ok/status.json").read_text())["usable"])

    def test_symlinked_output_is_rejected_before_launch(self):
        link = self.root / "output-link"
        link.symlink_to(self.root / "future-output", target_is_directory=True)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(trace.subprocess, "Popen") as popen:
            trace.main(["--pid", str(os.getpid()), "--bpftrace", str(self.fake),
                        "--output", str(link)])
            popen.assert_not_called()

    def test_invalid_selection_never_launches_tool(self):
        for args in (["--pid", "0"], ["--pid", "1", "--duration", "0"],
                     ["--pid", "1", "--front-port", "9987"],
                     ["--pid", "1; touch /tmp/no"]):
            with self.subTest(args=args), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    mock.patch.object(trace.subprocess, "Popen") as popen:
                trace.main([*args, "--emit"])
                popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
