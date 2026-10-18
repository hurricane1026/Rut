#!/usr/bin/env python3
"""Check payload/ownership behavior; capability-dependent cases fail explicitly."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY = Path(sys.argv.pop(1)).resolve()


def run(*arguments):
    result = subprocess.run([str(BINARY), *map(str, arguments)], capture_output=True, text=True, timeout=20)
    records = [json.loads(line) for line in result.stdout.splitlines()]
    return result, records


class HandoffTests(unittest.TestCase):
    def check_transfer(self, record, size):
        self.assertTrue(record["transfer_ok"], record)
        self.assertTrue(record["half_close_ok"], record)
        self.assertTrue(record["retired"], record)
        self.assertEqual(record["body_bytes"], size)
        self.assertEqual(record["copied_body_bytes"] + record["redirected_body_bytes"] +
                         record["spliced_body_bytes"], size)
        self.assertEqual(record["successor_userspace_bytes"], 18)
        self.assertGreater(record["cpu_ns"], 0)
        self.assertEqual(sum(record[key] for key in
                             ("setup_ns", "header_ns", "copy_or_handoff_ns", "redirect_wait_ns",
                              "tail_ns", "peer_join_ns", "retire_ns")), record["elapsed_ns"])
        self.assertGreaterEqual(record["tail_ns"], record["barrier_ns"])

    def test_larger_batches_preserve_boundaries(self):
        for mode in ("off", "auto", "splice"):
            for chunk in (16384, 65536):
                with self.subTest(mode=mode, chunk=chunk):
                    result, records = run(mode, "--packet-verdict", "--coalesced-tail",
                                          "--chunk-bytes", chunk, "--size", 1048576,
                                          "--delay-us", 0, "--slow-reader-us", 0)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.check_transfer(records[-1], 1048576)
                    self.assertEqual(records[-1]["requested_mode"], mode)
                    self.assertEqual(records[-1]["chunk_bytes"], chunk)

    def test_copy_and_auto_preserve_coalesced_data(self):
        for mode in ("off", "auto", "splice"):
            for size in (1, 4095, 4096, 4097, 65537, 1048576):
                with self.subTest(mode=mode, size=size):
                    result, records = run(mode, "--packet-verdict", "--coalesced-tail",
                                          "--size", size, "--prequeue", min(size, 4096),
                                          "--delay-us", 0, "--slow-reader-us", 0)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.check_transfer(records[-1], size)
                    if mode == "off":
                        self.assertFalse(records[-1]["available"])
                        self.assertEqual(records[-1]["redirected_body_bytes"], 0)
                    if mode == "splice":
                        self.assertEqual(records[-1]["backend"], "splice")
                        self.assertEqual(records[-1]["spliced_body_bytes"], size)
                        self.assertEqual(records[-1]["copied_body_bytes"], 0)

    def test_required_is_explicit(self):
        for extra in ((), ("--packet-verdict",)):
            result, records = run("required", *extra, "--coalesced-tail")
            if result.returncode == 0:
                self.assertTrue(records[-1]["available"])
                self.check_transfer(records[-1], 1048576)
            else:
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse(records[-1]["available"])
                self.assertGreater(records[-1]["errno"], 0)
                self.assertIn("stage", records[-1])

    def test_control_atomicity_and_rollback_or_capability_failure(self):
        result, records = run("required", "--packet-verdict", "--control-selftest")
        if result.returncode == 0:
            self.assertTrue(records[-1]["available"])
            self.assertTrue(records[-1]["control_selftest"])
        else:
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse(records[-1]["available"])
            self.assertGreater(records[-1]["errno"], 0)

    def test_notifications_identity_overflow_and_redirect_failure(self):
        result, records = run("required", "--packet-verdict", "--notification-selftest")
        if result.returncode == 0:
            self.assertTrue(records[-1]["available"])
            self.assertTrue(records[-1]["notification_selftest"])
        else:
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse(records[-1]["available"])
            self.assertGreater(records[-1]["errno"], 0)

    def test_bad_arguments(self):
        for arguments in ((), ("on",), ("off", "--size", 0), ("off", "--size", "oops"),
                          ("off", "--prequeue", 4097), ("off", "--packet-verdict", "--packet-verdict"),
                          ("off", "--size"), ("off", "--unknown"),
                          ("off", "--notification-selftest"),
                          ("off", "--delay-us", 1000001),
                          ("off", "--slow-reader-us", 1000001)):
            result, _ = run(*arguments)
            self.assertEqual(result.returncode, 2, result)

    def test_truncated_export_fails_before_capability_fallback(self):
        with tempfile.TemporaryDirectory(prefix="rut handoff ") as directory:
            prefix = Path(directory) / "truncated"
            for suffix in ("packet-verdict.bpf", "handoff-commit.bpf"):
                Path(f"{prefix}.{suffix}").write_bytes(bytes(8))
            result, _ = run("auto", "--packet-verdict", "--handoff-prefix", prefix)
            self.assertEqual(result.returncode, 2, result)
            self.assertIn("invalid handoff export files", result.stderr)


if __name__ == "__main__":
    unittest.main()
