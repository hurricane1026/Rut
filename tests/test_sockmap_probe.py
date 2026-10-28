#!/usr/bin/env python3
"""Black-box artifact, capability selection, and payload preservation checks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY = Path(sys.argv.pop(1)).resolve()


def run(*arguments):
    result = subprocess.run([str(BINARY), *arguments], capture_output=True, text=True, timeout=20)
    return result, [json.loads(line) for line in result.stdout.splitlines()]


class SockmapProbeTests(unittest.TestCase):
    def check_transfer(self, record):
        self.assertTrue(record["transfer_ok"])
        self.assertTrue(record["half_close_ok"])
        self.assertEqual(record["verified_bytes"], 2097169)
        expected = 0 if record["backend"] == "sockmap" else 2097169
        self.assertEqual(record["relay_userspace_bytes"], expected)

    def test_off_and_auto_preserve_payload(self):
        for mode in ("off", "auto"):
            with self.subTest(mode=mode):
                result, records = run(mode, "--header-rewrite")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.check_transfer(records[-1])
                self.assertEqual(records[-1]["header_userspace_bytes"], 54)
                if mode == "off":
                    self.assertEqual(records[-1]["backend"], "copy")
                    self.assertEqual(len(records), 1)

    def test_emitted_artifact_and_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = str(Path(directory) / "tunnel")
            result, records = run("emit", prefix)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(records[-1]["emitted"])
            self.assertEqual(Path(prefix + ".parser.bpf").stat().st_size, 16)
            self.assertEqual(Path(prefix + ".verdict.bpf").stat().st_size, 80)
            result, records = run("auto", "--bytecode", prefix)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.check_transfer(records[-1])
            Path(prefix + ".verdict.bpf").write_bytes(b"invalid")
            result, records = run("required", "--bytecode", prefix)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(records[-1]["stage"], "artifact_read")
            result, records = run("auto", "--bytecode", prefix)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(records[0]["stage"], "artifact_read")
            self.check_transfer(records[-1])
            result, records = run("emit", prefix)
            self.assertEqual(result.returncode, 2)  # do not overwrite an existing artifact

    def test_required_or_failure_is_explicit(self):
        result, records = run("required")
        if result.returncode == 0:
            self.assertEqual(records[-1]["backend"], "sockmap")
            self.check_transfer(records[-1])
            result, records = run("auto", "--fail-after-insert", "--header-rewrite")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(records[0]["stage"], "injected_after_front_insert")
            self.assertEqual(records[-1]["backend"], "copy")
            self.check_transfer(records[-1])
        else:
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(records[-1]["backend"], "unavailable")
            self.assertGreater(records[-1]["errno"], 0)

    def test_body_budget_and_prequeued_fallback(self):
        result, records = run("auto", "--header-rewrite", "--bounded-body")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.check_transfer(records[-1])
        if records[-1]["backend"] == "sockmap":
            self.assertEqual(records[-1]["successor_userspace_bytes"], 17)
        result, records = run("auto", "--header-rewrite", "--bounded-body", "--prequeued-body")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(records[-1]["backend"], "copy")
        self.check_transfer(records[-1])

    def test_invalid_arguments(self):
        for arguments in ((), ("on",), ("auto", "--bytecode"), ("auto", "--unknown"), ("auto", "--prequeued-body")):
            result, _ = run(*arguments)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
