#!/usr/bin/env python3
"""Regression tests for fail-closed compiler/TLC cross-check orchestration."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_concurrency_model import check_reference_case


def exported(verdict="None", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode,
                                       f"\\* native-result: {verdict}\n", stderr)


def tlc(output="Model checking completed. No error has been found.", code=0):
    return subprocess.CompletedProcess([], code, output, "")


class ReferenceChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name) / "case"

    def check_case(self, expected="None"):
        check_reference_case(Path("/checker"), Path("/tools.jar"), "case", self.work, expected)

    def test_success_preserves_reproducible_model_config_and_log(self):
        with patch("check_concurrency_model.subprocess.run", side_effect=[exported(), tlc()]):
            self.check_case()
        self.assertTrue((self.work / "concurrency_reference.tla").is_file())
        self.assertIn("native-result", (self.work / "concurrency_instance.tla").read_text())
        self.assertIn("PROPERTY Termination", (self.work / "instance.cfg").read_text())
        self.assertIn("No error", (self.work / "tlc.log").read_text())

    def test_shared_wrong_verdict_does_not_satisfy_golden_expectation(self):
        with patch("check_concurrency_model.subprocess.run", return_value=exported()) as run:
            with self.assertRaisesRegex(RuntimeError, "expected=Deadlock"):
                self.check_case("Deadlock")
            self.assertEqual(run.call_count, 1)

    def test_parse_failure_is_not_a_deadlock_counterexample(self):
        with patch("check_concurrency_model.subprocess.run", side_effect=[
                exported("Deadlock"), tlc("Parsing or semantic analysis failed", 150)]):
            with self.assertRaisesRegex(RuntimeError, "did not finish"):
                self.check_case("Deadlock")

    def test_counterexample_marker_requires_failure_exit_status(self):
        with patch("check_concurrency_model.subprocess.run", side_effect=[
                exported("Deadlock"), tlc("Deadlock reached", 0)]):
            with self.assertRaisesRegex(RuntimeError, "did not finish"):
                self.check_case("Deadlock")

    def test_killed_tlc_is_not_accepted_after_printing_a_counterexample(self):
        with patch("check_concurrency_model.subprocess.run", side_effect=[
                exported("Deadlock"), tlc("Deadlock reached", -9)]):
            with self.assertRaisesRegex(RuntimeError, "expected exit status"):
                self.check_case("Deadlock")

    def test_incomplete_native_search_is_not_a_proof(self):
        for verdict in ("StateLimit", "EdgeLimit", "WorkLimit", "OutOfMemory", "InvalidModel"):
            with self.subTest(verdict=verdict):
                with patch("check_concurrency_model.subprocess.run", return_value=exported(verdict)):
                    with self.assertRaisesRegex(RuntimeError, "incomplete native check"):
                        self.check_case()

    def test_timeout_preserves_partial_output_and_fails(self):
        for partial in (b"partial trace\n", "partial trace\n"):
            timeout = subprocess.TimeoutExpired(["java"], 180, output=partial)
            with patch("check_concurrency_model.subprocess.run", side_effect=[exported(), timeout]):
                with self.assertRaisesRegex(RuntimeError, "timed out; no proof"):
                    self.check_case()
            self.assertEqual((self.work / "tlc.log").read_text(), "partial trace\n")

    def test_export_failure_stops_before_tlc_and_preserves_diagnostic(self):
        with patch("check_concurrency_model.subprocess.run",
                   return_value=exported(returncode=1, stderr="invalid composition")) as run:
            with self.assertRaisesRegex(RuntimeError, "export failed"):
                self.check_case()
            self.assertEqual(run.call_count, 1)
        self.assertEqual((self.work / "export.log").read_text(), "invalid composition")

    def test_safety_counterexample_matches_golden_and_native(self):
        with patch("check_concurrency_model.subprocess.run", side_effect=[
                exported("UnsafeAction"), tlc("Invariant Safety is violated", 12)]):
            self.check_case("Safety")

    def test_missing_verdict_and_disagreeing_tlc_result_fail(self):
        for export_result, result in (
                (subprocess.CompletedProcess([], 0, "", ""), tlc()),
                (exported("Deadlock"), tlc())):
            with self.subTest(export=export_result.stdout):
                with patch("check_concurrency_model.subprocess.run", side_effect=[export_result, result]):
                    with self.assertRaises(RuntimeError):
                        self.check_case("Deadlock")


if __name__ == "__main__":
    unittest.main()
