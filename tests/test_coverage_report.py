#!/usr/bin/env python3

import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "coverage_report", ROOT / "scripts" / "coverage_report.py"
)
assert SPEC is not None and SPEC.loader is not None
coverage_report = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coverage_report
SPEC.loader.exec_module(coverage_report)


class CoverageReportTest(unittest.TestCase):
    def test_runtime_gate_exclusions_remain_reportable(self) -> None:
        excluded = (
            "include/rut/runtime/io_uring_backend.h",
            "include/rut/runtime/epoll_backend.h",
            "include/rut/runtime/epoll_event_loop.h",
            "include/rut/runtime/iouring_event_loop.h",
            "include/rut/runtime/shard.h",
            "include/rut/runtime/tls_iouring.h",
            "src/runtime/io_uring_backend.cc",
            "src/runtime/epoll_backend.cc",
            "src/runtime/socket.cc",
            "src/runtime/access_log.cc",
        )
        for path in excluded:
            with self.subTest(path=path):
                area = coverage_report.area_for_path(f"/repo/{path}")
                self.assertIsNotNone(area)
                self.assertEqual(area.name, "runtime")
                self.assertFalse(coverage_report.gate_includes_path(area, path))

        shard_control = "include/rut/runtime/shard_control.h"
        area = coverage_report.area_for_path(shard_control)
        self.assertIsNotNone(area)
        self.assertTrue(coverage_report.gate_includes_path(area, shard_control))

    def test_arch_specific_runtime_file_is_report_excluded(self) -> None:
        avx = "src/runtime/simd/avx2.cc"
        self.assertIsNone(coverage_report.area_for_path(avx))
        area = coverage_report.area_for_path(avx, include_report_excluded=True)
        self.assertIsNotNone(area)
        self.assertEqual(area.name, "runtime")

    def test_third_party_path_cannot_claim_first_party_prefix(self) -> None:
        path = "/repo/third_party/vendor/include/rut/runtime/copied.h"
        self.assertIsNone(
            coverage_report.area_for_path(path, include_report_excluded=True)
        )

    def test_changed_summary_marks_gate_and_report_exclusions(self) -> None:
        merged = {area.name: {} for area in coverage_report.AREAS}
        merged["runtime"] = {
            "/repo/src/runtime/access_log.cc": {1: 1, 2: 0},
            "/repo/src/runtime/http_parser.cc": {1: 1, 2: 1},
        }
        changed = [
            "src/runtime/access_log.cc",
            "src/runtime/http_parser.cc",
            "src/runtime/simd/neon.cc",
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            coverage_report.print_changed_file_summary(merged, changed)
        rendered = output.getvalue()
        self.assertIn("runtime         no", rendered)
        self.assertIn("runtime        yes", rendered)
        self.assertIn("runtime       skip", rendered)

    def test_area_stats_prioritizes_missed_lines(self) -> None:
        covered, total, files = coverage_report.area_stats(
            {
                "/repo/src/runtime/a.cc": {1: 1, 2: 0, 3: 0},
                "/repo/src/runtime/b.cc": {1: 1, 2: 0},
            }
        )
        self.assertEqual((covered, total), (2, 5))
        self.assertTrue(files[0][3].endswith("a.cc"))

    def test_main_keeps_report_and_gate_totals_distinct(self) -> None:
        merged = {area.name: {} for area in coverage_report.AREAS}
        merged["runtime"] = {
            "/repo/src/runtime/access_log.cc": {1: 0, 2: 0},
            "/repo/src/runtime/http_parser.cc": {1: 1, 2: 1},
        }
        output = io.StringIO()
        argv = [
            "coverage_report.py",
            "--profile",
            "unused.profdata",
            "--threshold",
            "95",
            "unused-binary",
        ]
        with mock.patch.object(coverage_report, "merge_line_hits", return_value=merged), mock.patch(
            "sys.argv", argv
        ), contextlib.redirect_stdout(output):
            result = coverage_report.main()
        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("runtime               2       4", rendered)
        self.assertIn("runtime GATE TOTAL: 2/2", rendered)
        self.assertIn("Threshold gate excludes 1", rendered)


if __name__ == "__main__":
    unittest.main()
