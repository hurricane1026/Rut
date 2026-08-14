#!/usr/bin/env python3
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROBE = load_module("rut_design_probe_test", ROOT / "probe.py")
SENSITIVITY = load_module("rut_design_sensitivity_test", ROOT / "sensitivity.py")


class SensitivityHarnessTest(unittest.TestCase):
    def test_child_processes_reuse_current_interpreter(self):
        self.assertEqual(
            SENSITIVITY.python_command(Path("fixture.py"), "--port", 19890),
            [sys.executable, "fixture.py", "--port", "19890"],
        )

    def test_rejects_overlapping_ports_before_binding(self):
        with self.assertRaisesRegex(RuntimeError, "port configuration overlaps"):
            SENSITIVITY.require_ports_available([19890, 19890])

    def test_disabled_websocket_excludes_its_mutant_port(self):
        ports = SENSITIVITY.sensitivity_ports(19882, websocket_enabled=False)
        self.assertEqual(len(ports), len(set(ports)))
        self.assertNotIn(19890, ports[:8])

        websocket_ports = SENSITIVITY.sensitivity_ports(
            19882,
            websocket_enabled=True,
        )
        self.assertNotEqual(len(websocket_ports), len(set(websocket_ports)))

    def test_active_health_phase_failures_are_distinct(self):
        failures = (
            PROBE.ACTIVE_HEALTH_EJECTION_FAILURE,
            PROBE.ACTIVE_HEALTH_RECOVERY_FAILURE,
        )
        self.assertNotEqual(*failures)
        for failure in failures:
            with self.subTest(failure=failure):
                with self.assertRaisesRegex(RuntimeError, failure):
                    PROBE._wait_for_active_health(
                        lambda: (500, b"unexpected"),
                        (200, b"expected"),
                        failure,
                        timeout=0,
                    )

    def test_ejection_failure_cannot_satisfy_recovery_sentinel(self):
        def fail_during_ejection():
            raise RuntimeError(PROBE.ACTIVE_HEALTH_EJECTION_FAILURE)

        with self.assertRaisesRegex(RuntimeError, "failed for the wrong reason"):
            SENSITIVITY.expect_detected(
                "health.recovery-damage",
                fail_during_ejection,
                [],
                expected_error=PROBE.ACTIVE_HEALTH_RECOVERY_FAILURE,
            )


if __name__ == "__main__":
    unittest.main()
