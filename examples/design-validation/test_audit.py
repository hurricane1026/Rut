#!/usr/bin/env python3
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


AUDIT = Path(__file__).with_name("audit.py")
SURFACE = "Routes, request inspection, direct responses"


class CapabilityAuditTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rut-capability-audit-")
        self.root = Path(self.temporary.name)
        (self.root / "docs").mkdir()
        self.fixture_root = self.root / "examples/design-validation"
        self.fixture_root.mkdir(parents=True)
        (self.root / "docs/core-capabilities.md").write_text(
            "# Core Capabilities\n\n"
            "### Current implementation boundary\n\n"
            "| Capability | Status | Current boundary |\n"
            "|---|---|---|\n"
            f"| {SURFACE} | **Implemented** | test boundary |\n\n"
        )
        (self.fixture_root / "routing.rut").write_text(
            'route GET "/" { return 204 }\n'
        )
        self.manifest = {
            "schema": 1,
            "surfaces": [SURFACE],
            "scenarios": [
                {"id": "routing", "fixtures": ["routing.rut"]},
            ],
            "capabilities": [
                {
                    "id": "response.direct",
                    "surface": SURFACE,
                    "scenarios": ["routing"],
                }
            ],
            "sentinels": [
                {
                    "id": "routing-damage",
                    "capabilities": ["response.direct"],
                }
            ],
        }

    def tearDown(self):
        self.temporary.cleanup()

    def run_audit(self, manifest=None, *extra):
        manifest_path = self.fixture_root / "capabilities.json"
        manifest_path.write_text(json.dumps(manifest or self.manifest))
        return subprocess.run(
            [
                sys.executable,
                str(AUDIT),
                "--manifest",
                str(manifest_path),
                "--root",
                str(self.root),
                *map(str, extra),
            ],
            capture_output=True,
            text=True,
        )

    def assert_rejected(self, result, expected):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout + result.stderr)

    def test_accepts_complete_contract(self):
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_capability_without_scenario(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["capabilities"][0]["scenarios"] = []
        self.assert_rejected(
            self.run_audit(manifest),
            "capability response.direct has no black-box scenario",
        )

    def test_rejects_fixture_without_scenario_owner(self):
        (self.fixture_root / "unowned.rut").write_text(
            'route GET "/unowned" { return 204 }\n'
        )
        self.assert_rejected(
            self.run_audit(),
            "Rut fixtures without scenario ownership: ['unowned.rut']",
        )

    def test_rejects_documented_surface_without_contract(self):
        docs = self.root / "docs/core-capabilities.md"
        contents = docs.read_text()
        docs.write_text(
            contents.replace(
                f"| {SURFACE} | **Implemented** | test boundary |\n\n",
                f"| {SURFACE} | **Implemented** | test boundary |\n"
                "| New shipped surface | **Implemented** | missing contract |\n\n",
            )
        )
        self.assert_rejected(
            self.run_audit(),
            "manifest surfaces do not exactly match",
        )

    def test_rejects_skipped_runtime_scenario(self):
        executed = self.root / "executed-scenarios"
        executed.write_text("")
        self.assert_rejected(
            self.run_audit(self.manifest, "--executed-scenarios", executed),
            "scenarios not executed: ['routing']",
        )

    def test_rejects_unexecuted_damage_sentinel(self):
        executed = self.root / "executed-sentinels"
        executed.write_text("")
        self.assert_rejected(
            self.run_audit(self.manifest, "--executed-sentinels", executed),
            "sentinels not executed: ['routing-damage']",
        )


if __name__ == "__main__":
    unittest.main()
