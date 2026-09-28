#!/usr/bin/env python3
"""Validate workload oracles and reproducibility, without timing Python routing."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("routing_corpus", ROOT / "bench/routing/generate.py")
corpus = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = corpus
SPEC.loader.exec_module(corpus)

COMPARE_SPEC = importlib.util.spec_from_file_location("routing_comparison", ROOT / "bench/routing/comparison.py")
comparison = importlib.util.module_from_spec(COMPARE_SPEC)
COMPARE_SPEC.loader.exec_module(comparison)


class RoutingCorpusTests(unittest.TestCase):
    def test_boundary_expected_answers(self):
        # Independent literal expectations pin the oracle, including captures.
        expected = {
            corpus.Contract.SEGMENT_PREFIX: [0, 1, 3, 2, 4, 0, 5, 6, 1],
            corpus.Contract.EXACT: [None, None, 3, None, 4, None, 5, 6, 1],
        }
        for contract, ids in expected.items():
            probes = corpus.boundary_case(contract)["probes"]
            self.assertEqual([p["expected"]["route_id"] if p["expected"] else None
                              for p in probes], ids)
            self.assertEqual(probes[7]["expected"]["captures"], {"id": "42"})

    def test_same_terminal_specific_method_and_first_declaration(self):
        routes = [{"id": 0, "method": "ANY", "path": "/api"},
                  {"id": 1, "method": "GET", "path": "/api"},
                  {"id": 2, "method": "GET", "path": "/api"}]
        for contract in corpus.Contract:
            self.assertEqual(corpus.reference_match(routes, "GET", "/api", contract)["route_id"], 1)
            self.assertEqual(corpus.reference_match(routes, "HEAD", "/api", contract)["route_id"], 0)

    def test_precedence_is_depth_then_literal_specificity(self):
        routes = [{"id": 0, "method": "GET", "path": "/api/:id"},
                  {"id": 1, "method": "GET", "path": "/api/v1/users"}]
        self.assertEqual(corpus.reference_match(routes, "GET", "/api/v1/users", corpus.Contract.EXACT)["route_id"], 1)

        routes = [{"id": 90, "method": "GET", "path": "/api/:id"},
                  {"id": 3, "method": "GET", "path": "/api/v1"}]
        self.assertEqual(corpus.reference_match(routes, "GET", "/api/v1", corpus.Contract.EXACT)["route_id"], 3)

        routes = [{"id": 99, "method": "GET", "path": "/api/:id"},
                  {"id": 4, "method": "GET", "path": "/api/v1"}]
        self.assertEqual(corpus.reference_match(routes, "GET", "/api/v1", corpus.Contract.SEGMENT_PREFIX)["route_id"], 4)

    def test_contracts_do_not_conflate_exact_and_prefix(self):
        routes = [{"id": 0, "method": "GET", "path": "/projects/:id"}]
        self.assertIsNone(corpus.reference_match(routes, "GET", "/projects/42/extra",
                                                corpus.Contract.EXACT))
        self.assertEqual(corpus.reference_match(routes, "GET", "/projects/42/extra",
                                               corpus.Contract.SEGMENT_PREFIX),
                         {"route_id": 0, "captures": {"id": "42"}})
        self.assertIsNone(corpus.reference_match(routes, "GET", "/projects//extra",
                                                corpus.Contract.SEGMENT_PREFIX))

    def test_every_profile_and_trace(self):
        for profile in corpus.PROFILES:
            for count in (n for n in (1, 4, 16) if n <= profile.max_routes):
                for contract in corpus.Contract:
                    with self.subTest(profile=profile.name, count=count, contract=contract):
                        case = corpus.case_for(profile, count, contract, 7)
                        self.assertEqual(len(case["routes"]), count)
                        self.assertEqual(len({(r["method"], r["path"]) for r in case["routes"]}), count)
                        for probe in case["probes"]:
                            if probe["tag"] == "endpoint":
                                self.assertIsNotNone(probe["expected"])
                            if probe["check"] == "observe":
                                self.assertIsNone(probe["expected"])
                        for trace in case["traces"].values():
                            self.assertEqual(len(trace), 1024)
                            for index in trace:
                                self.assertEqual(case["probes"][index]["check"], "assert")
                        for index in case["traces"].get("miss_only", []):
                            self.assertIsNone(case["probes"][index]["expected"])

    def test_root_has_no_manufactured_misses(self):
        case = corpus.case_for(corpus.PROFILE_BY_NAME["root_only"], 1,
                               corpus.Contract.SEGMENT_PREFIX, 1)
        self.assertNotIn("miss_only", case["traces"])

    def test_tiny_static_is_really_static_and_separates_local_from_proxy(self):
        for count in (1, 2, 4, 8):
            case = corpus.case_for(corpus.PROFILE_BY_NAME["tiny_static"], count,
                                   corpus.Contract.EXACT, 1)
            self.assertEqual(case["routes"][0]["path"], "/health")
            self.assertTrue(all(":" not in r["path"] for r in case["routes"]))
            self.assertEqual(case["execution_modes"], ["local_static", "proxy"])
            self.assertEqual(case["static_response_bytes"], [0, 16, 1024, 65536])

    def test_stress_capacity_is_explicit(self):
        case = corpus.case_for(corpus.PROFILE_BY_NAME["internet_gateway"], 512,
                               corpus.Contract.SEGMENT_PREFIX, 1)
        self.assertEqual(case["rut_route_capacity"], "exceeds_128")
        self.assertLess(len(case["sampled_route_ids"]), 512)
        self.assertEqual(case["sampled_route_ids"][0], 0)
        self.assertEqual(case["sampled_route_ids"][-1], 511)

    def test_cli_reproducible_files_and_valid_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            args = [sys.executable, str(ROOT / "bench/routing/generate.py"),
                    "--profiles", "ruby_rails", "saas_gateway", "--sizes", "1", "8",
                    "--output", str(output)]
            subprocess.run(args, check=True, capture_output=True)
            first = {p.name: p.read_bytes() for p in output.iterdir()}
            subprocess.run(args, check=True, capture_output=True)
            self.assertEqual(first, {p.name: p.read_bytes() for p in output.iterdir()})
            manifest = json.loads(first["manifest.json"])
            self.assertEqual(len(manifest["cases"]), 10)
            for entry in manifest["cases"]:
                self.assertEqual(corpus.hashlib.sha256(first[entry["file"]]).hexdigest(), entry["sha256"])


class ComparisonGateTests(unittest.TestCase):
    def setUp(self):
        self.matrix = comparison.plan({"cases": [{"file": "tiny.json", "sha256": "abc", "routes": 2, "asserted_probes": 10, "execution_modes": ["proxy"], "response_bytes": [16]}]})

    def evidence(self):
        rows = []
        for required in self.matrix["rows"]:
            row = dict(required, state="passed", asserted_probes=10, failed_probes=0)
            for field in ("binary_or_image_digest", "config_sha256", "probe_evidence_sha256",
                          "upstream_evidence_sha256", "environment_sha256",
                          "control_plane_digest", "route_status_evidence_sha256", "topology"):
                row[field] = "test-fixture-only"
            rows.append(row)
        return rows

    def test_requires_all_four_engines(self):
        self.assertEqual({r["engine"] for r in self.matrix["rows"]}, {"rut", "nginx", "envoy", "linkerd"})
        self.assertEqual(comparison.validate(self.matrix, self.evidence()), [])
        self.assertTrue(comparison.validate(self.matrix, self.evidence()[:-1]))

    def test_skip_wrong_input_and_no_probes_fail(self):
        for changes in ({"state": "skipped"}, {"case_sha256": "wrong"},
                        {"asserted_probes": 0}, {"asserted_probes": 9}, {"failed_probes": 1},
                        {"upstream_evidence_sha256": ""}):
            rows = self.evidence()
            rows[0].update(changes)
            self.assertTrue(comparison.validate(self.matrix, rows))

    def test_linkerd_requires_control_plane_and_route_status(self):
        rows = self.evidence()
        rows[-1].pop("route_status_evidence_sha256")
        self.assertTrue(comparison.validate(self.matrix, rows))

    def test_linkerd_local_response_is_explicitly_unsupported(self):
        matrix = comparison.plan({"cases": [{"file": "tiny.json", "sha256": "abc", "routes": 1,
                                              "asserted_probes": 10, "execution_modes": ["local_static"], "response_bytes": [16]}]})
        rows = [dict(r, execution_mode="local_static") for r in self.evidence()]
        self.assertTrue(comparison.validate(matrix, rows))
        rows[-1].update(state="unsupported", reason="Linkerd needs a backend for static content")
        self.assertEqual(comparison.validate(matrix, rows), [])

    def test_rut_over_capacity_is_explicitly_unsupported(self):
        matrix = comparison.plan({"cases": [{"file": "large.json", "sha256": "abc", "routes": 129,
                                              "asserted_probes": 10, "execution_modes": ["proxy"], "response_bytes": [16]}]})
        rows = []
        for required in matrix["rows"]:
            row = dict(required, state="passed", asserted_probes=10, failed_probes=0)
            for field in ("binary_or_image_digest", "config_sha256", "probe_evidence_sha256",
                          "upstream_evidence_sha256", "environment_sha256",
                          "control_plane_digest", "route_status_evidence_sha256", "topology"):
                row[field] = "test-fixture-only"
            rows.append(row)
        self.assertTrue(comparison.validate(matrix, rows))
        for row in rows:
            if row["engine"] == "rut":
                row.update(state="unsupported", reason="Rut currently supports at most 128 routes")
        self.assertEqual(comparison.validate(matrix, rows), [])

    def test_duplicate_and_unlisted_results_fail(self):
        rows = self.evidence()
        self.assertTrue(comparison.validate(self.matrix, rows + [rows[0]]))
        extra = dict(rows[0], case="not-requested.json")
        self.assertTrue(comparison.validate(self.matrix, rows + [extra]))


if __name__ == "__main__":
    unittest.main()
