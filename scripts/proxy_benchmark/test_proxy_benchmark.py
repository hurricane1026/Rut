import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import common
import prepare
import run_matrix
import summarize


class ProxyBenchmarkTests(unittest.TestCase):
    def test_payload_matches_native_streaming_fixture(self):
        known_sha = {
            "4k": "1c5d61d93c7f698d07b9214c78c07d59cc268ce4acdcce696f73fb40d208f17d",
            "64k": "0b4eedd2bd10476fb32848ab25484834e80cd7b583fae6f2bdcbdf2286bb6226",
            "256k": "c82bc5892ddae66cd45bf3beb38cedc385943477771fcf970370abb3efc97788",
            "1m": "e9e48dd7ce11036c77b8e7de3b29580539c2070396edfdb3aa23fad921dffb5b",
        }
        for label, size in prepare.SIZES.items():
            with self.subTest(body=label):
                actual = prepare.native_body(size)
                self.assertEqual(len(actual), size)
                self.assertEqual(hashlib.sha256(actual).hexdigest(), known_sha[label])

    def test_cpu_masks_are_binary_and_select_one_cpu(self):
        for cpu in (2, 3, 8, 14):
            mask = prepare.mask(cpu)
            self.assertEqual(len(mask), 64)
            self.assertEqual(mask.count("1"), 1)
            self.assertEqual(mask[-1 - cpu], "1")
            self.assertTrue(set(mask) <= {"0", "1"})

    def test_nginx_origin_modes_match_the_two_topologies(self):
        native = prepare.nginx_origin(8081, [3, 4, 8, 9], "/data/proxy")
        linkerd = prepare.nginx_origin(8080, [3, 4, 8, 9], "/data/body.bin", "0.0.0.0")
        self.assertIn("listen 127.0.0.1:8081;", native)
        self.assertIn("listen 0.0.0.0:8080;", linkerd)
        self.assertIn("alias /data/proxy;", native)
        self.assertIn("alias /data/body.bin;", linkerd)
        self.assertNotIn("keepalive_requests", native)
        self.assertNotIn("keepalive_requests", linkerd)
        self.assertIn("worker_cpu_affinity", native)
        self.assertIn(prepare.mask(9), native)

    def test_envoy_config_is_http1_router_only(self):
        config = prepare.envoy_config()
        listener = config["static_resources"]["listeners"][0]
        hcm = listener["filter_chains"][0]["filters"][0]["typed_config"]
        cluster = config["static_resources"]["clusters"][0]
        self.assertEqual(hcm["codec_type"], "HTTP1")
        self.assertEqual([entry["name"] for entry in hcm["http_filters"]], ["envoy.filters.http.router"])
        self.assertEqual(cluster["connect_timeout"], "1s")
        self.assertIn("explicit_http_config", cluster["typed_extension_protocol_options"][
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"])
        self.assertEqual(len(config["static_resources"]["listeners"]), 1)

    def test_pod_specs_preserve_single_hop_topology_and_runtime_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binaries = root / "rps"
            binaries.mkdir()
            (binaries / "rut").write_bytes(b"runtime")
            (binaries / "rut-compile").write_bytes(b"compiler")
            config = {
                "run_id": "test123", "checkpoint": tmp, "node_mount": "/benchmark",
                "worker_node": "bench-worker", "namespace": "bench",
                "selector": {"key": "benchmark-role", "value": "worker"},
                "configmaps": {"native": "pb-test-native", "linkerd": "pb-test-linkerd"},
                "images": {"nginx": "nginx@sha256:abc", "envoy": "envoy@sha256:def", "client": "client:test"},
                "cpus": {"proxy": 2, "origin": "3,4,8,9", "client": "5,7", "helpers": "6,14"},
                "paths": {"rut_rps": str(binaries), "rut_throughput": str(binaries),
                          "runtime_libs": str(root / "libs"), "clang": str(root / "clang"),
                          "ld": str(root / "ld"), "rut_config_dir": str(root / "config")},
            }
            linkerd = common.pod_spec(config, "linkerd", "4k", "pb-test-linkerd-4k")
            self.assertEqual(linkerd["spec"]["nodeName"], "bench-worker")
            self.assertEqual(linkerd["spec"]["nodeSelector"], {"benchmark-role": "worker"})
            self.assertEqual(len(linkerd["spec"]["containers"]), 1)
            self.assertIn("linkerd.io/inject", linkerd["metadata"]["annotations"])
            self.assertNotIn("limits", linkerd["spec"]["containers"][0].get("resources", {}))
            rut = common.pod_spec(config, "rut-rps", "4k", "pb-test-rut")
            frontend = rut["spec"]["containers"][0]
            self.assertEqual(frontend["args"][-2:], ["--backend", "io_uring"])
            self.assertEqual(frontend["command"], ["/runtime/rut"])
            self.assertEqual(frontend["image"], config["images"]["client"])
            self.assertEqual(rut["metadata"]["labels"]["benchmark-run-id"], "test123")

    def test_matrix_has_all_interleaved_unique_cells(self):
        cells = run_matrix.plan()
        self.assertEqual(len(cells), 48)
        self.assertEqual(len({(x["body"], x["engine"], x["rep"]) for x in cells}), 48)
        self.assertEqual([x["engine"] for x in cells[:4]], ["linkerd", "rut-rps", "nginx", "envoy"])
        self.assertEqual({x["engine"] for x in cells if x["body"] == "4k"},
                         {"linkerd", "rut-rps", "nginx", "envoy"})
        self.assertEqual({x["engine"] for x in cells if x["body"] == "1m"},
                         {"linkerd", "rut-throughput", "nginx", "envoy"})

    def test_resource_snapshot_requires_complete_unique_rows_and_successful_command(self):
        output = "101 120 80\n102 320 240\n"
        parsed = run_matrix.parse_smaps_rollup([101, 102, 101], output, 0)
        self.assertTrue(parsed["complete"])
        self.assertEqual(parsed["rows"], [
            {"pid": 101, "rss_kb": 120, "pss_kb": 80},
            {"pid": 102, "rss_kb": 320, "pss_kb": 240},
        ])
        self.assertFalse(run_matrix.parse_smaps_rollup([101, 102], output, 1)["complete"])
        self.assertFalse(run_matrix.parse_smaps_rollup([101, 102], "101 120 80\n", 0)["complete"])
        self.assertFalse(run_matrix.parse_smaps_rollup([101], "101 120 80\n101 120 80\n", 0)["complete"])
        self.assertFalse(run_matrix.parse_smaps_rollup([101], "101 missing\n", 0)["complete"])

    def test_maps_parser_reports_only_mapped_shared_objects(self):
        maps = ("7f000000-7f001000 r-xp 00000000 08:01 10 /usr/lib/libc.so.6\n"
                "7f001000-7f002000 rw-p 00000000 00:00 0 [heap]\n"
                "7f002000-7f003000 r-xp 00000000 08:01 11 /opt/lib with space/libx.so.1\n")
        self.assertEqual(run_matrix.mapped_shared_object_paths(maps),
                         ["/opt/lib with space/libx.so.1", "/usr/lib/libc.so.6"])

    def test_summary_rejects_errors_and_computes_rps(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            sample = out / "samples" / "one"
            sample.mkdir(parents=True)
            (sample / "returncode.txt").write_text("0\n")
            (sample / "wrk.log").write_text("METRICS 100 2000000 10 20 30 0 0 0 0 0\n")
            result = summarize.sample_metrics(out, "samples/one")
            self.assertEqual(result["rps"], 50)
            self.assertEqual(result["p99_us"], 30)
            (sample / "wrk.log").write_text("METRICS 100 2000000 10 20 30 0 0 0 1 0\n")
            with self.assertRaises(ValueError):
                summarize.sample_metrics(out, "samples/one")

    def test_resource_summary_keeps_proxy_and_origin_separate_and_nulls_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            cell = out / "samples" / "4k" / "one"
            cell.mkdir(parents=True)
            (cell / "valid.txt").write_text("valid\n")
            row = {"validation_path": "samples/4k/one/valid.txt"}
            empty = summarize.resource_metrics(out, row)
            self.assertIsNone(empty["proxy_idle_pss_kb"])
            proxy_idle = {"complete": True, "rss_kb": 100, "pss_kb": 80}
            origin_idle = {"complete": True, "rss_kb": 300, "pss_kb": 240}
            proxy_load = {"complete": True, "rss_kb": 120, "pss_kb": 90}
            origin_load = {"complete": True, "rss_kb": 320, "pss_kb": 250}
            summary = {
                "frontend_executables": [{"path": "/rut", "size_bytes": 123, "sha256": "abc"}],
                "mapped_shared_objects": {
                    "proxy": {"files": [{"path": "/lib/libc.so.6", "size_bytes": 1000, "sha256": "def"}],
                              "complete": True, "total_bytes": 1000},
                    "origin": {"files": [], "complete": True, "total_bytes": 0},
                },
                "idle": {"proxy": proxy_idle, "origin": origin_idle},
                "after_warmup": {"proxy": proxy_idle, "origin": origin_idle},
                "under_load_samples": [{"snapshot_valid": True, "proxy": proxy_load, "origin": origin_load}],
                "sampling_complete": False,
            }
            (cell / "resources-summary.json").write_text(json.dumps(summary))
            found = summarize.resource_metrics(out, row)
            self.assertEqual(found["proxy_executable_bytes"], 123)
            self.assertEqual(found["proxy_dynamic_dependency_bytes"], 1000)
            self.assertEqual(found["proxy_under_load_pss_kb"], 90)
            self.assertEqual(found["origin_under_load_pss_kb"], 250)
            self.assertFalse(found["resource_sampling_complete"])

    def test_client_image_has_no_private_default(self):
        source = Path(prepare.__file__).read_text()
        self.assertNotIn("rut-watchdog-wrk:attempt89", source)
        self.assertIn('p.add_argument("--client-image", required=True', source)
        dockerfile = Path(__file__).with_name("Dockerfile.client").read_text()
        self.assertIn("curl", dockerfile)
        self.assertIn("/usr/local/bin/wrk", dockerfile)


if __name__ == "__main__":
    unittest.main()
