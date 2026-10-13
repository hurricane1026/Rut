import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import common
import prepare
import run_client
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

    def test_cpu_affinity_lists_compare_as_sets_and_canonicalize_adjacent_helpers(self):
        self.assertEqual(common.cpu_set("3,4,8,9"), common.cpu_set("3-4,8-9"))
        self.assertNotEqual(common.cpu_set("3-4,8-9"), common.cpu_set("3-4,8-10"))
        self.assertEqual(prepare.cpus("3-4,8-9", 4, "--origin-cpus"), [3, 4, 8, 9])
        self.assertEqual(common.canonical_cpu_list({6, 7, 14}), "6-7,14")
        helper_script = prepare.helper_verify_script([6, 7, 14], False)
        self.assertIn("expected='6-7,14'", helper_script)
        self.assertIn('"$allowed" != "$expected"', helper_script)

    def test_image_reference_normalization_handles_docker_and_kubernetes_names(self):
        self.assertTrue(common.image_reference_matches("nginx@sha256:abc", "docker.io/library/nginx@sha256:abc"))
        self.assertTrue(common.image_reference_matches("client:local", "docker.io/library/client:local"))
        self.assertFalse(common.image_reference_matches("client:local", "client:other"))
        self.assertTrue(run_matrix.image_identity_matches(
            "docker-pullable://docker.io/library/nginx@sha256:manifest",
            {"worker_id": "sha256:config", "worker_repo_digests": ["nginx@sha256:manifest"]}))

    def test_prepare_resolves_worker_images_through_cri_with_mocked_inventory(self):
        identities = {
            "nginx": {"reference": "nginx@sha256:abc"},
            "client": {"reference": "client:local", "docker_id": "sha256:client"},
        }
        inventory = {"images": [
            {"id": "sha256:nginx", "repoTags": [], "repoDigests": ["docker.io/library/nginx@sha256:abc"]},
            {"id": "sha256:client", "repoTags": ["docker.io/library/client:local"], "repoDigests": []},
        ]}
        with mock.patch("prepare.run", return_value=json.dumps(inventory)) as run:
            result = prepare.worker_image_identities("docker", "worker", identities)
        self.assertEqual(result["nginx"]["worker_id"], "sha256:nginx")
        self.assertEqual(result["client"]["worker_id"], "sha256:client")
        self.assertEqual(run.call_args.args[0], ["docker", "exec", "worker", "crictl", "images", "-o", "json"])

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
                # prepare.py stores origin CPUs in canonical range form.
                "cpus": {"proxy": 2, "origin": "3-4,8-9", "client": "5,7", "helpers": "6,14"},
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
            native_origin = prepare.nginx_origin(
                8081, sorted(common.cpu_set(config["cpus"]["origin"])), "/data/proxy")
            self.assertIn("worker_cpu_affinity", native_origin)
            for cpu in (3, 4, 8, 9):
                self.assertIn(prepare.mask(cpu), native_origin)
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

    def test_matrix_repeat_count_controls_cells_and_reuses_balanced_interleave(self):
        once = run_matrix.plan(1)
        four = run_matrix.plan(4)
        self.assertEqual(len(once), 16)
        self.assertEqual(len(four), 64)
        self.assertEqual({cell["rep"] for cell in four}, {1, 2, 3, 4})
        self.assertEqual([cell["engine"] for cell in four[:4]], ["linkerd", "rut-rps", "nginx", "envoy"])
        with self.assertRaises(ValueError):
            run_matrix.plan(0)

    def test_run_id_matches_kubernetes_name_and_label_rules(self):
        for accepted in ("a", "run-123", "proxy-bench-9"):
            self.assertTrue(prepare.valid_run_id(accepted))
        for rejected in ("ABC", "测试", "-start", "end-", "two--ok?", "a" * 21):
            self.assertFalse(prepare.valid_run_id(rejected))

    def test_prepare_defines_default_tool_commands_in_benchmark_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkpoint = root / "checkpoint"
            checkpoint.mkdir()
            for name in ("rps", "throughput", "runtime-libs", "runtime-tools"):
                (checkpoint / name).mkdir()
            for directory in ("rps", "throughput"):
                for filename in ("rut", "rut-compile"):
                    (checkpoint / directory / filename).write_bytes(filename.encode())
            for filename in ("clang", "ld"):
                (checkpoint / "runtime-tools" / filename).write_bytes(filename.encode())
            output = root / "output"
            argv = ["prepare.py", "--checkpoint", str(checkpoint), "--output", str(output),
                    "--kubeconfig", str(checkpoint / "kubeconfig"), "--cluster-name", "bench",
                    "--worker-container", "bench-worker", "--worker-node", "bench-worker",
                    "--rut-rps-dir", str(checkpoint / "rps"), "--rut-throughput-dir", str(checkpoint / "throughput"),
                    "--runtime-libs", str(checkpoint / "runtime-libs"),
                    "--clang", str(checkpoint / "runtime-tools" / "clang"), "--ld", str(checkpoint / "runtime-tools" / "ld"),
                    "--client-image", "client:test", "--helper-cpus", "15,16"]
            docker_image = {"Id": "sha256:" + "a" * 64, "RepoDigests": []}
            with mock.patch("sys.argv", argv), mock.patch("prepare.run", return_value=json.dumps(docker_image)):
                self.assertEqual(prepare.main(), 0)
            config = json.loads((output / "benchmark.json").read_text())
            self.assertEqual(config["tools"], {"docker": "docker", "kubectl": "kubectl", "linkerd": "linkerd"})
            self.assertEqual(config["cpus"]["helpers"], "15-16")
            self.assertEqual(config["image_identities"]["client"]["docker_id"], docker_image["Id"])
            self.assertEqual(set(config["input_snapshot"]), {"client_dir", "rut_config_dir", "runtime_libs", "clang", "ld"})

    def test_input_snapshot_detects_contents_membership_renames_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = root / "inputs"
            tree.mkdir()
            (tree / "a.txt").write_text("one")
            baseline = common.snapshot_inputs({"bundle": tree})
            (tree / "a.txt").write_text("two")
            self.assertNotEqual(common.snapshot_inputs({"bundle": tree}), baseline)
            (tree / "a.txt").write_text("one")
            (tree / "b.txt").write_text("new")
            self.assertNotEqual(common.snapshot_inputs({"bundle": tree}), baseline)
            (tree / "b.txt").unlink()
            (tree / "a.txt").rename(tree / "renamed.txt")
            self.assertNotEqual(common.snapshot_inputs({"bundle": tree}), baseline)
            (tree / "renamed.txt").unlink()
            (tree / "link").symlink_to(root / "outside")
            with self.assertRaisesRegex(ValueError, "symlink"):
                common.snapshot_inputs({"bundle": tree})

    def test_provenance_check_detects_image_retag_and_worker_image_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = root / "inputs"
            inputs.mkdir()
            (inputs / "request.lua").write_text("return true")
            host_id = "sha256:" + "a" * 64
            worker_id = "sha256:" + "b" * 64
            config = {
                "input_snapshot": common.snapshot_inputs({"client_dir": inputs}),
                "tools": {"docker": "docker"}, "worker_container": "bench-worker",
                "image_identities": {"client": {"reference": "client:local", "docker_id": host_id,
                                                    "worker_id": worker_id}},
            }
            inventory = {"images": [{"id": worker_id, "repoTags": ["client:local"], "repoDigests": []}]}
            with mock.patch("run_matrix.invoke", side_effect=[
                    subprocess.CompletedProcess([], 0, host_id + "\n", ""),
                    subprocess.CompletedProcess([], 0, json.dumps(inventory), "")]):
                run_matrix.verify_provenance(config)
            (inputs / "request.lua").write_text("changed")
            with mock.patch("run_matrix.invoke") as invoke:
                with self.assertRaisesRegex(RuntimeError, "mounted benchmark inputs changed"):
                    run_matrix.verify_provenance(config)
                invoke.assert_not_called()
            (inputs / "request.lua").write_text("return true")
            with mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess([], 0, "sha256:retagged\n", "")):
                with self.assertRaisesRegex(RuntimeError, "Docker image identity changed"):
                    run_matrix.verify_provenance(config)
            inventory["images"][0]["id"] = "sha256:changed"
            with mock.patch("run_matrix.invoke", side_effect=[
                    subprocess.CompletedProcess([], 0, host_id + "\n", ""),
                    subprocess.CompletedProcess([], 0, json.dumps(inventory), "")]):
                with self.assertRaisesRegex(RuntimeError, "kind worker image identity changed"):
                    run_matrix.verify_provenance(config)

    def test_summary_rejects_sample_from_different_input_or_image_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            validation = output / "samples" / "one" / "valid.txt"
            validation.parent.mkdir(parents=True)
            validation.write_text("valid\n")
            row = {"validation_path": str(validation.relative_to(output))}
            config = {"images": {"client": "client:local"},
                      "image_identities": {"client": {"docker_id": "sha256:client", "worker_id": "sha256:node"}},
                      "input_snapshot": {"client_dir": {"entries": {"request.lua": {"sha256": "abc"}}}}}
            fingerprint = common.provenance_fingerprint(config)
            (validation.parent / "cell.json").write_text(json.dumps({"provenance_fingerprint": fingerprint}))
            summarize.validate_sample_provenance(output, row, fingerprint)
            changed = common.provenance_fingerprint({**config, "images": {"client": "client:new"}})
            with self.assertRaisesRegex(ValueError, "provenance does not match"):
                summarize.validate_sample_provenance(output, row, changed)

    def test_run_rechecks_every_recorded_artifact_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rut"
            path.write_bytes(b"original")
            config = {"artifacts": {"rut": {"path": str(path), "sha256": common.sha256(path)}}}
            run_matrix.verify_artifacts(config)
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                run_matrix.verify_artifacts(config)

    def test_prepared_payload_verification_detects_mutation_and_truncation_in_both_mount_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkpoint = root / "checkpoint"
            payload_dir = checkpoint / "payloads" / "4k"
            payload_dir.mkdir(parents=True)
            content = b"prepared-payload"
            for filename in ("proxy", "body.bin"):
                (payload_dir / filename).write_bytes(content)
            output = root / "output"
            output.mkdir()
            metadata = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            (output / "payloads.json").write_text(json.dumps({"4k": metadata}))
            config = {"output": str(output), "checkpoint": str(checkpoint), "bodies": {"4k": len(content)}}
            run_matrix.verify_payloads(config)
            for filename in ("proxy", "body.bin"):
                path = payload_dir / filename
                path.write_bytes(b"modified-payload")
                with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                    run_matrix.verify_payloads(config)
                path.write_bytes(content[:-1])
                with self.assertRaisesRegex(RuntimeError, "size mismatch"):
                    run_matrix.verify_payloads(config)
                path.write_bytes(content)
            run_matrix.verify_payloads(config)

    def test_measurement_start_stamp_follows_delayed_docker_start_and_running_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            stamp = Path(tmp) / "measurement-start-monotonic.txt"
            state = [subprocess.CompletedProcess([], 0, "", ""),
                     subprocess.CompletedProcess([], 0, "false\n", ""),
                     subprocess.CompletedProcess([], 0, "true\n", "")]
            with mock.patch("run_client.subprocess.run", side_effect=state) as docker_run, \
                    mock.patch("run_client.time.sleep"), \
                    mock.patch("run_client.time.monotonic", side_effect=[100.0, 100.1, 100.3, 100.8]):
                run_client.start_and_stamp("docker", "wrk-container", stamp)
            self.assertEqual(stamp.read_text(), "100.800000000\n")
            self.assertEqual(docker_run.call_args_list[0].args[0], ["docker", "start", "wrk-container"])
            self.assertEqual(docker_run.call_args_list[1].args[0],
                             ["docker", "inspect", "--format", "{{.State.Running}}", "wrk-container"])
            self.assertEqual(docker_run.call_args_list[2].args[0],
                             ["docker", "inspect", "--format", "{{.State.Running}}", "wrk-container"])

    def test_frontend_readiness_retries_probe_timeouts_and_connection_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            matrix = run_matrix.Matrix({"output": tmp, "tools": {"docker": "docker", "kubectl": "kubectl", "linkerd": "linkerd"},
                                        "kubeconfig": "", "worker_container": "worker",
                                        "cpus": {"client": "5,7"}, "images": {"client": "client:test"}})
            success = subprocess.CompletedProcess([], 0, "", "")
            with mock.patch("run_matrix.time.monotonic", return_value=0), \
                    mock.patch("run_matrix.time.sleep") as sleep, \
                    mock.patch("run_matrix.invoke", side_effect=[subprocess.TimeoutExpired("curl", 5),
                                                                    subprocess.CompletedProcess([], 7, "", "refused"),
                                                                    success]) as invoke:
                matrix.wait_frontend("10.0.0.2")
            self.assertEqual(invoke.call_count, 3)
            self.assertEqual(sleep.call_count, 2)

    def test_frontend_readiness_fails_after_bounded_retry_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            matrix = run_matrix.Matrix({"output": tmp, "tools": {"docker": "docker", "kubectl": "kubectl", "linkerd": "linkerd"},
                                        "kubeconfig": "", "worker_container": "worker",
                                        "cpus": {"client": "5,7"}, "images": {"client": "client:test"}})
            with mock.patch("run_matrix.time.monotonic", side_effect=[0, 0, 181]), \
                    mock.patch("run_matrix.time.sleep"), \
                    mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess([], 7, "", "refused")) as invoke:
                with self.assertRaisesRegex(RuntimeError, "did not become ready"):
                    matrix.wait_frontend("10.0.0.2")
            self.assertEqual(invoke.call_count, 1)

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
