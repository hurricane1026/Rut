import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
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

    def test_prepare_requires_matching_client_config_ids_not_repo_digests(self):
        host_id = "sha256:" + "a" * 64
        worker_id = " SHA256:" + "A" * 64 + " "
        identities = {"client": {"reference": "client:local", "docker_id": host_id,
                                  "repo_digests": ["client@sha256:host-manifest"]}}
        inventory = {"images": [{"id": worker_id, "repoTags": ["client:local"],
                                  "repoDigests": ["client@sha256:different-manifest"]}]}
        with mock.patch("prepare.run", return_value=json.dumps(inventory)):
            resolved = prepare.resolve_worker_image_identities("docker", "worker", identities)
        self.assertEqual(resolved["client"]["worker_id"], worker_id)

        inventory["images"][0]["id"] = "sha256:" + "b" * 64
        with mock.patch("prepare.run", return_value=json.dumps(inventory)):
            with self.assertRaisesRegex(RuntimeError, "config IDs differ"):
                prepare.resolve_worker_image_identities("docker", "worker", identities)
        for missing in ({"docker_id": "", "worker_id": "sha256:x"},
                        {"docker_id": "sha256:x", "worker_id": None}):
            with self.subTest(missing=missing), self.assertRaisesRegex(RuntimeError, "identity missing"):
                common.verify_client_image_config_identity(missing)

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
            (binaries / "rut").write_bytes(b"runtime has no embedded compiler path")
            (binaries / "rut-compile").write_bytes(b"compiler\0/usr/bin/clang\0/usr/bin/\0")
            config = {
                "run_id": "test123", "checkpoint": tmp, "node_mount": "/benchmark",
                "worker_node": "bench-worker", "namespace": "bench",
                "selector": {"key": "benchmark-role", "value": "worker"},
                "configmaps": {"native": "pb-test-native", "linkerd": "pb-test-linkerd"},
                "images": {"nginx": "nginx@sha256:abc", "envoy": "envoy@sha256:def", "client": "client:test"},
                # prepare.py stores origin CPUs in canonical range form.
                "cpus": {"proxy": 2, "origin": "3-4,8-9", "client": "5,7", "helpers": "6,14"},
                "native_linker_path": "/opt/llvm/bin/clang-22", "native_linker_dir": "/opt/llvm/bin/",
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
            mounts = {item["name"]: item["mountPath"] for item in frontend["volumeMounts"]}
            self.assertEqual(mounts["runtime-clang"], "/opt/llvm/bin/clang-22")
            self.assertEqual(mounts["runtime-ld"], "/opt/llvm/bin/ld")
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
                    data = (filename.encode() if filename == "rut" else
                            b"compiler\0/usr/bin/clang\0/usr/bin/\0")
                    path = checkpoint / directory / filename
                    path.write_bytes(data)
                    path.chmod(0o755)
            for filename in ("clang", "ld"):
                path = checkpoint / "runtime-tools" / filename
                path.write_bytes(filename.encode())
                path.chmod(0o755)
            output = root / "output"
            argv = ["prepare.py", "--checkpoint", str(checkpoint), "--output", str(output),
                    "--kubeconfig", str(checkpoint / "kubeconfig"), "--cluster-name", "bench",
                    "--worker-container", "bench-worker", "--worker-node", "bench-worker",
                    "--rut-rps-dir", str(checkpoint / "rps"), "--rut-throughput-dir", str(checkpoint / "throughput"),
                    "--runtime-libs", str(checkpoint / "runtime-libs"),
                    "--clang", str(checkpoint / "runtime-tools" / "clang"), "--ld", str(checkpoint / "runtime-tools" / "ld"),
                    "--client-image", "client:test", "--helper-cpus", "15,16"]
            (checkpoint / "rps" / "rut").chmod(0o644)
            with mock.patch("sys.argv", argv), mock.patch("prepare.run") as run:
                with self.assertRaises(SystemExit):
                    prepare.main()
            run.assert_not_called()
            (checkpoint / "rps" / "rut").chmod(0o755)
            docker_image = {"Id": "sha256:" + "a" * 64, "RepoDigests": []}
            with mock.patch("sys.argv", argv), mock.patch("prepare.run", return_value=json.dumps(docker_image)):
                self.assertEqual(prepare.main(), 0)
            config = json.loads((output / "benchmark.json").read_text())
            self.assertEqual(config["tools"], {"docker": "docker", "kubectl": "kubectl", "linkerd": "linkerd"})
            self.assertEqual(config["cpus"]["helpers"], "15-16")
            self.assertEqual(config["image_identities"]["client"]["docker_id"], docker_image["Id"])
            self.assertEqual(set(config["input_snapshot"]), {"client_dir", "rut_config_dir", "runtime_libs", "clang", "ld"})
            self.assertEqual(config["payloads"]["4k"], json.loads((output / "payloads.json").read_text())["4k"])
            self.assertEqual(json.loads((output / "native-configmap.json").read_text())["immutable"], True)

    def test_prepare_checks_only_compiler_nul_strings_and_rejects_mismatched_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, compiler = Path(tmp) / "rut", Path(tmp) / "rut-compile"
            runtime.write_bytes(b"no linker strings in rut")
            compiler.write_bytes(b"/opt/llvm/bin/clang-22\0/opt/llvm/bin/\0")
            self.assertTrue(prepare.linker_paths_match(compiler, "/opt/llvm/bin/clang-22", "/opt/llvm/bin/"))
            self.assertEqual(prepare.embedded_clang_path(compiler), "/opt/llvm/bin/clang-22")
            self.assertFalse(prepare.linker_paths_match(compiler, "/usr/bin/clang", "/usr/bin/"))
            self.assertFalse(prepare.linker_paths_match(compiler, "/opt/llvm/bin/clang-22", "/usr/bin/"))
            self.assertFalse(prepare.linker_paths_match(compiler, "/opt/llvm/bin/clang", "/opt/llvm/bin/"))

    def test_prepare_requires_execute_permission_for_every_benchmark_program(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [root / "rut-rps" / "rut", root / "rut-rps" / "rut-compile",
                     root / "rut-throughput" / "rut", root / "rut-throughput" / "rut-compile",
                     root / "clang", root / "ld"]
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("executable placeholder")
                path.chmod(0o755)
                prepare.require_executable(path, path.name)
                path.chmod(0o644)
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "executable file"):
                    prepare.require_executable(path, path.name)
                path.chmod(0o755)

    def test_origin_affinity_preserves_one_cpu_per_nginx_worker(self):
        rows = [{"pid": "100", "allowed": "3-4,8-9"},
                {"pid": "101", "allowed": "3"}, {"pid": "102", "allowed": "4"},
                {"pid": "103", "allowed": "8"}, {"pid": "104", "allowed": "9"}]
        run_matrix.verify_origin_affinity(100, "3-4,8-9", rows)
        for changed in (
                [{**row, "allowed": "3-4,8-9"} if row["pid"] == "101" else row for row in rows],
                rows[:-1],
                [{**row, "allowed": "10"} if row["pid"] == "104" else row for row in rows]):
            with self.assertRaises(RuntimeError):
                run_matrix.verify_origin_affinity(100, "3-4,8-9", changed)

    def test_interrupted_cell_runs_pod_cleanup_and_reraises_keyboard_interrupt(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = {"output": tmp, "tools": {"kubectl": "kubectl", "docker": "docker", "linkerd": "linkerd"},
                      "kubeconfig": "/tmp/kube", "namespace": "bench", "run_id": "run123"}
            matrix = run_matrix.Matrix(config)
            matrix.samples.mkdir(parents=True)
            interruption = KeyboardInterrupt()
            cell = {"body": "4k", "engine": "linkerd", "rep": 1}
            with mock.patch.object(matrix, "run_cell", side_effect=interruption), \
                    mock.patch.object(matrix, "kube", return_value=subprocess.CompletedProcess([], 0, "deleted\n", "")) as kube:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    run_matrix.run_cell_with_cleanup(matrix, config, cell)
            self.assertIs(caught.exception, interruption)
            self.assertEqual(kube.call_args.args[:3], ("delete", "pod", "proxybench-run123-4k-1-linkerd"))
            self.assertIn("--ignore-not-found=true", kube.call_args.args)

    def test_runtime_library_bundle_must_be_a_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            libraries = root / "libs"
            libraries.mkdir()
            prepare.validate_runtime_libs(libraries)
            file_path = root / "libs-file"
            file_path.write_text("not a directory")
            with self.assertRaisesRegex(ValueError, "runtime-libs must be a directory"):
                prepare.validate_runtime_libs(file_path)

    def test_compiler_string_scan_ignores_non_ascii_binary_chunks(self):
        real_binary = Path(sys.executable).read_bytes()
        self.assertTrue(real_binary)
        prepare.nul_strings(Path(sys.executable))
        with tempfile.TemporaryDirectory() as tmp:
            compiler = Path(tmp) / "rut-compile"
            compiler.write_bytes(b"\x7fELF\x00\xff\xfe machine code\x00/opt/llvm/bin/clang-22\x00/opt/llvm/bin/\x00")
            self.assertEqual(prepare.embedded_clang_path(compiler), "/opt/llvm/bin/clang-22")
            self.assertTrue(prepare.linker_paths_match(
                compiler, "/opt/llvm/bin/clang-22", "/opt/llvm/bin/"))

    def test_prepare_run_forwards_default_and_extended_subprocess_timeouts(self):
        completed = subprocess.CompletedProcess([], 0, "ok", "")
        with mock.patch("prepare.subprocess.run", return_value=completed) as process_run:
            self.assertEqual(prepare.run(["probe"]), "ok")
            self.assertEqual(process_run.call_args.kwargs["timeout"], 90)
            self.assertEqual(prepare.run(["probe"], timeout=190), "ok")
            self.assertEqual(process_run.call_args.kwargs["timeout"], 190)

    def test_configmap_immutable_uses_top_level_api_field(self):
        config = {"configmaps": {"native": "pb-run-native"}, "tools": {"kubectl": "kubectl"},
                  "kubeconfig": "/tmp/kube", "namespace": "bench",
                  "configmap_identities": {"native": {"uid": "uid1", "data": {"x": "one"}}}}
        api_object = {"metadata": {"uid": "uid1"}, "data": {"x": "one"}, "immutable": True}
        with mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess([], 0, json.dumps(api_object), "")):
            run_matrix.verify_configmaps(config)
        api_object["immutable"] = False
        with mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess([], 0, json.dumps(api_object), "")):
            with self.assertRaisesRegex(RuntimeError, "ConfigMap identity or data changed"):
                run_matrix.verify_configmaps(config)
        self.assertEqual(prepare.applied_configmap_identity(
            {"metadata": {"uid": "uid2"}, "data": {"x": "one"}, "immutable": True}, {"x": "one"}),
            {"uid": "uid2", "data": {"x": "one"}})
        with self.assertRaisesRegex(RuntimeError, "not immutable"):
            prepare.applied_configmap_identity(
                {"metadata": {"uid": "uid2", "immutable": True}, "data": {"x": "one"}}, {"x": "one"})

    def test_configmap_apply_failure_cleans_only_resources_confirmed_owned_by_run(self):
        run_id = "run123"
        attempt_id = "attempt-current"
        namespace = "bench"
        manifests = {}
        paths = {}
        for name in ("native", "linkerd"):
            manifests[name] = {"metadata": {"name": f"pb-{run_id}-{name}", "namespace": namespace,
                "labels": {"app.kubernetes.io/managed-by": "rut-proxy-benchmark",
                           "benchmark-run-id": run_id, "benchmark-create-attempt": attempt_id}},
                "data": {"config": name}}
            paths[name] = Path(f"/{name}.json")
        owned = {"metadata": {**manifests["native"]["metadata"], "uid": "native-uid"},
                 "data": manifests["native"]["data"], "immutable": True}
        unrelated = {"metadata": {**manifests["linkerd"]["metadata"], "uid": "other-uid",
                                   "labels": {"app.kubernetes.io/managed-by": "rut-proxy-benchmark",
                                               "benchmark-run-id": run_id,
                                               "benchmark-create-attempt": "attempt-old"}},
                     "data": manifests["linkerd"]["data"], "immutable": True}
        with mock.patch("prepare.run", side_effect=[
                RuntimeError("create response lost after partial success"),
                json.dumps(owned), "", json.dumps(unrelated)]
                ) as run:
            with self.assertRaisesRegex(RuntimeError, "create response lost"):
                prepare.apply_configmaps(["kubectl"], namespace, run_id, attempt_id, manifests, paths)
        deletes = [call.args[0] for call in run.call_args_list if "delete" in call.args[0]]
        self.assertEqual(deletes, [["kubectl", "delete", "configmap", "pb-run123-native", "-n", namespace,
                                    "--ignore-not-found=true", "--wait=true"]])

    def test_configmap_identity_failure_rolls_back_and_preserves_original_error(self):
        run_id = "run456"
        attempt_id = "attempt-current"
        namespace = "bench"
        manifests = {}
        paths = {}
        for name in ("native", "linkerd"):
            manifests[name] = {"metadata": {"name": f"pb-{run_id}-{name}", "namespace": namespace,
                "labels": {"app.kubernetes.io/managed-by": "rut-proxy-benchmark",
                           "benchmark-run-id": run_id, "benchmark-create-attempt": attempt_id}},
                "data": {"config": name}}
            paths[name] = Path(f"/{name}.json")
        mismatched = {"metadata": {**manifests["native"]["metadata"], "uid": "native-uid"},
                      "data": {"config": "stale"}, "immutable": True}
        with mock.patch("prepare.run", side_effect=["created", json.dumps(mismatched),
                json.dumps(mismatched), RuntimeError("delete unavailable"), RuntimeError("not found")]) as run:
            with self.assertRaisesRegex(RuntimeError, "data differs"):
                prepare.apply_configmaps(["kubectl"], namespace, run_id, attempt_id, manifests, paths)
        self.assertTrue(any("delete" in call.args[0] for call in run.call_args_list))

    def test_linkerd_probe_waits_for_pull_records_identity_and_deletes_probe(self):
        pod = {"spec": {"containers": [], "initContainers": [{"name": "linkerd-proxy", "image": "proxy:edge",
                                                                  "restartPolicy": "Always",
                                                                  "args": ["--log-level=error"],
                                                                  "env": [{"name": "A", "value": "B"}],
                                                                  "resources": {"requests": {"cpu": "1"}}}]},
               "status": {"initContainerStatuses": [{"name": "linkerd-proxy", "imageID": "containerd://sha256:cfg"}]}}
        inventory = {"images": [{"id": "sha256:cfg", "repoTags": ["proxy:edge"], "repoDigests": []}]}
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "probe.json"
            probe.write_text("{}")
            with mock.patch("prepare.run", side_effect=["", "", json.dumps(pod), json.dumps(inventory), ""]) as run:
                identity = prepare.discover_linkerd_proxy_identity(
                    ["kubectl", "--kubeconfig", "/kube"], "docker", "worker", probe, "probe", "bench")
        self.assertEqual(identity["identities"]["linkerd_proxy"]["worker_id"], "sha256:cfg")
        self.assertEqual(identity["injected_spec"]["initContainers"][0]["args"], ["--log-level=error"])
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn("wait", commands[1])
        self.assertIn("create", commands[0])
        self.assertEqual(commands[-1][3:6], ["delete", "pod", "probe"])
        self.assertEqual(run.call_args_list[1].kwargs["timeout"], 190)

    def test_linkerd_probe_deletes_pod_when_readiness_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "probe.json"
            probe.write_text("{}")
            with mock.patch("prepare.run", side_effect=["", RuntimeError("not ready"), ""]) as run:
                with self.assertRaisesRegex(RuntimeError, "not ready"):
                    prepare.discover_linkerd_proxy_identity(
                        ["kubectl"], "docker", "worker", probe, "probe", "bench")
        self.assertIn("delete", run.call_args_list[-1].args[0])

    def test_linkerd_probe_cleanup_attempts_delete_after_ambiguous_create_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "probe.json"
            probe.write_text("{}")
            create_timeout = subprocess.TimeoutExpired(["kubectl", "create"], 90)
            with mock.patch("prepare.run", side_effect=[create_timeout, ""]) as run:
                with self.assertRaises(subprocess.TimeoutExpired):
                    prepare.discover_linkerd_proxy_identity(
                        ["kubectl"], "docker", "worker", probe, "probe", "bench")
        cleanup = run.call_args_list[-1]
        self.assertIn("delete", cleanup.args[0])
        self.assertIn("--ignore-not-found=true", cleanup.args[0])
        self.assertEqual(cleanup.kwargs["timeout"], 90)

    def test_linkerd_probe_cleanup_failure_does_not_mask_create_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "probe.json"
            probe.write_text("{}")
            with mock.patch("prepare.run", side_effect=[RuntimeError("create timed out"), OSError("delete unavailable")]) as run:
                with self.assertRaisesRegex(RuntimeError, "create timed out"):
                    prepare.discover_linkerd_proxy_identity(
                        ["kubectl"], "docker", "worker", probe, "probe", "bench")
        self.assertIn("delete", run.call_args_list[-1].args[0])

    def test_linkerd_injected_proxy_image_is_taken_from_admitted_pod(self):
        admitted = {"spec": {"containers": [{"name": "origin", "image": "nginx@sha256:abc"}],
                             "initContainers": [{"name": "linkerd-proxy", "image": "cr.l5d.io/linkerd/proxy:edge",
                                                 "restartPolicy": "Always"}]}}
        self.assertEqual(prepare.injected_linkerd_proxy_image(admitted), "cr.l5d.io/linkerd/proxy:edge")
        with self.assertRaisesRegex(ValueError, "found 0"):
            prepare.injected_linkerd_proxy_image({"spec": {"containers": []}})
        duplicate = {"spec": {"containers": [{"name": "linkerd-proxy", "image": "one"}],
                              "initContainers": [{"name": "linkerd-proxy", "image": "two"}]}}
        with self.assertRaisesRegex(ValueError, "exactly one"):
            prepare.injected_linkerd_proxy_image(duplicate)

    def test_linkerd_probe_matches_benchmark_origin_injection_inputs(self):
        config = {"namespace": "bench", "run_id": "run1", "worker_node": "worker",
                  "node_mount": "/node", "cpus": {"proxy": 3, "origin": "4-5"},
                  "selector": {"key": "role", "value": "bench"},
                  "images": {"nginx": "nginx@sha256:abc"},
                  "configmaps": {"linkerd": "cfg"}}
        benchmark = common.pod_spec(config, "linkerd", "4k", "matrix")
        probe = prepare.linkerd_probe_spec("probe", "bench", "worker", config["images"]["nginx"])
        benchmark_origin = benchmark["spec"]["containers"][0]
        probe_app = probe["spec"]["containers"][0]
        self.assertEqual(probe["metadata"]["annotations"], benchmark["metadata"]["annotations"])
        self.assertEqual(probe_app["ports"], benchmark_origin["ports"])
        self.assertEqual(probe_app["imagePullPolicy"], benchmark_origin["imagePullPolicy"])
        self.assertEqual(probe_app["image"], benchmark_origin["image"])

    def test_linkerd_proxy_container_requires_prepared_image_identity(self):
        identities = {"linkerd_proxy": {"reference": "linkerd/proxy@sha256:abc", "worker_id": "sha256:cfg"}}
        identity = run_matrix.expected_container_identity("linkerd-proxy", "linkerd/proxy:edge", identities)
        self.assertIsNotNone(identity)
        run_matrix.verify_status_image_identity("linkerd-proxy", "linkerd/proxy:edge", "containerd://sha256:cfg", identities)
        with self.assertRaisesRegex(RuntimeError, "linkerd-proxy image identity changed"):
            run_matrix.verify_status_image_identity("linkerd-proxy", "linkerd/proxy:edge", "containerd://sha256:changed", identities)
        with self.assertRaisesRegex(RuntimeError, "identity missing"):
            run_matrix.verify_status_image_identity("linkerd-proxy", "", "containerd://sha256:cfg", {})

    def test_linkerd_injection_spec_binds_runtime_relevant_container_settings(self):
        pod = {"spec": {"containers": [
            {"name": "origin", "image": "nginx"},
            {"name": "linkerd-proxy", "image": "proxy", "args": ["--x"],
             "env": [{"name": "A", "value": "B"}], "resources": {"limits": {"cpu": "2"}},
             "securityContext": {"runAsUser": 1000}, "volumeMounts": [{"name": "x", "mountPath": "/x"}]},
        ], "initContainers": [{"name": "linkerd-init", "image": "init", "command": ["init"]}]}}
        normalized = common.normalized_linkerd_injection_spec(pod)
        self.assertEqual([item["name"] for item in normalized["containers"]], ["linkerd-proxy"])
        changed = json.loads(json.dumps(pod))
        changed["spec"]["containers"][1]["env"][0]["value"] = "C"
        self.assertNotEqual(normalized, common.normalized_linkerd_injection_spec(changed))
        base_config = {"images": {}, "linkerd_injected_spec": normalized}
        changed_config = {**base_config, "linkerd_injected_spec": common.normalized_linkerd_injection_spec(changed)}
        self.assertNotEqual(common.provenance_fingerprint(base_config),
                            common.provenance_fingerprint(changed_config))

    def test_service_account_mount_suffix_is_normalized_without_ignoring_other_mount_settings(self):
        def pod(suffix, mount_path="/var/run/secrets/kubernetes.io/serviceaccount"):
            return {"spec": {"containers": [{"name": "linkerd-proxy", "image": "proxy",
                "volumeMounts": [{"name": f"kube-api-access-{suffix}", "mountPath": mount_path,
                                  "readOnly": True}, {"name": "linkerd-config", "mountPath": "/etc/linkerd"}]}]}}
        left, right = pod("abc"), pod("xyz")
        left_normalized = common.normalized_linkerd_injection_spec(left)
        self.assertEqual(left_normalized, common.normalized_linkerd_injection_spec(right))
        self.assertEqual(left["spec"]["containers"][0]["volumeMounts"][0]["name"], "kube-api-access-abc")
        self.assertNotEqual(left_normalized, common.normalized_linkerd_injection_spec(pod("xyz", "/different")))
        changed_config = {"linkerd_injected_spec": common.normalized_linkerd_injection_spec(pod("xyz"))}
        changed_config["linkerd_injected_spec"]["containers"][0]["args"] = ["changed"]
        self.assertNotEqual(common.provenance_fingerprint({"linkerd_injected_spec": left_normalized}),
                            common.provenance_fingerprint(changed_config))

    def test_linkerd_injection_spec_binds_referenced_volume_definitions(self):
        def pod(token_suffix, audience="linkerd", medium="Memory", app_value="before"):
            return {"spec": {
                "containers": [
                    {"name": "origin", "volumeMounts": [{"name": "app-data", "mountPath": "/app"}]},
                    {"name": "linkerd-proxy", "volumeMounts": [
                        {"name": f"kube-api-access-{token_suffix}",
                         "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"},
                        {"name": "linkerd-identity", "mountPath": "/var/run/linkerd/identity"}]},
                ],
                "initContainers": [{"name": "linkerd-init", "volumeMounts": [
                    {"name": "linkerd-init-state", "mountPath": "/run/linkerd"}]}],
                "volumes": [
                    {"name": "kube-api-access-" + token_suffix,
                     "projected": {"sources": [{"serviceAccountToken": {
                         "audience": audience, "expirationSeconds": 86400}}]}},
                    {"name": "linkerd-identity", "emptyDir": {"medium": medium}},
                    {"name": "linkerd-init-state", "emptyDir": {}},
                    {"name": "app-data", "configMap": {"name": app_value}},
                ]}}
        baseline = common.normalized_linkerd_injection_spec(pod("random-a"))
        self.assertEqual(baseline, common.normalized_linkerd_injection_spec(pod("random-b")))
        self.assertEqual([volume["name"] for volume in baseline["volumes"]],
                         ["kube-api-access", "linkerd-identity", "linkerd-init-state"])
        for changed in (pod("random-c", audience="other"), pod("random-d", medium="")):
            self.assertNotEqual(baseline, common.normalized_linkerd_injection_spec(changed))
        self.assertEqual(baseline, common.normalized_linkerd_injection_spec(pod("random-e", app_value="changed")))

    def test_client_create_timeout_still_removes_deterministic_container_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "measurement"
            config = {"run_id": "run123", "image_identities": {"client": {"docker_id": "sha256:client"}},
                      "images": {"client": "client:tag"}, "cpus": {"client": "2,3"},
                      "concurrency": 4, "client_dir": "/benchmark",
                      "tools": {"docker": "docker"}, "worker_container": "worker"}
            with mock.patch("run_client.load_config", return_value=config), \
                    mock.patch("sys.argv", ["run_client.py", "--config", "unused", "--label", "4k-nginx-r1",
                                             "--pod-ip", "10.0.0.2", "--duration", "2s", "--lua", "warmup.lua",
                                             "--output", str(out)]), \
                    mock.patch("run_client.subprocess.run", side_effect=[
                        subprocess.TimeoutExpired(["docker", "create"], 30), OSError("daemon unavailable")]) as run:
                with self.assertRaises(subprocess.TimeoutExpired):
                    run_client.main()
            self.assertEqual(run.call_args_list[1].args[0], ["docker", "rm", "-f", "proxybench-run123-4k-nginx-r1"])

    def test_selected_config_is_frozen_for_both_client_phases(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            selected = Path(tmp) / "selected.json"
            config = {"output": str(output), "duration": "10s", "warmup": "2s",
                      "concurrency": 4, "kubeconfig": "/tmp/kube",
                      "tools": {"kubectl": "kubectl", "docker": "docker", "linkerd": "linkerd"}}
            selected.write_text(json.dumps(config))
            matrix = run_matrix.Matrix(config, selected)
            snapshot = matrix.freeze_client_config()
            selected.write_text(json.dumps({**config, "concurrency": 99}))
            self.assertEqual(json.loads(snapshot.read_text()), config)
            for kind in ("warmup", "measurement"):
                argv = matrix.client_argv(Path("run_client.py"), kind, "10.0.0.1", config["duration"], "x.lua", Path(tmp) / kind)
                self.assertEqual(argv[argv.index("--config") + 1], str(snapshot))
            self.assertEqual(json.loads(snapshot.read_text())["concurrency"], 4)

    def test_pod_runtime_validation_rejects_restart_and_replacement(self):
        status = {"name": "origin", "containerID": "containerd://abc", "imageID": "sha256:def", "restartCount": 0}
        pod = {"status": {"containerStatuses": [status]}}
        runtime = [{"name": "origin", "container_id": "abc", "image_id": "sha256:def", "restart_count": 0,
                    "pid": 5, "processes": [{"pid": 5, "name": "origin", "allowed": "2"}]}]
        run_matrix.verify_pod_runtime_stable(pod, json.loads(json.dumps(pod)), runtime)
        for field, value in (("restartCount", 1), ("containerID", "containerd://new"), ("imageID", "sha256:new")):
            changed = json.loads(json.dumps(pod))
            changed["status"]["containerStatuses"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "changed"):
                run_matrix.verify_pod_runtime_stable(pod, changed, runtime)

    def test_native_linkerd_proxy_init_container_is_identity_checked_and_inspected(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            pod = {"spec": {"nodeName": "worker", "containers": [{"name": "origin", "image": "nginx"}],
                            "initContainers": [{"name": "linkerd-proxy", "image": "proxy", "restartPolicy": "Always"}]},
                   "status": {
                       "containerStatuses": [{"name": "origin", "containerID": "containerd://origin-cid",
                                               "imageID": "sha256:nginx", "restartCount": 0}],
                       "initContainerStatuses": [{"name": "linkerd-proxy", "containerID": "containerd://proxy-cid",
                                                  "imageID": "sha256:proxy", "restartCount": 0}],
                   }}
            (output / "pod.json").write_text(json.dumps(pod))
            config = {"output": str(output), "worker_node": "worker", "worker_container": "worker-container",
                      "image_identities": {"origin": {"reference": "nginx", "worker_id": "sha256:nginx"},
                                           "linkerd_proxy": {"reference": "proxy", "worker_id": "sha256:proxy"}},
                      "linkerd_injected_spec": common.normalized_linkerd_injection_spec(pod),
                      "cpus": {"origin": "2", "proxy": 3},
                      "tools": {"kubectl": "kubectl", "docker": "docker", "linkerd": "linkerd"},
                      "kubeconfig": "/tmp/kube"}
            matrix = run_matrix.Matrix(config)
            pid_by_cid = {"origin-cid": 100, "proxy-cid": 200}
            def invoke(argv, **_kwargs):
                argv = [str(item) for item in argv]
                if "crictl" in argv:
                    cid = argv[-1]
                    result = json.dumps({"info": {"pid": pid_by_cid[cid]}})
                elif "cgroup" in argv[-1] and "/proc/" in argv[-1]:
                    pid = int(argv[-1].split("/")[2])
                    role = "origin" if pid == 100 else "proxy"
                    result = f"0::/{role}\n"
                elif argv[-1].endswith("cgroup.procs"):
                    result = "100\n" if "origin" in argv[-1] else "200\n"
                elif argv[-1].endswith("cpu.max"):
                    result = "max 100000\n"
                elif len(argv) > 1 and argv[-2] == "-c":
                    result = "100 origin 2\n" if "100" in argv[-1] else "200 linkerd-proxy 3\n"
                elif "readlink" in argv:
                    result = "/usr/bin/nginx\n"
                elif "stat" in argv:
                    result = "123\n"
                elif "sha256sum" in argv:
                    result = "digest  /proc/exe\n"
                elif argv[-1].endswith("/maps"):
                    result = ""
                else:
                    result = "pinned\n"
                return subprocess.CompletedProcess(argv, 0, result, "")
            with mock.patch("run_matrix.invoke", side_effect=invoke):
                pids = matrix.inspect_runtime("linkerd", output)
            records = json.loads((output / "container-runtime.json").read_text())
            self.assertEqual(pids, {"proxy": [200], "origin": [100]})
            self.assertEqual({row["name"] for row in records}, {"origin", "linkerd-proxy"})
            self.assertEqual(next(row for row in records if row["name"] == "linkerd-proxy")["pid"], 200)

    def test_live_runtime_validation_rejects_pid_or_affinity_change(self):
        config = {"output": "/tmp/out", "worker_container": "worker",
                  "tools": {"kubectl": "kubectl", "docker": "docker", "linkerd": "linkerd"},
                  "kubeconfig": "/tmp/kube"}
        matrix = run_matrix.Matrix(config)
        runtime = [{"name": "origin", "container_id": "abc", "pid": 5,
                    "processes": [{"pid": "5", "tid": 5, "name": "origin", "allowed": "2"}]}]
        outputs = [json.dumps({"info": {"pid": 5}}), "0::/foo\n", "5\n", "5 origin 2\n"]
        with mock.patch("run_matrix.invoke", side_effect=lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 0, outputs.pop(0), "")):
            matrix.verify_live_runtime(runtime)
        outputs = [json.dumps({"info": {"pid": 5}}), "0::/foo\n", "5\n", "5 origin 3\n"]
        with mock.patch("run_matrix.invoke", side_effect=lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 0, outputs.pop(0), "")):
            with self.assertRaisesRegex(RuntimeError, "affinity changed"):
                matrix.verify_live_runtime(runtime)

    def test_live_runtime_validation_preserves_duplicate_thread_multiplicity(self):
        config = {"output": "/tmp/out", "worker_container": "worker",
                  "tools": {"kubectl": "kubectl", "docker": "docker", "linkerd": "linkerd"},
                  "kubeconfig": "/tmp/kube"}
        matrix = run_matrix.Matrix(config)
        runtime = [{"name": "origin", "container_id": "abc", "pid": 5,
                    "processes": [{"pid": "5", "tid": 11, "name": "origin", "allowed": "2"},
                                  {"pid": "5", "tid": 12, "name": "origin", "allowed": "2"}]}]
        for observed in ("11 origin 2\n", "11 origin 2\n99 origin 2\n"):
            outputs = [json.dumps({"info": {"pid": 5}}), "0::/foo\n", "5\n", observed]
            with mock.patch("run_matrix.invoke", side_effect=lambda *_args, **_kwargs:
                            subprocess.CompletedProcess([], 0, outputs.pop(0), "")):
                with self.assertRaisesRegex(RuntimeError, "process/affinity changed"):
                    matrix.verify_live_runtime(runtime)

    def test_configmap_identity_verification_detects_recreate_and_data_change(self):
        config = {"configmaps": {"native": "pb-run-native"}, "tools": {"kubectl": "kubectl"},
                  "kubeconfig": "/tmp/kube", "namespace": "bench",
                  "configmap_identities": {"native": {"uid": "uid1", "data": {"x": "one"}}}}
        matching = {"metadata": {"uid": "uid1"}, "data": {"x": "one"}, "immutable": True}
        with mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess([], 0, json.dumps(matching), "")):
            run_matrix.verify_configmaps(config)
        for changed in ({"metadata": {"uid": "uid2"}, "data": {"x": "one"}, "immutable": True},
                        {"metadata": {"uid": "uid1"}, "data": {"x": "two"}, "immutable": True}):
            with mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess([], 0, json.dumps(changed), "")):
                with self.assertRaisesRegex(RuntimeError, "ConfigMap identity or data changed"):
                    run_matrix.verify_configmaps(config)

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
            config_dir = root / "config"
            libs = root / "libs"
            clang = root / "clang"
            ld = root / "ld"
            rps = root / "rps"
            throughput = root / "throughput"
            for directory in (config_dir, libs, rps, throughput):
                directory.mkdir()
            for path in (clang, ld):
                path.write_text(path.name)
            artifacts = {}
            for directory, name in ((rps, "rut_rps"), (rps, "rut_rps_compiler"),
                                    (throughput, "rut_throughput"), (throughput, "rut_throughput_compiler")):
                file_name = "rut-compile" if name.endswith("compiler") else "rut"
                path = directory / file_name
                path.write_text(name)
                artifacts[name] = {"path": str(path), "sha256": common.sha256(path)}
            host_id = "sha256:" + "a" * 64
            worker_id = host_id
            checkpoint = root / "checkpoint"
            checkpoint.mkdir()
            config = {
                "input_snapshot": common.snapshot_inputs({"client_dir": inputs, "rut_config_dir": config_dir,
                    "runtime_libs": libs, "clang": clang, "ld": ld}),
                "client_dir": str(inputs),
                "paths": {"rut_config_dir": str(config_dir), "runtime_libs": str(libs),
                          "clang": str(clang), "ld": str(ld), "rut_rps": str(rps),
                          "rut_throughput": str(throughput)},
                "artifacts": artifacts, "checkpoint": str(checkpoint), "node_mount": "/benchmark",
                "tools": {"docker": "docker"}, "worker_container": "bench-worker",
                "image_identities": {"client": {"reference": "client:local", "docker_id": host_id,
                                                    "worker_id": worker_id}},
            }
            inventory = {"images": [{"id": worker_id, "repoTags": ["client:local"], "repoDigests": []}]}
            worker = [{"Mounts": [{"Source": str(checkpoint), "Destination": "/benchmark"}]}]
            with mock.patch("run_matrix.invoke", side_effect=[
                    subprocess.CompletedProcess([], 0, json.dumps(worker), ""),
                    subprocess.CompletedProcess([], 0, host_id + "\n", ""),
                    subprocess.CompletedProcess([], 0, json.dumps(inventory), "")]):
                run_matrix.verify_provenance(config)
            split_worker_id = "sha256:" + "b" * 64
            config["image_identities"]["client"]["worker_id"] = split_worker_id
            inventory["images"][0]["id"] = split_worker_id
            with mock.patch("run_matrix.invoke", side_effect=[
                    subprocess.CompletedProcess([], 0, json.dumps(worker), ""),
                    subprocess.CompletedProcess([], 0, host_id + "\n", ""),
                    subprocess.CompletedProcess([], 0, json.dumps(inventory), "")]):
                with self.assertRaisesRegex(RuntimeError, "client Docker and kind worker image config IDs differ"):
                    run_matrix.verify_provenance(config)
            config["image_identities"]["client"]["worker_id"] = worker_id
            inventory["images"][0]["id"] = worker_id
            (inputs / "request.lua").write_text("changed")
            with mock.patch("run_matrix.invoke") as invoke:
                with self.assertRaisesRegex(RuntimeError, "mounted benchmark inputs changed"):
                    run_matrix.verify_provenance(config)
                invoke.assert_not_called()
            (inputs / "request.lua").write_text("return true")
            with mock.patch("run_matrix.invoke", side_effect=[
                    subprocess.CompletedProcess([], 0, json.dumps(worker), ""),
                    subprocess.CompletedProcess([], 0, "sha256:retagged\n", "")]):
                with self.assertRaisesRegex(RuntimeError, "Docker image identity changed"):
                    run_matrix.verify_provenance(config)
            inventory["images"][0]["id"] = "sha256:changed"
            with mock.patch("run_matrix.invoke", side_effect=[
                    subprocess.CompletedProcess([], 0, json.dumps(worker), ""),
                    subprocess.CompletedProcess([], 0, host_id + "\n", ""),
                    subprocess.CompletedProcess([], 0, json.dumps(inventory), "")]):
                with self.assertRaisesRegex(RuntimeError, "kind worker image identity changed"):
                    run_matrix.verify_provenance(config)

    def test_effective_runtime_paths_must_match_prepared_snapshot_and_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {}
            for key in ("client_dir", "rut_config_dir", "runtime_libs", "clang", "ld", "rut_rps", "rut_throughput"):
                path = root / key
                if key in ("clang", "ld"):
                    path.write_text(key)
                else:
                    path.mkdir()
                paths[key] = path
            artifacts = {}
            for binary_key, binary_name in (("rut_rps", "rut_rps"), ("rut_throughput", "rut_throughput")):
                for artifact_key, file_name in ((binary_name, "rut"), (f"{binary_name}_compiler", "rut-compile")):
                    file = paths[binary_key] / file_name
                    file.write_text(artifact_key)
                    artifacts[artifact_key] = {"path": str(file), "sha256": common.sha256(file)}
            config = {"client_dir": str(paths["client_dir"]),
                      "paths": {key: str(value) for key, value in paths.items() if key != "client_dir"},
                      "input_snapshot": common.snapshot_inputs({key: paths[key] for key in
                          ("client_dir", "rut_config_dir", "runtime_libs", "clang", "ld")}),
                      "artifacts": artifacts, "node_mount": "/benchmark"}
            run_matrix.verify_effective_paths(config)
            for mutation in (
                {**config, "client_dir": str(paths["rut_config_dir"])},
                {**config, "paths": {**config["paths"], "rut_config_dir": str(paths["client_dir"])}},
                {**config, "paths": {**config["paths"], "rut_rps": str(paths["rut_throughput"])}},
            ):
                with self.assertRaisesRegex(RuntimeError, "effective benchmark path"):
                    run_matrix.verify_effective_paths(mutation)
            for key, value in (("client_dir", str(paths["rut_config_dir"])),
                               ("paths", {**config["paths"], "rut_config_dir": "/other/config"}),
                               ("node_mount", "/other/mount")):
                self.assertNotEqual(common.provenance_fingerprint({**config, key: value}),
                                    common.provenance_fingerprint(config))

    def test_worker_node_mount_mapping_is_rechecked(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp)
            config = {"worker_container": "worker", "checkpoint": str(checkpoint),
                      "node_mount": "/benchmark"}
            worker = [{"Mounts": [{"Source": str(checkpoint), "Destination": "/benchmark"}]}]
            with mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(worker), "")) as invoke:
                run_matrix.verify_worker_mount(config, "docker")
            self.assertEqual(invoke.call_args.args[0], ["docker", "inspect", "worker"])
            config["node_mount"] = "/changed"
            with mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(worker), "")):
                with self.assertRaisesRegex(RuntimeError, "checkpoint mount differs"):
                    run_matrix.verify_worker_mount(config, "docker")

    def test_failed_cell_cleanup_attempts_unconditional_not_found_tolerant_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            (output / "samples").mkdir(parents=True)
            config = {"output": str(output), "tools": {"kubectl": "kubectl", "docker": "docker", "linkerd": "linkerd"},
                      "kubeconfig": "/tmp/kube", "namespace": "bench", "run_id": "run123"}
            matrix = run_matrix.Matrix(config)
            with mock.patch.object(matrix, "kube", return_value=subprocess.CompletedProcess([], 0, "deleted\n", "")) as kube:
                result = run_matrix.cleanup_failed_cell(matrix, config,
                    {"body": "4k", "engine": "nginx", "rep": 1}, RuntimeError("create timed out"))
            args = kube.call_args.args
            self.assertEqual(args[:3], ("delete", "pod", "proxybench-run123-4k-1-nginx"))
            self.assertIn("--ignore-not-found=true", args)
            self.assertFalse((output / "samples/4k/4k-nginx-r1/pod-create.txt").exists())
            self.assertEqual(result, "deleted\n")
            self.assertIn("create timed out", (output / "samples/last-failure.json").read_text())

    def test_client_drivers_receive_frozen_config_path_and_workload_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = {"output": str(Path(tmp) / "output"),
                  "tools": {"kubectl": "kubectl", "docker": "docker", "linkerd": "linkerd"},
                  "kubeconfig": "/tmp/kube"}
            matrix = run_matrix.Matrix(config, Path(tmp) / "selected.json")
            snapshot = matrix.freeze_client_config()
            for kind, duration, lua in (("warmup", "2s", "warmup.lua"),
                                        ("measurement", "10s", "request.lua")):
                argv = matrix.client_argv(Path("run_client.py"), f"cell-{kind}", "10.0.0.2",
                                          duration, lua, Path("results") / kind)
                self.assertEqual(argv[argv.index("--config") + 1], str(snapshot))
                self.assertEqual(argv[argv.index("--duration") + 1], duration)
                self.assertEqual(argv[argv.index("--lua") + 1], lua)

    def test_effective_runtime_paths_must_match_prepared_snapshot_and_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {}
            for key in ("client_dir", "rut_config_dir", "runtime_libs", "clang", "ld", "rut_rps", "rut_throughput"):
                path = root / key
                if key in ("clang", "ld"):
                    path.write_text(key)
                else:
                    path.mkdir()
                paths[key] = path
            artifacts = {}
            for binary_key, binary_name in (("rut_rps", "rut_rps"), ("rut_throughput", "rut_throughput")):
                for artifact_key, file_name in ((binary_name, "rut"), (f"{binary_name}_compiler", "rut-compile")):
                    file = paths[binary_key] / file_name
                    file.write_text(artifact_key)
                    artifacts[artifact_key] = {"path": str(file), "sha256": common.sha256(file)}
            config = {"client_dir": str(paths["client_dir"]),
                      "paths": {key: str(value) for key, value in paths.items() if key != "client_dir"},
                      "input_snapshot": common.snapshot_inputs({key: paths[key] for key in
                          ("client_dir", "rut_config_dir", "runtime_libs", "clang", "ld")}),
                      "artifacts": artifacts, "node_mount": "/benchmark"}
            run_matrix.verify_effective_paths(config)
            for mutation in (
                {**config, "client_dir": str(paths["rut_config_dir"])},
                {**config, "paths": {**config["paths"], "rut_config_dir": str(paths["client_dir"])}},
                {**config, "paths": {**config["paths"], "rut_rps": str(paths["rut_throughput"])}},
            ):
                with self.assertRaisesRegex(RuntimeError, "effective benchmark path"):
                    run_matrix.verify_effective_paths(mutation)
            for key, value in (("client_dir", str(paths["rut_config_dir"])),
                               ("paths", {**config["paths"], "rut_config_dir": "/other/config"}),
                               ("node_mount", "/other/mount")):
                self.assertNotEqual(common.provenance_fingerprint({**config, key: value}),
                                    common.provenance_fingerprint(config))

    def test_worker_node_mount_mapping_is_rechecked(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp)
            config = {"worker_container": "worker", "checkpoint": str(checkpoint),
                      "node_mount": "/benchmark"}
            worker = [{"Mounts": [{"Source": str(checkpoint), "Destination": "/benchmark"}]}]
            with mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(worker), "")) as invoke:
                run_matrix.verify_worker_mount(config, "docker")
            self.assertEqual(invoke.call_args.args[0], ["docker", "inspect", "worker"])
            config["node_mount"] = "/changed"
            with mock.patch("run_matrix.invoke", return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(worker), "")):
                with self.assertRaisesRegex(RuntimeError, "checkpoint mount differs"):
                    run_matrix.verify_worker_mount(config, "docker")

    def test_failed_cell_cleanup_attempts_unconditional_not_found_tolerant_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            (output / "samples").mkdir(parents=True)
            config = {"output": str(output), "tools": {"kubectl": "kubectl", "docker": "docker", "linkerd": "linkerd"},
                      "kubeconfig": "/tmp/kube", "namespace": "bench", "run_id": "run123"}
            matrix = run_matrix.Matrix(config)
            with mock.patch.object(matrix, "kube", return_value=subprocess.CompletedProcess([], 0, "deleted\n", "")) as kube:
                result = run_matrix.cleanup_failed_cell(matrix, config,
                    {"body": "4k", "engine": "nginx", "rep": 1}, RuntimeError("create timed out"))
            args = kube.call_args.args
            self.assertEqual(args[:3], ("delete", "pod", "proxybench-run123-4k-1-nginx"))
            self.assertIn("--ignore-not-found=true", args)
            self.assertFalse((output / "samples/4k/4k-nginx-r1/pod-create.txt").exists())
            self.assertEqual(result, "deleted\n")
            self.assertIn("create timed out", (output / "samples/last-failure.json").read_text())

    def test_summary_rejects_sample_from_different_input_or_image_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            sample_dir = Path("samples") / "4k" / "4k-nginx-r1"
            validation = output / sample_dir / "valid.txt"
            validation.parent.mkdir(parents=True)
            validation.write_text("valid\n")
            row = {"body_size": "4k", "engine": "nginx", "rep": 1,
                   "validation_path": (sample_dir / "valid.txt").as_posix(),
                   "warmup_dir": (sample_dir / "warmup").as_posix(),
                   "measure_dir": (sample_dir / "measurement").as_posix()}
            config = {"images": {"client": "client:local"},
                      "image_identities": {"client": {"docker_id": "sha256:client", "worker_id": "sha256:node"}},
                      "input_snapshot": {"client_dir": {"entries": {"request.lua": {"sha256": "abc"}}}}}
            fingerprint = common.provenance_fingerprint(config)
            (validation.parent / "cell.json").write_text(json.dumps({
                "body": "4k", "engine": "nginx", "rep": 1,
                "provenance_fingerprint": fingerprint}))
            summarize.validate_sample_provenance(output, row, fingerprint)
            changed = common.provenance_fingerprint({**config, "images": {"client": "client:new"}})
            with self.assertRaisesRegex(ValueError, "provenance does not match"):
                summarize.validate_sample_provenance(output, row, changed)
            changed_configmap = common.provenance_fingerprint({**config,
                "configmap_identities": {"native": {"uid": "new", "data": {"x": "changed"}}}})
            self.assertNotEqual(changed_configmap, fingerprint)
            configured = {**config, "concurrency": 128, "duration": "10s", "warmup": "2s",
                          "repeats": 3, "bodies": {"4k": 4096},
                          "cpus": {"proxy": 2, "origin": "3-4", "client": "5,7"},
                          "artifacts": {"rut": {"sha256": "before"}}}
            baseline = common.provenance_fingerprint(configured)
            (validation.parent / "cell.json").write_text(json.dumps({"body": "4k", "engine": "nginx", "rep": 1,
                                                                      "provenance_fingerprint": baseline}))
            mutations = [
                {**configured, "concurrency": 256},
                {**configured, "duration": "20s"},
                {**configured, "warmup": "4s"},
                {**configured, "repeats": 4},
                {**configured, "bodies": {"4k": 4096, "64k": 65536}},
                {**configured, "cpus": {"proxy": 3, "origin": "3-4", "client": "5,7"}},
                {**configured, "artifacts": {"rut": {"sha256": "after"}}},
                {**configured, "client_dir": "/different/client"},
                {**configured, "paths": {"rut_config_dir": "/different/config"}},
                {**configured, "node_mount": "/different/mount"},
            ]
            for mutated in mutations:
                changed_settings = common.provenance_fingerprint(mutated)
                self.assertNotEqual(changed_settings, baseline)
                with self.assertRaisesRegex(ValueError, "provenance does not match"):
                    summarize.validate_sample_provenance(output, row, changed_settings)
            self.assertEqual(common.provenance_fingerprint({**configured,
                "output": "/different/location", "checkpoint": "/other/checkpoint"}), baseline)

    def test_summary_rejects_index_identity_or_result_path_swaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            sample_dir = Path("samples") / "4k" / "4k-nginx-r1"
            cell_dir = output / sample_dir
            cell_dir.mkdir(parents=True)
            row = {"body_size": "4k", "engine": "nginx", "rep": 1,
                   "validation_path": (sample_dir / "valid.txt").as_posix(),
                   "warmup_dir": (sample_dir / "warmup").as_posix(),
                   "measure_dir": (sample_dir / "measurement").as_posix()}
            fingerprint = common.provenance_fingerprint({})
            (cell_dir / "cell.json").write_text(json.dumps({
                "body": "4k", "engine": "nginx", "rep": 1,
                "provenance_fingerprint": fingerprint}))
            summarize.validate_sample_provenance(output, row, fingerprint)
            for mutated in ({**row, "engine": "envoy"},
                            {**row, "body_size": "64k"},
                            {**row, "rep": 2},
                            {**row, "warmup_dir": "samples/4k/4k-envoy-r1/warmup"},
                            {**row, "measure_dir": "samples/4k/4k-envoy-r1/measurement"}):
                with self.assertRaisesRegex(ValueError, "index"):
                    summarize.validate_sample_provenance(output, mutated, fingerprint)

    def test_run_rechecks_every_recorded_artifact_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rut"
            path.write_bytes(b"original")
            path.chmod(0o755)
            config = {"artifacts": {"rut": {"path": str(path), "sha256": common.sha256(path)}}}
            run_matrix.verify_artifacts(config)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not executable"):
                run_matrix.verify_artifacts(config)
            path.chmod(0o755)
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
            config = {"output": str(output), "checkpoint": str(checkpoint), "bodies": {"4k": len(content)},
                      "payloads": {"4k": metadata}}
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

    def test_same_size_payload_and_metadata_replacement_is_rejected_and_changes_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkpoint = root / "checkpoint"
            payload_dir = checkpoint / "payloads" / "4k"
            payload_dir.mkdir(parents=True)
            original = b"original payload bytes"
            replacement = b"replaced payload bytes"
            self.assertEqual(len(replacement), len(original))
            for filename in ("proxy", "body.bin"):
                (payload_dir / filename).write_bytes(original)
            output = root / "output"
            output.mkdir()
            original_metadata = {"bytes": len(original), "sha256": hashlib.sha256(original).hexdigest()}
            replacement_metadata = {"bytes": len(replacement),
                                    "sha256": hashlib.sha256(replacement).hexdigest()}
            (output / "payloads.json").write_text(json.dumps({"4k": original_metadata}))
            config = {"schema": 1, "output": str(output), "checkpoint": str(checkpoint),
                      "bodies": {"4k": len(original)},
                      "payloads": {"4k": original_metadata}}
            original_fingerprint = common.provenance_fingerprint(config)
            sample_dir = Path("samples") / "4k" / "4k-nginx-r1"
            validation = output / sample_dir / "valid.txt"
            validation.parent.mkdir(parents=True)
            validation.write_text("valid\n")
            row = {"body_size": "4k", "engine": "nginx", "rep": 1,
                   "validation_path": (sample_dir / "valid.txt").as_posix(),
                   "warmup_dir": (sample_dir / "warmup").as_posix(),
                   "measure_dir": (sample_dir / "measurement").as_posix()}
            (validation.parent / "cell.json").write_text(json.dumps({
                "body": "4k", "engine": "nginx", "rep": 1,
                "provenance_fingerprint": original_fingerprint}))
            run_matrix.verify_payloads(config)
            for filename in ("proxy", "body.bin"):
                (payload_dir / filename).write_bytes(replacement)
            (output / "payloads.json").write_text(json.dumps({"4k": replacement_metadata}))
            with self.assertRaisesRegex(RuntimeError, "differs from benchmark config"):
                run_matrix.verify_payloads(config)
            config_path = output / "benchmark.json"
            config_path.write_text(json.dumps(config))
            with mock.patch("sys.argv", ["summarize.py", "--config", str(config_path)]):
                with self.assertRaisesRegex(RuntimeError, "differs from benchmark config"):
                    summarize.main()
            mutated_config = {**config, "payloads": {"4k": replacement_metadata}}
            self.assertNotEqual(common.provenance_fingerprint(mutated_config), original_fingerprint)
            with self.assertRaisesRegex(ValueError, "provenance does not match"):
                summarize.validate_sample_provenance(output, row,
                    common.provenance_fingerprint(mutated_config))

    def test_measurement_start_stamp_follows_delayed_docker_start_and_running_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            stamp = Path(tmp) / "measurement-start-monotonic.txt"
            state = [subprocess.CompletedProcess([], 0, "", ""),
                     subprocess.CompletedProcess([], 0, "false\n", ""),
                     subprocess.CompletedProcess([], 0, "true\n", "")]
            with mock.patch("run_client.subprocess.run", side_effect=state) as docker_run, \
                    mock.patch("run_client.time.sleep"), \
                    mock.patch("run_client.time.monotonic", side_effect=[100.0, 100.1, 100.3, 100.8]), \
                    mock.patch("run_client.os.replace", wraps=os.replace) as atomic_replace:
                run_client.start_and_stamp("docker", "wrk-container", stamp)
            self.assertEqual(stamp.read_text(), "100.800000000\n")
            atomic_replace.assert_called_once()
            self.assertEqual(list(Path(tmp).iterdir()), [stamp])
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
            events = []
            def invoke(argv, **_kwargs):
                events.append([str(item) for item in argv])
                if argv[1] == "run":
                    attempt = sum(1 for event in events if event[1] == "run")
                    if attempt == 1:
                        raise subprocess.TimeoutExpired("curl", 5)
                    return subprocess.CompletedProcess([], 7, "", "refused") if attempt == 2 else success
                return subprocess.CompletedProcess([], 0, "", "")
            with mock.patch("run_matrix.time.monotonic", return_value=0), \
                    mock.patch("run_matrix.time.sleep") as sleep, \
                    mock.patch("run_matrix.invoke", side_effect=invoke) as invoke_mock:
                matrix.wait_frontend("10.0.0.2")
            self.assertEqual(invoke_mock.call_count, 6)
            self.assertEqual([event[1] for event in events], ["run", "rm", "run", "rm", "run", "rm"])
            self.assertEqual(sleep.call_count, 2)
            self.assertIn("--connect-timeout", events[0])
            self.assertIn("--max-time", events[0])
            self.assertIn("--name", events[0])

    def test_frontend_cleanup_failure_reuses_same_name_and_cannot_spawn_another_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            matrix = run_matrix.Matrix({"output": tmp, "tools": {"docker": "docker", "kubectl": "kubectl", "linkerd": "linkerd"},
                                        "kubeconfig": "", "worker_container": "worker", "run_id": "r1",
                                        "cpus": {"client": "5,7"}, "images": {"client": "client:test"}})
            events = []
            def invoke(argv, **_kwargs):
                argv = [str(item) for item in argv]
                events.append(argv)
                if argv[1] == "run":
                    if sum(1 for row in events if row[1] == "run") == 1:
                        raise subprocess.TimeoutExpired(argv, 5)
                    return subprocess.CompletedProcess(argv, 125, "container name already in use", "")
                if sum(1 for row in events if row[1] == "rm") == 1:
                    raise OSError("Docker daemon did not remove the timed out probe")
                return subprocess.CompletedProcess(argv, 0, "", "")
            with mock.patch("run_matrix.time.monotonic", side_effect=[0, 0, 0, 181]), \
                    mock.patch("run_matrix.time.sleep"), \
                    mock.patch("run_matrix.invoke", side_effect=invoke):
                with self.assertRaisesRegex(RuntimeError, "did not become ready"):
                    matrix.wait_frontend("10.0.0.2")
            run_events = [row for row in events if row[1] == "run"]
            self.assertEqual(len(run_events), 2)
            self.assertEqual(run_events[0][run_events[0].index("--name") + 1],
                             run_events[1][run_events[1].index("--name") + 1])
            self.assertEqual([row[1] for row in events], ["run", "rm", "run", "rm"])

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
            self.assertEqual(invoke.call_count, 2)

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
            self.assertIsNone(found["proxy_under_load_pss_kb"])
            self.assertIsNone(found["origin_under_load_pss_kb"])
            self.assertEqual(found["proxy_under_load_observations"], 0)
            self.assertEqual(found["origin_under_load_observations"], 0)
            self.assertFalse(found["resource_sampling_complete"])
            summary["sampling_complete"] = True
            (cell / "resources-summary.json").write_text(json.dumps(summary))
            complete = summarize.resource_metrics(out, row)
            self.assertEqual(complete["proxy_under_load_pss_kb"], 90)
            self.assertEqual(complete["origin_under_load_pss_kb"], 250)
            self.assertEqual(summarize.aggregate_resource_values(
                [{**found, "resource_sampling_complete": False}, complete], "proxy_under_load_pss_kb"), [90])
            self.assertEqual(summarize.aggregate_resource_values(
                [{**found, "resource_sampling_complete": False}, complete], "proxy_executable_bytes"), [123, 123])

    def test_client_image_has_no_private_default(self):
        source = Path(prepare.__file__).read_text()
        self.assertNotIn("rut-watchdog-wrk:attempt89", source)
        self.assertIn('p.add_argument("--client-image", required=True', source)
        dockerfile = Path(__file__).with_name("Dockerfile.client").read_text()
        self.assertIn("curl", dockerfile)
        self.assertIn("/usr/local/bin/wrk", dockerfile)


if __name__ == "__main__":
    unittest.main()
