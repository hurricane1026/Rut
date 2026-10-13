#!/usr/bin/env python3
"""Prepare deterministic assets and ConfigMaps for an existing kind cluster."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from common import canonical_cpu_list, cpu_set, image_reference_matches, snapshot_inputs, write_json

SIZES = {"4k": 4096, "64k": 65536, "256k": 262144, "1m": 1048576}
IMAGES = {
    "nginx": "nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40",
    "envoy": "envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4",
}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def cpus(value: str, count: int, name: str) -> list[int]:
    try:
        values = sorted(cpu_set(value))
    except ValueError as error:
        raise ValueError(f"{name} must be a comma-separated CPU list or ranges") from error
    if len(values) != count or any(x < 0 or x > 63 for x in values):
        raise ValueError(f"{name} must contain {count} unique CPU IDs in 0..63")
    return values


def docker_image_identity(docker: str, reference: str) -> dict:
    raw = run([docker, "image", "inspect", "--format", "{{json .}}", reference])
    image = json.loads(raw)
    if not image.get("Id", "").startswith("sha256:"):
        raise RuntimeError(f"Docker did not return an immutable image ID for {reference}")
    return {"reference": reference, "docker_id": image["Id"],
            "repo_digests": sorted(image.get("RepoDigests") or [])}


def worker_image_identities(docker: str, worker: str, identities: dict) -> dict:
    raw = run([docker, "exec", worker, "crictl", "images", "-o", "json"])
    inventory = json.loads(raw).get("images", [])
    resolved = {}
    for name, identity in identities.items():
        reference = identity["reference"]
        matches = [image for image in inventory
                   if any(image_reference_matches(reference, candidate)
                          for candidate in (image.get("repoTags") or []) + (image.get("repoDigests") or []))]
        ids = {image.get("id") for image in matches if image.get("id")}
        if len(ids) != 1:
            raise RuntimeError(f"kind worker must have exactly one resolved image for {reference}; found {len(ids)}")
        image = next(image for image in matches if image.get("id") in ids)
        resolved[name] = {**identity, "worker_id": image["id"],
                          "worker_repo_digests": sorted(image.get("repoDigests") or [])}
    return resolved


def helper_verify_script(helpers: list[int], pin: bool) -> str:
    helper_cpus = canonical_cpu_list(set(helpers))
    pin_prefix = (f'for p in /proc/[0-9]*; do pid=${{p##*/}}; taskset -apc {helper_cpus} "$pid" >/dev/null 2>&1 || :; done; '
                  if pin else "")
    return (pin_prefix + f"expected='{helper_cpus}'; bad=0; "
            'for f in /proc/[0-9]*/task/[0-9]*/status; do '
            'allowed=$(awk "/^Cpus_allowed_list:/{print \\$2}" "$f"); '
            'if [ -n "$allowed" ] && [ "$allowed" != "$expected" ]; then echo "$f: $allowed"; bad=1; fi; '
            'done; [ "$bad" -eq 0 ] || exit 1; echo "all worker threads allowed only on $expected"')


def mask(cpu: int) -> str:
    return f"{1 << cpu:064b}"


def valid_run_id(value: str) -> bool:
    return len(value) <= 20 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", value) is not None


def native_body(size: int) -> bytes:
    chunks = []
    for block in range((size + 4095) // 4096):
        prefix = block.to_bytes(4, "big")
        chunks.append(prefix + bytes(((block * 17 + i * 29) & 255) for i in range(4092)))
    return b"".join(chunks)[:size]


def run(argv: list[str]) -> str:
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n{result.stdout}")
    return result.stdout


def nginx_origin(port: int, cpulist: list[int], alias: str, address: str = "127.0.0.1") -> str:
    affinity = " ".join(mask(cpu) for cpu in cpulist)
    return f'''worker_processes {len(cpulist)};
worker_cpu_affinity {affinity};
error_log /dev/stderr crit;
pid /tmp/nginx-origin.pid;
events {{ worker_connections 4096; }}
http {{
    map $http_x_rut_benchmark_preflight $benchmark_preflight {{ default 0; ~.+ 1; }}
    log_format rut_preflight "marker=$http_x_rut_benchmark_preflight connection=$connection requests=$connection_requests protocol=$server_protocol";
    access_log off;
    sendfile on;
    keepalive_timeout 65s;
    server {{
        listen {address}:{port};
        access_log /dev/stdout rut_preflight if=$benchmark_preflight;
        server_name _;
        location = /proxy {{ default_type application/octet-stream; alias {alias}; }}
    }}
}}
'''


def envoy_config() -> dict:
    return {
        "static_resources": {
            "listeners": [
                {
                    "name": "bench_http1_listener",
                    "address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}},
                    "filter_chains": [{"filters": [{
                        "name": "envoy.filters.network.http_connection_manager",
                        "typed_config": {
                            "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                            "stat_prefix": "bench_http1",
                            "codec_type": "HTTP1",
                            "generate_request_id": False,
                            "route_config": {
                                "name": "bench_routes",
                                "virtual_hosts": [{
                                    "name": "all",
                                    "domains": ["*"],
                                    "routes": [{
                                        "match": {"path": "/proxy"},
                                        "route": {"cluster": "origin", "timeout": "0s"},
                                    }],
                                }],
                            },
                            "http_filters": [{
                                "name": "envoy.filters.http.router",
                                "typed_config": {
                                    "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
                                    "suppress_envoy_headers": True,
                                },
                            }],
                        },
                    }]}],
                }
            ],
            "clusters": [{
                "name": "origin",
                "type": "STATIC",
                "connect_timeout": "1s",
                "lb_policy": "ROUND_ROBIN",
                "typed_extension_protocol_options": {
                    "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
                        "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
                        "explicit_http_config": {"http_protocol_options": {}},
                    }
                },
                "load_assignment": {
                    "cluster_name": "origin",
                    "endpoints": [{"lb_endpoints": [{
                        "endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 8081}}},
                    }]}],
                },
            }],
        },
        "admin": {"access_log_path": "/dev/null", "address": {"socket_address": {"address": "127.0.0.1", "port_value": 9901}}},
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--checkpoint", type=Path, required=True, help="host directory extra-mounted into the kind worker")
    p.add_argument("--output", type=Path, required=True, help="new or empty output directory")
    p.add_argument("--kubeconfig", type=Path, required=True)
    p.add_argument("--cluster-name", required=True, help="unique kind cluster name")
    p.add_argument("--worker-container", required=True, help="Docker container used for client netns")
    p.add_argument("--worker-node", required=True, help="Kubernetes worker node name")
    p.add_argument("--node-mount", default="/benchmark")
    p.add_argument("--namespace", default="proxy-benchmark")
    p.add_argument("--run-id", help="unique resource prefix; generated if omitted")
    p.add_argument("--selector-key", default="benchmark-role")
    p.add_argument("--selector-value", default="worker")
    p.add_argument("--rut-rps-dir", type=Path, required=True, help="matching rut + rut-compile directory")
    p.add_argument("--rut-throughput-dir", type=Path, required=True, help="matching rut + rut-compile directory")
    p.add_argument("--runtime-libs", type=Path, required=True)
    p.add_argument("--clang", type=Path, required=True)
    p.add_argument("--ld", type=Path, required=True)
    p.add_argument("--client-dir", type=Path, default=Path(__file__).with_name("client"),
                   help="directory containing request.lua and warmup.lua")
    p.add_argument("--proxy-cpu", type=int, default=2)
    p.add_argument("--origin-cpus", default="3,4,8,9")
    p.add_argument("--client-cpus", default="5,7")
    p.add_argument("--helper-cpus", default="6,14")
    p.add_argument("--nginx-image", default=IMAGES["nginx"])
    p.add_argument("--envoy-image", default=IMAGES["envoy"])
    p.add_argument("--client-image", required=True, help="locally built, explicitly selected client image")
    p.add_argument("--docker-bin", default="docker")
    p.add_argument("--kubectl-bin", default="kubectl")
    p.add_argument("--linkerd-bin", default="linkerd")
    p.add_argument("--duration", default="10s")
    p.add_argument("--warmup", default="2s")
    p.add_argument("--concurrency", type=int, default=128)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--verify-cluster", action="store_true", help="verify the selected worker, namespace, Docker extra mount, and Linkerd control plane")
    p.add_argument("--pin-worker-helpers", action="store_true",
                   help="pin existing kind-worker threads to --helper-cpus before verification")
    p.add_argument("--apply-configmaps", action="store_true")
    a = p.parse_args()

    checkpoint = a.checkpoint.resolve(strict=True)
    output = a.output.resolve()
    if output.exists() and any(output.iterdir()):
        p.error("--output must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    run_id = a.run_id or uuid.uuid4().hex[:10]
    if not valid_run_id(run_id):
        p.error("--run-id must be 1..20 lowercase DNS-compatible letters, digits, or interior hyphens")
    if a.repeats < 1:
        p.error("--repeats must be positive")
    if a.worker_node != f"{a.cluster_name}-worker":
        p.error("--worker-node must be <cluster-name>-worker")
    if a.worker_container != a.worker_node:
        p.error("--worker-container must match the kind worker node/container name")
    if not a.node_mount.startswith("/") or a.proxy_cpu < 0 or a.proxy_cpu > 63:
        p.error("node mount must be absolute and proxy CPU must be 0..63")
    try:
        origins = cpus(a.origin_cpus, 4, "--origin-cpus")
        clients = cpus(a.client_cpus, 2, "--client-cpus")
        helpers = cpus(a.helper_cpus, 2, "--helper-cpus")
    except ValueError as error:
        p.error(str(error))
    all_cpus = [a.proxy_cpu, *origins, *clients, *helpers]
    if len(set(all_cpus)) != len(all_cpus):
        p.error("proxy/origin/client/helper CPU assignments must be disjoint")

    paths = {"rut_rps": a.rut_rps_dir.resolve(strict=True), "rut_throughput": a.rut_throughput_dir.resolve(strict=True),
             "runtime_libs": a.runtime_libs.resolve(strict=True), "clang": a.clang.resolve(strict=True), "ld": a.ld.resolve(strict=True)}
    for key, path in paths.items():
        if not path.is_relative_to(checkpoint):
            p.error(f"{key} must be under --checkpoint so the kind worker can access it")
    for key in ("rut_rps", "rut_throughput"):
        if not all((paths[key] / name).is_file() for name in ("rut", "rut-compile")):
            p.error(f"{key} directory must contain rut and sibling rut-compile")
    client_dir = a.client_dir.resolve(strict=True)
    if not (client_dir / "request.lua").is_file() or not (client_dir / "warmup.lua").is_file():
        p.error("--client-dir must contain request.lua and warmup.lua")
    if not paths["clang"].is_file() or not paths["ld"].is_file():
        p.error("clang and ld must be files")

    image_refs = {"nginx": a.nginx_image, "envoy": a.envoy_image, "client": a.client_image}
    image_identities = {name: {"reference": reference} for name, reference in image_refs.items()}
    image_identities["client"] = docker_image_identity(a.docker_bin, a.client_image)

    config_dir = checkpoint / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "proxy-rps.rut").write_text('listen :8080\nupstream backend at "127.0.0.1:8081"\nroute GET "/proxy" { return forward(backend, hint: .rps, request_policy: { version: .http11, host: .upstream, connection: .omit, strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade] }) }\n')
    (config_dir / "proxy-throughput.rut").write_text('listen :8080\nupstream backend at "127.0.0.1:8081"\nroute GET "/proxy" { return forward(backend, hint: .throughput, request_policy: { version: .http11, host: .upstream, connection: .omit, strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade] }) }\n')

    payloads = {}
    for label, size in SIZES.items():
        directory = checkpoint / "payloads" / label
        directory.mkdir(parents=True, exist_ok=True)
        body = directory / "proxy"
        body.write_bytes(native_body(size))
        shutil.copyfile(body, directory / "body.bin")
        payloads[label] = {"bytes": size, "sha256": sha(body)}

    origin_cpus = origins
    front = f'''worker_processes 1;\nworker_cpu_affinity {mask(a.proxy_cpu)};\nerror_log /dev/stderr crit;\npid /tmp/nginx-front.pid;\nevents {{ worker_connections 4096; }}\nhttp {{ access_log off;\nupstream origin {{ server 127.0.0.1:8081; keepalive 4096; keepalive_timeout 60s; keepalive_requests 1000000000; }}\nserver {{ listen 0.0.0.0:8080; server_name _; keepalive_requests 1000000000;\nlocation = /proxy {{ proxy_pass http://origin; proxy_http_version 1.1; proxy_set_header Host $http_host; proxy_set_header Connection ""; proxy_buffering off; proxy_buffer_size 1024k; proxy_buffers 8 1024k; proxy_busy_buffers_size 1024k; proxy_max_temp_file_size 0; }} }}\n}}\n'''
    native_origin = nginx_origin(8081, origin_cpus, "/data/proxy")
    linkerd_origin = nginx_origin(8080, origin_cpus, "/data/body.bin", "0.0.0.0")
    owner_labels = {"app.kubernetes.io/managed-by": "rut-proxy-benchmark", "benchmark-run-id": run_id}
    native = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"pb-{run_id}-native", "namespace": a.namespace, "labels": owner_labels},
              "data": {"front-nginx.conf": front, "origin-nginx.conf": native_origin, "envoy-bootstrap.json": json.dumps(envoy_config(), separators=(",", ":"))}}
    linkerd = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"pb-{run_id}-linkerd", "namespace": a.namespace, "labels": owner_labels},
               "data": {"linkerd-origin.conf": linkerd_origin}}
    write_json(output / "native-configmap.json", native)
    write_json(output / "linkerd-configmap.json", linkerd)
    input_paths = {"client_dir": client_dir, "rut_config_dir": config_dir,
                   "runtime_libs": paths["runtime_libs"], "clang": paths["clang"], "ld": paths["ld"]}
    input_snapshot = snapshot_inputs(input_paths)

    config = {"schema": 1, "run_id": run_id, "checkpoint": str(checkpoint), "output": str(output), "kubeconfig": str(a.kubeconfig.resolve()),
              "cluster_name": a.cluster_name, "namespace": a.namespace, "worker_container": a.worker_container, "worker_node": a.worker_node,
              "node_mount": a.node_mount, "selector": {"key": a.selector_key, "value": a.selector_value},
              "configmaps": {"native": native["metadata"]["name"], "linkerd": linkerd["metadata"]["name"]},
              "images": image_refs, "image_identities": image_identities,
              "cpus": {"proxy": a.proxy_cpu, "origin": canonical_cpu_list(set(origins)),
                       "client": canonical_cpu_list(set(clients)), "helpers": canonical_cpu_list(set(helpers))},
              "paths": {**{key: str(value) for key, value in paths.items()}, "rut_config_dir": str(config_dir)},
              "client_dir": str(client_dir), "input_snapshot": input_snapshot,
              "tools": {"docker": a.docker_bin, "kubectl": a.kubectl_bin, "linkerd": a.linkerd_bin},
              "artifacts": {
                  "rut_rps": {"path": str(paths["rut_rps"] / "rut"), "sha256": sha(paths["rut_rps"] / "rut")},
                  "rut_rps_compiler": {"path": str(paths["rut_rps"] / "rut-compile"), "sha256": sha(paths["rut_rps"] / "rut-compile")},
                  "rut_throughput": {"path": str(paths["rut_throughput"] / "rut"), "sha256": sha(paths["rut_throughput"] / "rut")},
                  "rut_throughput_compiler": {"path": str(paths["rut_throughput"] / "rut-compile"), "sha256": sha(paths["rut_throughput"] / "rut-compile")},
              },
              "duration": a.duration, "warmup": a.warmup, "concurrency": a.concurrency, "repeats": a.repeats, "bodies": SIZES}
    checks = []
    if a.verify_cluster:
        inspect = json.loads(run([a.docker_bin, "inspect", a.worker_container]))[0]
        labels = inspect.get("Config", {}).get("Labels") or {}
        if labels.get("io.x-k8s.kind.cluster") != a.cluster_name or labels.get("io.x-k8s.kind.role") != "worker":
            p.error("Docker worker container labels do not identify the requested kind cluster and worker role")
        mounts = json.loads(run([a.docker_bin, "inspect", a.worker_container, "--format", "{{json .Mounts}}"]))
        if not any(Path(m["Source"]).resolve() == checkpoint and m["Destination"] == a.node_mount for m in mounts):
            p.error("worker container must bind-mount checkpoint at --node-mount")
        kube = [a.kubectl_bin, "--kubeconfig", str(a.kubeconfig.resolve())]
        context = run(kube + ["config", "current-context"]).strip()
        if context != f"kind-{a.cluster_name}":
            p.error(f"kubeconfig current-context must be kind-{a.cluster_name}; got {context!r}")
        node = json.loads(run(kube + ["get", "node", a.worker_node, "-o", "json"]))
        if node["metadata"].get("labels", {}).get(a.selector_key) != a.selector_value:
            p.error("worker node does not have the requested selector label")
        run(kube + ["get", "namespace", a.namespace])
        (output / "linkerd-check.txt").write_text(run([a.linkerd_bin, "--kubeconfig", str(a.kubeconfig.resolve()), "check"]))
        resolved_images = worker_image_identities(a.docker_bin, a.worker_container, image_identities)
        helper_cpus = canonical_cpu_list(set(helpers))
        verify_script = helper_verify_script(helpers, a.pin_worker_helpers)
        pin_result = run([a.docker_bin, "exec", a.worker_container, "taskset", "-c", helper_cpus,
                          "sh", "-eu", "-c", verify_script])
        (output / "worker-helper-pin.txt").write_text(pin_result)
        helpers_check = "worker helper thread affinity verified"
        checks = ["kind worker identity", "worker mount", "kubeconfig context", "node selector", "namespace", "linkerd check", helpers_check]
        config["image_identities"] = resolved_images
    config["verified_cluster_checks"] = checks
    write_json(output / "benchmark.json", config)
    write_json(output / "payloads.json", payloads)
    if a.apply_configmaps:
        if not a.verify_cluster:
            p.error("--apply-configmaps requires --verify-cluster")
        run([a.kubectl_bin, "--kubeconfig", str(a.kubeconfig.resolve()), "create", "-f", str(output / "native-configmap.json"), "-f", str(output / "linkerd-configmap.json")])
        config["configmaps_applied"] = True
    else:
        config["configmaps_applied"] = False
    write_json(output / "benchmark.json", config)
    print(json.dumps({"config": str(output / "benchmark.json"), "verified_cluster_checks": checks,
                      "payloads": payloads}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"prepare: {error}", file=sys.stderr)
        raise SystemExit(2)
