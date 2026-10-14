"""Shared helpers for the optional kind-based proxy comparison benchmark."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import subprocess


def load_config(path: str | Path) -> dict:
    config = json.loads(Path(path).read_text())
    if config.get("schema") != 1:
        raise ValueError("unsupported benchmark config schema")
    return config


def run(argv: list[str], *, check: bool = True, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n{result.stdout}")
    return result


def sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cpu_set(value: str) -> set[int]:
    cpus: set[int] = set()
    for part in value.split(","):
        if not part:
            raise ValueError(f"invalid CPU list: {value!r}")
        bounds = part.split("-")
        if len(bounds) == 1 and bounds[0].isdigit():
            start = end = int(bounds[0])
        elif len(bounds) == 2 and all(bound.isdigit() for bound in bounds):
            start, end = map(int, bounds)
            if start > end:
                raise ValueError(f"invalid CPU range: {part!r}")
        else:
            raise ValueError(f"invalid CPU list: {value!r}")
        selected = set(range(start, end + 1))
        if cpus & selected:
            raise ValueError(f"overlapping CPU list entries: {value!r}")
        cpus.update(selected)
    return cpus


def canonical_cpu_list(cpus: set[int]) -> str:
    if not cpus:
        raise ValueError("CPU list cannot be empty")
    ordered = sorted(cpus)
    ranges = []
    start = previous = ordered[0]
    for cpu in ordered[1:]:
        if cpu == previous + 1:
            previous = cpu
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = cpu
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def canonical_image_reference(reference: str) -> str:
    name, separator, digest = reference.partition("@")
    components = name.split("/")
    if len(components) == 1:
        name = f"docker.io/library/{name}"
    elif "." not in components[0] and ":" not in components[0] and components[0] != "localhost":
        name = f"docker.io/{name}"
    return f"{name}@{digest}" if separator else name


def image_reference_matches(reference: str, candidate: str) -> bool:
    return canonical_image_reference(reference) == canonical_image_reference(candidate)


def verify_client_image_config_identity(identity: dict) -> None:
    """Require Docker and the kind worker to use the same image config ID.

    RepoDigests identify registry manifests and are intentionally not used here:
    Docker's image ID and CRI's image ID both identify the image config.
    """
    docker_id = identity.get("docker_id")
    worker_id = identity.get("worker_id")
    docker_id = docker_id.strip().lower() if isinstance(docker_id, str) else ""
    worker_id = worker_id.strip().lower() if isinstance(worker_id, str) else ""
    if not docker_id or not worker_id:
        raise RuntimeError("client image config identity missing from Docker or kind worker")
    if docker_id != worker_id:
        raise RuntimeError(f"client Docker and kind worker image config IDs differ: {docker_id} != {worker_id}")


def normalized_linkerd_injection_spec(pod: dict) -> dict:
    spec = pod.get("spec", {})
    def normalize_container(item: dict) -> dict:
        normalized = copy.deepcopy(item)
        for mount in normalized.get("volumeMounts", []):
            if (mount.get("name", "").startswith("kube-api-access-") and
                    mount.get("mountPath") == "/var/run/secrets/kubernetes.io/serviceaccount"):
                mount["name"] = "kube-api-access"
        return normalized

    containers = sorted((normalize_container(item) for item in spec.get("containers", [])
                         if item.get("name", "").startswith("linkerd-")),
                        key=lambda item: item.get("name", ""))
    init_containers = sorted((normalize_container(item) for item in spec.get("initContainers", [])
                              if item.get("name", "").startswith("linkerd-")),
                             key=lambda item: item.get("name", ""))
    proxies = [item for item in containers + init_containers if item.get("name") == "linkerd-proxy"]
    if len(proxies) != 1:
        raise ValueError(f"Linkerd admission must inject exactly one linkerd-proxy; found {len(proxies)}")
    return {"containers": containers, "initContainers": init_containers}


def snapshot_inputs(paths: dict[str, str | Path]) -> dict:
    snapshot = {}
    for name, raw_path in sorted(paths.items()):
        root = Path(raw_path).resolve(strict=True)
        entries = {}
        selected = [root, *sorted(root.rglob("*"))] if root.is_dir() else [root]
        for path in selected:
            relative = "." if path == root else path.relative_to(root).as_posix()
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_symlink():
                raise ValueError(f"mounted input contains a symlink: {path}")
            if path.is_dir():
                entries[relative] = {"type": "directory", "mode": mode}
            elif path.is_file():
                entries[relative] = {"type": "file", "mode": mode, "size": path.stat().st_size,
                                     "sha256": sha256(path)}
            else:
                raise ValueError(f"mounted input contains an unsupported file: {path}")
        snapshot[name] = {"path": str(root), "entries": entries}
    return snapshot


def provenance_fingerprint(config: dict) -> str:
    evidence = {key: config[key] for key in (
        "images", "image_identities", "input_snapshot", "artifacts", "cpus",
        "duration", "warmup", "concurrency", "repeats", "bodies", "payloads",
        "worker_node", "selector", "client_dir", "paths", "node_mount",
        "linkerd_injected_spec",
    ) if key in config}
    evidence["schedule"] = {"algorithm": "balanced-interleave-v1",
                            "repeats": config.get("repeats")}
    evidence["native_linker_path"] = config.get("native_linker_path")
    evidence["native_linker_dir"] = config.get("native_linker_dir")
    evidence["configmap_identities"] = config.get("configmap_identities")
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def host_path(config: dict, relative: str) -> Path:
    return Path(config["checkpoint"]) / relative


def node_path(config: dict, relative: str) -> str:
    return str(Path(config["node_mount"]) / relative)


def pod_spec(config: dict, engine: str, body: str, name: str) -> dict:
    """Return one unmeshed-control or stock inbound-Linkerd Pod manifest."""
    node_root = Path(config["node_mount"])
    cpus = config["cpus"]
    proxy_cpu = int(cpus["proxy"])
    origin_cpus = sorted(cpu_set(cpus["origin"]))
    selector = config["selector"]
    if engine == "linkerd":
        return {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": config["namespace"],
                         "labels": {"app": name, "bench-engine": engine, "bench-body": body,
                                    "benchmark-run-id": config["run_id"]},
                         "annotations": {
                             "linkerd.io/inject": "enabled",
                             "config.linkerd.io/default-inbound-policy": "all-unauthenticated",
                             "config.linkerd.io/proxy-log-level": "error",
                             "config.linkerd.io/proxy-cpu-request": "1",
                         }},
            "spec": {
                "nodeName": config["worker_node"],
                "nodeSelector": {selector["key"]: selector["value"]},
                "terminationGracePeriodSeconds": 1,
                "containers": [{
                    "name": "origin", "image": config["images"]["nginx"],
                    "imagePullPolicy": "IfNotPresent", "ports": [{"name": "http", "containerPort": 8080}],
                    "volumeMounts": [
                        {"name": "payload", "mountPath": "/data", "readOnly": True},
                        {"name": "config", "mountPath": "/etc/nginx/nginx.conf", "subPath": "linkerd-origin.conf", "readOnly": True},
                    ], "resources": {"requests": {"cpu": 4, "memory": "64Mi"}},
                }],
                "volumes": [
                    {"name": "payload", "hostPath": {"path": str(node_root / "payloads" / body), "type": "Directory"}},
                    {"name": "config", "configMap": {"name": config["configmaps"]["linkerd"]}},
                ],
            },
        }

    configmap = config["configmaps"]["native"]
    payload_path = str(node_root / "payloads" / body / "proxy")
    front = {"name": "frontend", "ports": [{"name": "http", "containerPort": 8080}],
             "resources": {"requests": {"memory": "64Mi"}}}
    volumes = [
        {"name": "config", "configMap": {"name": configmap}},
        {"name": "payload", "hostPath": {"path": payload_path, "type": "File"}},
    ]
    origin = {
        "name": "origin", "image": config["images"]["nginx"], "imagePullPolicy": "IfNotPresent",
        "ports": [{"name": "origin", "containerPort": 8081}],
        "volumeMounts": [
            {"name": "config", "mountPath": "/etc/nginx/nginx.conf", "subPath": "origin-nginx.conf", "readOnly": True},
            {"name": "payload", "mountPath": "/data/proxy", "readOnly": True},
        ], "resources": {"requests": {"memory": "64Mi"}},
    }

    if engine in ("rut-rps", "rut-throughput"):
        variant = "rut_rps" if engine == "rut-rps" else "rut_throughput"
        binary_dir = config["paths"][variant]
        if not Path(binary_dir, "rut").is_file() or not Path(binary_dir, "rut-compile").is_file():
            raise ValueError(f"{variant} must contain matching rut and rut-compile binaries")
        mount_root = Path(config["node_mount"])
        binary_rel = Path(binary_dir).relative_to(Path(config["checkpoint"]))
        config_rel = Path(config["paths"]["rut_config_dir"]).relative_to(Path(config["checkpoint"]))
        libs_rel = Path(config["paths"]["runtime_libs"]).relative_to(Path(config["checkpoint"]))
        clang_rel = Path(config["paths"]["clang"]).relative_to(Path(config["checkpoint"]))
        ld_rel = Path(config["paths"]["ld"]).relative_to(Path(config["checkpoint"]))
        route_config = "proxy-rps.rut" if engine == "rut-rps" else "proxy-throughput.rut"
        front.update({
            "image": config["images"]["client"], "imagePullPolicy": "IfNotPresent",
            "command": ["/runtime/rut"],
            "args": [f"/benchmark/{route_config}", "--shards", "1", "--no-pin", "--drain", "1", "--opt", "2", "--backend", "io_uring"],
            "env": [{"name": "LD_LIBRARY_PATH", "value": "/lib64"}],
            "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False,
                                "seccompProfile": {"type": "Unconfined"}},
            "volumeMounts": [
                {"name": "rut-binaries", "mountPath": "/runtime", "readOnly": True},
                {"name": "rut-config", "mountPath": "/benchmark", "readOnly": True},
                {"name": "runtime-libs", "mountPath": "/lib64", "readOnly": True},
                {"name": "runtime-clang", "mountPath": config["native_linker_path"], "readOnly": True},
                {"name": "runtime-ld", "mountPath": str(Path(config["native_linker_dir"]) / "ld"), "readOnly": True},
            ],
        })
        volumes.extend([
            {"name": "rut-binaries", "hostPath": {"path": str(mount_root / binary_rel), "type": "Directory"}},
            {"name": "rut-config", "hostPath": {"path": str(mount_root / config_rel), "type": "Directory"}},
            {"name": "runtime-libs", "hostPath": {"path": str(mount_root / libs_rel), "type": "Directory"}},
            {"name": "runtime-clang", "hostPath": {"path": str(mount_root / clang_rel), "type": "File"}},
            {"name": "runtime-ld", "hostPath": {"path": str(mount_root / ld_rel), "type": "File"}},
        ])
    elif engine == "nginx":
        front.update({"image": config["images"]["nginx"], "imagePullPolicy": "IfNotPresent",
                      "command": ["nginx"], "args": ["-c", "/etc/nginx/front-nginx.conf", "-g", "daemon off;"],
                      "volumeMounts": [{"name": "config", "mountPath": "/etc/nginx/front-nginx.conf", "subPath": "front-nginx.conf", "readOnly": True}]})
    elif engine == "envoy":
        front.update({"image": config["images"]["envoy"], "imagePullPolicy": "IfNotPresent",
                      "command": ["envoy"], "args": ["-c", "/etc/envoy/bootstrap.json", "--concurrency", "1", "--disable-hot-restart", "--log-level", "error"],
                      "volumeMounts": [{"name": "config", "mountPath": "/etc/envoy/bootstrap.json", "subPath": "envoy-bootstrap.json", "readOnly": True}]})
    else:
        raise ValueError(f"unknown engine: {engine}")

    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": config["namespace"],
                     "labels": {"app": name, "bench-engine": engine, "bench-body": body,
                                "benchmark-run-id": config["run_id"]}},
        "spec": {"nodeName": config["worker_node"],
                 "nodeSelector": {selector["key"]: selector["value"]},
                 "terminationGracePeriodSeconds": 1,
                 "securityContext": {"seccompProfile": {"type": "Unconfined"}} if engine.startswith("rut-") else {},
                 "containers": [front, origin], "volumes": volumes},
    }


def write_json(path: str | Path, value: object) -> None:
    Path(path).write_text(json.dumps(value, indent=2) + "\n")
