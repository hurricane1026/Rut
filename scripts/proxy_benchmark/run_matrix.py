#!/usr/bin/env python3
"""Run a serial, interleaved HTTP/1.1 proxy matrix in a prepared kind cluster."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from common import (cpu_set, duration_seconds, image_reference_matches, load_config,
                    normalized_linkerd_injection_spec, pod_spec,
                    provenance_fingerprint, snapshot_inputs,
                    verify_client_image_config_identity, write_json)

SIZES = {"4k": 4096, "64k": 65536, "256k": 262144, "1m": 1048576}
ENGINES = {"4k": ("linkerd", "rut-rps", "nginx", "envoy"),
           "large": ("linkerd", "rut-throughput", "nginx", "envoy")}


def invoke(argv: list[str], *, check: bool = True, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    result = subprocess.run([str(x) for x in argv], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n{result.stdout}")
    return result


def parse_smaps_rollup(pids: list[int], stdout: str, returncode: int) -> dict:
    rows = []
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit() and fields[2].isdigit():
            rows.append({"pid": int(fields[0]), "rss_kb": int(fields[1]), "pss_kb": int(fields[2])})
        elif len(fields) == 2 and fields[0].isdigit() and fields[1] == "missing":
            rows.append({"pid": int(fields[0]), "rss_kb": None, "pss_kb": None})
    unique_pids = sorted(set(pids))
    rows_by_pid = {row["pid"]: row for row in rows}
    # Duplicate or unexpected rows are malformed evidence, not extra processes.
    well_formed = len(rows) == len(rows_by_pid) and set(rows_by_pid) <= set(unique_pids)
    complete = (returncode == 0 and well_formed and bool(unique_pids) and
                set(rows_by_pid) == set(unique_pids) and
                all(row["rss_kb"] is not None and row["pss_kb"] is not None for row in rows))
    return {"rows": [rows_by_pid[pid] for pid in unique_pids if pid in rows_by_pid],
            "complete": complete, "command_returncode": returncode}


def mapped_shared_object_paths(maps_text: str) -> list[str]:
    paths = set()
    for line in maps_text.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6:
            continue
        path = fields[5]
        if path.endswith(" (deleted)"):
            path = path[:-10]
        path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), path)
        if path.startswith("/") and re.search(r"\.so(?:\.|$)", path):
            paths.add(path)
    return sorted(paths)


def verify_origin_affinity(master_pid: int, cpus: str, rows: list[dict]) -> None:
    expected = cpu_set(cpus)
    by_process: dict[int, set[frozenset[int]]] = {}
    for row in rows:
        pid = int(row["pid"])
        allowed = cpu_set(row["allowed"])
        if not allowed or not allowed <= expected:
            raise RuntimeError(f"origin process {pid} affinity {row['allowed']} escapes {cpus}")
        by_process.setdefault(pid, set()).add(frozenset(allowed))
    master_masks = by_process.pop(master_pid, set())
    if master_masks != {frozenset(expected)}:
        raise RuntimeError(f"nginx master affinity does not match origin CPU set {cpus}")
    workers = list(by_process.values())
    if len(expected) == 1 and not workers:
        return
    worker_cpus = set()
    for masks in workers:
        if len(masks) != 1:
            raise RuntimeError("nginx worker threads have inconsistent CPU affinity")
        mask = next(iter(masks))
        if len(mask) != 1:
            raise RuntimeError("nginx worker affinity must remain pinned to one origin CPU")
        cpu = next(iter(mask))
        if cpu in worker_cpus:
            raise RuntimeError(f"multiple nginx workers share origin CPU {cpu}")
        worker_cpus.add(cpu)
    if worker_cpus != expected:
        raise RuntimeError(f"nginx worker CPU assignment {sorted(worker_cpus)} does not cover {cpus}")


class Matrix:
    def __init__(self, config: dict, config_path: Path | None = None):
        self.c = config
        self.out = Path(config["output"])
        self.config_path = self.out / "samples" / f"client-config-{provenance_fingerprint(config)}.json"
        self.samples = self.out / "samples"
        self.kubectl = config["tools"]["kubectl"]
        self.docker = config["tools"]["docker"]
        self.linkerd = config["tools"]["linkerd"]
        self.kubeconfig = config["kubeconfig"]

    def client_argv(self, client: Path, label: str, pod_ip: str, duration: str,
                    lua: str, target: Path) -> list[str]:
        return [sys.executable, str(client), "--config", str(self.config_path), "--label", label,
                "--pod-ip", pod_ip, "--duration", duration, "--lua", lua, "--output", str(target)]

    def freeze_client_config(self) -> Path:
        """Persist the config loaded by this process so both driver phases use one snapshot."""
        self.samples.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(self.c, indent=2, sort_keys=True) + "\n"
        if self.config_path.exists():
            if json.loads(self.config_path.read_text()) != self.c:
                raise RuntimeError("existing client config snapshot differs from selected benchmark")
        else:
            self.config_path.write_text(encoded)
        return self.config_path

    def kube(self, *args: str, check: bool = True, timeout: int = 240) -> subprocess.CompletedProcess[str]:
        return invoke([self.kubectl, "--kubeconfig", self.kubeconfig, *args], check=check, timeout=timeout)

    @staticmethod
    def file_sha(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def metric(self, pod: str, outdir: Path, phase: str) -> str:
        result = invoke([self.linkerd, "--kubeconfig", self.kubeconfig, "diagnostics", "proxy-metrics",
                         "-n", self.c["namespace"], f"po/{pod}"], timeout=90)
        (outdir / f"linkerd-metrics-{phase}.txt").write_text(result.stdout)
        return result.stdout

    def wait_frontend(self, pod_ip: str) -> None:
        """Wait until the application socket accepts an HTTP request."""
        deadline = time.monotonic() + 180
        safe_ip = re.sub(r"[^A-Za-z0-9_.-]", "-", pod_ip)
        name = f"proxybench-ready-{self.c.get('run_id', 'run')}-{safe_ip}"
        while time.monotonic() < deadline:
            argv = [self.docker, "run", "--rm", "--name", name,
                    "--network", f"container:{self.c['worker_container']}",
                    "--cpuset-cpus", self.c["cpus"]["client"], "--entrypoint", "curl",
                    self.c["images"]["client"], "--http1.1", "--fail", "--silent", "--show-error",
                    "--connect-timeout", "2", "--max-time", "4",
                    "--output", "/dev/null", f"http://{pod_ip}:8080/proxy"]
            try:
                result = invoke(argv, check=False, timeout=5)
            except subprocess.TimeoutExpired:
                result = None
            finally:
                try:
                    invoke([self.docker, "rm", "-f", name], check=False, timeout=5)
                except (OSError, subprocess.SubprocessError):
                    pass
            if result is not None and result.returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError(f"frontend at {pod_ip}:8080 did not become ready")

    @staticmethod
    def inbound_requests(text: str, target: str) -> float:
        values = []
        for line in text.splitlines():
            if line.startswith("request_total{") and 'direction="inbound"' in line and f'target_addr="{target}"' in line:
                values.append(float(line.split()[-1]))
        return sum(values)

    def inspect_runtime(self, engine: str, outdir: Path) -> dict[str, list[int]]:
        pod = json.loads((outdir / "pod.json").read_text())
        if pod["spec"].get("nodeName") != self.c["worker_node"]:
            raise RuntimeError(f"Pod scheduled on unexpected node {pod['spec'].get('nodeName')}")
        statuses_all = pod["status"].get("containerStatuses", []) + pod["status"].get("initContainerStatuses", [])
        if engine == "linkerd":
            injected = normalized_linkerd_injection_spec(pod)
            if injected != self.c.get("linkerd_injected_spec"):
                raise RuntimeError("Linkerd injected container spec differs from prepared benchmark")
        expected = {"origin", "linkerd-proxy"} if engine == "linkerd" else {"origin", "frontend"}
        statuses = [item for item in statuses_all if item.get("name") in expected and item.get("containerID")]
        if {item["name"] for item in statuses} != expected:
            raise RuntimeError(f"container set mismatch: expected {expected}, got {[x.get('name') for x in statuses]}")
        spec_containers = pod["spec"].get("containers", []) + pod["spec"].get("initContainers", [])
        spec_by_name = {item.get("name"): item for item in spec_containers}
        verify_statuses = statuses_all if engine == "linkerd" else statuses
        injected_names = ({item["name"] for item in normalized_linkerd_injection_spec(pod)["containers"] +
                           normalized_linkerd_injection_spec(pod)["initContainers"]} if engine == "linkerd" else set())
        if injected_names and not injected_names <= {item.get("name") for item in verify_statuses}:
            raise RuntimeError("Linkerd injected container status set is incomplete")
        for status in verify_statuses:
            if status.get("name") not in expected and status.get("name") not in injected_names:
                continue
            if status.get("name") in injected_names and not status.get("containerID"):
                raise RuntimeError(f"Linkerd injected container {status.get('name')} has no runtime identity")
            spec = spec_by_name.get(status["name"], {})
            verify_status_image_identity(status["name"], spec.get("image"), status.get("imageID", ""),
                                         self.c.get("image_identities", {}))
        if engine == "linkerd" and not any(item.get("name") == "linkerd-proxy" for item in spec_containers):
            raise RuntimeError("Linkerd did not inject the stock sidecar")
        if engine != "linkerd" and any(item.get("name", "").startswith("linkerd-") for item in spec_containers):
            raise RuntimeError("control Pod unexpectedly has a Linkerd sidecar")

        details = []
        resource_pids = {"proxy": [], "origin": []}
        frontend_binaries = {}
        mapped_libraries = {"proxy": {}, "origin": {}}
        for item in statuses:
            name = item["name"]
            cid = item["containerID"].split("://", 1)[-1]
            inspected = json.loads(invoke([self.docker, "exec", self.c["worker_container"], "crictl", "inspect", cid]).stdout)
            pid = int(inspected["info"]["pid"])
            cpus = self.c["cpus"]["origin"] if name == "origin" else str(self.c["cpus"]["proxy"])
            pin = invoke([self.docker, "exec", self.c["worker_container"], "taskset", "-apc", cpus, str(pid)])
            cg = invoke([self.docker, "exec", self.c["worker_container"], "cat", f"/proc/{pid}/cgroup"]).stdout.strip().splitlines()[-1]
            cgroot = "/sys/fs/cgroup" + cg.split(":", 2)[2]
            procs = invoke([self.docker, "exec", self.c["worker_container"], "cat", f"{cgroot}/cgroup.procs"]).stdout.split()
            if name != "origin":
                for process in procs:
                    invoke([self.docker, "exec", self.c["worker_container"], "taskset", "-apc", cpus, process])
            cpu_max = invoke([self.docker, "exec", self.c["worker_container"], "cat", f"{cgroot}/cpu.max"]).stdout.strip()
            if cpu_max != "max 100000":
                raise RuntimeError(f"{name} has unexpected CPU quota {cpu_max}")
            affinity = []
            process_binaries = []
            process_libraries = set()
            for process in procs:
                command = (f"for f in /proc/{process}/task/*/status; do "
                           "tid=${f%/status}; tid=${tid##*/}; "
                           "awk -v t=\"$tid\" '/^Name:/{n=$2}/^Cpus_allowed_list:/{print t, n, $2}' \"$f\"; done")
                lines = invoke([self.docker, "exec", self.c["worker_container"], "sh", "-c", command]).stdout.splitlines()
                for line in lines:
                    fields = line.split()
                    if len(fields) != 3 or not fields[0].isdigit():
                        raise RuntimeError(f"cannot read thread affinity for process {process}: {line!r}")
                    row = {"pid": process, "tid": int(fields[0]), "name": fields[1], "allowed": fields[2]}
                    affinity.append(row)
                    if name == "origin":
                        if not cpu_set(fields[2]) or not cpu_set(fields[2]) <= cpu_set(cpus):
                            raise RuntimeError(f"{name} thread in process {process} affinity {fields[2]} escapes {cpus}")
                    elif cpu_set(fields[2]) != cpu_set(cpus):
                        raise RuntimeError(f"{name} thread in process {process} affinity {fields[2]} != {cpus}")
                exe = invoke([self.docker, "exec", self.c["worker_container"], "readlink", f"/proc/{process}/exe"]).stdout.strip()
                size = int(invoke([self.docker, "exec", self.c["worker_container"], "stat", "-Lc", "%s", f"/proc/{process}/exe"]).stdout.strip())
                digest = invoke([self.docker, "exec", self.c["worker_container"], "sha256sum", f"/proc/{process}/exe"]).stdout.split()[0]
                process_binaries.append({"pid": process, "path": exe, "size_bytes": size, "sha256": digest})
                maps = invoke([self.docker, "exec", self.c["worker_container"], "cat", f"/proc/{process}/maps"]).stdout
                process_libraries.update(mapped_shared_object_paths(maps))
            if name == "origin":
                verify_origin_affinity(pid, cpus, affinity)
            if name != "origin":
                resource_pids["proxy"].extend(int(process) for process in procs)
                role = "proxy"
                for binary in process_binaries:
                    frontend_binaries[binary["sha256"]] = {"path": binary["path"], "size_bytes": binary["size_bytes"], "sha256": binary["sha256"]}
            else:
                resource_pids["origin"].extend(int(process) for process in procs)
                role = "origin"
            for path in process_libraries:
                if path in mapped_libraries[role]:
                    continue
                selected_pid = procs[0]
                proc_path = f"/proc/{selected_pid}/root{path}"
                size_result = invoke([self.docker, "exec", self.c["worker_container"], "stat", "-Lc", "%s", proc_path], check=False)
                hash_result = invoke([self.docker, "exec", self.c["worker_container"], "sha256sum", proc_path], check=False)
                library = {"path": path, "size_bytes": int(size_result.stdout.strip()) if size_result.returncode == 0 and size_result.stdout.strip().isdigit() else None,
                           "sha256": hash_result.stdout.split()[0] if hash_result.returncode == 0 and hash_result.stdout.split() else None}
                mapped_libraries[role][path] = library
            write_json(outdir / f"container-{name}-inspect.json", inspected)
            details.append({"name": name, "container_id": cid, "image_id": item.get("imageID"),
                            "restart_count": item.get("restartCount", 0), "pid": pid,
                            "cpuset_command": pin.stdout, "cpu_max": cpu_max, "cgroup": cgroot,
                            "processes": affinity, "process_binaries": process_binaries,
                            "mapped_shared_objects": sorted(process_libraries)})
        write_json(outdir / "container-runtime.json", details)
        write_json(outdir / "frontend-executables.json", list(frontend_binaries.values()))
        library_report = {}
        for role, libraries in mapped_libraries.items():
            files = list(libraries.values())
            complete = all(item["size_bytes"] is not None and item["sha256"] is not None for item in files)
            library_report[role] = {"files": files, "complete": complete,
                                    "total_bytes": sum(item["size_bytes"] for item in files) if complete else None}
        write_json(outdir / "mapped-shared-objects.json", library_report)
        return {key: sorted(set(value)) for key, value in resource_pids.items()}

    def verify_live_runtime(self, runtime: list[dict]) -> None:
        for record in runtime:
            inspected = json.loads(invoke([self.docker, "exec", self.c["worker_container"],
                                           "crictl", "inspect", record["container_id"]]).stdout)
            if int(inspected["info"]["pid"]) != record["pid"]:
                raise RuntimeError(f"container {record['name']} process PID changed during measurement")
            cg = invoke([self.docker, "exec", self.c["worker_container"], "cat",
                         f"/proc/{record['pid']}/cgroup"]).stdout.strip().splitlines()[-1]
            cgroot = "/sys/fs/cgroup" + cg.split(":", 2)[2]
            pids = set(invoke([self.docker, "exec", self.c["worker_container"], "cat",
                               f"{cgroot}/cgroup.procs"]).stdout.split())
            baseline_pids = {str(row["pid"]) for row in record["processes"]}
            if not baseline_pids <= pids:
                raise RuntimeError(f"container {record['name']} process set changed during measurement")
            observed = []
            for pid in sorted(pids):
                cmd = (f"for f in /proc/{pid}/task/*/status; do "
                       "tid=${f%/status}; tid=${tid##*/}; "
                       "awk -v t=\"$tid\" '/^Name:/{n=$2}/^Cpus_allowed_list:/{print t, n, $2}' \"$f\"; done")
                lines = invoke([self.docker, "exec", self.c["worker_container"], "sh", "-c", cmd]).stdout.splitlines()
                for line in lines:
                    fields = line.split()
                    if len(fields) != 3 or not fields[0].isdigit():
                        raise RuntimeError(f"cannot verify live thread affinity for {record['name']}")
                    observed.append((int(pid), int(fields[0]), fields[1], fields[2]))
            expected = {(int(row["pid"]), int(row["tid"]), row["name"], row["allowed"])
                        for row in record["processes"]}
            if set(observed) != expected:
                raise RuntimeError(f"container {record['name']} process/affinity changed during measurement")

    def capture_resources(self, outdir: Path, phase: str, pids: dict[str, list[int]]) -> dict:
        all_pids = sorted(set(pids["proxy"]) | set(pids["origin"]))
        groups = {"proxy": set(pids["proxy"]), "origin": set(pids["origin"])}
        if all_pids:
            cases = " ".join(str(pid) for pid in all_pids)
            script = (f"for bench_pid in {cases}; do "
                      "roll=/proc/$bench_pid/smaps_rollup; "
                      "[ -r $roll ] || { echo $bench_pid missing; continue; }; "
                      "awk -v p=$bench_pid '/^Rss:/{r=$2}/^Pss:/{s=$2}END{print p,r,s}' $roll; done")
            result = invoke([self.docker, "exec", self.c["worker_container"], "taskset", "-c",
                             self.c["cpus"]["helpers"], "sh", "-c", script], check=False)
            parsed = parse_smaps_rollup(all_pids, result.stdout, result.returncode)
            process_rows = parsed["rows"]
            command_returncode = parsed["command_returncode"]
        else:
            process_rows = []
            command_returncode = 0
            parsed = {"complete": False}
        grouped = {}
        for name, selected in groups.items():
            rows = [row for row in process_rows if row["pid"] in selected]
            complete = parsed["complete"] and bool(selected) and len(rows) == len(selected) and all(
                row["rss_kb"] is not None and row["pss_kb"] is not None for row in rows)
            grouped[name] = {"expected_process_count": len(selected), "process_count": len(rows),
                             "rss_kb": sum(row["rss_kb"] for row in rows) if complete else None,
                             "pss_kb": sum(row["pss_kb"] for row in rows) if complete else None,
                             "complete": complete, "processes": rows}
        record = {"phase": phase, **grouped, "command_returncode": command_returncode}
        write_json(outdir / f"resources-{phase}.json", record)
        return record

    def client_is_running(self, target: Path) -> bool:
        client_id_path = target / "container-id.txt"
        if not client_id_path.is_file():
            return False
        client_id = client_id_path.read_text().strip()
        running = invoke([self.docker, "inspect", "--format", "{{.State.Running}}", client_id], check=False)
        return running.returncode == 0 and running.stdout.strip() == "true"

    def curl(self, pod_ip: str, outdir: Path, body: str, *, marker: str | None = None, many: bool = False) -> None:
        client_cpus = self.c["cpus"]["client"]
        image = self.c["image_identities"]["client"]["docker_id"]
        argv = [self.docker, "run", "--rm", "--security-opt", "label=disable", "--network",
                f"container:{self.c['worker_container']}", "--cpuset-cpus", client_cpus,
                "--mount", f"type=bind,src={outdir},dst=/out", "--entrypoint", "curl", image,
                "--http1.1", "--fail", "--silent", "--show-error", "-H", "Host: client.example",
                "-H", "Connection: keep-alive"]
        url = f"http://{pod_ip}:8080/proxy"
        if marker:
            argv += ["-H", f"X-Rut-Benchmark-Preflight: {marker}"]
        if many:
            for _ in range(100):
                argv += ["--output", "/dev/null", "--write-out", "%{http_version} %{http_code} %{size_download} %{num_connects}\\n", url]
            (outdir / "keepalive-preflight-command.json").write_text(json.dumps(argv, indent=2) + "\n")
            result = invoke(argv)
            (outdir / "keepalive-preflight.log").write_text(result.stdout)
            lines = [line.split() for line in result.stdout.splitlines() if line.strip()]
            if len(lines) != 100 or any(len(line) != 4 or line[:2] != ["1.1", "200"] or int(line[2]) != SIZES[body] for line in lines):
                raise RuntimeError(f"HTTP/1.1 100-response preflight failed: {result.stdout[:1200]}")
            if int(lines[0][3]) != 1 or any(int(line[3]) != 0 for line in lines[1:]):
                raise RuntimeError("downstream keepalive preflight used more than one connection")
            return
        argv += ["-D", "/out/response.headers", "-o", "/out/response.bin", "-w", "%{http_version} %{http_code} %{size_download}\\n", url]
        (outdir / "byte-preflight-command.json").write_text(json.dumps(argv, indent=2) + "\n")
        result = invoke(argv)
        (outdir / "byte-preflight-status.txt").write_text(result.stdout)
        expected = Path(self.c["checkpoint"]) / "payloads" / body / "proxy"
        response = outdir / "response.bin"
        if result.stdout.strip() != f"1.1 200 {expected.stat().st_size}" or self.file_sha(response) != self.file_sha(expected):
            raise RuntimeError("HTTP/1.1 byte/hash preflight failed")
        (outdir / "response.sha256").write_text(self.file_sha(response) + "\n")

    def run_cell(self, body: str, engine: str, rep: int) -> Path:
        verify_artifacts(self.c)
        verify_payloads(self.c)
        verify_provenance(self.c)
        label = f"{body}-{engine}-r{rep}"
        pod_name = f"proxybench-{self.c['run_id']}-{body}-{rep}-{engine}"
        outdir = self.samples / body / label
        outdir.mkdir(parents=True, exist_ok=False)
        manifest = pod_spec(self.c, engine, body, pod_name)
        pod_path = outdir / "pod.json"
        write_json(outdir / "pod.yaml", manifest)  # JSON is a valid Kubernetes YAML document.
        created = self.kube("create", "-f", str(outdir / "pod.yaml"))
        (outdir / "pod-create.txt").write_text(created.stdout)
        ready = self.kube("wait", "--for=condition=Ready", f"pod/{pod_name}", "-n", self.c["namespace"], "--timeout=180s", timeout=190)
        (outdir / "pod-ready.txt").write_text(ready.stdout)
        fetched = self.kube("get", "pod", pod_name, "-n", self.c["namespace"], "-o", "json")
        pod_path.write_text(fetched.stdout)
        pod = json.loads(fetched.stdout)
        pod_ip = pod["status"]["podIP"]
        (outdir / "pod-ip.txt").write_text(pod_ip + "\n")
        self.wait_frontend(pod_ip)
        resource_pids = self.inspect_runtime(engine, outdir)
        resource_records = [self.capture_resources(outdir, "idle", resource_pids)]

        before = self.metric(pod_name, outdir, "before") if engine == "linkerd" else None
        self.curl(pod_ip, outdir, body)
        marker = engine if body == "4k" and rep == 1 else None
        if marker:
            self.curl(pod_ip, outdir, body, marker=marker, many=True)
            origin_log = self.kube("logs", pod_name, "-n", self.c["namespace"], "-c", "origin").stdout
            (outdir / "origin-100-request-preflight.log").write_text(origin_log)
            tagged = [line for line in origin_log.splitlines() if f"marker={marker}" in line]
            connections, requests, protocols = set(), [], set()
            for line in tagged:
                match = re.search(r"connection=(\d+) requests=(\d+) protocol=([^ ]+)", line)
                if not match:
                    raise RuntimeError(f"cannot parse origin marker: {line}")
                connections.add(match.group(1)); requests.append(int(match.group(2))); protocols.add(match.group(3))
            sequential = len(requests) == 100 and sorted(requests) == list(range(min(requests), min(requests) + 100))
            if len(tagged) != 100 or len(connections) != 1 or not sequential or protocols != {"HTTP/1.1"}:
                raise RuntimeError("origin HTTP/1.1 keepalive preflight failed")
            write_json(outdir / "origin-100-request-preflight-summary.json",
                       {"requests_logged": len(tagged), "connections": sorted(connections), "protocols": sorted(protocols)})
        if engine == "linkerd":
            after = self.metric(pod_name, outdir, "after")
            target = f"{pod_ip}:8080"
            if self.inbound_requests(after, target) <= self.inbound_requests(before, target):
                raise RuntimeError(f"Linkerd inbound request_total did not increase for {target}")

        if engine.startswith("rut-"):
            server = self.kube("logs", pod_name, "-n", self.c["namespace"], "-c", "frontend").stdout
            (outdir / "frontend-server.log").write_text(server)
            if "Backend: io_uring" not in server or "Listening" not in server:
                raise RuntimeError("Rut did not prove io_uring backend/listening")
        else:
            containers = ("linkerd-proxy", "origin") if engine == "linkerd" else ("frontend", "origin")
            for container in containers:
                logs = self.kube("logs", pod_name, "-n", self.c["namespace"], "-c", container, check=False)
                (outdir / f"{container}-server.log").write_text(logs.stdout)

        write_json(outdir / "cell.json", {"body": body, "engine": engine, "rep": rep, "pod_ip": pod_ip,
                   "duration": self.c["duration"], "warmup": self.c["warmup"], "concurrency": self.c["concurrency"],
                   "proxy_cpu": self.c["cpus"]["proxy"], "origin_cpus": self.c["cpus"]["origin"],
                   "client_cpus": self.c["cpus"]["client"], "route_config": "proxy-rps.rut" if engine == "rut-rps" else "proxy-throughput.rut" if engine == "rut-throughput" else None,
                   "provenance_fingerprint": provenance_fingerprint(self.c)})
        client = Path(__file__).with_name("run_client.py")
        for kind, duration, lua, target in (("warmup", self.c["warmup"], "warmup.lua", outdir / "warmup"),
                                            ("measurement", self.c["duration"], "request.lua", outdir / "measurement")):
            argv = self.client_argv(client, f"{label}-{kind}", pod_ip, duration, lua, target)
            (outdir / f"{kind}-driver-command.json").write_text(json.dumps(argv, indent=2) + "\n")
            child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            measure_start = None
            client_running = False
            next_state_check = time.monotonic()
            next_snapshot = 2.0
            measurement_duration = duration_seconds(self.c["duration"])
            while child.poll() is None:
                now = time.monotonic()
                if kind == "measurement" and now >= next_state_check:
                    client_running = self.client_is_running(target)
                    stamp = target / "measurement-start-monotonic.txt"
                    if client_running and measure_start is None and stamp.is_file():
                        measure_start = float(stamp.read_text().strip())
                    next_state_check = now + 0.5
                if kind == "measurement" and measure_start is not None:
                    elapsed = now - measure_start
                    if (client_running and elapsed < measurement_duration and elapsed >= next_snapshot and
                            len([r for r in resource_records if r["phase"].startswith("under-load")]) < 3):
                        sample_no = len([r for r in resource_records if r["phase"].startswith("under-load")]) + 1
                        snapshot_start = time.monotonic()
                        running_before = self.client_is_running(target)
                        resource = self.capture_resources(outdir, f"under-load-{sample_no}", resource_pids)
                        snapshot_end = time.monotonic()
                        running_after = self.client_is_running(target)
                        start_elapsed = snapshot_start - measure_start
                        end_elapsed = snapshot_end - measure_start
                        in_window = (running_before and running_after and start_elapsed >= 0 and
                                     end_elapsed <= measurement_duration)
                        resource["measurement_window_start_elapsed_sec"] = round(start_elapsed, 3)
                        resource["measurement_window_end_elapsed_sec"] = round(end_elapsed, 3)
                        resource["client_state_running_before"] = running_before
                        resource["client_state_running_after"] = running_after
                        resource["snapshot_valid"] = in_window and all(resource[role]["complete"] for role in ("proxy", "origin"))
                        if not resource["snapshot_valid"]:
                            for role in ("proxy", "origin"):
                                resource[role]["complete"] = False
                                resource[role]["rss_kb"] = None
                                resource[role]["pss_kb"] = None
                        write_json(outdir / f"resources-under-load-{sample_no}.json", resource)
                        resource_records.append(resource)
                        next_snapshot += 3.0
                time.sleep(0.2)
            driver_output = child.communicate()[0]
            (outdir / f"{kind}-driver.log").write_text(driver_output)
            if child.returncode:
                raise RuntimeError(f"{kind} wrk returned {child.returncode}; see {target}")
            if kind == "warmup":
                resource_records.append(self.capture_resources(outdir, "after-warmup", resource_pids))
            log = (target / "wrk.log").read_text()
            records = [line.split() for line in log.splitlines() if line.startswith("METRICS ")]
            if (target / "returncode.txt").read_text().strip() != "0" or len(records) != 1 or len(records[0]) != 11:
                raise RuntimeError(f"invalid wrk result in {target}")
            if any(int(value) != 0 for value in records[0][6:11]):
                raise RuntimeError(f"wrk errors in {target}: {' '.join(records[0])}")
        verify_artifacts(self.c)
        verify_payloads(self.c)
        verify_provenance(self.c)
        final = self.kube("get", "pod", pod_name, "-n", self.c["namespace"], "-o", "json")
        runtime = json.loads((outdir / "container-runtime.json").read_text())
        verify_pod_runtime_stable(pod, json.loads(final.stdout), runtime)
        self.verify_live_runtime(runtime)
        (outdir / "valid.txt").write_text("warmup and measurement valid; error counters 0\n")
        under_load = [row for row in resource_records if row["phase"].startswith("under-load")]
        write_json(outdir / "resources-summary.json", {
            "frontend_executables": json.loads((outdir / "frontend-executables.json").read_text()),
            "mapped_shared_objects": json.loads((outdir / "mapped-shared-objects.json").read_text()),
            "idle": {name: next((row[name] for row in resource_records if row["phase"] == "idle"), None) for name in ("proxy", "origin")},
            "after_warmup": {name: next((row[name] for row in resource_records if row["phase"] == "after-warmup"), None) for name in ("proxy", "origin")},
            "under_load_samples": under_load,
            "sampling_complete": (len(under_load) == 3 and all(row.get("snapshot_valid", False) for row in under_load) and
                                  all(row[role]["complete"] for row in resource_records if row["phase"] in ("idle", "after-warmup") for role in ("proxy", "origin"))),
            "expected_under_load_samples": 3,
            "observed_under_load_samples": len(under_load),
        })
        delete = self.kube("delete", "pod", pod_name, "-n", self.c["namespace"], "--grace-period=1", "--wait=true", timeout=90)
        (outdir / "pod-delete.txt").write_text(delete.stdout)
        return outdir


def plan(repeats: int = 3) -> list[dict]:
    schedules = {
        "4k": [["linkerd", "rut-rps", "nginx", "envoy"], ["envoy", "nginx", "rut-rps", "linkerd"], ["nginx", "linkerd", "envoy", "rut-rps"]],
        "64k": [["linkerd", "rut-throughput", "nginx", "envoy"], ["envoy", "nginx", "rut-throughput", "linkerd"], ["nginx", "linkerd", "envoy", "rut-throughput"]],
        "256k": [["linkerd", "rut-throughput", "nginx", "envoy"], ["envoy", "nginx", "rut-throughput", "linkerd"], ["nginx", "linkerd", "envoy", "rut-throughput"]],
        "1m": [["linkerd", "rut-throughput", "nginx", "envoy"], ["envoy", "nginx", "rut-throughput", "linkerd"], ["nginx", "linkerd", "envoy", "rut-throughput"]],
    }
    if repeats < 1:
        raise ValueError("repeats must be positive")
    return [{"body": body, "engine": engine, "rep": rep}
            for body, rounds in schedules.items() for rep in range(1, repeats + 1)
            for engine in rounds[(rep - 1) % len(rounds)]]


def verify_artifacts(config: dict) -> None:
    for name, artifact in config["artifacts"].items():
        path = Path(artifact["path"])
        if not path.is_file():
            raise RuntimeError(f"recorded artifact is missing: {name}: {path}")
        if not os.access(path, os.X_OK):
            raise RuntimeError(f"recorded artifact is not executable: {name}: {path}")
        actual = Matrix.file_sha(path)
        if actual != artifact["sha256"]:
            raise RuntimeError(f"recorded artifact hash mismatch for {name}: expected {artifact['sha256']}, got {actual}")


def verify_payloads(config: dict) -> None:
    prepared = json.loads((Path(config["output"]) / "payloads.json").read_text())
    bodies = config["bodies"]
    expected_payloads = config.get("payloads")
    if not isinstance(expected_payloads, dict):
        raise RuntimeError("benchmark config has no bound payload metadata")
    if prepared != expected_payloads:
        raise RuntimeError("prepared payload metadata differs from benchmark config")
    if set(prepared) != set(bodies):
        raise RuntimeError("prepared payload metadata does not match configured bodies")
    for body, configured_size in bodies.items():
        metadata = prepared[body]
        expected_size = int(configured_size)
        if metadata.get("bytes") != expected_size:
            raise RuntimeError(f"prepared payload size metadata mismatch for {body}")
        for filename in ("proxy", "body.bin"):
            path = Path(config["checkpoint"]) / "payloads" / body / filename
            if not path.is_file():
                raise RuntimeError(f"prepared payload is missing: {path}")
            actual_size = path.stat().st_size
            if actual_size != expected_size:
                raise RuntimeError(
                    f"prepared payload size mismatch for {body}/{filename}: expected {expected_size}, got {actual_size}"
                )
            if Matrix.file_sha(path) != metadata["sha256"]:
                raise RuntimeError(f"prepared payload hash mismatch for {body}/{filename}")


def image_identity_matches(actual: str, expected: dict) -> bool:
    actual_id = actual.rsplit("://", 1)[-1]
    expected_id = expected.get("worker_id", "")
    if expected_id and (actual_id == expected_id or actual_id.endswith(expected_id)):
        return True
    if "@" in actual_id:
        actual_digest = actual_id.rsplit("@", 1)[-1]
        return any("@" in candidate and candidate.rsplit("@", 1)[-1] == actual_digest
                   for candidate in expected.get("worker_repo_digests", []))
    return False


def pod_runtime_statuses(pod: dict) -> dict:
    statuses = pod.get("status", {}).get("containerStatuses", []) + pod.get("status", {}).get("initContainerStatuses", [])
    return {item.get("name"): (item.get("containerID", "").split("://", 1)[-1], item.get("imageID", ""),
                                int(item.get("restartCount", 0))) for item in statuses}


def verify_pod_runtime_stable(initial: dict, final: dict, runtime: list[dict]) -> None:
    before, after = pod_runtime_statuses(initial), pod_runtime_statuses(final)
    for record in runtime:
        name = record["name"]
        expected = (record["container_id"], record["image_id"], record.get("restart_count", 0))
        if before.get(name) != expected or after.get(name) != expected:
            raise RuntimeError(f"container {name} identity/restart state changed during measurement")
    # Every runtime process and its captured affinity must still be present in the
    # original container record; inspect_runtime records the PID and per-thread masks.
    if not runtime or any(not item.get("pid") or not item.get("processes") for item in runtime):
        raise RuntimeError("runtime process/affinity baseline is incomplete")


def expected_container_identity(name: str, image: str, identities: dict) -> dict | None:
    if name == "linkerd-proxy":
        return identities.get("linkerd_proxy")
    return next((value for value in identities.values() if value["reference"] == image), None)


def verify_status_image_identity(name: str, image: str, actual: str, identities: dict) -> None:
    identity = expected_container_identity(name, image, identities)
    if (name in {"origin", "frontend", "linkerd-proxy"} or name.startswith("linkerd-")) and not identity:
        raise RuntimeError(f"prepared {name} image identity missing")
    if identity and not image_identity_matches(actual, identity):
        raise RuntimeError(f"{name} image identity changed: {actual}")


def verify_effective_paths(config: dict) -> None:
    snapshot_paths = {name: Path(entry["path"]).resolve(strict=True)
                      for name, entry in config["input_snapshot"].items()}
    path_snapshots = {
        "client_dir": "client_dir",
        "rut_config_dir": "rut_config_dir",
        "runtime_libs": "runtime_libs",
        "clang": "clang",
        "ld": "ld",
    }
    for path_key, snapshot_name in path_snapshots.items():
        actual = config.get("client_dir") if path_key == "client_dir" else config.get("paths", {}).get(path_key)
        if actual is None or snapshot_name not in snapshot_paths or Path(actual).resolve(strict=True) != snapshot_paths[snapshot_name]:
            raise RuntimeError(f"effective benchmark path {path_key} differs from its prepared input snapshot")
    artifacts = config.get("artifacts", {})
    for path_key, artifact_key in (("rut_rps", "rut_rps"),
                                   ("rut_throughput", "rut_throughput")):
        binary_dir = config.get("paths", {}).get(path_key)
        artifact = artifacts.get(artifact_key, {})
        artifact_path = artifact.get("path")
        if (binary_dir is None or artifact_path is None or
                (Path(binary_dir) / "rut").resolve(strict=True) != Path(artifact_path).resolve(strict=True)):
            raise RuntimeError(f"effective benchmark path {path_key} differs from its prepared artifact")
    compiler_artifacts = (("rut_rps", "rut_rps_compiler"),
                          ("rut_throughput", "rut_throughput_compiler"))
    for path_key, artifact_key in compiler_artifacts:
        binary_dir = config["paths"][path_key]
        artifact_path = artifacts[artifact_key]["path"]
        if (Path(binary_dir) / "rut-compile").resolve(strict=True) != Path(artifact_path).resolve(strict=True):
            raise RuntimeError(f"effective benchmark path {path_key}/rut-compile differs from its prepared artifact")


def verify_worker_mount(config: dict, docker: str) -> None:
    worker = json.loads(invoke([docker, "inspect", config["worker_container"]]).stdout)[0]
    checkpoint = Path(config["checkpoint"]).resolve(strict=True)
    if not any(Path(mount["Source"]).resolve() == checkpoint and
               mount.get("Destination") == config["node_mount"]
               for mount in worker.get("Mounts", [])):
        raise RuntimeError("kind worker checkpoint mount differs from prepared node_mount")


def verify_provenance(config: dict) -> None:
    if "input_snapshot" not in config or "image_identities" not in config:
        raise RuntimeError("benchmark config lacks input/image provenance; rerun prepare.py")
    verify_effective_paths(config)
    try:
        current_snapshot = snapshot_inputs({name: entry["path"]
                                            for name, entry in config["input_snapshot"].items()})
    except (OSError, ValueError) as error:
        raise RuntimeError(f"cannot validate mounted benchmark inputs: {error}") from error
    if current_snapshot != config["input_snapshot"]:
        raise RuntimeError("mounted benchmark inputs changed since prepare.py")
    verify_configmaps(config)
    docker = config["tools"]["docker"]
    verify_worker_mount(config, docker)
    for name, identity in config["image_identities"].items():
        if identity.get("docker_id"):
            actual = invoke([docker, "image", "inspect", "--format", "{{.Id}}", identity["reference"]]).stdout.strip()
            if actual != identity["docker_id"]:
                raise RuntimeError(f"Docker image identity changed for {name}: expected {identity['docker_id']}, got {actual}")
    inventory = json.loads(invoke([docker, "exec", config["worker_container"], "crictl", "images", "-o", "json"]).stdout)
    images = inventory.get("images", [])
    for name, identity in config["image_identities"].items():
        expected_id = identity.get("worker_id")
        if not expected_id:
            raise RuntimeError(f"prepared worker image identity missing for {name}")
        matches = [image for image in images
                   if any(image_reference_matches(identity["reference"], candidate)
                          for candidate in (image.get("repoTags") or []) + (image.get("repoDigests") or []))]
        ids = {image.get("id") for image in matches if image.get("id")}
        if ids != {expected_id}:
            raise RuntimeError(f"kind worker image identity changed for {name}: expected {expected_id}, got {sorted(ids)}")
    verify_client_image_config_identity(config["image_identities"].get("client", {}))


def verify_configmaps(config: dict) -> None:
    expected = config.get("configmap_identities")
    if not expected:
        return
    for name, identity in expected.items():
        result = invoke([config["tools"]["kubectl"], "--kubeconfig", config["kubeconfig"],
                         "get", "configmap", config["configmaps"][name], "-n", config["namespace"], "-o", "json"])
        actual = json.loads(result.stdout)
        if (actual.get("metadata", {}).get("uid") != identity.get("uid") or
                actual.get("data") != identity.get("data") or actual.get("immutable") is not True):
            raise RuntimeError(f"ConfigMap identity or data changed for {name}")


def cleanup_failed_cell(matrix: Matrix, config: dict, cell: dict, error: BaseException) -> str:
    pod_name = f"proxybench-{config['run_id']}-{cell['body']}-{cell['rep']}-{cell['engine']}"
    try:
        cleanup = matrix.kube("delete", "pod", pod_name, "-n", config["namespace"],
                              "--ignore-not-found=true", "--grace-period=1", "--wait=true",
                              check=False, timeout=90)
        details = cleanup.stdout
    except Exception as cleanup_error:
        details = f"cleanup command failed: {cleanup_error}"
    write_json(matrix.samples / "last-failure.json",
               {"cell": cell, "error": str(error), "cleanup": details})
    return details


def run_cell_with_cleanup(matrix: Matrix, config: dict, cell: dict) -> Path:
    try:
        return matrix.run_cell(cell["body"], cell["engine"], cell["rep"])
    except KeyboardInterrupt as error:
        cleanup_failed_cell(matrix, config, cell, error)
        raise
    except Exception as error:
        cleanup_failed_cell(matrix, config, cell, error)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="benchmark.json from prepare.py")
    parser.add_argument("--limit", type=int, default=0, help="optional number of new cells for a smoke run")
    args = parser.parse_args()
    config = load_config(args.config)
    if not config.get("verified_cluster_checks") or not config.get("configmaps_applied"):
        parser.error("run prepare.py --verify-cluster --apply-configmaps before measurement")
    verify_artifacts(config)
    verify_payloads(config)
    verify_provenance(config)
    matrix = Matrix(config, args.config.resolve())
    matrix.samples.mkdir(parents=True, exist_ok=True)
    matrix.freeze_client_config()
    plan_path = matrix.samples / "schedule.json"
    work = plan(int(config["repeats"]))
    if plan_path.exists() and json.loads(plan_path.read_text()) != work:
        raise RuntimeError("existing run schedule does not match the selected benchmark")
    write_json(plan_path, work)
    index_path = matrix.samples / "index.json"
    index = json.loads(index_path.read_text()) if index_path.exists() else []
    keys = {(row["body_size"], row["engine"], row["rep"]) for row in index}
    completed = 0
    for i, cell in enumerate(work, 1):
        key = (cell["body"], cell["engine"], cell["rep"])
        if key in keys:
            continue
        if args.limit and completed >= args.limit:
            break
        label = f"{cell['body']}-{cell['engine']}-r{cell['rep']}"
        expected = matrix.samples / cell["body"] / label
        if expected.exists():
            raise RuntimeError(f"partial output already exists; inspect and move it before resuming: {expected}")
        print(f"START {i}/{len(work)} {label}", flush=True)
        result = run_cell_with_cleanup(matrix, config, cell)
        rel = lambda path: str(path.relative_to(matrix.out))
        index.append({"body_size": cell["body"], "engine": cell["engine"], "rep": cell["rep"],
                      "warmup_dir": rel(result / "warmup"), "measure_dir": rel(result / "measurement"),
                      "valid": True, "validation_path": rel(result / "valid.txt")})
        keys.add(key); completed += 1
        write_json(index_path, index)
        print(f"DONE {i}/{len(work)} {result}", flush=True)
    write_json(matrix.samples / "completed.json", {"count": len(index), "complete": len(index) == len(work)})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"run_matrix: {error}", file=sys.stderr)
        raise SystemExit(2)
