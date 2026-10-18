#!/usr/bin/env python3
"""Controlled copy/splice tunnel experiment in a shared container netns.

Uses nginx_benchmark's exact-body, slow-reader, successor, and origin-reuse
preflights. This is a mechanism probe, not a Rut L7 compatibility benchmark.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent / "nginx_benchmark"))
import run as base


def cpu_usage(pid):
    ids = [pid] + [int(p) for p in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]
    user = system = rss = 0
    for child in ids:
        fields = Path(f"/proc/{child}/stat").read_text().rsplit(")", 1)[1].split()
        user += int(fields[11])
        system += int(fields[12])
        rss += int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
    hz = os.sysconf("SC_CLK_TCK")
    return user / hz, system / hz, rss


def machine_cpu():
    # Includes unbound kernel workers, but also unrelated host activity. These
    # counters are observations, not exclusive attribution to the benchmark.
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    values = list(map(int, fields))
    return sum(values[i] for i in (0, 1, 2, 5, 6, 7)) / os.sysconf("SC_CLK_TCK")


def machine_cpu_by_cpu():
    hz = os.sysconf("SC_CLK_TCK")
    result = {}
    for line in Path("/proc/stat").read_text().splitlines():
        fields = line.split()
        if not fields[0].startswith("cpu"):
            continue
        values = list(map(int, fields[1:]))
        result[fields[0]] = sum(values[i] for i in (0, 1, 2, 5, 6, 7)) / hz
    return result


class RelayHarness(base.Harness):
    def prepare(self):
        a = self.args
        # The existing native preflight deliberately has a fixed body size.
        # Override it only in this standalone experiment, never in its CLI.
        base.NATIVE_BODY_SIZE = a.body_size
        self.command(["docker", "info", "--format", "{{.ServerVersion}}"])
        image = json.loads(self.command(["docker", "image", "inspect", self.image]).stdout)[0]
        payloads = self.out / "payloads"
        payloads.mkdir()
        (payloads / "proxy").write_bytes(base.expected_body("proxy", native_streaming=True))
        observations = (
            'map $http_x_rut_benchmark_preflight $benchmark_preflight { default 0; ~.+ 1; }\n'
            'log_format rut_preflight "marker=$http_x_rut_benchmark_preflight '
            'connection=$connection requests=$connection_requests";\n'
        )
        origin = (
            f"server {{ listen {a.origin_port}; keepalive_timeout 60; "
            "keepalive_requests 1000000000; "
            "access_log /dev/stdout rut_preflight if=$benchmark_preflight; "
            "location / { root /benchmark-payloads; default_type application/octet-stream; "
            'etag off; max_ranges 0; add_header Last-Modified ""; } }'
        )
        (self.out / "origin.conf").write_text(self.nginx_config(origin, observations))
        base.save_json(self.out / "environment.json", {
            "source_head": self.command(["git", "-C", base.ROOT, "rev-parse", "HEAD"]).stdout.strip(),
            "dirty": bool(self.command(["git", "-C", base.ROOT, "status", "--porcelain"]).stdout),
            "arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(a).items()},
            "kernel": list(os.uname()),
            "cpu_topology": self.command(["lscpu"]).stdout,
            "nginx_image": self.image,
            "nginx_image_id": image["Id"],
            "sha256": {str(p): base.sha256(p) for p in (a.relay, a.wrk, a.loader, a.libc)},
            "topology": "relay joins origin container network namespace; client enters published port",
            "relay_security": ("uid/gid 0, BPF+NET_ADMIN only, label=disable, no-new-privileges, default seccomp"
                               if a.include_ebpf else "uid/gid 65532, cap-drop ALL, no-new-privileges, Docker default seccomp"),
            "mode": "raw bidirectional TCP tunnel; no HTTP policy, routing, TLS, or body inspection",
            "batch_bytes": 65536,
            "tcp_nodelay": True,
            "preflight": "exact body, delayed reader + successor, 100 sequential requests, exact origin reuse",
            "note": "RSS excludes kernel pipe/socket memory; native preflight body override is local to this runner",
            "ebpf_scope": "optional whole upstream L4 stream; no L7 body takeover or Rut serving-loop integration",
            "machine_cpu_scope": "whole-host /proc/stat busy execution, includes background activity and both endpoints",
        })

    @contextlib.contextmanager
    def origin(self):
        a = self.args
        origin_cpus = a.origin_cpu if a.origin_affinity == "dedicated" else ",".join(
            sorted(set(a.server_cpus.split(",")) | {str(a.origin_cpu)}, key=int))
        cid = self.command([
            "docker", "create", "--pull=never", "--name", self.prefix + "-origin",
            "--cpuset-cpus", origin_cpus, "--ulimit", "nofile=65536:65536",
            "--publish", f"127.0.0.1:{a.front_port}:{a.front_port}",
            "--publish", f"127.0.0.1:{a.origin_port}:{a.origin_port}",
            "--mount", f"type=bind,src={self.out / 'origin.conf'},dst=/etc/nginx/nginx.conf,readonly",
            "--mount", f"type=bind,src={self.out / 'payloads'},dst=/benchmark-payloads,readonly",
            self.image, "nginx", "-g", "daemon off;",
        ]).stdout.strip()
        self.origin_container_id = cid
        try:
            self.command(["docker", "start", cid])
            pid = int(self.command(["docker", "inspect", "-f", "{{.State.Pid}}", cid]).stdout)
            self.ready(a.origin_port, pid)
            yield pid
        finally:
            self.finish_container(cid, "origin", check_exit=False)

    def finish_container(self, cid, label, check_exit=True):
        try:
            self.command(["docker", "stop", "-t", "2", cid])
            logs = self.command(["docker", "logs", cid])
            text = logs.stdout + logs.stderr
            (self.out / (label + "-server.log")).write_text(text)
            exit_code = int(self.command(["docker", "inspect", "-f", "{{.State.ExitCode}}", cid]).stdout)
            if check_exit:
                matches = re.findall(r"^COUNTERS (.+)$", text, re.MULTILINE)
                if exit_code != 0 or len(matches) != 1:
                    raise RuntimeError(f"relay did not stop cleanly: {label}, exit={exit_code}")
                counters = json.loads(matches[0])
                if counters["setup_failures"]:
                    raise RuntimeError(f"relay setup failures: {counters}")
                base.save_json(self.out / (label + "-counters.json"), counters)
        finally:
            self.command(["docker", "rm", "-f", cid])

    @contextlib.contextmanager
    def frontend(self, engine, work, label):
        a = self.args
        self.active_label = label
        cid = self.command([
            "docker", "create", "--pull=never", "--name", self.prefix + "-" + label,
            "--network", "container:" + self.origin_container_id,
            "--cpuset-cpus", a.server_cpus, "--ulimit", "nofile=65536:65536",
            "--user", "0:0" if a.include_ebpf else "65532:65532", "--cap-drop", "ALL",
            *(["--cap-add", "BPF", "--cap-add", "NET_ADMIN", "--security-opt", "label=disable"]
              if a.include_ebpf else []),
            "--stop-signal", "SIGTERM",
            "--security-opt", "no-new-privileges=true",
            "--mount", f"type=bind,src={a.relay},dst=/benchmark-relay,readonly",
            "--mount", f"type=bind,src={a.loader},dst=/benchmark-lib/loader,readonly",
            "--mount", f"type=bind,src={a.libc},dst=/benchmark-lib/libc.so.6,readonly",
            "--entrypoint", "/benchmark-lib/loader", self.image,
            "--library-path", "/benchmark-lib", "/benchmark-relay", engine,
            str(a.front_port), str(a.origin_port),
        ]).stdout.strip()
        self.active_container_id = cid
        try:
            self.command(["docker", "start", cid])
            pid = int(self.command(["docker", "inspect", "-f", "{{.State.Pid}}", cid]).stdout)
            self.ready(a.front_port, pid)
            isolation = {
                "relay_netns": self.command(["docker", "exec", cid, "readlink", "/proc/self/ns/net"]).stdout.strip(),
                "origin_netns": self.command(["docker", "exec", self.origin_container_id, "readlink", "/proc/self/ns/net"]).stdout.strip(),
                "process_status": Path(f"/proc/{pid}/status").read_text(),
                "docker_security": json.loads(self.command(["docker", "inspect", cid]).stdout)[0]["HostConfig"],
            }
            base.save_json(self.out / (label + "-isolation.json"), isolation)
            if isolation["relay_netns"] != isolation["origin_netns"]:
                raise RuntimeError("relay and origin do not share a network namespace")
            fields = dict(line.split(":", 1) for line in isolation["process_status"].splitlines() if ":" in line)
            expected_caps = (1 << 39) | (1 << 12) if a.include_ebpf else 0
            if int(fields["CapEff"].strip(), 16) != expected_caps or fields["NoNewPrivs"].strip() != "1":
                raise RuntimeError("relay privilege conditions do not match the experiment")
            expected_uid = fields["Uid"].split()[0] if a.include_ebpf else "65532"
            # User-namespace remapping can expose a mapped host UID for container
            # root. The structured Docker config records the requested 0:0 UID.
            if fields["Uid"].split() != [expected_uid] * 4 or fields["Seccomp"].strip() != "2":
                raise RuntimeError("relay uid/seccomp conditions do not match the experiment")
            yield pid
        finally:
            self.finish_container(cid, label)

    def benchmark(self, origin_pid):
        self.origin_pid = origin_pid
        for rep in range(1, self.args.repeats + 1):
            first = self.args.first_engine
            engines = ("copy", "ebpf") if self.args.include_ebpf else ("copy", "splice")
            ordered = (first,) + tuple(engine for engine in engines if engine != first)
            order = ordered if rep % 2 else tuple(reversed(ordered))
            for engine in order:
                label = f"relay-{engine}-r{rep}"
                with self.frontend(engine, "proxy", label) as pid:
                    self.validate_native_keepalive("proxy")
                    print(label, "full preflight PASS", flush=True)
                    for concurrency in self.args.concurrency:
                        tag = label + f"-c{concurrency}"
                        warm = self.wrk("proxy", False, concurrency, self.args.warmup, tag + "-warmup")
                        user0, sys0, _ = cpu_usage(pid)
                        origin0, _ = base.proc_usage(origin_pid)
                        machine0 = machine_cpu_by_cpu()
                        result = self.wrk("proxy", False, concurrency, self.args.duration, tag)
                        user1, sys1, rss = cpu_usage(pid)
                        origin1, _ = base.proc_usage(origin_pid)
                        machine1 = machine_cpu_by_cpu()
                        result.update(
                            engine=engine, rep=rep, concurrency=concurrency,
                            body_size=self.args.body_size, transport="http", connection="keepalive",
                            proxy_profile="kernel-relay-mechanism", warmup_errors=warm["errors"],
                            server_user_seconds=user1-user0, server_system_seconds=sys1-sys0,
                            server_cpu_pct=100*(user1-user0+sys1-sys0)/result["seconds"],
                            origin_cpu_pct=100*(origin1-origin0)/result["seconds"],
                            server_rss_bytes=rss,
                            machine_busy_seconds=machine1["cpu"]-machine0["cpu"],
                            machine_cpu_by_cpu={key: machine1[key]-value for key, value in machine0.items()},
                            valid=bool(result["requests"]) and not any(result["errors"].values())
                                and bool(warm["requests"]) and not any(warm["errors"].values()),
                        )
                        self.results.append(result)
                        base.save_json(self.out / "results.json", self.results)
                        # Post-load observation, outside the timed interval. Includes
                        # kernel charges omitted by RSS; not a synchronized peak.
                        memory = self.command([
                            "docker", "exec", self.active_container_id,
                            "cat", "/sys/fs/cgroup/memory.stat",
                        ]).stdout
                        (self.out / (tag + "-memory.stat")).write_text(memory)
                        print(json.dumps(result), flush=True)
        return all(r["valid"] for r in self.results)


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--relay", type=Path, required=True)
    p.add_argument("--wrk", type=Path, required=True)
    p.add_argument("--loader", type=Path, required=True, help="matching host libc ELF loader")
    p.add_argument("--libc", type=Path, required=True, help="host libc; mounted read-only, no image package install")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--body-size", type=base.positive, default=1048576)
    p.add_argument("--concurrency", nargs="+", type=base.positive, default=[1, 32])
    p.add_argument("--first-engine", choices=("copy", "splice", "ebpf"), default="copy")
    p.add_argument("--include-ebpf", action="store_true", help="compare copy/eBPF instead of copy/splice, with BPF+NET_ADMIN capabilities")
    p.add_argument("--origin-affinity", choices=("dedicated", "shared"), default="dedicated",
                   help="shared allows origin on the union of server and origin CPUs; total physical core budget is unchanged")
    p.add_argument("--front-port", type=int, default=8087)
    p.add_argument("--origin-port", type=int, default=9087)
    base.add_cpu_arguments(p)
    base.add_measurement_arguments(p, full_duration=8)
    a = p.parse_args()
    base.resolve_measurement_arguments(a)
    base.normalize_cpu_arguments(p, a)
    base.validate_cpu_topology(p, a)
    if a.first_engine == "ebpf" and not a.include_ebpf:
        p.error("first-engine ebpf requires --include-ebpf")
    if a.include_ebpf and a.first_engine == "splice":
        p.error("the eBPF experiment compares copy/ebpf; first-engine splice is unavailable")
    if a.workers != 1:
        p.error("relay probe has one worker")
    if a.body_size % 4096 or a.body_size > 1048576:
        p.error("body size must be a multiple of 4096, at most 1 MiB")
    if len(set(a.concurrency)) != len(a.concurrency) or max(a.concurrency) > 256:
        p.error("concurrency must be unique and at most 256")
    for key in ("relay", "wrk", "loader", "libc"):
        path = getattr(a, key).resolve()
        if not path.is_file():
            p.error(f"missing file: {path}")
        setattr(a, key, path)
    if a.front_port == a.origin_port or any(not 1024 <= port <= 9999 for port in (a.front_port, a.origin_port)):
        p.error("ports must be distinct unprivileged four-digit ports")
    for port in (a.front_port, a.origin_port):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError as error:
                p.error(str(error))
    a.output = a.output.resolve()
    if a.output.exists() and (not a.output.is_dir() or any(a.output.iterdir())):
        p.error("output must be new or empty")
    a.output.mkdir(parents=True, exist_ok=True)
    a.proxy_profile = "native-streaming"  # select the reusable preflight, not production performance acceptance
    a.keepalive_header = "implicit"
    a.tls_cert = a.tls_key = None
    return a


def main():
    a = arguments()
    status = {"complete": False, "valid": False}
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        h = RelayHarness(a)
        h.prepare()
        with h.origin() as origin_pid:
            valid = h.benchmark(origin_pid)
        status.update(complete=True, valid=valid)
        return 0 if valid else 1
    except (Exception, KeyboardInterrupt) as error:
        status["error"] = repr(error)
        print(repr(error), file=sys.stderr)
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous)
        base.save_json(a.output / "status.json", status)


if __name__ == "__main__":
    sys.exit(main())
