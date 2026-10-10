#!/usr/bin/env python3
"""Serial relay comparisons using the repository's existing benchmark harness."""

import argparse
import concurrent.futures
import contextlib
import copy
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import urllib.request


DEFAULT_SCENARIOS = ("static-close", "static-keepalive", "proxy-close", "proxy-keepalive")


def api_origin_command(source, port, cpus, payload, delay_ms, fragment_bytes, fragment_delay_ms):
    return [sys.executable, str(source.with_name("api_origin.py")), "--port", str(port),
            "--cpus", cpus, "--payload", str(payload), "--delay-ms", str(delay_ms),
            "--fragment-bytes", str(fragment_bytes),
            "--fragment-delay-ms", str(fragment_delay_ms)]


def wait_for_api_origin_ready(log, process, workers):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("API origin exited before readiness")
        ready_workers = sum(line.startswith("API_READY ") for line in log.read_text().splitlines())
        if ready_workers >= workers:
            return
        time.sleep(.05)
    raise RuntimeError("API origin readiness timeout")


def direct_origin_port(args):
    return args.origin_port


def module_valid_origin_reuse(records, expected_markers):
    if not records or [row[0] for row in records] != list(expected_markers):
        return False
    return all(row[1] == records[0][1] and row[2] == records[0][2] + index
               for index, row in enumerate(records))


def valid_fresh_origin_records(records, expected_markers):
    return (len(records) == len(expected_markers)
            and [row[0] for row in records] == list(expected_markers)
            and len({row[1] for row in records}) == len(records)
            and all(row[1] > 0 and row[2] == 1 for row in records))


def valid_api_origin_records(records, expected_markers, fresh_downstream,
                             reuse=True, request_policy="transparent"):
    if not reuse:
        return (len(records) == len(expected_markers)
                and [row[0] for row in records] == list(expected_markers)
                and len({row[1] for row in records}) == len(records)
                and all(row[1] > 0 and row[2] == 1 for row in records))
    if fresh_downstream and request_policy != "omit-connection":
        return (len(records) == len(expected_markers)
                and [row[0] for row in records] == list(expected_markers))
    return module_valid_origin_reuse(records, expected_markers)


def validate_api_origin_workers(origin_workers, cpus, origin_mode):
    if origin_mode == "api" and origin_workers != len(cpus.split(",")):
        raise ValueError("API origin workers must match the number of --origin-cpus")


def distinct_url_scenarios(remaining):
    """Return the scenarios requested in the delegated run.py arguments."""
    for index, argument in enumerate(remaining):
        if argument == "--scenarios":
            values = []
            for value in remaining[index + 1:]:
                if value.startswith("--"):
                    break
                values.append(value)
            return tuple(values) or DEFAULT_SCENARIOS
        if argument.startswith("--scenarios="):
            return tuple(argument.split("=", 1)[1].split(","))
    return DEFAULT_SCENARIOS


def validate_distinct_url_scenarios(scenarios, enabled):
    if enabled and any(scenario.startswith("static-") for scenario in scenarios):
        raise ValueError("--mixed-distinct-urls requires proxy-only scenarios; "
                         "pass --scenarios proxy-close proxy-keepalive")


def validate_api_mixed_payload(origin_mode, mixed_small_bytes):
    if origin_mode == "api" and mixed_small_bytes:
        raise ValueError("mixed-size workloads are not supported with --origin-mode api; "
                         "the API origin serves one payload for every request")


def validate_mixed_small_rate_scenarios(scenarios, enabled):
    if enabled and any(scenario != "proxy-keepalive" for scenario in scenarios):
        raise ValueError("--mixed-small-rate requires keepalive scenarios and specifically "
                         "proxy-keepalive; paced small probe is a proxy workload")


def delegated_option(remaining, name, default=None):
    for index, argument in enumerate(remaining):
        if argument == name:
            return remaining[index + 1] if index + 1 < len(remaining) else default
        if argument.startswith(name + "="):
            return argument.split("=", 1)[1]
    return default


def validate_direct_origin_options(engines, scenarios, remaining):
    if "direct-origin" not in engines:
        return
    if any(scenario.startswith("static-") for scenario in scenarios):
        raise ValueError("direct-origin supports proxy scenarios only")
    if "proxy-keepalive" in scenarios and delegated_option(
            remaining, "--native-origin-reuse", "on") == "off":
        raise ValueError("direct-origin proxy-keepalive requires native origin reuse on")


def validate_paced_tls(enabled, remaining):
    if enabled and (delegated_option(remaining, "--tls-cert") is not None
                    or delegated_option(remaining, "--tls-key") is not None):
        raise ValueError("--mixed-small-rate currently supports plaintext HTTP only")


def mixed_client_valid(sample):
    errors = sample.get("errors", {})
    return (sample.get("requests", 0) > 0
            and math.isfinite(float(sample.get("rps", 0))) and sample["rps"] > 0
            and math.isfinite(float(sample.get("p99_us", 0))) and sample["p99_us"] > 0
            and not any(errors.values())
            and sample.get("valid", True))


def mixed_cpu_masks(value):
    masks = value.split(";") if ";" in value else value.split(",")
    if len(masks) != 2:
        raise ValueError("mixed clients require two CPU masks, e.g. '5,7;6'")
    groups = []
    for mask in masks:
        parts = mask.split(",")
        if not all(part.isdigit() for part in parts):
            raise ValueError("mixed client masks must contain CPU numbers")
        cpus = [int(part) for part in parts]
        if len(cpus) != len(set(cpus)):
            raise ValueError("mixed client mask repeats a CPU")
        groups.append(set(cpus))
    if groups[0] & groups[1]:
        raise ValueError("large and small clients must use disjoint CPUs")
    return tuple(masks)


def cpu_snapshot():
    result = {}
    for line in Path("/proc/stat").read_text().splitlines():
        fields = line.split()
        if fields and fields[0].startswith("cpu") and fields[0][3:].isdigit():
            result[fields[0][3:]] = [int(item) for item in fields[1:9]]
    return result


def cpu_percentages(before, after):
    result = {}
    for cpu, end in after.items():
        if cpu not in before:
            continue
        delta = [a - b for a, b in zip(end, before[cpu])]
        total = sum(delta)
        if total <= 0 or any(value < 0 for value in delta):
            continue
        result[cpu] = dict(user=100 * (delta[0] + delta[1]) / total,
                          system=100 * delta[2] / total,
                          idle=100 * (delta[3] + delta[4]) / total,
                          irq=100 * delta[5] / total,
                          softirq=100 * delta[6] / total,
                          steal=100 * delta[7] / total)
    return result


def small_nginx_location(location, kib):
    small = location.replace("/proxy", "/small", 1)
    return re.sub(r"proxy_buffer_size\s+\S+;\s*proxy_buffers\s+\d+\s+\S+;\s*proxy_busy_buffers_size\s+\S+;",
                  f"proxy_buffer_size {kib}k; proxy_buffers 8 {kib}k; proxy_busy_buffers_size {2 * kib}k;", small)


def distinct_small_route(config):
    """Keep the proxy route and add an adjacent small route with the same policy."""
    route_pattern = re.compile(r'(?m)^([ \t]*route GET "/proxy"[^\r\n]*)(\r?\n|$)')

    def add_small_route(match):
        original = match.group(1)
        newline = match.group(2)
        small = original.replace('"/proxy"', '"/small"', 1)
        return original + newline + small + newline

    updated, count = route_pattern.subn(add_small_route, config)
    if count != 1:
        raise ValueError("expected exactly one native /proxy route")
    return updated


def origin_worker_config(text, workers, cpus, multi_accept, port, reuseport=False, pin=False):
    text = text.replace("worker_processes 1;", f"worker_processes {workers};", 1)
    text = text.replace("worker_connections 8192;", f"worker_connections 8192; multi_accept {multi_accept};", 1)
    if pin:
        mask = [int(cpu) for cpu in cpus.split(",")]
        if len(mask) != workers or len(set(mask)) != workers or any(cpu < 0 for cpu in mask):
            raise ValueError("pinned origin workers require one distinct CPU per worker")
        affinity = " ".join(f"{1 << cpu:b}" for cpu in mask)
        text = text.replace(f"worker_processes {workers};", f"worker_processes {workers};\nworker_cpu_affinity {affinity};", 1)
    if reuseport:
        listen = f"listen 127.0.0.1:{port};"
        if text.count(listen) != 1:
            raise ValueError("expected one native origin listen directive")
        text = text.replace(listen, f"listen 127.0.0.1:{port} reuseport;", 1)
    return text


def main():
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--engines", default="uring,nginx")
    parser.add_argument("--baseline-rut", type=Path)
    parser.add_argument("--origin-workers", type=int, default=4)
    parser.add_argument("--origin-cpus", default="3,4,8,9")
    parser.add_argument("--origin-multi-accept", choices=("on", "off"), default="on")
    parser.add_argument("--origin-reuseport", choices=("on", "off"), default="off")
    parser.add_argument("--origin-pin-workers", action="store_true")
    parser.add_argument("--origin-mode", choices=("native", "api"), default="native")
    parser.add_argument("--api-delay-ms", type=float, default=0)
    parser.add_argument("--api-fragment-bytes", type=int, default=0)
    parser.add_argument("--api-fragment-delay-ms", type=float, default=0)
    parser.add_argument("--mixed-small-bytes", type=int, default=0)
    parser.add_argument("--small-connections", type=int, default=32)
    parser.add_argument("--mixed-small-rate", type=int, default=0,
                        help="planned small requests/s; 0 retains saturation wrk")
    parser.add_argument("--mixed-client-cpus", default="7,5",
                        help="large;small CPU masks, e.g. '5,7;6'; legacy '7,5' works")
    parser.add_argument("--mixed-distinct-urls", action="store_true",
                        help="send small requests to /small rather than a header-selected /proxy")
    parser.add_argument("--nginx-buffering", choices=("on", "off"), default="off")
    parser.add_argument("--nginx-buffer-kib", type=int, default=1024)
    parser.add_argument("--nginx-small-buffer-kib", type=int, default=16)
    options, remaining = parser.parse_known_args()
    if not any(arg == "--origin-cpu" or arg.startswith("--origin-cpu=") for arg in remaining):
        remaining += ["--origin-cpu", options.origin_cpus.split(",")[0]]
    engines = options.engines.split(",")
    if not engines or any(e not in ("uring", "baseline-uring", "epoll", "nginx", "direct-origin") for e in engines):
        parser.error("--engines must contain uring, baseline-uring, epoll, nginx or direct-origin")
    if "baseline-uring" in engines and options.baseline_rut is None:
        parser.error("baseline-uring requires --baseline-rut and its matching rut-compile")
    if options.origin_workers < 1 or options.nginx_buffer_kib < 16 or options.nginx_small_buffer_kib < 16:
        parser.error("origin workers must be positive; nginx buffers must be at least 16KiB")
    if (options.mixed_small_bytes < 0 or options.small_connections < 1
            or options.mixed_small_rate < 0 or options.api_delay_ms < 0
            or options.api_fragment_bytes < 0 or options.api_fragment_delay_ms < 0):
        parser.error("invalid mixed workload size or connection count")
    try:
        mixed_masks = mixed_cpu_masks(options.mixed_client_cpus)
    except ValueError as error:
        parser.error(str(error))
    if options.mixed_small_rate and not options.mixed_small_bytes:
        parser.error("--mixed-small-rate requires --mixed-small-bytes")
    if options.mixed_distinct_urls and not options.mixed_small_bytes:
        parser.error("--mixed-distinct-urls requires --mixed-small-bytes")
    try:
        validate_api_mixed_payload(options.origin_mode, options.mixed_small_bytes)
    except ValueError as error:
        parser.error(str(error))
    try:
        validate_api_origin_workers(options.origin_workers, options.origin_cpus, options.origin_mode)
    except ValueError as error:
        parser.error(str(error))
    try:
        scenarios = distinct_url_scenarios(remaining)
        validate_distinct_url_scenarios(scenarios, options.mixed_distinct_urls)
        validate_mixed_small_rate_scenarios(scenarios, bool(options.mixed_small_rate))
        validate_direct_origin_options(engines, scenarios, remaining)
        validate_paced_tls(bool(options.mixed_small_rate), remaining)
    except ValueError as error:
        parser.error(str(error))
    source = Path(__file__).with_name("run.py")
    sys.path.insert(0, str(source.parent))
    if "--help" in remaining:
        print(parser.format_help())
    spec = importlib.util.spec_from_file_location("relay_bench", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.argv = [str(source), *remaining]
    module.engine_order = lambda first, rep: tuple(engines[(rep - 1) % len(engines):] + engines[:(rep - 1) % len(engines)])
    command = module.Harness.command

    def labelled(self, argv, *args, **kwargs):
        if len(argv) > 1 and argv[0] == "docker" and argv[1] in ("run", "create"):
            argv = argv[:2] + ["--security-opt", "label=disable"] + argv[2:]
        if options.mixed_small_bytes and "-s" in argv:
            lua = Path(argv[argv.index("-s") + 1])
            if lua.name.endswith("-small.lua"):
                script = lua.read_text()
                if options.mixed_distinct_urls:
                    script = script.replace('wrk.path="/proxy"', 'wrk.path="/small"')
                lua.write_text('wrk.headers["X-Payload"]="small"\n' + script)
        return command(self, argv, *args, **kwargs)

    module.Harness.command = labelled
    original_wrk = module.Harness.wrk

    def with_cpu_stats(self, *args, **kwargs):
        before = cpu_snapshot()
        result = original_wrk(self, *args, **kwargs)
        result["host_cpu_pct"] = cpu_percentages(before, cpu_snapshot())
        return result

    module.Harness.wrk = with_cpu_stats
    nginx = module.Harness.nginx

    @contextlib.contextmanager
    def origin(self, name, config, cpu, port):
        if name == "origin":
            if self.args.proxy_profile != "native-streaming" and any(
                scenario.startswith("proxy-") for scenario in self.args.scenarios
            ):
                raise ValueError("relay comparisons require --proxy-profile native-streaming")
            if options.mixed_small_bytes and self.tls_context:
                raise ValueError("mixed-size preflight currently supports plaintext HTTP only")
            cpu = options.origin_cpus
            if options.origin_mode == "api":
                payload = self.out / "api-payload.bin"
                payload.write_bytes(module.expected_body("proxy", getattr(self.args, "body_size", None), True))
                argv = api_origin_command(source, port, options.origin_cpus, payload,
                                          options.api_delay_ms, options.api_fragment_bytes,
                                          options.api_fragment_delay_ms)
                origin_log = self.out / "api-origin.log"
                log_handle = origin_log.open("w+")
                child = subprocess.Popen(argv, stdout=log_handle, stderr=subprocess.STDOUT)
                self.origin_pid = child.pid
                try:
                    wait_for_api_origin_ready(origin_log, child, len(options.origin_cpus.split(",")))
                    yield child.pid
                finally:
                    if child.poll() is None:
                        child.terminate()
                    child.wait(timeout=5)
                    log_handle.close()
                return
            path = self.out / config
            text = origin_worker_config(path.read_text(), options.origin_workers, options.origin_cpus,
                                        options.origin_multi_accept, port,
                                        options.origin_reuseport == "on", options.origin_pin_workers)
            if options.mixed_small_bytes:
                (self.out / "payloads" / "small").write_bytes(b"Z" * options.mixed_small_bytes)
                if options.mixed_distinct_urls:
                    text = text.replace("location / {", "location = /small { alias /benchmark-payloads/small; default_type application/octet-stream; etag off; max_ranges 0; } location / {", 1)
                else:
                    text = text.replace("server {", "map $http_x_payload $payload_file { default /benchmark-payloads/proxy; small /benchmark-payloads/small; }\nserver {", 1)
                    text = text.replace("location / {", "location = /proxy { alias $payload_file; default_type application/octet-stream; etag off; max_ranges 0; } location / {", 1)
            path.write_text(text)
            metadata = self.out / "environment.json"
            data = json.loads(metadata.read_text())
            data["relay_compare"] = vars(options) | {"baseline_rut": str(options.baseline_rut) if options.baseline_rut else None}
            data["origin_cpu"] = cpu
            data["origin_workers"] = options.origin_workers
            metadata.write_text(json.dumps(data, indent=2) + "\n")
        with nginx(self, name, config, cpu, port) as pid:
            if name == "origin" and options.origin_pin_workers:
                workers = []
                for attempt in range(100):
                    workers = []
                    children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
                    for child in children:
                        try:
                            if b"nginx: worker process" not in Path(f"/proc/{child}/cmdline").read_bytes():
                                continue
                            status = Path(f"/proc/{child}/status").read_text()
                            allowed = next(line.split(":", 1)[1].strip() for line in status.splitlines()
                                           if line.startswith("Cpus_allowed_list:"))
                            workers.append(dict(pid=int(child), cpu_mask=allowed))
                        except FileNotFoundError:
                            continue
                    if len(workers) == options.origin_workers and {w["cpu_mask"] for w in workers} == set(options.origin_cpus.split(",")):
                        break
                    time.sleep(.01)
                else:
                    raise RuntimeError(f"origin worker affinity mismatch: {workers}")
                (self.out / "origin-worker-affinity.json").write_text(json.dumps(workers, indent=2) + "\n")
            if name == "origin":
                self.origin_pid = pid
            yield pid

    module.Harness.nginx = origin
    original_verify_origin_reuse = module.Harness.verify_origin_reuse

    def verify_api_origin_reuse(self, expected_markers, fresh_downstream=False):
        if options.origin_mode != "api":
            return original_verify_origin_reuse(self, expected_markers, fresh_downstream)
        logs = (self.out / "api-origin.log").read_text()
        (self.out / f"{self.active_label}-origin-reuse.log").write_text(logs)
        records = module.origin_reuse_records(logs, expected_markers)
        reuse = (getattr(self.args, "native_origin_reuse", "on") == "on"
                 if getattr(self.args, "proxy_profile", "converter-strict") == "native-streaming"
                 else getattr(self.args, "bounded_origin_reuse", "off") == "on")
        policy = getattr(self.args, "native_request_policy", "transparent")
        if not valid_api_origin_records(records, expected_markers, fresh_downstream, reuse, policy):
            raise ValueError("API origin reuse evidence did not match expected markers")

    module.Harness.verify_origin_reuse = verify_api_origin_reuse
    frontend = module.Harness.frontend
    original_popen = subprocess.Popen
    active_backend = None
    active_output = None
    active_rut = None
    frontend_live = False
    active_engine = None

    original_verify_origin_reuse = module.Harness.verify_origin_reuse

    def verify_origin_reuse(self, expected_markers, fresh_downstream=False):
        if active_engine != "direct-origin" or not fresh_downstream:
            return original_verify_origin_reuse(self, expected_markers, fresh_downstream)
        logs = ((self.out / "api-origin.log").read_text()
                if options.origin_mode == "api"
                else self.command(["docker", "logs", getattr(self, "origin_container_id", "")]).stdout)
        marker_prefix = expected_markers[0].rsplit("-", 1)[0]
        (self.out / f"{marker_prefix}-origin-reuse.log").write_text(logs)
        records = module.origin_reuse_records(logs, expected_markers)
        # The direct-origin engine has no frontend policy layer to strip
        # Connection: close, so every close request must use a fresh origin
        # connection even when the Rut frontend policy omits that header.
        valid = valid_fresh_origin_records(records, expected_markers)
        if not valid:
            raise ValueError(f"direct-origin close preflight expected fresh origin connections: {records!r}")

    module.Harness.verify_origin_reuse = verify_origin_reuse

    def selected(argv, *args, **kwargs):
        if isinstance(argv, list) and argv and argv[0] == "taskset" and active_backend and active_output:
            if len(argv) > 3 and active_rut is not None and Path(argv[3]) == Path(active_rut):
                argv = argv + ["--backend", active_backend]
                with (active_output / "effective-rut-commands.jsonl").open("a") as handle:
                    handle.write(json.dumps([str(x) for x in argv]) + "\n")
        return original_popen(argv, *args, **kwargs)

    subprocess.Popen = selected

    @contextlib.contextmanager
    def chosen_frontend(self, engine, work, label):
        nonlocal active_backend, active_output, active_rut, frontend_live, active_engine
        if frontend_live:
            raise RuntimeError("frontends must run serially")
        frontend_live = True
        active_engine = engine
        if engine == "direct-origin":
            saved_port = self.args.front_port
            self.active_label = label
            self.args.front_port = direct_origin_port(self.args)
            try:
                yield self.origin_pid
            finally:
                self.args.front_port = saved_port
                frontend_live = False
                active_engine = None
            return
        active_backend = "epoll" if engine == "epoll" else "io_uring"
        active_output = self.out
        saved_rut = self.args.rut
        config = self.out / (work + "-nginx.conf")
        saved = config.read_text()
        rut_config = self.out / (work + ".rut")
        saved_rut_config = rut_config.read_text()
        if options.mixed_distinct_urls:
            rut_config.write_text(distinct_small_route(saved_rut_config))
            (self.out / (label + "-effective.rut")).write_text(rut_config.read_text())
        try:
            if engine == "baseline-uring":
                self.args.rut = options.baseline_rut.resolve()
            active_rut = self.args.rut
            if engine == "nginx" and work == "proxy":
                size = options.nginx_buffer_kib
                header = size if options.nginx_buffering == "off" else 16
                busy = size if options.nginx_buffering == "off" else 2 * size
                text, replacements = re.subn(
                    r"proxy_buffering\s+(?:on|off);\s*proxy_buffer_size\s+\S+;\s*(?:proxy_buffers\s+\d+\s+\S+;\s*)?proxy_busy_buffers_size\s+\S+;",
                    f"proxy_buffering {options.nginx_buffering}; proxy_buffer_size {header}k; proxy_buffers 8 {size}k; proxy_busy_buffers_size {busy}k; proxy_max_temp_file_size 0;",
                    saved,
                )
                if replacements != 1:
                    raise ValueError("expected exactly one native proxy buffer configuration")
                if options.mixed_distinct_urls:
                    location = re.search(r"location = /proxy \{[^{}]*\}", text)
                    if location is None:
                        raise ValueError("expected native /proxy location")
                    text = text[:location.start()] + small_nginx_location(location.group(), options.nginx_small_buffer_kib) + " " + text[location.start():]
                config.write_text(text)
                (self.out / (label + "-effective-nginx.conf")).write_text(text)
            with frontend(self, engine, work, label) as pid:
                if engine != "nginx":
                    if "Backend: " + active_backend not in (self.out / (label + "-server.log")).read_text():
                        raise RuntimeError("runtime selected an unexpected backend")
                if options.mixed_small_bytes:
                    small_path = "/small" if options.mixed_distinct_urls else "/proxy"
                    request = urllib.request.Request(f"http://127.0.0.1:{self.args.front_port}{small_path}", headers={"Host": "client.example", "X-Payload": "small"})
                    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response:
                        if response.read() != b"Z" * options.mixed_small_bytes:
                            raise RuntimeError("small payload preflight failed")
                yield pid
        finally:
            self.args.rut = saved_rut
            config.write_text(saved)
            rut_config.write_text(saved_rut_config)
            frontend_live = False
            active_engine = None
            active_backend = active_output = None
            active_rut = None

    module.Harness.frontend = chosen_frontend
    if options.mixed_small_bytes:
        lock = threading.Lock()
        save_json = module.save_json

        def serialized_save_json(path, value):
            with lock:
                save_json(path, value)

        module.save_json = serialized_save_json
        wrk = module.Harness.wrk

        def paced_small(self, work, close, concurrency, duration, label):
            if close or self.tls_context:
                raise ValueError("paced small probe supports plaintext keepalive only")
            before = cpu_snapshot()
            cpu_file = self.out / (label + ".cpu")
            probe = Path(__file__).with_name("paced_http_client.py")
            result = self.command(["/usr/bin/time", "-f", "%U %S", "-o", cpu_file,
                                   "taskset", "-c", self.args.client_cpus, sys.executable, probe,
                                   "--port", str(self.args.front_port), "--path", "/small" if options.mixed_distinct_urls else "/proxy",
                                   "--body-size", str(options.mixed_small_bytes), "--connections", str(concurrency),
                                   "--rate", str(options.mixed_small_rate), "--duration", str(duration)], timeout=duration + 15)
            (self.out / (label + ".log")).write_text(result.stdout + result.stderr)
            sample = json.loads(result.stdout)
            sample["client_cpu_seconds"] = sum(map(float, cpu_file.read_text().split()))
            sample["host_cpu_pct"] = cpu_percentages(before, cpu_snapshot())
            return sample

        def mixed_wrk(self, work, close, concurrency, duration, label):
            if concurrency <= options.small_connections:
                raise ValueError("concurrency must exceed --small-connections")
            big_cpu, small_cpu = mixed_masks
            big, small = copy.copy(self), copy.copy(self)
            big.args, small.args = copy.copy(self.args), copy.copy(self.args)
            big.args.client_cpus, small.args.client_cpus = big_cpu, small_cpu
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                large_future = pool.submit(wrk, big, work, close, concurrency - options.small_connections, duration, label + "-large")
                small_future = pool.submit(paced_small if options.mixed_small_rate else wrk,
                                           small, work, close, options.small_connections, duration, label + "-small")
                large, little = large_future.result(), small_future.result()
            result = dict(large)
            result.update(large_client=large, small_client=little)
            result["errors"] = {key: large["errors"][key] + little["errors"][key] for key in large["errors"]}
            result["valid"] = mixed_client_valid(large) and mixed_client_valid(little)
            for key in ("requests", "rps", "client_cpu_seconds"):
                result[key] = large[key] + little[key]
            return result

        module.Harness.wrk = mixed_wrk
    return module.main()


if __name__ == "__main__":
    sys.exit(main())
