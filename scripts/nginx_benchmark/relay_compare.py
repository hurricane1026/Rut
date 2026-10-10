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
import time
import threading
import urllib.request


def api_origin_command(source, port, cpus, payload, delay_ms, fragment_bytes, fragment_delay_ms,
                       small_payload=None, small_path="/api4k"):
    command = [sys.executable, str(source.with_name("api_origin.py")), "--port", str(port),
            "--cpus", cpus, "--payload", str(payload), "--delay-ms", str(delay_ms),
            "--fragment-bytes", str(fragment_bytes),
            "--fragment-delay-ms", str(fragment_delay_ms)]
    if small_payload is not None:
        command += ["--small-payload", str(small_payload), "--small-path", small_path]
    return command


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


def valid_api_origin_records(records, expected_markers, fresh_downstream):
    if fresh_downstream:
        return (len(records) == len(expected_markers)
                and [row[0] for row in records] == list(expected_markers))
    return module_valid_origin_reuse(records, expected_markers)


def module_valid_origin_reuse(records, expected_markers):
    if not records or [row[0] for row in records] != list(expected_markers):
        return False
    return all(row[1] == records[0][1] and row[2] == records[0][2] + index
               for index, row in enumerate(records))


def mixed_clients_valid(large, small):
    return all(
        isinstance(client.get("requests"), int) and client["requests"] > 0
        and isinstance(client.get("errors"), dict)
        and bool(client["errors"])
        and not any(client["errors"].values())
        and isinstance(client.get("p99_us"), (int, float))
        and math.isfinite(client["p99_us"]) and client["p99_us"] > 0
        for client in (large, small)
    )


def main():
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--engines", default="uring,nginx")
    parser.add_argument("--baseline-rut", type=Path)
    parser.add_argument("--origin-workers", type=int, default=4)
    parser.add_argument("--origin-cpus", default="3,4,8,9")
    parser.add_argument("--origin-multi-accept", choices=("on", "off"), default="on")
    parser.add_argument("--mixed-small-bytes", type=int, default=0)
    parser.add_argument("--mixed-small-path", default="/api4k")
    parser.add_argument("--small-connections", type=int, default=32)
    parser.add_argument("--mixed-client-cpus", default="7,5")
    parser.add_argument("--nginx-buffering", choices=("on", "off"), default="off")
    parser.add_argument("--nginx-buffer-kib", type=int, default=1024)
    parser.add_argument("--origin-mode", choices=("native", "api"), default="native")
    parser.add_argument("--api-delay-ms", type=float, default=0)
    parser.add_argument("--api-fragment-bytes", type=int, default=0)
    parser.add_argument("--api-fragment-delay-ms", type=float, default=0)
    options, remaining = parser.parse_known_args()
    if not any(arg == "--origin-cpu" or arg.startswith("--origin-cpu=") for arg in remaining):
        remaining += ["--origin-cpu", options.origin_cpus.split(",")[0]]
    engines = options.engines.split(",")
    if not engines or any(e not in ("direct-origin", "uring", "baseline-uring", "epoll", "nginx") for e in engines):
        parser.error("--engines must contain direct-origin, uring, baseline-uring, epoll or nginx")
    if "baseline-uring" in engines and options.baseline_rut is None:
        parser.error("baseline-uring requires --baseline-rut and its matching rut-compile")
    if options.origin_workers < 1 or options.nginx_buffer_kib < 16:
        parser.error("origin workers must be positive; nginx buffers must be at least 16KiB")
    if options.mixed_small_bytes < 0 or options.small_connections < 1:
        parser.error("invalid mixed workload size or connection count")
    if (not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+", options.mixed_small_path)
            or options.mixed_small_path == "/proxy"):
        parser.error("--mixed-small-path must be a non-root absolute path")
    if (options.api_delay_ms < 0 or options.api_fragment_bytes < 0
            or options.api_fragment_delay_ms < 0):
        parser.error("API origin delays and fragment size must be nonnegative")
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
        return command(self, argv, *args, **kwargs)

    module.Harness.command = labelled
    nginx = module.Harness.nginx

    @contextlib.contextmanager
    def origin(self, name, config, cpu, port):
        if name == "origin":
            if self.args.proxy_profile != "native-streaming":
                raise ValueError("relay comparisons require --proxy-profile native-streaming")
            if options.mixed_small_bytes and self.tls_context:
                raise ValueError("mixed-size preflight currently supports plaintext HTTP only")
            cpu = options.origin_cpus
            if options.origin_mode == "api":
                payload = self.out / "api-payload.bin"
                payload.write_bytes(module.expected_body("proxy", getattr(self.args, "body_size", None), True))
                small_payload = self.out / "api-small-payload.bin"
                small_payload.write_bytes(b"Z" * options.mixed_small_bytes)
                argv = api_origin_command(source, port, options.origin_cpus, payload,
                                          options.api_delay_ms, options.api_fragment_bytes,
                                          options.api_fragment_delay_ms,
                                          small_payload if options.mixed_small_bytes else None,
                                          options.mixed_small_path)
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
            text = path.read_text().replace("worker_processes 1;", f"worker_processes {options.origin_workers};")
            text = text.replace("worker_connections 8192;", f"worker_connections 8192; multi_accept {options.origin_multi_accept};")
            if options.mixed_small_bytes:
                (self.out / "payloads" / "small").write_bytes(b"Z" * options.mixed_small_bytes)
                text = text.replace("location / {", f"location = /proxy {{ alias /benchmark-payloads/proxy; default_type application/octet-stream; etag off; max_ranges 0; }} location = {options.mixed_small_path} {{ alias /benchmark-payloads/small; default_type application/octet-stream; etag off; max_ranges 0; }} location / {{", 1)
            path.write_text(text)
            metadata = self.out / "environment.json"
            data = json.loads(metadata.read_text())
            data["relay_compare"] = vars(options) | {"baseline_rut": str(options.baseline_rut) if options.baseline_rut else None}
            data["origin_cpu"] = cpu
            data["origin_workers"] = options.origin_workers
            metadata.write_text(json.dumps(data, indent=2) + "\n")
        with nginx(self, name, config, cpu, port) as pid:
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
        valid = valid_api_origin_records(records, expected_markers, fresh_downstream)
        if not valid:
            raise ValueError("API origin reuse evidence did not match expected markers")

    module.Harness.verify_origin_reuse = verify_api_origin_reuse
    frontend = module.Harness.frontend
    original_popen = subprocess.Popen
    active_backend = None
    active_output = None
    active_rut = None
    frontend_live = False

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
        nonlocal active_backend, active_output, active_rut, frontend_live
        if frontend_live:
            raise RuntimeError("frontends must run serially")
        frontend_live = True
        if engine == "direct-origin":
            saved_port = self.args.front_port
            self.active_label = label
            self.args.front_port = direct_origin_port(self.args)
            try:
                if options.mixed_small_bytes:
                    checks = (("/proxy", module.expected_body("proxy", getattr(self.args, "body_size", None), True), "large"),
                              (options.mixed_small_path, b"Z" * options.mixed_small_bytes, "small"))
                    for path, expected, client in checks:
                        request = urllib.request.Request(f"http://127.0.0.1:{self.args.front_port}{path}", headers={"Host": "client.example"})
                        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response:
                            if response.read() != expected:
                                raise RuntimeError(f"{client} payload preflight failed for {path}")
                yield self.origin_pid
            finally:
                self.args.front_port = saved_port
                frontend_live = False
            return
        active_backend = "epoll" if engine == "epoll" else "io_uring"
        active_output = self.out
        saved_rut = self.args.rut
        config = self.out / (work + "-nginx.conf")
        saved = config.read_text()
        source_file = self.out / (work + ".rut")
        source_text = source_file.read_text() if options.mixed_small_bytes and engine != "nginx" else None
        try:
            if engine == "baseline-uring":
                self.args.rut = options.baseline_rut.resolve()
            active_rut = self.args.rut
            if source_text is not None:
                source_file.write_text(source_text + f'\nroute GET "{options.mixed_small_path}" {{ return forward(backend) }}\n')
            if engine == "nginx":
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
                config.write_text(text)
                (self.out / (label + "-effective-nginx.conf")).write_text(text)
                if options.mixed_small_bytes:
                    text = config.read_text()
                    marker = "location = /proxy {"
                    small_header = size if options.nginx_buffering == "off" else 16
                    small_busy = size if options.nginx_buffering == "off" else 2 * size
                    small_buffers = (f'proxy_buffering {options.nginx_buffering}; '
                                     f'proxy_buffer_size {small_header}k; proxy_buffers 8 {size}k; '
                                     f'proxy_busy_buffers_size {small_busy}k; ')
                    small_location = (f'location = {options.mixed_small_path} {{ proxy_pass http://benchmark_origin; '
                                     'proxy_http_version 1.1; ' + small_buffers +
                                     'proxy_max_temp_file_size 0; proxy_set_header Host $http_host; '
                                     'proxy_set_header Connection ""; } ')
                    if marker not in text:
                        raise ValueError("expected native proxy nginx route")
                    text = text.replace(marker, small_location + marker, 1)
                    config.write_text(text)
                    (self.out / (label + "-effective-nginx.conf")).write_text(text)
            with frontend(self, engine, work, label) as pid:
                if engine != "nginx":
                    if "Backend: " + active_backend not in (self.out / (label + "-server.log")).read_text():
                        raise RuntimeError("runtime selected an unexpected backend")
                if options.mixed_small_bytes:
                    checks = (("/proxy", module.expected_body("proxy", getattr(self.args, "body_size", None), True), "large"),
                              (options.mixed_small_path, b"Z" * options.mixed_small_bytes, "small"))
                    for path, expected, client in checks:
                        request = urllib.request.Request(f"http://127.0.0.1:{self.args.front_port}{path}", headers={"Host": "client.example"})
                        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response:
                            if response.read() != expected:
                                raise RuntimeError(f"{client} payload preflight failed for {path}")
                yield pid
        finally:
            if source_text is not None:
                source_file.write_text(source_text)
            self.args.rut = saved_rut
            config.write_text(saved)
            frontend_live = False
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

        def mixed_wrk(self, work, close, concurrency, duration, label):
            if concurrency <= options.small_connections:
                raise ValueError("concurrency must exceed --small-connections")
            big_cpu, small_cpu = options.mixed_client_cpus.split(",")
            big, small = copy.copy(self), copy.copy(self)
            big.args, small.args = copy.copy(self.args), copy.copy(self.args)
            big.args.client_cpus, small.args.client_cpus = big_cpu, small_cpu
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                large_future = pool.submit(wrk, big, work, close, concurrency - options.small_connections, duration, label + "-large")
                small_future = pool.submit(wrk, small, options.mixed_small_path.lstrip("/"), close, options.small_connections, duration, label + "-small")
                large, little = large_future.result(), small_future.result()
            result = dict(large)
            result.update(large_client=large, small_client=little)
            result["errors"] = {key: large["errors"][key] + little["errors"][key] for key in large["errors"]}
            for key in ("requests", "rps", "client_cpu_seconds"):
                result[key] = large[key] + little[key]
            result["valid"] = mixed_clients_valid(large, little)
            return result

        module.Harness.wrk = mixed_wrk
    return module.main()


if __name__ == "__main__":
    sys.exit(main())
