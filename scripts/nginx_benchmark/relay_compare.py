#!/usr/bin/env python3
"""Serial relay comparisons using the repository's existing benchmark harness."""

import argparse
import concurrent.futures
import contextlib
import copy
import importlib.util
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--engines", default="uring,nginx")
    parser.add_argument("--baseline-rut", type=Path)
    parser.add_argument("--origin-workers", type=int, default=4)
    parser.add_argument("--origin-cpus", default="3,4,8,9")
    parser.add_argument("--origin-multi-accept", choices=("on", "off"), default="on")
    parser.add_argument("--mixed-small-bytes", type=int, default=0)
    parser.add_argument("--small-connections", type=int, default=32)
    parser.add_argument("--mixed-client-cpus", default="7,5")
    parser.add_argument("--nginx-buffering", choices=("on", "off"), default="off")
    parser.add_argument("--nginx-buffer-kib", type=int, default=1024)
    parser.add_argument("--mixed-nginx-small-buffer-kib", type=int, default=16)
    parser.add_argument("--origin-mode", choices=("static", "api"), default="static")
    parser.add_argument("--api-delay-ms", type=float, default=0)
    parser.add_argument("--api-fragment-bytes", type=int, default=0)
    parser.add_argument("--api-fragment-delay-ms", type=float, default=0)
    options, remaining = parser.parse_known_args()
    if not any(arg == "--origin-cpu" or arg.startswith("--origin-cpu=") for arg in remaining):
        remaining += ["--origin-cpu", options.origin_cpus.split(",")[0]]
    engines = options.engines.split(",")
    if not engines or any(e not in ("uring", "baseline-uring", "epoll", "nginx", "direct-origin") for e in engines):
        parser.error("--engines must contain uring, baseline-uring, epoll or nginx")
    if "baseline-uring" in engines and options.baseline_rut is None:
        parser.error("baseline-uring requires --baseline-rut and its matching rut-compile")
    if options.origin_workers < 1 or options.nginx_buffer_kib < 16:
        parser.error("origin workers must be positive; nginx buffers must be at least 16KiB")
    if options.mixed_small_bytes < 0 or options.small_connections < 1:
        parser.error("invalid mixed workload size or connection count")
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
                lua.write_text(lua.read_text().replace('wrk.path="/proxy"', 'wrk.path="/api4k"'))
        if len(argv)>2 and argv[:2]==["docker","logs"] and argv[2]==getattr(self,"api_origin_id",None):
            return subprocess.CompletedProcess(argv,0,self.api_log.read_text(),"")
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
            path = self.out / config
            text = path.read_text().replace("worker_processes 1;", f"worker_processes {options.origin_workers};")
            text = text.replace("worker_connections 8192;", f"worker_connections 8192; multi_accept {options.origin_multi_accept};")
            if options.mixed_small_bytes:
                (self.out / "payloads" / "small").write_bytes(b"Z" * options.mixed_small_bytes)
                text = text.replace("location / {", "location = /api4k { alias /benchmark-payloads/small; default_type application/octet-stream; etag off; max_ranges 0; } location / {", 1)
            path.write_text(text)
            metadata = self.out / "environment.json"
            data = json.loads(metadata.read_text())
            data["relay_compare"] = vars(options) | {"baseline_rut": str(options.baseline_rut) if options.baseline_rut else None}
            data["origin_cpu"] = cpu
            data["origin_workers"] = options.origin_workers
            if options.mixed_small_bytes:
                data["mixed_request_paths"] = {"large": "/proxy", "small": "/api4k"}
            metadata.write_text(json.dumps(data, indent=2) + "\n")
        if name=="origin" and options.origin_mode=="api":
            self.api_origin_id=self.prefix+"-api";self.origin_container_id=self.api_origin_id;self.api_log=self.out/"api-origin.log"
            argv=[sys.executable,str(Path(__file__).with_name("api_origin.py")),"--port",str(port),"--cpus",options.origin_cpus,"--payload",str(self.out/"payloads"/"proxy"),"--delay-ms",str(options.api_delay_ms),"--fragment-bytes",str(options.api_fragment_bytes),"--fragment-delay-ms",str(options.api_fragment_delay_ms)]
            with self.api_log.open("w") as log:
                process=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT)
                try:
                    deadline=time.monotonic()+15
                    while self.api_log.read_text().count("API_READY ")<options.origin_workers:
                        if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError("API origin did not become ready")
                        time.sleep(.05)
                    self.ready(port,process.pid)
                    self.experiment_origin_pid=process.pid
                    yield process.pid
                finally:
                    process.terminate()
                    try:process.wait(timeout=15)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
            return
        with nginx(self, name, config, cpu, port) as pid:
            if name=="origin":self.experiment_origin_pid=pid
            yield pid

    module.Harness.nginx = origin
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

    def validate_mixed_urls(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.args.front_port, timeout=5)
        try:
            connection.connect()
            retained = connection.sock
            # Cross-route successor requests must not inherit a previous large
            # response's relay owner or body state on the persistent connection.
            for index in range(8):
                small = index % 2 == 1
                connection.request("GET", "/api4k" if small else "/proxy",
                                   headers={"Host": "client.example"})
                reply = connection.getresponse()
                wanted = b"Z" * options.mixed_small_bytes if small else module.expected_body(
                    "proxy", self.args.body_size, native_streaming=True)
                if reply.status != 200 or reply.read() != wanted or connection.sock is not retained:
                    raise RuntimeError("mixed URL persistent response preflight failed")
        finally:
            connection.close()

    @contextlib.contextmanager
    def chosen_frontend(self, engine, work, label):
        nonlocal active_backend, active_output, active_rut, frontend_live
        if engine=="direct-origin":
            self.active_label=label
            saved_port=self.args.front_port
            self.args.front_port=self.args.origin_port
            if options.mixed_small_bytes:
                request = urllib.request.Request(f"http://127.0.0.1:{self.args.front_port}/api4k")
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response:
                    if response.read() != b"Z" * options.mixed_small_bytes:
                        raise RuntimeError("direct-origin small URL preflight failed")
            if options.mixed_small_bytes:
                validate_mixed_urls(self)
            try:yield self.experiment_origin_pid
            finally:self.args.front_port=saved_port
            return
        if frontend_live:
            raise RuntimeError("frontends must run serially")
        frontend_live = True
        active_backend = "epoll" if engine == "epoll" else "io_uring"
        active_output = self.out
        saved_rut = self.args.rut
        config = self.out / (work + "-nginx.conf")
        saved = config.read_text()
        if options.mixed_small_bytes:
            program = self.out / (work + ".rut")
            original_program = program.read_text()
            if 'route GET "/api4k"' not in original_program:
                program.write_text(original_program + 'route GET "/api4k" { return forward(backend) }\n')
        try:
            if engine == "baseline-uring":
                self.args.rut = options.baseline_rut.resolve()
            active_rut = self.args.rut
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
                if options.mixed_small_bytes:
                    match = re.search(r"location = /proxy\s*\{([^{}]*)\}", text)
                    if not match:
                        raise ValueError("expected one proxy location for mixed URL configuration")
                    small_body = match.group(1)
                    if options.mixed_nginx_small_buffer_kib:
                        small_size = options.mixed_nginx_small_buffer_kib
                        small_body = re.sub(
                            r"proxy_buffering\s+(?:on|off);\s*proxy_buffer_size\s+\S+;\s*(?:proxy_buffers\s+\d+\s+\S+;\s*)?proxy_busy_buffers_size\s+\S+;",
                            f"proxy_buffering off; proxy_buffer_size {small_size}k; proxy_buffers 8 {small_size}k; proxy_busy_buffers_size {2 * small_size}k;",
                            small_body,
                        )
                    text = text[:match.end()] + " location = /api4k {" + small_body + "}" + text[match.end():]
                config.write_text(text)
                (self.out / (label + "-effective-nginx.conf")).write_text(text)
            with frontend(self, engine, work, label) as pid:
                if engine != "nginx":
                    if "Backend: " + active_backend not in (self.out / (label + "-server.log")).read_text():
                        raise RuntimeError("runtime selected an unexpected backend")
                if options.mixed_small_bytes:
                    request = urllib.request.Request(f"http://127.0.0.1:{self.args.front_port}/api4k", headers={"Host": "client.example"})
                    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response:
                        if response.read() != b"Z" * options.mixed_small_bytes:
                            raise RuntimeError("small payload preflight failed")
                    validate_mixed_urls(self)
                yield pid
        finally:
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
                small_future = pool.submit(wrk, small, work, close, options.small_connections, duration, label + "-small")
                large, little = large_future.result(), small_future.result()
            result = dict(large)
            result.update(large_client=large, small_client=little)
            result["errors"] = {key: large["errors"][key] + little["errors"][key] for key in large["errors"]}
            for key in ("requests", "rps", "client_cpu_seconds"):
                result[key] = large[key] + little[key]
            return result

        module.Harness.wrk = mixed_wrk
    return module.main()


if __name__ == "__main__":
    sys.exit(main())
