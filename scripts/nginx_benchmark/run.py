#!/usr/bin/env python3
"""Local pinned-nginx / converter-stdout benchmark; no performance CI gate."""

import argparse
import asyncio
import collections
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ("static-close", "static-keepalive", "proxy-close", "proxy-keepalive")
ERROR_NAMES = ("connect", "read", "write", "status", "timeout")


def save_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def response_head(head):
    if not head.startswith(b"HTTP/1.1 200 OK\r\n"):
        raise ValueError(f"unexpected status: {head[:100]!r}")
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        if not line:
            continue
        key, value = line.split(b":", 1)
        key = key.lower()
        if key in headers:
            raise ValueError(f"duplicate header: {key!r}")
        headers[key] = value.strip()
    length = headers.get(b"content-length", b"")
    if not length.isdigit() or int(length) > 2048 or b"transfer-encoding" in headers:
        raise ValueError("expected bounded Content-Length response")
    return int(length), headers.get(b"connection", b"").lower() == b"close"


def request_bytes(work, close):
    mode = "close" if close else "keep-alive"
    return f"GET /{work} HTTP/1.1\r\nHost: client.example\r\nConnection: {mode}\r\n\r\n".encode()


def expected_body(work):
    return b"hello from nginx" if work == "static" else b"x" * 1024


def response(sock, work, close):
    sock.sendall(request_bytes(work, close))
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ValueError("EOF before response header")
        data += chunk
        if len(data) > 8192:
            raise ValueError("oversized response")
    head, body = data.split(b"\r\n\r\n", 1)
    length, server_close = response_head(head)
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            raise ValueError("EOF before complete body")
        body += chunk
    if len(body) != length or body != expected_body(work):
        raise ValueError("unexpected body")
    if (close or server_close) and sock.recv(1) != b"":
        raise ValueError("expected EOF after response")
    normalized = re.sub(rb"(?im)^Date: [^\r\n]+", b"Date: NORMALIZED", head)
    return normalized + b"\r\n\r\n" + body, server_close


def proc_usage(pid):
    """Parent + direct children; RSS can double-count nginx shared pages."""
    ids = [pid]
    ids += [
        int(p) for p in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
    ]
    ticks = rss = 0
    for child in ids:
        fields = Path(f"/proc/{child}/stat").read_text().rsplit(")", 1)[1].split()
        ticks += int(fields[11]) + int(fields[12])
        rss += int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
    return ticks / os.sysconf("SC_CLK_TCK"), rss


class Harness:
    def __init__(self, args):
        self.args = args
        self.out = args.output
        self.prefix = "rut-bench-" + uuid.uuid4().hex[:12]
        self.image = (ROOT / "tests/pinned-nginx-image.txt").read_text().strip()
        self.references = {}
        self.results = []
        self.commands = []

    def command(self, argv, *, timeout=20):
        argv = [str(v) for v in argv]
        self.commands.append(argv)
        save_json(self.out / "commands.json", self.commands)
        # Own a process group: interrupting GNU time must also stop its wrk child.
        with subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        ) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except BaseException as error:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
                (self.out / f"command-failure-{len(self.commands)}.log").write_text(
                    repr(error) + "\n" + stdout + stderr
                )
                raise
            if process.returncode:
                error = subprocess.CalledProcessError(
                    process.returncode, argv, stdout, stderr
                )
                (self.out / f"command-failure-{len(self.commands)}.log").write_text(
                    repr(error) + "\n" + stdout + stderr
                )
                raise error
            return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)

    def prepare(self):
        a = self.args
        context = self.command(["docker", "context", "inspect"]).stdout
        endpoint = (
            os.environ.get("DOCKER_HOST")
            or json.loads(context)[0]["Endpoints"]["docker"]["Host"]
        )
        if not endpoint.startswith("unix://"):
            raise ValueError(
                "this harness requires a local Docker daemon via a Unix socket"
            )
        self.command(["docker", "info", "--format", "{{.ServerVersion}}"])
        inspection = json.loads(
            self.command(["docker", "image", "inspect", self.image]).stdout
        )[0]
        metadata = {
            "harness_revision": self.command(
                ["git", "-C", ROOT, "rev-parse", "HEAD"]
            ).stdout.strip(),
            "harness_dirty": bool(
                self.command(["git", "-C", ROOT, "status", "--porcelain"]).stdout
            ),
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "arguments": {
                k: str(v) if isinstance(v, Path) else v for k, v in vars(a).items()
            },
            "binaries_sha256": {str(p): sha256(p) for p in (a.rut, a.converter, a.wrk)},
            "nginx_image": self.image,
            "nginx_image_id": inspection["Id"],
            "kernel": list(os.uname()),
            "cpu_topology": self.command(["lscpu"]).stdout,
            "tcp_tw_reuse": Path("/proc/sys/net/ipv4/tcp_tw_reuse").read_text().strip(),
            "note": "Harness revision is not proof of binary source revision. Record build provenance separately.",
        }
        save_json(self.out / "environment.json", metadata)
        (self.out / "origin.conf").write_text(
            self.nginx_config(
                f"server {{ listen 127.0.0.1:{a.origin_port}; keepalive_timeout 0; "
                'location / { default_type text/plain; return 200 "'
                + "x" * 1024
                + '"; } }'
            )
        )
        for work in ("static", "proxy"):
            local = (
                'location = /static { return 200 "hello from nginx"; }'
                if work == "static"
                else ""
            )
            fragment = (
                f"server {{ listen 127.0.0.1:{a.front_port}; {local} "
                f"location / {{ proxy_pass http://127.0.0.1:{a.origin_port}; }} }}\n"
            )
            source = self.out / (work + ".conf")
            source.write_text(fragment)
            (self.out / (work + "-nginx.conf")).write_text(self.nginx_config(fragment))
            converted = self.command([a.converter, "--format", "server", source])
            (self.out / (work + ".rut")).write_text(converted.stdout)
            (self.out / (work + "-converter.log")).write_text(converted.stderr)

    @staticmethod
    def nginx_config(server):
        return (
            "worker_processes 1;\nerror_log /dev/stderr warn;\npid /tmp/nginx.pid;\n"
            "events { worker_connections 8192; }\nhttp { access_log off;\n"
            + server
            + "\n}\n"
        )

    def ready(self, port, pid):
        for _ in range(100):
            if not Path(f"/proc/{pid}").exists():
                raise RuntimeError("server exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"listener {port} did not become ready")

    @contextlib.contextmanager
    def nginx(self, name, config, cpu, port):
        # Capture the ID before start/inspect/readiness so failures still clean up.
        cid = self.command(
            [
                "docker",
                "create",
                "--pull=never",
                "--name",
                self.prefix + "-" + name,
                "--network",
                "host",
                "--cpuset-cpus",
                cpu,
                "--ulimit",
                "nofile=65536:65536",
                "--mount",
                f"type=bind,src={self.out / config},dst=/etc/nginx/nginx.conf,readonly",
                self.image,
                "nginx",
                "-g",
                "daemon off;",
            ]
        ).stdout.strip()
        try:
            self.command(["docker", "start", cid])
            pid = int(
                self.command(["docker", "inspect", "-f", "{{.State.Pid}}", cid]).stdout
            )
            self.ready(port, pid)
            yield pid
        finally:
            try:
                self.command(["docker", "stop", "-t", "2", cid])
            finally:
                try:
                    logs = self.command(["docker", "logs", cid])
                    (self.out / (name + "-server.log")).write_text(
                        logs.stdout + logs.stderr
                    )
                finally:
                    self.command(["docker", "rm", "-f", cid])

    @contextlib.contextmanager
    def frontend(self, engine, work, label):
        a = self.args
        if engine == "nginx":
            with self.nginx(
                label, work + "-nginx.conf", a.server_cpu, a.front_port
            ) as pid:
                yield pid
            return
        argv = [
            "taskset",
            "-c",
            str(a.server_cpu),
            str(a.rut),
            str(self.out / (work + ".rut")),
            "--shards",
            "1",
            "--no-pin",
            "--drain",
            "1",
            "--opt",
            "2",
        ]
        self.commands.append(argv)
        save_json(self.out / "commands.json", self.commands)
        with (self.out / (label + "-server.log")).open("w") as log:
            proc = subprocess.Popen(argv, stdout=log, stderr=log)
        try:
            self.ready(a.front_port, proc.pid)
            yield proc.pid
            if proc.poll() is not None:
                raise RuntimeError(f"RUT exited unexpectedly: {proc.returncode}")
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    def validate(self, work, keepalive):
        for close in [True, False] if keepalive else [True]:
            sock = None
            try:
                for _ in range(100):
                    if sock is None:
                        sock = socket.create_connection(
                            ("127.0.0.1", self.args.front_port), timeout=3
                        )
                    raw, server_close = response(sock, work, close)
                    key = (work, close)
                    if key in self.references and self.references[key] != raw:
                        raise ValueError(f"response mismatch for {key}")
                    self.references[key] = raw
                    (
                        self.out
                        / f"{work}-{'close' if close else 'keepalive'}-response.txt"
                    ).write_bytes(raw)
                    if close or server_close:
                        sock.close()
                        sock = None
                        if not close:
                            raise ValueError(
                                "keepalive preflight closed before 100 requests"
                            )
            finally:
                if sock is not None:
                    sock.close()

    def wrk(self, work, close, concurrency, duration, label):
        a = self.args
        mode = "close" if close else "keep-alive"
        lua = self.out / (label + ".lua")
        lua.write_text(
            f'wrk.method="GET"\nwrk.path="/{work}"\nwrk.headers["Host"]="client.example"\n'
            f'wrk.headers["Connection"]="{mode}"\n'
            'done=function(s,l,r)\n print(string.format("METRICS %.0f %.0f %.0f %.0f %.0f %d %d %d %d %d",'
            "s.requests,s.duration,l:percentile(50),l:percentile(95),l:percentile(99),"
            "s.errors.connect,s.errors.read,s.errors.write,s.errors.status,s.errors.timeout))\nend\n"
        )
        cpu_file = self.out / (label + ".cpu")
        argv = [
            "/usr/bin/time",
            "-f",
            "%U %S",
            "-o",
            cpu_file,
            "taskset",
            "-c",
            a.client_cpus,
            a.wrk,
            f"-t{min(concurrency, len(a.client_cpus.split(',')))}",
            f"-c{concurrency}",
            f"-d{duration}s",
            "--latency",
            "--timeout",
            "2s",
            "-s",
            lua,
            f"http://127.0.0.1:{a.front_port}/{work}",
        ]
        result = self.command(argv, timeout=duration + 15)
        (self.out / (label + ".log")).write_text(result.stdout + result.stderr)
        match = re.search(r"^METRICS (.+)$", result.stdout, re.MULTILINE)
        if not match:
            raise ValueError(f"missing wrk metrics: {label}")
        values = [float(v) for v in match[1].split()]
        if len(values) != 10 or values[1] <= 0:
            raise ValueError("invalid wrk metrics")
        return {
            "requests": int(values[0]),
            "seconds": values[1] / 1e6,
            "rps": values[0] / (values[1] / 1e6),
            "p50_us": values[2],
            "p95_us": values[3],
            "p99_us": values[4],
            "errors": dict(zip(ERROR_NAMES, map(int, values[5:]))),
            "client_cpu_seconds": sum(map(float, cpu_file.read_text().split())),
        }

    def benchmark(self, origin_pid):
        for scenario in self.args.scenarios:
            work, mode = scenario.split("-")
            for rep in range(1, self.args.repeats + 1):
                for engine in ("nginx", "rut") if rep % 2 else ("rut", "nginx"):
                    label = f"{scenario}-{engine}-r{rep}"
                    with self.frontend(engine, work, label) as pid:
                        self.validate(work, mode == "keepalive")
                        print(label, "response preflight PASS", flush=True)
                        for concurrency in self.args.concurrency:
                            tag = label + f"-c{concurrency}"
                            warmup = self.wrk(
                                work,
                                mode == "close",
                                concurrency,
                                self.args.warmup,
                                tag + "-warmup",
                            )
                            before, _ = proc_usage(pid)
                            origin_before, _ = proc_usage(origin_pid)
                            result = self.wrk(
                                work,
                                mode == "close",
                                concurrency,
                                self.args.duration,
                                tag,
                            )
                            after, rss = proc_usage(pid)
                            origin_after, _ = proc_usage(origin_pid)
                            result.update(
                                workload=work,
                                connection=mode,
                                engine=engine,
                                rep=rep,
                                concurrency=concurrency,
                                warmup_errors=warmup["errors"],
                                server_cpu_pct=100
                                * (after - before)
                                / result["seconds"],
                                origin_cpu_pct=100
                                * (origin_after - origin_before)
                                / result["seconds"],
                                server_rss_bytes=rss,
                                valid=bool(result["requests"])
                                and not any(result["errors"].values())
                                and bool(warmup["requests"])
                                and not any(warmup["errors"].values()),
                            )
                            self.results.append(result)
                            save_json(self.out / "results.json", self.results)
                            print(json.dumps(result), flush=True)
        return all(r["valid"] for r in self.results)

    async def independent(self, work, close):
        counts = collections.Counter()
        examples = []
        deadline = time.monotonic() + self.args.duration

        async def worker():
            reader = writer = None

            async def disconnect():
                nonlocal writer
                if writer:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), 3)
                    except (OSError, asyncio.TimeoutError):
                        pass
                    writer = None

            try:
                while time.monotonic() < deadline:
                    try:
                        if writer is None:
                            reader, writer = await asyncio.wait_for(
                                asyncio.open_connection(
                                    "127.0.0.1", self.args.front_port
                                ),
                                3,
                            )
                        writer.write(request_bytes(work, close))
                        await asyncio.wait_for(writer.drain(), 3)
                        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
                        length, server_close = response_head(head)
                        body = await asyncio.wait_for(reader.readexactly(length), 3)
                        if body != expected_body(work):
                            raise ValueError("unexpected response body")
                        if close or server_close:
                            if await asyncio.wait_for(reader.read(1), 3) != b"":
                                raise ValueError("expected EOF after response")
                            await disconnect()
                        counts["correct_responses"] += 1
                    except (
                        OSError,
                        ValueError,
                        asyncio.IncompleteReadError,
                        asyncio.LimitOverrunError,
                        asyncio.TimeoutError,
                    ) as error:
                        counts[type(error).__name__] += 1
                        if len(examples) < 5:
                            examples.append(repr(error))
                        await disconnect()
            finally:
                await disconnect()

        await asyncio.gather(*(worker() for _ in range(self.args.concurrency[0])))
        return {"counts": dict(counts), "examples": examples}

    def diagnose(self):
        for scenario in self.args.scenarios:
            work, mode = scenario.split("-")
            for engine in ("nginx", "rut"):
                label = f"diagnose-{scenario}-{engine}"
                with self.frontend(engine, work, label):
                    self.validate(work, mode == "keepalive")
                    load = self.wrk(
                        work,
                        mode == "close",
                        self.args.concurrency[0],
                        self.args.warmup,
                        label,
                    )
                    original_affinity = os.sched_getaffinity(0)
                    try:
                        os.sched_setaffinity(
                            0, set(map(int, self.args.client_cpus.split(",")))
                        )
                        result = asyncio.run(self.independent(work, mode == "close"))
                    finally:
                        os.sched_setaffinity(0, original_affinity)
                    result.update(scenario=scenario, engine=engine, prior_wrk=load)
                    result["valid"] = (
                        bool(result["counts"].get("correct_responses"))
                        and not any(
                            v
                            for k, v in result["counts"].items()
                            if k != "correct_responses"
                        )
                        and bool(load["requests"])
                        and not any(load["errors"].values())
                    )
                    self.results.append(result)
                    save_json(self.out / "diagnostics.json", self.results)
                    print(label, json.dumps(result), flush=True)
        return all(r["valid"] for r in self.results)


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rut", type=Path, required=True)
    parser.add_argument("--converter", type=Path, required=True)
    parser.add_argument("--wrk", type=Path, required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="new or empty directory; no resume"
    )
    parser.add_argument(
        "--mode", choices=("benchmark", "diagnose"), default="benchmark"
    )
    parser.add_argument("--server-cpu", type=int, required=True)
    parser.add_argument("--origin-cpu", type=int, required=True)
    parser.add_argument(
        "--client-cpus",
        required=True,
        help="comma-separated CPU IDs on distinct physical cores",
    )
    parser.add_argument("--front-port", type=int, default=8087)
    parser.add_argument("--origin-port", type=int, default=9087)
    parser.add_argument("--concurrency", nargs="+", type=positive, default=[1, 32, 128])
    parser.add_argument("--duration", type=positive, default=8)
    parser.add_argument("--warmup", type=positive, default=2)
    parser.add_argument("--repeats", type=positive, default=3)
    parser.add_argument(
        "--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS)
    )
    args = parser.parse_args()
    if args.mode == "diagnose" and len(args.concurrency) != 1:
        parser.error("diagnose requires one --concurrency value")
    if len(set(args.concurrency)) != len(args.concurrency) or len(
        set(args.scenarios)
    ) != len(args.scenarios):
        parser.error("duplicate concurrency or scenario")
    for attr in ("rut", "converter", "wrk"):
        path = getattr(args, attr).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(f"{attr} must name an executable file")
        setattr(args, attr, path)
    args.output = args.output.resolve()
    if args.output.exists() and (
        not args.output.is_dir() or any(args.output.iterdir())
    ):
        parser.error(
            "output must be new or empty; existing evidence is never overwritten"
        )
    cpus = [args.server_cpu, args.origin_cpu]
    try:
        clients = [int(cpu) for cpu in args.client_cpus.split(",")]
    except ValueError:
        parser.error("client-cpus must be comma-separated integer CPU IDs")
    cpus += clients
    if len(set(cpus)) != len(cpus) or not set(cpus) <= os.sched_getaffinity(0):
        parser.error("CPU IDs must be available and disjoint")
    cores = []
    for cpu in cpus:
        topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        cores.append(
            (
                (topology / "physical_package_id").read_text(),
                (topology / "core_id").read_text(),
            )
        )
    if len(set(cores)) != len(cores):
        parser.error("choose distinct physical cores, not SMT siblings")
    args.client_cpus = ",".join(map(str, clients))
    if args.front_port == args.origin_port or any(
        not 1024 <= p <= 9999 for p in (args.front_port, args.origin_port)
    ):
        parser.error("ports must be distinct unprivileged four-digit ports")
    for port in (args.front_port, args.origin_port):
        try:
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
        except OSError as error:
            parser.error(f"port {port} unavailable: {error}")
    for tool in ("docker", "taskset", "lscpu", "git", "/usr/bin/time"):
        if not shutil.which(tool):
            parser.error(f"required tool missing: {tool}")
    args.output.mkdir(parents=True, exist_ok=True)
    return args


def main():
    args = arguments()
    harness = Harness(args)
    status = {"complete": False, "valid": False}

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    try:
        harness.prepare()
        with harness.nginx(
            "origin", "origin.conf", args.origin_cpu, args.origin_port
        ) as origin_pid:
            valid = (
                harness.benchmark(origin_pid)
                if args.mode == "benchmark"
                else harness.diagnose()
            )
        status.update(complete=True, valid=valid)
        return 0 if valid else 1
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - persist incomplete evidence on any failure
        status["error"] = repr(error)
        print(repr(error), file=sys.stderr)
        return 2
    finally:
        save_json(args.output / "status.json", status)


if __name__ == "__main__":
    sys.exit(main())
