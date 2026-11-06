#!/usr/bin/env python3
"""Compare a declared routing/transform subset with a pinned, real Kong oracle.

The fixtures are independently authored for each gateway. This is not a Kong
configuration importer. Known differences have exact per-side expectations.
"""
import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.reply()

    def do_HEAD(self):
        self.reply()

    def do_POST(self):
        self.reply()

    def do_DELETE(self):
        self.reply()

    def reply(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        result = body or b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(result)))
        self.send_header("X-Origin", self.server.marker)
        self.send_header("X-Origin-Path", self.path)
        self.send_header("X-Origin-Policy", self.headers.get("X-Policy", ""))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(result)

    def log_message(self, *args):
        pass


def request(port, method, path, body="", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body.encode(),
                           headers={"Host": "api.example.test", **(headers or {})})
        response = connection.getresponse()
        return {"status": response.status, "body": response.read().decode(),
                "origin": response.getheader("X-Origin"),
                "path": response.getheader("X-Origin-Path"),
                "policy": response.getheader("X-Origin-Policy")}
    finally:
        connection.close()


def transformer(value):
    return {"name": "request-transformer",
            "config": {"remove": {"headers": ["X-Policy"]},
                       "add": {"headers": [f"X-Policy:{value}"]}}}


def kong_config(api, fallback):
    def route(name, path, plugins=()):
        return {"name": name, "paths": [path], "strip_path": False,
                "preserve_host": True, "path_handling": "v0", "protocols": ["http"], "plugins": list(plugins)}
    return {"_format_version": "3.0", "_transform": True,
            "plugins": [transformer("global")],
            "services": [
                {"name": "api", "url": f"http://127.0.0.1:{api}",
                 "plugins": [transformer("service")],
                 "routes": [route("api", "/api/"), route("catalog", "/catalog"),
                            {**route("hosted", "/hosted"), "hosts": ["special.example.test"]},
                            {**route("header", "/header"), "headers": {"x-variant": ["blue"]}},
                            {**route("method", "/method"), "methods": ["POST"]},
                            route("override", "/api/override", [transformer("route")]),
                            route("denied", "/api/admin", [
                                {"name": "request-termination",
                                 "config": {"status_code": 403, "body": "blocked"}}])]},
                {"name": "fallback", "url": f"http://127.0.0.1:{fallback}",
                 "routes": [route("fallback", "/")]}]}


def rut_config(api, fallback):
    return (
        f'upstream api {{ host: "127.0.0.1", port: {api} }}\n'
        f'upstream fallback {{ host: "127.0.0.1", port: {fallback} }}\n'
        'route "/api/admin" { return response(403, body: "blocked") }\n'
        'route "/hosted" { if req.header("Host").or("") == "special.example.test" '
        '{ req.set("X-Policy", "service") return forward(api, load_balance: .roundRobin) } '
        'else { req.set("X-Policy", "global") return forward(fallback, load_balance: .roundRobin) } }\n'
        'route "/header" { if req.header("X-Variant").or("") == "blue" '
        '{ req.set("X-Policy", "service") return forward(api, load_balance: .roundRobin) } '
        'else { req.set("X-Policy", "global") return forward(fallback, load_balance: .roundRobin) } }\n'
        'route POST "/method" { req.set("X-Policy", "service") '
        'return forward(api, load_balance: .roundRobin) }\n'
        'route "/api/override" { req.set("X-Policy", "route") '
        'return forward(api, load_balance: .roundRobin) }\n'
        'route "/catalog" { req.set("X-Policy", "service") '
        'return forward(api, load_balance: .roundRobin) }\n'
        'route "/api/" { req.set("X-Policy", "service") '
        'return forward(api, load_balance: .roundRobin) }\n'
        'route "/" { req.set("X-Policy", "global") '
        'return forward(fallback, load_balance: .roundRobin) }\n'
    )


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_kong(port, container):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if request(port, "GET", "/")["status"] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    captured = subprocess.run(["docker", "logs", container], capture_output=True, text=True)
    state = subprocess.run(["docker", "inspect", "--format", "{{json .State}}", container],
                           capture_output=True, text=True)
    raise AssertionError(f"Kong startup timed out:\n{captured.stdout}{captured.stderr}\n{state.stdout}{state.stderr}")


def exercise(args):
    base = Path(__file__).resolve().parent
    image = next(line.strip() for line in (base / "pinned-kong-image.txt").read_text().splitlines()
                 if line.strip() and not line.startswith("#"))
    if not re.fullmatch(r"kong@sha256:[0-9a-f]{64}", image):
        raise AssertionError("Kong image must be pinned by digest")
    required = os.environ.get("RUT_KONG_DIFFERENTIAL_REQUIRED") == "1"
    ready = shutil.which("docker") is not None
    if ready:
        ready = subprocess.run(["docker", "image", "inspect", image],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=15).returncode == 0
    if not ready:
        message = f"pinned Kong oracle unavailable; provision with docker pull {image}"
        if required:
            raise RuntimeError(message)
        print("SKIP:", message)
        raise SystemExit(77)
    origins = []
    workers = []
    for marker in ("api", "fallback"):
        origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        origin.marker = marker
        origin.daemon_threads = True
        worker = threading.Thread(target=origin.serve_forever, daemon=True)
        worker.start()
        origins.append(origin)
        workers.append(worker)
    container = "rut-kong-differential-" + uuid.uuid4().hex
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="rut-kong-", dir="/var/tmp") as directory:
            root = Path(directory)
            api, fallback = (origin.server_port for origin in origins)
            kong_source = root / "kong.json"
            kong_source.write_text(json.dumps(kong_config(api, fallback)))
            source = root / "gateway.rut"
            source.write_text(rut_config(api, fallback))
            kong_port = available_port()
            # Host networking is confined to loopback listeners. Only this
            # uniquely named container is removed by the cleanup below.
            subprocess.run([
                "docker", "run", "--detach", "--name", container, "--network", "host",
                "--pull", "never", "--ulimit", "nofile=4096:4096",
                "--env", "KONG_DATABASE=off",
                "--env", "KONG_DECLARATIVE_CONFIG_STRING=" + kong_source.read_text(),
                "--env", f"KONG_PROXY_LISTEN=127.0.0.1:{kong_port}",
                "--env", "KONG_ADMIN_LISTEN=off", "--env", "KONG_STATUS_LISTEN=off",
                "--env", "KONG_ROUTER_FLAVOR=traditional_compatible",
                "--env", "KONG_NGINX_WORKER_PROCESSES=1",
                "--env", "KONG_PROXY_ACCESS_LOG=off", image],
                check=True, stdout=subprocess.DEVNULL)
            wait_for_kong(kong_port, container)
            with (root / "rut.log").open("w+") as log:
                process = subprocess.Popen([
                    args.server, "0", str(source), "--backend", args.backend, "--shards", "1",
                    "--no-pin", "--drain", "0", "--max-connections-per-shard", "64"],
                    stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 30
                rut_port = None
                while time.monotonic() < deadline and process.poll() is None:
                    log.seek(0)
                    match = re.search(r"Listening on port (\d+)", log.read())
                    if match:
                        rut_port = int(match[1])
                        break
                    time.sleep(0.02)
                if rut_port is None:
                    log.seek(0)
                    raise AssertionError(log.read())
                cases = json.loads((base / "fixtures/kong-routing-cases.json").read_text())
                observations = []
                for case in cases:
                    options = (case["method"], case["path"], case.get("body", ""),
                               case.get("headers", {}))
                    kong = request(kong_port, *options)
                    rut = request(rut_port, *options)
                    observations.append({"id": case["id"], "classification": case["classification"],
                                         "kong": kong, "rut": rut})
                    if args.report:
                        Path(args.report).write_text(json.dumps(
                            {"image": image, "backend": args.backend, "cases": observations},
                            indent=2) + "\n")
                    if not args.observe:
                        assert (kong == rut) == (case["classification"] == "equivalent"), case["id"]
                        assert kong == case["kong"], (case["id"], "Kong", kong, case["kong"])
                        assert rut == case["rut"], (case["id"], "Rut", rut, case["rut"])
                        print(case["id"], "equal" if kong == rut else "documented difference")
                if args.observe:
                    print(json.dumps(observations, indent=2))
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        subprocess.run(["docker", "rm", "--force", container],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for origin in origins:
            origin.shutdown()
            origin.server_close()
        for worker in workers:
            worker.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    parser.add_argument("--report", help="write the observed per-case transcript as JSON")
    parser.add_argument("--observe", action="store_true",
                        help="print both observations without altering the expectation fixture")
    exercise(parser.parse_args())
