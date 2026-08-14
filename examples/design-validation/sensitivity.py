#!/usr/bin/env python3
import argparse
import contextlib
import http.client
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class DetectionError(RuntimeError):
    pass


def load_probe(path):
    spec = importlib.util.spec_from_file_location("rut_design_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def python_command(script, *args):
    return [sys.executable, str(script), *map(str, args)]


def wait_for_port(process, port, log_path, label):
    deadline = time.monotonic() + 8
    last_error = None
    while time.monotonic() < deadline:
        status = process.poll()
        if status is not None:
            log = log_path.read_text(errors="replace")
            raise RuntimeError(f"{label} exited with status {status}:\n{log}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError as error:
            last_error = error
            time.sleep(0.05)
    raise RuntimeError(f"{label} did not listen on {port}: {last_error}")


def stop_process(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def require_ports_available(ports):
    if len(ports) != len(set(ports)):
        raise RuntimeError("sensitivity port configuration overlaps")
    sockets = []
    try:
        for port in ports:
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            sockets.append(listener)
    finally:
        for listener in sockets:
            listener.close()


def sensitivity_ports(base_port, websocket_enabled):
    mutant_count = 9 if websocket_enabled else 8
    ports = [base_port + index for index in range(mutant_count)]
    ports.extend((19890, 19894))
    if websocket_enabled:
        ports.append(19892)
    return ports


@contextlib.contextmanager
def fixture_process(command, port, log_path, label):
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            wait_for_port(process, port, log_path, label)
            yield process
        finally:
            stop_process(process)


@contextlib.contextmanager
def rut_process(binary, fixture, port, log_path, shards=1, extra=()):
    command = [
        str(binary),
        str(port),
        "--backend",
        "epoll",
        "--shards",
        str(shards),
        "--no-pin",
        "--drain",
        "0",
        "--opt",
        "0",
        *map(str, extra),
        str(fixture),
    ]
    with fixture_process(command, port, log_path, f"Rut mutant {fixture.name}") as process:
        yield process


def mutate(source_root, temp_root, relative, old, new):
    source = source_root / relative
    contents = source.read_text()
    count = contents.count(old)
    if count != 1:
        raise RuntimeError(
            f"mutation for {relative} expected one source match, found {count}: {old!r}"
        )
    destination = temp_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(contents.replace(old, new))
    return destination


def http_response(port, path, method="GET", body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(), response.getheaders()
    finally:
        connection.close()


def require_response(port, path, status, expected_body):
    actual_status, actual_body, _ = http_response(port, path)
    if (actual_status, actual_body) != (status, expected_body):
        raise DetectionError(
            f"{path} returned {(actual_status, actual_body)!r}, "
            f"expected {(status, expected_body)!r}"
        )


def expect_detected(sentinel_id, oracle, executed, expected_error=None):
    try:
        oracle()
    except DetectionError as error:
        executed.append(sentinel_id)
        print(f"PASS {sentinel_id}: {error}")
        return
    except Exception as error:
        if expected_error is None or expected_error not in str(error):
            raise RuntimeError(
                f"{sentinel_id} failed for the wrong reason: {error}"
            ) from error
        executed.append(sentinel_id)
        detail = str(error)
        if len(detail) > 240:
            detail = detail[:237] + "..."
        print(f"PASS {sentinel_id}: {detail}")
        return
    raise RuntimeError(f"damage sentinel survived its black-box oracle: {sentinel_id}")


def run_simple_mutant(
    binary,
    source_root,
    temp_root,
    base_port,
    index,
    sentinel_id,
    relative,
    old,
    new,
    oracle,
    executed,
    shards=1,
    extra=(),
    expected_error=None,
):
    fixture = mutate(source_root, temp_root, relative, old, new)
    port = base_port + index
    log_path = temp_root / f"{sentinel_id}.log"
    with rut_process(binary, fixture, port, log_path, shards=shards, extra=extra):
        expect_detected(
            sentinel_id,
            lambda: oracle(port),
            executed,
            expected_error,
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rut", type=Path, required=True)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--base-port", type=int, default=19940)
    parser.add_argument("--websocket", choices=("0", "1"), default="1")
    args = parser.parse_args()

    root = (args.root or Path(__file__).resolve().parents[2]).resolve()
    source_root = root / "examples/design-validation"
    binary = args.rut.resolve()
    if not os.access(binary, os.X_OK):
        raise SystemExit(f"Rut binary is not executable: {binary}")
    probe = load_probe(source_root / "probe.py")
    executed = []
    require_ports_available(
        sensitivity_ports(args.base_port, args.websocket == "1")
    )

    with tempfile.TemporaryDirectory(prefix="rut-design-sensitivity-") as temp_name:
        temp_root = Path(temp_name)

        run_simple_mutant(
            binary,
            source_root,
            temp_root,
            args.base_port,
            0,
            "routing.direct-response-damage",
            "routing.rut",
            'route GET "/health" {\n    return 204\n}',
            'route GET "/health" {\n    return 205\n}',
            lambda port: require_response(port, "/health", 204, b""),
            executed,
        )
        run_simple_mutant(
            binary,
            source_root,
            temp_root,
            args.base_port,
            1,
            "core.response-effects-damage",
            "core.rut",
            "    resp.status = 202\n",
            "    resp.status = 203\n",
            lambda port: require_response(
                port,
                "/response",
                202,
                b'{"status":202,"observed":"/response"}',
            ),
            executed,
        )
        run_simple_mutant(
            binary,
            source_root,
            temp_root,
            args.base_port,
            2,
            "data.serialization-damage",
            "data.rut",
            "answer: 40 + 2",
            "answer: 40 + 1",
            lambda port: require_response(
                port,
                "/data?tag=core&tag=jit",
                200,
                b'{"path":"/data?tag=core&tag=jit","answer":42,'
                b'"tags":["core","jit"],"meta":{"ok":true}}',
            ),
            executed,
        )
        run_simple_mutant(
            binary,
            source_root,
            temp_root,
            args.base_port,
            3,
            "middleware.after-damage",
            "middleware.rut",
            "    resp.status = 201\n",
            "    resp.status = 202\n",
            lambda port: require_response(
                port,
                "/chain",
                201,
                b'{"stage":"after","ok":true}',
            ),
            executed,
        )

        def state_oracle(port):
            statuses = [http_response(port, "/limited")[0] for _ in range(3)]
            if statuses != [200, 200, 429]:
                raise DetectionError(
                    f"state admission sequence was {statuses}, expected [200, 200, 429]"
                )

        run_simple_mutant(
            binary,
            source_root,
            temp_root,
            args.base_port,
            4,
            "state.write-damage",
            "state.rut",
            "buckets.set(req.remoteAddr, tat + 600000000)",
            "buckets.set(req.remoteAddr, tat)",
            state_oracle,
            executed,
        )

        access_log = temp_root / "policy-access.log"
        access_log.touch()
        run_simple_mutant(
            binary,
            source_root,
            temp_root,
            args.base_port,
            5,
            "policy.global-scope-damage",
            "policy.rut",
            "scope: global",
            "scope: shard",
            lambda port: probe.global_rate_limit(port, 64, access_log),
            executed,
            shards=2,
            extra=("--access-log", access_log),
            expected_error="global rate limit admitted",
        )

        origin_log = temp_root / "origin.log"
        origin_command = python_command(
            source_root / "origin.py",
            "--port",
            "19890",
        )
        with fixture_process(origin_command, 19890, origin_log, "HTTP origin"):
            run_simple_mutant(
                binary,
                source_root,
                temp_root,
                args.base_port,
                6,
                "proxy.rewrite-damage",
                "proxy.rut",
                '"X-Inject": "yes"',
                '"X-Inject": "no"',
                lambda port: require_response(port, "/rewrite", 200, b"/rewritten|yes"),
                executed,
            )

        health_state = temp_root / "health-state"
        health_state.write_text("down\n")
        health_log = temp_root / "health-origin.log"
        health_command = python_command(
            source_root / "origin.py",
            "--port",
            "19894",
            "--health-file",
            str(health_state),
        )
        with fixture_process(health_command, 19894, health_log, "health origin"):
            run_simple_mutant(
                binary,
                source_root,
                temp_root,
                args.base_port,
                7,
                "health.recovery-damage",
                "health.rut",
                "status: 200",
                "status: 204",
                lambda port: probe.active_health(port, health_state),
                executed,
                expected_error=probe.ACTIVE_HEALTH_RECOVERY_FAILURE,
            )

        if args.websocket == "1":
            websocket_log = temp_root / "websocket-origin.log"
            websocket_command = python_command(
                source_root / "origin.py",
                "--port",
                "19892",
            )
            with fixture_process(
                websocket_command,
                19892,
                websocket_log,
                "WebSocket origin",
            ):
                run_simple_mutant(
                    binary,
                    source_root,
                    temp_root,
                    args.base_port,
                    8,
                    "websocket.filter-damage",
                    "websocket.rut",
                    "else { frame.drop() }",
                    "else { frame.forward() }",
                    probe.websocket_filter,
                    executed,
                    expected_error="terminate filter forwarded the wrong payload",
                )

        executed_path = temp_root / "executed-sentinels"
        executed_path.write_text("".join(f"{sentinel}\n" for sentinel in executed))
        audit_command = python_command(
            source_root / "audit.py",
            "--manifest",
            str(source_root / "capabilities.json"),
            "--root",
            str(root),
            "--executed-sentinels",
            str(executed_path),
        )
        if args.websocket == "0":
            audit_command.extend(("--disable", "websocket"))
        subprocess.run(audit_command, check=True)

    print("All compilable behavior-damage sentinels were rejected by black-box oracles.")


if __name__ == "__main__":
    main()
