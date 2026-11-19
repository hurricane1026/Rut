#!/usr/bin/env python3
"""Exercise legacy query omission through the CLI and real gateway requests."""
import argparse
from contextlib import contextmanager
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time

from auth_h2_fixture import request as h2_request


def registry(staff, other):
    return dict(
        version=1,
        consumers=[
            dict(id="alice", enabled=True, groups=["staff"]),
            dict(id="bob", enabled=True, groups=[]),
        ],
        credentials=[
            dict(id="staff-key", enabled=True, method="header", consumerId="alice", secret=staff),
            dict(id="other-key", enabled=True, method="header", consumerId="bob", secret=other),
        ],
    )


@contextmanager
def gateway(args, root, origin_port, config, path_only, compressed=False):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    source = root / "gateway.rut"
    source.write_text(f'''
listen :{port}
upstream api at "127.0.0.1:{origin_port}"
route GET "/auth/:resource" {{
    guard let identity = consumerAuthenticateQuery(req.path, env("AUTH_REGISTRY"), "api_key") else {{ return 401 }}
    guard jwtHasGroup(identity, "staff") else {{ return 403 }}
    return forward(api, load_balance: .roundRobin)
}}
route GET "/check/:resource" {{ return 204 }}
''')
    logfile = root / "access.log"
    command = [args.server, str(source), "--backend", args.backend,
               "--access-log", str(logfile), "--no-pin", "--drain", "0", "--shards", "1"]
    if path_only:
        command.append("--access-log-path-only")
    if compressed:
        command.append("--access-log-compress")
    with (root / "server.log").open("w+") as diagnostics:
        process = subprocess.Popen(command, env=dict(os.environ, AUTH_REGISTRY=json.dumps(config)),
                                   stdout=diagnostics, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    diagnostics.seek(0)
                    output = diagnostics.read()
                    if args.backend == "io_uring" and "io_uring is unavailable" in output:
                        raise SystemExit(77)
                    raise AssertionError(output)
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.15):
                        break
                except OSError:
                    assert time.monotonic() < deadline, command
                    time.sleep(.025)
            source.unlink()
            yield port, logfile
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        diagnostics.seek(0)
        assert process.returncode == 0, diagnostics.read()


def h1_request(connection, target):
    connection.request("GET", target)
    response = connection.getresponse()
    return response.status, response.read()


def h1_pipeline(port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as peer:
        peer.sendall(
            b"GET /check/pipeline-first?pipeline-private-a HTTP/1.1\r\nHost: x\r\n\r\n"
            b"GET /check/pipeline-second?pipeline-private-b HTTP/1.1\r\nHost: x\r\n"
            b"Connection: close\r\n\r\n"
        )
        wire = bytearray()
        while True:
            chunk = peer.recv(4096)
            if not chunk:
                break
            wire.extend(chunk)
    assert re.findall(rb"HTTP/1\.1 (\d+) ", wire) == [b"204", b"204"], wire


def path_only_case(args, root, origin, received, staff, other, compressed):
    path = "/auth/encoded%3Fpath"
    before = len(received)
    with gateway(args, root, origin.server_port, registry(staff, other), True, compressed) as (
        port, logfile
    ):
        accepted = f"{path}?api_key={staff}&show=%2f"
        future_secret = "unmatched-fixture-key"
        longest_path = "/check/" + "p" * (129 - len("/check/"))
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            assert h1_request(conn, accepted) == (200, b"ok")
            keepalive = conn.sock
            assert keepalive is not None
            assert h1_request(conn, f"{path}?api_key={future_secret}")[0] == 401
            assert conn.sock is keepalive
            assert h1_request(conn, f"{path}?api_key={other}")[0] == 403
            assert h1_request(conn, f"{path}?api_key={staff}&field=%gg")[0] == 401
            assert h1_request(conn, "/check/longquery?private=" + "q" * 256)[0] == 204
            assert h1_request(conn, longest_path + "?long-path-private")[0] == 204
        finally:
            conn.close()
        h1_pipeline(port)
        assert h2_request(port, accepted, []) == (200, b"ok")
        assert h2_request(port, f"{path}?api_key={future_secret}", [])[0] == 401
        assert h2_request(port, f"{path}?api_key={other}", [])[0] == 403
        assert received[before:] == [accepted, accepted], received

    raw = logfile.read_bytes()
    if compressed:
        raw = subprocess.run([args.decompress_helper], input=raw, check=True, capture_output=True).stdout
    output = raw.decode()
    rows = [line.split() for line in output.splitlines()]
    targets_and_statuses = [(row[2], row[3]) for row in rows]
    # Ordinary H2 requests retain their existing lack of legacy target entries.
    assert targets_and_statuses == [
        (path, "200"), (path, "401"), (path, "403"), (path, "401"),
        ("/check/longquery", "204"), ("<request-target-over-limit:129>", "204"),
        ("/check/pipeline-first", "204"), ("/check/pipeline-second", "204"),
    ], output
    for secret in (staff, other, future_secret, "api_key", "pipeline-private", "long-path-private",
                   "private="):
        assert secret not in output, output
    assert "?" not in output, output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--backend", required=True, choices=("epoll", "io_uring"))
    parser.add_argument("--decompress-helper", required=True)
    args = parser.parse_args()
    staff, other = "accepted-fixture-query-key", "access-denied-fixture-query-key"
    received = []

    class Origin(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            received.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="rut-legacy-log-") as directory:
            root = Path(directory)
            alone = subprocess.run([args.server, "--access-log-path-only"], capture_output=True, timeout=5)
            assert alone.returncode != 0 and b"requires --access-log" in alone.stderr, alone
            live = root / "live.rut"
            live_log = root / "live.log"
            live.write_text(
                f'accessLog {{ path: "{live_log}", format: downstreamRequestBytes, publication: live }}\n'
                'route GET "/" { return 204 }\n'
            )
            conflict = subprocess.run([args.server, str(live), "--access-log-path-only"],
                                      capture_output=True, timeout=5)
            assert conflict.returncode != 0 and b"Conflicting source accessLog" in conflict.stderr, conflict
            assert not live_log.exists()
            with gateway(args, root, origin.server_port, registry(staff, other), False) as (port, logfile):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    assert h1_request(conn, "/check/default?legacy-full-target")[0] == 204
                finally:
                    conn.close()
            assert " GET /check/default?legacy-full-target 204 " in logfile.read_text()
            logfile.unlink()
            path_only_case(args, root, origin, received, staff, other, compressed=False)
            logfile.unlink()
            path_only_case(args, root, origin, received, staff, other, compressed=True)
    finally:
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=5)
    print(f"PASS: {args.backend} legacy path-only access log and unchanged forwarding")


if __name__ == "__main__":
    main()
