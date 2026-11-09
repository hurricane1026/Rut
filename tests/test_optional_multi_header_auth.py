#!/usr/bin/env python3
"""Exercise optional custom-header identity policies through native-loaded Rut."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


def exchange(port, path, version, fields):
    # A key in query/body is never evidence for the selected header source.
    body = b"X-API-Key: alice:opaque"
    request = (f"GET {path}?api_key=alice:opaque {version}\r\nHost: local\r\n"
               "Connection: close\r\nX-Consumer-ID: attacker\r\n"
               "X-Credential-ID: attacker\r\n" + fields +
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(request)
        response = b""
        while True:
            data = conn.recv(65536)
            if not data:
                break
            response += data
    head, payload = response.split(b"\r\n\r\n", 1)
    lines = head.decode().split("\r\n")
    challenges = [line.split(":", 1)[1].strip() for line in lines[1:]
                  if line.lower().startswith("www-authenticate:")]
    return int(lines[0].split()[1]), payload.decode(), challenges


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    args = parser.parse_args()
    source = Path(args.source).resolve()
    profiles = [
        ("both", "alice:opaque", "bob/key", True),
        ("alice-disabled", "", "bob/key", True),
        ("bob-disabled", "alice:opaque", "", True),
        ("disabled", "", "", False),
        ("ambiguous", "alice:opaque", "alice:opaque", False),
    ]
    requests = [
        ("", "guest"),
        ("X-API-Key: alice:opaque\r\n", "alice"),
        ("x-api-key: bob/key\r\n", "bob"),
        ("X-API-Key:\r\n", None),
        ("X-API-Key: wrong\r\n", None),
        ("X-API-Key: alice:opaque\r\nx-api-key: bob/key\r\n", None),
        ("X-API-Key: alice:opaque\r\nx-api-key: alice:opaque\r\n", None),
        ("X-API-Key: wrong\r\nx-api-key: bob/key\r\n", None),
        ("Authorization: Bearer alice:opaque\r\n", "guest"),
    ]
    checks = 0
    with tempfile.TemporaryDirectory(prefix="rut-optional-header-") as directory:
        root = Path(directory)
        middleware = root / "middleware"
        middleware.mkdir()
        for name in ("auth.rut", "header_auth.rut"):
            shutil.copyfile(source.parent / "middleware" / name, middleware / name)
        for profile, first, second, valid in profiles:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            program = root / "optional.rut"
            program.write_text(source.read_text().replace("listen :8080", f"listen :{port}"))
            env = dict(os.environ, ALICE_HEADER_KEY=first, BOB_HEADER_KEY=second)
            with (root / "gateway.log").open("w+") as log:
                proc = subprocess.Popen(
                    [args.server, str(program), "--backend", args.backend,
                     "--shards", "1", "--drain", "0"],
                    env=env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        if proc.poll() is not None:
                            log.seek(0)
                            output = log.read()
                            if args.backend == "io_uring" and "io_uring is unavailable" in output:
                                print("SKIP: io_uring unavailable")
                                return 77
                            raise AssertionError(output)
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                log.seek(0)
                                raise AssertionError("startup timeout: " + log.read())
                            time.sleep(.02)
                    for version in ("HTTP/1.0", "HTTP/1.1"):
                        for path in ("/optional", "/private", "/stripped"):
                            for fields, identity in requests:
                                expected = 200
                                if not valid:
                                    expected = 503
                                elif identity is None or (identity == "alice" and not first) or (
                                        identity == "bob" and not second):
                                    expected = 401
                                elif identity == "guest" and path == "/private":
                                    expected = 403
                                status, body, challenges = exchange(port, path, version, fields)
                                context = (args.backend, profile, version, path, fields, status)
                                assert status == expected, context
                                assert challenges == (["ApiKey"] if expected == 401 else []), context
                                if status == 200:
                                    expected_body = identity
                                    if path == "/stripped":
                                        expected_body = "" if identity == "guest" else identity + "-key"
                                    assert body == expected_body, (context, body, expected_body)
                                checks += 1
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
    print(f"{args.backend}: {checks} native HTTP checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
