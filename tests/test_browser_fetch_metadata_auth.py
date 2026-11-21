#!/usr/bin/env python3
"""Browser mutation routes require strict Origin and Fetch Metadata."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


def exchange(port, path, fields):
    request = (f"POST {path} HTTP/1.1\r\nHost: attacker.example\r\n"
               "Connection: close\r\n" + fields + "Content-Length: 0\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(request)
        return int(conn.recv(4096).split(b" ")[1])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--opt", required=True)
    args = parser.parse_args()
    source = Path(args.source).resolve()
    cases = [("Sec-Fetch-Site: same-origin\r\n", 204),
             ("sec-fetch-site: same-origin\r\n", 204),
             ("", 403), ("Sec-Fetch-Site: cross-site\r\n", 403),
             ("Sec-Fetch-Site: same-site\r\n", 403),
             ("Sec-Fetch-Site: none\r\n", 403),
             ("Sec-Fetch-Site: same-origin, cross-site\r\n", 403),
             ("Sec-Fetch-Site: same-origin\r\nsec-fetch-site: same-origin\r\n", 403)]
    with tempfile.TemporaryDirectory(prefix="rut-browser-origin-") as directory:
        root = Path(directory)
        (root / "middleware").mkdir()
        for name in ("browser_origin.rut", "browser_fetch_metadata.rut"):
            shutil.copyfile(source.parent / "middleware" / name, root / "middleware" / name)
        for config in ("same-origin", "", "*", "same-site", "cross-site"):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            program = root / "server.rut"
            program.write_text(source.read_text().replace("listen :8080", f"listen :{port}"))
            with (root / "server.log").open("w+") as log:
                proc = subprocess.Popen([args.server, str(program), "--backend", args.backend,
                                         "--opt", args.opt, "--shards", "1", "--drain", "0"],
                                        env=dict(os.environ, BROWSER_ORIGIN="https://admin.example.com", BROWSER_FETCH_SITE=config), stdout=log, stderr=subprocess.STDOUT)
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
                    for path in ("/admin/write", "/session"):
                        for fields, expected in cases:
                            actual = exchange(port, path, "Origin: https://admin.example.com\r\n" + fields)
                            assert actual == (expected if config == "same-origin" else 503), (config, path, fields, actual)
                finally:
                    proc.terminate()
                    proc.wait(timeout=10)
    print("browser fetch metadata checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
