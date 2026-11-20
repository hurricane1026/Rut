#!/usr/bin/env python3
"""Browser mutation routes require one exact deployment-owned Origin."""
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
    cases = [("Origin: https://admin.example.com\r\n", 204),
             ("origin: https://admin.example.com\r\n", 204),
             ("", 403), ("Origin: null\r\n", 403),
             ("Origin: https://evil.example\r\n", 403),
             ("Origin: https://admin.example.com.evil.example\r\n", 403),
             ("Origin: https://admin.example.com:443\r\n", 403),
             ("Origin: https://admin.example.com, https://evil.example\r\n", 403),
             ("Origin: https://admin.example.com\r\norigin: https://admin.example.com\r\n", 403)]
    with tempfile.TemporaryDirectory(prefix="rut-browser-origin-") as directory:
        root = Path(directory)
        (root / "middleware").mkdir()
        shutil.copyfile(source.parent / "middleware/browser_origin.rut", root / "middleware/browser_origin.rut")
        configs = [(value, "https://console.example.com") for value in
                   ("https://admin.example.com", "", "*", "null", "https://admin.example.com/path",
                    "https://admin.example.com, https://evil.example",
                    "https://admin..example.com", "https://admin.example.com:70000",
                    "https://-admin.example.com", "https://admin-.example.com")]
        configs += [("https://admin.example.com", value) for value in
                    ("", "*", "null", "https://console.example.com/path", "https://admin.example.com")]
        for config, second in configs:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            program = root / "server.rut"
            program.write_text(source.read_text().replace("listen :8080", f"listen :{port}"))
            with (root / "server.log").open("w+") as log:
                proc = subprocess.Popen([args.server, str(program), "--backend", args.backend,
                                         "--opt", args.opt, "--shards", "1", "--drain", "0"],
                                        env=dict(os.environ, BROWSER_ORIGIN=config, BROWSER_SECOND_ORIGIN=second), stdout=log, stderr=subprocess.STDOUT)
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
                            actual = exchange(port, path, fields)
                            assert actual == (expected if config == "https://admin.example.com" else 503), (config, path, fields, actual)
                        if config and config not in ("*", "null"):
                            actual = exchange(port, path, f"Origin: {config}\r\n")
                            assert actual == (204 if config == "https://admin.example.com" else 503), (config, path, actual)
                    for fields, expected in cases + [("Origin: https://console.example.com\r\n", 204),
                                                     ("Origin: https://console.example.com.evil.example\r\n", 403),
                                                     ("Origin: https://admin.example.com\r\nOrigin: https://console.example.com\r\n", 403)]:
                        actual = exchange(port, "/shared/write", fields)
                        assert actual == (expected if config == "https://admin.example.com" and second == "https://console.example.com" else 503), (config, second, fields, actual)
                finally:
                    proc.terminate()
                    proc.wait(timeout=10)
    print("browser origin checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
