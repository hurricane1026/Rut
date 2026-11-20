#!/usr/bin/env python3
"""Host-bound session clear response stays fixed and guarded."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time


def exchange(port, fields, context):
    request = ("POST /clear-cookie HTTP/1.1\r\nHost: localhost\r\n"
               "Connection: close\r\n" + fields + "Content-Length: 0\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw, \
            context.wrap_socket(raw, server_hostname="localhost") as conn:
        conn.sendall(request)
        response = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            response += chunk
        return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--opt", required=True)
    parser.add_argument("--testdata", required=True, type=Path)
    args = parser.parse_args()
    cert = args.testdata / "localhost_cert.pem"
    key = args.testdata / "localhost_key.pem"
    context = ssl.create_default_context(cafile=str(cert))
    source = Path(args.source).resolve()
    cases = [("Sec-Fetch-Site: same-origin\r\n", 204),
             ("sec-fetch-site: same-origin\r\n", 204),
             ("", 403), ("Sec-Fetch-Site: cross-site\r\n", 403),
             ("Sec-Fetch-Site: same-site\r\n", 403),
             ("Sec-Fetch-Site: none\r\n", 403),
             ("Sec-Fetch-Site: same-origin, cross-site\r\n", 403),
             ("Sec-Fetch-Site: same-origin\r\nsec-fetch-site: same-origin\r\n", 403)]
    with tempfile.TemporaryDirectory(prefix="rut-browser-session-clear-") as directory:
        root = Path(directory)
        (root / "middleware").mkdir()
        for name in ("browser_origin.rut", "browser_fetch_metadata.rut", "browser_session_cookie.rut"):
            shutil.copyfile(source.parent / "middleware" / name, root / "middleware" / name)
        for config in ("same-origin", "", "*", "same-site", "cross-site"):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            program = root / "server.rut"
            shutil.copyfile(source, program)
            with (root / "server.log").open("w+") as log:
                proc = subprocess.Popen([args.server, str(port), str(program), "--backend", args.backend,
                                         "--opt", args.opt, "--shards", "1", "--drain", "0",
                                         "--tls-cert", str(cert), "--tls-key", str(key)],
                                        env=dict(os.environ, BROWSER_ORIGIN="https://admin.example.com",
                                                 BROWSER_FETCH_SITE=config),
                                        stdout=log, stderr=subprocess.STDOUT)
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
                    program.unlink()
                    for fields, expected in cases:
                        actual = exchange(port, "Origin: https://admin.example.com\r\n" + fields, context)
                        status = int(actual.split(b" ")[1])
                        assert status == (expected if config == "same-origin" else 503), (config, fields, actual)
                        if status == 204:
                            cookie = (b"Set-Cookie: __Host-rut_session=; Path=/; Max-Age=0; "
                                      b"Secure; HttpOnly; SameSite=Strict\r\n")
                            assert actual.count(cookie) == 1
                            assert b"Cache-Control: no-store\r\n" in actual
                        else:
                            assert b"Set-Cookie:" not in actual
                    if config == "same-origin":
                        for origin in ("", "Origin: https://other.example\r\n",
                                       "Origin: https://admin.example.com\r\nOrigin: https://admin.example.com\r\n"):
                            actual = exchange(port, origin + "Sec-Fetch-Site: same-origin\r\n", context)
                            assert int(actual.split(b" ")[1]) == 403, actual
                            assert b"Set-Cookie:" not in actual
                finally:
                    proc.terminate()
                    proc.wait(timeout=10)
    print("browser cookie clear checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
