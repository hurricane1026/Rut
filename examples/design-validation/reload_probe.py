#!/usr/bin/env python3
import argparse
import http.client
import os
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path


SOURCE = """\
route GET "/" { return STATUS }
route POST "/reload" {
    guard reload() else { return 503 }
    return 202
}
"""


def wait_for(log_path, pattern, process, timeout=10):
    deadline = time.monotonic() + timeout
    regex = re.compile(pattern)
    while time.monotonic() < deadline:
        text = log_path.read_text(errors="replace")
        match = regex.search(text)
        if match:
            return match
        if process.poll() is not None:
            raise RuntimeError(f"rut exited early with {process.returncode}\n{text}")
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {pattern!r}\n{log_path.read_text()}")


def request(port, method, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request(method, path, headers={"Content-Length": "0"})
    response = conn.getresponse()
    response.read()
    status = response.status
    conn.close()
    return status


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rut", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rut-route-reload-") as tmp:
        root = Path(tmp)
        releases = root / "releases"
        releases.mkdir()
        v1 = releases / "v1.rut"
        v2 = releases / "v2.rut"
        v1.write_text(SOURCE.replace("STATUS", "200"))
        v2.write_text(SOURCE.replace("STATUS", "201"))
        source = root / "app.rut"
        source.symlink_to(v1.relative_to(root))
        log_path = root / "rut.log"

        with log_path.open("w+b") as log:
            process = subprocess.Popen(
                [
                    args.rut,
                    "0",
                    "--backend",
                    "epoll",
                    "--shards",
                    "1",
                    "--no-pin",
                    "--drain",
                    "0",
                    "--allow-route-reload",
                    str(source),
                ],
                stdout=subprocess.DEVNULL,
                stderr=log,
            )
            try:
                match = wait_for(log_path, r"Listening on port ([0-9]+)", process)
                port = int(match.group(1))
                assert request(port, "GET", "/") == 200

                replacement = root / "app.next"
                replacement.symlink_to(v2.relative_to(root))
                os.replace(replacement, source)
                assert request(port, "POST", "/reload") == 202
                wait_for(log_path, r"Reload activated", process)
                assert request(port, "GET", "/") == 201

                process.send_signal(signal.SIGTERM)
                if process.wait(timeout=10) != 0:
                    raise RuntimeError(f"rut shutdown returned {process.returncode}")
            except Exception:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                raise


if __name__ == "__main__":
    main()
