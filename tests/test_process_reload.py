#!/usr/bin/env python3

import argparse
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def wait_for(log_path: Path, pattern: str, process: subprocess.Popen, timeout: float = 15.0):
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
    raise RuntimeError(f"timed out waiting for {pattern!r}\n{log_path.read_text(errors='replace')}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rut", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rut-reload-") as tmp:
        root = Path(tmp)
        source = root / "app.rut"
        releases = root / "releases"
        releases.mkdir()
        version1 = releases / "v1.rut"
        version2 = releases / "v2.rut"
        log_path = root / "rut.log"
        version1.write_text('route GET "/" { return 200 }\n')
        source.symlink_to(version1.relative_to(root))

        with log_path.open("w+b") as log:
            process = subprocess.Popen(
                [args.rut, "0", "--shards", "1", "--no-pin", "--drain", "0", str(source)],
                stdout=subprocess.DEVNULL,
                stderr=log,
            )
            try:
                wait_for(log_path, r"Listening on port [0-9]+", process)

                version2.write_text('route GET "/" { return 201 }\n')
                replacement = root / "app.next"
                replacement.symlink_to(version2.relative_to(root))
                os.replace(replacement, source)
                os.kill(process.pid, signal.SIGHUP)
                wait_for(log_path, r"Reload activated", process)
                wait_for(
                    log_path,
                    r'\{"event":"reload","request_id":1,"source":"signal",'
                    r'"old_generation":1,"new_generation":2,"outcome":"activated"\}',
                    process,
                )

                os.kill(process.pid, signal.SIGTERM)
                if process.wait(timeout=10) != 0:
                    raise RuntimeError(f"rut shutdown returned {process.returncode}")
            except Exception:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                print(log_path.read_text(errors="replace"), file=sys.stderr)
                raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
