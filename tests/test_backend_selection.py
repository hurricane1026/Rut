#!/usr/bin/env python3

import argparse
import signal
import subprocess
import tempfile
import time
from pathlib import Path


def wait_for_backend(process: subprocess.Popen, log_path: Path, timeout: float = 15.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = log_path.read_text(errors="replace")
        if "Backend: epoll" in text and "Listening on port" in text:
            return text
        if process.poll() is not None:
            raise RuntimeError(f"rut exited early with {process.returncode}\n{text}")
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for epoll startup\n{log_path.read_text(errors='replace')}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rut", required=True)
    args = parser.parse_args()

    invalid = subprocess.run(
        [args.rut, "--backend", "invalid"], capture_output=True, text=True, check=False
    )
    if invalid.returncode == 0 or "--backend must be" not in invalid.stderr:
        raise RuntimeError(f"invalid backend was accepted\n{invalid.stderr}")

    with tempfile.TemporaryDirectory(prefix="rut-backend-") as tmp:
        root = Path(tmp)
        source = root / "app.rut"
        log_path = root / "rut.log"
        source.write_text(
            'upstream api { host: "127.0.0.1", port: 9, '
            'health_check: { path: "/health", interval: 1s } }\n'
            'route GET "/" { return 200 }\n'
        )

        with log_path.open("w+b") as log:
            process = subprocess.Popen(
                [
                    args.rut,
                    "0",
                    "--shards",
                    "1",
                    "--no-pin",
                    "--drain",
                    "0",
                    "--backend",
                    "auto",
                    str(source),
                ],
                stdout=subprocess.DEVNULL,
                stderr=log,
            )
            try:
                wait_for_backend(process, log_path)
                process.send_signal(signal.SIGTERM)
                if process.wait(timeout=10) != 0:
                    raise RuntimeError(f"rut shutdown returned {process.returncode}")
            except Exception:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                raise

        forced = subprocess.run(
            [args.rut, "--backend", "io_uring", str(source)],
            capture_output=True,
            text=True,
            check=False,
        )
        if forced.returncode == 0:
            raise RuntimeError("io_uring accepted a config requiring active health probes")
        if "io_uring" not in forced.stderr:
            raise RuntimeError(f"missing io_uring failure diagnostic\n{forced.stderr}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
