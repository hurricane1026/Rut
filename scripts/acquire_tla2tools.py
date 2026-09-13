#!/usr/bin/env python3
"""Acquire the pinned TLA+ tools jar with a bounded, fail-closed transfer."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path


TLA2TOOLS_URL = (
    "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"
)
TLA2TOOLS_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"


class AcquisitionError(RuntimeError):
    """A transfer failed before an artifact could be published."""

    def __init__(self, message: str, returncode: int | None = None) -> None:
        super().__init__(message)
        self.returncode = returncode


class ChecksumError(AcquisitionError):
    """The completed transfer did not match its pinned digest."""


def acquire(
    url: str,
    destination: Path,
    expected_sha256: str,
    *,
    connect_timeout: float = 10,
    max_time: float = 30,
    retries: int = 3,
    curl: str = "curl",
) -> None:
    """Download *url* and atomically publish it to *destination* on hash match.

    The optional arguments exist for deterministic local tests. Production uses
    the constants and defaults in :func:`main`; callers cannot override those
    through the command line.
    """
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, staging_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".part", dir=destination.parent
    )
    os.close(fd)
    staging = Path(staging_name)
    try:
        command = [
            curl,
            "--fail",
            "--location",
            "--retry",
            str(retries),
            "--retry-all-errors",
            "--connect-timeout",
            str(connect_timeout),
            "--max-time",
            str(max_time),
            "--output",
            str(staging),
            url,
        ]
        # Do not capture stderr: curl diagnostics and its distinct exit status
        # remain visible to CI. The staging file is always ours to remove.
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            raise AcquisitionError(
                f"curl failed with exit status {result.returncode}", result.returncode
            )

        digest = hashlib.sha256()
        with staging.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        actual = digest.hexdigest()
        if actual != expected_sha256:
            raise ChecksumError(
                f"checksum mismatch: expected {expected_sha256}, got {actual}"
            )
        os.replace(staging, destination)
    finally:
        try:
            staging.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        acquire(TLA2TOOLS_URL, args.destination, TLA2TOOLS_SHA256)
    except ChecksumError as exc:
        print(f"tla2tools acquisition checksum failure: {exc}", file=sys.stderr, flush=True)
        return 2
    except AcquisitionError as exc:
        print(f"tla2tools acquisition failed: {exc}", file=sys.stderr, flush=True)
        return exc.returncode if exc.returncode is not None else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
