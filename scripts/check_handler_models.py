#!/usr/bin/env python3
"""Compare compiler-generated RIR/peer compositions with independent TLC semantics."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import tempfile

from check_concurrency_model import check_reference_case

CASES = {
    "receive_first": "Deadlock",
    "send_first": "None",
    "any_timeout": "None",
    "any_blocked": "Deadlock",
    "ownership": "Safety",
    "resource_leak": "Safety",
    "sleep": "None",
    "yield_cycle": "Livelock",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checker", required=True, type=Path,
                        help="path to test_handler_reference")
    parser.add_argument("--jar", type=Path, default=os.environ.get("TLA2TOOLS_JAR"))
    parser.add_argument("--output-dir", type=Path,
                        help="preserve exported models, configs and counterexample logs")
    args = parser.parse_args()
    if not args.jar or not args.jar.is_file() or not shutil.which("java"):
        parser.error("Java and --jar/TLA2TOOLS_JAR are required")
    with tempfile.TemporaryDirectory(prefix="rut-handler-reference-") as directory:
        work = args.output_dir.resolve() if args.output_dir else Path(directory)
        for case, expected in CASES.items():
            check_reference_case(args.checker.resolve(), args.jar.resolve(), case,
                                 work / case, expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
