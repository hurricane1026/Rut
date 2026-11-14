#!/usr/bin/env python3
"""Check precise response timer ownership and required safety/liveness counterexamples."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import tempfile

from check_timer_model import run_case

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    *((f"generation_bound_{limit}", "response_timer_owner",
       f'Limit = {limit}\nFault = "none"', "success") for limit in (1, 2, 3)),
    *((fault, "response_timer_owner", f'Limit = 2\nFault = "{fault}"', "safety")
      for fault in ("generation_wrap", "publish_before_sqe", "phantom_cancel",
                    "clear_on_first", "missing_generation", "accept_duplicate",
                    "reset_borrowed_storage", "clear_owned")),
    *((fault, "response_timer_owner", f'Limit = 2\nFault = "{fault}"', "liveness")
      for fault in ("unfair_target", "unfair_cancel")),
)


def check_manifest() -> None:
    # Drift alarms; not a refinement proof.
    anchors = {
        "include/rut/runtime/connection_base.h": (
            "clear_response_read_timer_owner", "next_response_read_timer_generation",
            "consume_response_read_timer_completion", "visit_response_read_timer_owner_fields"),
        "src/runtime/io_uring_backend.cc": ("IoUringBackend::add_response_read_timer",
                                            "IoUringBackend::cancel_response_read_timer"),
        "tests/test_response_timer_owner.cc": ("bounded_owner_sequences", "generation_exhaustion"),
    }
    for file, names in anchors.items():
        content = (ROOT / file).read_text()
        for name in names:
            if name not in content:
                raise RuntimeError(f"response timer owner mapping missing: {file}: {name}")
    source = (ROOT / "spec/response_timer_owner.tla").read_text()
    for name in ("Arm", "Cancel", "ArmFull", "CancelFull", "Complete", "Ignored", "Reset", "Clear"):
        if not re.search(rf"^{name}(?:\([^\n]*\))?\s*==", source, re.MULTILINE):
            raise RuntimeError(f"missing action: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--jar", type=Path, default=os.environ.get("TLA2TOOLS_JAR"))
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    check_manifest()
    if args.check_only:
        print("response timer owner manifest passed (TLC not requested)")
        return 0
    if not args.jar or not args.jar.is_file() or not shutil.which("java"):
        parser.error("Java and --jar/TLA2TOOLS_JAR are required")
    with tempfile.TemporaryDirectory(prefix="rut-response-timer-") as directory:
        work = args.output_dir.resolve() if args.output_dir else Path(directory)
        for case in CASES:
            run_case(args.jar.resolve(), work / case[0], case)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
