#!/usr/bin/env python3
"""Require response timer tests to reject isolated production ownership mutations."""
from __future__ import annotations

import argparse
from pathlib import Path

from check_timer_mutations import run_implementation_mutations

HEADER = "rut/runtime/connection_base.h"
MUTATIONS = {
    "missing_generation": (HEADER, "generation == 0 || generation != response_read_timer_owner_generation",
                           "generation == 0"),
    "duplicate_cancel_pending": (HEADER, "if (!owned) return false;", ""),
    "clear_borrowed_storage": (HEADER,
                               "if (response_read_timer_target_owned || response_read_timer_cancel_owned) return false;",
                               ""),
    "generation_exhaustion": (HEADER,
                              "response_read_timer_generation >= kResponseReadTimerGenerationMask",
                              "response_read_timer_generation > kResponseReadTimerGenerationMask"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    filters = {name: ["--filter=generation_exhaustion" if name == "generation_exhaustion"
                      else "--filter=owner_guard_smoke"] for name in MUTATIONS}
    run_implementation_mutations(args.build_dir, args.output_dir, "test_response_timer_owner", MUTATIONS, filters)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
