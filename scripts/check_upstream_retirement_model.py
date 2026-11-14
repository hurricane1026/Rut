#!/usr/bin/env python3
"""Check bounded io_uring retirement safety, progress and required fault traces."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    ("recv_one_episode", 1, 1, "none", "success"),
    ("send_recv_one_episode", 2, 1, "none", "success"),
    ("recv_slot_reuse", 1, 2, "none", "success"),
    ("send_recv_slot_reuse", 2, 2, "none", "success"),
    *((fault, 1, 2 if fault in {"stale_final", "stale_callback"} else 1, fault, "safety")
      for fault in ("more_final", "duplicate_final", "stale_final", "wrong_aux",
                    "missing_cancel_count", "retry_counted", "retry_not_cleared",
                    "early_reclaim", "double_reclaim", "stale_callback")),
    ("target_fairness_required", 1, 1, "unfair_target", "liveness"),
    ("cancel_fairness_required", 1, 1, "unfair_cancel", "liveness"),
)
# Structural drift map only: these anchors do not establish refinement.
MANIFEST = {
    "include/rut/runtime/iouring_event_loop.h": (
        "begin_upstream_retirement_impl", "retry_strict_upstream_retirement_cancels",
        "consume_strict_upstream_retirement_event", "strict_upstream_retirement_blocks_reclaim",
        "upstream_retirement_target_owned", "upstream_retirement_cancel_owned",
        "upstream_retirement_cancel_retry", "reclaim_pending",
    ),
    "tests/test_network.cc": (
        "provided_more_target_first_and_unowned_records_are_isolated",
        "cancel_final_first_retires_each_owner_once", "cancel_submission_failure_retries_before_wait",
        "target_final_before_cancel_retry_allows_exact_one_reuse",
        "mixed_partial_cancel_failure_retries_or_collapses_exact_bit",
        "downstream_close_during_second_retirement_reclaims_exactly_once",
        "latest_tombstone_persists_across_immediate_reset_and_slot_reuse",
        "all_send_recv_completion_permutations_preserve_exact_owners",
    ),
}


def check_manifest() -> None:
    for file, anchors in MANIFEST.items():
        content = (ROOT / file).read_text()
        for anchor in anchors:
            if anchor not in content:
                raise RuntimeError(f"missing retirement mapping: {file}: {anchor}")
    source = (ROOT / "spec/upstream_retirement.tla").read_text()
    for action in ("RetrySubmit", "RetryFull", "TargetFinal", "CancelFinal", "More", "MoreCancel", "Ignored", "Reclaim", "Reuse"):
        if not re.search(rf"^{action}(?:\([^\n]*\))?\s*==", source, re.MULTILINE):
            raise RuntimeError(f"missing model action: {action}")


def run_case(jar: Path, work: Path, case: tuple) -> None:
    name, ops, episodes, fault, expected = case
    work.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "spec/upstream_retirement.tla", work)
    config = work / "instance.cfg"
    config.write_text("SPECIFICATION Spec\nINVARIANT Safety\nPROPERTY Settles\nCONSTANTS\n"
                      f'OpCount = {ops}\nEpisodes = {episodes}\nFault = "{fault}"\n')
    command = ["java", "-Xmx768m", "-XX:+UseParallelGC", "-XX:ActiveProcessorCount=2", "-cp", str(jar),
               "tlc2.TLC", "-workers", "1", "-lncheck", "final", "-cleanup",
               "-metadir", str(work / "states"), "-config", config.name, "upstream_retirement"]
    try:
        result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired as exc:
        partial = "".join(p.decode(errors="replace") if isinstance(p, bytes) else p or ""
                          for p in (exc.stdout, exc.stderr))
        (work / "tlc.log").write_text(partial)
        raise RuntimeError(f"{name}: TLC timed out; no proof") from exc
    output = result.stdout + result.stderr
    (work / "tlc.log").write_text(output)
    actual = classify(result.returncode, output)
    if actual != expected:
        raise RuntimeError(f"{name}: expected={expected}, actual={actual}\n{output}")
    print(f"PASS {name}: {actual}", flush=True)


def classify(code: int, output: str) -> str:
    if code == 0 and "Model checking completed" in output and "No error has been found" in output:
        return "success"
    if (code == 12 and "Invariant Safety is violated by the initial state:" in output
            and "/\\ episode =" in output and "/\\ pending =" in output):
        return "safety"
    if "State 1:" in output:
        if code == 12 and "Invariant Safety is violated" in output:
            return "safety"
        if code == 13 and "Temporal properties were violated" in output:
            return "liveness"
    return "error"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--jar", type=Path, default=os.environ.get("TLA2TOOLS_JAR"))
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    check_manifest()
    if args.check_only:
        print("upstream retirement source manifest passed (TLC not requested)")
        return 0
    if not args.jar or not args.jar.is_file() or not shutil.which("java"):
        parser.error("Java and --jar/TLA2TOOLS_JAR are required")
    with tempfile.TemporaryDirectory(prefix="rut-upstream-retirement-") as directory:
        work = args.output_dir.resolve() if args.output_dir else Path(directory)
        for case in CASES:
            run_case(args.jar.resolve(), work / case[0], case)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
