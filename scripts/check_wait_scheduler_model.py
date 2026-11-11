#!/usr/bin/env python3
"""Check the wait scheduler contract and require TLC counterexamples for faults.

The source manifest is a drift check, not proof of model/C++ equivalence.
--check-only performs only that check; full checking requires the pinned TLC jar.
"""
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
    ("single", 1, 1, "none", "success"),
    ("fifo_batch_one", 2, 1, "none", "success"),
    ("fifo_batch_two", 2, 2, "none", "success"),
    ("inline", 2, 1, "inline", "safety"),
    ("lifo", 2, 1, "lifo", "safety"),
    ("redrain", 2, 1, "redrain", "safety"),
    ("no_fence", 2, 1, "no_fence", "safety"),
    ("no_cancel", 2, 1, "no_cancel", "safety"),
    ("stale_wake", 2, 1, "stale_wake", "safety"),
    ("no_shutdown_cancel", 2, 1, "no_shutdown_cancel", "safety"),
    ("blocking", 2, 1, "blocking", "liveness"),
    ("unfair_scheduler", 2, 1, "unfair_scheduler", "liveness"),
    ("unfair_io", 2, 1, "unfair_io", "liveness"),
)


def check_manifest() -> None:
    requirements = {
        "include/rut/runtime/event_loop.h": (
            "kJitReadyBatchLimit = 64", "Ready batch[kJitReadyBatchLimit]",
            "count < kJitReadyBatchLimit", "cancel_ready_jit_handler(c)",
            "c.handler_gen != batch[i].generation", "c.handler_state != batch[i].state",
        ),
        "include/rut/runtime/callbacks_impl.h": ("loop->defer_jit_handler(conn)",),
        "tests/test_network.cc": ("ready_wait_shutdown_discard_never_invokes_handler",),
        "tests/test_wait_scheduler.cc": (
            "batch_limit_and_fifo_at_64_65_and_129_owners",
            "peer_close_inside_detached_batch_cancels_resume",
            "peer_close_and_reuse_inside_batch_cannot_resume_new_generation",
            "generation_or_continuation_change_invalidates_queued_resume",
            "kernel_send_cannot_steal_ready_queue_completion",
        ),
    }
    for backend in ("epoll", "iouring", "kqueue"):
        requirements[f"include/rut/runtime/{backend}_event_loop.h"] = (
            "this->drain_ready_jit_handlers()", "this->has_ready_jit_handlers()",
            "this->discard_ready_jit_handlers()", "!conn.jit_ready_queued",
        )
    for filename, tokens in requirements.items():
        source = (ROOT / filename).read_text()
        for token in tokens:
            if token not in source:
                raise RuntimeError(f"scheduler manifest drift: {filename}: missing {token}")
    model = (ROOT / "spec/wait_scheduler.tla").read_text()
    for action in ("Publish", "ArmIO", "Begin", "Resume", "EndDrain", "Poll", "IOComplete", "Close", "Reuse", "StaleWake", "Shutdown"):
        if not re.search(rf"^{action}(?:\([^\n]*\))? ==", model, re.M):
            raise RuntimeError(f"missing scheduler model action: {action}")


def run_cases(jar: Path, output_dir: Path | None = None) -> None:
    if not jar.is_file() or not shutil.which("java"):
        raise RuntimeError("Java and the pinned --jar/TLA2TOOLS_JAR are required")
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rut-wait-scheduler-") as directory:
        work = Path(directory)
        shutil.copy(ROOT / "spec/wait_scheduler.tla", work)
        for name, owners, limit, fault, expected in CASES:
            config = work / f"{name}.cfg"
            config.write_text(
                "SPECIFICATION Spec\nINVARIANT Safety\nPROPERTY Settles\nCONSTANTS\n"
                f"OwnerCount = {owners}\nBatchLimit = {limit}\nFault = \"{fault}\"\n"
            )
            result = subprocess.run(
                ["java", "-Xmx768m", "-XX:ActiveProcessorCount=2", "-cp", str(jar),
                 "tlc2.TLC", "-workers", "1", "-cleanup", "-metadir", str(work / f"states-{name}"),
                 "-config", config.name, "wait_scheduler"],
                cwd=work, capture_output=True, text=True, timeout=120,
            )
            output = result.stdout + result.stderr
            if output_dir:
                (output_dir / f"{name}.log").write_text(output)
            verdict = (
                "success" if result.returncode == 0 and "No error has been found" in output and "Model checking completed" in output
                else "safety" if result.returncode != 0 and "Invariant Safety is violated" in output
                else "liveness" if result.returncode != 0 and "Temporal properties were violated" in output
                else "error"
            )
            if verdict != expected or (expected != "success" and "State 1:" not in output):
                raise RuntimeError(f"{name}: expected {expected}, got {verdict}\n{output}")
            print(f"PASS {name}: {verdict}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--jar", type=Path, default=os.environ.get("TLA2TOOLS_JAR"))
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    check_manifest()
    if args.check_only:
        print("wait scheduler source manifest passed (TLC not requested)")
        return 0
    if not args.jar:
        parser.error("--jar or TLA2TOOLS_JAR is required; use --check-only for the source manifest")
    run_cases(args.jar.resolve(), args.output_dir)
    print(f"wait scheduler TLC checks passed: {len(CASES)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
