#!/usr/bin/env python3
"""Check timer wheel and yield lifecycle safety, progress and required fault traces."""
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
    ("wheel_small", "timer_wheel", 'Slots = 4\nBudget = 3\nFault = "none"', "success"),
    ("wheel_64", "timer_wheel", 'Slots = 64\nBudget = 2\nFault = "none"', "success"),
    ("wheel_requires_tick", "timer_wheel", 'Slots = 4\nBudget = 3\nFault = "unfair_tick"', "liveness"),
    *((fault, "timer_wheel", f'Slots = 4\nBudget = 3\nFault = "{fault}"', "safety")
      for fault in ("off_by_one", "refresh_keeps_old", "remove_lost")),
    *((f"{backend}_{fault}", "yield_timer", f'Backend = "{backend}"\nFault = "{fault}"', verdict)
      for backend in ("heap", "uring")
      for fault, verdict in (("none", "success"), ("early_fire", "safety"),
                             ("unfair_clock", "liveness"))),
    ("uring_io_leaves_armed", "yield_timer", 'Backend = "uring"\nFault = "io_leaves_armed"', "safety"),
    ("uring_missing_generation", "yield_timer", 'Backend = "uring"\nFault = "missing_generation"', "safety"),
    ("uring_stale_disarms", "yield_timer", 'Backend = "uring"\nFault = "stale_disarms"', "liveness"),
    ("uring_early_reuse", "yield_timer", 'Backend = "uring"\nFault = "early_reuse"', "safety"),
)


def check_manifest() -> None:
    # Drift alarms only; concrete tests supply implementation evidence.
    anchors = {
        "include/rut/runtime/timer_wheel.h": ("cursor++", "node->remove()"),
        "include/rut/runtime/epoll_event_loop.h": ("schedule_yield_timer", "drain_yield_heap", "c.handler_gen != entry.handler_gen"),
        "include/rut/runtime/iouring_event_loop.h": ("schedule_yield_timer", "ev.result == static_cast<i32>(c.yield_timer_gen)"),
        "src/runtime/timer_wheel.cc": ("cursor + seconds", "c->timer_node.remove()"),
        "tests/test_timer_model.cc": ("bounded_wheel_sequences", "heap_matches_deadline_oracle",
                                      "stale_uring_completion_preserves_successor",
                                      "epoll_disarm_removes_all_entries_and_preserves_peer"),
    }
    for file, names in anchors.items():
        content = (ROOT / file).read_text()
        for name in names:
            if name not in content:
                raise RuntimeError(f"timer mapping missing: {file}: {name}")
    for module in ("timer_wheel", "yield_timer"):
        content = (ROOT / f"spec/{module}.tla").read_text()
        for name in ("Init", "Next", "Safety", "Settles", "Spec"):
            if not re.search(rf"^{name}\s*==", content, re.MULTILINE):
                raise RuntimeError(f"{module}: missing {name}")


def run_case(jar: Path, work: Path, case: tuple) -> None:
    name, module, constants, expected = case
    work.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / f"spec/{module}.tla", work)
    config = work / "instance.cfg"
    config.write_text("SPECIFICATION Spec\nINVARIANT Safety\nPROPERTY Settles\nCONSTANTS\n"
                      + constants + "\n")
    command = ["java", "-Xmx768m", "-XX:+UseParallelGC", "-XX:ActiveProcessorCount=2", "-cp", str(jar),
               "tlc2.TLC", "-workers", "1", "-lncheck", "final", "-cleanup",
               "-metadir", str(work / "states"), "-config", config.name, module]
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
        print("timer source manifest passed (TLC not requested)")
        return 0
    if not args.jar or not args.jar.is_file() or not shutil.which("java"):
        parser.error("Java and --jar/TLA2TOOLS_JAR are required")
    with tempfile.TemporaryDirectory(prefix="rut-timer-") as directory:
        work = args.output_dir.resolve() if args.output_dir else Path(directory)
        for case in CASES:
            run_case(args.jar.resolve(), work / case[0], case)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
