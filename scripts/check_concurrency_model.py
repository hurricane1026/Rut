#!/usr/bin/env python3
"""Cross-check the native finite protocol checker against the pinned TLC tool."""

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
    "mutual", "timeout", "or_wait", "livelock", "starvation_fair",
    "starvation_unfair", "intermittent", "ownership", "wait_single",
    "wait_any", "wait_mixed", "wait_mixed_reverse", "stale_completion", "reclaim",
    "missing_cancel", "missing_disarm", "missing_cancel_ack", "reclaim_before_cancel_ack",
    "submit_all", "submit_after_wait", "submit_reuse", "all_early_resume",
    "consistent_ack", "consistent_early_ack", "consistent_self_wait", "consistent_self_inline",
    "consistent_cycle", "consistent_timeout", "consistent_full",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--jar", type=Path, default=os.environ.get("TLA2TOOLS_JAR"))
    args = parser.parse_args()
    if not args.jar or not args.jar.is_file() or not shutil.which("java"):
        parser.error("Java and --jar/TLA2TOOLS_JAR are required for this explicit reference check")
    checker = args.checker.resolve()
    jar = args.jar.resolve()
    with tempfile.TemporaryDirectory(prefix="rut-concurrency-reference-") as directory:
        work = Path(directory)
        shutil.copy(ROOT / "spec/concurrency_reference.tla", work)
        for case in CASES:
            exported = subprocess.run(
                [str(checker), f"--export-reference={case}"],
                capture_output=True, text=True, check=True, timeout=30,
            ).stdout
            match = re.search(r"^\\\* native-result: (\w+)$", exported, re.MULTILINE)
            if not match:
                raise RuntimeError(f"{case}: no native verdict")
            native = match.group(1)
            (work / "concurrency_instance.tla").write_text(exported)
            config = work / f"{case}.cfg"
            constants = ("ActorCount", "Initial", "Terminal", "InitialBits",
                         "TerminalClear", "Actions", "Invariants", "FairGroups")
            config.write_text(
                "SPECIFICATION Spec\nINVARIANT Safety\nPROPERTY Termination\nCONSTANTS\n"
                + "".join(f"{name} <- {name}Value\n" for name in constants)
            )
            completed = subprocess.run(
                ["java", "-Xmx1g", "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC", "-workers", "1", "-lncheck", "final", "-cleanup",
                 "-metadir", str(work / f"states-{case}"), "-config", config.name,
                 "concurrency_instance"],
                cwd=work, capture_output=True, text=True, timeout=180,
            )
            output = completed.stdout + completed.stderr
            if "Deadlock reached" in output:
                reference = "Deadlock"
            elif "Temporal properties were violated" in output:
                reference = "Livelock"
            elif "Invariant Safety is violated" in output:
                reference = "Safety"
            elif completed.returncode == 0 and "No error has been found" in output:
                reference = "None"
            else:
                raise RuntimeError(f"{case}: TLC did not finish a property check\n{output}")
            expected = "Safety" if native in (
                "UnsafeAction", "InvariantViolation", "ResourceLeak",
            ) else native
            if reference != expected:
                raise RuntimeError(f"{case}: native={native}, TLC={reference}\n{output}")
            print(f"PASS: {case}: native={native}, TLC={reference}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
