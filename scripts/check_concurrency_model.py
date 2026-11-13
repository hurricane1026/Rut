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



SAFETY_ISSUES = {"UnsafeAction", "InvariantViolation", "ResourceLeak"}
CONSTANTS = ("ActorCount", "Initial", "Terminal", "InitialBits", "TerminalClear",
             "Actions", "Invariants", "FairGroups")


def check_reference_case(checker: Path, jar: Path, case: str, work: Path,
                         expected: str | None = None) -> None:
    """Check one exported model; preserve the instance and all tool output."""
    work.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "spec/concurrency_reference.tla", work)
    export = subprocess.run([str(checker), f"--export-reference={case}"],
                            capture_output=True, text=True, timeout=30)
    (work / "export.log").write_text(export.stderr)
    (work / "concurrency_instance.tla").write_text(export.stdout)
    if export.returncode:
        raise RuntimeError(f"{case}: model export failed ({export.returncode})\n{export.stderr}")
    match = re.search(r"^\\\* native-result: (\w+)$", export.stdout, re.MULTILINE)
    if not match:
        raise RuntimeError(f"{case}: no native verdict")
    native = match.group(1)
    normalized = "Safety" if native in SAFETY_ISSUES else native
    if normalized not in {"None", "Safety", "Deadlock", "Livelock"}:
        raise RuntimeError(f"{case}: incomplete native check: {native}")
    # Golden expectations catch a shared mistake in the compiler and TLC model.
    if expected is not None and normalized != expected:
        raise RuntimeError(f"{case}: expected={expected}, native={native}")
    config = work / "instance.cfg"
    config.write_text("SPECIFICATION Spec\nINVARIANT Safety\nPROPERTY Termination\nCONSTANTS\n"
                      + "".join(f"{name} <- {name}Value\n" for name in CONSTANTS))
    command = ["java", "-Xmx1g", "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC",
               "-workers", "1", "-lncheck", "final", "-cleanup", "-metadir",
               str(work / "states"), "-config", config.name, "concurrency_instance"]
    try:
        completed = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as exc:
        partial = "".join(part.decode(errors="replace") if isinstance(part, bytes) else part or ""
                          for part in (exc.stdout, exc.stderr))
        (work / "tlc.log").write_text(partial)
        raise RuntimeError(f"{case}: TLC timed out; no proof obtained") from exc
    output = completed.stdout + completed.stderr
    (work / "tlc.log").write_text(output)
    # Exit statuses are those of the project's pinned TLC tool. A killed or
    # crashed process is not an accepted counterexample, even after a marker.
    if "Deadlock reached" in output:
        reference, status = "Deadlock", 11
    elif "Temporal properties were violated" in output:
        reference, status = "Livelock", 13
    elif "Invariant Safety is violated" in output:
        reference, status = "Safety", 12
    elif "No error has been found" in output:
        reference, status = "None", 0
    else:
        raise RuntimeError(f"{case}: TLC did not finish a property check\n{output}")
    if completed.returncode != status:
        raise RuntimeError(f"{case}: TLC did not finish with the expected exit status: "
                           f"expected={status}, actual={completed.returncode}\n{output}")
    if reference != normalized:
        raise RuntimeError(f"{case}: native={native}, TLC={reference}\n{output}")
    print(f"PASS: {case}: native={native}, TLC={reference}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--jar", type=Path, default=os.environ.get("TLA2TOOLS_JAR"))
    parser.add_argument("--output-dir", type=Path, help="preserve models, configs and TLC traces")
    args = parser.parse_args()
    if not args.jar or not args.jar.is_file() or not shutil.which("java"):
        parser.error("Java and --jar/TLA2TOOLS_JAR are required for this explicit reference check")
    with tempfile.TemporaryDirectory(prefix="rut-concurrency-reference-") as directory:
        work = args.output_dir.resolve() if args.output_dir else Path(directory)
        for case in CASES:
            check_reference_case(args.checker.resolve(), args.jar.resolve(), case, work / case)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
