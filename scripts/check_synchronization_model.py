#!/usr/bin/env python3
"""Check bounded synchronization design paths and required counterexamples."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
# Each fault must be detected; merely completing TLC is not a passing test.
CASES = {
    "submit_all_owner_ack": ({"WaitAll"}, "None"),
    "submit_any_owner_ack": (set(), "None"),
    "all_early_resume": ({"WaitAll", "EarlyResume"}, "Safety"),
    "any_early_resume": ({"EarlyResume"}, "Safety"),
    "owner_early_ack": ({"EarlyAck"}, "Safety"),
    "owner_self_wait": ({"SelfWait"}, "Deadlock"),
    "owner_self_wait_timeout": ({"SelfWait", "Timeout"}, "None"),
    "owner_full_failure": ({"QueueFull"}, "None"),
    "wait_before_submit": ({"WaitBeforeSubmit"}, "Deadlock"),
    "wait_before_submit_timeout": ({"WaitBeforeSubmit", "Timeout"}, "None"),
}
CONSTANTS = ("WaitAll", "EarlyResume", "EarlyAck", "SelfWait", "QueueFull",
             "Timeout", "WaitBeforeSubmit")


def check_case(work: Path, jar: Path, module: str, name: str,
               config: Path, expected: str) -> None:
    result = subprocess.run(
        ["java", "-Xmx1g", "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC", "-workers", "1",
         "-cleanup", "-metadir", str(work / name), "-config", config.name,
         module], cwd=work, text=True, capture_output=True, timeout=60,
    )
    output = result.stdout + result.stderr
    if "Invariant Safety is violated" in output:
        actual = "Safety"
    elif "Deadlock reached" in output:
        actual = "Deadlock"
    elif "Temporal properties were violated" in output:
        actual = "Livelock"
    elif result.returncode == 0 and "No error has been found" in output:
        actual = "None"
    else:
        raise RuntimeError(f"{name}: TLC did not complete\n{output}")
    if actual != expected:
        raise RuntimeError(f"{name}: expected={expected}, actual={actual}\n{output}")
    print(f"PASS: {name}: {actual}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=Path, default=os.environ.get("TLA2TOOLS_JAR"))
    args = parser.parse_args()
    if not args.jar or not args.jar.is_file() or not shutil.which("java"):
        parser.error("Java and --jar/TLA2TOOLS_JAR are required")
    with tempfile.TemporaryDirectory(prefix="rut-synchronization-") as directory:
        work = Path(directory)
        shutil.copy(ROOT / "spec/synchronization.tla", work)
        for name, (enabled, expected) in CASES.items():
            config = work / f"{name}.cfg"
            config.write_text(
                "SPECIFICATION Spec\nINVARIANT Safety\nPROPERTY Termination\nCONSTANTS\n"
                + "".join(f"{key} = {'TRUE' if key in enabled else 'FALSE'}\n"
                          for key in CONSTANTS)
            )
            check_case(work, args.jar.resolve(), "synchronization", name, config, expected)
        # These models correspond to the actual .rut fixtures used by the JIT
        # compiler test. Keep the bad and corrected order as a regression pair.
        shutil.copy(ROOT / "spec/receive_before_send.tla", work)
        for name, expected in (("receive_before_send", "Deadlock"),
                               ("send_before_receive", "None")):
            config = work / f"{name}.cfg"
            shutil.copy(ROOT / "spec" / config.name, config)
            check_case(work, args.jar.resolve(), "receive_before_send", name, config, expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
