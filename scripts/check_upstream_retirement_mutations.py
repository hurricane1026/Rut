#!/usr/bin/env python3
"""Require concrete upstream retirement tests to reject isolated C++ header mutations.

Uses an existing Ninja build's compile/link commands and pinned libraries.
Never edits the source tree, build objects, or original test executable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = Path("rut/runtime/iouring_event_loop.h")
MUTATIONS = {
    "more_releases_owner": (" || ev.more) return true;", ") return true;"),
    "duplicate_releases_owner": (" || (*owned & retirement_op) == 0", ""),
}
FILTER = "--filter=all_send_recv_completion_permutations_preserve_exact_owners"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    ninja = shutil.which("ninja") or shutil.which("ninja-build")
    if not ninja:
        parser.error("the configured Ninja build is required")
    baseline = subprocess.run([str(build / "tests/test_network"), FILTER], capture_output=True, text=True, timeout=60)
    if baseline.returncode or not re.search(r"\b[1-9][0-9]* passed, 0 failed", baseline.stdout):
        raise RuntimeError(f"baseline retirement tests failed\n{baseline.stdout}{baseline.stderr}")
    entries = json.loads((build / "compile_commands.json").read_text())
    entry = next(e for e in entries if Path(e["file"]).resolve() == ROOT / "tests/test_network.cc")
    compile_base = entry.get("arguments") or shlex.split(entry["command"])
    commands = subprocess.check_output([ninja, "-C", str(build), "-t", "commands", "test_network"], text=True)
    link_line = next(line for line in commands.splitlines() if " -o tests/test_network " in line)
    link_base = shlex.split(link_line)
    # CMake's Ninja link rule wraps one compiler invocation with ': && ... && :'.
    if link_base[:2] != [":", "&&"] or link_base[-2:] != ["&&", ":"]:
        raise RuntimeError("unrecognized CMake/Ninja link wrapper")
    link_base = link_base[2:-2]
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rut-retirement-mutations-") as directory:
        work = Path(directory)
        original = (ROOT / "include" / HEADER).read_text()
        begin = original.index("    bool consume_strict_upstream_retirement_event(")
        end = original.index("        // A live successor can have", begin)
        scoped = original[begin:end]
        for name, (old, new) in MUTATIONS.items():
            if scoped.count(old) != 1:
                raise RuntimeError(f"mutation drift: {name}: expected exactly one source match")
            overlay = work / name
            header = overlay / HEADER
            header.parent.mkdir(parents=True)
            header.write_text(original[:begin] + scoped.replace(old, new) + original[end:])
            obj = overlay / "probe.o"
            executable = overlay / "probe"
            command = list(compile_base)
            command.insert(1, f"-I{overlay}")
            command[command.index("-o") + 1] = str(obj)
            if "-MF" in command:
                command[command.index("-MF") + 1] = str(overlay / "probe.d")
            command.append("-O0")
            compiled = subprocess.run(command, cwd=entry["directory"], capture_output=True, text=True, timeout=300)
            if compiled.returncode:
                raise RuntimeError(f"{name}: mutant did not compile\n{compiled.stdout}{compiled.stderr}")
            link = list(link_base)
            object_index = next(i for i, x in enumerate(link) if x.endswith("test_network.cc.o"))
            link[object_index] = str(obj)
            link[link.index("-o") + 1] = str(executable)
            link = [f"--dependency-file={overlay / 'link.d'}" if x.startswith("--dependency-file=") else x for x in link]
            linked = subprocess.run(link, cwd=build, capture_output=True, text=True, timeout=60)
            if linked.returncode:
                raise RuntimeError(f"{name}: mutant did not link\n{linked.stdout}{linked.stderr}")
            result = subprocess.run([str(executable), FILTER], capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
            if args.output_dir:
                (args.output_dir / f"{name}.log").write_text(output)
            if result.returncode <= 0 or not re.search(r"\b[1-9][0-9]* failed", output):
                raise RuntimeError(f"{name}: expected test assertions, not success/crash\n{output}")
            print(f"PASS {name}: concrete C++ tests rejected the mutant", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
