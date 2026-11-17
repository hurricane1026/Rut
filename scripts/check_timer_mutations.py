#!/usr/bin/env python3
"""Require concrete timer tests to reject isolated production header mutations.

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
MUTATIONS = {
    "wheel_off_by_one": ("rut/runtime/timer_wheel.h",
                         "&slots[cursor & (kSlots - 1)]",
                         "&slots[(cursor + 1) & (kSlots - 1)]"),
    "heap_scan_sifts_before_compacting": (
        "rut/runtime/epoll_event_loop.h",
        """        u32 kept = 0;
        for (u32 i = 0; i < size; ++i) {
            if (entries[i].conn_id != conn_id) entries[kept++] = entries[i];
        }
        const u32 removed = size - kept;
        size = kept;
        if (removed > 0) {
            for (u32 i = size / 2; i > 0; --i) sift_down(i - 1);
        }""",
        """        u32 removed = 0;
        u32 i = 0;
        while (i < size) {
            if (entries[i].conn_id != conn_id) { ++i; continue; }
            entries[i] = entries[--size];
            ++removed;
            if (i < size) { sift_up(i); sift_down(i); }
        }"""),
    "stale_uring_disarms_successor": ("rut/runtime/iouring_event_loop.h",
                                      "if (matching_generation) {", "if (true) {"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    run_implementation_mutations(args.build_dir, args.output_dir, "test_timer_model", MUTATIONS,
                                 {"wheel_off_by_one": ["--filter=wheel_deadline_boundary_smoke"]})
    return 0


def run_implementation_mutations(build: Path, output_dir: Path | None, target: str,
                                 mutations: dict, filters: dict | None = None) -> None:
    build = build.resolve()
    ninja = shutil.which("ninja") or shutil.which("ninja-build")
    if not ninja:
        raise RuntimeError("the configured Ninja build is required")
    baseline = subprocess.run([str(build / f"tests/{target}")], capture_output=True, text=True, timeout=60)
    if baseline.returncode or not re.search(r"\b[1-9][0-9]* passed, 0 failed", baseline.stdout):
        raise RuntimeError(f"baseline timer tests failed\n{baseline.stdout}{baseline.stderr}")
    entries = json.loads((build / "compile_commands.json").read_text())
    entry = next(e for e in entries if Path(e["file"]).resolve() == ROOT / f"tests/{target}.cc")
    compile_base = entry.get("arguments") or shlex.split(entry["command"])
    commands = subprocess.check_output([ninja, "-C", str(build), "-t", "commands", target], text=True)
    link_line = next(line for line in commands.splitlines() if f" -o tests/{target} " in line)
    link_base = shlex.split(link_line)
    # CMake's Ninja link rule wraps one compiler invocation with ': && ... && :'.
    if link_base[:2] != [":", "&&"] or link_base[-2:] != ["&&", ":"]:
        raise RuntimeError("unrecognized CMake/Ninja link wrapper")
    link_base = link_base[2:-2]
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rut-timer-mutations-") as directory:
        work = Path(directory)
        for name, (relative, old, new) in mutations.items():
            original = (ROOT / "include" / relative).read_text()
            if original.count(old) != 1:
                raise RuntimeError(f"mutation drift: {name}: expected exactly one source match")
            overlay = work / name
            header = overlay / relative
            header.parent.mkdir(parents=True)
            header.write_text(original.replace(old, new))
            obj = overlay / "probe.o"
            executable = overlay / "probe"
            command = list(compile_base)
            command.insert(1, f"-I{overlay}")
            command[command.index("-o") + 1] = str(obj)
            if "-MF" in command:
                command[command.index("-MF") + 1] = str(overlay / "probe.d")
            command.append("-O0")
            compiled = subprocess.run(command, cwd=entry["directory"], capture_output=True, text=True, timeout=180)
            if compiled.returncode:
                raise RuntimeError(f"{name}: mutant did not compile\n{compiled.stdout}{compiled.stderr}")
            link = list(link_base)
            object_index = next(i for i, x in enumerate(link) if x.endswith(f"{target}.cc.o"))
            link[object_index] = str(obj)
            link[link.index("-o") + 1] = str(executable)
            link = [f"--dependency-file={overlay / 'link.d'}" if x.startswith("--dependency-file=") else x for x in link]
            linked = subprocess.run(link, cwd=build, capture_output=True, text=True, timeout=60)
            if linked.returncode:
                raise RuntimeError(f"{name}: mutant did not link\n{linked.stdout}{linked.stderr}")
            arguments = (filters or {}).get(name, [])
            result = subprocess.run([str(executable), *arguments], capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
            if output_dir:
                (output_dir / f"{name}.log").write_text(output)
            if result.returncode <= 0 or not re.search(r"\b[1-9][0-9]* failed", output):
                raise RuntimeError(f"{name}: expected test assertions, not success/crash\n{output}")
            print(f"PASS {name}: concrete C++ tests rejected the mutant", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
