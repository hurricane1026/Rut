#!/usr/bin/env python3
"""Compute first-party coverage as the union across test binaries.

The default `llvm-cov report` aggregates over all `--object` binaries by
picking the first-listed binary's instantiation for each source line.
That's wrong for inline/template functions in headers: if binary A
instantiates `handle_jit_outcome<Loop>` for a loop type that never
exercises a branch, binary B's real coverage of the same branch is
invisible in the combined report.

This script instead exports per-binary JSON, walks the line segments,
and reports a line as covered if ANY binary hits it. That matches how
people read "overall coverage" and matches how coverage of library
code should be measured in multi-binary test suites.

Usage:
    coverage_report.py --profile PATH --threshold PCT BINARY [BINARY ...]
    coverage_report.py --profile PATH --threshold PCT --changed-files-from changed.txt BINARY...
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
import subprocess
import sys


@dataclass(frozen=True)
class CoverageArea:
    name: str
    sources: tuple[str, ...]
    exclude: re.Pattern[str] | None = None


# Runtime files excluded from the coverage gate:
#   - io_uring_backend / epoll_backend: require kernel features / perms
#     not available in CI
#   - socket.cc / access_log.cc / shard.h: thin wrappers or shard
#     bookkeeping that belong in a later test pass
#   - epoll_event_loop.h / iouring_event_loop.h: constructor-only headers
RUNTIME_EXCLUDE_PATH_RE = re.compile(
    r"io_uring_backend|epoll_backend|socket\.cc|access_log\.cc|"
    r"shard\.h|epoll_event_loop\.h|iouring_event_loop\.h"
)

AREAS = (
    CoverageArea(
        "runtime",
        ("include/rut/common/", "include/rut/runtime/", "src/runtime/"),
        RUNTIME_EXCLUDE_PATH_RE,
    ),
    CoverageArea("parser", ("include/rut/compiler/", "src/compiler/")),
    CoverageArea("replay/sim", ("include/rut/sim/", "src/sim/")),
    CoverageArea("jit", ("include/rut/jit/", "src/jit/")),
)

FIRST_PARTY_SOURCES = sorted({source for area in AREAS for source in area.sources})


def area_for_path(path: str) -> CoverageArea | None:
    for area in AREAS:
        if any(source in path for source in area.sources):
            if area.exclude and area.exclude.search(path):
                return None
            return area
    return None


def per_binary_segments(profile: str, binary: str) -> dict:
    """Return llvm-cov JSON export for one binary restricted to first-party sources."""
    proc = subprocess.run(
        [
            "llvm-cov",
            "export",
            f"--instr-profile={profile}",
            f"--object={binary}",
            "--sources",
            *FIRST_PARTY_SOURCES,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


def merge_line_hits(binaries: list[str], profile: str) -> dict[str, dict[str, dict[int, int]]]:
    """For each first-party source file, max-merge per-line counts across binaries."""
    merged: dict[str, dict[str, dict[int, int]]] = {area.name: {} for area in AREAS}
    for b in binaries:
        data = per_binary_segments(profile, b)
        for f in data["data"][0]["files"]:
            path = f["filename"]
            if "/tests/" in path or path.endswith("test.h") or "/third_party/" in path:
                continue
            # Limit to first-party source prefixes. llvm-cov export
            # occasionally leaks transitively-referenced files here
            # (core/expected.h, placement_new.cc) that the CI report
            # mode would have filtered out via --sources.
            area = area_for_path(path)
            if area is None:
                continue
            area_files = merged[area.name]
            lines = area_files.setdefault(path, {})
            for seg in f.get("segments", []):
                # seg: [line, col, count, hasCount, isRegionEntry, isGapRegion]
                if len(seg) < 6 or not seg[3] or seg[5]:
                    continue
                line = seg[0]
                cnt = seg[2]
                # Keep the highest hit count across binaries; a line is
                # "covered" iff at least one binary reached it.
                if line not in lines or cnt > lines[line]:
                    lines[line] = cnt
    return merged


def area_stats(files: dict[str, dict[int, int]]) -> tuple[int, int, list[tuple[int, int, int, str]]]:
    total = 0
    covered = 0
    per_file_stats = []
    for path, lines in files.items():
        c = sum(1 for v in lines.values() if v > 0)
        t = len(lines)
        total += t
        covered += c
        per_file_stats.append((t - c, t, c, path))
    per_file_stats.sort(key=lambda x: (-x[0], x[3]))
    return covered, total, per_file_stats


def normalize_changed_path(path: str) -> str | None:
    path = path.strip()
    if not path:
        return None
    normalized = PurePosixPath(path).as_posix()
    if normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("/") or normalized.startswith("../"):
        return None
    return normalized


def read_changed_files(paths: list[str], files_from: list[str]) -> list[str]:
    changed: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        normalized = normalize_changed_path(path)
        if normalized and normalized not in seen:
            seen.add(normalized)
            changed.append(normalized)

    for path in paths:
        add(path)
    for list_path in files_from:
        with open(list_path, encoding="utf-8") as f:
            for line in f:
                add(line)
    return changed


def print_changed_file_summary(
    merged: dict[str, dict[str, dict[int, int]]], changed_files: list[str]
) -> None:
    if not changed_files:
        return

    by_changed_path: dict[str, tuple[str, int, int, int]] = {}
    for area_name, files in merged.items():
        for cov_path, lines in files.items():
            for changed_path in changed_files:
                if not cov_path.endswith(changed_path):
                    continue
                covered = sum(1 for v in lines.values() if v > 0)
                total = len(lines)
                missed = total - covered
                by_changed_path[changed_path] = (area_name, missed, total, covered)

    print("\nChanged first-party files:")
    print(f"{'Area':<12} {'Missed':>7} {'Total':>7} {'Cover':>7}  File")
    for changed_path in changed_files:
        stats = by_changed_path.get(changed_path)
        if stats is None:
            area = area_for_path(changed_path)
            if area is not None:
                print(f"{area.name:<12} {'n/a':>7} {'n/a':>7} {'n/a':>7}  {changed_path}")
            continue
        area_name, missed, total, covered = stats
        pct = 100.0 * covered / total if total else 100.0
        print(f"{area_name:<12} {missed:>7} {total:>7}  {pct:>5.1f}%  {changed_path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True, help="merged .profdata path")
    ap.add_argument("--threshold", type=float, required=True, help="fail below this line pct")
    ap.add_argument(
        "--threshold-area",
        default="runtime",
        choices=[area.name for area in AREAS],
        help="area used for the threshold gate",
    )
    ap.add_argument(
        "--changed-file",
        action="append",
        default=[],
        help="first-party file changed in this PR; may be passed multiple times",
    )
    ap.add_argument(
        "--changed-files-from",
        action="append",
        default=[],
        help="file containing changed paths, one per line",
    )
    ap.add_argument("binaries", nargs="+")
    args = ap.parse_args()

    merged = merge_line_hits(args.binaries, args.profile)
    changed_files = read_changed_files(args.changed_file, args.changed_files_from)

    print(f"{'Area':<12} {'Covered':>10} {'Total':>7} {'Cover':>7}")
    summaries: dict[str, tuple[int, int, list[tuple[int, int, int, str]]]] = {}
    for area in AREAS:
        covered, total, per_file_stats = area_stats(merged[area.name])
        summaries[area.name] = (covered, total, per_file_stats)
        pct = 100.0 * covered / total if total else 100.0
        print(f"{area.name:<12} {covered:>10} {total:>7}  {pct:>5.1f}%")

    gate_covered, gate_total, gate_file_stats = summaries[args.threshold_area]
    gate_pct = 100.0 * gate_covered / gate_total if gate_total else 100.0

    print(f"\nLowest-covered files in {args.threshold_area}:")
    print(f"{'Missed':>7} {'Total':>7} {'Cover':>7}  File")
    for missed, total, covered, path in gate_file_stats:
        pct = 100.0 * covered / total if total else 100.0
        print(f"{missed:>7} {total:>7}  {pct:>5.1f}%  {path}")
    print(
        f"\n{args.threshold_area} TOTAL: "
        f"{gate_covered}/{gate_total} lines covered = {gate_pct:.2f}%"
    )
    print_changed_file_summary(merged, changed_files)

    if gate_pct < args.threshold:
        print(
            f"ERROR: {args.threshold_area} line coverage {gate_pct:.2f}% "
            f"is below {args.threshold}% threshold"
        )
        return 1
    print(f"Coverage OK: {args.threshold_area} {gate_pct:.2f}% >= {args.threshold}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
