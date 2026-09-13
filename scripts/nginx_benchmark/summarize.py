#!/usr/bin/env python3
"""Summarize a run without presenting errored or incomplete groups as capacity."""

import argparse
import csv
import json
import statistics
from pathlib import Path


def aggregate(rows, repeats, complete):
    groups = {}
    for row in rows:
        key = tuple(row[k] for k in ("workload", "connection", "concurrency", "engine"))
        groups.setdefault(key, []).append(row)
    result = {}
    for key, samples in groups.items():
        group = dict(zip(("workload", "connection", "concurrency", "engine"), key))
        group.update(
            samples=len(samples),
            valid=complete
            and len(samples) == repeats
            and {s["rep"] for s in samples} == set(range(1, repeats + 1))
            and all(
                s["valid"]
                and s["rps"] > 0
                and not any(s["errors"].values())
                and not any(s["warmup_errors"].values())
                for s in samples
            ),
            measurement_errors=sum(sum(s["errors"].values()) for s in samples),
            warmup_errors=sum(sum(s["warmup_errors"].values()) for s in samples),
        )
        for metric in (
            "rps",
            "p50_us",
            "p95_us",
            "p99_us",
            "server_cpu_pct",
            "origin_cpu_pct",
            "server_rss_bytes",
        ):
            group[metric] = statistics.median(s[metric] for s in samples)
        group["rps_min"] = min(s["rps"] for s in samples)
        group["rps_max"] = max(s["rps"] for s in samples)
        group["client_cpu_pct"] = statistics.median(
            s["client_cpu_seconds"] / s["seconds"] * 100 for s in samples
        )
        result[key] = group
    return result


def render(groups):
    lines = [
        "# Local nginx / RUT benchmark",
        "",
        (
            "Medians of per-run metrics; p99 values are not merged histograms. "
            "Errored, zero-throughput, missing-repeat or incomplete groups have no capacity ratio."
        ),
        "",
        "| Workload | Connection | Concurrency | nginx req/s | RUT req/s | RUT/nginx | nginx p99 µs | RUT p99 µs |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for key in sorted({k[:3] for k in groups}):
        nginx = groups.get((*key, "nginx"))
        rut = groups.get((*key, "rut"))

        def metric(row, field):
            return (
                f"{row[field]:,.0f}" if row and row["valid"] else "INVALID / INCOMPLETE"
            )

        ratio = (
            f"{rut['rps'] / nginx['rps']:.2f}×"
            if nginx and rut and nginx["valid"] and rut["valid"] and nginx["rps"] > 0
            else "—"
        )
        lines.append(
            f"| {key[0]} | {key[1]} | {key[2]} | {metric(nginx, 'rps')} | {metric(rut, 'rps')} | "
            f"{ratio} | {metric(nginx, 'p99_us')} | {metric(rut, 'p99_us')} |"
        )
    lines += [
        "",
        (
            "Raw values, warmup/measurement errors, repeat counts, CPU and RSS are in summary.csv. "
            "Raw values from invalid groups are diagnostic only. Socket errors are not a request failure rate. "
            "Each frontend process persists across concurrency levels within a repeat. "
            "See environment.json for conditions and status.json for completion/cleanup status."
        ),
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory = args.directory
    rows = json.loads((directory / "results.json").read_text())
    env = json.loads((directory / "environment.json").read_text())
    status = json.loads((directory / "status.json").read_text())
    groups = aggregate(rows, env["arguments"]["repeats"], status["complete"])
    if not groups:
        parser.error("no measured samples")
    with (directory / "summary.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(next(iter(groups.values()))))
        writer.writeheader()
        writer.writerows(groups.values())
    report = render(groups)
    (directory / "REPORT.md").write_text(report)
    print(report, end="")


if __name__ == "__main__":
    main()
