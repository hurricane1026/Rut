#!/usr/bin/env python3
"""Run the explicit HTTP/TLS/body-size matrix; missing/failed cells never pass."""
import argparse
import itertools
import json
import statistics
import subprocess
import sys
from pathlib import Path

from run import SCENARIOS, positive, save_json


def assess(rows, scenario, transport, size, concurrency, repeats, duration):
    work, connection = scenario.split("-")
    selected = [r for r in rows if r.get("concurrency") == concurrency]
    engines = {}
    for engine in ("nginx", "rut"):
        samples = [r for r in selected if r.get("engine") == engine]
        valid = len(samples) == repeats and {r.get("rep") for r in samples} == set(range(1, repeats + 1))
        valid = valid and all(
            r.get("valid") and r.get("workload") == work
            and r.get("connection") == connection and r.get("transport") == transport
            and r.get("body_size") == size and r.get("requests", 0) > 0
            and r.get("rps", 0) > 0 and not any(r.get("errors", {"missing": 1}).values())
            and not any(r.get("warmup_errors", {"missing": 1}).values())
            for r in samples
        )
        engines[engine] = statistics.median(r["rps"] for r in samples) if valid else None
    ratio = engines["rut"] / engines["nginx"] if all(engines.values()) else None
    # Short smoke runs establish functionality, never performance acceptance.
    eligible = repeats >= 3 and duration >= 5
    return {"scenario": scenario, "transport": transport, "body_size": size,
            "concurrency": concurrency, "median_rps": engines, "rut_over_nginx": ratio,
            "measurement_valid": ratio is not None, "performance_eligible": eligible,
            "target_met": eligible and ratio is not None and ratio >= 1.10}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tls-cert", type=Path, required=True)
    parser.add_argument("--tls-key", type=Path, required=True)
    parser.add_argument("--transports", nargs="+", choices=("http", "https"), default=["http", "https"])
    parser.add_argument("--body-sizes", nargs="+", type=positive, default=[16, 1024, 65536, 1048576])
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS))
    parser.add_argument("--concurrency", nargs="+", type=positive, default=[1, 32, 128])
    parser.add_argument("--duration", type=positive, default=10)
    parser.add_argument("--warmup", type=positive, default=2)
    parser.add_argument("--repeats", type=positive, default=3)
    args, common = parser.parse_known_args()
    for values in (args.transports, args.body_sizes, args.scenarios, args.concurrency):
        if len(values) != len(set(values)):
            parser.error("duplicate matrix coordinate")
    if any(n > 1048576 for n in args.body_sizes):
        parser.error("body size exceeds 1 MiB")
    args.output = args.output.resolve()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error("output must be new or empty")
    args.output.mkdir(parents=True, exist_ok=True)
    coordinates = list(itertools.product(args.transports, args.body_sizes, args.scenarios))
    report = {"complete": False, "target_met": False,
              "expected_cells": len(coordinates) * len(args.concurrency), "cells": []}
    save_json(args.output / "matrix.json", report)
    try:
        for transport, size, scenario in coordinates:
            folder = args.output / f"{transport}-{size}-{scenario}"
            command = [sys.executable, str(Path(__file__).with_name("run.py")), *common,
                       "--output", str(folder), "--body-size", str(size), "--scenarios", scenario,
                       "--concurrency", *map(str, args.concurrency), "--duration", str(args.duration),
                       "--warmup", str(args.warmup), "--repeats", str(args.repeats)]
            if transport == "https":
                command += ["--tls-cert", str(args.tls_cert.resolve()), "--tls-key", str(args.tls_key.resolve())]
            with (args.output / (folder.name + ".log")).open("w") as log:
                # Child harness owns cleanup; keep it in our process group so
                # an interactive interrupt reaches both parent and child.
                completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
            rows_path = folder / "results.json"
            rows = json.loads(rows_path.read_text()) if rows_path.exists() else []
            for concurrency in args.concurrency:
                cell = assess(rows, scenario, transport, size, concurrency, args.repeats, args.duration)
                cell.update(exit_code=completed.returncode, evidence=str(folder), command=command)
                if completed.returncode != 0:
                    cell["measurement_valid"] = cell["target_met"] = False
                report["cells"].append(cell)
            save_json(args.output / "matrix.json", report)
            print(folder.name, "exit", completed.returncode, flush=True)
        report["complete"] = len(report["cells"]) == report["expected_cells"]
        report["target_met"] = report["complete"] and all(c["target_met"] for c in report["cells"])
        return 0 if report["target_met"] else 2
    finally:
        save_json(args.output / "matrix.json", report)


if __name__ == "__main__":
    sys.exit(main())
