#!/usr/bin/env python3
"""Run the explicit HTTP/TLS/body-size matrix; missing/failed cells never pass."""
import argparse
import itertools
import json
import math
import signal
import statistics
import subprocess
import sys
from pathlib import Path

from run import (SCENARIOS, ERROR_NAMES, positive, save_json,
                 add_measurement_arguments, resolve_measurement_arguments,
                 print_measurement_budget)


def run_cell(command, log):
    # The child owns its containers. Isolate terminal signals, then forward a
    # single termination request so its cleanup cannot receive the signal twice.
    with subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                          start_new_session=True) as child:
        try:
            return child.wait()
        except BaseException:
            previous = {sig: signal.signal(sig, signal.SIG_IGN)
                        for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
            raise


def finite_nonnegative(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def sample_shape_valid(row):
    if not isinstance(row, dict) or type(row.get("valid")) is not bool:
        return False
    if not all(isinstance(row.get(key), str)
               for key in ("workload", "connection", "transport", "engine")):
        return False
    if not all(type(row.get(key)) is int and row[key] >= 0
               for key in ("body_size", "concurrency", "rep", "requests")):
        return False
    if not all(finite_nonnegative(row.get(key)) for key in ("rps", "seconds")):
        return False
    return all(isinstance(row.get(key), dict) and set(row[key]) == set(ERROR_NAMES)
               and all(type(value) is int and value >= 0 for value in row[key].values())
               for key in ("errors", "warmup_errors"))


def load_evidence(folder):
    try:
        rows = json.loads((folder / "results.json").read_text())
        status = json.loads((folder / "status.json").read_text())
        if not isinstance(rows, list) or not all(sample_shape_valid(row) for row in rows):
            raise ValueError("results.json must contain well-formed benchmark samples")
        if not isinstance(status, dict) or any(type(status.get(key)) is not bool
                                               for key in ("complete", "valid")):
            raise ValueError("status.json must contain boolean complete and valid fields")
        return rows, status, None
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        # Partial/missing artifacts belong to this coordinate, not the whole
        # matrix. Keep the files and diagnosis, and continue later coordinates.
        return [], {}, f"{type(error).__name__}: {error}"


def assess(rows, scenario, transport, size, concurrency, repeats, duration, static_profile=None):
    work, connection = scenario.split("-")
    if not isinstance(rows, list) or not all(sample_shape_valid(row) for row in rows):
        rows = []
    selected = [r for r in rows if r.get("concurrency") == concurrency]
    engines = {}
    for engine in ("nginx", "rut"):
        samples = [r for r in selected if r.get("engine") == engine]
        valid = len(selected) == 2 * repeats and len(samples) == repeats and {r.get("rep") for r in samples} == set(range(1, repeats + 1))
        valid = valid and all(
            r.get("valid") and r.get("workload") == work
            and r.get("connection") == connection and r.get("transport") == transport
            and (work != "static" or static_profile is None
                 or r.get("static_profile", "converter-return") == static_profile)
            and r.get("body_size") == size and r.get("requests", 0) > 0
            and r.get("rps", 0) > 0 and r["seconds"] > 0
            and set(r.get("errors", {})) == set(ERROR_NAMES)
            and set(r.get("warmup_errors", {})) == set(ERROR_NAMES)
            and not any(r.get("errors", {"missing": 1}).values())
            and not any(r.get("warmup_errors", {"missing": 1}).values())
            for r in samples
        )
        engines[engine] = statistics.median(r["rps"] for r in samples) if valid else None
        if not finite_nonnegative(engines[engine]):
            engines[engine] = None
    ratio = engines["rut"] / engines["nginx"] if all(engines.values()) else None
    if not finite_nonnegative(ratio):
        ratio = None
    # Short smoke runs establish functionality, never performance acceptance.
    eligible = (repeats >= 3 and duration >= 5 and len(selected) == 2 * repeats
                and all(r["seconds"] >= 5 for r in selected))
    return {"scenario": scenario, "transport": transport, "body_size": size,
            "concurrency": concurrency, "median_rps": engines, "rut_over_nginx": ratio,
            "measurement_valid": ratio is not None, "performance_eligible": eligible,
            "target_met": eligible and ratio is not None and ratio >= 1.10}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-profile", choices=("converter-return", "native-body"), default="converter-return")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tls-cert", type=Path, required=True)
    parser.add_argument("--tls-key", type=Path, required=True)
    parser.add_argument("--transports", nargs="+", choices=("http", "https"), default=["http", "https"])
    parser.add_argument("--body-sizes", nargs="+", type=positive, default=[16, 1024, 65536, 1048576])
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS))
    parser.add_argument("--concurrency", nargs="+", type=positive, default=[1, 32, 128])
    add_measurement_arguments(parser, full_duration=10)
    args, common = parser.parse_known_args()
    resolve_measurement_arguments(args)
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
              "profile": args.profile, "static_profile": args.static_profile,
              "expected_cells": len(coordinates) * len(args.concurrency), "cells": []}
    print_measurement_budget(args, report["expected_cells"])
    save_json(args.output / "matrix.json", report)
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    try:
        for transport, size, scenario in coordinates:
            folder = args.output / f"{transport}-{size}-{scenario}"
            command = [sys.executable, str(Path(__file__).with_name("run.py")), *common,
                       "--profile", args.profile, "--static-profile", args.static_profile,
                       "--output", str(folder), "--body-size", str(size), "--scenarios", scenario,
                       "--concurrency", *map(str, args.concurrency), "--duration", str(args.duration),
                       "--warmup", str(args.warmup), "--repeats", str(args.repeats)]
            if transport == "https":
                command += ["--tls-cert", str(args.tls_cert.resolve()), "--tls-key", str(args.tls_key.resolve())]
            with (args.output / (folder.name + ".log")).open("w") as log:
                returncode = run_cell(command, log)
            rows, status, evidence_error = load_evidence(folder)
            # Exit 1 means a completed run contains bad samples. Assess each
            # concurrency independently; only incomplete/setup failures discard
            # every group, including results written before cleanup failed.
            completed = returncode in (0, 1) and status.get("complete") is True
            for concurrency in args.concurrency:
                cell = assess(rows, scenario, transport, size, concurrency, args.repeats, args.duration,
                              args.static_profile)
                if scenario.startswith("static-"):
                    cell["static_profile"] = args.static_profile
                cell.update(exit_code=returncode, evidence=str(folder), command=command)
                if evidence_error:
                    cell["evidence_error"] = evidence_error
                if not completed:
                    cell["measurement_valid"] = cell["target_met"] = False
                report["cells"].append(cell)
            save_json(args.output / "matrix.json", report)
            print(folder.name, "exit", returncode, flush=True)
        report["complete"] = len(report["cells"]) == report["expected_cells"]
        report["target_met"] = report["complete"] and all(c["target_met"] for c in report["cells"])
        return 0 if report["target_met"] else 2
    finally:
        save_json(args.output / "matrix.json", report)


if __name__ == "__main__":
    sys.exit(main())
