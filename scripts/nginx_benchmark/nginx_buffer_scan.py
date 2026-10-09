#!/usr/bin/env python3
"""Screen nginx buffers, then recheck two candidates against Rut serially."""

import argparse
import json
import os
from pathlib import Path
import random
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--screen-duration", type=int, default=10)
    parser.add_argument("--confirm-duration", type=int, default=15)
    parser.add_argument("--confirm-repeats", type=int, default=3)
    args, harness_args = parser.parse_known_args()
    if min(args.screen_duration, args.confirm_duration, args.confirm_repeats) < 1:
        parser.error("durations and repeat count must be positive")
    reserved = ("--duration", "--repeats", "--engines", "--nginx-buffer-kib", "--nginx-buffering")
    if any(flag in harness_args for flag in reserved):
        parser.error("scan controls duration, repeats, engines and nginx buffer options")
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    configs = [("off", size) for size in (16, 32, 64, 128, 256, 512, 1024)]
    configs += [("on", size) for size in (16, 64, 128, 256)]
    random.Random(20261010).shuffle(configs)
    driver = Path(__file__).with_name("relay_compare.py")

    def run(label, buffering, size, engine, duration):
        command = [sys.executable, str(driver), *harness_args, "--engines", engine,
                   "--nginx-buffering", buffering, "--nginx-buffer-kib", str(size),
                   "--duration", str(duration), "--repeats", "1", "--output", str(args.output / label)]
        with (args.output / "commands.jsonl").open("a") as handle:
            handle.write(json.dumps({"label": label, "argv": command}) + "\n")
        print("START " + label, flush=True)
        log = args.output / (label + ".log")
        with log.open("w") as handle:
            process = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT, env=os.environ.copy())
        if process.returncode:
            raise RuntimeError(f"{label} failed; inspect {log}")
        rows = [json.loads(line) for line in log.read_text().splitlines() if line.startswith('{"requests"')]
        if len(rows) != 1 or not rows[0]["valid"] or any(rows[0]["errors"].values()):
            raise RuntimeError(f"{label} missing or invalid measurement")
        row = rows[0] | {"buffering": buffering, "buffer_kib": size, "scan_label": label}
        print(f'END {label}: {row["rps"]:.0f} RPS p99={row["p99_us"]/1000:.3f}ms', flush=True)
        return row

    for buffering, size in configs:
        row = run(f"screen-{buffering}-{size}k", buffering, size, "nginx", args.screen_duration)
        results.append(row)
        (args.output / "screen-results.json").write_text(json.dumps(results, indent=2) + "\n")
    rank = sorted(results, key=lambda row: row["rps"], reverse=True)
    first = rank[0]
    second = min(results, key=lambda row: row["p99_us"])
    if (first["buffering"], first["buffer_kib"]) == (second["buffering"], second["buffer_kib"]):
        second = rank[1]
    selected = [(row["buffering"], row["buffer_kib"]) for row in (first, second)]
    (args.output / "selected-configs.json").write_text(json.dumps(selected, indent=2) + "\n")
    confirmed = []
    for repeat in range(1, args.confirm_repeats + 1):
        order = [("nginx", *choice) for choice in selected] + [("uring", "off", 1024)]
        offset = (repeat - 1) % len(order)
        order = order[offset:] + order[:offset]
        for engine, buffering, size in order:
            name = f"{buffering}-{size}k" if engine == "nginx" else "rut"
            row = run(f"confirm-{name}-r{repeat}", buffering, size, engine, args.confirm_duration)
            confirmed.append(row | {"outer_repeat": repeat})
            (args.output / "confirm-results.json").write_text(json.dumps(confirmed, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
