#!/usr/bin/env python3
"""Validate retained wrk logs and summarize medians without hiding failures."""
import argparse
import csv
import json
from pathlib import Path
import statistics
import sys

from common import load_config, provenance_fingerprint, write_json


def sample_metrics(output: Path, relative: str) -> dict:
    directory = output / relative
    log = (directory / "wrk.log").read_text()
    if (directory / "returncode.txt").read_text().strip() != "0":
        raise ValueError(f"nonzero wrk return code: {directory}")
    records = [line.split() for line in log.splitlines() if line.startswith("METRICS ")]
    if len(records) != 1 or len(records[0]) != 11:
        raise ValueError(f"missing/invalid METRICS line: {directory}")
    fields = [int(x) for x in records[0][1:]]
    requests, duration_us, p50, p95, p99, *errors = fields
    if requests <= 0 or duration_us <= 0 or any(errors):
        raise ValueError(f"empty or errorful sample {directory}: {records[0]}")
    if "Permission denied" in log or "cannot open /benchmark/" in log:
        raise ValueError(f"wrk script was not readable: {directory}")
    return {"requests": requests, "duration_us": duration_us,
            "rps": requests * 1_000_000 / duration_us,
            "p50_us": p50, "p95_us": p95, "p99_us": p99,
            "errors": {name: value for name, value in zip(("connect", "read", "write", "status", "timeout"), errors)}}


def resource_metrics(output: Path, row: dict) -> dict:
    path = output / Path(row["validation_path"]).parent / "resources-summary.json"
    fields = {}
    for role in ("proxy", "origin"):
        for stage in ("idle", "after_warmup", "under_load"):
            for measure in ("rss_kb", "pss_kb"):
                fields[f"{role}_{stage}_{measure}"] = None
    fields.update({"proxy_executable_bytes": None, "proxy_executables": [],
                   "proxy_dynamic_dependency_bytes": None, "proxy_dynamic_dependencies": [],
                   "origin_dynamic_dependency_bytes": None, "origin_dynamic_dependencies": [],
                   "proxy_under_load_observations": 0, "origin_under_load_observations": 0,
                   "resource_sampling_complete": False})
    if not path.is_file():
        return fields
    data = json.loads(path.read_text())
    executables = data.get("frontend_executables", [])
    dependencies = data.get("mapped_shared_objects", {})

    def phase(role: str, name: str) -> tuple[int | None, int | None]:
        record = (data.get(name) or {}).get(role)
        if not record or not record.get("complete"):
            return None, None
        return record.get("rss_kb"), record.get("pss_kb")

    for role in ("proxy", "origin"):
        for stage, source in (("idle", "idle"), ("after_warmup", "after_warmup")):
            rss, pss = phase(role, source)
            fields[f"{role}_{stage}_rss_kb"] = rss
            fields[f"{role}_{stage}_pss_kb"] = pss
    samples = data.get("under_load_samples", [])
    valid_samples = [item for item in samples if item.get("snapshot_valid")]
    for role in ("proxy", "origin"):
        role_samples = [item.get(role, {}) for item in valid_samples]
        for measure in ("rss_kb", "pss_kb"):
            values = [item[measure] for item in role_samples if item.get("complete") and item.get(measure) is not None]
            fields[f"{role}_under_load_{measure}"] = statistics.median(values) if values else None
        fields[f"{role}_under_load_observations"] = sum(1 for item in role_samples if item.get("complete"))
    fields["resource_sampling_complete"] = bool(data.get("sampling_complete"))
    fields["proxy_executable_bytes"] = sum(item["size_bytes"] for item in executables) if executables else None
    fields["proxy_executables"] = executables
    for role in ("proxy", "origin"):
        role_dependencies = dependencies.get(role, {})
        fields[f"{role}_dynamic_dependency_bytes"] = role_dependencies.get("total_bytes") if role_dependencies.get("complete") else None
        fields[f"{role}_dynamic_dependencies"] = role_dependencies.get("files", [])
    return fields


def validate_sample_provenance(output: Path, row: dict, expected: str) -> None:
    cell_path = (output / row["validation_path"]).parent / "cell.json"
    if not cell_path.is_file():
        raise ValueError(f"sample has no provenance record: {row.get('validation_path')}")
    cell = json.loads(cell_path.read_text())
    if cell.get("provenance_fingerprint") != expected:
        raise ValueError(f"sample provenance does not match prepared inputs: {row.get('validation_path')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--allow-partial", action="store_true", help="summarize a smoke or interrupted run")
    args = parser.parse_args()
    config = load_config(args.config)
    output = Path(config["output"])
    sample_root = output / "samples"
    index = json.loads((sample_root / "index.json").read_text())
    samples = []
    seen = set()
    expected_provenance = provenance_fingerprint(config)
    for row in index:
        key = (row["body_size"], row["engine"], row["rep"])
        if key in seen:
            raise ValueError(f"duplicate sample: {key}")
        seen.add(key)
        valid = output / row["validation_path"]
        if not row.get("valid") or not valid.is_file():
            raise ValueError(f"sample lacks a valid marker: {key}")
        validate_sample_provenance(output, row, expected_provenance)
        warm = sample_metrics(output, row["warmup_dir"])
        measurement = sample_metrics(output, row["measure_dir"])
        samples.append({**row, **measurement, **resource_metrics(output, row), "warmup": warm})

    expected = {(body, engine, rep) for body in config["bodies"]
                for engine in (("linkerd", "rut-rps", "nginx", "envoy") if body == "4k" else ("linkerd", "rut-throughput", "nginx", "envoy"))
                for rep in range(1, config["repeats"] + 1)}
    missing = sorted(expected - seen)
    unexpected = sorted(seen - expected)
    complete = not missing and not unexpected
    if complete is False and not args.allow_partial:
        raise ValueError(f"matrix incomplete: {len(missing)} missing and {len(unexpected)} unexpected cells")

    groups = []
    for body, size in config["bodies"].items():
        for engine in (("rut-rps", "nginx", "envoy", "linkerd") if body == "4k" else ("rut-throughput", "nginx", "envoy", "linkerd")):
            rows = [item for item in samples if item["body_size"] == body and item["engine"] == engine]
            if not rows:
                continue
            rps = [row["rps"] for row in rows]
            p99 = [row["p99_us"] / 1000 for row in rows]
            resource_fields = ("proxy_executable_bytes", "proxy_dynamic_dependency_bytes", "origin_dynamic_dependency_bytes",
                               "proxy_idle_rss_kb", "proxy_idle_pss_kb",
                               "proxy_after_warmup_rss_kb", "proxy_after_warmup_pss_kb",
                               "proxy_under_load_rss_kb", "proxy_under_load_pss_kb",
                               "origin_idle_rss_kb", "origin_idle_pss_kb",
                               "origin_after_warmup_rss_kb", "origin_after_warmup_pss_kb",
                               "origin_under_load_rss_kb", "origin_under_load_pss_kb")
            resources = {}
            for key in resource_fields:
                values = [row[key] for row in rows if row.get(key) is not None]
                resources[f"median_{key}"] = statistics.median(values) if values else None
                resources[f"{key}_observations"] = len(values)
            groups.append({"body": body, "bytes": size, "engine": engine, "count": len(rows),
                           "median_rps": statistics.median(rps), "min_rps": min(rps), "max_rps": max(rps),
                           "median_payload_gbps": statistics.median(rps) * size * 8 / 1_000_000_000,
                           "median_p99_ms": statistics.median(p99), "min_p99_ms": min(p99), "max_p99_ms": max(p99),
                           **resources})
    report = {"schema": 1, "complete": complete, "sample_count": len(samples), "missing": missing,
              "unexpected": unexpected, "groups": groups, "samples": samples}
    write_json(output / "summary.json", report)
    with (output / "summary.csv").open("w", newline="") as stream:
        resource_fields = ("proxy_executable_bytes", "proxy_dynamic_dependency_bytes", "origin_dynamic_dependency_bytes",
                           "proxy_idle_rss_kb", "proxy_idle_pss_kb", "proxy_after_warmup_rss_kb", "proxy_after_warmup_pss_kb",
                           "proxy_under_load_rss_kb", "proxy_under_load_pss_kb", "origin_idle_rss_kb", "origin_idle_pss_kb",
                           "origin_after_warmup_rss_kb", "origin_after_warmup_pss_kb", "origin_under_load_rss_kb", "origin_under_load_pss_kb")
        writer = csv.DictWriter(stream, fieldnames=("body", "bytes", "engine", "count", "median_rps", "min_rps", "max_rps", "median_payload_gbps", "median_p99_ms", "min_p99_ms", "max_p99_ms", *[f"median_{name}" for name in resource_fields], *[f"{name}_observations" for name in resource_fields]))
        writer.writeheader(); writer.writerows(groups)
    print(json.dumps({"complete": complete, "sample_count": len(samples), "groups": groups}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"summarize: {error}", file=sys.stderr)
        raise SystemExit(2)
