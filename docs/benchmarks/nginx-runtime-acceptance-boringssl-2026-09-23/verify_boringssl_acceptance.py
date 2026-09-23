#!/usr/bin/env python3
"""Audit and archive a BoringSSL native-body acceptance matrix.

The matrix runner is the source of truth for cell verdicts.  This script
independently checks the coordinate set and raw wrk JSON before creating an
archive.  It never starts a benchmark.
"""
import argparse, csv, hashlib, json, os, re, shutil, statistics, subprocess, sys, tarfile, tempfile
from datetime import datetime, timezone
from pathlib import Path

EXPECTED = 96
MIN_SECONDS = 5.0
ENGINES = {"nginx", "rut"}
KEY_WORDS = ("private", "secret", ".key", "key.pem")
FATAL_MARKERS = ("source SHA", "provenance", "binary hash", "remote ref", "invalid/error",
                 "short sample", "missing evidence", "runner cell exit_code", "ratio differs",
                 "median differs", "verdict mismatch", "reps are not", "schema", "metadata mismatch")

def is_fatal_problem(problem):
    return any(marker in problem for marker in FATAL_MARKERS)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def json_lines(path):
    out = []
    for line in Path(path).read_text(errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out

def errors_zero(sample):
    return all(int(v or 0) == 0 for v in sample.get("errors", {}).values()) and \
           all(int(v or 0) == 0 for v in sample.get("warmup_errors", {}).values())

def check_remote_reachability(remote, remote_ref, source_sha):
    """Prove source_sha is an ancestor of the exact remote ref head.

    ls-remote identifies the advertised head, while a temporary bare clone
    supplies the object graph needed by merge-base.  The temporary repository
    is deliberately isolated from every checkout used by the benchmark.
    """
    result = {"remote": remote, "ref": remote_ref,
              "observed_head": None, "checked_at": datetime.now(timezone.utc).isoformat(),
              "reachable": False, "fetch_succeeded": False}
    ls = subprocess.run(["git", "ls-remote", remote, remote_ref], text=True,
                        capture_output=True, check=False)
    lines = [line.split() for line in ls.stdout.splitlines()
             if len(line.split()) >= 2 and line.split()[1] == remote_ref]
    if ls.returncode != 0:
        result["error"] = f"ls-remote failed ({ls.returncode})"
        return result
    if len(lines) != 1 or not re.fullmatch(r"[0-9a-fA-F]{40}", lines[0][0]):
        result["error"] = "remote ref did not resolve to one commit"
        return result
    observed = lines[0][0].lower()
    result["observed_head"] = observed
    with tempfile.TemporaryDirectory(prefix="rut-acceptance-reachability-") as td:
        repo = Path(td) / "objects.git"
        init = subprocess.run(["git", "init", "--bare", "-q", str(repo)],
                              text=True, capture_output=True, check=False)
        if init.returncode != 0:
            result["error"] = "temporary bare repository initialization failed"
            return result
        fetch = subprocess.run(["git", "-C", str(repo), "fetch", "--no-tags", "-q",
                                remote, f"{remote_ref}:refs/acceptance/head"],
                               text=True, capture_output=True, check=False)
        if fetch.returncode != 0:
            result["error"] = f"fetch of remote ref failed ({fetch.returncode})"
            return result
        result["fetch_succeeded"] = True
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "refs/acceptance/head"],
                              text=True, capture_output=True, check=False)
        if head.returncode != 0 or head.stdout.strip().lower() != observed:
            result["error"] = "fetched head differs from ls-remote head"
            return result
        source_obj = subprocess.run(["git", "-C", str(repo), "cat-file", "-e",
                                     f"{source_sha}^{{commit}}"], capture_output=True, check=False)
        head_obj = subprocess.run(["git", "-C", str(repo), "cat-file", "-e",
                                   f"{observed}^{{commit}}"], capture_output=True, check=False)
        if source_obj.returncode != 0 or head_obj.returncode != 0:
            result["error"] = "source or advertised head commit object is missing"
            return result
        ancestor = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                                   source_sha, observed], capture_output=True, check=False)
        result["reachable"] = ancestor.returncode == 0
        if not result["reachable"]:
            result["error"] = "source SHA is not an ancestor of remote ref head"
    return result

def resolve_remote(remote):
    """Resolve a caller worktree remote name while preserving URL arguments."""
    resolved = subprocess.run(["git", "remote", "get-url", remote], text=True,
                              capture_output=True, check=False)
    if resolved.returncode == 0 and resolved.stdout.strip():
        return resolved.stdout.strip()
    return remote

def audit(matrix_path, provenance_path, source_sha=None, remote=None, remote_ref=None):
    matrix = json.loads(Path(matrix_path).read_text())
    provenance = json.loads(Path(provenance_path).read_text())
    cells = matrix.get("cells", [])
    coords = [(c.get("transport"), c.get("scenario"), int(c.get("body_size", -1)),
               int(c.get("concurrency", -1))) for c in cells]
    problems = []
    integrity = {"source_sha_present": False, "required_file_schema": False,
                 "hashes_checked": 0, "hashes_match": 0,
                 "remote_ref_checked": False, "remote_ref_match": False,
                 "exact_head_match": False,
                 "source_reachable_from_remote_ref": False,
                 "remote_reachability": None, "remote_arg": remote,
                 "resolved_url": None}
    if matrix.get("expected_cells") != EXPECTED or len(cells) != EXPECTED:
        problems.append(f"matrix has {len(cells)} cells, expected {EXPECTED}")
    if len(set(coords)) != len(coords):
        problems.append("duplicate cell coordinates")
    expected_coords = {(t, s, b, c) for t in ("http", "https")
                       for s in ("static-close", "static-keepalive", "proxy-close", "proxy-keepalive")
                       for b in (16, 1024, 65536, 1048576) for c in (1, 32, 128)}
    missing = expected_coords - set(coords)
    if missing:
        problems.append(f"missing coordinates: {sorted(missing)[:8]}")
    recorded_source = provenance.get("source_sha") or provenance.get("source_head") or provenance.get("source_revision")
    integrity["source_sha_present"] = bool(recorded_source)
    if not recorded_source:
        problems.append("provenance has no source SHA")
    if source_sha and recorded_source != source_sha:
        problems.append("source SHA does not match requested SHA")
    required_files = {"rut", "converter", "wrk", "wrk_patch"}
    files = provenance.get("files", {})
    hashes = provenance.get("sha256", {})
    integrity["required_file_schema"] = required_files.issubset(files) and required_files.issubset(hashes)
    if not integrity["required_file_schema"]:
        if "binary_hashes_after_run" in provenance:
            problems.append("legacy provenance schema lacks required files/sha256 paths")
        else:
            problems.append("provenance files/sha256 must contain rut, converter, wrk, wrk_patch")
    if remote and source_sha and remote_ref:
        integrity["remote_ref_checked"] = True
        resolved_remote = resolve_remote(remote)
        integrity["resolved_url"] = resolved_remote
        reach = check_remote_reachability(resolved_remote, remote_ref, source_sha)
        integrity["remote_reachability"] = reach
        integrity["exact_head_match"] = bool(reach.get("observed_head") == source_sha)
        integrity["remote_ref_match"] = integrity["exact_head_match"]
        integrity["source_reachable_from_remote_ref"] = bool(reach.get("reachable"))
        if not reach.get("reachable"):
            problems.append(f"remote ref {remote_ref} cannot prove source SHA reachability: {reach.get('error', 'unknown error')}")
    for name in required_files:
        path = files.get(name); expected = hashes.get(name)
        if path and expected: integrity["hashes_checked"] += 1
        if expected and Path(path).is_file() and sha256(path) == expected:
            integrity["hashes_match"] += 1
        elif expected and Path(path).is_file():
            problems.append(f"binary hash changed for {name}")
        elif expected and not Path(path).is_file():
            problems.append(f"provenance file missing for {name}: {path}")

    raw = []; error_samples = []; short_samples = []; cell_checks = []
    for c in cells:
        ev = Path(c["evidence"])
        if not ev.is_dir():
            problems.append(f"missing evidence directory: {ev}")
            continue
        if c.get("exit_code", 0) != 0:
            problems.append(f"runner cell exit_code={c.get('exit_code')} for {ev}")
        samples = []
        result_file = ev / "results.json"
        result_values = json.loads(result_file.read_text()) if result_file.is_file() else []
        expected_workload = c.get("scenario", "").split("-", 1)[0]
        for s in result_values:
            if (s.get("engine") in ENGINES and "rps" in s and
                    s.get("transport") == c.get("transport") and
                    s.get("body_size") == c.get("body_size") and
                    s.get("connection") == c.get("scenario", "").removeprefix("static-").removeprefix("proxy-" ) and
                    s.get("concurrency") == c.get("concurrency") and
                    s.get("workload") == expected_workload and
                    s.get("static_profile") == c.get("static_profile", "native-body") and
                    s.get("proxy_profile") == c.get("proxy_profile", "converter-strict")):
                samples.append((result_file, s))
        if result_values and not samples:
            problems.append(f"{ev}: sample metadata mismatch")
        for log, s in samples:
            if float(s.get("seconds", 0)) < MIN_SECONDS:
                problems.append(f"short sample {log}: {s.get('seconds')}")
                short_samples.append(str(log))
            if not errors_zero(s) or s.get("valid") is False:
                problems.append(f"invalid/error sample {log}")
                error_samples.append(str(log))
            raw.append((c, log, s))
        by_engine = {e: [s for _, s in samples if s.get("engine") == e] for e in ENGINES}
        reps_ok = all(sorted(s.get("rep") for s in by_engine[e]) == [1, 2, 3] for e in ENGINES)
        sample_quality_ok = all(float(s.get("seconds", 0)) >= MIN_SECONDS and
                                errors_zero(s) and s.get("valid") is not False for _, s in samples)
        if any(len(by_engine[e]) != 3 for e in ENGINES):
            problems.append(f"{ev}: expected 3 measurements per engine, got "
                           f"nginx={len(by_engine['nginx'])}, rut={len(by_engine['rut'])}")
        if len(by_engine["nginx"]) == 3 and len(by_engine["rut"]) == 3:
            nm = statistics.median(s["rps"] for s in by_engine["nginx"])
            rm = statistics.median(s["rps"] for s in by_engine["rut"])
            ratio = rm / nm if nm else 0.0
            ratio_ok = ratio >= 1.10
            if abs(ratio - float(c["rut_over_nginx"])) > 1e-9:
                problems.append(f"{ev}: matrix ratio differs from raw recomputation")
            if abs(nm - float(c["median_rps"]["nginx"])) > 1e-6 or abs(rm - float(c["median_rps"]["rut"])) > 1e-6:
                problems.append(f"{ev}: matrix median differs from raw recomputation")
            target_matches = bool(c.get("target_met")) == ratio_ok
            measurement_matches = bool(c.get("measurement_valid")) == (sample_quality_ok and reps_ok)
            if not target_matches: problems.append(f"{ev}: target verdict mismatch")
            if not measurement_matches: problems.append(f"{ev}: measurement_valid mismatch")
            if not reps_ok: problems.append(f"{ev}: reps are not exactly 1,2,3 per engine")
            cell_checks.append({"coordinate": coords[cells.index(c)], "ratio": ratio,
                                "ratio_ok": ratio_ok, "target_matches": target_matches,
                                "measurement_quality_ok": sample_quality_ok,
                                "reps_unique": reps_ok,
                                "measurement_valid_matches": measurement_matches,
                                "raw_recomputed": True})
        else:
            cell_checks.append({"coordinate": coords[cells.index(c)], "raw_recomputed": False,
                                "measurement_quality_ok": sample_quality_ok, "reps_unique": reps_ok,
                                "target_matches": False, "measurement_valid_matches": False})
    return matrix, provenance, cells, raw, problems, error_samples, short_samples, cell_checks, integrity

def archive(args, matrix, provenance, cells, raw, problems, error_samples, short_samples, cell_checks, integrity):
    out = Path(args.output); out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.matrix, out / "matrix.json")
    rows = []
    for c in cells:
        rows.append({"transport": c["transport"], "scenario": c["scenario"],
                     "body_size": c["body_size"], "concurrency": c["concurrency"],
                     "nginx_median_rps": c["median_rps"]["nginx"],
                     "rut_median_rps": c["median_rps"]["rut"],
                     "rut_over_nginx": c["rut_over_nginx"],
                     "measurement_valid": c["measurement_valid"],
                     "target_met": c["target_met"], "evidence": c["evidence"]})
    with open(out / "cells.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    integrity_ok = (integrity["source_sha_present"] and integrity["required_file_schema"] and
                    integrity["hashes_match"] == 4 and integrity["remote_ref_checked"] and
                    integrity["source_reachable_from_remote_ref"])
    verdict = {"accepted": bool(not problems and integrity_ok and args.run_command_json and args.run_timing_json and
                                matrix.get("complete") and matrix.get("target_met") and
                                len(raw) == EXPECTED * 6 and all(c.get("measurement_valid") and c.get("target_met") for c in cells)),
               "runner_complete": matrix.get("complete"), "runner_target_met": matrix.get("target_met"),
               "cell_count": len(cells), "sample_count": len(raw),
               "generated_at": datetime.now(timezone.utc).isoformat()}
    (out / "acceptance.json").write_text(json.dumps(verdict, indent=2) + "\n")
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    source = provenance.get("source_sha") or provenance.get("source_head") or provenance.get("source_revision")
    (out / "command.json").write_text(json.dumps({"matrix": str(Path(args.matrix).resolve()),
                                                   "provenance": str(Path(args.provenance).resolve()),
                                                   "source_sha": source,
                                                   "remote_arg": args.remote,
                                                   "remote": integrity.get("resolved_url") or args.remote,
                                                   "remote_ref": args.remote_ref}, indent=2) + "\n")
    if args.run_timing_json:
        shutil.copyfile(args.run_timing_json, out / "wall-time.json")
    else:
        (out / "wall-time.json").write_text(json.dumps({"verified": False, "reason": "no run timing sidecar supplied"}, indent=2) + "\n")
    actual_coords = {(c.get("transport"), c.get("scenario"), int(c.get("body_size", -1)), int(c.get("concurrency", -1))) for c in cells}
    expected_coords = {(t, s, b, c) for t in ("http", "https")
                       for s in ("static-close", "static-keepalive", "proxy-close", "proxy-keepalive")
                       for b in (16, 1024, 65536, 1048576) for c in (1, 32, 128)}
    checks = {"coordinates_unique_and_complete": len(cells) == EXPECTED and len(actual_coords) == EXPECTED and actual_coords == expected_coords,
              "provenance_integrity": integrity,
              "raw_samples": len(raw), "expected_samples": EXPECTED * 6,
              "all_sample_durations_and_errors_valid": not error_samples and not short_samples,
              "short_samples": short_samples, "error_samples": error_samples,
              "independently_recomputed": all(x.get("raw_recomputed", False) for x in cell_checks),
              "cell_checks": cell_checks, "problems": problems}
    (out / "verification.json").write_text(json.dumps(checks, indent=2) + "\n")
    groups = {}
    below = []
    for c, check in zip(cells, cell_checks):
        key = (c["transport"], int(c["body_size"]))
        g = groups.setdefault(key, {"PASS": 0, "BELOW_TARGET": 0, "INVALID": 0})
        if not check.get("measurement_quality_ok"):
            g["INVALID"] += 1
        elif check.get("ratio_ok"):
            g["PASS"] += 1
        else:
            g["BELOW_TARGET"] += 1
            below.append((c["transport"], c["scenario"], c["body_size"], c["concurrency"], check.get("ratio")))
    perf = "PASS" if matrix.get("complete") and matrix.get("target_met") else "FAIL"
    summary = [f"Performance gate: **{perf}**", "", "| Transport | Body | Pass | Below 1.10 | Invalid |", "|---|---:|---:|---:|---:|"]
    for (transport, body), counts in sorted(groups.items()):
        summary.append(f"| {transport} | {body} | {counts['PASS']} | {counts['BELOW_TARGET']} | {counts['INVALID']} |")
    summary += ["", "Cells below 1.10:"] + [f"- {t} {s} body={b} concurrency={c}: ratio={r:.6f}" for t,s,b,c,r in below]
    report_head = ("# BoringSSL native-body full-96 acceptance\n\n" +
                   f"Source: `{source}`\n\nCells: {len(cells)}; raw samples: {len(raw)}.\n\n")
    report_head += "Raw verification: **PASS**\n" if not problems else \
                   "Raw verification: **FAIL**\n\n" + "\n".join(f"- {p}" for p in problems) + "\n"
    (out / "REPORT.md").write_text(report_head)
    with open(out / "REPORT.md", "a") as f: f.write("\n" + "\n".join(summary) + "\n")
    (out / "README.md").write_text("# BoringSSL acceptance archive\n\n" + "\n".join(summary) + "\n")
    shutil.copyfile(Path(__file__), out / "verify_boringssl_acceptance.py")
    if args.run_command_json:
        shutil.copyfile(args.run_command_json, out / "command.json")
    evidence = out / "evidence.tar.gz"
    with tarfile.open(evidence, "w:gz") as tar:
        seen = set()
        for c, _, _ in raw:
            root = Path(c["evidence"])
            if str(root) in seen: continue
            seen.add(str(root))
            for p in root.rglob("*"):
                if p.is_symlink() or not p.is_file(): continue
                if any(k in part.lower() for part in p.relative_to(root).parts for k in KEY_WORDS): continue
                try:
                    marker = b"PRIVATE KEY-----"
                    tail = b""
                    with open(p, "rb") as src:
                        found = False
                        while True:
                            chunk = src.read(1 << 20)
                            if not chunk: break
                            data = tail + chunk
                            if re.search(rb"-----BEGIN [^-]*PRIVATE KEY-----", data):
                                found = True; break
                            tail = data[-64:]
                    if found: continue
                except OSError:
                    continue
                tar.add(p, arcname=Path("evidence") / root.name / p.relative_to(root))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", required=True); ap.add_argument("--provenance", required=True)
    ap.add_argument("--output", required=True); ap.add_argument("--source-sha")
    ap.add_argument("--remote", help="git remote URL used for ls-remote reachability")
    ap.add_argument("--remote-ref", default="refs/heads/perf/quick-nginx-benchmark")
    ap.add_argument("--run-command-json")
    ap.add_argument("--run-timing-json")
    ap.add_argument("--check-only", action="store_true"); ap.add_argument("--allow-incomplete", action="store_true")
    a = ap.parse_args()
    if not a.allow_incomplete and (not a.source_sha or not a.remote or not a.remote_ref):
        print("full verification requires --source-sha, --remote, and --remote-ref", file=sys.stderr)
        return 2
    matrix, prov, cells, raw, problems, errors, shorts, cell_checks, integrity = audit(
        a.matrix, a.provenance, a.source_sha, a.remote, a.remote_ref)
    print(json.dumps({"cells": len(cells), "raw_samples": len(raw), "problems": problems,
                      "provenance_integrity": integrity}, indent=2))
    if problems and (not a.allow_incomplete or any(is_fatal_problem(p) for p in problems)): return 2
    if a.check_only: return 0
    archive(a, matrix, prov, cells, raw, problems, errors, shorts, cell_checks, integrity); return 0
if __name__ == "__main__": sys.exit(main())
