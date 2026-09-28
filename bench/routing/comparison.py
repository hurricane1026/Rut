#!/usr/bin/env python3
"""Build a required cross-proxy matrix and reject incomplete result sets.

This is an acceptance gate for future runners, not a benchmark or a launcher.
Only routing-semantic equivalence belongs here; HTTP wire equivalence remains
in the repository's nginx/Envoy differential harnesses.
"""

import argparse
from enum import Enum
import json
from pathlib import Path


class Engine(str, Enum):
    RUT = "rut"
    NGINX = "nginx"
    ENVOY = "envoy"
    LINKERD = "linkerd"


def plan(manifest):
    rows = []
    for case in manifest["cases"]:
        for mode in case["execution_modes"]:
            for response_bytes in case["response_bytes"]:
                for engine in Engine:
                    prerequisite = (
                        "exceeds_current_128_route_capacity" if engine == Engine.RUT and case["routes"] > 128
                        else "no_equivalent_local_static_responder" if engine == Engine.LINKERD and mode == "local_static"
                        else "pinned_proxy_and_control_plane_with_accepted_outbound_routes"
                        if engine == Engine.LINKERD else "pinned_proxy_and_verified_config")
                    rows.append({"case": case["file"], "case_sha256": case["sha256"],
                                 "engine": engine, "execution_mode": mode, "response_bytes": response_bytes,
                                 "state": "not_run",
                                 "prerequisite": prerequisite,
                                 "routing_correctness_required": True,
                                 "required_asserted_probes": case["asserted_probes"],
                                 "performance_allowed_only_after_correctness": True})
    return {"schema_version": 1, "engines": list(Engine), "rows": rows}


def validate(matrix, results):
    """A missing engine, changed input or skipped required row cannot become PASS.

    Runners must persist individual probe observations and upstream accounting;
    a naked success boolean or a QPS number cannot satisfy this gate. This
    validates the aggregate evidence index, not authenticity of external runs.
    """
    errors = []
    indexed = {}
    for row in results:
        key = (row.get("case"), row.get("engine"), row.get("execution_mode"), row.get("response_bytes"))
        if key in indexed:
            errors.append(f"duplicate result: {key}")
        indexed[key] = row
    wanted = {(row["case"], row["engine"], row["execution_mode"], row["response_bytes"]) for row in matrix["rows"]}
    for key in indexed.keys() - wanted:
        errors.append(f"unexpected result: {key}")
    for required in matrix["rows"]:
        key = (required["case"], required["engine"], required["execution_mode"], required["response_bytes"])
        row = indexed.get(key)
        if row is None:
            errors.append(f"missing: {key}")
            continue
        if row.get("case_sha256") != required["case_sha256"]:
            errors.append(f"input hash mismatch: {key}")
        if required["prerequisite"] == "no_equivalent_local_static_responder":
            if row.get("state") != "unsupported" or not row.get("reason"):
                errors.append(f"must explicitly report unsupported local response: {key}")
            continue
        if required["prerequisite"] == "exceeds_current_128_route_capacity":
            if row.get("state") != "unsupported" or not row.get("reason"):
                errors.append(f"must explicitly report unsupported route capacity: {key}")
            continue
        if row.get("state") != "passed":
            errors.append(f"not passed: {key}: {row.get('state')}")
        for field in ("binary_or_image_digest", "config_sha256", "probe_evidence_sha256",
                      "upstream_evidence_sha256", "environment_sha256"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                errors.append(f"missing provenance {field}: {key}")
        checked = row.get("asserted_probes", 0)
        if (type(checked) is not int or checked != required["required_asserted_probes"]
                or checked <= 0 or row.get("failed_probes") != 0):
            errors.append(f"no successful correctness evidence: {key}")
        if required["engine"] == Engine.LINKERD:
            for field in ("control_plane_digest", "route_status_evidence_sha256", "topology"):
                if not isinstance(row.get(field), str) or not row[field].strip():
                    errors.append(f"missing Linkerd provenance {field}: {key}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--results", type=Path,
                        help="Validate a runner's JSON list against every required row")
    args = parser.parse_args()
    matrix = plan(json.loads(args.manifest.read_text()))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(matrix, indent=2) + "\n")
    if args.results:
        errors = validate(matrix, json.loads(args.results.read_text()))
        for error in errors:
            print(error)
        if not errors:
            unsupported = sum(r["prerequisite"] == "no_equivalent_local_static_responder"
                              for r in matrix["rows"])
            print(f"Result index complete; {unsupported} explicitly unsupported rows (not passes).")
        return 1 if errors else 0
    print(f"Prepared {len(matrix['rows'])} required comparisons; none executed by this tool.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
