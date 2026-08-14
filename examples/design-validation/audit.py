#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


KNOWN_CONDITIONS = {"auto-backend", "process", "websocket"}


def load_ids(path):
    values = []
    for line in path.read_text().splitlines():
        value = line.strip()
        if value:
            values.append(value)
    return values


def duplicates(values):
    seen = set()
    repeated = set()
    for value in values:
        if value in seen:
            repeated.add(value)
        seen.add(value)
    return repeated


def documented_surfaces(path):
    lines = path.read_text().splitlines()
    try:
        heading = lines.index("### Current implementation boundary")
    except ValueError:
        raise ValueError(f"{path} is missing the current implementation boundary")

    surfaces = []
    in_table = False
    for line in lines[heading + 1 :]:
        if line.startswith("| Capability | Status | Current boundary |"):
            in_table = True
            continue
        if not in_table:
            continue
        if line.startswith("|---"):
            continue
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 3:
            raise ValueError(f"malformed capability row: {line}")
        surfaces.append(cells[0])
    return surfaces


def validate_unique_ids(items, collection, errors):
    ids = [item.get("id") for item in items]
    missing = [index for index, value in enumerate(ids) if not value]
    if missing:
        errors.append(f"{collection} entries missing id at indexes {missing}")
    repeated = sorted(duplicates(ids))
    if repeated:
        errors.append(f"duplicate {collection} ids: {repeated}")
    return set(ids)


def expected_ids(items, disabled):
    return {
        item["id"]
        for item in items
        if item.get("condition") not in disabled
    }


def validate_execution(label, items, path, disabled, errors):
    observed_list = load_ids(path)
    repeated = sorted(duplicates(observed_list))
    if repeated:
        errors.append(f"duplicate executed {label}: {repeated}")
    observed = set(observed_list)
    expected = expected_ids(items, disabled)
    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    if missing:
        errors.append(f"{label} not executed: {missing}")
    if unexpected:
        errors.append(f"unexpected {label} executed: {unexpected}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--executed-scenarios", type=Path)
    parser.add_argument("--executed-sentinels", type=Path)
    parser.add_argument("--disable", action="append", default=[])
    args = parser.parse_args()

    errors = []
    disabled = set(args.disable)
    unknown_disabled = sorted(disabled - KNOWN_CONDITIONS)
    if unknown_disabled:
        errors.append(f"unknown disabled conditions: {unknown_disabled}")

    try:
        manifest = json.loads(args.manifest.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot load capability manifest: {error}")
    if manifest.get("schema") != 1:
        errors.append(f"unsupported manifest schema: {manifest.get('schema')!r}")

    scenarios = manifest.get("scenarios", [])
    capabilities = manifest.get("capabilities", [])
    sentinels = manifest.get("sentinels", [])
    scenario_ids = validate_unique_ids(scenarios, "scenario", errors)
    capability_ids = validate_unique_ids(capabilities, "capability", errors)
    validate_unique_ids(sentinels, "sentinel", errors)

    for collection, items in (("scenario", scenarios), ("sentinel", sentinels)):
        for item in items:
            condition = item.get("condition")
            if condition is not None and condition not in KNOWN_CONDITIONS:
                errors.append(
                    f"{collection} {item.get('id')} has unknown condition {condition!r}"
                )

    docs_path = args.root / "docs/core-capabilities.md"
    try:
        docs_surfaces = documented_surfaces(docs_path)
    except (OSError, ValueError) as error:
        errors.append(str(error))
        docs_surfaces = []
    manifest_surfaces = manifest.get("surfaces", [])
    if manifest_surfaces != docs_surfaces:
        errors.append(
            "manifest surfaces do not exactly match docs/core-capabilities.md: "
            f"manifest={manifest_surfaces!r}, docs={docs_surfaces!r}"
        )
    surface_ids = set(manifest_surfaces)

    scenarios_in_use = set()
    surfaces_in_use = set()
    for capability in capabilities:
        capability_id = capability.get("id")
        surface = capability.get("surface")
        if surface not in surface_ids:
            errors.append(f"capability {capability_id} has unknown surface {surface!r}")
        else:
            surfaces_in_use.add(surface)
        evidence = capability.get("scenarios", [])
        if not evidence:
            errors.append(f"capability {capability_id} has no black-box scenario")
        unknown = sorted(set(evidence) - scenario_ids)
        if unknown:
            errors.append(f"capability {capability_id} references unknown scenarios: {unknown}")
        scenarios_in_use.update(evidence)

    unused_surfaces = sorted(surface_ids - surfaces_in_use)
    if unused_surfaces:
        errors.append(f"documented surfaces without capabilities: {unused_surfaces}")
    unused_scenarios = sorted(scenario_ids - scenarios_in_use)
    if unused_scenarios:
        errors.append(f"scenarios without capability evidence: {unused_scenarios}")

    fixture_root = args.manifest.parent
    manifest_fixtures = set()
    for scenario in scenarios:
        for relative in scenario.get("fixtures", []):
            fixture = fixture_root / relative
            manifest_fixtures.add(relative)
            if not fixture.is_file():
                errors.append(f"scenario {scenario.get('id')} fixture is missing: {relative}")
    disk_fixtures = {
        str(path.relative_to(fixture_root))
        for path in fixture_root.rglob("*.rut")
    }
    missing_from_manifest = sorted(disk_fixtures - manifest_fixtures)
    stale_manifest_fixtures = sorted(manifest_fixtures - disk_fixtures)
    if missing_from_manifest:
        errors.append(f"Rut fixtures without scenario ownership: {missing_from_manifest}")
    if stale_manifest_fixtures:
        errors.append(f"manifest references absent Rut fixtures: {stale_manifest_fixtures}")

    for sentinel in sentinels:
        unknown = sorted(set(sentinel.get("capabilities", [])) - capability_ids)
        if unknown:
            errors.append(f"sentinel {sentinel.get('id')} references unknown capabilities: {unknown}")
        if not sentinel.get("capabilities"):
            errors.append(f"sentinel {sentinel.get('id')} has no capability target")

    if args.executed_scenarios:
        validate_execution(
            "scenarios",
            scenarios,
            args.executed_scenarios,
            disabled,
            errors,
        )
    if args.executed_sentinels:
        validate_execution(
            "sentinels",
            sentinels,
            args.executed_sentinels,
            disabled,
            errors,
        )

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        raise SystemExit(1)
    print(
        f"Capability contract OK: {len(capabilities)} capabilities, "
        f"{len(scenarios)} scenarios, {len(sentinels)} damage sentinels"
    )


if __name__ == "__main__":
    main()
