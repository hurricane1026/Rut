#!/usr/bin/env python3
"""Summarize medians and spread, retaining every raw repetition."""
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
import generate as g

root = Path(sys.argv[1])
selected = {}
for line in (root / 'validation.log').read_text().splitlines():
    if line.startswith('SELECT '):
        _, profile, size, candidate = line.split()
        selected[(profile, size)] = candidate
samples = defaultdict(lambda: defaultdict(list))
repeats = defaultdict(lambda: defaultdict(list))
for row in csv.DictReader((root / 'raw.csv').open()):
    key = (row['profile'], row['routes'], row['trace'])
    try:
        repeat = int(row['repeat'])
        value = float(row['ns_per_lookup'])
    except (TypeError, ValueError) as error:
        raise AssertionError(f"Invalid repeat or measurement for {key}") from error
    repeats[key][row['candidate']].append(repeat)
    samples[key][row['candidate']].append(value)
expected = set()
for profile in g.PROFILES:
    for size in g.SIZES:
        if size <= profile.max_routes:
            case = g.case_for(profile, size, g.Contract.SEGMENT_PREFIX, 729)
            expected.update((profile.name, str(size), trace) for trace in case['traces'])
assert set(samples) == expected, f"Incomplete matrix: {len(samples)}/{len(expected)}"
result = []
for (profile, size, trace), candidates in samples.items():
    case = g.case_for(g.PROFILE_BY_NAME[profile], int(size), g.Contract.SEGMENT_PREFIX, 729)
    expected_candidates = {"linear", "segment_trie"}
    if not any(":" in route["path"] for route in case["routes"]):
        expected_candidates |= {"scalar_art", "jit_art"}
    assert set(candidates) == expected_candidates, (
        f"Unexpected candidates for {(profile, size, trace)}: "
        f"got {set(candidates)}, expected {expected_candidates}")
    for candidate in expected_candidates:
        assert sorted(repeats[(profile, size, trace)][candidate]) == list(range(8)), (
            f"Expected unique repeats 0..7 for {(profile, size, trace, candidate)}")
    medians = {name: statistics.median(values) for name, values in candidates.items()}
    winner = min(medians, key=medians.get)
    pick = selected[(profile, size)]
    assert pick in expected_candidates, f"Selected candidate {pick!r} is unavailable for {(profile, size)}"
    result.append(dict(profile=profile, routes=int(size), trace=trace, selected=pick,
                       fastest=winner, ratio=medians[pick]/medians[winner], median_ns=medians,
                       min_max_ns={name: [min(v), max(v)] for name, v in candidates.items()}))
(root / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
print('Measured scenarios:', len(result))
print('Selected >20% slower:', sum(r['ratio'] > 1.2 for r in result))
for profile in sorted({r['profile'] for r in result}):
    rows = [r for r in result if r['profile'] == profile]
    worst = max(rows, key=lambda r: r['ratio'])
    print(profile, 'worst', worst['routes'], worst['trace'], round(worst['ratio'], 2), worst['selected'], '->', worst['fastest'])
