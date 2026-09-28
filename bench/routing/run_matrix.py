#!/usr/bin/env python3
"""Emit a correctness-gated canonical segment-prefix matrix for dispatch_matrix.cc."""
import generate as g
import argparse

METHODS = dict(ANY=0, GET=1, POST=2, PUT=3, DELETE=4, PATCH=5, HEAD=6, OPTIONS=7)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--profiles', nargs='+', choices=[p.name for p in g.PROFILES])
parser.add_argument('--sizes', nargs='+', type=int, choices=g.SIZES, default=g.SIZES)
args = parser.parse_args()
for profile in g.PROFILES:
    if args.profiles and profile.name not in args.profiles:
        continue
    for size in args.sizes:
        if size > profile.max_routes:
            continue
        case = g.case_for(profile, size, g.Contract.SEGMENT_PREFIX, 729)
        asserted = [(i, p) for i, p in enumerate(case['probes']) if p['check'] == 'assert']
        remap = {old: new for new, (old, _) in enumerate(asserted)}
        params = any(':' in r['path'] for r in case['routes'])
        print(profile.name, size, len(asserted), len(case['traces']), int(params))
        for r in case['routes']:
            print(METHODS[r['method']], r['id'], g.canonical(r['path']) or '~')
        order = sorted(enumerate(case['routes']),
                       key=lambda item: g.route_precedence(
                           item[1],
                           tuple(0 if p.startswith(':') else 1 for p in g.parts(item[1]['path'])),
                           None, item[0]), reverse=True)
        order = [r for _, r in order]
        print(*(r['id'] for r in order))
        for _, p in asserted:
            print(METHODS[p['method']], p['expected']['route_id'] if p['expected'] else 65535, p['canonical_path'] or '~')
        for name, indices in case['traces'].items():
            print(name, *(remap[i] for i in indices))
