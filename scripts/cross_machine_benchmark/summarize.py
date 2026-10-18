#!/usr/bin/env python3
"""Summarize paired, valid runs with identical workload parameters."""
import argparse
import json
from pathlib import Path
import statistics


def summarize(root):
    failures = list(root.rglob('failure.json'))
    if failures:
        raise ValueError(f'failed attempts present: {failures}')
    unfinished = [p.parent for p in root.rglob('environment.json')
                  if not (p.parent / 'failure.json').exists() and
                  not (p.parent / 'result.json').exists()]
    if unfinished:
        raise ValueError(f'unfinished attempts present: {unfinished}')
    groups = {}
    for p in sorted(root.rglob('result.json')):
        d = json.loads(p.read_text())
        if not d['valid']:
            raise ValueError(f'invalid run: {p}; do not discard failed runs')
        key = (d['host'], d['body_size'], d['connections'], d['duration'], d['threads'], d['warmup'], d['port'], d['cpus'])
        rows = groups.setdefault(key, {'rut': {}, 'nginx': {}})[d['engine']]
        if d['repetition'] in rows:
            raise ValueError(f'duplicate engine/repetition: {p}')
        rows[d['repetition']] = next(r for r in d['results'] if r['phase'] == 'measurement')
    if not groups:
        raise ValueError('no results')
    output = []
    for key, engines in groups.items():
        if set(engines['rut']) != set(engines['nginx']) or len(engines['rut']) < 3:
            raise ValueError(f'need at least three matching repetitions for both engines: {key}')
        item = dict(zip(('host', 'body_size', 'connections', 'duration', 'threads', 'warmup', 'port', 'cpus'), key))
        for engine, runs in engines.items():
            rps = [r['rps'] for r in runs.values()]
            item[engine] = {'rps': rps, 'median_rps': statistics.median(rps),
                            'median_p99_us': statistics.median(r['p99_us'] for r in runs.values())}
            item[engine]['payload_gbps'] = statistics.median(rps) * key[1] * 8 / 1e9
        gains = [(engines['rut'][rep]['rps'] / engines['nginx'][rep]['rps'] - 1) * 100
                 for rep in sorted(engines['rut'])]
        item['per_repetition_gain_percent'] = gains
        item['rut_gain_percent'] = statistics.median(gains)
        output.append(item)
    return output


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('results', type=Path)
    print(json.dumps(summarize(p.parse_args().results), indent=2))
