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
    timestamps = {}
    for p in sorted(root.rglob('result.json')):
        d = json.loads(p.read_text())
        if not d['valid']:
            raise ValueError(f'invalid run: {p}; do not discard failed runs')
        if d.get('throughput_classification') != 'instrumented-client-rps-full-body-lua':
            raise ValueError(f'unknown throughput classification: {p}')
        env = p.parent / 'environment.json'
        if not env.exists():
            raise ValueError(f'missing client environment: {p}')
        key = (d['host'], d['body_size'], d['connections'], d['duration'], d['threads'], d['warmup'], d['port'], d['cpus'],
               d['server_cpus'], d['server_workers'])
        timestamps.setdefault(key, []).append((json.loads(env.read_text())['time'], d['engine'], d['repetition']))
        rows = groups.setdefault(key, {'rut': {}, 'nginx': {}})[d['engine']]
        if d['repetition'] in rows:
            raise ValueError(f'duplicate engine/repetition: {p}')
        rows[d['repetition']] = (d, next(r for r in d['results'] if r['phase'] == 'measurement'))
    if not groups:
        raise ValueError('no results')
    expected_order = [('rut', 1), ('nginx', 1), ('nginx', 2),
                      ('rut', 2), ('rut', 3), ('nginx', 3)]
    output = []
    for key, engines in groups.items():
        if set(engines['rut']) != set(engines['nginx']) or len(engines['rut']) < 3:
            raise ValueError(f'need at least three matching repetitions for both engines: {key}')
        if [(engine, rep) for _, engine, rep in sorted(timestamps[key])] != expected_order:
            raise ValueError(f'runs are not in documented interleaved order: {key}')
        for engine, runs in engines.items():
            run_ids = [d['server_run_id'] for d, _ in runs.values()]
            if len(set(run_ids)) != len(run_ids):
                raise ValueError(f'duplicate server run identity: {engine}')
            binary_hashes = {d['server_binary_sha256'] for d, _ in runs.values()}
            effective_hashes = {d['server_effective_config_sha256'] for d, _ in runs.values()}
            if len(binary_hashes) != 1 or len(effective_hashes) != 1:
                raise ValueError(f'{engine} server binary/config changed between repetitions')
        normalized = {d['server_config_sha256'] for runs in engines.values() for d, _ in runs.values()}
        if len(normalized) != 1:
            raise ValueError('normalized configuration changed between paired runs')
        item = dict(zip(('host', 'body_size', 'connections', 'duration', 'threads', 'warmup', 'port', 'cpus',
                         'server_cpus', 'server_workers'), key))
        for engine, runs in engines.items():
            rps = [r['rps'] for _, r in runs.values()]
            item[engine] = {'instrumented_rps': rps,
                            'median_instrumented_rps': statistics.median(rps),
                            'median_p99_us': statistics.median(r['p99_us'] for _, r in runs.values())}
        item['throughput_classification'] = 'inconclusive-lua-body-callback'
        output.append(item)
    return output


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('results', type=Path)
    print(json.dumps(summarize(p.parse_args().results), indent=2))
