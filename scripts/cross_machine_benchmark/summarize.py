#!/usr/bin/env python3
"""Summarize paired, valid runs with identical workload parameters."""
import argparse
import json
from pathlib import Path
import statistics


def wrk_hash(environment):
    binaries = environment.get('binaries', {})
    hashes = list(binaries.values())
    if len(binaries) != 1 or len(hashes) != 1 or len(hashes[0]) != 64 or any(c not in '0123456789abcdef' for c in hashes[0].lower()):
        raise ValueError('client environment must contain exactly one valid wrk binary hash')
    return hashes[0]


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
    client_hashes = {}
    client_identities = {}
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
        environment = json.loads(env.read_text())
        timestamps.setdefault(key, []).append((environment['time'], d['engine'], d['repetition']))
        client_hashes.setdefault(key, []).append(wrk_hash(environment))
        try:
            raw_identity = environment['uname']
            if not isinstance(raw_identity, list):
                raise ValueError
            identity = tuple(raw_identity)
        except (KeyError, TypeError, ValueError):
            raise ValueError(f'client environment is missing uname identity: {p}')
        if len(identity) != 5 or any(not isinstance(value, str) or not value for value in identity):
            raise ValueError(f'client environment has malformed uname identity: {p}')
        client_identities.setdefault(key, []).append(identity)
        rows = groups.setdefault(key, {'rut': {}, 'nginx': {}})[d['engine']]
        if d['repetition'] in rows:
            raise ValueError(f'duplicate engine/repetition: {p}')
        rows[d['repetition']] = (d, next(r for r in d['results'] if r['phase'] == 'measurement'))
    if not groups:
        raise ValueError('no results')
    output = []
    for key, engines in groups.items():
        repetitions = sorted(engines['rut'])
        if (repetitions != sorted(engines['nginx']) or repetitions != list(range(1, len(repetitions) + 1))
                or len(repetitions) < 3):
            raise ValueError(f'need at least three matching repetitions for both engines: {key}')
        expected_order = []
        for rep in repetitions:
            expected_order.extend((('rut', rep), ('nginx', rep)) if rep % 2 else
                                  (('nginx', rep), ('rut', rep)))
        if [(engine, rep) for _, engine, rep in sorted(timestamps[key])] != expected_order:
            raise ValueError(f'runs are not in documented interleaved order: {key}')
        if len(set(client_hashes[key])) != 1:
            raise ValueError(f'client wrk binary changed between paired runs: {key}')
        if len(set(client_identities[key])) != 1:
            raise ValueError(f'client machine identity changed between paired runs: {key}')
        server_identities = {tuple(d.get('server_machine_uname', ()))
                             for runs in engines.values() for d, _ in runs.values()}
        if (len(server_identities) != 1 or len(next(iter(server_identities))) != 5
                or any(not isinstance(value, str) or not value for value in next(iter(server_identities))):
            raise ValueError(f'proxy machine identity changed or was not recorded: {key}')
        for engine, runs in engines.items():
            run_ids = [d['server_run_id'] for d, _ in runs.values()]
            if len(set(run_ids)) != len(run_ids):
                raise ValueError(f'duplicate server run identity: {engine}')
            binary_hashes = {d['server_binary_sha256'] for d, _ in runs.values()}
            effective_hashes = {d['server_effective_config_sha256'] for d, _ in runs.values()}
            if len(binary_hashes) != 1 or len(effective_hashes) != 1:
                raise ValueError(f'{engine} server binary/config changed between repetitions')
            compiler_hashes = {d.get('server_compiler_sha256') for d, _ in runs.values()}
            if engine == 'rut' and len(compiler_hashes) != 1 or engine == 'rut' and None in compiler_hashes:
                raise ValueError(f'{engine} compiler changed or was not recorded')
        origin_fields = ('origin_endpoint', 'origin_run_id', 'origin_cpus', 'origin_workers',
                         'origin_listen_port', 'origin_binary_sha256', 'origin_config_sha256',
                         'origin_effective_config_sha256')
        origin_identity = {tuple(d.get(field) for field in origin_fields)
                           for runs in engines.values() for d, _ in runs.values()}
        if len(origin_identity) != 1 or None in next(iter(origin_identity)):
            raise ValueError(f'origin manifest changed or was not recorded: {key}')
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
