#!/usr/bin/env python3
"""Serial, repeatable screening of offline runtime policies by origin workload.

RUT_STUDY_POLICY is an experimental runtime knob, not a production CLI contract.
Never interpret the winner as a global optimum or infer a future response size.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys

WORKLOADS = [
    dict(name='tiny-512', body=512, mode='static', intent='dispatch overhead'),
    dict(name='api-fast-4k', body=4096, mode='api', intent='small API proxy'),
    dict(name='medium-64k', body=65536, mode='static', intent='copy/relay crossover'),
    dict(name='static-256k', body=262144, mode='static', intent='bulk transfer'),
    dict(name='static-1m', body=1048576, mode='static', intent='large bulk transfer'),
    dict(name='api-delayed-4k', body=4096, mode='api', delay=1,
         intent='upstream service latency'),
    dict(name='stream-fragmented-256k', body=262144, mode='api', fragment=16384, gap=.2,
         intent='source readiness and repeated partial progress'),
    dict(name='mixed-4k-1m', body=1048576, mode='static', small=4096,
         intent='small request fairness during large transfers'),
]
POLICIES = ['latency', 'balanced', 'current', 'throughput']


def metric(row):
    if 'small_client' in row:
        return row['small_client']['p99_us']
    return row['p99_us']


def throughput_score(row):
    if 'small_client' in row:
        workload = row.get('workload_profile', {})
        large = workload.get('body', row.get('body_size', 1048576))
        small = workload.get('small', 4096)
        return (row['large_client']['rps'] * large + row['small_client']['rps'] * small) / 1048576
    return row['rps']


def summarize(rows, limit):
    groups = {}
    for row in rows:
        if row['stage'] != 'confirm':
            continue
        key = (row['workload_profile']['name'], row['engine'], row['policy'])
        groups.setdefault(key, []).append(row)
    summary = []
    for (workload, engine, policy), samples in groups.items():
        if len(samples) < 3:
            continue
        summary.append(dict(workload=workload, engine=engine, policy=policy,
                            repeats=len(samples), rps=statistics.median(r['rps'] for r in samples),
                            throughput_score=statistics.median(throughput_score(r) for r in samples),
                            throughput_range=[min(throughput_score(r) for r in samples), max(throughput_score(r) for r in samples)],
                            p99_us=statistics.median(metric(r) for r in samples),
                            rps_range=[min(r['rps'] for r in samples), max(r['rps'] for r in samples)],
                            p99_range_us=[min(metric(r) for r in samples), max(metric(r) for r in samples)],
                            server_cpu_pct=statistics.median(r['server_cpu_pct'] for r in samples),
                            origin_cpu_pct=statistics.median(r['origin_cpu_pct'] for r in samples)))
    decisions = []
    for workload in WORKLOADS:
        for engine in ['uring', 'epoll']:
            options = [r for r in summary if r['workload'] == workload['name'] and r['engine'] == engine]
            baseline = next((r for r in options if r['policy'] == 'current'), None)
            if not baseline:
                continue
            eligible = [r for r in options if r['p99_us'] <= baseline['p99_us'] * (1 + limit)]
            winner = max(eligible, key=lambda r: r['throughput_score'])
            # Retain current if the measured gain is smaller than the declared practical threshold.
            if winner['throughput_score'] < baseline['throughput_score'] * 1.03:
                winner = baseline
            candidate = winner
            ranges_separate = candidate['throughput_range'][0] > baseline['throughput_range'][1]
            if candidate['policy'] != 'current' and not ranges_separate:
                winner = baseline
            tail_candidate = min(options, key=lambda r: r['p99_us'])
            tail = tail_candidate
            if (tail['p99_us'] > baseline['p99_us'] * .95 or
                    tail['p99_range_us'][1] >= baseline['p99_range_us'][0]):
                tail = baseline
            origin = next((r for r in rows if r['stage'] == 'origin' and
                           r['workload_profile']['name'] == workload['name']), None)
            capacity_ratio = winner['throughput_score'] / throughput_score(origin) if origin else None
            decisions.append(dict(workload=workload['name'], engine=engine,
                                  direct_capacity_ratio=capacity_ratio,
                                  possible_capacity_limit=capacity_ratio is not None and capacity_ratio >= .85,
                                  throughput_policy=winner['policy'], latency_policy=tail['policy'],
                                  experimental_throughput_candidate=candidate['policy'],
                                  experimental_latency_candidate=tail_candidate['policy'],
                                  observed_rate_ranges_separate=ranges_separate,
                                  rps_ratio=winner['rps'] / baseline['rps'],
                                  throughput_ratio=winner['throughput_score'] / baseline['throughput_score'],
                                  p99_ratio=winner['p99_us'] / baseline['p99_us'],
                                  scope='best confirmed candidate, not a global optimum'))
    return dict(summary=summary, decisions=decisions)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--relay-script', type=Path, required=True)
    p.add_argument('--rut', type=Path, required=True)
    p.add_argument('--converter', type=Path, required=True)
    p.add_argument('--wrk', type=Path, required=True)
    p.add_argument('--workloads', nargs='+', choices=[w['name'] for w in WORKLOADS])
    p.add_argument('--screen-seconds', type=int, default=8)
    p.add_argument('--confirm-seconds', type=int, default=12)
    p.add_argument('--p99-increase-limit', type=float, default=.10)
    p.add_argument('--skip-nginx', action='store_true')
    args = p.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    workloads = [w for w in WORKLOADS if not args.workloads or w['name'] in args.workloads]
    common = [sys.executable, str(args.relay_script.resolve()), '--rut', str(args.rut.resolve()),
              '--converter', str(args.converter.resolve()), '--wrk', str(args.wrk.resolve()),
              '--origin-workers', '4', '--origin-cpus', '3,4,8,9', '--server-cpu', '2',
              '--client-cpus', '5,7', '--workers', '1', '--front-port', '8604', '--origin-port', '8704',
              '--concurrency', '128', '--keepalive-header', 'implicit', '--proxy-profile', 'native-streaming',
              '--native-nginx-buffering', 'off', '--native-origin-reuse', 'on', '--scenarios', 'proxy-keepalive']
    env = dict(os.environ)
    env.pop('DOCKER_HOST', None)
    env['RUT_BENCH_RELAY_STATS'] = '1'
    rows = []
    selected = {}
    manifest = dict(workloads=workloads, policies=POLICIES, concurrency=128, frontend_workers=1,
                    frontend_cpu=2, origin_workers=4, origin_cpus=[3, 4, 8, 9], client_cpus=[5, 7],
                    p99_increase_limit=args.p99_increase_limit, practical_rps_gain=.03,
                    screen_seconds=args.screen_seconds, confirm_seconds=args.confirm_seconds,
                    confirm_repeats=3, serial_frontends=True,
                    binaries={str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in [args.rut, args.rut.with_name('rut-compile'), args.converter, args.wrk]})
    prior = out / 'study.json'
    if prior.exists() and json.loads(prior.read_text()) != manifest:
        raise RuntimeError('study manifest changed; use a new output directory')
    prior.write_text(json.dumps(manifest, indent=2) + '\n')

    def run(stage, workload, engine, policy, repeat, duration):
        label = f'{stage}-{workload["name"]}-{engine}-{policy}-r{repeat}'
        log = out / (label + '.log')
        destination = out / label
        if log.exists():
            samples = [json.loads(line) for line in log.read_text().splitlines()
                       if line.startswith('{"requests"')]
            if len(samples) != 1 or not samples[0]['valid']:
                raise RuntimeError('preserved incomplete or failed case: ' + label)
            row = samples[0]
        else:
            origin_mode = 'api' if workload['mode'] == 'api' else 'native'
            argv = common + ['--engines', engine, '--origin-mode', origin_mode,
                             '--api-delay-ms', str(workload.get('delay', 0)),
                             '--api-fragment-bytes', str(workload.get('fragment', 0)),
                             '--api-fragment-delay-ms', str(workload.get('gap', 0)),
                             '--body-size', str(workload['body']), '--duration', str(duration),
                             '--warmup', '2', '--repeats', '1', '--output', str(destination)]
            if workload.get('small'):
                argv += ['--mixed-small-bytes', str(workload['small']), '--small-connections', '32']
            if engine == 'nginx':
                size = 16 if workload['body'] <= 16384 else workload['body'] // 1024
                argv += ['--nginx-buffer-kib', str(size)]
            run_env = dict(env, RUT_STUDY_POLICY=policy)
            with (out / 'commands.jsonl').open('a') as handle:
                handle.write(json.dumps(dict(label=label, argv=argv, policy=policy)) + '\n')
            print('START ' + label, flush=True)
            with log.open('w') as handle:
                result = subprocess.run(argv, stdout=handle, stderr=subprocess.STDOUT, env=run_env)
            if result.returncode:
                raise RuntimeError(f'{label} failed {result.returncode}; inspect preserved log')
            samples = [json.loads(line) for line in log.read_text().splitlines()
                       if line.startswith('{"requests"')]
            if len(samples) != 1 or not samples[0]['valid']:
                raise RuntimeError('invalid measurement: ' + label)
            row = samples[0]
        if any(row['errors'].values()) or any(row['warmup_errors'].values()):
            raise RuntimeError('measurement has errors: ' + label)
        if engine in ('uring', 'epoll'):
            server_log = next(destination.glob('*-server.log')).read_text()
            if f'RUT_STUDY_POLICY profile={policy} ' not in server_log:
                raise RuntimeError('runtime policy did not activate: ' + label)
        row.update(stage=stage, workload_profile=workload, policy=policy, outer_repeat=repeat)
        rows.append(row)
        (out / 'measurements.json').write_text(json.dumps(rows, indent=2) + '\n')
        (out / 'summary.json').write_text(json.dumps(summarize(rows, args.p99_increase_limit), indent=2) + '\n')
        print(f'END {label}: {row["rps"]:.0f} RPS p99={metric(row)/1000:.3f}ms '
              f'frontendCPU={row["server_cpu_pct"]:.1f} originCPU={row["origin_cpu_pct"]:.1f}', flush=True)
        return row

    for workload in workloads:
        run('origin', workload, 'direct-origin', 'current', 1, 8)
    for engine in ['uring', 'epoll']:
        for workload in workloads:
            policies = POLICIES[:] if workload['body'] > 16384 else POLICIES[:3]
            random.Random(20261010 + len(workload['name']) + (engine == 'epoll')).shuffle(policies)
            screening = [run('screen', workload, engine, policy, 1, args.screen_seconds) for policy in policies]
            baseline = next(r for r in screening if r['policy'] == 'current')
            eligible = [r for r in screening if metric(r) <= metric(baseline) * (1 + args.p99_increase_limit)]
            throughput = max(eligible, key=throughput_score)['policy']
            latency = min(screening, key=metric)['policy']
            choices = POLICIES[:] if workload.get('small') else list(dict.fromkeys(['current', throughput, latency]))
            selected[f'{engine}-{workload["name"]}'] = choices
            (out / 'selected-policies.json').write_text(json.dumps(selected, indent=2) + '\n')
            for repeat in range(1, 4):
                order = choices[repeat % len(choices):] + choices[:repeat % len(choices)]
                for policy in order:
                    run('confirm', workload, engine, policy, repeat, args.confirm_seconds)
    if not args.skip_nginx:
        for workload in workloads:
            for repeat in range(1, 4):
                run('confirm', workload, 'nginx', 'reference', repeat, args.confirm_seconds)
    print('STUDY COMPLETE', flush=True)


if __name__ == '__main__':
    main()
