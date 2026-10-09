#!/usr/bin/env python3
"""Serial policy comparisons for WebSocket tunnels and chunked HTTP streams."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import signal
import socket
import statistics
import subprocess
import sys
import time
import uuid

CASES = [
    dict(name='websocket-interactive-64', kind='websocket', size=64, chunks=16, delay=0),
    dict(name='websocket-bulk-64k', kind='websocket', size=65536, chunks=16, delay=0),
    dict(name='streaming-bulk-64k', kind='streaming', size=4096, chunks=16, delay=0),
    dict(name='streaming-live-256', kind='streaming', size=256, chunks=2048, delay=1),
]


def ready(port, process, log, workers=0):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(log.read_text())
        if workers and log.read_text().count('PROTOCOL_READY ') < workers:
            time.sleep(.05)
            continue
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError('startup timeout: ' + log.read_text())


@contextlib.contextmanager
def process(argv, log, env=None):
    with log.open('w') as handle:
        child = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT, env=env)
        try:
            yield child
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def run_client(argv, log, timeout, env):
    # Own the process group so a timeout cannot leave benchmark workers alive.
    with log.open('w') as handle:
        child = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise
        if code:
            raise subprocess.CalledProcessError(code, argv)


def save_container_log(name, destination, env):
    logs = subprocess.run(['docker', 'logs', name], capture_output=True, text=True, env=env)
    destination.write_text(logs.stdout + logs.stderr)


def summarize(rows):
    summaries = []
    for case in CASES:
        options = []
        for engine in ['direct-origin', 'uring', 'epoll', 'nginx']:
            for policy in ['latency', 'balanced', 'current', 'reference']:
                group = [row for row in rows if row['case']['name'] == case['name']
                         and row['engine'] == engine and row['policy'] == policy]
                if len(group) < 3:
                    continue
                metric = 'rtt_us' if case['kind'] == 'websocket' else 'delivery_us'
                item = dict(case=case['name'], engine=engine, policy=policy,
                            rate=statistics.median(row['messages_per_second'] for row in group),
                            mib_per_second=statistics.median(row['received_mib_per_second'] for row in group),
                            p99_us=statistics.median(row[metric]['p99_us'] for row in group),
                            rate_range=[min(row['messages_per_second'] for row in group),
                                        max(row['messages_per_second'] for row in group)],
                            p99_range_us=[min(row[metric]['p99_us'] for row in group),
                                          max(row[metric]['p99_us'] for row in group)],
                            origin_cpu_pct=statistics.median(row['origin_cpu_pct'] for row in group),
                            frontend_cpu_pct=statistics.median(row['frontend_cpu_pct'] for row in group))
                if case['kind'] == 'streaming':
                    item['first_p99_us'] = statistics.median(row['first_us']['p99_us'] for row in group)
                    item['source_gap_p99_us'] = statistics.median(row['source_gap_us']['p99_us'] for row in group)
                options.append(item)
        direct = next((item for item in options if item['engine'] == 'direct-origin'), None)
        for engine in ['uring', 'epoll']:
            candidates = [item for item in options if item['engine'] == engine]
            current = next((item for item in candidates if item['policy'] == 'current'), None)
            if not current:
                continue
            eligible = [item for item in candidates if item['p99_us'] <= current['p99_us'] * 1.1
                        and (case['kind'] == 'websocket' or item['first_p99_us'] <= current['first_p99_us'] * 1.1)]
            winner = max(eligible, key=lambda item: item['rate'])
            current['experimental_throughput_candidate'] = winner['policy']
            if winner['rate'] < current['rate'] * 1.03 or winner['rate_range'][0] <= current['rate_range'][1]:
                winner = current
            current['throughput_policy'] = winner['policy']
            tail = min(candidates, key=lambda item: item['p99_us'])
            current['experimental_latency_candidate'] = tail['policy']
            if tail['p99_us'] > current['p99_us'] * .95 or tail['p99_range_us'][1] >= current['p99_range_us'][0]:
                tail = current
            current['latency_policy'] = tail['policy']
            current['direct_capacity_ratio'] = winner['rate'] / direct['rate'] if direct else None
        summaries.extend(options)
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rut', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, default=Path(__file__).with_name('protocol_workload.py'))
    parser.add_argument('--duration', type=int, default=8)
    parser.add_argument('--cases', nargs='+', choices=[case['name'] for case in CASES])
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--policies', nargs='+', choices=['latency', 'balanced', 'current'])
    parser.add_argument('--engines', nargs='+', choices=['direct-origin', 'uring', 'epoll', 'nginx'])
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('runtime_benchmark', args.harness)
    harness = importlib.util.module_from_spec(spec); spec.loader.exec_module(harness)
    image = (harness.ROOT / 'tests/pinned-nginx-image.txt').read_text().strip()
    manifest = dict(cases=CASES, duration=args.duration, frontend_cpus=[2], origin_cpus=[3, 4, 8, 9],
                    client_cpus=[5, 7], connections=128, client='Python asyncio; direct-origin ceiling required',
                    rut_sha256=hashlib.sha256(args.rut.read_bytes()).hexdigest(), nginx_image=image,
                    fixture_sha256=hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
                    ws_recv_mode=os.environ.get('RUT_STUDY_WS_RECV', 'once'),
                    nginx_keepalive_requests=1000000,
                    ws_splice_mode=os.environ.get('RUT_STUDY_WS_SPLICE', 'off'))
    prior = out / 'study.json'
    if prior.exists() and json.loads(prior.read_text()) != manifest:
        raise RuntimeError('manifest changed; use another output directory')
    prior.write_text(json.dumps(manifest, indent=2) + '\n')
    rows = []
    fixture = [sys.executable, str(args.fixture.resolve())]
    origin_port = 8805; front_port = 8804
    env = dict(os.environ); env.pop('DOCKER_HOST', None)
    cases = [case for case in CASES if not args.cases or case['name'] in args.cases]

    for case in cases:
        # Protocol paths do not enter Content-Length body splice. current and
        # throughput have identical effective settings, so compare three batches.
        configurations = [('direct-origin', 'current')]
        for engine in ['uring', 'epoll']:
            policies = ['latency', 'balanced', 'current']
            random.Random(20261010 + len(case['name']) + (engine == 'epoll')).shuffle(policies)
            configurations += [(engine, policy) for policy in policies]
        configurations += [('nginx', 'reference')]
        if args.smoke:
            configurations = [('uring', 'current'), ('epoll', 'current')]
        if args.engines:
            configurations = [(engine, policy) for engine, policy in configurations if engine in args.engines]
            if 'direct-origin' in args.engines and not any(engine == 'direct-origin' for engine, _ in configurations):
                configurations.insert(0, ('direct-origin', 'current'))
        if args.policies:
            configurations = [(engine, policy) for engine, policy in configurations
                              if engine not in ['uring', 'epoll'] or policy in args.policies]
        repeats = 1 if args.smoke else 3
        for repeat in range(1, repeats + 1):
            offset = (repeat - 1) % len(configurations)
            order = configurations[offset:] + configurations[:offset]
            for engine, policy in order:
                label = f'{case["name"]}-{engine}-{policy}-r{repeat}'
                directory = out / label
                result_file = directory / 'result.json'
                if result_file.exists():
                    row = json.loads(result_file.read_text())
                    if not row['valid'] or not all(key in row for key in ['case', 'engine', 'policy', 'repeat']):
                        raise RuntimeError('preserved invalid or incomplete case: ' + label)
                    rows.append(row)
                    continue
                if directory.exists():
                    raise RuntimeError('preserved incomplete case: ' + label)
                directory.mkdir()
                print('START ' + label, flush=True)
                common = ['--kind', case['kind'], '--size', str(case['size']), '--chunks', str(case['chunks']),
                          '--delay-ms', str(case['delay'])]
                origin_argv = fixture + ['origin', '--port', str(origin_port), '--cpus', '3,4,8,9', *common]
                origin_log = directory / 'origin.log'
                with process(origin_argv, origin_log, env) as origin:
                    ready(origin_port, origin, origin_log, 4)
                    program = directory / 'gateway.rut'
                    program.write_text(f'listen 127.0.0.1:{front_port}\n'
                                       f'upstream origin at "127.0.0.1:{origin_port}"\n'
                                       'route GET "/ws" { return websocket(origin) }\n'
                                       'route GET "/stream" { return forward(origin) }\n')
                    nginx = directory / 'nginx.conf'
                    nginx.write_text('worker_processes 1; error_log /dev/stderr warn; pid /tmp/nginx.pid;\n'
                                     'events { worker_connections 8192; }\nhttp { access_log off; keepalive_requests 1000000; '
                                     'map $http_upgrade $connection_upgrade { default upgrade; "" ""; }\n'
                                     f'upstream fixture {{ server 127.0.0.1:{origin_port}; keepalive 4096; }}\n'
                                     f'server {{ listen 127.0.0.1:{front_port}; location / {{ proxy_pass http://fixture; '
                                     'proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; '
                                     'proxy_set_header Connection $connection_upgrade; proxy_buffering off; '
                                     'proxy_buffer_size 16k; proxy_buffers 8 16k; proxy_busy_buffers_size 32k; '
                                     'proxy_read_timeout 60s; } } }\n')
                    with contextlib.ExitStack() as stack:
                        if engine == 'direct-origin':
                            port = origin_port; frontend_pid = origin.pid
                        elif engine == 'nginx':
                            name = 'rut-protocol-' + uuid.uuid4().hex[:12]
                            command = ['docker', 'run', '--pull=never', '-d', '--name', name,
                                       '--security-opt', 'label=disable', '--ulimit', 'nofile=65536:65536', '--network', 'host', '--cpuset-cpus', '2',
                                       '--mount', f'type=bind,src={nginx},dst=/etc/nginx/nginx.conf,readonly',
                                       image, 'nginx', '-g', 'daemon off;']
                            subprocess.run(command, check=True, capture_output=True, text=True, env=env)
                            stack.callback(subprocess.run, ['docker', 'rm', '-f', name],
                                           check=True, capture_output=True, env=env)
                            stack.callback(save_container_log, name, directory / 'frontend.log', env)
                            frontend_pid = int(subprocess.check_output(['docker', 'inspect', '-f', '{{.State.Pid}}', name], env=env))
                            port = front_port
                            deadline = time.monotonic() + 10
                            while True:
                                try:
                                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                                        break
                                except OSError:
                                    if time.monotonic() >= deadline:
                                        raise RuntimeError(subprocess.check_output(['docker', 'logs', name], env=env).decode())
                                    time.sleep(.05)
                        else:
                            backend = 'io_uring' if engine == 'uring' else 'epoll'
                            command = ['taskset', '-c', '2', str(args.rut.resolve()), str(program),
                                       '--backend', backend, '--shards', '1', '--no-pin', '--drain', '0']
                            frontend_log = directory / 'frontend.log'
                            frontend = stack.enter_context(process(command, frontend_log,
                                                                   dict(env, RUT_STUDY_POLICY=policy)))
                            ready(front_port, frontend, frontend_log)
                            startup_deadline = time.monotonic() + 30
                            log = frontend_log.read_text()
                            while 'Listening on port' not in log:
                                if frontend.poll() is not None or time.monotonic() >= startup_deadline:
                                    raise RuntimeError('runtime initialization did not finish: ' + log)
                                time.sleep(.05)
                                log = frontend_log.read_text()
                            if f'Backend: {backend}' not in log or f'RUT_STUDY_POLICY profile={policy} ' not in log:
                                raise RuntimeError('backend or policy did not activate')
                            if engine == 'uring' and f"RUT_STUDY_WS_RECV mode={manifest['ws_recv_mode']}" not in log:
                                raise RuntimeError('WebSocket receive mode did not activate')
                            if engine == 'uring' and manifest['ws_splice_mode'] == 'on' and 'RUT_STUDY_WS_SPLICE mode=on' not in log:
                                raise RuntimeError('WebSocket splice mode did not activate')
                            port = front_port; frontend_pid = frontend.pid
                        if case['kind'] == 'websocket':
                            subprocess.run(fixture + ['preflight', '--port', str(port)], check=True, timeout=10, env=env)
                        usage_started = time.monotonic()
                        before, _ = harness.proc_usage(frontend_pid)
                        origin_before, _ = harness.proc_usage(origin.pid)
                        client_command = fixture + ['client', '--port', str(port), '--cpus', '5,7',
                                                    '--connections', '64', '--duration', str(args.duration),
                                                    '--warmup', '2', '--output', str(result_file), *common]
                        run_client(client_command, directory / 'client.log', args.duration + 45, env)
                        after, _ = harness.proc_usage(frontend_pid)
                        origin_after, _ = harness.proc_usage(origin.pid)
                        usage_seconds = time.monotonic() - usage_started
                        row = json.loads(result_file.read_text())
                        row.update(case=case, engine=engine, policy=policy, repeat=repeat,
                                   ws_recv_mode=manifest['ws_recv_mode'] if engine == 'uring' else None,
                                   ws_splice_mode=manifest['ws_splice_mode'] if engine == 'uring' else None,
                                   cpu_observation_seconds=usage_seconds,
                                   frontend_cpu_pct=100 * (after - before) / usage_seconds,
                                   origin_cpu_pct=100 * (origin_after - origin_before) / usage_seconds)
                        result_file.write_text(json.dumps(row, indent=2) + '\n')
                rows.append(row)
                (out / 'measurements.json').write_text(json.dumps(rows, indent=2) + '\n')
                (out / 'summary.json').write_text(json.dumps(summarize(rows), indent=2) + '\n')
                print(f'END {label}: {row["messages_per_second"]:.0f} messages/chunks per second, '
                      f'{row["received_mib_per_second"]:.1f} MiB/s, errors={row["errors"]}', flush=True)
    print('PROTOCOL STUDY COMPLETE', flush=True)


if __name__ == '__main__':
    main()
