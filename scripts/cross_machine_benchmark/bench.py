#!/usr/bin/env python3
"""Three-host HTTP streaming benchmark. Python standard library only."""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

STATUS_SCRIPT = '''
threads = {}
function setup(thread)
  threads[#threads + 1] = thread
  thread:set("bad", 0)
end
function response(status, headers, body)
  if status ~= 200 then bad = bad + 1 end
end
function done(summary, latency, requests)
  local total = 0
  for _, thread in ipairs(threads) do
    total = total + (thread:get("bad") or 0)
  end
  print("Timed non-200 responses: " .. total)
end
'''

MAX_RUT_WORKERS = 64  # Keep in sync with include/rut/common/shard_limits.h.


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def capture(argv):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return {'command': argv, 'returncode': r.returncode,
                'stdout': r.stdout, 'stderr': r.stderr}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'command': argv, 'error': str(e)}


def snapshot(out, binaries=()):
    data = {'time': time.time(), 'uname': list(os.uname()),
            'affinity': sorted(os.sched_getaffinity(0)),
            'network': [capture(c) for c in (
                ['ip', '-details', 'link'], ['ip', 'route'], ['ss', '-s'])],
            'binaries': {}}
    for binary in binaries:
        p = Path(shutil.which(binary) or binary).resolve()
        data['binaries'][str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
    save(out, data)


def positive(s):
    n = int(s)
    if n <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return n


def normalize_cpus(value):
    cpus = set()
    for item in value.split(','):
        bounds = item.split('-', 1)
        if len(bounds) == 1:
            start = end = int(bounds[0])
        else:
            start, end = map(int, bounds)
        if start < 0 or end < start:
            raise ValueError('invalid CPU set')
        cpus.update(range(start, end + 1))
    if not cpus:
        raise ValueError('empty CPU set')
    return ','.join(str(cpu) for cpu in sorted(cpus))


def payload(size):
    pattern = bytes(range(256))
    return (pattern * ((size + 255) // 256))[:size]


def config(out, body_size, origin, port, workers):
    out.mkdir(parents=True, exist_ok=False)
    (out / 'proxy').write_bytes(payload(body_size))
    # Paths embedded in nginx syntax must not contain quotes or control chars.
    root = str(out.resolve())
    if any(c in root for c in '"$\\\n\r'):
        raise ValueError('unsupported output path characters')
    common = (f'worker_processes {workers};\ndaemon off;\n'
              'error_log stderr warn;\npid nginx.pid;\n'
              'events { worker_connections 65536; }\nhttp {\n'
              'access_log off; default_type application/octet-stream;\n'
              'sendfile on; tcp_nopush off; tcp_nodelay on;\n'
              'keepalive_timeout 60s; keepalive_requests 1000000000;\n')
    origin_conf = (common + f'server {{ listen 0.0.0.0:{port}; '
                   f'location = /proxy {{ root "{root}"; }} }}\n}}\n')
    (out / 'origin.conf').write_text(origin_conf)
    if origin:
        host, upstream_port = origin.rsplit(':', 1)
        ipaddress.IPv4Address(host)
        if not 1 <= int(upstream_port) <= 65535:
            raise ValueError('invalid origin port')
        (out / 'proxy.rut').write_text(
            f'listen 0.0.0.0:{port}\nupstream backend at "{origin}"\n'
            'route GET "/proxy" { return forward(backend) }\n')
        (out / 'proxy.conf').write_text(common +
            f'upstream backend {{ server {origin}; keepalive 4096; '
            'keepalive_timeout 60s; keepalive_requests 1000000000; }\n'
            f'server {{ listen 0.0.0.0:{port}; location = /proxy {{ '
            'proxy_pass http://backend; proxy_http_version 1.1; '
            'proxy_set_header Host $http_host; proxy_set_header Connection ""; '
            'proxy_buffering off; proxy_buffer_size 16k; proxy_busy_buffers_size 16k; '
            'proxy_read_timeout 60s; } }\n}\n')
    save(out / 'config.json', dict(body_size=body_size, origin=origin,
                                 port=port, workers=workers))


def config_identity(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def port_is_free(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def process_owns_port(pid, port):
    pids = [pid]
    for current in list(pids):
        try:
            children = Path(f'/proc/{current}/task/{current}/children').read_text().split()
            pids.extend(int(child) for child in children)
        except (FileNotFoundError, OSError, ValueError):
            pass
    try:
        port_hex = f'{port:04X}'
        for current in pids:
            fd_dir = Path(f'/proc/{current}/fd')
            inodes = set()
            for fd in fd_dir.iterdir():
                try:
                    link = os.readlink(fd)
                except OSError:
                    continue
                if link.startswith('socket:['):
                    inodes.add(link.split('[', 1)[1][:-1])
            for table in ('tcp', 'tcp6'):
                lines = Path(f'/proc/{current}/net/{table}').read_text().splitlines()[1:]
                for line in lines:
                    fields = line.split()
                    if len(fields) > 9 and fields[1].rsplit(':', 1)[-1] == port_hex and fields[3] == '0A':
                        if fields[9] in inodes:
                            return True
    except (FileNotFoundError, OSError, IndexError):
        return False
    return False


def validate_server_manifest(manifest, engine, port, body_size):
    required = ('schema', 'engine', 'cpus', 'workers', 'body_size', 'listen_port',
                'config_sha256', 'effective_config_sha256', 'binary_sha256', 'run_id')
    if any(key not in manifest for key in required):
        raise ValueError('incomplete server manifest')
    if manifest['schema'] != 1 or manifest['engine'] != engine:
        raise ValueError('server manifest does not match client engine')
    if manifest['workers'] <= 0 or not manifest['cpus']:
        raise ValueError('incomplete server manifest')
    if manifest['listen_port'] != port or manifest['body_size'] != body_size:
        raise ValueError('server manifest does not match client coordinates')
    return manifest


def validate_rut_workers(workers):
    if workers > MAX_RUT_WORKERS:
        raise ValueError(f'Rut supports at most {MAX_RUT_WORKERS} workers')


def serve(a):
    out = a.config.resolve()
    c = json.loads((out / 'config.json').read_text())
    binary = str(Path(shutil.which(a.binary) or a.binary).resolve())
    if a.engine == 'rut':
        validate_rut_workers(c['workers'])
    if not port_is_free(c['port']):
        raise ValueError(f'listen port is already occupied: {c["port"]}')
    run_id = f'{a.engine}-{time.time_ns()}-{os.getpid()}'
    snapshot(out / f'{run_id}-environment.json', [binary])
    if a.engine == 'rut':
        if not c['origin']:
            raise ValueError('rut requires a proxy config with --origin')
        env = {k: v for k, v in os.environ.items() if not k.startswith('RUT_STUDY_')}
        env['RUT_STUDY_HTTP_ASYNC_SPLICE'] = 'on'
        argv = [binary, str(out / 'proxy.rut'), '--shards', str(c['workers']),
                '--no-pin', '--drain', '1', '--opt', '2', '--backend', 'io_uring']
    else:
        env = {k: v for k, v in os.environ.items() if not k.startswith('RUT_STUDY_')}
        name = 'origin.conf' if a.engine == 'origin' else 'proxy.conf'
        argv = [binary, '-p', str(out) + '/', '-c', str(out / name)]
        subprocess.run(argv + ['-t'], check=True)
    argv = ['taskset', '-c', a.cpus] + argv
    save(out / f'{run_id}-command.json', {'argv': argv,
         'study_environment': {k: v for k, v in env.items() if k.startswith('RUT_STUDY_')}})
    effective_name = 'proxy.rut' if a.engine == 'rut' else ('origin.conf' if a.engine == 'origin' else 'proxy.conf')
    manifest = {
        'schema': 1,
        'run_id': run_id,
        'engine': a.engine,
        'cpus': normalize_cpus(a.cpus),
        'workers': c['workers'],
        'body_size': c['body_size'],
        'listen_port': c['port'],
        'config_sha256': config_identity(out / 'config.json'),
        'effective_config_sha256': config_identity(out / effective_name),
        'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        'command': str(out / f'{run_id}-command.json'),
    }
    child = subprocess.Popen(argv, env=env)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise ValueError('server exited before becoming ready')
            try:
                with socket.create_connection(('127.0.0.1', c['port']), timeout=0.2):
                    if not process_owns_port(child.pid, c['port']):
                        raise ValueError('readiness socket is not owned by launched server')
                    save(out / 'server-manifest.json', manifest)
                    return child.wait()
            except OSError:
                time.sleep(0.05)
        raise ValueError('server did not become ready')
    except BaseException:
        child.terminate()
        child.wait(timeout=5)
        raise


def preflight(host, port, size):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    expected = payload(size)
    try:
        for _ in range(3):
            conn.request('GET', '/proxy')
            response = conn.getresponse()
            if response.status != 200:
                raise ValueError(f'unexpected HTTP status: {response.status}')
            if response.getheader('Content-Length') != str(size):
                raise ValueError('unexpected Content-Length')
            if response.will_close:
                raise ValueError('response closes keepalive connection')
            sock = conn.sock
            if response.read() != expected:
                raise ValueError('response payload mismatch')
            if conn.sock is not sock or sock is None:
                raise ValueError('keepalive socket changed')
    finally:
        conn.close()


def parse_wrk(text):
    rps = re.search(r'Requests/sec:\s+([\d.]+)', text)
    p99 = re.search(r'^\s*99%\s+([\d.]+)(us|ms|s)\s*$', text, re.M)
    errors = re.search(r'Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)', text)
    statuses = re.search(r'Non-2xx or 3xx responses:\s*(\d+)', text)
    timed_statuses = re.search(r'Timed non-200 responses:\s*(\d+)', text)
    if not rps or not p99:
        raise ValueError('incomplete wrk output; requires --latency')
    if not timed_statuses:
        raise ValueError('incomplete wrk output; requires Timed non-200 responses marker')
    counts = dict(zip(('connect', 'read', 'write', 'timeout'),
                      map(int, errors.groups() if errors else ('0',) * 4)))
    counts['status'] = int(statuses[1]) if statuses else 0
    counts['timed_status'] = int(timed_statuses[1])
    return {'rps': float(rps[1]), 'p99_us': float(p99[1]) *
            {'us': 1, 'ms': 1000, 's': 1000000}[p99[2]], 'errors': counts,
            'valid': not any(counts.values())}


def client(a):
    ipaddress.IPv4Address(a.host)
    a.output.mkdir(parents=True, exist_ok=False)
    a.output_created = True
    manifest = json.loads(a.server_manifest.read_text())
    validate_server_manifest(manifest, a.engine, a.port, a.body_size)
    snapshot(a.output / 'environment.json', [a.wrk])
    cpus = normalize_cpus(a.cpus)
    preflight(a.host, a.port, a.body_size)
    status_script = a.output / 'status.lua'
    status_script.write_text(STATUS_SCRIPT)
    argv = ['taskset', '-c', cpus, a.wrk, '-s', str(status_script), '-t', str(a.threads),
            '-c', str(a.connections), '--latency', '--timeout', '5s']
    url = f'http://{a.host}:{a.port}/proxy'
    results = []
    for name, duration in [('warmup', a.warmup), ('measurement', a.duration)]:
        command = argv + ['-d', f'{duration}s', url]
        r = subprocess.run(command, capture_output=True, text=True, timeout=duration + 30)
        (a.output / f'{name}.txt').write_text(r.stdout + r.stderr)
        row = parse_wrk(r.stdout)
        row['valid'] = row['valid'] and r.returncode == 0
        row.update(phase=name, command=command, returncode=r.returncode)
        results.append(row)
    preflight(a.host, a.port, a.body_size)
    result = dict(engine=a.engine, repetition=a.rep, host=a.host, cpus=cpus,
                  body_size=a.body_size, connections=a.connections,
                  duration=a.duration, warmup=a.warmup, port=a.port, threads=a.threads, results=results,
                  server_cpus=manifest['cpus'], server_workers=manifest['workers'],
                  server_config_sha256=manifest['config_sha256'],
                  server_effective_config_sha256=manifest['effective_config_sha256'],
                  server_binary_sha256=manifest['binary_sha256'],
                  server_manifest=str(a.server_manifest.resolve()), server_listen_port=manifest['listen_port'],
                  server_run_id=manifest['run_id'],
                  throughput_classification='instrumented-client-rps-full-body-lua',
                  valid=all(r['valid'] for r in results))
    save(a.output / 'result.json', result)
    print(json.dumps(result, indent=2))
    return 0 if result['valid'] else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    c = sub.add_parser('prepare')
    c.add_argument('--output', type=Path, required=True)
    c.add_argument('--body-size', type=positive, default=1048576)
    c.add_argument('--origin', help='origin IPv4:port; omit on origin host')
    c.add_argument('--port', type=positive, default=8087)
    c.add_argument('--workers', type=positive, default=1)
    s = sub.add_parser('serve')
    s.add_argument('--config', type=Path, required=True)
    s.add_argument('--engine', choices=['origin', 'nginx', 'rut'], required=True)
    s.add_argument('--binary', required=True)
    s.add_argument('--cpus', required=True)
    c = sub.add_parser('client')
    c.add_argument('--host', required=True)
    c.add_argument('--port', type=positive, default=8087)
    c.add_argument('--engine', choices=['rut', 'nginx'], required=True)
    c.add_argument('--rep', type=positive, required=True)
    c.add_argument('--body-size', type=positive, default=1048576)
    c.add_argument('--connections', type=positive, default=128)
    c.add_argument('--threads', type=positive, default=4)
    c.add_argument('--cpus', required=True)
    c.add_argument('--wrk', default='wrk')
    c.add_argument('--server-manifest', type=Path, required=True)
    c.add_argument('--warmup', type=positive, default=5)
    c.add_argument('--duration', type=positive, default=30)
    c.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if getattr(a, 'port', 1) > 65535:
        p.error('port exceeds 65535')
    if a.action == 'prepare':
        config(a.output, a.body_size, a.origin, a.port, a.workers)
    elif a.action == 'serve':
        serve(a)
    else:
        try:
            return client(a)
        except (OSError, ValueError, AssertionError, http.client.HTTPException, subprocess.SubprocessError) as e:
            if getattr(a, 'output_created', False) and not (a.output / 'result.json').exists():
                save(a.output / 'failure.json', {'valid': False, 'error': str(e)})
            raise
    return 0


if __name__ == '__main__':
    sys.exit(main())
