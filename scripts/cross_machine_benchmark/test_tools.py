import http.server
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import bench
import summarize


class Tests(unittest.TestCase):
    def test_normalize_cpus_and_reject_nginx_variables(self):
        self.assertEqual(bench.normalize_cpus('5,2-3,4'), '2,3,4,5')
        with self.assertRaises(ValueError):
            bench.normalize_cpus('3-2')
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'cost$bucket'
            with self.assertRaises(ValueError):
                bench.config(bad, 64, None, 8087, 1)

    def test_server_manifest_coordinates_and_required_fields(self):
        manifest = dict(schema=1, engine='rut', cpus='2', workers=1, body_size=1024,
                        listen_port=8087, config_sha256='a' * 64,
                        effective_config_sha256='c' * 64,
                        binary_sha256='b' * 64, run_id='rut-run',
                        machine_uname=['Linux', 'proxy', '5.0', 'x86_64', 'proxy'])
        self.assertIs(bench.validate_server_manifest(manifest, 'rut', 8087, 1024), manifest)
        with self.assertRaises(ValueError):
            bench.validate_server_manifest(dict(manifest, engine='nginx'), 'rut', 8087, 1024)
        with self.assertRaises(ValueError):
            bench.validate_server_manifest(dict(manifest, listen_port=9087), 'rut', 8087, 1024)
        missing = dict(manifest)
        del missing['binary_sha256']
        with self.assertRaises(ValueError):
            bench.validate_server_manifest(missing, 'rut', 8087, 1024)
        malformed = dict(manifest, machine_uname='Linux')
        with self.assertRaises(ValueError):
            bench.validate_server_manifest(malformed, 'rut', 8087, 1024)
        self.assertIsNone(bench.validate_rut_workers(64))
        with self.assertRaises(ValueError):
            bench.validate_rut_workers(65)
        origin = dict(schema=1, engine='origin', body_size=1024, listen_port=9087,
                      endpoint='192.0.2.30:9087', cpus='6-7', workers=4,
                      config_sha256='d' * 64, effective_config_sha256='e' * 64,
                      binary_sha256='f' * 64, run_id='origin-1')
        self.assertIs(bench.validate_origin_manifest(origin, '192.0.2.30:9087'), origin)
        with self.assertRaises(ValueError):
            bench.validate_origin_manifest(origin, '192.0.2.30:9088')
        proxy = {f'origin_{field}': origin[field] for field in
                 ('endpoint', 'run_id', 'cpus', 'workers', 'listen_port',
                  'binary_sha256', 'config_sha256', 'effective_config_sha256')}
        bench.validate_origin_provenance(proxy, origin)
        with self.assertRaises(ValueError):
            bench.validate_origin_provenance(proxy, dict(origin, run_id='origin-2'))
        with self.assertRaises(ValueError):
            bench.validate_origin_provenance(proxy, dict(origin, binary_sha256='0' * 64))

    def test_wrk_errors_and_units(self):
        text = ('  99% 2.50ms\nRequests/sec: 1000.25\n'
                'Timed non-200 responses: 0\n')
        self.assertEqual(bench.parse_wrk(text)['p99_us'], 2500)
        self.assertFalse(bench.parse_wrk(text + 'Socket errors: connect 0, read 1, write 0, timeout 2\n')['valid'])
        bad_timed = text.replace('Timed non-200 responses: 0',
                                 'Timed non-200 responses: 1')
        self.assertFalse(bench.parse_wrk(bad_timed)['valid'])
        self.assertFalse(bench.parse_wrk(text + 'Non-2xx or 3xx responses: 3\n')['valid'])
        with self.assertRaises(ValueError):
            bench.parse_wrk('Requests/sec: 100\n')
        with self.assertRaises(ValueError):
            bench.parse_wrk('  99% 2.50ms\nRequests/sec: 1000.25\n')

    def test_preflight_real_keepalive_and_corruption(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            corrupt = False

            def do_GET(self):
                body = b'x' * 4096 if self.corrupt else bench.payload(4096)
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            bench.preflight('127.0.0.1', server.server_port, 4096)
            Handler.corrupt = True
            with self.assertRaises(ValueError):
                bench.preflight('127.0.0.1', server.server_port, 4096)
        finally:
            server.shutdown()
            server.server_close()
            t.join()

    def test_wrk_status_counter_across_threads(self):
        wrk = os.environ.get('WRK') or shutil.which('wrk')
        if not wrk:
            self.skipTest('wrk is not installed; set WRK to a local binary for integration coverage')
        class Handler(http.server.BaseHTTPRequestHandler):
            requests = 0
            all_ok = False
            def do_GET(self):
                type(self).requests += 1
                status = 200 if type(self).all_ok else (201 if type(self).requests % 2 else 200)
                self.send_response(status)
                self.send_header('Content-Length', '0')
                self.end_headers()
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                script = Path(tmp) / 'status.lua'
                script.write_text(bench.STATUS_SCRIPT)
                r = subprocess.run(
                    [wrk, '-s', str(script), '-t', '2', '-c', '2', '-d', '1s',
                     '--latency', f'http://127.0.0.1:{server.server_port}/'],
                    capture_output=True, text=True, timeout=15)
                self.assertEqual(r.returncode, 0, r.stderr)
                parsed = bench.parse_wrk(r.stdout)
                self.assertGreater(parsed['errors']['timed_status'], 0, r.stdout)
                self.assertFalse(parsed['valid'])
                Handler.all_ok = True
                r = subprocess.run(
                    [wrk, '-s', str(script), '-t', '2', '-c', '2', '-d', '1s',
                     '--latency', f'http://127.0.0.1:{server.server_port}/'],
                    capture_output=True, text=True, timeout=15)
                self.assertEqual(r.returncode, 0, r.stderr)
                parsed = bench.parse_wrk(r.stdout)
                self.assertEqual(parsed['errors']['timed_status'], 0, r.stdout)
                self.assertTrue(parsed['valid'])
        finally:
            server.shutdown()
            server.server_close()
            t.join()

    def test_config_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'config'
            bench.config(out, 4096, '192.0.2.3:9087', 8087, 1)
            self.assertEqual((out / 'proxy').read_bytes(), bench.payload(4096))
            self.assertIn('proxy_buffering off', (out / 'proxy.conf').read_text())
            with self.assertRaises(FileExistsError):
                bench.config(out, 1024, None, 8087, 1)

    def test_port_ownership_preflight_rejects_occupied_port(self):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))
        child = subprocess.Popen(['sleep', '2'])
        try:
            self.assertFalse(bench.port_is_free(sock.getsockname()[1]))
            sock.listen(1)
            self.assertTrue(bench.process_owns_port(os.getpid(), sock.getsockname()[1]))
            self.assertFalse(bench.process_owns_port(child.pid, sock.getsockname()[1]))
        finally:
            sock.close()
            child.terminate()
            child.wait()

    def test_main_propagates_serve_exit_status(self):
        with mock.patch.object(bench, 'serve', return_value=7):
            with mock.patch.object(bench.sys, 'argv', ['bench.py', 'serve', '--config', 'x',
                                                       '--engine', 'rut', '--binary', 'x', '--cpus', '0']):
                self.assertEqual(bench.main(), 7)

    def test_summary_pairs_and_failed_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rps_by_engine = {
                'nginx': [1, 100, 101],
                'rut': [2, 101, 202],
            }
            for engine, rps_values in rps_by_engine.items():
                for rep in range(1, 4):
                    p = root / f'{engine}{rep}'
                    p.mkdir()
                    bench.save(p / 'result.json', dict(engine=engine, repetition=rep,
                        host='192.0.2.2', body_size=1024, connections=128, duration=30,
                        warmup=5, port=8087, threads=4, cpus='2-5', server_cpus='2',
                        server_workers=1, server_config_sha256='config-a', server_effective_config_sha256='effective-a',
                        server_binary_sha256='binary-a',
                        server_machine_uname=['Linux', 'proxy', '5.0', 'x86_64', 'proxy'],
                        server_compiler_sha256=('compiler-a' if engine == 'rut' else None),
                        origin_endpoint='192.0.2.30:9087', origin_run_id='origin-1',
                        origin_cpus='6-7', origin_workers=4, origin_listen_port=9087,
                        origin_binary_sha256='origin-binary-a', origin_config_sha256='origin-config-a',
                        origin_effective_config_sha256='origin-effective-a',
                        throughput_classification='instrumented-client-rps-full-body-lua',
                        server_manifest='/tmp/server-manifest.json', server_listen_port=8087,
                        server_run_id=f'{engine}-{rep}', valid=True,
                        results=[dict(phase='measurement', rps=rps_values[rep - 1], p99_us=100)]))
            for engine in ('rut', 'nginx'):
                for rep in range(1, 4):
                    order = {('rut', 1): 1, ('nginx', 1): 2, ('nginx', 2): 3,
                             ('rut', 2): 4, ('rut', 3): 5, ('nginx', 3): 6}
                    (root / f'{engine}{rep}' / 'environment.json').write_text(
                        json.dumps({'time': order[(engine, rep)], 'uname': ['Linux', 'fixture', '5.0', 'x86_64', 'fixture'],
                                    'binaries': {'/opt/wrk': 'a' * 64}}))
            self.assertEqual(summarize.summarize(root)[0]['throughput_classification'],
                             'inconclusive-lua-body-callback')
            self.assertEqual(summarize.summarize(root)[0]['rut']['instrumented_rps'], [2, 101, 202])
            self.assertEqual(summarize.summarize(root)[0]['cpus'], '2-5')
            self.assertEqual(summarize.summarize(root)[0]['server_cpus'], '2')

            client_changed = root / 'client-changed'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, client_changed / name)
            client_env = client_changed / 'rut2' / 'environment.json'
            client_data = json.loads(client_env.read_text())
            client_data['binaries']['/opt/wrk'] = 'b' * 64
            client_env.write_text(json.dumps(client_data))
            with self.assertRaises(ValueError):
                summarize.summarize(client_changed)
            compiler_changed = root / 'compiler-changed'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, compiler_changed / name)
            compiler_result = compiler_changed / 'rut2' / 'result.json'
            compiler_data = json.loads(compiler_result.read_text())
            compiler_data['server_compiler_sha256'] = 'compiler-b'
            compiler_result.write_text(json.dumps(compiler_data))
            with self.assertRaises(ValueError):
                summarize.summarize(compiler_changed)
            machine_changed = root / 'machine-changed'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, machine_changed / name)
            machine_env = machine_changed / 'nginx2' / 'environment.json'
            machine_data = json.loads(machine_env.read_text())
            machine_data['uname'] = ['Linux', 'different-client', '5.0', 'x86_64', 'fixture']
            machine_env.write_text(json.dumps(machine_data))
            with self.assertRaises(ValueError):
                summarize.summarize(machine_changed)
            malformed = root / 'malformed-uname'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, malformed / name)
            malformed_env = malformed / 'rut1' / 'environment.json'
            malformed_data = json.loads(malformed_env.read_text())
            malformed_data['uname'] = 'Linux'
            malformed_env.write_text(json.dumps(malformed_data))
            with self.assertRaises(ValueError):
                summarize.summarize(malformed)
            missing_uname = root / 'missing-uname'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, missing_uname / name)
            missing_env = missing_uname / 'rut1' / 'environment.json'
            missing_data = json.loads(missing_env.read_text())
            del missing_data['uname']
            missing_env.write_text(json.dumps(missing_data))
            with self.assertRaises(ValueError):
                summarize.summarize(missing_uname)
            origin_changed = root / 'origin-changed'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, origin_changed / name)
            origin_result = origin_changed / 'nginx2' / 'result.json'
            origin_data = json.loads(origin_result.read_text())
            origin_data['origin_run_id'] = 'origin-2'
            origin_result.write_text(json.dumps(origin_data))
            with self.assertRaises(ValueError):
                summarize.summarize(origin_changed)
            proxy_machine_changed = root / 'proxy-machine-changed'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, proxy_machine_changed / name)
            proxy_result = proxy_machine_changed / 'rut2' / 'result.json'
            proxy_data = json.loads(proxy_result.read_text())
            proxy_data['server_machine_uname'] = ['Linux', 'other-proxy', '5.0', 'x86_64', 'proxy']
            proxy_result.write_text(json.dumps(proxy_data))
            with self.assertRaises(ValueError):
                summarize.summarize(proxy_machine_changed)
            proxy_scalar = root / 'proxy-scalar-identity'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, proxy_scalar / name)
            scalar_result = proxy_scalar / 'rut1' / 'result.json'
            scalar_data = json.loads(scalar_result.read_text())
            scalar_data['server_machine_uname'] = 'Linux'
            scalar_result.write_text(json.dumps(scalar_data))
            with self.assertRaises(ValueError):
                summarize.summarize(proxy_scalar)
            proxy_missing = root / 'proxy-missing-identity'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, proxy_missing / name)
            missing_result = proxy_missing / 'rut1' / 'result.json'
            missing_data = json.loads(missing_result.read_text())
            del missing_data['server_machine_uname']
            missing_result.write_text(json.dumps(missing_data))
            with self.assertRaises(ValueError):
                summarize.summarize(proxy_missing)
            versioned = root / 'versioned-wrk'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, versioned / name)
                env_path = versioned / name / 'environment.json'
                env = json.loads(env_path.read_text())
                env['binaries'] = {'/opt/wrk-4.2.0': 'a' * 64}
                env_path.write_text(json.dumps(env))
            self.assertEqual(len(summarize.summarize(versioned)), 1)

            four = root / 'four-pair'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, four / name)
            for engine in ('rut', 'nginx'):
                target = four / f'{engine}4'
                shutil.copytree(four / f'{engine}3', target)
                result = json.loads((target / 'result.json').read_text())
                result['repetition'] = 4
                result['server_run_id'] = f'{engine}-4'
                (target / 'result.json').write_text(json.dumps(result))
            for engine, time_value in [('nginx', 7), ('rut', 8)]:
                env_path = four / f'{engine}4' / 'environment.json'
                env = json.loads(env_path.read_text())
                env['time'] = time_value
                env_path.write_text(json.dumps(env))
            self.assertEqual(len(summarize.summarize(four)[0]['rut']['instrumented_rps']), 4)
            four_bad = root / 'four-pair-misordered'
            shutil.copytree(four, four_bad)
            env_path = four_bad / 'rut4' / 'environment.json'
            env = json.loads(env_path.read_text())
            env['time'] = 6
            env_path.write_text(json.dumps(env))
            with self.assertRaises(ValueError):
                summarize.summarize(four_bad)
            duplicate = root / 'duplicate-run'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, duplicate / name)
            duplicate_result = duplicate / 'rut2' / 'result.json'
            duplicate_data = json.loads(duplicate_result.read_text())
            duplicate_data['server_run_id'] = 'rut-1'
            duplicate_result.write_text(json.dumps(duplicate_data))
            with self.assertRaises(ValueError):
                summarize.summarize(duplicate)
            reordered = root / 'reordered'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, reordered / name)
            (reordered / 'nginx1' / 'environment.json').write_text(json.dumps({'time': 10}))
            with self.assertRaises(ValueError):
                summarize.summarize(reordered)
            binary_changed = root / 'binary-changed'
            for name in ('rut1', 'rut2', 'rut3', 'nginx1', 'nginx2', 'nginx3'):
                shutil.copytree(root / name, binary_changed / name)
            binary_result = binary_changed / 'rut2' / 'result.json'
            binary_data = json.loads(binary_result.read_text())
            binary_data['server_binary_sha256'] = 'binary-b'
            binary_result.write_text(json.dumps(binary_data))
            with self.assertRaises(ValueError):
                summarize.summarize(binary_changed)
            mismatch = root / 'mismatch'
            for engine, server_cpus in [('rut', '2'), ('nginx', '3')]:
                for rep in range(1, 4):
                    p = mismatch / f'{engine}{rep}'
                    p.mkdir(parents=True)
                    bench.save(p / 'result.json', dict(engine=engine, repetition=rep,
                        host='192.0.2.2', body_size=1024, connections=128, duration=30,
                        warmup=5, port=8087, threads=4, cpus='2-5', server_cpus=server_cpus,
                        server_workers=1, server_config_sha256='config-a', server_effective_config_sha256='effective-a',
                        server_binary_sha256='binary-a',
                        server_machine_uname=['Linux', 'proxy', '5.0', 'x86_64', 'proxy'],
                        server_compiler_sha256=('compiler-a' if engine == 'rut' else None),
                        origin_endpoint='192.0.2.30:9087', origin_run_id='origin-1',
                        origin_cpus='6-7', origin_workers=4, origin_listen_port=9087,
                        origin_binary_sha256='origin-binary-a', origin_config_sha256='origin-config-a',
                        origin_effective_config_sha256='origin-effective-a',
                        throughput_classification='instrumented-client-rps-full-body-lua',
                        server_manifest='/tmp/server-manifest.json', server_listen_port=8087,
                        server_run_id=f'{engine}-{rep}', valid=True,
                        results=[dict(phase='measurement', rps=100, p99_us=100)]))
                    (p / 'environment.json').write_text(json.dumps(
                        {'time': (rep - 1) * 2 + (1 if engine == 'rut' else 2), 'uname': ['Linux', 'fixture', '5.0', 'x86_64', 'fixture'],
                         'binaries': {'/opt/wrk': 'a' * 64}}))
            with self.assertRaises(ValueError):
                summarize.summarize(mismatch)
            config_mismatch = root / 'config-mismatch'
            for engine, config_hash in [('rut', 'config-a'), ('nginx', 'config-b')]:
                for rep in range(1, 4):
                    p = config_mismatch / f'{engine}{rep}'
                    p.mkdir(parents=True)
                    bench.save(p / 'result.json', dict(engine=engine, repetition=rep,
                        host='192.0.2.2', body_size=1024, connections=128, duration=30,
                        warmup=5, port=8087, threads=4, cpus='2-5', server_cpus='2',
                        server_workers=1, server_config_sha256=config_hash, server_effective_config_sha256='effective-a',
                        server_binary_sha256='binary-a',
                        server_machine_uname=['Linux', 'proxy', '5.0', 'x86_64', 'proxy'],
                        server_compiler_sha256=('compiler-a' if engine == 'rut' else None),
                        origin_endpoint='192.0.2.30:9087', origin_run_id='origin-1',
                        origin_cpus='6-7', origin_workers=4, origin_listen_port=9087,
                        origin_binary_sha256='origin-binary-a', origin_config_sha256='origin-config-a',
                        origin_effective_config_sha256='origin-effective-a',
                        throughput_classification='instrumented-client-rps-full-body-lua',
                        server_manifest='/tmp/server-manifest.json', server_listen_port=8087,
                        server_run_id=f'{engine}-{rep}', valid=True,
                        results=[dict(phase='measurement', rps=100, p99_us=100)]))
                    (p / 'environment.json').write_text(json.dumps(
                        {'time': (rep - 1) * 2 + (1 if engine == 'rut' else 2), 'uname': ['Linux', 'fixture', '5.0', 'x86_64', 'fixture'],
                         'binaries': {'/opt/wrk': 'a' * 64}}))
            with self.assertRaises(ValueError):
                summarize.summarize(config_mismatch)
            unfinished = root / 'unfinished'
            unfinished.mkdir()
            (unfinished / 'environment.json').write_text('{}')
            with self.assertRaises(ValueError):
                summarize.summarize(root)
            bench.save(root / 'failure.json', {'valid': False})
            with self.assertRaises(ValueError):
                summarize.summarize(root)


if __name__ == '__main__':
    unittest.main()
