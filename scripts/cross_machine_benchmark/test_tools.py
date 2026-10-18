import http.server
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import threading
import unittest

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
                        binary_sha256='b' * 64, run_id='rut-run')
        self.assertIs(bench.validate_server_manifest(manifest, 'rut', 8087, 1024), manifest)
        with self.assertRaises(ValueError):
            bench.validate_server_manifest(dict(manifest, engine='nginx'), 'rut', 8087, 1024)
        with self.assertRaises(ValueError):
            bench.validate_server_manifest(dict(manifest, listen_port=9087), 'rut', 8087, 1024)
        missing = dict(manifest)
        del missing['binary_sha256']
        with self.assertRaises(ValueError):
            bench.validate_server_manifest(missing, 'rut', 8087, 1024)
        self.assertIsNone(bench.validate_rut_workers(64))
        with self.assertRaises(ValueError):
            bench.validate_rut_workers(65)

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
                        server_workers=1, server_config_sha256='config-a', server_binary_sha256='binary-a',
                        server_manifest='/tmp/server-manifest.json', server_listen_port=8087,
                        server_run_id=f'{engine}-{rep}', valid=True,
                        results=[dict(phase='measurement', rps=rps_values[rep - 1], p99_us=100)]))
            for engine in ('rut', 'nginx'):
                for rep in range(1, 4):
                    (root / f'{engine}{rep}' / 'environment.json').write_text('{}')
            self.assertEqual(summarize.summarize(root)[0]['per_repetition_gain_percent'][::2],
                             [100, 100])
            self.assertAlmostEqual(summarize.summarize(root)[0]['per_repetition_gain_percent'][1], 1)
            self.assertEqual(summarize.summarize(root)[0]['rut_gain_percent'], 100)
            self.assertEqual(summarize.summarize(root)[0]['cpus'], '2-5')
            self.assertEqual(summarize.summarize(root)[0]['server_cpus'], '2')
            mismatch = root / 'mismatch'
            for engine, server_cpus in [('rut', '2'), ('nginx', '3')]:
                for rep in range(1, 4):
                    p = mismatch / f'{engine}{rep}'
                    p.mkdir(parents=True)
                    bench.save(p / 'result.json', dict(engine=engine, repetition=rep,
                        host='192.0.2.2', body_size=1024, connections=128, duration=30,
                        warmup=5, port=8087, threads=4, cpus='2-5', server_cpus=server_cpus,
                        server_workers=1, server_config_sha256='config-a', server_binary_sha256='binary-a',
                        server_manifest='/tmp/server-manifest.json', server_listen_port=8087,
                        server_run_id=f'{engine}-{rep}', valid=True,
                        results=[dict(phase='measurement', rps=100, p99_us=100)]))
            with self.assertRaises(ValueError):
                summarize.summarize(root)
            config_mismatch = root / 'config-mismatch'
            for engine, config_hash in [('rut', 'config-a'), ('nginx', 'config-b')]:
                for rep in range(1, 4):
                    p = config_mismatch / f'{engine}{rep}'
                    p.mkdir(parents=True)
                    bench.save(p / 'result.json', dict(engine=engine, repetition=rep,
                        host='192.0.2.2', body_size=1024, connections=128, duration=30,
                        warmup=5, port=8087, threads=4, cpus='2-5', server_cpus='2',
                        server_workers=1, server_config_sha256=config_hash, server_binary_sha256='binary-a',
                        server_manifest='/tmp/server-manifest.json', server_listen_port=8087,
                        server_run_id=f'{engine}-{rep}', valid=True,
                        results=[dict(phase='measurement', rps=100, p99_us=100)]))
            with self.assertRaises(ValueError):
                summarize.summarize(root)
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
