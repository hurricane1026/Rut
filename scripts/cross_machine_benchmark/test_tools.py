import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest

import bench
import summarize


class Tests(unittest.TestCase):
    def test_wrk_errors_and_units(self):
        text = '  99% 2.50ms\nRequests/sec: 1000.25\n'
        self.assertEqual(bench.parse_wrk(text)['p99_us'], 2500)
        self.assertFalse(bench.parse_wrk(text + 'Socket errors: connect 0, read 1, write 0, timeout 2\n')['valid'])
        self.assertFalse(bench.parse_wrk(text + 'Non-2xx or 3xx responses: 3\n')['valid'])
        with self.assertRaises(ValueError):
            bench.parse_wrk('Requests/sec: 100\n')

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
            with self.assertRaises(AssertionError):
                bench.preflight('127.0.0.1', server.server_port, 4096)
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
            for engine, rps in [('rut', 200), ('nginx', 100)]:
                for rep in range(1, 4):
                    p = root / f'{engine}{rep}'
                    p.mkdir()
                    bench.save(p / 'result.json', dict(engine=engine, repetition=rep,
                        host='192.0.2.2', body_size=1024, connections=128, duration=30,
                        warmup=5, port=8087, threads=4, valid=True,
                        results=[dict(phase='measurement', rps=rps, p99_us=100)]))
            self.assertEqual(summarize.summarize(root)[0]['rut_gain_percent'], 100)
            bench.save(root / 'failure.json', {'valid': False})
            with self.assertRaises(ValueError):
                summarize.summarize(root)


if __name__ == '__main__':
    unittest.main()
