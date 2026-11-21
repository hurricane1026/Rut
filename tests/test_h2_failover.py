#!/usr/bin/env python3
"""Live pre-send connect failover and non-replay checks on both Linux backends."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time
from auth_h2_fixture import request as h2_request
from test_consistent_hash import SEED, winner, multiplex


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True)
    args = parser.parse_args()
    received = []

    class Origin(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.do_POST()

        def do_POST(self):
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            received.append((self.server.server_port, self.path, body))
            if self.path == '/reset':
                self.close_connection = True
                return
            self.send_response(503 if self.path == '/status' else 200)
            self.send_header('Content-Length', str(len(body) or 2))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body or b'ok')

    servers = [ThreadingHTTPServer(('127.0.0.1', 0), Origin) for _ in range(2)]
    closed = [socket.socket() for _ in range(3)]
    process = None
    try:
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        for sock in closed:
            # Reserve a refused endpoint so another test cannot reuse its port.
            sock.bind(('127.0.0.1', 0))
        dead = [sock.getsockname()[1] for sock in closed]
        live = [server.server_port for server in servers]
        endpoints = [dead[0], live[0], live[1]]
        addresses = ', '.join(f'"127.0.0.1:{p}": {w}'
                              for p, w in zip(endpoints, (1, 3, 0)))
        capped = ', '.join(f'"127.0.0.1:{p}"' for p in [*dead, live[0]])
        source = ''.join(f'upstream {name} {{ backends: [{addresses}] }}\n'
                         for name in ('rr', 'least', 'hashed', 'post_pool')) + f'''
upstream cap {{ backends: [{capped}] }}
upstream origins {{ backends: ["127.0.0.1:{live[0]}", "127.0.0.1:{live[1]}"] }}
route GET "/rr" {{ return forward(rr, load_balance: .roundRobin) }}
route GET "/least" {{ return forward(least, load_balance: .leastRequests) }}
route GET "/hash-close" {{ return forward(hashed, load_balance: .consistentHash,
    hash_key: req.header("X-Key").or(""), hash_seed: "{SEED}") }}
route POST "/post" {{ return forward(post_pool, load_balance: .roundRobin,
    target_transform: {{ strip_prefix: "/", replace_prefix: "/", mode: .rawPrefix }}) }}
route GET "/cap" {{ return forward(cap, load_balance: .roundRobin) }}
route POST "/status" {{ return forward(origins, load_balance: .roundRobin,
    target_transform: {{ strip_prefix: "/", replace_prefix: "/", mode: .rawPrefix }}) }}
route POST "/reset" {{ return forward(origins, load_balance: .roundRobin,
    target_transform: {{ strip_prefix: "/", replace_prefix: "/", mode: .rawPrefix }}) }}
'''
        with tempfile.TemporaryDirectory(prefix='rut-h2-failover-') as directory:
            root = Path(directory)
            program, log = root / 'gateway.rut', root / 'gateway.log'
            program.write_text(source)
            with log.open('wb') as output:
                process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                            '--no-pin', '--shards', '1', '--drain', '0'],
                                           stdout=output, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace')
                match = re.search(r'Listening on port ([0-9]+) with', text)
                if match:
                    port = int(match[1])
                    break
                if process.poll() is not None:
                    if args.backend == 'io_uring' and 'io_uring is unavailable' in text:
                        return 77
                    raise AssertionError(text)
                time.sleep(.025)
            else:
                raise AssertionError(log.read_text())
            for path in ('/rr', '/least'):
                for _ in range(8):
                    assert h2_request(port, path, []) == (200, b'ok'), path
            # Force the initial HRW choice to the refused target. Its next eligible
            # candidate must preserve the key and skip the zero-weight live target.
            keys = [f'key-{i}' for i in range(200)
                    if winner(f'key-{i}'.encode(), endpoints, (1, 3, 0)) == 0][:8]
            assert len(keys) == 8
            for key in keys:
                assert h2_request(port, '/hash-close', [('X-Key', key)]) == (200, b'ok')
            assert multiplex(port, keys) == [(200, b'ok')] * len(keys)
            for i in range(8):
                body = f'post-body-{i}'.encode()
                before = len(received)
                reply = h2_request(port, '/post', [], body, 'POST')
                assert reply == (200, body), (reply, received[before:], i)
                assert received[before:] == [(live[0], '/post', body)]
            before = len(received)
            assert h2_request(port, '/cap', [])[0] == 502
            assert len(received) == before  # The fourth target is outside the budget.
            for path, status in (('/status', 503), ('/reset', 502)):
                before = len(received)
                assert h2_request(port, path, [], b'once', 'POST')[0] == status
                assert len(received) == before + 1, received[before:]
            # Preserve existing H1 connect failover as the helper is shared.
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
            try:
                for _ in range(8):
                    connection.request('GET', '/rr')
                    response = connection.getresponse()
                    assert (response.status, response.read()) == (200, b'ok')
            finally:
                connection.close()
            assert all(p != live[1] for p, path, _ in received if path not in ('/status', '/reset'))
            assert process.poll() is None
            print(f'H1/H2 connect failover, weighted/HRW selection, POST and no-replay: {args.backend}')
            return 0
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for server in servers:
            server.shutdown()
            server.server_close()
        for sock in closed:
            sock.close()


if __name__ == '__main__':
    raise SystemExit(main())
