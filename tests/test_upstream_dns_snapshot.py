#!/usr/bin/env python3
"""Cold-start upstream DNS snapshots against loopback DNS and origins."""
import argparse
import http.client
import http.server
from pathlib import Path
import re
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


def wire_name(name):
    return b''.join(bytes([len(part)]) + part.encode() for part in name.split('.')) + b'\0'


class DnsState:
    def __init__(self):
        self.mode = 'alias'
        self.queries = 0
        self.tcp_queries = 0

    def answer(self, data, tcp=False):
        self.queries += 1
        self.tcp_queries += int(tcp)
        end = 12
        labels = []
        while data[end]:
            n = data[end]
            labels.append(data[end + 1:end + 1 + n].decode())
            end += n + 1
        end += 5
        question = data[12:end]
        if self.mode == 'timeout':
            return None
        if self.mode == 'missing':
            return data[:2] + struct.pack('!HHHHH', 0x8183, 1, 0, 0, 0) + question
        if self.mode == 'tcp' and not tcp:
            return data[:2] + struct.pack('!HHHHH', 0x8380, 1, 0, 0, 0) + question
        if self.mode == 'alias' and '.'.join(labels) == 'service.test':
            target = wire_name('alias.test')
            record = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 1, len(target)) + target
            return data[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question + record
        count = 9 if self.mode == 'overflow' else 2
        records = b''.join(b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) +
                           bytes([127, 0, 0, i + 1]) for i in range(count))
        return data[:2] + struct.pack('!HHHHH', 0x8180, 1, count, 0, 0) + question + records


class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        response = self.server.state.answer(data)
        if response:
            sock.sendto(response, self.client_address)


class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        prefix = self.request.recv(2, socket.MSG_WAITALL)
        if len(prefix) != 2:
            return
        data = self.request.recv(struct.unpack('!H', prefix)[0], socket.MSG_WAITALL)
        response = self.server.state.answer(data, tcp=True)
        if response:
            self.request.sendall(struct.pack('!H', len(response)) + response)


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.server_address[0].encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--backend', required=True)
    args = parser.parse_args()
    state = DnsState()
    tcp = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Tcp)
    tcp.daemon_threads = True
    udp = socketserver.ThreadingUDPServer(('127.0.0.1', tcp.server_address[1]), Udp)
    udp.daemon_threads = True
    tcp.state = udp.state = state
    origins = [http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)]
    origins.append(http.server.ThreadingHTTPServer(('127.0.0.2', origins[0].server_port), Origin))
    for server in [tcp, udp, *origins]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='rut-upstream-dns-') as directory:
            root = Path(directory)
            source = root / 'gateway.rut'
            source.write_text(f'upstream api {{ host: "Service.Test." port: {origins[0].server_port} }}\n'
                              f'upstream literal {{ host: "127.0.0.1" port: {origins[0].server_port} }}\n'
                              'route GET "/" { return forward(api, load_balance: .roundRobin) }\n'
                              'route GET "/numeric" { return forward(literal, load_balance: .roundRobin) }\n')
            compiler = str(Path(args.server).resolve().with_name('rut-compile'))
            result = subprocess.run([compiler, str(source), '0'], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, timeout=30)
            assert result.returncode == 0, result.stderr.decode(errors='replace')
            assert state.queries == 0, state.queries
            offline = subprocess.run([compiler, str(source), '0', '--ebpf-plan'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
            assert offline.returncode != 0
            assert state.queries == 0, state.queries
            for invalid in ('localhost:53', '127.0.0.1:0', '0.0.0.0:53', '127.0.0.1:bad', '[::1]:53'):
                failed = subprocess.run([args.server, '--upstream-dns-resolver', invalid],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
                assert failed.returncode != 0 and b'upstream-dns-resolver' in failed.stdout
            for mode in ('alias', 'tcp', 'missing', 'overflow', 'timeout'):
                state.mode = mode
                log = root / (mode + '.log')
                with log.open('wb') as output:
                    proc = subprocess.Popen([args.server, '0', str(source), '--backend', args.backend,
                                             '--upstream-dns-resolver', f'127.0.0.1:{tcp.server_address[1]}',
                                             '--no-pin', '--shards', '1', '--drain', '0'],
                                            stdout=output, stderr=subprocess.STDOUT)
                try:
                    end = time.monotonic() + 30
                    while time.monotonic() < end:
                        text = log.read_text(errors='replace')
                        match = re.search(r'Listening on port (\d+)', text)
                        if match or proc.poll() is not None:
                            break
                        time.sleep(.025)
                    else:
                        raise AssertionError(text)
                    if args.backend == 'io_uring' and 'io_uring is unavailable' in text:
                        return 77
                    if mode in ('alias', 'tcp'):
                        assert match, text
                        queries_at_start = state.queries
                        time.sleep(1.2)  # TTL expires, but this is a cold-start snapshot.
                        seen = set()
                        for _ in range(6):
                            conn = http.client.HTTPConnection('127.0.0.1', int(match[1]), timeout=5)
                            conn.request('GET', '/')
                            response = conn.getresponse()
                            assert response.status == 200
                            seen.add(response.read())
                            conn.close()
                        assert seen == {b'127.0.0.1', b'127.0.0.2'}, seen
                        conn = http.client.HTTPConnection('127.0.0.1', int(match[1]), timeout=5)
                        conn.request('GET', '/numeric')
                        response = conn.getresponse()
                        assert response.status == 200 and response.read() == b'127.0.0.1'
                        conn.close()
                        assert state.queries == queries_at_start
                        if mode == 'tcp':
                            assert state.tcp_queries > 0
                    else:
                        assert not match and proc.returncode != 0, text
                        assert 'service.test' in text.lower(), text
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    proc.wait(timeout=10)
        return 0
    finally:
        for server in [tcp, udp, *origins]:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    raise SystemExit(main())
