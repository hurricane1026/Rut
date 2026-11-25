#!/usr/bin/env python3
"""Exercise the pure Rut client against the standalone MaxMind database tool."""
import argparse
from contextlib import contextmanager
import http.client
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time


PROGRAM = '''import * as geoip from "geoip.rut"

route POST "/country" {
    let pending = geoip.country(req.body)
    guard let code = pending else { return 404 }
    return response(200, body: code)
}
'''


def mmdb_fixture():
    # MMDB control bytes encode type in the upper bits and size in the lower bits.
    def string(value):
        return bytes([0x40 | len(value)]) + value.encode('ascii')

    def uint(value, kind):
        encoded = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        return bytes([(kind << 5) | len(encoded)]) + encoded

    def mapping(*fields):
        return bytes([0xe0 | len(fields)]) + b''.join(
            string(key) + value for key, value in fields)

    country = mapping(('country', mapping(('iso_code', string('DE')))))
    no_country = mapping(('city', mapping()))
    node_count = 2
    data_record = node_count + 16
    # 0.0.0.0/1 has a country, 128.0.0.0/2 lacks a country, 192.0.0.0/2 is absent.
    tree = b''.join(value.to_bytes(3, 'big') for value in
                    (data_record, 1, data_record + len(country), node_count))
    metadata = mapping(
        ('node_count', uint(node_count, 6)), ('record_size', uint(24, 5)),
        ('ip_version', uint(4, 5)), ('database_type', string('GeoIP2-Country')),
        ('languages', b'\x01\x04' + string('en')),
        ('binary_format_major_version', uint(2, 5)),
        ('binary_format_minor_version', uint(0, 5)),
        ('build_epoch', b'\x01\x02\x01'),
        ('description', mapping(('en', string('Rut test')))))
    return tree + bytes(16) + country + no_country + b'\xab\xcd\xefMaxMind.com' + metadata


@contextmanager
def listener(command, log, pattern, env=None, skip_unavailable=False):
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, env=env)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            data = log.read_bytes()
            match = re.search(pattern, data)
            if match:
                yield int(match[1])
                return
            if process.poll() is not None:
                if skip_unavailable and b'io_uring is unavailable' in data:
                    yield None
                    return
                raise AssertionError(data.decode(errors='replace'))
            time.sleep(.025)
        raise AssertionError(log.read_text(errors='replace'))
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--geoip', required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, required=True, choices=(0, 2))
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix='rut-geoip-') as directory:
        root = Path(directory)
        shutil.copyfile(args.library, root / 'geoip.rut')
        source, db, invalid_db = root / 'gateway.rut', root / 'country.mmdb', root / 'invalid.mmdb'
        source.write_text(PROGRAM)
        db.write_bytes(mmdb_fixture())
        invalid_db.write_bytes(b'invalid database')

        for path in (invalid_db, root / 'missing.mmdb'):
            rejected = subprocess.run([args.geoip, str(path), '0'], stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, timeout=8, check=False)
            assert rejected.returncode == 1 and b'Failed to open GeoIP database' in rejected.stdout, (
                rejected.returncode, rejected.stdout)

        with listener([args.geoip, str(db), '0'], root / 'geoip.log',
                      rb'Listening on 127[.]0[.]0[.]1:([0-9]+)') as lookup_port:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
                peer.settimeout(3)
                peer.connect(('127.0.0.1', lookup_port))
                for query in (b'', b'1.2.3.4\x00', b'127.100.100.100x', b'1.2.3.4' * 20):
                    peer.send(query)
                    assert peer.recv(2) == b'', query
            env = os.environ.copy()
            env['GEOIP_ENDPOINT'] = f'{{"address":"127.0.0.1","port":{lookup_port}}}'
            command = [args.server, '0', str(source), '--backend', args.backend,
                       '--opt', str(args.opt), '--no-pin', '--shards', '1', '--drain', '0']
            with listener(command, root / 'server.log', rb'Listening on port ([0-9]+) with',
                          env=env, skip_unavailable=args.backend == 'io_uring') as port:
                if port is None:
                    return 77
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
                try:
                    for address, expected in (
                        ('1.2.3.200', 200), ('129.0.0.1', 404), ('200.3.2.1', 404), ('::1', 404),
                    ):
                        connection.request('POST', '/country', body=address)
                        response = connection.getresponse()
                        body = response.read()
                        assert response.status == expected, (address, response.status, body)
                        if expected == 200:
                            assert body == b'DE', body
                finally:
                    connection.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
