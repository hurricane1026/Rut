#!/usr/bin/env python3
"""Test an operator-supplied MMDB through the normal Rut server entry point."""
import argparse
import http.client
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


PROGRAM = '''import * as geoip from "geoip.rut"

route POST "/country" {
    guard let ip = IP.parse(req.body) else { return 400 }
    guard let code = geoip.country(ip) else { return 404 }
    if code == "DE" { return 204 } else { return 409 }
}

route GET "/peer" {
    if geoip.country(req.remoteAddr).or("") == "DE" { return 204 } else { return 404 }
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


def run_server(command, log, backend, has_database):
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            data = log.read_bytes()
            match = re.search(rb'Listening on port ([0-9]+) with', data)
            if match:
                break
            if process.poll() is not None:
                if backend == 'io_uring' and b'io_uring is unavailable' in data:
                    return 77
                raise AssertionError(data.decode(errors='replace'))
            time.sleep(.025)
        else:
            raise AssertionError(log.read_text(errors='replace'))

        connection = http.client.HTTPConnection('127.0.0.1', int(match[1]), timeout=8)
        try:
            for method, path, body, expected in (
                ('POST', '/country', '1.2.3.200', 204 if has_database else 404),
                ('POST', '/country', '129.0.0.1', 404),
                ('POST', '/country', '200.3.2.1', 404),
                ('POST', '/country', '::1', 400),
                ('GET', '/peer', None, 204 if has_database else 404),
            ):
                connection.request(method, path, body=body)
                response = connection.getresponse()
                response.read()
                assert response.status == expected, (method, path, body, response.status)
        finally:
            connection.close()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--backend', required=True, choices=('epoll', 'io_uring'))
    parser.add_argument('--opt', type=int, required=True, choices=(0, 2))
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix='rut-geoip-') as directory:
        root = Path(directory)
        shutil.copyfile(args.library, root / 'geoip.rut')
        source, log = root / 'gateway.rut', root / 'server.log'
        source.write_text(PROGRAM)
        db, invalid_db = root / 'country.mmdb', root / 'invalid.mmdb'
        db.write_bytes(mmdb_fixture())
        invalid_db.write_bytes(b'invalid database')
        command = [args.server, '0', str(source), '--backend', args.backend,
                   '--opt', str(args.opt), '--no-pin', '--shards', '1', '--drain', '0']

        for path in (invalid_db, root / 'missing.mmdb'):
            rejected = subprocess.run(command + ['--geoip-db', str(path)],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      timeout=8, check=False)
            assert rejected.returncode == 1 and b'Failed to open --geoip-db' in rejected.stdout, (
                rejected.returncode, rejected.stdout)
        result = run_server(command + ['--geoip-db', str(db)], log, args.backend, True)
        if result:
            return result
        return run_server(command, log, args.backend, False)


if __name__ == '__main__':
    raise SystemExit(main())
