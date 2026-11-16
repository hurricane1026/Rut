#!/usr/bin/env python3
"""Bounded OAuth JWT access profile with independent RS256-signed fixtures."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from auth_h2_fixture import request as h2_request
from test_keycloak_roles import MODULUS, signed

ISSUER = 'https://access.example/issuer'
AUDIENCE = 'orders-api'
CLIENT_ID = 'orders-web'


@contextmanager
def gateway(args, directory, required_type='at+jwt', client_id=CLIENT_ID,
            scope='orders:read', revoked_jtis=None):
    original = Path(args.source).resolve()
    root = directory / str(time.monotonic_ns())
    root.mkdir()
    (root / 'middleware').mkdir()
    shutil.copyfile(original.parent / 'middleware' / 'jwt_access.rut',
                    root / 'middleware' / 'jwt_access.rut')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    source = root / 'gateway.rut'
    source.write_text(original.read_text().replace('listen :8080', f'listen :{port}'))
    policy = dict(issuer=ISSUER, audience=AUDIENCE, kids=['current'],
                  jwks=dict(keys=[dict(kid='current', kty='RSA', alg='RS256', n=MODULUS, e='AQAB')]))
    if revoked_jtis is not None:
        policy['revokedJtis'] = revoked_jtis
    if required_type is not None:
        policy['requiredType'] = required_type
    env = dict(os.environ, JWT_ACCESS_RS256_POLICY=json.dumps(policy),
               JWT_ACCESS_CLIENT_ID=client_id, JWT_ACCESS_REQUIRED_SCOPE=scope)
    log = root / 'gateway.log'
    with log.open('w') as output:
        process = subprocess.Popen([args.server, str(source), '--backend', args.backend,
                                    '--opt', str(args.opt), '--no-pin', '--shards', '2', '--drain', '0'],
                                   env=env, stdout=output, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 60
        while True:
            if process.poll() is not None:
                if args.backend == 'io_uring' and 'io_uring is unavailable' in log.read_text():
                    raise SystemExit(77)
                raise AssertionError(log.read_text())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(.025)
        source.unlink()
        shutil.rmtree(root / 'middleware')
        yield port
    finally:
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def token(claims, typ='at+jwt', header=None):
    header = header or dict(alg='RS256', kid='current', typ=typ)
    return signed(claims, header)


def request(port, path, credential, version, duplicate=False):
    fields = [('X-Client-ID', CLIENT_ID), ('X-Scope', 'orders:read'),
              ('X-Subject', 'admin'), ('X-Role', 'admin')]
    if credential is not None:
        fields += [('Authorization', 'Bearer ' + credential)] * (2 if duplicate else 1)
    path += '?client_id=admin&scope=orders%3Aread&sub=admin'
    if version == 'h2':
        status, body = h2_request(port, path, fields)
        return status, body
    headers = ''.join(f'{key}: {value}\r\n' for key, value in fields)
    wire = f'GET {path} {version}\r\nHost: local\r\nConnection: close\r\n{headers}\r\n'.encode()
    with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
        connection.sendall(wire)
        data = b''
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            data += chunk
    head, _, body = data.partition(b'\r\n\r\n')
    return int(head.split(b' ', 2)[1]), body


def raw_duplicate_claims(claims):
    text = json.dumps(claims, separators=(',', ':'))
    return text[:-1] + ',"client_id":"orders-web"}'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    args = parser.parse_args()
    now = int(time.time())
    base = dict(sub='alice', iss=ISSUER, aud=AUDIENCE, iat=now, exp=now + 600,
                client_id=CLIENT_ID, jti='token-1', scope='orders:read')
    accepted = dict(base)
    accepted_payload_type = dict(base, typ='JWT')
    cases = [
        (accepted, (204, 200)),
        (accepted_payload_type, (204, 200)),  # payload typ never replaces protected-header typ
        (dict(base, client_id='another-client'), (204, 403)),
        (dict(base, scope='orders:write'), (204, 403)),
        (dict(base, scope='orders:reader'), (204, 403)),
        ({key: value for key, value in base.items() if key != 'scope'}, (204, 403)),
        (dict(base, scope=['orders:read']), (204, 403)),
        (dict(base, scope='orders:read\u0000'), (204, 403)),
        (dict(base, jti='revoked'), (204, 200)),
        (dict(base, jti=''), (401, 401)),
        (dict(base, jti=1), (401, 401)),
        (dict(base, jti=[]), (401, 401)),
        (dict(base, jti='j' * 129), (401, 401)),
        ({key: value for key, value in base.items() if key != 'jti'}, (401, 401)),
        (dict(base, client_id=''), (401, 401)),
        (dict(base, client_id=1), (401, 401)),
        (dict(base, client_id=None), (401, 401)),
        (dict(base, client_id=[]), (401, 401)),
        (dict(base, client_id='c' * 1025), (401, 401)),
        ({key: value for key, value in base.items() if key != 'client_id'}, (401, 401)),
        (dict(base, iat=now + 300), (401, 401)),
        (dict(base, iat=now - 301), (401, 401)),
        (dict(base, iat=now, exp=now + 3601), (401, 401)),
        (dict(base, sub=''), (401, 401)),
        ({key: value for key, value in base.items() if key != 'sub'}, (401, 401)),
        (dict(base, iss='https://other.example/issuer'), (401, 401)),
        (dict(base, aud='other-api'), (401, 401)),
        (dict(base, aud=['other-api', AUDIENCE]), (204, 200)),
        (dict(base, exp=now - 1), (401, 401)),
        (dict(base, nbf=now + 600), (401, 401)),
    ]
    for bad_iat in (None, 'now', 0, -1, 1.5, 2**63):
        cases.append((dict(base, iat=bad_iat), (401, 401)))
    cases.append(({key: value for key, value in base.items() if key != 'iat'}, (401, 401)))
    cases.append((raw_duplicate_claims(base), (401, 401)))
    checks = 0
    with tempfile.TemporaryDirectory(prefix='rut-jwt-access-') as directory:
        root = Path(directory)
        for required_type in ('at+jwt', 'application/at+jwt'):
            with gateway(args, root, required_type) as port:
                for version in ('HTTP/1.0', 'HTTP/1.1', 'h2'):
                    for claims, expected in cases:
                        credential = token(claims, required_type)
                        for path, status in zip(('/access', '/read'), expected):
                            actual, body = request(port, path, credential, version)
                            assert actual == status, (required_type, version, path, claims, actual, status)
                            if path == '/read' and status == 200:
                                assert body == b'alice', (version, body)
                            checks += 1
                good = token(accepted, required_type)
                bad_signature = good[:-5] + ('A' if good[-5] != 'A' else 'B') + good[-4:]
                bad_credentials = (
                    (None, False, None), ('malformed', False, None),
                    (bad_signature, False, None), (good, True, None),
                    (token(accepted, 'JWT'), False, None),
                    (token(dict(base, typ='at+jwt'), 'JWT'), False, None),
                    (token(accepted, 'at+jwt' if required_type != 'at+jwt' else 'application/at+jwt'), False, None),
                    (good, False, dict(alg='HS256', kid='current', typ=required_type)),
                    (good, False, dict(alg='RS256', kid='unknown', typ=required_type)),
                    (good, False, dict(alg='RS256', kid='current', typ=required_type, crit=['bad'])),
                    (good, False, dict(alg='RS256', kid='current')),
                    (good, False, dict(alg='RS256', kid='current', typ=1)),
                    (good, False, dict(alg='RS256', kid='current', typ='at+JWT')))
                for credential, duplicate, header in bad_credentials:
                    credential = credential if header is None else token(accepted, required_type, header)
                    for version in ('HTTP/1.0', 'HTTP/1.1', 'h2'):
                        actual, _ = request(port, '/read', credential, version, duplicate)
                        assert actual == 401, (required_type, version, credential, actual)
                        checks += 1
        # Invalid profile selectors are configuration failures before token use.
        for wrong_type in ('JWT', None):
            with gateway(args, root, wrong_type) as port:
                valid_type = wrong_type or 'at+jwt'
                credential = token(accepted, valid_type)
                actual, _ = request(port, '/access', credential, 'HTTP/1.1')
                assert actual == 503, (wrong_type, actual)
                checks += 1
        # A malformed optional requiredType is rejected while loading the policy,
        # rather than reported as an HTTP response.
        malformed_policy = dict(issuer=ISSUER, audience=AUDIENCE, kids=['current'],
                                jwks=dict(keys=[dict(kid='current', kty='RSA', alg='RS256', n=MODULUS, e='AQAB')]),
                                requiredType=1)
        with tempfile.TemporaryDirectory(prefix='rut-jwt-access-load-') as load_dir:
            root_path = Path(load_dir)
            (root_path / 'middleware').mkdir()
            shutil.copyfile(Path(args.source).resolve().parent / 'middleware' / 'jwt_access.rut',
                            root_path / 'middleware' / 'jwt_access.rut')
            source = root_path / 'gateway.rut'
            source.write_text(Path(args.source).resolve().read_text().replace('listen :8080', 'listen :0'))
            env = dict(os.environ, JWT_ACCESS_RS256_POLICY=json.dumps(malformed_policy),
                       JWT_ACCESS_CLIENT_ID=CLIENT_ID)
            result = subprocess.run([args.server, str(source), '--backend', args.backend, '--opt', str(args.opt),
                                     '--no-pin', '--shards', '1', '--drain', '0'], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
            if args.backend == 'io_uring' and b'io_uring is unavailable' in result.stdout:
                raise SystemExit(77)
            diagnostic = result.stdout.decode(errors='replace')
            assert result.returncode != 0 and 'invalid RS256 trust policy' in diagnostic, diagnostic
            checks += 1
        # Trusted client selection is exact and malformed config is 503.
        with gateway(args, root, 'at+jwt', 'another-client') as port:
            actual, _ = request(port, '/read', token(accepted), 'h2')
            assert actual == 403, actual
            checks += 1
        with gateway(args, root, 'at+jwt', 'x' * 1025) as port:
            actual, _ = request(port, '/read', token(accepted), 'h2')
            assert actual == 503, actual
            checks += 1
        for bad_scope in ('', 'orders read', 'orders"read', 'orders\\read'):
            with gateway(args, root, scope=bad_scope) as port:
                actual, _ = request(port, '/read', token(accepted), 'HTTP/1.1')
                assert actual == 503, (bad_scope, actual)
                checks += 1
        with gateway(args, root, revoked_jtis=['revoked']) as port:
            actual, _ = request(port, '/access', token(dict(base, jti='revoked')), 'HTTP/1.1')
            assert actual == 401, actual
            checks += 1
    print(f'PASS: {checks} JWT access-profile checks ({args.backend}, O{args.opt})')


if __name__ == '__main__':
    main()
