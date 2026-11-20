#!/usr/bin/env python3
"""Casdoor v4.27.1 DefaultJWT claims adapter with independent RS256 tokens."""
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

ISSUER = 'https://casdoor.example'
AUDIENCE = 'casdoor-api'


@contextmanager
def gateway(args, directory, org='tenant', group='staff', second='billing:read', forbidden='suspended', subject='alice', principal=False):
    original = Path(args.source).resolve()
    root = directory / str(time.monotonic_ns())
    root.mkdir()
    (root / 'middleware').mkdir()
    for name in ('auth.rut', 'casdoor.rut'):
        shutil.copyfile(original.parent / 'middleware' / name, root / 'middleware' / name)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    source = root / 'gateway.rut'
    program = original.read_text()
    if principal:
        program = program[:program.index('route GET "/access"')] + \
            'route GET "/principal" {\n' + \
            '    let document = verifyRs256(req.authorization.or(""), env("JWT_RS256_POLICY"))\n' + \
            '    let principal = casdoor.requirePrincipal(document, env("CASDOOR_ORG"), env("CASDOOR_SUBJECT"))\n' + \
            '    guard json.string(json.get(principal, "/owner").or(principal)).or("") == env("CASDOOR_ORG") else { return 403 }\n' + \
            '    return 204\n}\n'
    source.write_text(program.replace('listen :8080', f'listen :{port}'))
    policy = dict(issuer=ISSUER, audience=AUDIENCE, kids=['current'],
                  jwks=dict(keys=[dict(kid='current', kty='RSA', alg='RS256', n=MODULUS, e='AQAB')]))
    env = dict(os.environ, JWT_RS256_POLICY=json.dumps(policy), CASDOOR_ORG=org,
               CASDOOR_GROUP=group, CASDOOR_SECOND_GROUP=second, CASDOOR_FORBIDDEN_GROUP=forbidden,
               CASDOOR_SUBJECT=subject)
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


def request(port, path, token, version, duplicate=False):
    fields = [('X-Casdoor-Owner', 'tenant'), ('X-Groups', 'tenant/staff'),
              ('X-Role', 'admin'), ('X-Scope', 'staff')]
    if token is not None:
        fields += [('Authorization', 'Bearer ' + token)] * (2 if duplicate else 1)
    path += '?owner=attacker&group=admin&scope=staff'
    if version == 'h2':
        return h2_request(port, path, fields)[0]
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
    return int(data.split(b' ', 2)[1])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    args = parser.parse_args()
    now = int(time.time())
    base = dict(sub='alice', iss=ISSUER, aud=AUDIENCE, iat=now, exp=now + 600,
                owner='tenant', tokenType='access-token')
    accepted = dict(base, groups=['tenant/staff', 'tenant/billing:read'])
    no_groups = dict(base, groups=[])
    cases = [
        (accepted, (204, 204, 204)),
        (dict(base, groups=['tenant/staff']), (204, 204, 403)),
        (no_groups, (204, 403, 403)),
        (dict(accepted, owner='other'), (401, 401, 401)),
        (dict(accepted, owner='tenant-extra'), (401, 401, 401)),
        (dict(accepted, groups=['tenant/staff-extra', 'tenant/billing:read-more']), (204, 403, 403)),
        (dict(accepted, groups=['Tenant/staff', 'tenant/Billing:read']), (204, 403, 403)),
        (dict(accepted, groups=['staff', 'billing:read']), (204, 403, 403)),
        (dict(accepted, groups=['tenant/staff', 'tenant/staff/billing:read']), (204, 204, 403)),
        (dict(accepted, groups=['tenant/staff', 1]), (204, 403, 403)),
        (dict(accepted, groups=['tenant/staff', '']), (204, 403, 403)),
        (dict(accepted, groups='tenant/staff'), (204, 403, 403)),
        (dict(accepted, groups=[['tenant/staff']]), (204, 403, 403)),
        (dict(accepted, groups=None), (204, 403, 403)),
        ({key: value for key, value in base.items() if key != 'groups'}, (204, 403, 403)),
        (dict(base, groups=[], roles=['tenant/staff'], scope='tenant/staff'), (204, 403, 403)),
        (dict(accepted, groups=['tenant/billing:read', 'tenant/staff']), (204, 204, 204)),
        (dict(accepted, groups=['tenant/staff', 'tenant/billing:read', 'tenant/billing:read']), (204, 204, 204)),
        (dict(accepted, scope='tenant/staff', roles=['admin']), (204, 204, 204)),
        (dict(accepted, aud='admin', azp='orders'), (401, 401, 401)),
        (dict(accepted, aud=['other', AUDIENCE]), (204, 204, 204)),
        (dict(accepted, iss='https://id.example/other'), (401, 401, 401)),
        (dict(accepted, exp=now - 1), (401, 401, 401)),
        (dict(accepted, nbf=now + 600), (401, 401, 401)),
        (dict(accepted, sub=''), (401, 401, 401)),
        (dict(accepted, owner=1), (401, 401, 401)),
        ({key: value for key, value in accepted.items() if key != 'owner'}, (401, 401, 401)),
    ]
    for kind in ('id-token', 'refresh-token', 'Access-token', '', None, 1):
        cases.append((dict(accepted, tokenType=kind), (401, 401, 401)))
    cases.append(({key: value for key, value in accepted.items() if key != 'tokenType'}, (401, 401, 401)))
    duplicate = json.dumps(accepted)[:-1] + ',"owner":"tenant"}'
    cases.append((duplicate, (401, 401, 401)))
    with tempfile.TemporaryDirectory(prefix='rut-casdoor-access-') as directory:
        root = Path(directory)
        checks = 0
        with gateway(args, root) as port:
            for version in ('HTTP/1.0', 'HTTP/1.1', 'h2'):
                for claims, expected in cases:
                    token = signed(claims)
                    for path, status in zip(('/access', '/group', '/all'), expected):
                        actual = request(port, path, token, version)
                        assert actual == status, (version, path, claims, actual, status)
                        checks += 1
                for claims, any_status, restricted in (
                        (accepted, 204, 204),
                        (dict(base, groups=['tenant/billing:read']), 204, 403),
                        (dict(base, groups=['tenant/staff', 'tenant/suspended']), 204, 403),
                        (dict(base, groups=['tenant/suspended', 'tenant/staff']), 204, 403),
                        (dict(base, groups=['tenant/staff', 'other/suspended']), 204, 204),
                        (dict(base, groups=['tenant/staff', 'tenant/suspended-extra']), 204, 204),
                        (dict(base, groups=['tenant/staff', 7]), 403, 403),
                        (dict(base, groups=['other/staff', 'other/billing:read']), 403, 403),
                        (dict(base, groups=['tenant/suspended']), 403, 403),
                        (dict(base, owner='other', groups=['tenant/staff']), 401, 401),
                        (dict(base, tokenType='refresh-token', groups=['tenant/staff']), 401, 401),
                        (base, 403, 403)):
                    token = signed(claims)
                    assert request(port, '/any', token, version) == any_status
                    assert request(port, '/restricted', token, version) == restricted
                    checks += 2
                valid = signed(accepted)
                bad = valid[:-5] + ('A' if valid[-5] != 'A' else 'B') + valid[-4:]
                for token, duplicate_header, header in (
                        (None, False, None), ('malformed', False, None), (bad, False, None),
                        (valid, True, None), (signed(accepted, dict(alg='HS256', kid='current')), False, None),
                        (signed(accepted, dict(alg='RS256', kid='unknown')), False, None),
                        (valid, False, dict(alg='RS256', kid='current', crit=['bad']))):
                    credential = token if header is None else signed(accepted, header)
                    assert request(port, '/all', credential, version, duplicate_header) == 401
                    checks += 1
        for org, group, second, path, expected in (
                ('other', 'staff', 'billing:read', '/group', 401),
                ('tenant/', 'staff', 'billing:read', '/group', 503),
                ('tenant', 'staff/child', 'billing:read', '/group', 503),
                ('tenant', '', 'billing:read', '/group', 503),
                ('tenant', 'x' * 129, 'billing:read', '/group', 503),
                ('tenant', 'staff', 'bad group', '/all', 503),
                ('x' * 129, 'staff', 'billing:read', '/group', 503)):
            with gateway(args, root, org, group, second) as port:
                assert request(port, path, signed(accepted), 'HTTP/1.1') == expected
                assert request(port, path, 'malformed', 'HTTP/1.1') == 401
                if path == '/group' and group == 'staff/child':
                    assert request(port, path, signed(dict(accepted, tokenType='id-token')), 'HTTP/1.1') == 503
                    checks += 1
                checks += 2
        with gateway(args, root, second='bad/group', forbidden='staff') as port:
            assert request(port, '/any', signed(accepted), 'HTTP/1.1') == 503
            assert request(port, '/restricted', signed(accepted), 'h2') == 503
            checks += 2
        with gateway(args, root, principal=True) as port:
            for version in ('HTTP/1.0', 'HTTP/1.1', 'h2'):
                for claims, status in ((accepted, 204), (dict(accepted, sub='Alice'), 401),
                                   (dict(accepted, sub='alice-extra'), 401),
                                   (dict(accepted, sub='bob', name='alice'), 401),
                                   (dict(accepted, owner='other'), 401),
                                   (dict(accepted, tokenType='refresh-token'), 401),
                                   (dict(accepted, aud='other'), 401),
                                   (dict(accepted, groups=[]), 204)):
                    assert request(port, '/principal', signed(claims), version) == status, (claims, version, status)
                    checks += 1
        for subject in ('', 'x' * 129):
            with gateway(args, root, subject=subject, principal=True) as port:
                assert request(port, '/principal', signed(accepted), 'h2') == 503
                assert request(port, '/principal', 'malformed', 'HTTP/1.1') == 401
                checks += 2
        with gateway(args, root, subject='s' * 128, principal=True) as port:
            assert request(port, '/principal', signed(dict(accepted, sub='s' * 128)), 'h2') == 204
            checks += 1
        # Organization selection is trusted configuration, not a request value.
        with gateway(args, root, 'tenant-other') as port:
            assert request(port, '/group', signed(accepted), 'h2') == 401
            checks += 1
    print(f'PASS: {checks} Casdoor DefaultJWT checks ({args.backend}, O{args.opt})')


if __name__ == '__main__':
    main()
