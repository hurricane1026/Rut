#!/usr/bin/env python3
"""Native Keycloak claim authorization with independently signed RS256 tokens."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from auth_h2_fixture import request as h2_request

# Public test-only RSA material from RFC 7515 Appendix A.2. No system crypto CLI
# or extra Python package is used; signing is independent of the Rut verifier.
# https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2
MODULUS = (
    'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx'
    'HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs'
    'D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH'
    'SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV'
    'MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8'
    'NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ')
PRIVATE = (
    'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I'
    'jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0'
    'BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn'
    '439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT'
    'CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh'
    'BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ')
ISSUER = 'https://id.example/realms/shop'
AUDIENCE = 'orders'


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=')


def signed(claims, header=None):
    protected = json.dumps(header or dict(alg='RS256', kid='current', typ='JWT')).encode()
    payload = claims.encode() if isinstance(claims, str) else json.dumps(claims).encode()
    message = encode(protected) + b'.' + encode(payload)
    digest_info = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256(message).digest()
    encoded = b'\x00\x01' + b'\xff' * (256 - len(digest_info) - 3) + b'\x00' + digest_info
    modulus = int.from_bytes(base64.urlsafe_b64decode(MODULUS + '=='), 'big')
    private = int.from_bytes(base64.urlsafe_b64decode(PRIVATE + '=='), 'big')
    signature = pow(int.from_bytes(encoded, 'big'), private, modulus).to_bytes(256, 'big')
    return (message + b'.' + encode(signature)).decode()


@contextmanager
def gateway(args, directory, client='orders', realm='member', role='read'):
    original = Path(args.source).resolve()
    root = directory / str(time.monotonic_ns())
    root.mkdir()
    (root / 'middleware').mkdir()
    for name in ('auth.rut', 'keycloak.rut'):
        shutil.copyfile(original.parent / 'middleware' / name, root / 'middleware' / name)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    source = root / 'auth.rut'
    source.write_text(original.read_text().replace('listen :8080', f'listen :{port}'))
    policy = dict(issuer=ISSUER, audience=AUDIENCE, kids=['current'],
                  jwks=dict(keys=[dict(kid='current', kty='RSA', alg='RS256', n=MODULUS, e='AQAB')]))
    env = dict(os.environ, JWT_RS256_POLICY=json.dumps(policy), KEYCLOAK_CLIENT=client,
               KEYCLOAK_REALM_ROLE=realm, KEYCLOAK_CLIENT_ROLE=role)
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
    # Client metadata never selects a policy, realm, role, audience or bearer.
    fields = [('X-Realm-Role', 'member'), ('X-Client-Role', 'read'),
              ('X-Consumer-ID', 'admin'), ('X-Keycloak-Client', 'admin'), ('X-Scope', 'read')]
    if token is not None:
        fields += [('Authorization', 'Bearer ' + token)] * (2 if duplicate else 1)
    path += '?client=admin&role=read&access_token=spoofed'
    if version == 'h2':
        return h2_request(port, path, fields)[0]
    headers = ''.join(f'{k}: {v}\r\n' for k, v in fields)
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
    base = dict(sub='alice', iss=ISSUER, aud=AUDIENCE, iat=now, exp=now + 600, typ='Bearer')
    roles = dict(realm_access=dict(roles=['member']), resource_access=dict(orders=dict(roles=['read'])))
    valid = dict(base, **roles)
    # Independently specified realm/client/both decisions, not calculated with
    # the implementation's projection or matching algorithm.
    cases = [
        (valid, (204, 204, 204)),
        (dict(base), (403, 403, 403)),
        (dict(base, realm_access=dict(roles=['member'])), (204, 403, 403)),
        (dict(base, resource_access=dict(orders=dict(roles=['read']))), (403, 204, 403)),
        (dict(base, realm_access=dict(roles=['read']), resource_access=dict(orders=dict(roles=['member']))), (403, 403, 403)),
        (dict(base, realm_access=dict(roles=['member']), resource_access=dict(admin=dict(roles=['read']))), (204, 403, 403)),
        (dict(base, groups=['member', 'read'], scope='member read'), (403, 403, 403)),
        (dict(valid, realm_access=dict(roles=['Member'])), (403, 204, 403)),
        (dict(valid, resource_access=dict(orders=dict(roles=['reader']))), (204, 403, 403)),
        (dict(valid, aud='admin', azp='orders'), (401, 401, 401)),
        (dict(valid, iss='https://id.example/realms/other'), (401, 401, 401)),
        (dict(valid, exp=now - 1), (401, 401, 401)),
        (dict(valid, sub=''), (401, 401, 401)),
        (dict(valid, aud=['unrelated', AUDIENCE]), (204, 204, 204)),
        (dict(valid, resource_access=dict(orders=dict(roles=['read', 'read']))), (204, 204, 204)),
    ]
    for kind in ('ID', 'Refresh', 'bearer', '', None, 1):
        cases.append((dict(valid, typ=kind), (401, 401, 401)))
    cases.append(({k: v for k, v in valid.items() if k != 'typ'}, (401, 401, 401)))
    for malformed in ('read', ['read', 1], ['read', ''], [], None, {}, [['read']]):
        cases.append((dict(valid, resource_access=dict(orders=dict(roles=malformed))), (204, 403, 403)))
    for malformed in ('member', ['member', 1], ['member', ''], [], None, {}, [['member']]):
        cases.append((dict(valid, realm_access=dict(roles=malformed)), (403, 204, 403)))
    cases += [(dict(valid, resource_access=[dict(roles=['read'])]), (204, 403, 403)),
              (dict(valid, realm_access=[dict(roles=['member'])]), (403, 204, 403))]
    cases += [(dict(valid, resource_access=dict(orders=[dict(roles=['read'])])), (204, 403, 403)),
              (dict(valid, realm_access=True), (403, 204, 403)),
              (dict(valid, resource_access=dict(orders=None)), (204, 403, 403))]
    duplicate = json.dumps(valid)[:-1] + ',"realm_access":{"roles":["member"]}}'
    cases.append((duplicate, (401, 401, 401)))
    checks = 0
    with tempfile.TemporaryDirectory(prefix='rut-keycloak-roles-') as directory:
        root = Path(directory)
        with gateway(args, root) as port:
            for version in ('HTTP/1.0', 'HTTP/1.1', 'h2'):
                for claims, decisions in cases:
                    credential = signed(claims)
                    for path, expected in zip(('/realm', '/client', '/both'), decisions):
                        actual = request(port, path, credential, version)
                        assert actual == expected, (version, path, claims, actual, expected)
                        checks += 1
                good = signed(valid)
                bad = good[:-5] + ('A' if good[-5] != 'A' else 'B') + good[-4:]
                for credential, duplicate_header in ((None, False), ('malformed', False), (bad, False), (good, True),
                                                       (signed(valid, dict(alg='HS256', kid='current')), False),
                                                       (signed(valid, dict(alg='RS256', kid='unknown')), False)):
                    assert request(port, '/both', credential, version, duplicate_header) == 401
                    checks += 1
        for client, realm, role, expected in (
                ('other', 'member', 'read', 403), ('orders', 'other', 'write', 403),
                ('orders/roles', 'member', 'read', 503), ('~1', 'member', 'read', 503),
                ('orders\n', 'member', 'read', 503), ('orders ', 'member', 'read', 503),
                ('', 'member', 'read', 503), ('x' * 129, 'member', 'read', 503),
                ('orders', '', 'read', 503), ('orders', 'member', 'x' * 129, 503),
                ('0', 'member', 'read', 403)):
            with gateway(args, root, client, realm, role) as port:
                assert request(port, '/both', signed(valid), 'HTTP/1.1') == expected
                assert request(port, '/both', 'malformed', 'HTTP/1.1') == 401
                if client == '0':
                    assert request(port, '/client', signed(dict(valid, resource_access=[dict(roles=['read'])])), 'h2') == 403
                    checks += 1
                checks += 2
        # Maximum accepted byte lengths are usable, without truncating a client
        # pointer or matching a role prefix. Wider configuration already denies.
        with gateway(args, root, 'c' * 128, 'm' * 128, 'r' * 128) as port:
            maximum = dict(base, realm_access=dict(roles=['m' * 128]),
                           resource_access={'c' * 128: dict(roles=['r' * 128])})
            assert request(port, '/both', signed(maximum), 'h2') == 204
            assert request(port, '/both', signed(valid), 'HTTP/1.1') == 403
            checks += 2
    print(f'PASS: {checks} native Keycloak role checks ({args.backend}, O{args.opt})')


if __name__ == '__main__':
    main()
