#!/usr/bin/env python3
"""Exercise the Casdoor DefaultJWT policy with tokens issued by pinned Casdoor."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from test_casdoor_access import gateway, request

IMAGE = 'casbin/casdoor@sha256:a0499a9e1bc0c089af79f19b16b866432bc9519a495e286ac7c558181c302b2a'
CLIENT = 'fixture-client'
ISSUER = 'http://127.0.0.1:8000'


def docker(*args, check=True):
    return subprocess.run(['docker', *args], check=check, capture_output=True, text=True, timeout=60)


def claims(token):
    payload = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--fixtures', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', type=int, default=2)
    args = parser.parse_args()
    try:
        available = docker('info', check=False)
    except FileNotFoundError:
        raise SystemExit(77)
    if available.returncode:
        raise SystemExit(77)
    name = 'rut-casdoor-' + uuid.uuid4().hex
    fixtures = Path(args.fixtures)
    seed = {
        'organizations': [dict(owner='admin', name='tenant', displayName='Tenant',
                               passwordType='bcrypt', defaultApplication='app', defaultTokenFormat='JWT')],
        'applications': [dict(owner='admin', name='app', displayName='App', organization='tenant',
                              cert='cert', enablePassword=True, clientId=CLIENT, clientSecret='fixture-secret',
                              grantTypes=['password', 'refresh_token'], tokenFormat='JWT', expireInHours=1)],
        'users': [dict(owner='tenant', name='alice', type='normal-user', password='fixture-password',
                       passwordType='plain', displayName='Alice', isAdmin=False,
                       groups=['tenant/staff', 'tenant/billing:read'])],
        'certs': [dict(owner='tenant', name='cert', scope='JWT', type='x509', cryptoAlgorithm='RS256',
                       certificate=(fixtures / 'localhost_cert.pem').read_text(),
                       privateKey=(fixtures / 'localhost_key.pem').read_text())],
    }
    with tempfile.TemporaryDirectory(prefix='rut-casdoor-live-') as directory:
        root = Path(directory)
        seed_file = root / 'seed.json'
        seed_file.write_text(json.dumps(seed))
        try:
            docker('create', '--name', name, '--label', 'rut.test.suite=casdoor-live',
                   '-e', 'driverName=sqlite', '-e', 'dataSourceName=file:/tmp/casdoor.db?cache=shared',
                   '-e', 'initDataFile=/tmp/seed.json', IMAGE)
            docker('cp', str(seed_file), name + ':/tmp/seed.json')
            docker('start', name)
            deadline = time.monotonic() + 60
            while True:
                health = docker('exec', name, 'curl', '-fsS', 'http://127.0.0.1:8000/api/health', check=False)
                if health.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError(docker('logs', name, check=False).stdout)
                time.sleep(.2)
            result = docker('exec', name, 'curl', '-fsS', '-X', 'POST',
                            ISSUER + '/api/login/oauth/access_token', '-d',
                            'grant_type=password&client_id=fixture-client&client_secret=fixture-secret'
                            '&username=alice&password=fixture-password&scope=openid')
            tokens = json.loads(result.stdout)
            access = tokens['access_token']
            payload = claims(access)
            assert payload['iss'] == ISSUER and CLIENT in payload['aud']
            assert payload['owner'] == 'tenant' and payload['tokenType'] == 'access-token'
            assert set(payload['groups']) == {'tenant/staff', 'tenant/billing:read'}
            assert claims(tokens['refresh_token'])['tokenType'] == 'refresh-token'
            jwks = json.loads(docker('exec', name, 'curl', '-fsS', ISSUER + '/.well-known/jwks').stdout)
            key = next(key for key in jwks['keys'] if key['kid'] == 'cert')
            policy = dict(issuer=ISSUER, audience=CLIENT, kids=['cert'],
                          jwks=dict(keys=[{k: key[k] for k in ('kid', 'kty', 'alg', 'n', 'e')}]))
            with gateway(args, root, policy=policy) as port:
                for version in ('HTTP/1.1', 'h2'):
                    for path in ('/access', '/group', '/all', '/any', '/restricted'):
                        assert request(port, path, access, version) == 204, (path, version)
                    for token in (tokens['id_token'], tokens['refresh_token'], None, 'malformed'):
                        assert request(port, '/access', token, version) == 401, version
                    assert request(port, '/access', access, version, True) == 401
                    parts = access.split('.')
                    parts[2] = ('A' if parts[2][0] != 'A' else 'B') + parts[2][1:]
                    assert request(port, '/access', '.'.join(parts), version) == 401
            with gateway(args, root, group='missing', policy=policy) as port:
                assert request(port, '/group', access, 'HTTP/1.1') == 403
                assert request(port, '/all', access, 'h2') == 403
            with gateway(args, root, org='other', policy=policy) as port:
                assert request(port, '/access', access, 'HTTP/1.1') == 401
            with gateway(args, root, forbidden='billing:read', policy=policy) as port:
                assert request(port, '/restricted', access, 'h2') == 403
            with gateway(args, root, policy=dict(policy, audience='wrong-audience')) as port:
                assert request(port, '/access', access, 'HTTP/1.1') == 401
            print('PASS: pinned Casdoor DefaultJWT issuance and policy', args.backend)
        finally:
            docker('rm', '-f', name, check=False)


if __name__ == '__main__':
    main()
