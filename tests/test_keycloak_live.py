#!/usr/bin/env python3
"""Run the Rut resource-server profile with tokens issued by pinned Keycloak."""
import argparse
import base64
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

from test_keycloak_roles import gateway, request

IMAGE = ('quay.io/keycloak/keycloak:26.2.5'
         '@sha256:4883630ef9db14031cde3e60700c9a9a8eaf1b5c24db1589d6a2d43de38ba2a9')
HOSTNAME = 'https://id.example'
PASSWORD = 'local-testing-only'
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def realm(name):
    clients = [dict(clientId='orders', protocol='openid-connect', enabled=True,
                    standardFlowEnabled=False)]
    for client, audience in [('storefront', 'orders'), ('other', 'other-resource')]:
        clients.append(dict(
            clientId=client, protocol='openid-connect', enabled=True, publicClient=True,
            standardFlowEnabled=False, directAccessGrantsEnabled=True, fullScopeAllowed=True,
            protocolMappers=[dict(
                name='test-resource', protocol='openid-connect', protocolMapper='oidc-audience-mapper',
                config={'included.custom.audience': audience, 'access.token.claim': 'true'})]))
    users = []
    for user, roles, client_roles in [('alice', ['member'], {'orders': ['read']}),
                                      ('realm-only', ['member'], {})]:
        users.append(dict(username=user, firstName='Test', lastName='Fixture',
                          email=user + '@example.test', enabled=True, emailVerified=True,
                          credentials=[dict(type='password', value=PASSWORD, temporary=False)],
                          realmRoles=roles, clientRoles=client_roles))
    return dict(realm=name, enabled=True, sslRequired='none', clients=clients, users=users,
                roles=dict(realm=[dict(name='member')], client={'orders': [dict(name='read')]}))


def docker(*args):
    result = subprocess.run(['docker', *args], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=180)
    assert result.returncode == 0, result.stdout
    return result.stdout.strip()


def payload(token, segment=1):
    part = token.split('.')[segment]
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))


def get_json(url, form=None):
    body = urllib.parse.urlencode(form).encode() if form else None
    with OPENER.open(urllib.request.Request(url, data=body), timeout=3) as response:
        return json.load(response)


@contextmanager
def provider(root):
    name = 'rut-keycloak-' + uuid.uuid4().hex
    fixtures = root / 'import'
    fixtures.mkdir(mode=0o755)
    for fixture in ('shop', 'other-shop'):
        file = fixtures / (fixture + '-realm.json')
        file.write_text(json.dumps(realm(fixture)))
        file.chmod(0o644)
    try:
        docker('create', '--name', name, '--label', 'rut.test.suite=keycloak',
               '-p', '127.0.0.1::8080', IMAGE, 'start-dev', '--import-realm',
               '--hostname', HOSTNAME)
        docker('cp', str(fixtures), name + ':/opt/keycloak/data/import')
        docker('start', name)
        port = int(docker('port', name, '8080/tcp').rsplit(':', 1)[1])
        base = f'http://127.0.0.1:{port}'
        deadline = time.monotonic() + 120
        while True:
            try:
                get_json(base + '/realms/shop/.well-known/openid-configuration')
                break
            except OSError:
                if time.monotonic() >= deadline or docker('inspect', '-f', '{{.State.Running}}', name) != 'true':
                    raise AssertionError(docker('logs', name))
                time.sleep(.25)
        yield base
    finally:
        subprocess.run(['docker', 'rm', '-fv', name], capture_output=True, timeout=30)


def grant(base, user='alice', client='storefront', fixture='shop'):
    return get_json(base + f'/realms/{fixture}/protocol/openid-connect/token',
                    dict(grant_type='password', client_id=client, username=user,
                         password=PASSWORD, scope='openid'))


def check_gateway(args, root, base):
    alice = grant(base)
    good = alice['access_token']
    other = grant(base, fixture='other-shop')['access_token']
    realm_only = grant(base, user='realm-only')['access_token']
    wrong_audience = grant(base, user='realm-only', client='other')['access_token']
    assert payload(good)['iss'] == HOSTNAME + '/realms/shop'
    assert payload(other)['iss'] == HOSTNAME + '/realms/other-shop'
    assert 'orders' not in payload(wrong_audience).get('aud', [])
    signing = get_json(base + '/realms/shop/protocol/openid-connect/certs')
    kid = payload(good, 0)['kid']
    key = next(key for key in signing['keys'] if key['kid'] == kid and key['alg'] == 'RS256')
    # Pin a trusted issuer and its public key, as an operator would before
    # starting Rut. This fixture does not configure remote JWKS.
    public = {field: key[field] for field in ('kid', 'kty', 'alg', 'n', 'e')}
    policy = dict(issuer=HOSTNAME + '/realms/shop', audience='orders', kids=[kid],
                  jwks=dict(keys=[public]))
    with gateway(args, root, subject=payload(good)['sub'], policy=policy) as port:
        for version in ('HTTP/1.1', 'h2'):
            for route in ('/realm', '/client', '/both', '/party', '/subject'):
                assert request(port, route, good, version) == 204, (version, route)
            assert request(port, '/realm', realm_only, version) == 204
            assert request(port, '/client', realm_only, version) == 403
            assert request(port, '/both', realm_only, version) == 403
            for invalid in (wrong_audience, other, alice['id_token'], alice['refresh_token']):
                assert request(port, '/realm', invalid, version) == 401


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    args = parser.parse_args()
    if not shutil.which('docker') or subprocess.run(
            ['docker', 'info', '--format', '{{.ServerVersion}}'], capture_output=True, timeout=15).returncode:
        return 77
    with tempfile.TemporaryDirectory(prefix='rut-keycloak-live-') as directory:
        root = Path(directory)
        with provider(root) as base:
            check_gateway(args, root, base)
    print(f'PASS: Keycloak 26.2.5 live access-token profile ({args.backend}, O{args.opt})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
