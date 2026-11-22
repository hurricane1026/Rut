#!/usr/bin/env python3
"""Verify the embedded refresh transition and the native TLS gateway."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import select
import shutil
import ssl
import subprocess
import tempfile
import time

from test_auth_replay_durable import DurableStore
from test_jwt_sessions import KEY, signed

NAMESPACE = 'refresh:fixture'
FAMILY = NAMESPACE.encode() + b':' + hashlib.sha256(b'alice').hexdigest().encode()


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest().encode()


def credential(**overrides):
    now = int(time.time())
    claims = dict(sub='alice', iss='issuer', aud='refresh', iat=now, exp=now + 300,
                  jti='initial', scope='refresh')
    return signed(dict(claims, **overrides))


def authorize_store(store):
    assert store.command(b'ACL', b'SETUSER', b'gateway', b'resetkeys',
                         b'~' + NAMESPACE.encode() + b':*', b'+eval', b'+get', b'+pttl', b'+set') == b'OK'


@contextmanager
def gateway(args, store):
    certs = Path(args.testdata).resolve()
    cert = certs / 'localhost_cert.pem'
    with tempfile.TemporaryDirectory(prefix='rut-refresh-family-') as directory:
        root = Path(directory)
        source = Path(args.source).resolve()
        shutil.copytree(source.parent / 'clients', root / 'clients')
        shutil.copytree(source.parent / 'middleware', root / 'middleware')
        path = root / 'refresh.rut'
        shutil.copyfile(source, path)
        endpoint = dict(address='127.0.0.1', port=store.port, poolIdleMs=5000)
        if args.tls:
            endpoint.update(tls=True, caFile=str(cert), serverName='localhost')
        env = dict(os.environ, REFRESH_SECRET=KEY, REFRESH_ISSUER='issuer',
                   REFRESH_AUDIENCE='refresh', REFRESH_SUBJECT='alice',
                   REFRESH_NAMESPACE=NAMESPACE, REDIS_ENDPOINT=json.dumps(endpoint),
                   REDIS_USERNAME='gateway', REDIS_PASSWORD='service-password',
                   REDIS_DATABASE='1')
        process = subprocess.Popen(
            [args.server, '0', str(path), '--backend', args.backend, '--opt', str(args.opt),
             '--no-pin', '--shards', '2', '--drain', '0', '--tls-cert', str(cert),
             '--tls-key', str(certs / 'localhost_key.pem')],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = b''
        try:
            deadline = time.monotonic() + 120
            while process.poll() is None and time.monotonic() < deadline:
                if select.select([process.stdout], [], [], .05)[0]:
                    output += process.stdout.read1(4096)
                    if match := re.search(rb'Listening on port ([0-9]+) with', output):
                        break
            else:
                if b'io_uring is unavailable' in output:
                    raise SystemExit(77)
                raise AssertionError(output.decode(errors='replace'))
            port = int(match.group(1))
            context = ssl.create_default_context(cafile=str(cert))

            def refresh(value, duplicate=False, path="/refresh"):
                connection = http.client.HTTPSConnection('localhost', port, context=context, timeout=10)
                try:
                    connection.putrequest('POST', path)
                    connection.putheader('Authorization', 'Bearer ' + value)
                    if duplicate:
                        connection.putheader('Authorization', 'Bearer ' + value)
                    connection.putheader('Content-Length', '0')
                    connection.endheaders()
                    response = connection.getresponse()
                    return response.status, response.read().decode(), response.getheader('Cache-Control')
                finally:
                    connection.close()

            yield refresh
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                output += process.communicate(timeout=10)[0]
            except subprocess.TimeoutExpired:
                process.kill()
                output += process.communicate()[0]
            assert KEY.encode() not in output and b'service-password' not in output


def exercise_script(store, script):
    key, a, b, c = b'family:test', b'a' * 64, b'b' * 64, b'c' * 64

    def transition(old, new):
        return store.command(b'EVAL', script, b'1', key, old, new)

    assert transition(a, b) == 0
    assert store.command(b'SET', key, b'v1:' + a, b'PX', b'60000') == b'OK'
    original = store.command(b'PTTL', key)
    assert transition(a, b) == 1
    assert store.command(b'GET', key) == b'v1:' + b
    assert 0 < store.command(b'PTTL', key) <= original
    assert transition(a, c) == 2
    assert store.command(b'GET', key) == b'revoked'
    assert 0 < store.command(b'PTTL', key) <= original
    assert transition(b, c) == 0
    assert store.command(b'SET', key, b'v1:' + a) == b'OK'
    assert transition(a, b) == -1
    assert store.command(b'GET', key) == b'v1:' + a
    assert store.command(b'SET', key, b'corrupt', b'PX', b'60000') == b'OK'
    assert transition(a, b) == -1
    assert store.command(b'GET', key) == b'corrupt'
    assert store.command(b'SET', key, b'v1:' + a, b'PX', b'60000') == b'OK'
    assert transition(a, a) == -1
    assert transition(b'X' * 64, b) == -1
    assert store.command(b'GET', key) == b'v1:' + a
    assert store.command(b'PEXPIRE', key, b'1') == 1
    time.sleep(.02)
    assert transition(a, b) == 0
    assert store.command(b'GET', key) is None


def exercise_gateway(args, store):
    authorize_store(store)
    with gateway(args, store) as refresh:
        initial = credential()
        assert refresh(initial)[0] == 401
        assert store.command(b'SET', FAMILY, b'v1:' + digest(initial), b'PX', b'60000') == b'OK'
        for rejected in (initial + 'x', credential(sub='bob'), credential(aud='access'),
                         credential(scope='access'), credential(exp=int(time.time()) - 1)):
            assert refresh(rejected)[0] == 401
        assert refresh(initial, duplicate=True)[0] == 401
        assert store.command(b'GET', FAMILY) == b'v1:' + digest(initial)
        before = store.command(b'PTTL', FAMILY)
        status, next_token, cache = refresh(initial)
        assert status == 200 and next_token != initial and cache == 'no-store'
        assert store.command(b'GET', FAMILY) == b'v1:' + digest(next_token)
        assert 0 < store.command(b'PTTL', FAMILY) <= before

        store.kill()
        outage = refresh(next_token)
        assert outage[0] == 503 and next_token not in outage[1], outage
        store.start()
        authorize_store(store)
        assert store.command(b'GET', FAMILY) == b'v1:' + digest(next_token)

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(refresh, (next_token, next_token)))
        assert sorted(result[0] for result in results) == [200, 401]
        assert store.command(b'GET', FAMILY) == b'revoked'
        assert 0 < store.command(b'PTTL', FAMILY) <= before
        newest = next(result[1] for result in results if result[0] == 200)
        assert refresh(newest)[0] == 401

        logout_path = "/refresh/logout"
        current = credential(jti="logout")
        assert store.command(b'SET', FAMILY, b'v1:' + digest(current), b'PX', b'60000') == b'OK'
        for rejected in (current + 'x', credential(sub='bob'), credential(aud='access')):
            assert refresh(rejected, path=logout_path)[0] == 401
        assert refresh(current, duplicate=True, path=logout_path)[0] == 401
        assert store.command(b'GET', FAMILY) == b'v1:' + digest(current)
        before = store.command(b'PTTL', FAMILY)
        assert refresh(current, path=logout_path) == (204, '', 'no-store')
        assert refresh(current, path=logout_path) == (204, '', 'no-store')
        assert store.command(b'GET', FAMILY) == b'revoked'
        assert 0 < store.command(b'PTTL', FAMILY) <= before
        assert refresh(current)[0] == 401

        store.kill()
        store.start()
        authorize_store(store)
        assert store.command(b'GET', FAMILY) == b'revoked'
        assert refresh(current)[0] == 401
        assert store.command(b'DEL', FAMILY) == 1
        assert refresh(current, path=logout_path) == (204, '', 'no-store')
        assert store.command(b'GET', FAMILY) is None
        assert store.command(b'SET', FAMILY, b'bad-record', b'PX', b'60000') == b'OK'
        assert refresh(current, path=logout_path)[0] == 503
        assert store.command(b'GET', FAMILY) == b'bad-record'

        assert store.command(b'SET', FAMILY, b'v1:' + digest(current), b'PX', b'60000') == b'OK'
        with ThreadPoolExecutor(max_workers=2) as workers:
            rotating = workers.submit(refresh, current)
            revoking = workers.submit(refresh, current, path=logout_path)
            rotation = rotating.result()
            assert revoking.result() == (204, '', 'no-store')
        assert rotation[0] in (200, 401)
        assert store.command(b'GET', FAMILY) == b'revoked'
        if rotation[0] == 200:
            assert refresh(rotation[1])[0] == 401

        replacement = credential(jti='uncertain')
        assert store.command(b'SET', FAMILY, b'v1:' + digest(replacement), b'PX', b'60000') == b'OK'
        assert store.command(b'ACL', b'SETUSER', b'gateway', b'-waitaof') == b'OK'
        uncertain = refresh(replacement)
        assert uncertain[0] == 503 and replacement not in uncertain[1], uncertain
        changed = store.command(b'GET', FAMILY)
        assert changed.startswith(b'v1:') and changed != b'v1:' + digest(replacement)
        assert refresh(replacement, path=logout_path)[0] == 503
        assert store.command(b'GET', FAMILY) == b'revoked'



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', type=int, choices=(0, 2), default=2)
    parser.add_argument('--tls', action='store_true', help='use TLS for the Redis link')
    args = parser.parse_args()
    if not shutil.which('docker') or subprocess.run(
            ['docker', 'info', '--format', '{{.ServerVersion}}'],
            capture_output=True, timeout=15).returncode:
        return 77
    source = Path(args.source).read_text()
    literal = re.search(r'func redisRefreshFamilyScript\(\) -> Bytes \{\s+Bytes\((".*")\)', source)
    assert literal
    script = json.loads(literal.group(1)).encode()
    store = DurableStore(args)
    try:
        exercise_script(store, script)
        exercise_gateway(args, store)
    finally:
        store.close()
    print(f'PASS: authenticated atomic refresh-family rotation ({args.backend}, O{args.opt})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
