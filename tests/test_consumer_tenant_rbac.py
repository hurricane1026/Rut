#!/usr/bin/env python3
"""Native verified Consumer-to-tenant binding followed by RBAC, H1 and H2."""
import argparse
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from auth_h2_fixture import request as h2_request


def registry(groups_by_id):
    consumers = [dict(id=cid, enabled=True, groups=groups) for cid, groups in groups_by_id.items()]
    credentials = [dict(id='max-key' if len(cid) == 64 else f'{cid}-key', consumerId=cid,
                        method='bearer', secret='max-secret' if len(cid) == 64 else f'{cid}-secret',
                        enabled=True) for cid in groups_by_id]
    return dict(version=1, consumers=consumers, credentials=credentials)


INVALID_ROUTES = r'''
route GET "/test-duplicate" {
    guard let identity = consumerAuthenticate(req.authorization.or(""), env("AUTH_REGISTRY"), "bearer") else { return 401 }
    let bound = rbac.requireTenant(identity, "acme",
        rbac.TenantBinding(consumerId: "alice", tenant: "acme"),
        rbac.TenantBinding(consumerId: "", tenant: ""), rbac.TenantBinding(consumerId: "", tenant: ""),
        rbac.TenantBinding(consumerId: "alice", tenant: "other"))
    return response(200, body: "ok")
}
route GET "/test-partial" {
    guard let identity = consumerAuthenticate(req.authorization.or(""), env("AUTH_REGISTRY"), "bearer") else { return 401 }
    let bound = rbac.requireTenant(identity, "acme",
        rbac.TenantBinding(consumerId: "alice", tenant: "acme"),
        rbac.TenantBinding(consumerId: "", tenant: "other"), rbac.TenantBinding(consumerId: "", tenant: ""),
        rbac.TenantBinding(consumerId: "", tenant: ""))
    return response(200, body: "ok")
}
route GET "/test-later-invalid" {
    guard let identity = consumerAuthenticate(req.authorization.or(""), env("AUTH_REGISTRY"), "bearer") else { return 401 }
    let bound = rbac.requireTenant(identity, "acme",
        rbac.TenantBinding(consumerId: "alice", tenant: "acme"),
        rbac.TenantBinding(consumerId: "", tenant: ""), rbac.TenantBinding(consumerId: "bad id", tenant: "other"),
        rbac.TenantBinding(consumerId: "", tenant: ""))
    return response(200, body: "ok")
}
route GET "/test-empty" {
    guard let identity = consumerAuthenticate(req.authorization.or(""), env("AUTH_REGISTRY"), "bearer") else { return 401 }
    let bound = rbac.requireTenant(identity, "acme",
        rbac.TenantBinding(consumerId: "", tenant: ""), rbac.TenantBinding(consumerId: "", tenant: ""),
        rbac.TenantBinding(consumerId: "", tenant: ""), rbac.TenantBinding(consumerId: "", tenant: ""))
    return response(200, body: "ok")
}
route GET "/test-malformed-identity" {
    guard let identity = json.parse("\"alice\"") else { return 503 }
    let bound = rbac.requireTenant(identity, "acme",
        rbac.TenantBinding(consumerId: "alice", tenant: "acme"), rbac.TenantBinding(consumerId: "", tenant: ""),
        rbac.TenantBinding(consumerId: "", tenant: ""), rbac.TenantBinding(consumerId: "", tenant: ""))
    return response(200, body: "ok")
}
'''

BOUNDARY_ROUTE = r'''
route GET "/test-boundary" {
    guard let identity = consumerAuthenticate(req.authorization.or(""), env("AUTH_REGISTRY"), "bearer") else { return 401 }
    let bound = rbac.requireTenant(identity, "SELECTOR",
        rbac.TenantBinding(consumerId: "CONSUMER", tenant: "BINDING"),
        rbac.TenantBinding(consumerId: "", tenant: ""), rbac.TenantBinding(consumerId: "", tenant: ""),
        rbac.TenantBinding(consumerId: "", tenant: ""))
    return response(200, body: "ok")
}
'''


@contextmanager
def gateway(args, groups, snapshot_variant=False, invalid_routes=False, boundary_mode=None,
            duplicate_same=False, malformed_mode=None):
    with tempfile.TemporaryDirectory(prefix='rut-consumer-tenant-rbac-') as temporary:
        root = Path(temporary)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        source = root / 'tenant-rbac.rut'
        program = Path(args.source).read_text().replace('listen :8080', f'listen :{port}')
        if snapshot_variant:
            program = program.replace('TenantBinding(consumerId: "alice", tenant: "acme")',
                                      'TenantBinding(consumerId: "alice", tenant: "other")')
        if invalid_routes:
            program += INVALID_ROUTES
        if duplicate_same:
            program = program.replace('TenantBinding(consumerId: "alice", tenant: "other")',
                                      'TenantBinding(consumerId: "alice", tenant: "acme")')
        if malformed_mode:
            malformed = {'missing': 'json.parse("{}")',
                         'wrong-type': 'json.parse("{\\"consumerId\\":7}")'}[malformed_mode]
            program = program.replace(r'json.parse("\"alice\"")', malformed)
        if boundary_mode:
            selector, consumer, binding = {
                'maximum': ('t' * 128, 'c' * 64, 't' * 128),
                'long-selector': ('t' * 129, 'alice', 'acme'),
                'long-binding': ('acme', 'alice', 't' * 129),
                'long-id': ('acme', 'c' * 65, 'acme'),
                'empty-selector': ('', 'alice', 'acme'),
            }[boundary_mode]
            program += BOUNDARY_ROUTE.replace('SELECTOR', selector).replace('CONSUMER', consumer).replace('BINDING', binding)
        source.write_text(program)
        middleware = root / 'middleware'
        middleware.mkdir()
        for name in ('auth.rut', 'rbac.rut'):
            (middleware / name).write_bytes((Path(args.source).parent / 'middleware' / name).read_bytes())
        log = root / 'gateway.log'
        with log.open('w') as output:
            process = subprocess.Popen([args.server, str(source), '--backend', args.backend, '--opt', str(args.opt),
                                        '--no-pin', '--shards', '2', '--drain', '0'],
                env=dict(os.environ, AUTH_REGISTRY=json.dumps(registry(groups))),
                stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while True:
                if process.poll() is not None:
                    data = log.read_text()
                    if args.backend == 'io_uring' and 'io_uring is unavailable' in data:
                        raise SystemExit(77)
                    raise AssertionError(data)
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, log.read_text()
                    time.sleep(.025)
            source.unlink()
            (middleware / 'auth.rut').unlink()
            (middleware / 'rbac.rut').unlink()
            yield port
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            assert 'alice-secret' not in log.read_text()


def request_h1(port, path, token, method='GET'):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        connection.putrequest(method, path)
        connection.putheader('X-Consumer-ID', 'alice')
        connection.putheader('X-Groups', 'invoice-admin')
        if token is not None:
            connection.putheader('Authorization', 'Bearer ' + token)
        connection.endheaders()
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def request_h2(port, path, token, method='GET'):
    fields = [('x-consumer-id', 'alice'), ('x-groups', 'invoice-admin')]
    if token is not None:
        tokens = list(token) if isinstance(token, tuple) else [token]
        fields.extend(('authorization', 'Bearer ' + value) for value in tokens)
    return h2_request(port, path, fields, method=method)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), default='2')
    args = parser.parse_args()
    max_id = 'c' * 64
    groups = {'alice': ['invoice-reader'], 'bob': ['invoice-reader'],
              'mallory': ['invoice-reader'], max_id: ['invoice-reader']}
    acme, other, delete = ('/tenant/acme/invoices/read', '/tenant/other/invoices/read',
                           '/tenant/acme/invoices')
    for context_groups, vectors in (
        (groups, [(acme, 'alice', 200, b'alice'), (acme, 'bob', 403, b''),
                  (other, 'bob', 200, b'bob'), (other, 'alice', 403, b''),
                  (acme, 'mallory', 403, b''), (delete, 'alice', 403, b'')]),
        ({'alice': ['invoice-reader', 'suspended'], 'bob': ['invoice-reader'],
          'mallory': ['invoice-reader']}, [(acme, 'alice', 403, b''), (other, 'alice', 403, b'')]),
        ({'alice': [], 'bob': ['invoice-reader'], 'mallory': ['invoice-reader']},
         [(acme, 'alice', 403, b'')]),
        ({'alice': ['invoice-admin'], 'bob': ['invoice-admin'], 'mallory': []},
         [(delete, 'alice', 200, b'alice'), (delete, 'bob', 403, b'')]),
        ({'alice': ['invoice-admin', 'suspended'], 'bob': ['invoice-admin'], 'mallory': []},
         [(delete, 'alice', 403, b'')]),
    ):
        with gateway(args, context_groups, invalid_routes=True) as port:
            for request in (request_h1, request_h2):
                for path, consumer, status, body in vectors:
                    method = 'DELETE' if path == delete else 'GET'
                    actual = request(port, path, f'{consumer}-secret', method)
                    assert actual[0] == status and (status != 200 or actual[1] == body), (
                        args.backend, request.__name__, consumer, path, actual, status, body)
                assert request(port, acme, None)[0] == 401
                assert request(port, acme, 'wrong-secret')[0] == 401
                for path in ('/test-duplicate', '/test-partial', '/test-later-invalid',
                             '/test-empty'):
                    assert request(port, path, 'alice-secret')[0] == 503, (args.backend, path)
                assert request(port, '/test-malformed-identity', 'alice-secret')[0] == 403
                assert request(port, '/test-later-invalid', None)[0] == 401
                if request is request_h1:
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    connection.putrequest('GET', acme)
                    connection.putheader('Authorization', 'Bearer alice-secret')
                    connection.putheader('Authorization', 'Bearer alice-secret')
                    connection.endheaders()
                    duplicate_response = connection.getresponse()
                    assert duplicate_response.status == 401
                    duplicate_response.read()
                    connection.close()
                else:
                    assert request(port, acme, ('alice-secret', 'alice-secret'))[0] == 401
    with gateway(args, groups, invalid_routes=True, duplicate_same=True) as port:
        for request in (request_h1, request_h2):
            assert request(port, '/test-duplicate', 'alice-secret')[0] == 503
    for malformed_mode in ('missing', 'wrong-type'):
        with gateway(args, groups, invalid_routes=True, malformed_mode=malformed_mode) as port:
            for request in (request_h1, request_h2):
                assert request(port, '/test-malformed-identity', 'alice-secret')[0] == 403
    for mode in ('maximum', 'long-selector', 'long-binding', 'long-id', 'empty-selector'):
        with gateway(args, groups, boundary_mode=mode) as port:
            expected = 200 if mode == 'maximum' else 503
            token = 'max-secret' if mode == 'maximum' else 'alice-secret'
            expected_body = b'ok' if mode == 'maximum' else b''
            for request in (request_h1, request_h2):
                actual = request(port, '/test-boundary', token)
                assert actual[0] == expected and (expected != 200 or actual[1] == expected_body), (
                    args.backend, mode, request.__name__, actual)
    with gateway(args, groups) as old:
        assert request_h1(old, acme, 'alice-secret') == (200, b'alice')
        assert request_h2(old, acme, 'alice-secret') == (200, b'alice')
        with gateway(args, groups, snapshot_variant=True) as new:
            assert request_h1(old, acme, 'alice-secret') == (200, b'alice')
            assert request_h2(old, acme, 'alice-secret') == (200, b'alice')
            assert request_h1(new, acme, 'alice-secret')[0] == 403
            assert request_h2(new, acme, 'alice-secret')[0] == 403
            assert request_h1(new, other, 'alice-secret') == (200, b'alice')
    print(f'PASS consumer tenant binding {args.backend}: exact verified IDs, tenant RBAC, invalid snapshots, H1/H2, source/module unlink')


if __name__ == '__main__':
    main()
