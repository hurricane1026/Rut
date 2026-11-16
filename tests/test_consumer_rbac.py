#!/usr/bin/env python3
"""Native Consumer group to exact resource/action RBAC policy, H1 and H2."""
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


def registry(groups):
    return dict(version=1, consumers=[dict(id='alice', enabled=True, groups=groups),
                                      dict(id='bob', enabled=True, groups=[])],
                credentials=[dict(id='key', consumerId='alice', method='bearer',
                                  secret='alice-key', enabled=True),
                            dict(id='bob-key', consumerId='bob', method='bearer',
                                 secret='bob-key', enabled=True)])


@contextmanager
def gateway(args, groups, invalid_policy=False, policy_variant=False):
    with tempfile.TemporaryDirectory(prefix='rut-consumer-rbac-') as temporary:
        root = Path(temporary)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        source = root / 'rbac.rut'
        program = Path(args.source).read_text().replace('listen :8080', f'listen :{port}')
        if policy_variant:
            program = program.replace('acme:invoice-reader', 'acme:removed-reader')
        if invalid_policy:
            program += '''
route GET "/test-invalid-policy" {
    guard let identity = consumerAuthenticate(req.authorization.or(""), env("AUTH_REGISTRY"), "bearer") else { return 401 }
    let allowed = rbac.require(identity, "acme", "invoices", "read",
        rbac.Rule(tenant: "acme", role: "acme:invoice-reader", resource: "invoices", action: "read", effect: "allow"),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""),
        rbac.Rule(tenant: "other", role: "invalid-unrelated-rule", resource: "invoices", action: "read", effect: "permit"))
    guard let subject = json.string(json.get(allowed, "/consumerId").or(allowed)) else { return 503 }
    return response(200, body: subject)
}
route GET "/test-resource-mismatch" {
    guard let identity = consumerAuthenticate(req.authorization.or(""), env("AUTH_REGISTRY"), "bearer") else { return 401 }
    let allowed = rbac.require(identity, "acme", "reports", "read",
        rbac.Rule(tenant: "acme", role: "acme:invoice-reader", resource: "invoices", action: "read", effect: "allow"),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""))
    guard let subject = json.string(json.get(allowed, "/consumerId").or(allowed)) else { return 503 }
    return response(200, body: subject)
}
route GET "/test-empty-policy" {
    guard let identity = consumerAuthenticate(req.authorization.or(""), env("AUTH_REGISTRY"), "bearer") else { return 401 }
    let allowed = rbac.require(identity, "acme", "invoices", "read",
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""))
    guard let subject = json.string(json.get(allowed, "/consumerId").or(allowed)) else { return 503 }
    return response(200, body: subject)
}
'''
            program += f'''
route GET "/test-overlong-selector" {{
    guard let identity = consumerAuthenticate(req.authorization.or(""), env("AUTH_REGISTRY"), "bearer") else {{ return 401 }}
    let allowed = rbac.require(identity, "{'t' * 129}", "invoices", "read",
        rbac.Rule(tenant: "acme", role: "acme:invoice-reader", resource: "invoices", action: "read", effect: "allow"),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""),
        rbac.Rule(tenant: "", role: "", resource: "", action: "", effect: ""))
    guard let subject = json.string(json.get(allowed, "/consumerId").or(allowed)) else {{ return 503 }}
    return response(200, body: subject)
}}
'''
        source.write_text(program)
        middleware = root / 'middleware'
        middleware.mkdir()
        for name in ('auth.rut', 'rbac.rut'):
            (middleware / name).write_bytes((Path(args.source).parent / 'middleware' / name).read_bytes())
        log = root / 'gateway.log'
        with log.open('w') as output:
            process = subprocess.Popen([args.server, str(source), '--backend', args.backend,
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
            output = log.read_text()
            assert 'alice-key' not in output, output


def h1(port, path, token='alice-key', method='GET'):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        headers = [] if token is None else list(token) if isinstance(token, tuple) else [token]
        connection.putrequest(method, path)
        connection.putheader('X-Groups', 'acme:invoice-admin')
        connection.putheader('X-Consumer-ID', 'bob')
        for value in headers:
            connection.putheader('Authorization', 'Bearer ' + value)
        connection.endheaders()
        response = connection.getresponse()
        result = response.status, response.read()
        return result
    finally:
        connection.close()


def h2(port, path, token='alice-key', method='GET'):
    values = [] if token is None else list(token) if isinstance(token, tuple) else [token]
    fields = [('x-groups', 'acme:invoice-admin'), ('x-consumer-id', 'bob')]
    fields += [('authorization', 'Bearer ' + value) for value in values]
    return h2_request(port, path, fields, method=method)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    paths = (('GET', '/tenant/acme/invoices/read'), ('POST', '/tenant/acme/invoices/delete'),
             ('GET', '/tenant/other/invoices/read'))
    cases = [
        (['acme:invoice-reader'], [(200, b'alice'), (403, b''), (403, b'')], 'alice-key'),
        (['acme:invoice-admin'], [(200, b'alice'), (200, b'alice'), (403, b'')], 'alice-key'),
        (['acme:invoice-reader', 'acme:suspended'], [(403, b''), (403, b''), (403, b'')], 'alice-key'),
        (['acme:invoice-admin', 'acme:suspended'], [(403, b''), (403, b''), (403, b'')], 'alice-key'),
        (['other:invoice-reader'], [(403, b''), (403, b''), (200, b'alice')], 'alice-key'),
        ([], [(403, b''), (403, b''), (403, b'')], 'alice-key'),
        (['acme:invoice-reader'], [(403, b''), (403, b''), (403, b'')], 'bob-key'),
        (['acme:invoice-reader'], [(401, b''), (401, b''), (401, b'')], None),
        (['acme:invoice-reader'], [(401, b''), (401, b''), (401, b'')], 'wrong-key'),
    ]
    for groups, expected, token in cases:
        with gateway(args, groups, invalid_policy=True) as port:
            for request, label in ((h1, 'HTTP/1'), (h2, 'HTTP/2')):
                for (method, path), result in zip(paths, expected):
                    actual = request(port, path, token, method)
                    assert actual[0] == result[0] and (result[0] != 200 or actual[1] == b'alice'), (
                        args.backend, label, groups, path, actual, result)
                if token == 'alice-key':
                    assert request(port, '/test-invalid-policy', token)[0] == 503, (args.backend, label)
                    assert request(port, '/test-resource-mismatch', token)[0] == 403, (args.backend, label)
                    assert request(port, '/test-empty-policy', token)[0] == 503, (args.backend, label)
                    assert request(port, '/test-overlong-selector', token)[0] == 503, (args.backend, label)
    with gateway(args, ['acme:invoice-reader']) as old:
        assert h1(old, paths[0][1]) == (200, b'alice')
        assert h2(old, paths[0][1]) == (200, b'alice')
        assert h1(old, paths[0][1], ('alice-key', 'alice-key'))[0] == 401
        assert h2(old, paths[0][1], ('alice-key', 'alice-key'))[0] == 401
        with gateway(args, ['acme:invoice-reader'], policy_variant=True) as new:
            assert h1(old, paths[0][1]) == (200, b'alice')
            assert h2(old, paths[0][1]) == (200, b'alice')
            assert h1(new, paths[0][1])[0] == 403
            assert h2(new, paths[0][1])[0] == 403
    print(f'PASS consumer RBAC {args.backend}: exact rules, deny override, default deny, bad policy, H1/H2 and unlinked native source/modules')


if __name__ == '__main__':
    main()
