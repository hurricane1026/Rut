#!/usr/bin/env python3
"""Connection-verified certificate deny list before Consumer authentication."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import tempfile

from test_mtls_consumers import registry_gateway, registry_request
from auth_h2_fixture import request as h2_request


def main():
    parser = argparse.ArgumentParser()
    for option in ('server', 'source', 'testdata', 'backend'):
        parser.add_argument('--' + option, required=True)
    args = parser.parse_args()
    certs = Path(args.testdata)
    cert = certs / 'localhost_cert.pem'
    second = certs / 'mtls_second_cert.pem'
    key = certs / 'localhost_key.pem'
    pins = [hashlib.sha256(ssl.PEM_cert_to_DER_cert(p.read_text())).hexdigest() for p in (cert, second)]
    registry = dict(version=1, consumers=[dict(id='alice', enabled=True, groups=[]),
                                         dict(id='bob', enabled=True, groups=[])],
                    credentials=[dict(id=name, consumerId=owner, method='mtls', secret=pin, enabled=True)
                                 for name, owner, pin in zip(('one', 'two'), ('alice', 'bob'), pins)])
    with tempfile.TemporaryDirectory(prefix='rut-mtls-deny-') as directory:
        root = Path(directory)
        ca = root / 'ca.pem'
        ca.write_text(cert.read_text() + second.read_text())
        args.client_ca = ca
        module = root / 'middleware' / 'mtls_deny.rut'
        module.parent.mkdir()
        module.write_bytes((Path(args.source).parent / 'middleware/mtls_deny.rut').read_bytes())
        contexts = []
        for client in (cert, second):
            context = ssl.create_default_context(cafile=str(cert))
            context.load_cert_chain(str(client), str(key))
            contexts.append(context)
        for first, second_pin, expected in [(pins[0], '', (403, 200)), ('', pins[1], (200, 403)),
                                            ('0' * 64, '', (200, 200)), ('', '', (503, 503)),
                                            ('A' * 64, '', (503, 503)), (pins[0], pins[0], (503, 503))]:
            source = root / 'gateway.rut'
            source.write_bytes(Path(args.source).read_bytes())
            env = dict(os.environ, MTLS_DENY_FIRST=first, MTLS_DENY_SECOND=second_pin,
                       MTLS_REGISTRY=json.dumps(registry))
            with registry_gateway(args, source, env, 'mtls') as port:
                for context, status in zip(contexts, expected):
                    headers = {'X-Client-Cert-Sha256': pins[1], 'X-Consumer-ID': 'bob'}
                    assert registry_request(port, '/private', headers, context)[0] == status
                    context.set_alpn_protocols(['h2'])
                    assert h2_request(port, '/private', list(headers.items()), tls_context=context)[0] == status
                    context.set_alpn_protocols(['http/1.1'])
        source = root / 'gateway.rut'
        source.write_bytes(Path(args.source).read_bytes())
        env = dict(os.environ, MTLS_DENY_FIRST=pins[0], MTLS_DENY_SECOND='', MTLS_REGISTRY=json.dumps(registry))
        with registry_gateway(args, source, env, 'clear') as port:
            assert registry_request(port, '/private', {})[0] == 403
    print('PASS verified mTLS deny policy')


if __name__ == '__main__':
    main()
