#!/usr/bin/env python3
"""Two authenticated, same-role tenant members with distinct ownership."""
import argparse
from test_consumer_tenant_rbac import gateway, request_h1, request_h2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), default='2')
    args = parser.parse_args()
    groups = {'alice': ['invoice-reader'], 'bob': ['invoice-reader']}
    with gateway(args, groups) as port:
        for request in (request_h1, request_h2):
            path = '/tenant/acme/invoices/alice'
            assert request(port, path, 'alice-secret') == (200, b'alice')
            assert request(port, path, 'bob-secret')[0] == 403
            assert request(port, path, None)[0] == 401
    print('PASS owner gate', args.backend)


if __name__ == '__main__':
    main()
