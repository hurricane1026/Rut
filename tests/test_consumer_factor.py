#!/usr/bin/env python3
"""Verified Consumer factor restriction and effective group composition."""
import argparse
import json
import test_consumer_rbac as fixture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--backend', required=True)
    args = parser.parse_args()
    # Two factors share the same Consumer, but each has a different effective group.
    fixture.registry = lambda groups: dict(version=1,
        consumers=[dict(id='alice', enabled=True, groups=['readers', 'writers'])],
        credentials=[dict(id='reader-key', consumerId='alice', method='bearer', secret='alice-key', enabled=True, groups=groups),
                     dict(id='other-key', consumerId='alice', method='bearer', secret='other-key', enabled=True, groups=['readers'])])
    for groups, expected in [(['readers'], 200), (['writers'], 403), ([], 403)]:
        with fixture.gateway(args, groups) as port:
            for request in (fixture.h1, fixture.h2):
                assert request(port, '/read')[0] == expected
                assert request(port, '/read', 'other-key')[0] == 403
                assert request(port, '/wrong-method')[0] == 403
                assert request(port, '/bad-policy')[0] == 503
                assert request(port, '/bad-method')[0] == 503
                assert request(port, '/read', 'wrong')[0] == 401
                assert request(port, '/read', ('alice-key', 'alice-key'))[0] == 401
    print('PASS Consumer factor restriction and effective groups')


if __name__ == '__main__':
    main()
