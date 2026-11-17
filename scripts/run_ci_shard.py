#!/usr/bin/env python3
"""Run one disjoint part of the primary CI suite on an isolated runner."""

import argparse
from collections import Counter
import json
import re
from pathlib import Path
import subprocess
import sys


def records(command):
    result = subprocess.run(command + ['--show-only=json-v1'],
                            check=True, capture_output=True, text=True)
    return json.loads(result.stdout)['tests']


def inventory(command):
    return [test['name'] for test in records(command)]


def pr_selection(tests, changed):
    changed_names = {Path(path).name for path in changed}
    changed_stems = {Path(path).stem for path in changed if path.startswith('tests/')}
    selected = []
    for test in tests:
        properties = {p['name']: p['value'] for p in test.get('properties', [])}
        command_names = {Path(arg).name for arg in test.get('command', [])}
        if ('unit' in properties.get('LABELS', [])
                or test['name'].startswith('test_integration.shard_')
                or command_names & (changed_names | changed_stems)):
            selected.append(test['name'])
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--shard', type=int, required=True)
    parser.add_argument('--shards', type=int, default=4)
    parser.add_argument('--plan-only', action='store_true')
    parser.add_argument('--pr', action='store_true', help='unit, integration smoke and directly changed test commands')
    parser.add_argument('--changed-files-json', default='[]')
    args = parser.parse_args()
    if not 1 <= args.shard <= args.shards:
        parser.error('require 1 <= shard <= shards')

    command = ['ctest', '--test-dir', str(args.build_dir), '-LE', 'docker']
    deferred = []
    if args.pr:
        changed = json.loads(args.changed_files_json)
        if not isinstance(changed, list) or any(not isinstance(path, str) for path in changed):
            raise ValueError('changed files must be a JSON array of paths')
        available = records(command)
        names = pr_selection(available, changed)
        deferred = [test['name'] for test in available if test['name'] not in names]
        if not names:
            raise ValueError('PR selection must be nonempty')
        command += ['-R', '^(' + '|'.join(re.escape(name) for name in names) + ')$']
    complete = inventory(command)
    parts = [inventory(command + ['-I', f'{index},,{args.shards}'])
             for index in range(1, args.shards + 1)]
    # Verify CTest's actual selection after label filtering, including any
    # automatically selected fixture tests. Fail closed on omissions/overlap.
    selected = [name for part in parts for name in part]
    if (not complete or any(not part for part in parts)
            or Counter(selected) != Counter(complete)
            or len(selected) != len(set(selected))):
        raise ValueError('CTest shards must be nonempty and cover every eligible test exactly once')
    report = {'total': len(complete), 'shard': args.shard,
              'shards': parts, 'excluded_label': 'docker', 'scope': 'pr' if args.pr else 'full', 'deferred_tests': deferred}
    (args.build_dir / 'ci-shard-inventory.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'CI shard {args.shard}/{args.shards}: '
          f'{len(parts[args.shard - 1])}/{len(complete)} tests; '
          'complete disjoint partition verified', flush=True)
    if args.plan_only:
        return 0
    # Keep serial scheduling, test-specific timeouts, resource locks and the
    # original Docker exclusion. Concurrency is between isolated CI runners.
    return subprocess.run(command + [
        '-I', f'{args.shard},,{args.shards}', '--output-on-failure',
        '--no-tests=error', '-j', '1', '--timeout', '120',
        '--output-junit', str((args.build_dir / 'ci-shard-results.xml').resolve()),
    ]).returncode


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f'CI shard failed: {error}', file=sys.stderr)
        sys.exit(1)
