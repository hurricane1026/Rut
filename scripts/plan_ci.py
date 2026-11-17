#!/usr/bin/env python3
"""Classify changed paths and emit a bounded PR matrix or full regression matrix."""

import argparse
import json
from pathlib import Path
import subprocess


def classify(paths):
    native = formatting = models = False
    for path in paths:
        if path.startswith(('docs/', '.agents/')) or path.endswith('.md'):
            continue
        if path.startswith(('src/', 'include/', 'helpers/', 'testing/', 'third_party/')):
            native = True
        elif path.startswith(('bench/', 'cmake/', 'tests/', 'examples/')):
            native = True
        elif path in ('CMakeLists.txt', 'dev.sh', '.gitmodules'):
            native = True
        elif path.startswith('.github/') or path in (
                'scripts/plan_ci.py', 'scripts/run_ci_shard.py'):
            # CI selection controls get dedicated real-CTest checks.
            # CMake/default build changes above still require native smoke tests.
            pass
        else:
            native = True  # Unknown inputs conservatively require native checks.
        formatting |= path.endswith(('.cc', '.h'))
        models |= path.startswith('models/') or any(
            token in path for token in ('model', 'mutation', 'verifier', 'scheduler', 'timer', 'retirement'))
    return {'native': native, 'format': formatting, 'models': models}


def matrix(full):
    return {'include': [dict(compiler=compiler, build_type=kind, shard=shard)
                        for compiler, kind in ([('clang', 'Debug'), ('clang', 'Release'),
                                                ('gcc', 'Debug'), ('gcc', 'Release')]
                                               if full else [('clang', 'Debug')])
                        for shard in range(1, 5)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base')
    parser.add_argument('--head', default='HEAD')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    paths = []
    if args.base:
        paths = subprocess.check_output(
            ['git', 'diff', '--name-only', '-z', f'{args.base}...{args.head}']).decode().split('\0')
        paths = [path for path in paths if path]
    full = not args.base
    flags = {name: True for name in ('native', 'format', 'models')} if full else classify(paths)
    flags.update(full=full, matrix=matrix(full), changed=paths)
    with args.output.open('a') as stream:
        for key, value in flags.items():
            stream.write(f'{key}={json.dumps(value, separators=(",", ":"))}\n')


if __name__ == '__main__':
    main()
