#!/usr/bin/env python3
"""Reject new unproven unsigned-to-signed 64-bit conversions in production."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from functools import cache
import json
from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MESSAGE = 'u64 to i64 conversion requires a range proof'
DIAGNOSTIC = re.compile(
    r'^(.+?):(\d+):(\d+):(?:\{(\d+):(\d+)-(\d+):(\d+)\}:)?'
    rf' warning: {re.escape(MESSAGE)}$', re.M
)


def first_party(path):
    return any(path.is_relative_to(ROOT / folder) for folder in ('src', 'include'))


@cache
def source_lines(path):
    return path.read_bytes().splitlines()


def fingerprint(path, line, span):
    lines = source_lines(path)
    context = lines[line - 1].strip()
    if span:
        first, start, last, end = span
        if first == last:
            expression = lines[first - 1][start - 1:end - 1]
        else:
            expression = b'\n'.join([lines[first - 1][start - 1:], *lines[first:last - 1],
                                     lines[last - 1][:end - 1]])
    else:
        expression = context
    return json.dumps([str(path.relative_to(ROOT)), context.decode(), expression.decode()],
                      ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('plugin', type=Path)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--inventory', type=Path)
    args = parser.parse_args()
    check = ['-fsyntax-only', '-Xclang', '-load', '-Xclang', str(args.plugin.resolve()),
             '-Xclang', '-add-plugin', '-Xclang', 'rut-u64-to-i64']
    subprocess.run([args.clang, *check, '-Xclang', '-verify', '-I', ROOT / 'include',
                    '-std=c++23', ROOT / 'scripts/clang/u64_to_i64_cases.cc'], check=True)

    commands = set()
    entries = json.loads((args.build / 'compile_commands.json').read_text())
    for entry in entries:
        cwd = Path(entry['directory'])
        path = (cwd / entry['file']).resolve()
        if not path.is_relative_to(ROOT / 'src') or path.suffix not in {'.cc', '.cpp', '.cxx', '.c'}:
            continue
        command = entry.get('arguments') or shlex.split(entry['command'])
        start = 2 if Path(command[0]).name == 'ccache' else 1
        flags = command[start:]
        output = flags.index('-o')
        del flags[output:output + 2]
        flags.remove('-c')
        commands.add((cwd, tuple(flag for flag in flags if flag != '-w')))
    if not commands:
        raise SystemExit('no production translation units for u64 to i64 conversion audit')

    def inspect(command):
        cwd, flags = command
        run = subprocess.run([args.clang, *flags, '-Wno-error', '-fno-color-diagnostics',
                              '-fdiagnostics-print-source-range-info', *check], cwd=cwd,
                             text=True, capture_output=True)
        if run.returncode:
            raise RuntimeError(f'Clang conversion audit failed\n{run.stderr}')
        diagnostics = DIAGNOSTIC.findall(run.stderr)
        if len(diagnostics) != run.stderr.count(f'warning: {MESSAGE}'):
            raise RuntimeError(f'Could not read Clang conversion diagnostics\n{run.stderr}')
        sites = set()
        for filename, line, column, *span in diagnostics:
            path = (cwd / filename).resolve()
            if first_party(path):
                sites.add((path, int(line), int(column), tuple(map(int, span)) if span[0] else ()))
        return sites

    with ThreadPoolExecutor(max_workers=args.jobs) as workers:
        sites = sorted(set().union(*workers.map(inspect, sorted(commands))))

    baseline = Counter(line for line in (ROOT / 'scripts/u64_to_i64_baseline.txt').read_text().splitlines()
                       if line and not line.startswith('#'))
    rows = []
    findings = []
    for path, line, column, span in sites:
        relative = path.relative_to(ROOT)
        key = fingerprint(path, line, span)
        rows.append(key)
        if baseline[key] > 0:
            baseline[key] -= 1
        else:
            findings.append(f'{relative}:{line}:{column}: {MESSAGE}')
    if args.inventory:
        args.inventory.write_text(''.join(row + '\n' for row in sorted(rows)))
    for report in findings:
        print(report)
    print(f'{len(commands)} production compile commands, {len(sites) - len(findings)} existing '
          f'unproven conversions, {len(findings)} new unproven conversions')
    return bool(findings)


if __name__ == '__main__':
    raise SystemExit(main())
