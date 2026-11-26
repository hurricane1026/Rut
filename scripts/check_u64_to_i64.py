#!/usr/bin/env python3
"""Reject unproven unsigned-to-signed 64-bit conversions in production."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import cache
import json
from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MESSAGE = 'u64 to i64 conversion requires a range proof'
OVERFLOW_MESSAGE = 'checked arithmetic requires an explicit return from a nodiscard function'
DIAGNOSTIC = re.compile(
    r'^(.+?):(\d+):(\d+):(?:\{(\d+):(\d+)-(\d+):(\d+)\}:)?'
    rf' warning: ({re.escape(MESSAGE)}|{re.escape(OVERFLOW_MESSAGE)})$', re.M
)


def changed_source_lines(base):
    # Git supplies the migration boundary. No inventory of exceptions is kept.
    names = subprocess.check_output(
        ['git', 'diff', '--name-only', '-z', '--no-renames', '--diff-filter=AM', f'{base}...HEAD'], cwd=ROOT
    )
    changes = {}
    for name in names.decode().split('\0'):
        path = ROOT / name
        if not first_party(path) or path.suffix not in {'.cc', '.cpp', '.cxx', '.c', '.h', '.hpp'}:
            continue
        patch = subprocess.check_output(
            ['git', 'diff', '--unified=0', '--no-ext-diff', '--no-renames', f'{base}...HEAD', '--', name],
            cwd=ROOT, text=True
        )
        changes[path] = [range(int(start), int(start) + int(count or 1))
                         for start, count in re.findall(
                             r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', patch, re.M)]
    return changes


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
    parser.add_argument('--overflow-base', help='audit checked arithmetic on C++ lines added since the merge base')
    args = parser.parse_args()
    check = ['-fsyntax-only', '-Xclang', '-load', '-Xclang', str(args.plugin.resolve()),
             '-Xclang', '-add-plugin', '-Xclang', 'rut-u64-to-i64']
    subprocess.run([args.clang, *check, '-Xclang', '-verify', '-I', ROOT / 'include',
                    '-std=c++23', ROOT / 'scripts/clang/u64_to_i64_cases.cc'], check=True)

    overflow_check = ['-Xclang', '-add-plugin', '-Xclang', 'rut-overflow-result']
    subprocess.run([args.clang, '-fsyntax-only', '-Xclang', '-load', '-Xclang',
                    str(args.plugin.resolve()), *overflow_check, '-Xclang', '-verify',
                    '-std=c++23', ROOT / 'scripts/clang/overflow_result_cases.cc'], check=True)
    changed = changed_source_lines(args.overflow_base) if args.overflow_base else {}
    if not changed:
        overflow_check = []

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
                              '-fdiagnostics-print-source-range-info', *check, *overflow_check], cwd=cwd,
                             text=True, capture_output=True)
        if run.returncode:
            raise RuntimeError(f'Clang conversion audit failed\n{run.stderr}')
        diagnostics = DIAGNOSTIC.findall(run.stderr)
        if len(diagnostics) != sum(run.stderr.count(f'warning: {message}')
                                   for message in (MESSAGE, OVERFLOW_MESSAGE)):
            raise RuntimeError(f'Could not read Clang audit diagnostics\n{run.stderr}')
        sites = set()
        for filename, line, column, first, start, last, end, message in diagnostics:
            path = (cwd / filename).resolve()
            line = int(line)
            if not first_party(path):
                continue
            if message == OVERFLOW_MESSAGE and not any(
                line in lines for lines in changed.get(path, ())
            ):
                continue
            span = tuple(map(int, (first, start, last, end))) if first else ()
            sites.add((path, line, int(column), span, message))
        return sites

    with ThreadPoolExecutor(max_workers=args.jobs) as workers:
        sites = sorted(set().union(*workers.map(inspect, sorted(commands))))

    if args.inventory:
        rows = [fingerprint(path, line, span) for path, line, _, span, message in sites
                if message == MESSAGE]
        args.inventory.write_text(''.join(row + '\n' for row in sorted(rows)))
    for path, line, column, _, message in sites:
        print(f'{path.relative_to(ROOT)}:{line}:{column}: {message}')
    conversions = sum(message == MESSAGE for *_, message in sites)
    print(f'{len(commands)} production compile commands, {conversions} unproven conversions')
    if args.overflow_base:
        print(f'{len(sites) - conversions} unchecked arithmetic result paths on changed lines')
    return bool(sites)


if __name__ == '__main__':
    raise SystemExit(main())
