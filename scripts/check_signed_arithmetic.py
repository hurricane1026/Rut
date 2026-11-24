#!/usr/bin/env python3
"""Fail CI on residual signed add/sub overflow checks in first-party compiled code."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
# Instrument only the audit objects. Recovering handlers retain an individual
# source record and model the overflow path without making it unreachable.
FLAGS = [
    '-O2', '-g0', '-Werror=integer-overflow', '-fno-wrapv', '-fno-sanitize=all',
    '-fsanitize=signed-integer-overflow,implicit-signed-integer-truncation',
    '-fsanitize-recover=all', '-fno-sanitize-merge', '-femit-all-decls',
    '-Xclang', '-disable-llvm-passes', '-fno-sanitize-trap=all', '-fno-sanitize-ignorelist',
    '-emit-llvm', '-c',
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('reader', type=Path)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    reader = args.reader.resolve()
    # Includes new workspace sources on local runs. Vendored sources and
    # generated build files do not impose a Rut arithmetic contract.
    files = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others',
                                     '--exclude-standard'], cwd=ROOT).decode().split('\0')
    owned = {ROOT / f for f in files if f and not f.startswith('third_party/')}
    entries = json.loads((args.build / 'compile_commands.json').read_text())
    units = [e for e in entries if (Path(e['directory']) / e['file']).resolve() in owned
             and Path(e['file']).suffix in {'.c', '.cc', '.cpp', '.cxx'}]
    if not units:
        raise SystemExit('No first-party compilation commands')

    with tempfile.TemporaryDirectory() as tmp:
        def inspect(flags, cwd, obj):
            run = subprocess.run([args.clang, *flags, *FLAGS, '-o', obj], cwd=cwd,
                                 capture_output=True, text=True)
            if run.returncode:
                raise RuntimeError(f'Arithmetic audit compilation failed\n{run.stderr}')
            output = subprocess.check_output([reader, obj], cwd=cwd, text=True)
            obj.unlink()
            return [line.split('\t') for line in output.splitlines()]

        fixture = ROOT / 'scripts/clang/signed_arithmetic_cases.cc'
        locations = inspect([fixture, '-std=c++23'], ROOT, Path(tmp) / 'fixture.bc')
        expected = {(n, line.split('// report ')[1].strip())
                    for n, line in enumerate(fixture.read_text().splitlines(), 1)
                    if '// report ' in line}
        actual = {(int(n), op) for file, n, _, op in locations if Path(file) == fixture}
        if not expected or actual != expected:
            raise SystemExit(f'Signed arithmetic self-test: expected {expected}, got {actual}')

        def analyze(item):
            index, entry = item
            cwd = Path(entry['directory'])
            command = entry.get('arguments') or shlex.split(entry['command'])
            flags = command[2 if Path(command[0]).name == 'ccache' else 1:]
            out = flags.index('-o')
            del flags[out:out + 2]
            flags.remove('-c')
            sites = set()
            for file, line, col, op in inspect(flags, cwd, Path(tmp) / f'{index}.bc'):
                source = (cwd / file).resolve()
                if source in owned:
                    sites.add((str(source.relative_to(ROOT)), int(line), int(col), op))
            return sites

        with ThreadPoolExecutor(max_workers=args.jobs) as workers:
            findings = set().union(*workers.map(analyze, enumerate(units)))
    lines = [f'{file}:{line}:{col}: signed {op} range not proven'
             for file, line, col, op in sorted(findings)]
    if args.report:
        args.report.write_text(''.join(line + '\n' for line in lines))
    display = lines[:50] if args.report else lines
    for line in display:
        print(line)
    if len(display) < len(lines):
        print(f'Full list of {len(lines)} sites: {args.report}')
    print(f'{len(units)} compilation commands, {len(findings)} unproven arithmetic sites')
    return bool(findings)


if __name__ == '__main__':
    raise SystemExit(main())
