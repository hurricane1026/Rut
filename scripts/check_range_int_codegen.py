#!/usr/bin/env python3
"""Compare optimized assembly for range_int and equivalent raw integers."""

import argparse
import difflib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'scripts/clang/range_int_codegen.cc'
FUNCTION = re.compile(r'^(compare_\w+):')
COMMENT = re.compile(r'//|#(?=\s|$)')


def assemble(compiler, target, optimization, wrapped):
    flags = ['-std=c++23', optimization, '-S', '-I', ROOT / 'include',
             '-Wno-return-type-c-linkage']
    if target:
        flags.extend(['--target=' + target, '-ffreestanding'])
    if wrapped:
        flags.append('-DRUT_USE_RANGE_INT')
    output = subprocess.check_output([compiler, *flags, FIXTURE, '-o', '-'], text=True)
    # Keep instructions, labels, data and alignment. Drop comments while
    # preserving AArch64 immediates such as "#8".
    lines = (COMMENT.split(line, maxsplit=1)[0].strip() for line in output.splitlines())
    return [line for line in lines if line]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', default='clang++')
    parser.add_argument('--target', help='cross-compile a freestanding fixture for this Clang target')
    parser.add_argument('--show-asm', action='store_true', help='print the matching assembly')
    args = parser.parse_args()

    failed = False
    for optimization in ('-O2', '-O3'):
        configuration = f'{args.compiler} {args.target or "native"} {optimization}'
        raw = assemble(args.compiler, args.target, optimization, wrapped=False)
        wrapped = assemble(args.compiler, args.target, optimization, wrapped=True)
        functions = {match[1] for line in raw if (match := FUNCTION.match(line))}
        wrapped_functions = {match[1] for line in wrapped if (match := FUNCTION.match(line))}
        if not functions or functions != wrapped_functions:
            raise SystemExit(f'{configuration}: expected the same comparison functions')
        if raw != wrapped:
            failed = True
            print('\n'.join(difflib.unified_diff(
                raw, wrapped, f'{configuration} raw', f'{configuration} range_int', lineterm='')))
        else:
            print(f'{configuration}: identical assembly for {len(functions)} functions')
            if args.show_asm:
                print('\n'.join(wrapped))
    return failed


if __name__ == '__main__':
    raise SystemExit(main())
