#!/usr/bin/env python3
"""Check Clang loop bytes and optionally measure the effect of code layout."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'scripts/clang/range_int_codegen.cc'
HARNESS = ROOT / 'scripts/clang/range_int_loop_bench.cc'
LOOP = 'compare_accumulate'


def run(*args):
    subprocess.run(args, check=True)


def compile_loop(compiler, objcopy, directory, arch_flags, kind):
    obj = directory / f'{kind}.o'
    code = directory / f'{kind}.bin'
    defines = ('-DRUT_USE_RANGE_INT',) if kind == 'wrapped' else ()
    run(compiler, '-O3', '-std=c++23', '-Wno-return-type-c-linkage', '-I', ROOT / 'include',
        '-ffunction-sections', *arch_flags, *defines, '-c', FIXTURE, '-o', obj)
    run(objcopy, '--dump-section', f'.text.{LOOP}={code}', obj)
    run(objcopy, f'--keep-global-symbol={LOOP}', obj)
    run(objcopy, '--redefine-sym', f'{LOOP}={kind}_loop', obj)
    return obj, code.read_bytes()


def measure(compiler, directory, raw, wrapped):
    target = directory / 'bench'
    for label, objects, link_flags in (
        ('raw first', (raw, wrapped), ()),
        ('wrapped first', (wrapped, raw), ()),
        ('same-address control', (raw,), ('-Wl,--defsym,wrapped_loop=raw_loop',)),
    ):
        run(compiler, '-O2', '-std=c++23', '-I', ROOT / 'include', '-Wl,--gc-sections',
            *link_flags, HARNESS, *objects, '-o', target)
        print(label, flush=True)
        run(target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', default='clang++-22')
    parser.add_argument('--objcopy', default='objcopy')
    parser.add_argument('--measure', action='store_true', help='run the pinned Linux microbenchmark')
    args = parser.parse_args()

    if args.measure and not hasattr(os, 'sched_getaffinity'):
        parser.error('--measure requires Linux CPU affinity support')

    run(args.compiler, '--version')
    with tempfile.TemporaryDirectory(prefix='rut-range-int-loop-') as temp:
        directory = Path(temp)
        for arch_flags in ((), ('-march=native',)):
            raw, raw_code = compile_loop(args.compiler, args.objcopy, directory, arch_flags, 'raw')
            wrapped, wrapped_code = compile_loop(
                args.compiler, args.objcopy, directory, arch_flags, 'wrapped')
            label = ' '.join(('-O3', *arch_flags))
            if not raw_code or raw_code != wrapped_code:
                raise SystemExit(f'{label}: {LOOP} machine code differs')
            print(f'{label}: {len(raw_code)} identical loop bytes', flush=True)
            if args.measure:
                measure(args.compiler, directory, raw, wrapped)


if __name__ == '__main__':
    main()
