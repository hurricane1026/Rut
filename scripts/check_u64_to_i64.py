#!/usr/bin/env python3
"""Enforce Clang integer range and API style policies in production code."""

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
OVERFLOW_NODISCARD_MESSAGE = 'checked arithmetic status requires [[nodiscard]]'
ADDRESS_MESSAGE = 'use bounded offsets for address arithmetic or validate a raw span explicitly'
ARITHMETIC_MESSAGE = 'integer arithmetic needs a range proof'
NARROWING_MESSAGE = 'integer arithmetic result may not fit the destination'
INDEX_MESSAGE = 'use range_int::index() or at() for array indexing'
RANGE_CAST_MESSAGE = 'narrow a range_int with a range-checked conversion'
BIT_CAST_MESSAGE = 'use a value conversion for integer or enum bit casts'
NODISCARD_MESSAGE = 'non-void functions require [[nodiscard]]'
MUTABLE_REFERENCE_MESSAGE = 'use a pointer for a mutable scalar parameter'
VOID_DISCARD_MESSAGE = 'void cast discards a [[nodiscard]] result'
CAST_MESSAGES = ('static_cast is prohibited', 'C-style casts are prohibited')
TU_EXTENSIONS = {'.cc', '.cpp', '.cxx', '.c++', '.c'}
SOURCE_EXTENSIONS = TU_EXTENSIONS | {'.h', '.hh', '.hpp', '.hxx', '.inc'}
CAST_FOLDERS = ('src', 'include', 'tests', 'testing', 'bench', 'helpers')
ARITHMETIC_MESSAGES = (ARITHMETIC_MESSAGE, NARROWING_MESSAGE)
MESSAGES = (MESSAGE, OVERFLOW_MESSAGE, OVERFLOW_NODISCARD_MESSAGE, INDEX_MESSAGE, RANGE_CAST_MESSAGE, NODISCARD_MESSAGE,
            ADDRESS_MESSAGE, BIT_CAST_MESSAGE, VOID_DISCARD_MESSAGE, MUTABLE_REFERENCE_MESSAGE,
            *CAST_MESSAGES, *ARITHMETIC_MESSAGES)
DIAGNOSTIC = re.compile(
    r'^(.+?):(\d+):(\d+):(?:\{(\d+):(\d+)-(\d+):(\d+)\}:)?'
    rf' warning: ({"|".join(map(re.escape, MESSAGES))})$', re.M
)
OVERFLOW_BUILTIN = re.compile(rb'\b__builtin_(?:[su])?(add|sub|mul)(?:ll?)?_overflow(?:_p)?\b')
TRAP_BUILTIN = re.compile(rb'\b__builtin_(?:debug|verbose_)?trap\b')
RANGE_COMMENT = re.compile(rb'//\s*RUT_INTEGER_RANGE:\s*\S')


def changed_source_lines(base, *, check_deleted_attributes=False, cast_scope=False):
    # Git supplies the migration boundary. No inventory of exceptions is kept.
    names = subprocess.check_output(
        ['git', 'diff', '--name-only', '-z', '--no-renames', '--diff-filter=AM', base, '--'], cwd=ROOT
    )
    changes = {}
    for name in names.decode().split('\0'):
        path = ROOT / name
        in_scope = in_cast_scope(path) if cast_scope else first_party(path)
        if not in_scope or path.suffix not in SOURCE_EXTENSIONS:
            continue
        patch = subprocess.check_output(
            ['git', 'diff', '--unified=0', '--no-ext-diff', '--no-renames', base, '--', name],
            cwd=ROOT, text=True
        )
        changes[path] = [range(int(start), int(start) + int(count or 1))
                         for start, count in re.findall(
                             r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', patch, re.M)]
        if check_deleted_attributes:
            for hunk in re.split(r'^@@ ', patch, flags=re.M)[1:]:
                match = re.match(r'-\d+(?:,\d+)? \+(\d+),0 @@', hunk)
                if match and re.search(r'^-.*\[\[.*\bnodiscard\b', hunk, re.M):
                    following = int(match[1]) + 1
                    changes[path].append(range(following, following + 1))
    return changes


def first_party(path):
    return any(path.is_relative_to(ROOT / folder) for folder in ('src', 'include'))


def in_cast_scope(path):
    return any(path.is_relative_to(ROOT / folder) for folder in CAST_FOLDERS)


def check_builtin_locations():
    tracked = subprocess.check_output(
        ['git', 'ls-files', '-z', '--', 'src', 'include', 'tests'], cwd=ROOT
    )
    locations = []
    for name in tracked.decode().split('\0'):
        path = ROOT / name
        if path.suffix not in {'.cc', '.cpp', '.cxx', '.c', '.h', '.hpp'}:
            continue
        if not path.is_file():
            continue
        check_arithmetic = first_party(path) and name != 'include/rut/common/checked_arithmetic.h'
        check_trap = name != 'include/rut/common/trap.h'
        for line, source in enumerate(source_lines(path), 1):
            if check_arithmetic and OVERFLOW_BUILTIN.search(source):
                locations.append(f'{name}:{line}: use rut checked arithmetic helpers')
            if check_trap and TRAP_BUILTIN.search(source):
                locations.append(f'{name}:{line}: use RUT_TRAP to log before terminating')
    return locations


@cache
def base_source(base, path):
    previous = subprocess.run(
        ['git', 'show', f'{base}:{path.relative_to(ROOT)}'], cwd=ROOT, capture_output=True
    )
    return previous.stdout if previous.returncode == 0 else b''


@cache
def without_whitespace(source):
    return re.sub(rb'\s+', b'', source)


def inherited_overflow_call(base, path, span):
    if not span:
        return False
    call = without_whitespace(expression_text(source_lines(path), span))
    if not re.match(rb'(?:add|sub|mul)_overflow\(', call):
        return False
    # A rename of an existing builtin still has the same result semantics.
    # Account for duplicate calls so introducing a copy cannot bypass the gate.
    previous = without_whitespace(base_source(base, path))
    current = without_whitespace(b'\n'.join(source_lines(path)))
    return 0 < current.count(call) <= previous.count(b'__builtin_' + call)


@cache
def source_lines(path):
    return path.read_bytes().splitlines()


def expression_text(lines, span):
    first, start, last, end = span
    if first == last:
        return lines[first - 1][start - 1:end - 1]
    return b'\n'.join([lines[first - 1][start - 1:], *lines[first:last - 1],
                      lines[last - 1][:end - 1]])


def fingerprint(path, line, span):
    lines = source_lines(path)
    context = lines[line - 1].strip()
    expression = expression_text(lines, span) if span else context
    return json.dumps([str(path.relative_to(ROOT)), context.decode(), expression.decode()],
                      ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('plugin', type=Path)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--arithmetic-inventory', type=Path,
                        help='write native arithmetic sites that need a proof')
    parser.add_argument('--require-arithmetic-proofs', action='store_true',
                        help='fail on unannotated native arithmetic in the audit scope')
    parser.add_argument('--overflow-base',
                        help='audit checked arithmetic and mutable scalar references since the merge base')
    parser.add_argument('--range-cast-inventory', type=Path,
                        help='write all explicit narrowing casts derived from range_int::value()')
    parser.add_argument('--nodiscard-inventory', type=Path,
                        help='report declarations that are missing [[nodiscard]]')
    parser.add_argument('--nodiscard-base', help='require [[nodiscard]] on declarations changed since this commit')
    parser.add_argument('--cast-base', help='fail on casts changed since this commit instead of all casts')
    parser.add_argument('--strict-bench-casts', action='store_true',
                        help='scan all tracked benchmark sources and reject every cast in bench/')
    parser.add_argument('--cast-inventory', type=Path, help='write all static_cast and C-style cast sites')
    args = parser.parse_args()
    load_plugin = ['-fsyntax-only', '-Xclang', '-load', '-Xclang', str(args.plugin.resolve())]
    check = [*load_plugin, '-Xclang', '-add-plugin', '-Xclang', 'rut-u64-to-i64']
    subprocess.run([args.clang, *check, '-Xclang', '-verify', '-I', ROOT / 'include',
                    '-std=c++23', ROOT / 'scripts/clang/u64_to_i64_cases.cc'], check=True)

    overflow_check = ['-Xclang', '-add-plugin', '-Xclang', 'rut-overflow-result']
    subprocess.run([args.clang, '-fsyntax-only', '-Xclang', '-load', '-Xclang',
                    str(args.plugin.resolve()), *overflow_check, '-Xclang', '-verify',
                    '-I', ROOT / 'include', '-std=c++23',
                    ROOT / 'scripts/clang/overflow_result_cases.cc'], check=True)
    address_check = ['-Xclang', '-add-plugin', '-Xclang', 'rut-address-addition']
    subprocess.run([args.clang, '-fsyntax-only', '-Xclang', '-load', '-Xclang',
                    str(args.plugin.resolve()), *address_check, '-Xclang', '-verify',
                    '-I', ROOT / 'include', '-std=c++23',
                    ROOT / 'scripts/clang/address_addition_cases.cc'], check=True)
    arithmetic_check = ['-Xclang', '-add-plugin', '-Xclang', 'rut-integer-arithmetic']
    subprocess.run([args.clang, '-fsyntax-only', '-Xclang', '-load', '-Xclang',
                    str(args.plugin.resolve()), *arithmetic_check, '-Xclang', '-verify',
                    '-isystem', ROOT / 'include', '-std=c++23',
                    ROOT / 'scripts/clang/integer_arithmetic_cases.cc'], check=True)
    nodiscard_check = ['-Xclang', '-add-plugin', '-Xclang', 'rut-nodiscard']
    subprocess.run([args.clang, '-fsyntax-only', '-Xclang', '-load', '-Xclang',
                    str(args.plugin.resolve()), *nodiscard_check, '-Xclang', '-verify',
                    '-std=c++23', ROOT / 'scripts/clang/nodiscard_cases.cc'], check=True)
    cast_check = ['-Xclang', '-add-plugin', '-Xclang', 'rut-explicit-cast-style']
    subprocess.run([args.clang, '-fsyntax-only', '-Xclang', '-load', '-Xclang',
                    str(args.plugin.resolve()), *cast_check, '-Xclang', '-verify', '-I', ROOT / 'include',
                    '-std=c++23', ROOT / 'scripts/clang/explicit_cast_style_cases.cc'], check=True)
    cast_changed = changed_source_lines(args.cast_base, cast_scope=True) if args.cast_base else {}
    nodiscard_changed = (changed_source_lines(args.nodiscard_base, check_deleted_attributes=True)
                         if args.nodiscard_base else {})
    base = (subprocess.check_output(['git', 'merge-base', args.overflow_base, 'HEAD'],
                                    cwd=ROOT, text=True).strip() if args.overflow_base else None)
    changed = changed_source_lines(base) if base else {}

    commands = set()
    benchmark_sources = set()
    entries = json.loads((args.build / 'compile_commands.json').read_text())
    for entry in entries:
        cwd = Path(entry['directory'])
        path = (cwd / entry['file']).resolve()
        if not in_cast_scope(path) or path.suffix not in TU_EXTENSIONS:
            continue
        command = entry.get('arguments') or shlex.split(entry['command'])
        start = 2 if Path(command[0]).name == 'ccache' else 1
        flags = command[start:]
        output = flags.index('-o')
        del flags[output:output + 2]
        flags.remove('-c')
        if path.is_relative_to(ROOT / 'bench'):
            benchmark_sources.add(path)
        commands.add((cwd, tuple(flag for flag in flags if flag != '-w'),
                      path.is_relative_to(ROOT / 'src')))
    if args.strict_bench_casts:
        tracked = subprocess.check_output(['git', 'ls-files', '-z', '--', 'bench'], cwd=ROOT)
        for name in tracked.decode().split('\0'):
            path = ROOT / name
            if path.suffix not in TU_EXTENSIONS or path in benchmark_sources:
                continue
            standard = '-std=c17' if path.suffix == '.c' else '-std=c++23'
            commands.add((ROOT, (standard, '-Iinclude', '-Itesting', str(path)), False))

    production_count = sum(production for _, _, production in commands)
    if not production_count:
        raise SystemExit('no production translation units for u64 to i64 conversion audit')

    def inspect(command):
        cwd, flags, production = command
        compiler = [args.clang, *flags, '-Wno-error', '-fno-color-diagnostics',
                    '-fdiagnostics-print-source-range-info']
        if production:
            compiler += [*check, *overflow_check, *arithmetic_check, *nodiscard_check, *address_check]
        else:
            compiler += load_plugin
        run = subprocess.run([*compiler, *cast_check], cwd=cwd,
                             text=True, capture_output=True)
        if run.returncode:
            raise RuntimeError(f'Clang conversion audit failed\n{run.stderr}')
        diagnostics = DIAGNOSTIC.findall(run.stderr)
        if len(diagnostics) != sum(run.stderr.count(f'warning: {message}')
                                   for message in MESSAGES):
            raise RuntimeError(f'Could not read Clang audit diagnostics\n{run.stderr}')
        sites = set()
        for filename, line, column, first, start, last, end, message in diagnostics:
            path = (cwd / filename).resolve()
            line = int(line)
            if message in CAST_MESSAGES:
                if not in_cast_scope(path):
                    continue
            elif not first_party(path):
                continue
            span = tuple(map(int, (first, start, last, end))) if first else ()
            if message == OVERFLOW_MESSAGE:
                if not any(line in lines for lines in changed.get(path, ())):
                    continue
                if inherited_overflow_call(base, path, span):
                    continue
            sites.add((path, line, int(column), span, message))
        return sites

    with ThreadPoolExecutor(max_workers=args.jobs) as workers:
        sites = sorted(set().union(*workers.map(inspect, sorted(commands))))

    if args.inventory:
        rows = [fingerprint(path, line, span) for path, line, _, span, message in sites
                if message == MESSAGE]
        args.inventory.write_text(''.join(row + '\n' for row in sorted(rows)))
    arithmetic = [site for site in sites if site[-1] in ARITHMETIC_MESSAGES]
    range_casts = [site for site in sites if site[-1] == RANGE_CAST_MESSAGE]
    nodiscard = [site for site in sites if site[-1] == NODISCARD_MESSAGE]
    mutable_references = [site for site in sites if site[-1] == MUTABLE_REFERENCE_MESSAGE]
    failures = [site for site in sites if site[-1] not in
                (*ARITHMETIC_MESSAGES, *CAST_MESSAGES, NODISCARD_MESSAGE, MUTABLE_REFERENCE_MESSAGE)]
    casts = [site for site in sites if site[-1] in CAST_MESSAGES]
    if args.cast_inventory:
        args.cast_inventory.write_text(''.join(
            f'{path.relative_to(ROOT)}:{line}:{column}: {message}\n'
            for path, line, column, _, message in casts
        ))
    for site in casts:
        path, line, _, span, _ = site
        first, last = (span[0], span[2]) if span else (line, line)
        strict = not args.cast_base or (args.strict_bench_casts and path.is_relative_to(ROOT / 'bench'))
        if strict or any(interval and interval.start <= last and first < interval.stop
                                     for interval in cast_changed.get(path, ())):
            failures.append(site)
    for message in CAST_MESSAGES:
        total = sum(site[-1] == message for site in casts)
        rejected = sum(site[-1] == message for site in failures)
        print(f'{rejected} prohibited casts ({total} found): {message}')
    for site in mutable_references:
        path, line, _, span, _ = site
        first, last = (span[0], span[2]) if span else (line, line)
        if any(interval and interval.start <= last and first < interval.stop
               for interval in changed.get(path, ())):
            failures.append(site)
    enforced = sum(site[-1] == MUTABLE_REFERENCE_MESSAGE for site in failures)
    print(f'{enforced} changed mutable scalar reference parameters '
          f'({len(mutable_references)} in production)')
    for site in nodiscard:
        path, line, _, span, _ = site
        first, last = (span[0], span[2]) if span else (line, line)
        if any(interval and interval.start <= last and first < interval.stop
               for interval in nodiscard_changed.get(path, ())):
            failures.append(site)
    if args.nodiscard_inventory:
        args.nodiscard_inventory.write_text(''.join(
            f'{path.relative_to(ROOT)}:{line}:{column}: {message}\n'
            for path, line, column, _, message in nodiscard
        ))
    enforced = sum(site[-1] == NODISCARD_MESSAGE for site in failures)
    print(f'{enforced} changed declarations missing [[nodiscard]] ({len(nodiscard)} in production)')
    missing_status = sum(site[-1] == OVERFLOW_NODISCARD_MESSAGE for site in failures)
    print(f'{missing_status} checked arithmetic status paths missing [[nodiscard]]')
    discards = sum(site[-1] == VOID_DISCARD_MESSAGE for site in failures)
    print(f'{discards} void casts discarding [[nodiscard]] results')

    if args.range_cast_inventory:
        args.range_cast_inventory.write_text(''.join(
            f'{path.relative_to(ROOT)}:{line}:{column}: {message}\n'
            for path, line, column, _, message in range_casts
        ))
    rows = []
    for path, line, col, span, message in arithmetic:
        lines = source_lines(path)
        note = next((entry.strip().decode() for entry in lines[max(0, line - 2):line]
                     if RANGE_COMMENT.search(entry)), None)
        rows.append(f'{path.relative_to(ROOT)}:{line}:{col}: {note or message}\n')
        if args.require_arithmetic_proofs and not note and (
            not base or any(line in interval for interval in changed.get(path, ()))
        ):
            failures.append((path, line, col, span, message))
    if args.arithmetic_inventory:
        args.arithmetic_inventory.write_text(''.join(rows))
        narrowing = sum(message == NARROWING_MESSAGE for *_, message in arithmetic)
        print(f'{len(arithmetic) - narrowing} native arithmetic sites, '
              f'{narrowing} arithmetic result conversions require review')
    for path, line, column, _, message in failures:
        print(f'{path.relative_to(ROOT)}:{line}:{column}: {message}')
    conversions = sum(message == MESSAGE for *_, message in sites)
    print(f'{production_count} production compile commands, {conversions} unproven conversions')
    print(f'{len(commands)} compile commands checked for explicit casts')
    if args.overflow_base:
        unchecked = sum(message == OVERFLOW_MESSAGE for *_, message in failures)
        print(f'{unchecked} unchecked arithmetic result paths on changed lines')
    print(f'{len(range_casts)} explicit narrowing casts without a range_int conversion')
    indices = sum(message == INDEX_MESSAGE for *_, message in failures)
    print(f'{indices} array indices bypass range_int::index() or at()')
    addresses = sum(message == ADDRESS_MESSAGE for *_, message in failures)
    print(f'{addresses} address additions without bounded offsets or raw-span validation')
    bit_casts = sum(message == BIT_CAST_MESSAGE for *_, message in failures)
    print(f'{bit_casts} integer or enum bit casts')
    direct = check_builtin_locations()
    for location in direct:
        print(location)
    return bool(failures or direct)


if __name__ == '__main__':
    raise SystemExit(main())
