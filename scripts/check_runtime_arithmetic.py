#!/usr/bin/env python3
"""Audit native runtime arithmetic with Clang AST matchers (no target code execution)."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
# Clang uses the result type *after* integer promotion. Pointer arithmetic and
# overloaded operators have different semantics and do not match these rules.
UNSIGNED = 'hasType(isUnsignedInteger())'
ARITH = f'binaryOperator(hasAnyOperatorName("+", "-"), {UNSIGNED})'
VALUE = f'ignoringParenImpCasts({ARITH})'
ZERO = 'ignoringParenImpCasts(integerLiteral(equals(0)))'


def queries(scope):
    # Check the comparison operand type too: a signed widened expression can
    # represent values below zero even if it originated in an unsigned value.
    arithmetic = f'expr({UNSIGNED}, {VALUE})'
    ineffective = (
        f'binaryOperator({scope}, anyOf('
        f'allOf(hasAnyOperatorName("<", ">="), hasLHS({arithmetic}), hasRHS({ZERO})),'
        f'allOf(hasAnyOperatorName(">", "<="), hasLHS({ZERO}), hasRHS({arithmetic}))))'
    )
    inventory = (
        f'expr({scope}, anyOf(binaryOperator(hasAnyOperatorName("+", "-", "+=", "-="),'
        f' hasType(isInteger())), unaryOperator(hasAnyOperatorName("++", "--"),'
        f' hasType(isInteger()))))'
    )
    # Two scalar operands added in their unsigned type before an upper-bound
    # comparison. Explicit widening before the addition avoids this shape.
    ref = 'ignoringParenImpCasts(declRefExpr())'
    raw_sum = (f'ignoringParenImpCasts(binaryOperator(hasOperatorName("+"), {UNSIGNED}, '
               f'hasLHS({ref}), hasRHS({ref})))')
    late_bound = (f'binaryOperator({scope}, anyOf('
                  f'allOf(hasOperatorName(">"), hasLHS({raw_sum})), '
                  f'allOf(hasOperatorName("<"), hasRHS({raw_sum}), '
                  'hasParent(ifStmt(hasThen(returnStmt()))))))')
    # A signed one-step wrap test already invoked undefined behavior on the
    # very input it tries to detect. Both reads must name the same scalar.
    var = 'declRefExpr(hasType(unless(isVolatileQualified())), to(varDecl().bind("v")))'
    same = 'ignoringParenImpCasts(declRefExpr(to(varDecl(equalsBoundNode("v")))))'
    def post_check(op, comparison):
        step = (f'binaryOperator(hasOperatorName("{op}"), hasType(isSignedInteger()), '
                f'hasLHS(ignoringParenImpCasts({var})), '
                'hasRHS(ignoringParenImpCasts(integerLiteral(equals(1)))))')
        return (f'allOf(hasOperatorName("{comparison}"), '
                f'hasLHS(ignoringParenImpCasts({step})), hasRHS({same}))')
    signed = f'binaryOperator({scope}, anyOf({post_check("+", "<")}, {post_check("-", ">")}))'
    return ineffective, late_bound, signed, inventory


def matches(tool, file, query, flags):
    command = [tool, '-c', 'set traversal AsIs', '-c', 'match ' + query, str(file), *flags]
    run = subprocess.run(command, text=True, capture_output=True)
    locations = re.findall(r'^(.+?:\d+:\d+): note: "root" binds here', run.stdout, re.M)
    count = re.search(r'^(\d+) match(?:es)?\.', run.stdout, re.M)
    if run.returncode or not count or int(count[1]) != len(locations):
        raise RuntimeError(f'{file}: clang-query failed\n{run.stderr}\n{run.stdout[-2000:]}')
    return locations


def self_test(tool):
    with tempfile.TemporaryDirectory() as directory:
        file = Path(directory) / 'probe.cc'
        file.write_text("""using U = unsigned;
bool bad(U a, U b) { return a - b < 0; }
bool bad_add(U a, U b) { return 0 <= a + b; }
bool guarded(U a, U b) { return a >= b && a - b <= 8; }
bool promoted(unsigned char a, unsigned char b) { return a - b < 0; }
bool bounded(U a, U b, U cap) { return a <= cap && b <= cap - a; }
bool late(U a, U b, U cap) { return a + b > cap; }
bool wide(U a, U b, U cap) { return (unsigned long long)a + b > cap; }
bool signed_bad(int n) { return n + 1 < n; }
bool under_bad(int n) { return n - 1 > n; }
bool distinct(int n, int m) { return n + 1 < m; }
bool volatile_reads(volatile int &n) { return n + 1 < n; }
""")
        gate, bound, signed, inventory = queries('isExpansionInMainFile()')
        flags = ['--', '-std=c++23']
        for query, expected in ((gate, [2, 3]), (bound, [7]), (signed, [9, 10]), (inventory, list(range(2, 13)))):
            found = sorted(int(p.rsplit(':', 2)[1]) for p in matches(tool, file, query, flags))
            if found != expected:
                raise RuntimeError(f'clang-query self-test: expected lines {expected}, got {found}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--clang-query', default='clang-query')
    parser.add_argument('--inventory', type=Path, help='write unique arithmetic sites for review')
    args = parser.parse_args()
    self_test(args.clang_query)
    database = json.loads((args.build / 'compile_commands.json').read_text())
    files = {Path(e['directory']) / e['file'] for e in database}
    units = sorted(p for p in files if p.is_relative_to(ROOT / 'src/runtime'))
    if not units:
        raise SystemExit('no runtime translation units in compilation database')
    path = '(^|/)(src/runtime|include/rut/(runtime|common)|include/core)/'
    gate, bound, signed, inventory = queries(f'isExpansionInFileMatching({json.dumps(path)})')
    findings = set()
    bounds = set()
    post_checks = set()
    sites = set()
    for file in units:
        flags = ['-p', str(args.build.resolve())]
        findings.update(matches(args.clang_query, file, gate, flags))
        post_checks.update(matches(args.clang_query, file, signed, flags))
        bounds.update(matches(args.clang_query, file, bound, flags))
        if args.inventory:
            sites.update(matches(args.clang_query, file, inventory, flags))
    if args.inventory:
        args.inventory.write_text(''.join(p + '\n' for p in sorted(sites)))
        print(f'{len(sites)} distinct arithmetic locations')
    for p in sorted(findings):
        print(f'{p}: unsigned arithmetic compared against zero with an invariant result')
    for p in sorted(bounds):
        print(f'{p}: unsigned addition occurs before the upper-bound check')
    for p in sorted(post_checks):
        print(f'{p}: check signed arithmetic limits before adding or subtracting one')
    print(f'{len(units)} runtime translation units, {len(findings) + len(bounds) + len(post_checks)} findings')
    return bool(findings or bounds or post_checks)


if __name__ == '__main__':
    raise SystemExit(main())
