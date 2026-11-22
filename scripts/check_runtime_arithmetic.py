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
# Only accept Clang's diagnostic level in its structured location prefix.  Do
# not treat source text such as `#warning "error:"` or prose in a note as a
# compiler failure.
CLANG_ERROR = re.compile(
    r'(?m)^(?:'
    r'.+:\d+:\d+:\s*(?:fatal )?error:'
    r'|clang[^:\n]*:\s*(?:fatal )?error:'
    r'|fatal error:'
    r'|error:)'
)


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


def unsigned_add_sub(scope):
    # Inspect operands before implicit promotions (u8 + 1 computes an int).
    # Look through parentheses and implicit casts, but respect an explicit
    # conversion of the operand to a signed type. Include pointer offsets.
    value = 'expr(anyOf(declRefExpr(to(varDecl())), memberExpr(), callExpr(), arraySubscriptExpr()))'
    operand = (f'ignoringParenImpCasts(expr(hasType(isUnsignedInteger()),'
               f' unless(hasType(booleanType())), unless(unaryExprOrTypeTraitExpr()),'
               f' anyOf({value}, hasDescendant({value}))))')
    return (f'expr({scope}, anyOf(binaryOperator(hasAnyOperatorName("+", "-", "+=", "-="),'
            f' hasEitherOperand({operand})), unaryOperator(hasAnyOperatorName("+", "-"),'
            f' hasUnaryOperand({operand})), cxxOperatorCallExpr('
            f' hasAnyOverloadedOperatorName("+", "-", "+=", "-="), hasAnyArgument({operand}))))')


def matches(tool, file, query, flags):
    command = [tool, '-c', 'set traversal AsIs', '-c', 'match ' + query, str(file), *flags]
    try:
        separator = command.index('--')
    except ValueError:
        command.extend(['--', '-fdiagnostics-format=clang', '-fshow-column',
                        '-fno-color-diagnostics'])
    else:
        command[separator + 1:separator + 1] = [
            '-fdiagnostics-format=clang', '-fshow-column', '-fno-color-diagnostics'
        ]
    run = subprocess.run(command, text=True, capture_output=True)
    diagnostics = run.stderr + run.stdout
    locations = re.findall(r'^(.+?:\d+:\d+): note: "root" binds here', run.stdout, re.M)
    count = re.search(r'^(\d+) match(?:es)?\.', run.stdout, re.M)
    if run.returncode or CLANG_ERROR.search(diagnostics) or not count or int(count[1]) != len(locations):
        target = f'{file} [{" ".join(flags)}]'
        raise RuntimeError(f'{target}: clang-query failed\n{run.stderr}\n{run.stdout[-2000:]}')
    return locations


def self_test(tool):
    for diagnostic in (
        'clang-query-18: error: bad option',
        'clang++-18: fatal error: no input',
        'fatal error: missing header',
        '/tmp/bad:error.cc:4:7: error: expected expression',
    ):
        if not CLANG_ERROR.search(diagnostic):
            raise RuntimeError(f'clang diagnostic self-test did not match: {diagnostic}')

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
        if matches(tool, file, 'expr(isExpansionInMainFile(), integerLiteral(equals(987654321)))', flags):
            raise RuntimeError('clang-query self-test: expected a valid zero-match query')

        warning = Path(directory) / 'warning.cc'
        warning.write_text(
            '#warning "error: this is source text, not a diagnostic level"\n'
            '// error: this is a comment\n'
            'const char *text = "error: normal";\n'
            'int okay;\n'
        )
        if matches(tool, warning, 'expr(isExpansionInMainFile(), integerLiteral(equals(987654321)))', flags):
            raise RuntimeError('clang-query self-test: warning source unexpectedly matched')

        path_warning = Path(directory) / 'path-error:valid.cc'
        path_warning.write_text('int okay;\n')
        if matches(tool, path_warning, 'expr(isExpansionInMainFile(), integerLiteral(equals(987654321)))', flags):
            raise RuntimeError('clang-query self-test: path containing error unexpectedly matched')

        colon_valid = Path(directory) / 'bad:error.cc'
        colon_valid.write_text('int okay;\n')
        if matches(tool, colon_valid, 'expr(isExpansionInMainFile(), integerLiteral(equals(987654321)))', flags):
            raise RuntimeError('clang-query self-test: valid colon path unexpectedly matched')

        broken = Path(directory) / 'broken.cc'
        broken.write_text('using U = unsigned; U broken(U x) { return x + ; }\n')
        try:
            matches(tool, broken, unsigned_add_sub('isExpansionInMainFile()'), flags)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('clang-query self-test: compiler diagnostics were not rejected')

        colon_broken = Path(directory) / 'bad:error.cc'
        colon_broken.write_text('using U = unsigned; U broken(U x) { return x + ; }\n')
        try:
            matches(tool, colon_broken, 'expr(isExpansionInMainFile(), integerLiteral(equals(987654321)))', flags)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('clang-query self-test: colon-path compiler diagnostic was not rejected')

        missing = Path(directory) / 'missing.cc'
        missing.write_text('#include "definitely-missing-header-7f3c.h"\nint broken;\n')
        try:
            matches(tool, missing, 'expr(isExpansionInMainFile(), integerLiteral(equals(987654321)))', flags)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('clang-query self-test: missing-header diagnostic was not rejected')

        colon_missing = Path(directory) / 'fatal:error.cc'
        colon_missing.write_text('#include "definitely-missing-header-7f3c.h"\nint broken;\n')
        try:
            matches(tool, colon_missing, 'expr(isExpansionInMainFile(), integerLiteral(equals(987654321)))', flags)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('clang-query self-test: colon-path fatal diagnostic was not rejected')

        try:
            matches(tool, file, 'expr(isExpansionInMainFile(), integerLiteral(equals(987654321)))',
                    ['--', '-std=c++23', '-target=not-a-target'])
        except RuntimeError:
            pass
        else:
            raise RuntimeError('clang-query self-test: invalid driver option was not rejected')


def test_unsigned_add_sub(tool):
    with tempfile.TemporaryDirectory() as directory:
        file = Path(directory) / 'operands.cc'
        file.write_text("""using U = unsigned;
struct S { U n; };
U next();
void test(U u, unsigned char small, int i, S s, char *p, U *values) {
    (void)(i + small);
    (void)(u - i);
    i += s.n;
    u -= 1;
    (void)(p + u);
    (void)(-values[i]);
    (void)(+next());
    (void)(static_cast<long long>(u) + i);
    (void)(i - 1u);
    (void)(p - p);
    ++i;
    (void)(i + sizeof(S)); (void)(i + (1u << 3));
}
S operator+(S, U);
S overload(S s, U n) { return s + n; }
template<class T> T add(T x) { return x + 1; }
template unsigned add(unsigned);
#define STEP(x) ((x) - 1)
int macro(unsigned short n) { return STEP(n); }
""")
        query = unsigned_add_sub('isExpansionInMainFile()')
        hits = matches(tool, file, query, ['--', '-std=c++23'])
        if sorted(int(loc.rsplit(':', 2)[1]) for loc in hits) != [*range(5, 12), 19, 20, 23]:
            raise RuntimeError(f'unsigned operand self-test failed: {hits}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--clang-query', default='clang-query')
    parser.add_argument('--inventory', type=Path, help='write unique arithmetic sites for review')
    args = parser.parse_args()
    self_test(args.clang_query)
    test_unsigned_add_sub(args.clang_query)
    database = json.loads((args.build / 'compile_commands.json').read_text())
    files = {Path(e['directory']) / e['file'] for e in database}
    units = sorted(p for p in files if p.is_relative_to(ROOT / 'src/runtime'))
    if not units:
        raise SystemExit('no runtime translation units in compilation database')
    path = '(^|/)(src/runtime|include/rut/(runtime|common)|include/core)/'
    gate, bound, signed, inventory = queries(f'isExpansionInFileMatching({json.dumps(path)})')
    unsigned = unsigned_add_sub(f'isExpansionInFileMatching({json.dumps(path)})')
    operands = set()
    findings = set()
    bounds = set()
    post_checks = set()
    sites = set()
    for file in units:
        flags = ['-p', str(args.build.resolve())]
        operands.update(matches(args.clang_query, file, unsigned, flags))
        findings.update(matches(args.clang_query, file, gate, flags))
        post_checks.update(matches(args.clang_query, file, signed, flags))
        bounds.update(matches(args.clang_query, file, bound, flags))
        if args.inventory:
            sites.update(matches(args.clang_query, file, inventory, flags))
    if args.inventory:
        sites.update(operands)
        args.inventory.write_text(''.join(p + '\n' for p in sorted(sites)))
        print(f'{len(sites)} distinct arithmetic locations')
    for p in sorted(operands):
        print(f'{p}: unsigned operand in addition or subtraction')
    for p in sorted(findings):
        print(f'{p}: unsigned arithmetic compared against zero with an invariant result')
    for p in sorted(bounds):
        print(f'{p}: unsigned addition occurs before the upper-bound check')
    for p in sorted(post_checks):
        print(f'{p}: check signed arithmetic limits before adding or subtracting one')
    print(f'{len(units)} runtime translation units, {len(operands) + len(findings) + len(bounds) + len(post_checks)} findings')
    return bool(operands or findings or bounds or post_checks)


if __name__ == '__main__':
    raise SystemExit(main())
