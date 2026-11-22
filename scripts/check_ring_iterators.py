#!/usr/bin/env python3
"""Check iterator boundary proofs on fixtures and the configured runtime C++ units."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROBE = """
namespace rut {
struct IoUringPosition {
    unsigned value;
    IoUringPosition& operator++();
    IoUringPosition operator++(int);
    IoUringPosition& operator--();
    bool operator==(const IoUringPosition&) const = default;
};
}
using P = rut::IoUringPosition;
void mutate(P&);
"""
# The expected diagnostic count also ensures the checker actually recognizes
# both operator directions. Compile-time C++ errors do not count as findings.
CASES = (
    ('checked loop', 'while (p != end && ready) { ++p; }', 0),
    ('early exit', 'if (p == end) return; p++;', 0),
    ('reverse', 'if (begin != p) --p;', 0),
    ('unchecked', '++p;', 1),
    ('wrong direction', 'if (p != end) --p;', 1),
    ('wrong cursor', 'if (other != end) ++p;', 1),
    ('wrong branch', 'if (p == end) ++p;', 1),
    ('alternate path', 'if (p != end || ready) ++p;', 1),
    ('double step', 'if (p != end) { p++; ++p; }', 1),
    ('direct reassignment', 'if (p != end) { p = end; ++p; }', 1),
    ('raw field write', 'if (p != end) { p.value = end.value; ++p; }', 1),
    ('mutable call', 'if (p != end) { mutate(p); ++p; }', 1),
    ('alias before guard', 'P &alias = p; if (p != end) { alias = end; ++p; }', 1),
    ('field increment', 'if (p != end) { ++p.value; ++p; }', 1),
    ('loop without recheck', 'if (p != end) while (ready) ++p;', 1),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('checker', type=Path)
    parser.add_argument('build', type=Path)
    args = parser.parse_args()
    tool = str(args.checker.resolve())
    with tempfile.TemporaryDirectory() as tmp:
        file = Path(tmp) / 'probe.cc'
        for name, code, expected in CASES:
            file.write_text(PROBE + 'void f(P p, P other, const P begin, const P end, bool ready) {'
                            + code + '}\n')
            result = subprocess.run([tool, str(file), '--', '-std=c++20'], capture_output=True, text=True)
            actual = result.stderr.count('error: ring iterator step requires')
            if actual != expected or bool(result.returncode) != bool(expected):
                raise SystemExit(f'{name}: expected {expected} diagnostics, got {actual}\n{result.stderr}')
    build = args.build.resolve()
    entries = json.loads((build / 'compile_commands.json').read_text())
    units = sorted({(Path(e['directory']) / e['file']).resolve() for e in entries})
    units = [p for p in units if p.is_relative_to(ROOT / 'src/runtime') and p.suffix != '.c']
    if not units:
        raise SystemExit('no runtime C++ sources in compile_commands.json')
    subprocess.run([tool, '-p', str(build), *units], check=True)
    print(f'{len(CASES)} iterator fixtures and {len(units)} runtime translation units passed')


if __name__ == '__main__':
    main()
