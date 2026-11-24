#!/usr/bin/env python3
"""Run the positive-sum checker on production compilation commands."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import plistlib
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('plugin', type=Path)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    analyzer = ['--analyze', '-Xclang', '-load', '-Xclang', str(args.plugin.resolve()),
                '-Xanalyzer', '-analyzer-checker=rut.PositiveSum',
                '-Xanalyzer', '-analyzer-config', '-Xanalyzer', 'ipa=basic-inlining']
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / 'report.plist'
        subprocess.run([args.clang, '-fsyntax-only', '-Werror=unused-result', '-Xclang',
                        '-verify=discard', '-I', ROOT / 'include', '-std=c++23',
                        ROOT / 'scripts/clang/positive_sum_cases.cc'], check=True)
        subprocess.run([args.clang, *analyzer, '-Xclang', '-verify', '-I', ROOT / 'include',
                        '-std=c++23', ROOT / 'scripts/clang/positive_sum_cases.cc',
                        '-o', report], check=True)
        entries = json.loads((args.build / 'compile_commands.json').read_text())

        def analyze(item):
            index, entry = item
            cwd = Path(entry['directory'])
            file = (cwd / entry['file']).resolve()
            if not file.is_relative_to(ROOT / 'src') or file.suffix not in {'.cc', '.cpp', '.c'}:
                return 0, False
            command = entry.get('arguments') or shlex.split(entry['command'])
            # CMake may prefix the compiler with ccache.
            start = 2 if Path(command[0]).name == 'ccache' else 1
            flags = command[start:]
            output = flags.index('-o')
            del flags[output:output + 2]
            flags.remove('-c')
            subprocess.run([args.clang, *flags, '-fsyntax-only', '-Werror=unused-result'],
                           cwd=cwd, check=True)
            # Only declarations visible in this build configuration can impose
            # a contract. Preprocess with the actual defines and include paths.
            source = subprocess.check_output([args.clang, *flags, '-E', '-w'], cwd=cwd)
            contracts = (b'"rut_positive"', b'"rut_positive_sum"', b'"rut_representable"')
            if not any(contract in source for contract in contracts):
                return 0, False
            failed = False
            report = Path(tmp) / f'{index}.plist'
            run = subprocess.run([args.clang, *flags, *analyzer, '-o', report], cwd=cwd,
                                 capture_output=True, text=True)
            if run.returncode:
                raise RuntimeError(f'Clang analysis failed for {file}\n{run.stderr}')
            with report.open('rb') as stream:
                results = plistlib.load(stream)
            for finding in results['diagnostics']:
                if finding['check_name'] == 'rut.PositiveSum':
                    loc = finding['location']
                    print(f"{results['files'][loc['file']]}:{loc['line']}:{loc['col']}: "
                          f"{finding['description']}", flush=True)
                    failed = True
            return 1, failed

        with ThreadPoolExecutor(max_workers=args.jobs) as workers:
            results = list(workers.map(analyze, enumerate(entries)))
        checked = sum(count for count, _ in results)
        failed = any(finding for _, finding in results)
        if not checked:
            raise SystemExit('no production translation unit with a positive integer contract')
        print(f'Checked positive integer contracts in {checked} production translation units')
        return failed


if __name__ == '__main__':
    raise SystemExit(main())
