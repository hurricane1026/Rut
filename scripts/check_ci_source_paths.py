#!/usr/bin/env python3
"""Check that compiler launchers preserve absolute __FILE__ fixture paths."""

import argparse
from pathlib import Path
import subprocess
import tempfile


PROGRAM = r'''
#include <stdio.h>
#include <string.h>
int main(void) {
    const char* source = __FILE__;
    if (source[0] != '/') return 2;
    const char* slash = strrchr(source, '/');
    char fixture[4096];
    int length = snprintf(fixture, sizeof(fixture), "%.*s/fixture.txt",
                          (int)(slash - source), source);
    if (length < 0 || length >= (int)sizeof(fixture)) return 3;
    FILE* input = fopen(fixture, "r");
    if (!input) return 4;
    int value = fgetc(input);
    fclose(input);
    return value == 'R' ? 0 : 5;
}
'''


def check(compiler, launcher=None):
    # Keep the probe inside the checkout so a workspace-wide base_dir would
    # rewrite its source path just like the real test sources.
    with tempfile.TemporaryDirectory(prefix='rut-ci-source-paths-', dir=Path.cwd()) as directory:
        root = Path(directory)
        for name in ('source', 'build', 'run'):
            (root / name).mkdir()
        source = root / 'source' / 'probe.c'
        source.write_text(PROGRAM)
        (root / 'source' / 'fixture.txt').write_text('Rut fixture\n')
        # Compile twice: both the initial compilation and cached output must
        # locate fixtures independently of the test's working directory.
        for index in range(2):
            obj = root / 'build' / f'probe-{index}.o'
            binary = root / 'build' / f'probe-{index}'
            subprocess.run(([launcher] if launcher else []) + [
                compiler, '-c', str(source), '-o', str(obj)],
                cwd=root / 'build', check=True)
            subprocess.run([compiler, str(obj), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], cwd=root / 'run', check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True)
    parser.add_argument('--launcher')
    args = parser.parse_args()
    check(args.compiler, args.launcher)
    print('Compiler source paths and fixture lookup verified across working directories')


if __name__ == '__main__':
    main()
