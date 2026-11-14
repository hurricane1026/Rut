#!/usr/bin/env python3
"""Exercise CRL store ownership and validation without JIT, including sanitizers."""
import argparse
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--helper', required=True)
parser.add_argument('--testdata', required=True)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='rut-crl-context-') as directory:
    subprocess.run([args.helper, args.testdata, directory], check=True, timeout=10)
    subprocess.run([args.helper, args.testdata, directory, '--verify'], check=True, timeout=10)
print('PASS: CRL context construction/ownership, strict validation and CA-only compatibility')
