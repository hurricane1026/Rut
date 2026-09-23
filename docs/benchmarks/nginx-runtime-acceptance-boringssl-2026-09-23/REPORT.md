# BoringSSL native-body full-96 acceptance report

## Verdict

**Raw verification: PASS. Performance gate: FAIL.** The run contains 96/96 coordinates and 576/576 raw samples. Every cell has nginx and Rut repetitions 1, 2, and 3; each sample ran for at least 5 seconds with zero warmup and measurement errors. Independent medians and ratios match the matrix.

The target is a Rut/nginx median requests-per-second ratio of at least 1.10:

| Transport | Body | Passed | Below 1.10 | Invalid | Total |
|---|---:|---:|---:|---:|---:|
| HTTP | 16 B | 9 | 3 | 0 | 12 |
| HTTP | 1 KiB | 10 | 2 | 0 | 12 |
| HTTP | 64 KiB | 6 | 6 | 0 | 12 |
| HTTP | 1 MiB | 0 | 12 | 0 | 12 |
| HTTPS | 16 B | 12 | 0 | 0 | 12 |
| HTTPS | 1 KiB | 12 | 0 | 0 | 12 |
| HTTPS | 64 KiB | 11 | 1 | 0 | 12 |
| HTTPS | 1 MiB | 3 | 9 | 0 | 12 |
| **Total** |  | **63** | **33** | **0** | **96** |

The complete 96-cell table is [cells.csv](cells.csv); independent raw checks are in [verification.json](verification.json). Extreme examples are HTTPS static-close 1 MiB/c1 at `0.012053`, HTTP static-keepalive 1 MiB/c1 at `0.006899`, and HTTP static-close 16 B/c32 at `1.316712`.

## Provenance and conditions

Measured source is `12bd10e9e84a7f3a6df9af54a4c543416f470dfd`, with base main `f53401d7`. The verifier resolved `origin` to `git@github.com:hurricane1026/Rut.git`, fetched `refs/heads/perf/quick-nginx-benchmark` into an isolated temporary bare repository, and proved the source commit is an ancestor of the advertised head. It verified SHA-256 entries for Rut, converter, patched `wrk`, and the decompressed [wrk-boringssl-full-handshake.patch.gz](wrk-boringssl-full-handshake.patch.gz). Details are in [provenance.json](provenance.json) and [verification.json](verification.json).

The runner used clang 22.1.8 Release with `-O3 -DNDEBUG`; nginx was image `nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`, version 1.29.7. HTTPS used BoringSSL full handshakes and the public [certificate.pem](certificate.pem). The corresponding private key was used only by the runner and is excluded from this archive and [evidence.tar.gz](evidence.tar.gz). Host CPU, OS, and pinning are measurement context in [environment.json](environment.json), not tuning claims.

This directory is the canonical BoringSSL native-body record. Existing converter/native and earlier runtime acceptance directories are historical records and were not modified.
