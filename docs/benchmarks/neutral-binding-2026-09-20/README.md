# Neutral exact-response binding check benchmark

Benchmark runs used baseline `56d90fa14da0081b117b1f04b7451a9c462e2b0b` and candidate `242e23fc29e73b8243ff1c22ee0791440f498f45`.
Runtime SHA-256 baseline/candidate: `9ab41e1b92ca3fbdee6ba37b8bf353b93c0a5da8797cfa3adc9cf968e07af658` / `f5de83216479516bf0c12a4fcc2bd361699641de243d91cc704e94e2e77e921b`.
Converter SHA-256 baseline/candidate: `1e5505b58f5392384070b9b8f64053573f51b8fbeaab1ba7b50ccef074e6c3bc` / `1e5505b58f5392384070b9b8f64053573f51b8fbeaab1ba7b50ccef074e6c3bc`; wrk SHA-256: `d2469ea6ec7cd969c602aa7f69056e4c875b8f496884e8e5f74a013ac14d9de5` (source `a211dd5a7050b1f9e8a9870b95513060e72ac4a0`).
Nginx image: `nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.
Compiler/build: Release clang22 JIT ON IPO OFF, project -O2; both phases recorded the same build mode.
Host CPU: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz (8 cores / 16 threads); server CPU 2, origin CPU 3, wrk client CPUs 4–5.
Services used host networking, one Rut shard, and one nginx worker; upstream keepalive was disabled at both ends. No frequency lock or exclusive CPU reservation was used.
Runs lasted 8 seconds after a 2-second warmup, with 3 repetitions; all 168 rows are valid, ≥8s, and have zero request/warmup errors.

## Results

Phase 1 is static HTTP keepalive, 16-byte response body, concurrency 128; combined candidate/baseline median RPS was **+7.81%**.

| Variant | RUT median RPS | RUT/nginx factor |
|---|---:|---:|
| Baseline B1+B2 | 180,156 | 1.40x |
| Candidate C1+C2 | 194,218 | 1.44x |

Phase 2 covers static/proxy, close/keepalive, and concurrency 1/32/128.

| Scenario | C | Baseline RPS | Candidate RPS | C/B | B RUT/nginx | C RUT/nginx |
|---|---:|---:|---:|---:|---:|---:|
| static-close | 1 | 14,175 | 14,196 | +0.14% | 1.00x | 1.00x |
| static-close | 32 | 36,828 | 38,693 | +5.06% | 0.89x | 0.94x |
| static-close | 128 | 40,523 | 41,592 | +2.64% | 0.98x | 1.01x |
| static-keepalive | 1 | 50,890 | 51,687 | +1.57% | 1.02x | 1.03x |
| static-keepalive | 32 | 174,924 | 187,243 | +7.04% | 1.32x | 1.42x |
| static-keepalive | 128 | 179,788 | 192,996 | +7.35% | 1.38x | 1.48x |
| proxy-close | 1 | 4,493 | 4,502 | +0.22% | 0.63x | 0.63x |
| proxy-close | 32 | 10,454 | 10,560 | +1.02% | 0.83x | 0.83x |
| proxy-close | 128 | 11,687 | 11,723 | +0.31% | 0.92x | 0.93x |
| proxy-keepalive | 1 | 4,940 | 4,991 | +1.05% | 0.47x | 0.48x |
| proxy-keepalive | 32 | 13,758 | 13,909 | +1.10% | 0.88x | 0.89x |
| proxy-keepalive | 128 | 15,467 | 15,537 | +0.45% | 1.00x | 1.01x |

Sub-percent phase 2 deltas are within run-to-run variation; the repeatable result is static keepalive at c32 and c128.

Diagnostic `cycles:u` profiles: baseline 3,984 samples; candidate 3,988 (0 lost). Strict-table self share was 35.10%→8.21%; libc `memcmp` accounted for 6.07% of candidate self samples. This is a shift in sampled user cycles, not a whole-system CPU gain.

## Reproduction

Execution order was phase 1 `B1 → C1 → C2 → B2`, then phase 2 `B → C`; substitute local checkout paths below and keep the pinned binaries, image, wrk build, and CPU placement.

```sh
BASE=/path/to/Rut-perf-baseline
CAND=/path/to/Rut-perf-date
WRK=/path/to/wrk
RUNNER="$BASE/scripts/nginx_benchmark/run.py"
for ROUND in b1 c1 c2 b2; do
  case "$ROUND" in b1|b2) TREE="$BASE";; *) TREE="$CAND";; esac
  OUT="results/phase1-$ROUND"
  python3 "$RUNNER" --rut "$TREE/build/src/rut" --converter "$TREE/build/src/rut-nginx-convert" --wrk "$WRK" --output "$OUT" --server-cpu 2 --origin-cpu 3 --client-cpus 4,5 --keepalive-header implicit --scenarios static-keepalive --concurrency 128 --body-size 16 --duration 8 --warmup 2 --repeats 3
done
for TREE in "$BASE" "$CAND"; do
  OUT="results/phase2-$(basename "$TREE")"
  python3 "$RUNNER" --rut "$TREE/build/src/rut" --converter "$TREE/build/src/rut-nginx-convert" --wrk "$WRK" --output "$OUT" --server-cpu 2 --origin-cpu 3 --client-cpus 4,5 --keepalive-header implicit --scenarios static-close static-keepalive proxy-close proxy-keepalive --concurrency 1 32 128 --duration 8 --warmup 2 --repeats 3
done
```

## Scope and data

The 168-row CSV includes validity, timing, request/warmup errors, p99, and CPU observations; only this compact CSV is published, while full logs and baseline/candidate profile captures remain local in `.cache/perf-evidence/neutral-binding-2026-09-20.tar.gz` (SHA-256 `d67b2be34d886b372ee42851e7954765a5dc4e55156eee6e22540c18d8a1afaf`).
TLS, large response bodies, and the 96-cell expanded matrix were not covered.
RUT/nginx factors are sequential controls within each phase; no cross-engine normalization is applied.
