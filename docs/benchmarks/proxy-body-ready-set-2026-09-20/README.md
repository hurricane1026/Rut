# Proxy body-pump ready-set benchmark

Baseline runtime: `8af7134915a1c7bfcb74cecc65a4ecba511cf930` (squash tree identical to the built `eddcf3196c0ab631dc970b929009458e240f84d7`).
Candidate runtime: `b088feb36891207e47b382d8af86f5743e308039`.

The candidate replaces the pending response-body pump scan over every Connection with a compact ready bitmap. Both binaries use the same default 16,384 slots, one shard, and the same protocol and response validation paths.

## Results

Median throughput; keepalive uses six samples per engine/variant, close uses three. The nginx column is the control measured with the candidate.

| Proxy connection | Concurrency | Baseline RPS | Candidate RPS | nginx RPS | Candidate/baseline | Candidate/nginx |
|---|---:|---:|---:|---:|---:|---:|
| keepalive | 1 | 4,940 | 8,833 | 9,879 | 1.788x | 0.894x |
| keepalive | 32 | 13,779 | 15,491 | 15,132 | 1.124x | 1.024x |
| keepalive | 128 | 15,335 | 16,015 | 15,074 | 1.044x | 1.062x |
| close | 1 | 4,456 | 6,618 | 6,876 | 1.485x | 0.963x |
| close | 32 | 10,088 | 11,790 | 12,562 | 1.169x | 0.939x |
| close | 128 | 11,346 | 11,980 | 12,605 | 1.056x | 0.950x |

The large, repeatable improvement is low-concurrency proxy throughput. This does **not** establish an across-the-board win over nginx: keepalive c1 and all three close cells remain behind nginx; the c32 keepalive lead is small.

| Proxy connection | Concurrency | Baseline p99 (us) | Candidate p99 (us) | nginx p99 (us) | Baseline CPU (us/request) | Candidate CPU (us/request) |
|---|---:|---:|---:|---:|---:|---:|
| keepalive | 1 | 252.5 | 155.5 | 142.5 | 157.10 | 66.70 |
| keepalive | 32 | 2,626.0 | 2,243.0 | 2,259.5 | 47.40 | 39.66 |
| keepalive | 128 | 8,929.0 | 9,237.0 | 9,033.5 | 40.62 | 38.15 |
| close | 1 | 250.0 | 158.0 | 141.0 | 169.93 | 81.94 |
| close | 32 | 3,540.0 | 2,901.0 | 2,780.0 | 64.62 | 51.40 |
| close | 128 | 12,290.0 | 11,375.0 | 10,710.0 | 54.87 | 50.45 |

CPU/request is derived from the measured frontend process CPU time and completed requests. Tail latency varied substantially: candidate keepalive c128 phase medians were 10,008 us in C1 and 8,394 us in C2. The combined median is 3.4% above the baseline; this change does not claim a consistent p99 improvement at every concurrency.

## Method and reproduction

- Intel Core i7-10700; server CPU 2, origin CPU 3, wrk CPUs 4–5 (distinct physical cores). No frequency lock or exclusive CPU reservation. No builds or test suites ran during benchmark samples.
- Release clang22, project `-O2`, JIT ON, IPO OFF; same converter and wrk for every phase.
- Pinned nginx `nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`, one worker, host networking.
- Cleartext HTTP, 1 KiB proxy body, upstream keepalive disabled on both frontends; downstream close/implicit HTTP/1.1 keepalive as shown.
- Eight-second measurements after two-second warmups, three repetitions. All 108 rows are valid, at least eight seconds long, with zero warmup/request errors.
- Actual phase order: keepalive B1, close B, keepalive C1, C2, B2, then close C. Binary copies were immutable during measurement.

Using the repository harness, substitute the pinned baseline/candidate binary paths and a fresh output directory for each phase:

```sh
python3 scripts/nginx_benchmark/run.py \
  --rut /path/to/pinned-rut-binary --converter /path/to/rut-nginx-convert \
  --wrk /path/to/wrk --output /path/to/new-output \
  --server-cpu 2 --origin-cpu 3 --client-cpus 4,5 \
  --keepalive-header implicit --body-size 1024 \
  --scenarios proxy-keepalive --concurrency 1 32 128 \
  --duration 8 --warmup 2 --repeats 3
```

For close phases change the scenario to `proxy-close`. Keep identical startup capacity and CPU placement. A local Docker daemon and access to the pinned image are required; on this SELinux host the dedicated bind-mount directory was labeled `container_file_t`.

## Provenance and scope

Baseline binary SHA-256: `ae71e1c07a43a1fc675fd720325a0c1dfe6bfb2570740200df51c9ad0dfe88bb`.
Candidate binary SHA-256: `4605569aea71d4de19161d96dad0e51c33a81c68b6a232abc835d97dc528729f`.
Harness `run.py` SHA-256: `928f40928c80d775ba00ac14dc8cd01716bf746ef127b7187847cce5b13943dc`.
Converter SHA-256: `1e5505b58f5392384070b9b8f64053573f51b8fbeaab1ba7b50ccef074e6c3bc`.
wrk SHA-256: `d2469ea6ec7cd969c602aa7f69056e4c875b8f496884e8e5f74a013ac14d9de5` (source `a211dd5a7050b1f9e8a9870b95513060e72ac4a0`).

The complete measured rows are in [samples.csv](samples.csv). Full local evidence, test logs, provenance, and diagnostic captures are retained under `.cache/perf-evidence/proxy-ready-set/` in the main checkout. The diagnostic profile is separate from these acceptance samples.

Local correctness validation: all 1,254 network tests (325,612 checks), both integration shards, and a targeted ASan/UBSan ready-set probe passed. The sanitizer probe covers header-defined ready-set/storage behavior and links the ordinary runtime library; it is not a claim of a fully sanitizer-built runtime suite.

Static routes, TLS performance, other body sizes, and the full expanded matrix were not measured in this comparison.

A separate candidate c1 diagnostic recorded `cycles:u` at 499 Hz with zero lost samples: `dispatch_batch` self share was 2.23%, while failure-policy shape validation and response-policy validation accounted for 19.36% and 12.40%. These are userspace sample shares, not wall-time percentages or another acceptance run.

Raw evidence archive: `.cache/perf-evidence/proxy-body-ready-set-2026-09-20.tar.gz` (SHA-256 `4fec29ceed02ad411c216a5298aab6dfcf8f5423324973be2f1ad10f1aef99f8`).
