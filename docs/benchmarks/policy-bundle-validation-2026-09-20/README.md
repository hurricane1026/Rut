# Complete-buffering policy validation benchmark

Baseline runtime: `b088feb36891207e47b382d8af86f5743e308039` (the body-pump ready-set optimization in #657).
Candidate runtime: `8d4c90948bb5167d7a066828c8ccb96dd23cb67a`.

Within one `RouteConfig::policy_bundle_id_is_valid` call, validate the response, failure and timeout policy shapes once, then check the complete-buffering tuple. Public validation helpers and the non-buffering path remain unchanged; there is no validation cache across requests or callbacks.

## Results

Median RPS; keepalive c1/c32 and close c32 use six samples per engine/variant from B/C/C/B; other cells use three from B/C regression phases. nginx is the control measured alongside the candidate.

| Connection | Concurrency | Baseline RPS | Candidate RPS | nginx RPS | Candidate/baseline | Candidate/nginx |
|---|---:|---:|---:|---:|---:|---:|
| keepalive | 1 | 8,808 | 8,960 | 9,816 | 1.017x | 0.913x |
| keepalive | 32 | 15,446 | 15,976 | 15,074 | 1.034x | 1.060x |
| keepalive | 128 | 16,114 | 16,406 | 15,051 | 1.018x | 1.090x |
| close | 1 | 6,584 | 6,673 | 6,879 | 1.013x | 0.970x |
| close | 32 | 11,515 | 11,766 | 12,592 | 1.022x | 0.934x |
| close | 128 | 11,628 | 12,232 | 12,569 | 1.052x | 0.973x |

| Connection | Concurrency | Baseline p99 (us) | Candidate p99 (us) | nginx p99 (us) | Baseline CPU (us/request) | Candidate CPU (us/request) |
|---|---:|---:|---:|---:|---:|---:|
| keepalive | 1 | 150.0 | 152.5 | 141.5 | 66.90 | 64.28 |
| keepalive | 32 | 2,302.0 | 2,212.5 | 2,321.0 | 39.83 | 37.67 |
| keepalive | 128 | 8,450.0 | 8,854.0 | 8,903.0 | 38.00 | 36.22 |
| close | 1 | 157.0 | 154.0 | 135.0 | 82.24 | 80.03 |
| close | 32 | 2,998.5 | 2,972.5 | 2,701.5 | 52.75 | 50.99 |
| close | 128 | 11,758.0 | 11,393.0 | 10,805.0 | 51.80 | 48.44 |

This is an incremental gain over #657, not evidence of an across-the-board nginx win. Keepalive c1 p99 moved from 150 to 152.5 us, with overlapping sample ranges and opposite C1/C2 movement; no consistent tail-latency improvement is claimed. Keepalive c128 median p99 increased 4.8% (8,450 to 8,854 us). The first close c32 comparison showed a p99 increase of 11.3%; the reverse-order confirmation did not reproduce it, and all six samples per variant yield 2,998.5 versus 2,972.5 us. Both phases remain in the data.

## Method and scope

- Same 16,384 connection slots, one shard/worker, clang22 Release project -O2, JIT ON, IPO OFF.
- Intel Core i7-10700; frontend CPU 2, origin CPU 3, wrk CPUs 4–5 on distinct physical cores. No frequency lock or exclusive reservation. No builds or test suites during measurement.
- Cleartext HTTP, 1 KiB proxy responses, upstream keepalive disabled for both engines; downstream implicit keepalive or close.
- Pinned nginx `nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.
- Eight-second samples after two-second warmups, three repetitions per phase. Actual order: keepalive c1/c32 B1,C1,C2,B2; close c1/c32/c128 B,C; keepalive c128 B,C; then close c32 C,B to investigate a tail-latency signal.
- All 108 samples valid, at least eight seconds, with zero request or warmup errors. Static routes, TLS performance and other response sizes were not measured.

Reproduction uses the [same harness and controls as #657](../proxy-body-ready-set-2026-09-20/README.md#method-and-reproduction), substituting the pinned binaries and the phase-specific concurrency list.

Baseline binary SHA-256: `4605569aea71d4de19161d96dad0e51c33a81c68b6a232abc835d97dc528729f`.
Candidate binary SHA-256: `114ee32e033315a35537f8795ed97f8ee66688ce504d99ce86f0f40965a7fab2`.

## Validation and evidence

Builds of rut, test_network and test_integration passed. Full network run passed 1,254 cases with two io_uring-unavailable skips; both skipped cases passed isolated reruns after integration completed. Both integration shards passed. Negative tests cover invalid role IDs and shapes, tuple constraints, timeout-only and None-buffering compatibility, and valid/malformed/restored policies. Independent Luna correctness review passed.

Measured rows are in [samples.csv](samples.csv). Full logs, binary hashes, phase environments and raw responses remain locally under `.cache/perf-evidence/policy-bundle-validation/` in the main checkout.

Raw local evidence archive: `.cache/perf-evidence/policy-bundle-validation-2026-09-20.tar.gz` (SHA-256 `88961d8e5990e191c806b1908756832df14f62335395de50063c955a44ea76e3`).
