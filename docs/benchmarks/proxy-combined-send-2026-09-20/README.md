# Bounded complete-response combined-send benchmark

Baseline runtime: `8d4c90948bb5167d7a066828c8ccb96dd23cb67a` (the policy-validation optimization in #658).
Candidate runtime: `b90459b114832b37d576f21d4f96a24479a25c97`. Later commits change tests and documentation only.

For an eligible, complete positive cleartext GET response, copy the body into unused space in the existing header slice and submit header plus body together. Keep the logical header length unchanged and use an explicit Combined owner, phase and callback. Capacity misses and noneligible profiles retain the existing path; timer, retirement and request-boundary proofs remain in place.

## Results

Median RPS; keepalive uses six samples per engine/variant from B/C/C/B; close uses three from B/C regression phases. nginx is the control measured alongside the candidate.

| Connection | Concurrency | Baseline RPS | Candidate RPS | nginx RPS | Candidate/baseline | Candidate/nginx |
|---|---:|---:|---:|---:|---:|---:|
| keepalive | 1 | 8,981 | 9,523 | 9,891 | 1.060x | 0.963x |
| keepalive | 32 | 16,008 | 17,963 | 15,150 | 1.122x | 1.186x |
| keepalive | 128 | 16,663 | 18,715 | 15,100 | 1.123x | 1.239x |
| close | 1 | 6,683 | 7,099 | 6,853 | 1.062x | 1.036x |
| close | 32 | 12,117 | 13,347 | 12,613 | 1.101x | 1.058x |
| close | 128 | 12,214 | 13,682 | 12,639 | 1.120x | 1.083x |

| Connection | Concurrency | Baseline p99 (us) | Candidate p99 (us) | nginx p99 (us) | Baseline CPU (us/request) | Candidate CPU (us/request) |
|---|---:|---:|---:|---:|---:|---:|
| keepalive | 1 | 154.0 | 147.5 | 142.0 | 64.06 | 60.02 |
| keepalive | 32 | 2,216.5 | 1,973.5 | 2,355.5 | 37.48 | 34.61 |
| keepalive | 128 | 8,373.0 | 7,321.5 | 9,380.5 | 35.66 | 32.90 |
| close | 1 | 157.0 | 148.0 | 140.0 | 79.80 | 74.79 |
| close | 32 | 2,797.0 | 2,585.0 | 2,686.0 | 49.35 | 45.70 |
| close | 128 | 11,072.0 | 9,602.0 | 10,752.0 | 48.64 | 44.34 |

This candidate leads nginx throughput in five of the six measured cells, but keepalive c1 remains 3.7% behind. All six median p99 values improve against the immediately preceding Rut baseline; Rut still trails nginx p99 at c1 for both connection modes. This is not a general claim of superiority across body sizes, TLS, hardware or all latency percentiles.

The nginx baseline keepalive c1 control contains a p99 outlier of 591 us and the candidate-period c32 control contains a 2,849 us outlier. All samples are retained; reported comparisons use medians.

## Method and scope

- Same 16,384 connection slots, one shard/worker, clang22 Release project -O2, JIT ON, IPO OFF.
- Intel Core i7-10700; frontend CPU 2, origin CPU 3, wrk CPUs 4–5 on distinct physical cores. No frequency lock or exclusive reservation. No builds or test suites during measurement.
- Cleartext HTTP, 1 KiB proxy responses, upstream keepalive disabled for both engines; downstream implicit keepalive or close.
- Pinned nginx `nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.
- Eight-second samples after two-second warmups, three repetitions per phase. Actual order: keepalive c1/c32/c128 B1,C1,C2,B2, then close c1/c32/c128 B,C.
- All 108 samples valid, at least eight seconds, with zero request or warmup errors. Static routes, TLS performance and other response sizes were not measured.

Reproduction uses the [same harness and controls as #657](../proxy-body-ready-set-2026-09-20/README.md#method-and-reproduction), substituting the pinned binaries and the phase-specific concurrency list.

Baseline binary SHA-256: `114ee32e033315a35537f8795ed97f8ee66688ce504d99ce86f0f40965a7fab2`.
Candidate binary SHA-256: `209cb8b7f0c38a05e3097dcfee8aea6a4255bec083e310811f21d15c68ffe346`.

## Validation and evidence

All 1,265 network tests (326,036 checks, no skips) and both integration shards passed. Nine Combined-send tests (366 checks) passed an ASan/UBSan-instrumented test translation unit and header-defined runtime probe; the static runtime libraries were ordinary builds, so this is not a fully sanitizer-built runtime suite. Tests cover capacity equality/overflow, frame and owner corruption, actual backend completion processing across partial-send boundaries, partial send followed by EPIPE/ECONNRESET, duplicate events, and target/cancel ordering with retained slices. Independent Luna source/test review passed.

Measured rows are in [samples.csv](samples.csv). Full logs, binary hashes, phase environments and raw responses remain locally under `.cache/perf-evidence/proxy-combined-send/` in the main checkout.

Raw local evidence archive: `.cache/perf-evidence/proxy-combined-send-2026-09-20.tar.gz` (SHA-256 `91f82dc7daf9808fd2f18c2ef50b5705b1d0c4d765a3c8d89173ea981683fd5f`).
