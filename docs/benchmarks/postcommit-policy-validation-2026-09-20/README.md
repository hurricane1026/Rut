# Post-commit policy validation fast path benchmark

This report covers a narrow runtime optimization for the existing Complete
content-length response path. During one synchronous call,
`response_read_deadline_post_commit_is_stable` reuses the already successful
Complete policy-bundle proof and its binding checks instead of repeating the
same role validation. The `None` buffering path keeps its strict role checks.
No policy result is cached across callbacks or calls.

This is a bounded performance result for a 1 KiB HTTP proxy response. It does
not establish results for TLS, other response sizes, or other workloads.

## Measurements

The table shows the median of retained RUT runs for each variant and cell.
`Δ` compares candidate with baseline. Close concurrency 32 and 128 include the
additional reverse-order confirmation runs in the reported medians. The p99
column is the median of per-run p99 values, not a percentile recomputed from
merged histograms.

| Connection | Concurrency | Baseline RPS | Candidate RPS | Δ RPS | Baseline p99 µs | Candidate p99 µs | Δ p99 | Baseline CPU µs/req | Candidate CPU µs/req | Δ CPU |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Keepalive | 1 | 9,542 | 9,664 | +1.28% | 145.5 | 143.0 | −1.72% | 59.94 | 58.23 | −2.85% |
| Keepalive | 32 | 17,988 | 18,315 | +1.82% | 1,945 | 1,926 | −0.98% | 34.52 | 33.37 | −3.36% |
| Keepalive | 128 | 18,761 | 19,320 | +2.98% | 7,410 | 7,041 | −4.98% | 32.73 | 31.37 | −4.15% |
| Close | 1 | 7,098 | 7,175 | +1.09% | 146.0 | 141.0 | −3.42% | 74.97 | 73.52 | −1.94% |
| Close | 32 | 13,332 | 13,406 | +0.55% | 2,505.5 | 2,528.0 | +0.90% | 45.55 | 44.81 | −1.64% |
| Close | 128 | 13,608 | 13,494 | **−0.83%** | 9,887.5 | 9,890.5 | +0.03% | 44.48 | 44.57 | **+0.20%** |

The close-128 result is a measured loss: throughput fell 0.83% and CPU per
request rose 0.20%, while p99 was effectively flat. The initial close-32
B/C comparison showed candidate median p99 2,832 µs versus baseline 2,519 µs
(+12.4%). A reverse-order C/B confirmation measured 2,489 versus 2,465 µs
(+1.0%); combining the six runs per variant gives 2,528 versus 2,505.5 µs
(+0.9%). The initial tail result is retained here rather than replaced by the
confirmation.

At keepalive concurrency 1, candidate RUT delivered 9,664 RPS against nginx
at 9,882 RPS, remaining about 2.2% behind that control. The concurrency 32
and 128 cells were above nginx in these measurements. These results describe
only the stated 1 KiB HTTP workload.

All 120 rows in `samples.csv` are valid; measured and warmup error counters
are zero. The primary keepalive concurrency-1/32 order was B,C,C,B. Other
initial cells used B,C order; close concurrency-32/128 additionally used C,B
confirmation runs. Raw run data and commands remain in the local evidence phase subdirectories.

## Environment and reproducibility

- Host: Intel Core i7-10700, x86_64, Linux 6.19.10-300.fc44.x86_64.
- Compiler/build: clang22 Release, project `-O2`, JIT ON, IPO OFF.
- No frequency lock or exclusive machine reservation; no builds or tests during measurement.
- Fixed runtime connection capacity: 16,384 for baseline and candidate.
- One RUT shard, server CPU 2, origin CPU 3, wrk client CPUs 4 and 5.
- nginx control: host networking, pinned image
  `nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.
- Upstream keepalive disabled for both engines; nginx frontend uses one worker.
- Plain HTTP/1.1 proxy, 1,024-byte response, 2-second warmup and 8-second
  measured runs, three repeats. Keepalive uses the implicit HTTP/1.1 default;
  close cells send `Connection: close`.
- The harness validates the proxy response before measurement; all warmup and
  measured connect/read/write/status/timeout counters are zero. Each frontend
  run is a separate process; RUT is native while nginx runs in a host-networked
  container, so that execution difference remains part of the comparison.
- RUT runtime command uses one shard, `--no-pin`, drain 1 and optimization 2.
  Nginx frontend and origin are pinned as recorded in the per-phase command and
  environment files.

Source and binary provenance:

| Item | Revision or SHA-256 |
|---|---|
| Baseline runtime | `b90459b114832b37d576f21d4f96a24479a25c97` |
| Candidate runtime | `51cd6f2ccdd45a960fb53b5b4aa36a2f0ad52b74` |
| Source and test snapshot | `ef1e73e55b52c1f89cf5944d008841734cdea348` |
| Baseline RUT binary | `209cb8b7f0c38a05e3097dcfee8aea6a4255bec083e310811f21d15c68ffe346` |
| Candidate RUT binary | `9ef971fb25949099061580b06a031c52901f7b523f97d86392b31b4bd0b971a2` |
| Converter binary | `1e5505b58f5392384070b9b8f64053573f51b8fbeaab1ba7b50ccef074e6c3bc` |
| wrk binary | `d2469ea6ec7cd969c602aa7f69056e4c875b8f496884e8e5f74a013ac14d9de5` |

Published measurements are in [samples.csv](samples.csv). Detailed provenance,
commands, environment captures, and raw phase files remain locally in the main
checkout under `.cache/perf-evidence/postcommit-policy-validation/`.

Reproduction uses the [same harness and controls as #657](../proxy-body-ready-set-2026-09-20/README.md#method-and-reproduction), substituting the binaries and phase-specific concurrency lists recorded above.

## Review and validation

- Independent Luna source review: **APPROVED** (`review.txt`).
- Astra final architecture/performance/ready gate: **PASS**.
- Build: runtime, network and integration targets passed.
- Network: all 1,267 tests passed, 326,161 checks, zero failures/skips.
- Integration: both shards passed in 246.49 seconds.
- The initial new None fixture omitted deadline arming and failed its phase
  precondition. Adding that setup call preserved all strict assertions; the
  entire network suite then passed. The initial failure log is retained.
- New tests cover fresh valid-but-different role bindings, mutation/restore,
  None bundles with missing roles, and Combined frame corruption.
- Local evidence archive: `.cache/perf-evidence/postcommit-policy-validation-2026-09-20.tar.gz`
  (SHA-256 `cc71b881c018a293a65c33567c1adaa6a73cc54552b4fbd3bc181c220f1548ba`).
