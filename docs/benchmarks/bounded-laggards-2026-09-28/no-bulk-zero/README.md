# Bulk response buffers without payload clearing

The user explicitly requested removing payload clearing after the nginx source
comparison. This changes the bulk allocator contract: cached bulk buffers may
contain bytes from previous responses. Ordinary 16 KiB slices retain their
zero-on-return contract. No allocation size, idle cache limit, read-ahead limit,
release boundary or timer policy changes.

## Implementation

- `SlicePool::free_bulk` returns hot buffers to the free stack without writing
  their payload. Excess buffers still use MADV_DONTNEED to reclaim resident
  pages on Linux. Discard success is not a prerequisite for correct reuse.
- `alloc_bulk` explicitly documents uninitialized contents; callers must set
  metadata and publish only bytes actually received or copied.
- Remove the obsolete `free_written` helper. Response chains return nodes
  through `free`, which routes bulk and ordinary slices separately.
- ResponseBodyChain initializes next/len/offset before use. Direct recv grows
  the valid range only through commit; append copies exactly its valid bytes.
- The other bulk consumers, take_relay_recv_buffer and
  upgrade_upstream_recv_to_bulk, retain their existing initialized-length and
  asynchronous-owner checks. No recv/send pinning or completion behavior changes.

## Regression coverage

Pool tests now check address routing, duplicate/misaligned returns, retained
payload and the resident cache bound under the new contract. Ordinary-slice
zeroing tests remain unchanged.

New chain tests prefill an entire bulk node, including pointer and length
metadata, with 0xa5. They exercise append, direct short receive, partial consume,
a fully consumed tail pinned by a pending recv, subsequent commit, early release,
and the next response reusing that node. They verify that only the new valid
range is visible even when old bytes remain immediately after it.

This is a deliberate removal of idle bulk-payload erasure, not a promise that
unused memory contains zeros. Valid-range enforcement remains mandatory.

## Validation

- clang 22 Release build: runtime, test_arena and test_network passed.
- Complete test_network: 1423 passed, 338612 checks, zero failures.
- Complete test_arena: 68 passed, 1073511 checks, zero failures.
- Eleven nginx CTest entries passed, including the general differential suite
  and ten targeted default-buffering/status/timeout cases (81.13 s total).
- clang-format 20 check passed for all four changed source/test files.
- git diff --check passed.

Performance measurements are below. The full integration suite and
full 48-cell performance matrix were not run for this change.


## Performance

Intel i7-10700, clang 22 Release, one Rut shard and one nginx worker. Server
CPU 2, origin CPU 3, wrk CPUs 4,5; no CPU frequency lock or exclusive host.
Converter-strict proxy, upstream reuse disabled. Each phase used 3 repetitions,
1 s warmup and 5 s measurement; nginx/Rut order alternated per repetition.
For HTTP 1 MiB, baseline/candidate then candidate/baseline provides six Rut
samples per variant. Other cells have three samples per variant.
Medians below are computed from all retained samples, not selected runs.
The p99 figures in summary.json are medians of per-run p99 values.

Pinned nginx image:
`nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.
For 1 MiB the existing harness uses nginx proxy_buffer_size 16k,
proxy_buffers 8 16k and proxy_busy_buffers_size 32k. The unchanged Rut uses
256 KiB bulk nodes and a 4 KiB release boundary; buffer geometry is not equal.
TLS uses the same certificate and patched BoringSSL wrk client for both engines.

| Transport/body/connection/c | Baseline RPS | Candidate RPS | RPS change | CPU us/request change | Candidate nginx RPS |
|---|---:|---:|---:|---:|---:|
| http / 64 KiB / close / 1 | 5821.3 | 5812.7 | -0.15% | -1.53% | 6104.7 |
| http / 64 KiB / keepalive / 1 | 7697.7 | 7736.2 | +0.50% | -1.36% | 8073.9 |
| http / 1024 KiB / close / 32 | 2066.2 | 2109.0 | +2.07% | -2.43% | 2336.4 |
| http / 1024 KiB / close / 128 | 1764.0 | 1831.5 | +3.82% | -3.80% | 2317.1 |
| https / 1024 KiB / keepalive / 32 | 1168.6 | 1187.8 | +1.64% | -1.85% | 918.7 |

All 84 engine samples passed response preflights and recorded zero
warmup/measured errors. The first suite's 78 process snapshots observed no
external compiler/test processes; spot checks during the reversed confirmation
also observed none. A 3.6-second formatting validation ran during the reversed
confirmation; no builds or perf profiling overlapped timed benchmark runs.
These are modest measured gains, not a confidence interval or a full-matrix win.
HTTP 1 MiB remains below nginx; 64 KiB throughput is effectively flat.

A separate candidate perf run at HTTP 1 MiB/c32 measured memset at **7.70%**
of user-space cycle samples, versus **46.47%** in the original baseline profile.
It is no longer the dominant hotspot; response parsing is 8.07%, memmove 6.99%,
and repeated proof checks remain visible. These percentages are shares of
user-space samples, not total CPU and not predicted throughput improvement.

The code change is retained. It implements the explicitly requested bulk
contract change and reduces CPU cost with repeatable modest large-body gains.
Raw logs, configurations, binaries and the full driver are retained at
`/tmp/rut-bounded-followup-20260928`; binary/patch SHA-256 provenance and the
selected measurements are stored alongside this report.
