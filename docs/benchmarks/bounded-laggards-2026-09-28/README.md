# Bounded buffering: investigation of cells below nginx

Measured on 2026-09-28 using the final PR #726 runtime revision
`0b8fdcab9290d6b6a2093b775087efacd17c59bd`. PR #726 merged into
`perf/bounded-buffering-frontend`; these results must not be attributed to
`main` at the time of this investigation.

## Scope and method

HTTP proxy, converter-strict profile, upstream reuse disabled. One Rut shard
and one nginx worker, server CPU 2, origin CPU 3, wrk CPUs 4,5. Intel i7-10700.
Release build, clang 22.1.8. Each cell has three repetitions, 1 s warmup and
5 s measured time. Engine order alternates each repetition. No compilation
or profiling ran concurrently with timed benchmarks. CPU frequency was not
locked and the machine was not exclusively reserved.

Pinned nginx image:
`nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.

For 1 MiB the harness configures nginx with `proxy_buffer_size 16k`,
`proxy_buffers 8 16k`, and `proxy_busy_buffers_size 32k` to avoid timeouts.
Rut still uses 4 KiB release units. These are the existing acceptance
configurations, not a controlled comparison with equal buffer geometry.
The historical 1 MiB close/c1 cell was effectively tied (ratios 0.995/1.003)
and was not remeasured. This investigation does not rerun the full 48-cell
matrix or establish TLS performance.

## Measurements

Each row is the median of three repetitions. Ratios below 1 mean Rut trails
nginx. All 108 engine samples passed response preflights, with zero recorded
warmup or measurement errors.

| Run | Body | Connection | Concurrency | Rut RPS | nginx RPS | Rut/nginx |
|---|---|---|---:|---:|---:|---:|
| baseline-r1-1m | 1024 KiB | close | 32 | 2064.4 | 2320.6 | 0.8896 |
| baseline-r1-1m | 1024 KiB | close | 128 | 1794.0 | 2304.0 | 0.7786 |
| baseline-r1-64k | 64 KiB | close | 1 | 5827.7 | 6135.4 | 0.9498 |
| baseline-r1-64k | 64 KiB | keepalive | 1 | 7775.2 | 8095.7 | 0.9604 |
| baseline-r2-64k | 64 KiB | close | 1 | 5829.4 | 6112.8 | 0.9536 |
| baseline-r2-64k | 64 KiB | keepalive | 1 | 7736.1 | 8072.6 | 0.9583 |
| header-more-r1-1m | 1024 KiB | close | 32 | 2091.3 | 2369.0 | 0.8828 |
| header-more-r1-1m | 1024 KiB | close | 128 | 1760.2 | 2262.6 | 0.7780 |
| header-more-r1-64k | 64 KiB | close | 1 | 6034.5 | 6130.8 | 0.9843 |
| header-more-r1-64k | 64 KiB | keepalive | 1 | 7737.0 | 8050.8 | 0.9610 |
| header-more-r2-64k | 64 KiB | close | 1 | 5891.0 | 6086.3 | 0.9679 |
| header-more-r2-64k | 64 KiB | keepalive | 1 | 7540.2 | 8040.4 | 0.9378 |
| streaming-zero-r1-1m | 1024 KiB | close | 32 | 1992.2 | 2332.9 | 0.8539 |
| streaming-zero-r1-1m | 1024 KiB | close | 128 | 1736.4 | 2311.6 | 0.7511 |
| streaming-zero-r1-64k | 64 KiB | close | 1 | 5806.2 | 6109.5 | 0.9504 |
| streaming-zero-r1-64k | 64 KiB | keepalive | 1 | 7669.4 | 8044.8 | 0.9533 |
| vector-zero-r1-1m | 1024 KiB | close | 32 | 1890.5 | 2334.0 | 0.8100 |
| vector-zero-r1-1m | 1024 KiB | close | 128 | 1645.5 | 2270.6 | 0.7247 |

In the reversed comparison, header MSG_MORE improved close/c1 by **1.06%**
(5891.0 versus 5829.4 RPS), while keepalive/c1 fell **2.53%**
(7540.2 versus 7736.1 RPS). Initial keepalive was down 0.49%.
The short-connection benefit is promising but not an across-cell win;
no runtime change is retained from this investigation.

## Profiling

Separate `perf record -e cycles:u -F 997` runs, with a separate DWARF callgraph
run for 1 MiB/c32. Percentages below are **user-space cycle samples**, not
fractions of total CPU time and not predicted throughput improvements.

- 1 MiB/c32: memset 46.47%; c128: 41.57%.
- Callgraph c32: 42.14% of all samples are memset called by
  `SlicePool::free_bulk`, and 3.98% by `SlicePool::free`.
- 64 KiB/c1: memset 7.8%, parser 4.62%, one phase-1 proof 4.40%,
  memmove 4.13%; no similarly dominant single hotspot.
- Repeated parser and policy proof work remains a secondary candidate.
  Proof caching would require explicit invalidation and mutation tests.

The pool guarantees that returned buffers contain no previous owner's data.
Removing clearing or moving it past reuse would violate this contract.
`free_written` already limits bulk clearing to the written prefix. The next
useful experiments should change buffer geometry and turnover while retaining
that contract, and separately isolate nginx's larger-buffer configuration.
A profile hotspot alone does not prove an optimization will improve throughput.

## Experiments and decision

1. Lower glibc `x86_memset_non_temporal_threshold` to 65536 for the Rut process
   only. 1 MiB Rut throughput regressed about 3.5% at c32 and 3.2% at c128.
2. Raise `x86_rep_stosb_threshold` to 1048576 for the Rut process only.
   1 MiB throughput regressed about 8.4% at c32 and 8.3% at c128.
3. Set MSG_MORE for plaintext Bounded header sends whose body is already
   buffered. Initial 64 KiB close/c1 improved 3.55%, but repeat results and
   keepalive behavior require caution. 1 MiB showed no consistent benefit.

The runtime experiment was reverted. `header-more.patch` is an experimental
artifact, not an accepted implementation. It built successfully and passed
benchmark response checks, but has not passed the network/integration suites.
Draft assertions were saved separately in the local evidence directory and
were not compiled. No production changes or glibc settings remain applied.

## Evidence

Full per-run measurements are in `samples.json`; medians and error validation
are in `summary.json`. Profiles and baseline/candidate binary provenance are
stored alongside this report. The candidate provenance hash describes the
built experimental binary. `header-more.patch` is the exact measured code.

Full raw logs, generated configurations, commands, binaries, perf data and
reproduction driver remain in `/tmp/rut-bounded-followup-20260928`.
The first `baseline-64k` attempt failed container startup because of its
SELinux mount label and is excluded; it produced no successful benchmark.
After labelling only the experiment directory for container access, all
completed measured runs used response preflights and checked warmup and
measured error counters.

Reproduce with `run_selected.py TAG BINARY [64k|1m]` in that directory,
under `flock /tmp/rut-clean-bench/bench.lock sg docker -c '...'`.
The driver uses the repository's `scripts/nginx_benchmark/run.py` acceptance
profile. `header-more-r2` followed by `baseline-r2` reverses candidate order
from the initial baseline/candidate comparison.
