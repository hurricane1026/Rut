# Bulk cache retention and the remaining nginx gap

Baseline: `f30cfb06` (bulk payload clearing already removed). This follow-up
increases `SlicePool::kMaxCachedBulk` from 64 to 256. Per-shard idle bulk
retention rises from 16 MiB to **64 MiB**; returns beyond the new bound still
use MADV_DONTNEED. Allocation size, capacity limits, read-ahead window,
release granularity, timers and protocol checks do not change.
This is a bounded memory/performance tradeoff, not proof that 256 is optimal
for every concurrency or memory budget. More shards multiply the idle limit.

## Why nginx was still faster

Separate uninstrumented process-stat probes measured user and system CPU
from `/proc`, plus minor faults and scheduler counters. Each cell ran
nginx, Rut, Rut, nginx, with 2 s warmup and 6 s measurement per process.
These diagnostics use the same HTTP close workload and pinned CPUs as the
acceptance runs. They record wrk errors but are not a replacement for the
acceptance harness's exact-body preflight.

Approximate CPU microseconds per request:

| HTTP response / concurrency | nginx user | Rut user | nginx system | Rut system |
|---|---:|---:|---:|---:|
| 64 KiB / 1 | 11.3 | 16.1 | 74.0 | 72.0 |
| 1 MiB / 32 | 24.5 | 24.9 | 266.8 | 316.5 |
| 1 MiB / 128 | 24.0 | 28.1 | 267.4 | 377.8 |

At c128, Rut incurred about **43–61 minor faults/request**, versus nginx's
0.26. At c32 Rut had only 0.007–0.012. Runqueue waiting was under 3 us/request,
and the observed context-switch counts do not explain the ~110 us c128
system-time gap. These are process CPU accounting numbers, not all host IRQ
or background-worker CPU time.

### Causal cache experiment

With io_uring unchanged, the cache-only diagnostic variant was run in
candidate, baseline, baseline, candidate order:

- c128: baseline 1770–1872 RPS, candidate 2010–2044 RPS (about +11% using
  the two-run means). Minor faults dropped from 34–58/request to 0.07–0.08.
  System CPU fell from 360–387 to 319–326 us/request.
- c32: approximately flat, as expected when page churn was already negligible.

This links a substantial part of the concurrency cliff to discard/refault
churn, rather than demonstrating an inherent io_uring disadvantage.

### Kernel profiles

Separate profiles used cycles:k at 499 Hz with callchains, attached only to
our benchmark processes through a temporary diagnostic container. PERFMON
was scoped to that container; a separate SYSLOG-capable read captured live
kallsyms. No global perf/kptr settings changed. perf report could not resolve
its recorded kernel map directly, so raw IPs were mapped offline against the
same-session live text symbols, and leaf event periods were aggregated by
symbol. Raw data, symbol snapshot and reports remain in the local evidence.
Each profile has about 3000 samples and no reported lost samples.

At c32, `rep_movs_alternative` accounts for **33.88%** of Rut kernel cycles
versus **17.07%** for nginx. Callchains place it in TCP receive's
`_copy_to_iter` and TCP send's `_copy_from_iter`. At c128 the cache variant
removes the large fault/churn problem, but TCP copying is still prominent.
Functions directly named io_*, __io_* and the io_uring enter wrappers account
for roughly 1–1.4% of self samples. This is **not** a bound on all indirect
io_uring costs: generic helpers, data locality and scheduling can depend on
how the backend is used. Neither the kernel percentages nor earlier
user-space memset percentages are predicted throughput gains.

Thus the remaining c32 gap is predominantly in kernel data movement, but the
specific reason its copies are more expensive still needs an isolated
experiment. It is not established that switching to epoll would fix it.
The current Bounded path has no equivalent implementation in EpollEventLoop,
so a simple backend substitution would not be a valid same-semantics A/B.

### Counts and buffer geometry

Separate diagnostic builds/interposition measured approximately, per request:

- Rut 1 MiB: 8 initial downstream send submissions, 7 direct body receive
  submissions, 35 response parser calls, 31 post-commit proofs and 90 phase-1
  proofs. Initial send counts omit backend partial-send resubmissions.
- nginx 1 MiB: 36 writev calls, 17 readv calls, plus approximately 2 recv calls.
- Rut 64 KiB: 3 initial sends, 2 direct receives, 17 response parses and
  41 phase-1 proofs. This makes repeated user-space work a more plausible
  small-response target than an explanation for the large-response system gap.

These counters include warmup and divide by completed requests; in-flight
shutdown requests and instrumentation can slightly affect the counts. They
are not syscall-equivalent or used as throughput evidence.

Changing nginx from 8 × 16 KiB / 32 KiB busy to 4 × 256 KiB / 512 KiB busy
in a separate geometry probe improved its 1 MiB throughput to 2738–2798 RPS
at c32 and 2873–2905 at c128. The original control was about 2300 RPS.
Larger blocks alone therefore do not explain Rut's loss, nor can the nginx
small-buffer configuration be assumed to be its best performance setting.
That experiment changes total buffering as well as block size and does not
isolate a single buffer-geometry parameter.

## Validation

- Release runtime, test_network and test_arena build passed.
- Complete network suite: 1423 passed, 339764 checks, zero failures.
- Complete arena/chain suite: 68 passed, 1073511 checks, zero failures.
- Existing resident-cache tests exercise the new 256-buffer retention limit,
  including the six excess buffers discarded beyond that bound.
- No runtime instrumentation remains in the source or production executable.
- Full integration and full 48-cell acceptance matrix were not rerun for this
  retention-only change. Broader tuning and TLS performance are not claimed.

## Evidence and reproduction

`diagnostics.csv` contains the unprofiled CPU/fault and geometry experiments.
`kernel-hotspots.json` retains weighted kernel leaf percentages.
`provenance.json` identifies the base and binary hashes. Full probe drivers,
raw logs, perf data and variants are in `/tmp/rut-bounded-followup-20260928/gap`.
The production candidate differs from the cache-only diagnostic binary only
in source comments.

## Formal acceptance results

Ran the repository nginx benchmark acceptance profile with exact-body preflight,
three repetitions per engine/cell, 1 s warmup and 5 s measurement. Baseline
completed before candidate; nginx/Rut order alternated within each run. The
reverse-order cache diagnostic above independently checks the large c128 effect.
Server/origin/client CPUs were pinned to 2/3/4–5, with one worker/shard,
HTTP, upstream reuse off and implicit keepalive headers. The host was not
reserved or frequency-locked. nginx 1.29.7 used image digest
`sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.

Medians of three repetitions (RPS):

| Body / connection / concurrency | Rut before | Rut after | Change | Before / nginx | After / nginx |
|---|---:|---:|---:|---:|---:|
| 64 KiB / close / 1 | 5833.8 | 5812.7 | -0.36% | 95.72% | 95.00% |
| 64 KiB / keepalive / 1 | 7741.2 | 7656.9 | -1.09% | 96.37% | 95.61% |
| 1024 KiB / close / 32 | 2080.2 | 2110.2 | +1.44% | 90.03% | 89.66% |
| 1024 KiB / close / 128 | 1773.2 | 2035.7 | +14.80% | 77.18% | 87.67% |

At c128, Rut CPU/request fell from 413.2 to 348.6 us (−15.6%), p99 from
76.143 to 65.748 ms (−13.7%), and observed median process RSS rose from
210.0 to 222.7 MiB. RSS is whole-process sampled memory, not the idle-cache
limit. The nginx-normalized throughput improvement was 13.6%; raw Rut
throughput improved 14.8%. The c32 raw gain of 1.4% did not improve its nginx
ratio, while the small-body cells measured −0.4% and −1.1%. These short runs
do not establish small changes as statistically significant.

All 48 measured samples were valid, with zero measurement and warmup errors.
The candidate remains behind nginx in these four cells; no claim is made
about the untested matrix. `acceptance-samples.csv` contains all raw samples;
`acceptance-summary.json` contains medians, CPU/request and nginx ratios.
