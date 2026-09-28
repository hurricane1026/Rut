# eBPF investigation of remaining nginx gaps

Runtime baseline: `c108b5f3` (parser fix on the ordinary-page/cache-retention
work); tracing tool: `7000af87` / PR #732. This investigation has **not**
established an across-matrix win. No huge-page advice or kernel tuning was used.

## Setup and evidence limits

Linux 6.19.10-300.fc44.x86_64, Intel i7-10700, bpftrace 0.27.0. One Rut shard
or nginx worker on CPU 2, origin CPU 3, wrk CPUs 4–5. HTTP proxy, upstream reuse
off, close/keepalive request headers from the existing acceptance fixtures.
The nginx image is pinned by the repository's `tests/pinned-nginx-image.txt`.

Diagnostic nginx workers run as the host user's UID, with a writable tmpfs
for `/var/cache/nginx`, so the unprivileged collector can verify host process
identities. Configuration and origin payloads are the existing benchmark
fixtures. Each process passed an exact-body HTTP preflight, then 2 s warmup.
All recorded warmup and measured wrk error counters are zero.

The all-group eBPF runs use a 12 s observation interval containing 8 s of load.
They observe TCP, receive-copy helper, scheduler, faults and 99 Hz kernel stacks.
The narrower geometry runs use TCP and receive-copy probes only, with additional
iterator type, destination offset and helper-length aggregation. Missing groups
are not zero measurements. Trace status is complete/usable for the retained runs.

**Instrumented RPS is not acceptance evidence.** nginx issues more probe-covered
calls, and profiling changes its throughput more. In particular, the traced
64 KiB results reverse the unprofiled ranking; that is not a Rut performance win.
Off-CPU totals include idle time around the load and must not be treated as
per-request network waiting. Helper elapsed time is inclusive, not pure memcpy
CPU time; it overlaps TCP time and cannot be added to it.

Kernel addresses were decoded locally against the same-boot symbol snapshot
from the prior investigation. The dominant leaf remains `rep_movs_alternative`
in `_copy_to_iter` / `_copy_from_iter`. Dynamically generated BPF trampoline
addresses must not be interpreted using stale nearest-symbol names.

All our builds, profiles and loads are serialized with
`/tmp/rut-clean-bench/bench.lock`; we waited for an independent routing benchmark
before starting. The host is not reserved or frequency-locked. Independent
clang-format activity was observed after the syntax-memo timing run; overlap
with that run was not established. Small changes below a few percent have no
confidence interval and are not accepted as established improvements.

## What the eBPF measurements establish

Approximate elapsed microseconds per completed request, with trace startup and
in-flight boundary effects (TCP response byte totals are within about 0.4% of
completed-request totals):

| Body / concurrency | Engine | Upstream TCP recv | Receive-copy helper | Downstream TCP send | Minor faults/request | Runqueue us/request |
|---|---|---:|---:|---:|---:|---:|
| 1 MiB / 32 | nginx | 140.3 | 49.8 | 199.8 | 0.055 | 0.1 |
| 1 MiB / 32 | Rut | 188.5 | 104.0 | 210.0 | <0.001 | 1.3 |
| 1 MiB / 128 | nginx | 139.6 | 49.4 | 201.2 | 0.204 | 0.1 |
| 1 MiB / 128 | Rut | 197.0 | 112.3 | 207.4 | 0.094 | 2.5 |

Rut uses approximately 8 receive and 8 downstream send calls per 1 MiB request,
versus nginx's 18 receive and 35 send calls. Thus fewer calls alone do not
explain throughput. The receive-helper difference is material; observed minor
faults and runnable queue delay are too small to explain it on their own.
This does not isolate every possible indirect io_uring cost.

### Iterator and buffer controls

Additional c32 traces validate the earlier rejected receive-API experiment:

- Rut's 16-iovec RECVMSG binary genuinely uses `ITER_IOVEC` for most body bytes,
  but still spends about **108 us/request** in the receive helper.
- nginx with 4 × 256 KiB buffers / 512 KiB busy limit spends about
  **57 us/request**, using a mixture of UBUF and IOVEC paths. This is a geometry
  control, not the default acceptance configuration.
- Across common comparable helper lengths and numerous destination page offsets,
  Rut is near 0.10 ns/byte and nginx near 0.05 ns/byte. There is no single measured
  destination offset explaining the gap. The helper may traverse several
  fragments/iovecs; its starting offset is not every underlying copy's offset.

Consequently, changing the iterator API alone has not removed the gap, and
large nginx buffers still do not reproduce Rut's high copy cost. The relevant
kernel iterator layout is documented in the
[Linux 6.19 uio source](https://raw.githubusercontent.com/torvalds/linux/v6.19/include/linux/uio.h).

### Hardware counters

A separate perf-stat diagnostic (no eBPF probes) measured c32 with exact-body
preflight. Counters include userspace and kernel work attributed to the selected
process, not the entire host. Six events multiplexed at 66–83% running time;
reported counts are scaled, so these are supporting diagnostics, not precise
cache bandwidth measurements.

| Event per completed request | nginx | Rut |
|---|---:|---:|
| cache-misses | 3,668 | 63,903 |
| dTLB-load-misses | 54.1 | 465.5 |

The roughly 17× cache-miss and 8.6× dTLB-miss differences support investigating
working set and access locality. They do not by themselves identify which
allocation, lifetime, batching decision, or copy causes those misses. No huge
page experiment is proposed or retained.

## Unprofiled causal experiments

Each cell uses candidate/baseline/baseline/candidate process order, 2 s warmup
and 6 s measurement, with preflights and retained warmup error checks. Deltas
below use the means of two runs per binary; these are diagnostic probes, **not**
the three-repeat acceptance profile. No network/integration suite was run for
the discarded transport/buffer variants.

| Candidate | 1 MiB close c32 | 1 MiB close c128 | 64 KiB close c1 | 64 KiB keepalive c1 |
|---|---:|---:|---:|---:|
| immediate large send + normal async completion | -0.71% | +0.45% | -0.63% | -1.33% |
| 64 KiB bulk blocks, same 64 MiB idle byte budget | -14.31% | -13.92% | -4.12% | -4.41% |
| immediate direct receive + send, async completion retained | -1.67% | -3.07% | -2.60% | -1.98% |
| 16 events per userspace wait batch | +0.99% | -3.04% | +0.04% | +0.50% |
| coalesce only below 128 KiB, read-ahead cap unchanged | -0.69% | -1.49% | -0.24% | -0.20% |
| remove same-call duplicate owner policy checks | — | — | +0.73% | -0.69% |
| exact-byte short pinned-header semantic memo | — | — | +1.45% | -0.80% |
| exact-byte short pinned-header syntax memo | — | — | +1.02% | -1.62% |
| 256-entry large provided-buffer ring | +1.11% | +0.33% | -0.53% | -1.40% |
| POLL_FIRST on one-shot header receives, r1 | — | — | -1.56% | +2.12% |
| POLL_FIRST, reversed process order r2 | — | — | +1.02% | +1.05% |
| 128 KiB window and bulk blocks, same idle byte budget | -12.42% | -17.30% | — | — |

None of these provides a repeatable improvement across the measured cells.
POLL_FIRST is a possible small keepalive improvement, but close results changed
sign, with substantial within-run variation in r1; it needs longer validation.
The reverse-order r2 retained process scheduler accounting and before/after host
process snapshots. Its small runnable waits do not establish the cause of the
throughput variation. In particular,
smaller memory blocks or earlier synchronous syscalls cannot be recommended from
these results. Removing repeated parsing lowers userspace time but did not
improve keepalive throughput in these runs; timing/CPU breakdown needs further
investigation before keeping a cache. The memo adds bounded per-connection state.

The syntax memo's focused tests passed: two tests, 27,136 checks. They compare
against fresh parsing after every one-byte mutation, buffer relocation, empty
values, chunked input, many/long headers, and separately reject changed request
and policy facts while preserving 64-bit range classification. These checks do
not replace a complete network/integration run or establish a performance win.

The current optimization target remains unresolved. A full acceptance matrix
must be rerun after a retained candidate wins the focused, uninstrumented tests.

## Plaintext bulk-first candidate

A validated Content-Length larger than one bulk node previously missed the
fresh-chain bulk preference. It started with an ordinary slice even though the
whole body was already known to be large. The candidate extends that preference
to plaintext bodies spanning several nodes. It preserves TLS selection, ordinary
allocation fallback, the 256 KiB bulk size, 512 KiB read-ahead window and 64 MiB
idle cache limit. It does not change async ownership or byte publication.

Two independent process-order comparisons gave approximately 2–3% higher
throughput for 1 MiB close responses at c32 and c128. The second reverses the
first's candidate/baseline ordering. These remain short diagnostic measurements.

A fresh all-group trace corroborates a concrete mechanism: downstream send calls
fall from about 8 to 7 per request, and upstream receives from about 8.2 to 7.1.
Receive-copy cost remains near 0.10–0.11 ns/byte: this candidate reduces work but
does not solve the main receive-copy gap against nginx.

The final source passed all 1,423 network tests (339,764 checks) and 68 arena
tests (1,073,511 checks), with zero failures. The affected header passes
clang-format and the patch passes `git diff --check`. Benchmark binaries and
patch provenance are retained alongside the results. No entire-matrix win has
been established.

A follow-up also preferred bulk for nonempty plaintext chains whose remaining
buffered size had fallen below the ordinary-slice threshold. Compared with the
retained bulk-first binary, c32 changed -0.37% and c128 -0.14%.
This variant was reverted: the measured change does not justify broadening the
allocation rule. Its patch is relative to `83e5d8a1`; its driver uses that binary
as the baseline, unlike the earlier experiments.

### Uninstrumented nginx acceptance comparison

Three repetitions per engine, 1 s warmup and 5 s load, alternating engine order,
with the existing default nginx configuration. All preflights and warmup/load
error checks passed. Arithmetic mean RPS:

| HTTP body / connection / concurrency | nginx | Rut | Rut/nginx |
|---|---:|---:|---:|
| 64 KiB / close / 1 | 6,049 | 5,843 | 0.966 |
| 64 KiB / keepalive / 1 | 7,977 | 7,632 | 0.957 |
| 1 MiB / close / 32 | 2,239 | 2,098 | 0.937 |
| 1 MiB / close / 128 | 2,279 | 2,002 | 0.879 |

The TLS 1 MiB keepalive c32 control averages 1,175 RPS for Rut versus 908
for nginx (ratio 1.294), also with three valid, error-free repetitions.
TLS buffer selection is unchanged by the candidate.

These four remaining-gap HTTP cells still lose to nginx. The local improvement over
Rut's baseline must not be confused with meeting the nginx target. This focused
run is not a rerun of the complete acceptance matrix.

## Reproduction

`compare.py`, `compare_geometry.py`, `compare_geometry_controls.py`,
`compare_pmu.py` and `probe.py` retain the local commands and fixture paths.
The scripts are lab drivers, with explicit absolute paths, not portable product
CLIs. `summarize_compare.py` and `summarize_geometry.py` aggregate retained data.
Patches record the separate experiments; none should be applied together.

Binary hashes are in `provenance.json`. `trace-evidence.json` retains trace status,
TCP/copy/scheduler/fault maps and histograms; full kernel stacks and original
JSONL are retained locally. Raw programs, diagnostics, process snapshots, load
logs, configurations, binaries and PMU CSV remain in:

`/tmp/rut-bounded-followup-20260928/{ebpf-compare-r2,ebpf-geometry-r1,ebpf-geometry-controls-r1,ebpf-pmu-r1}`

The first comparison attempt failed to start nonroot nginx without its writable
cache directory. It is excluded; the corrected r2 setup is the retained trace.
