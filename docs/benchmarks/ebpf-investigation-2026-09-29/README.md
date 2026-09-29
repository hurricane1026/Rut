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

## Follow-up: 512 KiB bulk blocks

Against the retained bulk-first binary, 512 KiB blocks with a 128-block idle
cache preserve the 64 MiB idle byte limit. The initial process-order probe
improved 1 MiB close c32 by 4.47% and c128 by 6.18%; reverse order improved
those cells by 3.99% and 6.62%. All 1,423 network tests (338,996 checks) and 68 arena tests (1,073,509
checks) passed. Focused nginx acceptance runs are recorded below; these diagnostic probes
are not evidence of an across-matrix win. The prototype keeps
4096 maximum bulk nodes, so its reserved virtual-address ceiling doubles to
2 GiB per pool. Its physical working-set tradeoff still needs assessment.

The follow-up trace reduces downstream sends from about 7 to 6 per request,
and send elapsed time by about 22–26 us/request. Receive-copy time is nearly
unchanged, around 103–113 us/request. At c128 minor faults increased from
0.084 to 0.455 per request. Traced throughput is diagnostic only.

A separate forced-epoll control failed exact-body preflight: the server closed
the connection without a response. Its log confirms epoll activation. No load
measurements were accepted, and its source edit was reverted. This is not a
valid backend performance comparison, nor evidence that io_uring causes the
copy gap. The cause of the epoll preflight failure has not been isolated.

In both process-order probes, c128 mean RSS increased from roughly 224–225 MiB
to 245–247 MiB. Minor faults increased from 0.11–0.12 to 0.53–0.71 per
request. c32 RSS increased from about 169 MiB to 175 MiB. Keeping the idle
byte limit constant therefore does not keep active memory constant.

The uninstrumented three-repeat nginx comparison for the 512 KiB candidate
passed all preflights and warmup/load error checks. Mean RPS:

| HTTP body / connection / concurrency | nginx | Rut | Rut/nginx |
|---|---:|---:|---:|
| 64 KiB / close / 1 | 6,104 | 5,770 | 0.945 |
| 64 KiB / keepalive / 1 | 7,995 | 7,628 | 0.954 |
| 1 MiB / close / 32 | 2,329 | 2,245 | 0.964 |
| 1 MiB / close / 128 | 2,307 | 2,190 | 0.949 |

The large-response gap narrows, but every focused HTTP cell still loses.
Small-response results do not establish an improvement. Comparing separate
acceptance runs does not isolate a 64 KiB regression; no same-session
candidate/baseline causal probe has been run for those small cells yet.

The TLS 1 MiB keepalive c32 control passed all checks: Rut averages 1,156
RPS and nginx 912 (ratio 1.268). The 512 KiB change is retained for its
repeatable 4–6.6% large-plaintext improvement, with the measured memory cost
explicitly recorded. These gates do not prove no regressions across the full
matrix, which remains outstanding. No huge-page advice or kernel tuning was
introduced. Final source differs from the measured prototype only in comments.

## Pending: MSG_MORE for already-buffered response continuations

The experimental buffered-more variant sets MSG_MORE only when the selected
complete-body pump or bounded release boundary has more bytes to send after
the current operation. It never uses declared-but-unreceived body bytes as
the hint. The experiment is not retained or accepted yet.

Initial large-body samples suggested about 5% improvement, but a parallel
PR #733 checkout build began during the first probe. Recorded host snapshots
show many clang++ processes during the falling 64 KiB throughput. The reversed
run also overlapped that build and was interrupted; scheduled acceptance and
tracing jobs were cancelled before starting. The interfered results are
retained for diagnosis only, not used to accept or reject this candidate.
Fresh idle-host measurements and full functional validation are outstanding.

The candidate passed all 1,423 network tests (338,996 checks). An additional
real-socket control uses a custom origin that sends 16, 64 or 512 KiB, pauses
for 300 ms, then finishes its 1 MiB body. Both close and implicit keepalive
requests received the entire eligible prefix before the 100 ms timeout and
then verified the exact full body. Candidate prefix times were 0.6–2.1 ms;
these are functional liveness observations under concurrent external tests,
not latency acceptance measurements. The first attempt added an explicit
Connection: keep-alive header and failed baseline preflight. The corrected
control uses the benchmark's implicit keepalive request form.

Guarded clean-r1/r2 probes were rejected before measurement because the
external integration test was still live. Clean-r3/r4 now wait for the
identified external ninja process to exit, then retain per-sample host guards.

## Completion scope audit

The full existing runtime acceptance scope remains 96 coordinates:
HTTP/HTTPS × static-close/static-keepalive/proxy-close/proxy-keepalive ×
16/1024/65536/1048576 bytes × concurrency 1/32/128. As in the complete
2026-09-24 archive, static uses `native-body` (the separate converter-return
profile cannot represent the two largest bodies); proxy remains
`converter-strict`. No coordinates may be dropped. The harness requires
three valid, error-free samples of at least five seconds per engine and
median Rut/nginx >= 1.10 in every cell, with completed cleanup evidence.

The focused results above neither cover that scope nor pass that gate. The
latest archived full run predates these runtime changes and is not current
completion evidence. A fresh full matrix remains required after selecting
the candidate. The no-huge-pages constraint also remains in force.

Clean-r3/r4 completed after the external test process exited, without triggering
the per-sample host guards. Diagnostic mean RPS changes versus 512 KiB baseline:

| Run | Cell | Change |
|---|---|---:|
| buffered-more-clean-r3 | 1m-c128-close | +4.39% |
| buffered-more-clean-r3 | 1m-c32-close | +8.35% |
| buffered-more-clean-r3 | 64k-c1-close | +3.17% |
| buffered-more-clean-r3 | 64k-c1-keepalive | +0.07% |
| buffered-more-clean-r4 | 1m-c128-close | +4.70% |
| buffered-more-clean-r4 | 1m-c32-close | +5.17% |
| buffered-more-clean-r4 | 64k-c1-close | +2.98% |
| buffered-more-clean-r4 | 64k-c1-keepalive | -0.61% |

The c32 r3 samples vary substantially, so its unusually large delta is not
treated as the expected gain. The c128 and reversed c32 comparison corroborate
a roughly 4–5% large-response gain; 64 KiB keepalive shows no established win.
The guarded nginx acceptance and repeat eBPF comparison are still running.

The guarded three-repeat nginx comparison completed without warmup/load errors
or host-guard failures. Median RPS (the matrix uses median ratios):

| HTTP size / connection / concurrency | nginx | Rut | Rut/nginx |
|---|---:|---:|---:|
| 64k / close / 1 | 6078 | 5923 | 0.975 |
| 64k / keepalive / 1 | 8022 | 7670 | 0.956 |
| 1m / close / 32 | 2308 | 2349 | 1.017 |
| 1m / close / 128 | 2291 | 2286 | 0.998 |

None reaches the full-matrix 1.10 target. Earlier tables explicitly report
means, so they should not be subtracted directly from these median ratios.

The repeat trace is complete and usable for all four runs. Downstream send
calls remain near six per request, while TCP send elapsed time falls from
174.5 to 154.7 us/request at c32 and from 179.8 to 157.9 at c128. Receive-copy
time remains near 106–114 us/request. This supports a send-side benefit from
MSG_MORE without attributing it to fewer send calls or a solved receive-copy
gap. The code is retained in `187bd5d9`, after full network tests, socket stall
checks, opposite-order baseline probes and guarded nginx comparison. The
measured binary differs from final source only in comments and formatting.

## Rejected: direct final proxy send and early FIN

For a complete, closing plaintext Bounded response only, the prototype
reused the local-response nonblocking final write plus early shutdown path,
retaining the authenticated asynchronous completion. Exact-body preflights
and warmup/load error checks passed in the diagnostic probe; full runtime
tests were not run for this discarded variant. Relative to buffered-more:

| Cell | Mean RPS change |
|---|---:|
| 1m-c128-close | -0.01% |
| 1m-c32-close | +2.44% |
| 64k-c1-close | +0.88% |
| 64k-c1-keepalive | +0.39% |

The c32 samples had substantial variation, c128 was effectively flat, and
the small-close gain was below 1%. This does not justify the additional
branch and ownership conditions; the prototype was reverted.

A quick diagnostic now covers all 96 coordinates using the retained
`187bd5d9` runtime, native-body static and converter-strict proxy profiles.
Its 1-repeat, 2-second samples are explicitly ineligible for acceptance.
The first launch was rejected by CPU-affinity validation before any load:
pinning the matrix driver to CPU 6 hid CPUs 2–5 from its available-CPU check.
The corrected r2 leaves driver affinity unrestricted while retaining the
harness's explicit server/origin/client pinning and per-sample host guards.
Results are pending; no matrix pass is claimed.

The in-progress quick matrix exposed a larger static gap: HTTP 1 MiB
static-keepalive ratios were 0.813/0.826/0.842 at c1/32/128. Rut server CPU
was about 23/34/34%, versus nginx 43/41/38%. This single-repeat diagnostic
does not establish a CPU-copy bottleneck or a stable regression; server
underutilization makes send/wait behavior worth tracing as well. Small 16 B
proxy-close ratios were about 0.99–1.06. Separate eBPF comparisons for these
small proxy cells and large static keepalive cells are queued after the matrix.

The HTTP 1 MiB proxy-close group was rejected by a newly observed clang++
process at the host guard, before Rut's load. Its three coordinates remain
invalid and need a fresh run; the successful nginx-only partials are not a
comparison. This interruption is preserved in the matrix evidence.

The corrected quick matrix completed all 96 coordinate evaluations: 93 valid
comparisons and three invalid HTTP 1 MiB proxy-close cells from host-guard
rejection. Of the valid diagnostic ratios, 69 were at least 1.10 and 24 below
it. **No cell qualifies for performance acceptance** with this short,
single-repeat profile. Matrix JSON, sample/status files, wrk logs and host
snapshots are retained in `matrix-quick-r2-evidence.tar.gz` (hash recorded
next to it); readable matrix/sample/status summaries are in `matrix-quick-r2/`.
Original configurations and
payloads remain under the corresponding `/tmp` output path.

The retained runtime is `187bd5d9`. A three-repeat static-large keepalive
validation and the invalid-cell retry are queued with the tracing controls.
A separate unretained prototype removes the copied body prefix only when a
plaintext static body has a memfd: the header is sent first and sendfile
starts at offset zero. Its build/probe are serialized after baseline work.

The small-proxy traces completed. At 16 B/c1, nginx/Rut user CPU was about
8.9/13.8 us per close request and 7.9/10.4 us per keepalive request. Kernel
TCP receive-copy helpers account for less than 1 us/request total. Rut made
about two upstream receives per request versus nginx one at c1; at c32 the
relationship changed, so this is workload/timing dependent. Instrumented
throughput is not used as acceptance evidence. The small-body gap calls for
control-path and receive-attempt analysis, not a bulk-copy explanation.

The rejected HTTP 1 MiB proxy-close coordinates were retried successfully;
`matrix-quick-combined.json` retains their replacement rows with provenance
to both original matrices. All 96 coordinates now have valid short diagnostic
comparisons, still none eligible for acceptance. The failed original rows
remain preserved.

Three-repeat static 1 MiB keepalive validation confirmed the gap, with
nginx/Rut median RPS of 5,442/4,456 (c1), 9,907/8,689 (c32), and
9,719/8,565 (c128), ratios 0.819/0.877/0.881. All preflight and warmup/load
checks passed without host-guard rejection. eBPF sees about 17 kernel
`tcp_sendmsg` calls per request on both engines (including sendfile's internal
chunks, not 17 application syscalls). At c32 Rut's send elapsed and process
CPU times are lower despite lower throughput. These results do not establish
a server-copy CPU bottleneck; the file-prefix prototype remains under test.

## Static file-prefix and header-push controls

Removing the initial userspace body prefix for plaintext file-backed bodies
showed less than 1% change and was reverted. A separate candidate preserves
the prefix and clears MSG_MORE only for local file-backed plaintext output,
leaving the newly retained proxy-buffer hint unchanged. Diagnostic deltas:

| Candidate | Cell | Mean RPS change |
|---|---|---:|
| file-body-only-r1 | 1m-c1-keepalive | +0.66% |
| file-body-only-r1 | 1m-c32-close | +0.55% |
| file-body-only-r1 | 1m-c32-keepalive | +0.54% |
| file-header-push-r1 | 1m-c1-keepalive | +8.31% |
| file-header-push-r1 | 1m-c32-close | +4.40% |
| file-header-push-r1 | 1m-c32-keepalive | +17.78% |

The header-push c1 samples vary substantially; the c32 keepalive gain is
large in both samples. Reverse-order and 64 KiB controls are pending.
Neither variant has a full runtime test run yet; preflight bodies and
warmup/load errors passed for these probes.

The reverse-order and small-file controls completed:

| Run | Cell | Mean RPS change |
|---|---|---:|
| file-header-push-r2 | 1m-c1-keepalive | +25.32% |
| file-header-push-r2 | 1m-c32-close | +5.20% |
| file-header-push-r2 | 1m-c32-keepalive | +15.03% |
| file-header-push-64k-r1 | 64k-c1-close | +1.61% |
| file-header-push-64k-r1 | 64k-c1-keepalive | +2.70% |
| file-header-push-64k-r1 | 64k-c32-close | -0.80% |
| file-header-push-64k-r1 | 64k-c32-keepalive | -2.40% |

The large keepalive c32 gain repeats, but the 64 KiB keepalive c32 control
regresses about 2.4%. The next candidate therefore suppresses MSG_MORE only
when a plaintext file tail exceeds 64 KiB, preserving coalescing for smaller
tails. This threshold is a measured performance heuristic, not a protocol
requirement. The step patch is relative to the all-file prototype. A fresh
network test build and all 12 affected HTTP static acceptance coordinates
(two sizes, two connection modes, three concurrency levels) are queued.
TCP send-window diagnostics for the large-body candidate are also queued.

The all-file header-push prototype passed 1,423 network tests (338,996
checks). The narrowed >64 KiB-tail version is rebuilding and has separate
pending tests; the prototype result must not be attributed to that final
source yet.

TCP-state tracing exposes a transport-flow difference. At c1, the fraction
of send-entry observations with peer window >=256 KiB rises from 0% to
93.5%; observations with >=64 KiB not yet transmitted fall from 73.5% to
0.4%. At c32 the corresponding changes are 0% to 58.5%, and 76.4% to
63.3%. Both send-buffer histograms remain in the same 2–4 MiB bin. These
are call-weighted observations, not percentages of elapsed time or exact
per-flow averages. They support a receive-window/send-timing explanation;
they do not isolate ACK behavior or prove one receive-autotuning mechanism.
The trace covers the all-file prototype, whose 1 MiB send flags match the
narrowed candidate; it is not an uninstrumented throughput comparison.

The narrowed large-file candidate subsequently passed all 1,423 network
tests (338,996 checks), and its formatted patch passes `git diff --check`.
The final candidate binary hash and exact patch are retained. The affected
12-cell acceptance matrix has started; its outcome is still pending.

## Narrowed large-file header push: formal result

All 12 affected HTTP static coordinates completed with three valid 5-second samples per engine, clean warmups/load and cleanup. The matrix exits 2 because the 1.10 target is not met, not because measurements failed.

| Bytes | Mode | Concurrency | nginx median RPS | Rut median RPS | Ratio |
|---:|---|---:|---:|---:|---:|
| 65536 | static-close | 1 | 12928 | 13531 | 1.0467 |
| 65536 | static-close | 32 | 29176 | 31602 | 1.0832 |
| 65536 | static-close | 128 | 29139 | 32344 | 1.1100 |
| 65536 | static-keepalive | 1 | 28444 | 30331 | 1.0664 |
| 65536 | static-keepalive | 32 | 62887 | 89228 | 1.4189 |
| 65536 | static-keepalive | 128 | 62967 | 89585 | 1.4227 |
| 1048576 | static-close | 1 | 3413 | 3568 | 1.0453 |
| 1048576 | static-close | 32 | 6614 | 7774 | 1.1753 |
| 1048576 | static-close | 128 | 6487 | 7540 | 1.1623 |
| 1048576 | static-keepalive | 1 | 5496 | 5486 | 0.9983 |
| 1048576 | static-keepalive | 32 | 9874 | 10273 | 1.0404 |
| 1048576 | static-keepalive | 128 | 9784 | 10054 | 1.0276 |

The 1 MiB keepalive regression is largely removed: c1 is approximately equal, and c32/c128 lead by 4.0%/2.8%. The previous formal ratios were 0.8187/0.8770/0.8813; these are separate runs on an unreserved host, while the alternating same-host causal probes establish the direction of benefit. Five of these twelve coordinates reach 1.10; this is not full-matrix acceptance. Preserve the narrowed change and continue investigating. Raw evidence is archived with SHA-256.

## Rejected synchronous large-file prefix experiment

The nonblocking prefix send dispatched a complete write immediately under the existing sendfile recursion guard, so sendfile could start before a header CQE. Partial writes retained ordinary asynchronous completion accounting. Against the accepted large-file header-push binary, two diagnostic samples per engine produced:

| Case | Mean RPS change |
|---|---:|
| 1m-c1-keepalive | +0.20% |
| 1m-c32-close | +0.60% |
| 1m-c32-keepalive | -3.35% |

All body/warmup/load checks passed, but concurrent keepalive regressed and other changes were negligible relative to variation. The candidate is reverted; it did not receive the full network suite and is not retained runtime code. This does not support removing the header completion wait as a throughput optimization.

## Small proxy userspace attribution

The existing eBPF small-response trace puts the receive-copy helpers below 1 us/request while Rut spends more time in userspace. A complementary `perf record -e cycles:u -F 997 --call-graph dwarf,8192` sample of the accepted large-file-header-push binary covers 16 B proxy c1 close and keepalive (20 s load each). Body preflight, warmup/load error checks and host guards passed; no lost samples were reported. This is diagnostic data, not acceptance throughput.

For close, memset accounts for 7.74% of sampled user cycles, with 6.63% directly attributed to `SlicePool::free`. For keepalive, total memset falls to 1.02%. The 8 KiB captured stacks do not establish complete root-to-leaf call chains through the large runtime frames. Ordinary slices still zero on return; bulk slices alone currently skip clearing. This provides a new scoped hypothesis: allow explicit byte-buffer leases to reuse dirty ordinary slices while keeping ordinary allocation zero-filled. The prototype and poisoned-storage tests are pending validation.

The first scoped ordinary-slice prototype changes only plaintext upstream/header byte buffers and response body chain nodes; connection request/send buffers still use ordinary cleared allocations. Its two-sample alternating diagnostic results against the accepted header-push binary are:

| Case | Mean RPS change |
|---|---:|
| 16-c1-close | +0.22% |
| 16-c1-keepalive | -0.00% |
| 16-c32-close | -0.42% |
| 65536-c1-close | +0.42% |
| 65536-c1-keepalive | +0.05% |

All preflight and warmup/load checks pass, but none of these changes establish a gain. The pool is shared: connection teardown pushes dirty upstream/header buffers after the ordinary request/send buffers, so the following connection can clear them during its ordinary allocations. This is a source-level explanation to test, not a measured allocation census. The next experiment will include the plaintext connection request/send byte buffers and preserve zero-filled allocation for other callers.

Re-examining the retained eBPF return counters clarifies the apparent extra tiny upstream receive: at 16 B/c1 close, Rut has 58,682 upstream EAGAIN returns for 58,744 completed requests; nginx has none. Keepalive likewise has 81,443 EAGAIN returns for 81,462 Rut requests. Both perform one successful upstream copy per request. Thus the extra calls are predominantly speculative empty reads, not split payload copies. At c32 Rut EAGAIN falls to 1,218/106,622 requests; nginx instead has 100,779 upstream zero returns (EOF). These are workload/timing-dependent observations, not a universal backend ordering. Earlier POLL_FIRST trials covered 64 KiB and were inconclusive; the tiny c1 response is a distinct follow-up candidate.

The scoped uninitialized prototype passed all 71 arena tests (1,139,070 checks). Its network run reports 1,422 pass/1 fail: four checks in the deferred-body-slice reclamation test assumed `in_use_map` contained exactly 0/1. The dirty state adds bit 1, so the ownership checks are being updated to inspect bit 0 without weakening the before/after-completion lifetime assertion. The expanded candidate includes plaintext io_uring connection request/send buffers and a poisoned reuse/parser/TLS-listener control; its full suite and reverse-order performance check remain pending.

Expanded plaintext connection-buffer diagnostic, two samples per engine:

| Case | Mean RPS change |
|---|---:|
| 16-c1-close | -0.49% |
| 16-c1-keepalive | +0.05% |
| 16-c32-close | +6.72% |
| 65536-c1-close | -0.42% |
| 65536-c1-keepalive | -1.02% |

Only 16 B/c32 close shows a material positive signal (+6.72%); 64 KiB/c1 keepalive is about 1% lower. All body/warmup/load checks passed. The expanded source is experimental and uncommitted; full network tests and the reverse-order c32 run are queued/running. No improvement has yet been accepted from this prototype.

The expanded candidate subsequently passes all 1,424 network tests (371,775 checks) and 71 arena tests (1,139,070 checks). This includes a dirty connection-buffer reuse test, parser valid-length bounds, preserved zero-filled TLS-listener allocations, and unchanged deferred body ownership assertions using the in-use bit. Reverse-order performance validation is still running; test success alone does not establish a throughput benefit.

The reverse-order 16 B/c32 close probe returns baseline 14,845/14,145 RPS and candidate 14,861/14,883 RPS, a +2.60% mean change. Both directions are positive, but one baseline sample matches the candidate and the baseline varies, so +6.72% is not a stable expected gain. A 12-cell 16 B HTTP static/proxy acceptance matrix and the two 64 KiB/c1 proxy acceptance controls are now running serially. The first matrix invocation exited at argument parsing because the driver requires TLS credential paths even for HTTP-only selection; no load ran from that invocation. The corrected invocation is queued after the 64 KiB controls.

The 64 KiB/c1 proxy controls completed with three valid five-second samples per engine and complete cleanup.

| Mode | nginx median RPS | Rut median RPS | Ratio |
|---|---:|---:|---:|
| close | 6058 | 5919 | 0.9771 |
| keepalive | 8031 | 7722 | 0.9616 |

Both remain below the 1.10 goal; this is not proof that the candidate beats the accepted Rut baseline. Raw evidence and its hash are retained. The separate 12-cell 16 B acceptance process is live.

A one-line POLL_FIRST follow-up is queued behind the 16 B acceptance matrix. It changes only `add_recv_upstream_once` and compares against the frozen uninitialized-connection candidate, isolating receive submission timing from buffer clearing. The earlier POLL_FIRST probes covered 64 KiB, while the retained tiny-response eBPF return counters now justify checking 16 B/c1 and c32 explicitly, with 64 KiB controls. Its build and load remain serialized; no POLL_FIRST runtime change has yet been accepted.

## Ordinary dirty-buffer candidate: 16 B formal results

All 12 coordinates have three valid five-second samples per engine, clean warmup/load counters and complete cleanup. Eight meet the 1.10 target. The matrix exit code 2 reflects the unmet performance target.

| Scenario | Concurrency | nginx median RPS | Rut median RPS | Ratio |
|---|---:|---:|---:|---:|
| static-close | 1 | 14119 | 16285 | 1.1534 |
| static-close | 32 | 34886 | 45471 | 1.3034 |
| static-close | 128 | 34072 | 45323 | 1.3302 |
| static-keepalive | 1 | 38386 | 60856 | 1.5853 |
| static-keepalive | 32 | 83326 | 249677 | 2.9964 |
| static-keepalive | 128 | 83609 | 258150 | 3.0876 |
| proxy-close | 1 | 7614 | 7609 | 0.9994 |
| proxy-close | 32 | 14024 | 14688 | 1.0473 |
| proxy-close | 128 | 13897 | 15001 | 1.0794 |
| proxy-keepalive | 1 | 10904 | 10998 | 1.0086 |
| proxy-keepalive | 32 | 16709 | 19859 | 1.1886 |
| proxy-keepalive | 128 | 16691 | 22833 | 1.3680 |

Proxy close c1 remains effectively tied; close c32/c128 and keepalive c1 still miss the target. These results do not establish the causal change against the previous Rut binary for static responses; the separate alternating static probe is queued. The POLL_FIRST prototype builds after this completed matrix and uses its own binary and evidence directory.

The alternating static control confirms the connection-buffer change against the previous accepted Rut binary:

| Case | Mean RPS change |
|---|---:|
| 16-c1-close | +7.47% |
| 16-c32-close | -0.02% |

Both c1 candidate samples exceed both baseline samples. At c32 user CPU drops but throughput is flat. Retain the explicit uninitialized network-buffer leases based on the c1 static gain, the positive proxy c32 controls, the passing full tests, and formal nginx comparisons. The ordinary allocator still returns zero-filled memory, and dirty leases remain bounded by the existing cache budget and completion ownership. This is not across-matrix acceptance. POLL_FIRST remains a separate pending prototype.

## POLL_FIRST: measured empty-read removal

Both focused TCP-only eBPF traces are complete/usable with matching target identities and clean warmup/load counters. At 16 B/c1 close, upstream recv calls/request drop from 1.9992 to 1.0000, and upstream EAGAIN/request from 0.9992 to zero. Upstream recv elapsed time falls from 1.1063 to 0.8530 us/request. These inclusive elapsed times are instrumented diagnostics, not pure CPU time or acceptance throughput. The corresponding uninstrumented 16 B/c1 close change is -0.04%, so removing this empty read is not enough to close the main throughput gap.

| Probe | Case | Mean RPS change |
|---|---|---:|
| small-poll-first-r1 | 16-c1-close | -0.04% |
| small-poll-first-r1 | 16-c1-keepalive | +0.38% |
| small-poll-first-r1 | 16-c32-close | -0.58% |
| small-poll-first-r1 | 65536-c1-close | +0.90% |
| small-poll-first-r1 | 65536-c1-keepalive | +1.90% |
| small-poll-first-64k-r2 | 65536-c1-close | +1.09% |
| small-poll-first-64k-r2 | 65536-c1-keepalive | +0.93% |

The 64 KiB changes are positive in both process orders, around 1–2%; no material gain appears for 16 B. The full network suite and formal 64 KiB nginx controls are running before deciding whether to retain the one-line change.

POLL_FIRST passes the full 1,424-test network suite (371,775 checks). Its formal 64 KiB comparison is now running. A separate large-file header-only experiment is queued behind it: suppress the copied body prefix only where the original file tail would exceed 64 KiB, preserving small-file behavior and the accepted no-MSG_MORE large-header push. The earlier file-body-only probe retained MSG_MORE, so this checks a previously unmeasured interaction. The frozen POLL_FIRST binary is the control, and only the static native-body path is measured. No runtime conclusion is available yet.

The POLL_FIRST 64 KiB/c1 formal controls completed with three valid five-second samples per engine and clean cleanup:

| Mode | nginx median RPS | Rut median RPS | Ratio |
|---|---:|---:|---:|
| close | 6077 | 5972 | 0.9827 |
| keepalive | 8008 | 7796 | 0.9735 |

Retain POLL_FIRST on one-shot upstream receives: both-order 64 KiB diagnostics show small positive changes, eBPF verifies removal of speculative empty reads, and the full network suite passes. The before/after formal ratios move from 0.9771/0.9616 to 0.9827/0.9735, but these are separate runs on an unreserved host and do not establish an exact gain. Both cells still miss the goal. Tiny-response throughput is effectively unchanged; no across-matrix claim follows.

## Rejected uncorked header-only large-file send

Against the accepted POLL_FIRST/dirty-buffer binary, removing the copied initial body prefix while preserving the no-MSG_MORE header push gives:

| Case | Mean RPS change |
|---|---:|
| 1m-c1-keepalive | +2.49% |
| 1m-c32-close | -14.88% |
| 1m-c32-keepalive | -10.88% |

All preflight and warmup/load counters pass, but both c32 modes regress materially. Revert the prototype; it has no full-network test gate and is not retained runtime code. The result shows that the initial body prefix matters even with the earlier corking change, without proving a specific window-growth mechanism. The accepted frozen POLL_FIRST binary is now running the complete 96-coordinate quick diagnostic matrix.

A larger-prefix control is queued after the 96-cell scan: for plaintext memfd responses >=128 KiB, borrow a bulk slice but bind only 64 KiB of send capacity, copy the already-built header before returning its old slice, and preserve the normal sendfile remainder. It declines on an armed send, absent pool support, or allocation failure. This may consume an additional bulk lease and touch more memory per active connection; the diagnostic captures RSS. It is an unbuilt/unvalidated hypothesis at this checkpoint, not retained production code. No huge-page advice or kernel setting is changed.

## Accepted-runtime full quick matrix after POLL_FIRST

The complete HTTP/HTTPS × four scenarios × four sizes × three concurrency levels matrix has 96 valid diagnostic coordinates. 92 ratios are >=1.00, and 71 are >=1.10. Every coordinate is performance-ineligible because this is one two-second sample per engine. Do not combine these with older formal results to claim acceptance for the current binary. The remaining ratios below 1.10 are:

| Transport | Bytes | Scenario | Concurrency | Rut/nginx |
|---|---:|---|---:|---:|
| http | 16 | proxy-close | 1 | 0.9917 |
| http | 16 | proxy-close | 32 | 1.0345 |
| http | 16 | proxy-close | 128 | 1.0543 |
| http | 16 | proxy-keepalive | 1 | 1.0102 |
| http | 1024 | proxy-close | 1 | 0.9939 |
| http | 1024 | proxy-close | 32 | 1.0491 |
| http | 1024 | proxy-close | 128 | 1.0542 |
| http | 1024 | proxy-keepalive | 1 | 1.0137 |
| http | 65536 | static-close | 1 | 1.0284 |
| http | 65536 | static-close | 32 | 1.0994 |
| http | 65536 | static-close | 128 | 1.0947 |
| http | 65536 | static-keepalive | 1 | 1.0664 |
| http | 65536 | proxy-close | 1 | 0.9856 |
| http | 65536 | proxy-keepalive | 1 | 0.9578 |
| http | 1048576 | static-close | 1 | 1.0707 |
| http | 1048576 | static-keepalive | 32 | 1.0381 |
| http | 1048576 | static-keepalive | 128 | 1.0269 |
| http | 1048576 | proxy-close | 1 | 1.0711 |
| http | 1048576 | proxy-close | 32 | 1.0479 |
| http | 1048576 | proxy-close | 128 | 1.0023 |
| https | 16 | proxy-keepalive | 1 | 1.0654 |
| https | 1024 | proxy-keepalive | 1 | 1.0592 |
| https | 65536 | proxy-keepalive | 1 | 1.0283 |
| https | 1048576 | static-close | 128 | 1.0378 |
| https | 1048576 | proxy-close | 128 | 1.0076 |

All four ratios below 1.00 are HTTP/c1 proxy: 16 B close, 1024 B close, 64 KiB close, and 64 KiB keepalive. The other 21 listed coordinates lead nginx in this scan but miss the 1.10 target. Prior 1 MiB/static/keepalive c1 formal measurements were effectively tied, so its favorable single sample here is not proof that it is solved. Complete raw logs, host snapshots, configurations and per-group statuses are archived with a hash; TLS private keys and payload binaries are excluded.

## Rejected 64 KiB initial file prefix

Two alternating samples per engine, all preflight and warmup/load checks passing:

| Case | Mean RPS change | Candidate/baseline mean RSS MiB |
|---|---:|---:|
| 1m-c1-keepalive | -20.43% | 133.7/133.7 |
| 1m-c32-close | -3.08% | 135.9/134.8 |
| 1m-c32-keepalive | +1.05% | 135.8/134.6 |

The c1 keepalive regression is about 20%; c32 close also regresses. Revert the prototype, which did not receive a full network test run. At c32 keepalive its system CPU time rises from about 35.6 to 57.6 us/request despite almost flat throughput; this does not establish a specific kernel mechanism. The accepted 16 KiB prefix remains. The next proposed control revisits synchronous prefix completion: the earlier prototype set the file-completion recursion guard around the prefix, which forced a full keepalive file tail to queue a completion. A non-empty file tail can instead use its existing body-completion guard to stop synchronous pipeline recursion. That needs an explicit pipeline test before retention.

## Rejected synchronous keepalive file prefix without outer guard

Two alternating 6-second samples per engine, body preflight and warmup/load checks passed.

| Case | Mean RPS change |
|---|---:|
| 1m-c1-keepalive | +8.70% |
| 1m-c32-close | +0.88% |
| 1m-c32-keepalive | -2.57% |

The c1 baseline was bimodal (5463.5 and 4686.0 RPS), while the candidate was around 5510–5523 RPS. This does not establish a stable c1 gain; c32 keepalive regressed. The prototype was reverted without a full network test run. No acceptance claim.

## Sampled client receive SKB geometry

Accepted runtime versus pinned nginx, HTTP 1 MiB static keepalive. Four traces passed target identity and diagnostic checks; preflight bodies and warm/load error checks passed. Approximately 1/64 helper entries are sampled. Instrumented throughput is not acceptance evidence.

| Case | Samples | One fragment | 16+ fragments |
|---|---:|---:|---:|
| 1048576-c1-keepalive-nginx | 120211 | 2.10% | 97.90% |
| 1048576-c1-keepalive-rut | 158008 | 7.81% | 86.97% |
| 1048576-c32-keepalive-nginx | 267811 | 2.10% | 97.90% |
| 1048576-c32-keepalive-rut | 269850 | 1.41% | 93.00% |

These are call-weighted observations of whole SKBs at copy-helper entry, not bytes-weighted distributions or the number of fragments traversed by each partial copy. Both engines predominantly present SKBs with 16+ fragments; this does not support a simple explanation that Rut alone suffers highly fragmented receive buffers. Differences in smaller SKBs remain correlational. No page-size or kernel setting was changed. The first diagnostic run was rejected for a signed division warning; the corrected run has no diagnostic warnings.

## Rejected early upstream request send

For requests up to 4096 bytes, reserve an SQE before a nonblocking send; full writes use a result-injected NOP, partial writes retain offset and queue the remainder. Upstream episode and CQE accounting remain in the existing path. Two alternating 6-second samples per engine versus accepted POLL_FIRST runtime:

| Case | Mean RPS change |
|---|---:|
| 16-c1-close | -0.06% |
| 16-c1-keepalive | +0.32% |
| 16-c32-close | -3.36% |
| 65536-c1-close | +0.25% |
| 65536-c1-keepalive | +1.03% |

All preflight and warm/load checks passed. The c32 small-response regression outweighs the roughly 1% 64 KiB keepalive improvement; reverted before full network regression. A diagnostic phase trace is being collected separately; no instrumented RPS is used for acceptance.

## Small proxy upstream send-to-read phase trace

HTTP 16 B c1 close; all three traces usable with stable target identities and zero warm/load errors. Interval is tcp_sendmsg entry to the first successful tcp_recvmsg exit on the same upstream socket. It includes origin, scheduler, network, and receive-copy time; it is not CPU time.

| Engine | Samples | Mean us |
|---|---:|---:|
| 16-c1-close-nginx | 60295 | 25.134 |
| 16-c1-close-rut-base | 60425 | 24.613 |
| 16-c1-close-rut-direct | 60322 | 24.579 |

Rut does not have a larger mean than nginx in this interval in this diagnostic. Instrumentation overhead and run ordering prevent interpreting this as an acceptance comparison. The rejected direct-send experiment did not improve uninstrumented c1 throughput materially. The next trace splits the front-read to upstream-send and upstream-read to front-send intervals; process-level correlation is only valid for this c1, non-pipelined workload.

## Expanded c1 proxy phase trace

Both traces usable, identity stable, exact-body preflight passed, zero warm/load errors. Process-level correlation is restricted to this non-pipelined HTTP 16 B c1 close load. Intervals include scheduling and kernel work and are not CPU time.

| Engine | Front read→upstream send us | Upstream send→read us | Upstream read→front send us | Front read→send us |
|---|---:|---:|---:|---:|
| 16-c1-close-nginx | 33.300 | 24.964 | 18.664 | 76.577 |
| 16-c1-close-rut-base | 33.468 | 24.419 | 20.328 | 77.910 |

The three stage means should sum closely to the full interval; probe execution between timestamps adds small overhead. Instrumented timings do not substitute for an uninstrumented throughput comparison.

## Upstream TCP close timing control

HTTP 16 B c1 close, both traces usable with exact-body and zero warm/load error checks. Mean inclusive upstream tcp_close elapsed time is 11.227 us for nginx and 10.955 us for Rut. Front read→send is 76.831/78.617 us and upstream read→front send is 18.811/21.024 us respectively. These traces do not support slower upstream close as the cause of Rut’s response-stage gap. Close time is an inclusive kernel interval, not CPU time; asynchronous close could also run outside the response-stage interval, so subtraction is not a proof of userspace overhead. Runtime retirement ordering remains unchanged.

## Rejected per-thread second-level Date cache

A thread-local 29-byte cache keyed by exact realtime second avoids repeated gmtime_r and formatting within the second. Epoch-zero, same-second, rollover and backward-clock output/guard tests passed (24 checks); the full network suite passed all 1425 tests / 371799 checks. Forward and reverse benchmark order:

| Run | Case | Mean RPS change |
|---|---|---:|
| date-cache-r1 | 16-c1-close | -0.03% |
| date-cache-r1 | 16-c1-keepalive | +0.05% |
| date-cache-r1 | 16-c32-close | +1.86% |
| date-cache-r1 | 65536-c1-close | -0.18% |
| date-cache-r1 | 65536-c1-keepalive | -0.73% |
| date-cache-r2 | 16-c1-close | -0.35% |
| date-cache-r2 | 16-c1-keepalive | -0.50% |
| date-cache-r2 | 16-c32-close | -1.13% |
| date-cache-r2 | 65536-c1-close | -0.35% |
| date-cache-r2 | 65536-c1-keepalive | -1.03% |

The throughput improvement is not repeatable; 64 KiB keepalive regresses in both orders. Reverted runtime and test changes, retaining patch and raw evidence. Build-rel still contains the rejected candidate until rebuilt; rut-small-poll-first remains the accepted frozen binary. An independent accepted-source build with the existing RUT_ENABLE_IPO option is queued to test code-generation effects without changing runtime semantics.

## Rejected ThinLTO build control

An independent source snapshot of b833535e (accepted runtime unchanged since 06cdea9d) enables the existing RUT_ENABLE_IPO option. The runtime command differs from baseline only by -flto=thin after excluding source/build paths; dependencies also receive IPO through CMake. Build completed, binary hash and compile command retained. All body preflight and warm/load checks passed. Two alternating 6-second samples per engine:

| Case | Mean RPS change |
|---|---:|
| 16-c1-close | +0.06% |
| 16-c1-keepalive | -0.16% |
| 16-c32-close | -0.91% |
| 65536-c1-close | -0.81% |
| 65536-c1-keepalive | -0.58% |

No measured improvement supports retaining IPO for this goal. No default build setting changed and no full IPO network suite was run. These diagnostic samples do not establish a universal LTO regression.

## 64 KiB front-side send geometry

All four traces usable with exact-body preflight and zero warm/load errors. Kernel tcp_sendmsg entry counts normalized by measured completed requests:

| Case | Calls/request |
|---|---:|
| 65536-c1-close-nginx | 5.0248 |
| 65536-c1-close-rut-base | 3.0063 |
| 65536-c1-keepalive-nginx | 5.1330 |
| 65536-c1-keepalive-rut-base | 3.0009 |

Rut uses approximately three calls: a 128–255 byte rewritten header, an 8–16 KiB first body fragment, and a 32–64 KiB remainder. nginx uses about five. Thus excess Rut send-call count is not supported; Rut still pays serial completion/pump transitions between its three fragments. Different probe counts bias instrumented throughput, so no throughput conclusion is drawn. A small-header synchronous-completion prototype is being tested separately; it preserves the existing owned Send generation, exact-frame checks and ordinary asynchronous body completion.

## Rejected synchronous terminal proxy header

A complete small plaintext Bounded header was dispatched synchronously with the same owned generation and exact send-frame checks, while body sends remained asynchronous. Partial header writes used the existing remainder proactor. All preflight and warm/load checks passed; no full network suite was run.

| Case | Mean RPS change |
|---|---:|
| 16-c1-close | -0.93% |
| 16-c1-keepalive | -0.63% |
| 16-c32-close | -0.76% |
| 65536-c1-close | -0.18% |
| 65536-c1-keepalive | +0.48% |

The roughly 0.5% 64 KiB keepalive signal is insufficient to retain a new synchronous completion path, especially with flat close results and noisy negative control cases. Reverted.

## Rejected 12 KiB page-aligned file prefix

For plaintext memfd bodies >=128 KiB, round the copied initial body prefix down to a 4 KiB multiple. This keeps the ordinary 16 KiB send slice, usually copying 12 KiB of body before sendfile. Exact-body preflight and warm/load checks passed; no full network suite.

| Case | Mean RPS change |
|---|---:|
| 1m-c1-keepalive | +12.34% |
| 1m-c32-close | +0.12% |
| 1m-c32-keepalive | -3.41% |

The c1 baseline is bimodal again (5666.5/4742.8 RPS), so the mean gain is not a stable expected speedup; candidate samples are 5819.5/5873.8. The c32 keepalive regression prevents retaining this variant. The test changes both alignment and initial burst length. The next prototype keeps 16 KiB body bytes in the prefix using a wider staging buffer; that introduces a separate allocation/layout change and must be measured, not assumed beneficial.

## 16 KiB aligned file prefix: concurrency tradeoff

A wider (32 KiB bound) staging view backed by an existing bulk lease allows copying exactly 16 KiB of body after the header. Existing bulk leases are reused on keepalive; otherwise the ordinary send slice is returned after copying its header. Only plaintext memfd bodies >=128 KiB are eligible. This changes allocation/layout as well as offset alignment.

| Run | Case | Mean RPS change |
|---|---|---:|
| file-prefix16-aligned-r1 | 1m-c1-keepalive | +18.34% |
| file-prefix16-aligned-r1 | 1m-c32-close | -0.02% |
| file-prefix16-aligned-r1 | 1m-c32-keepalive | -0.75% |
| file-prefix16-aligned-r2 | 1m-c1-keepalive | +19.80% |
| file-prefix16-aligned-r2 | 1m-c32-close | +0.49% |
| file-prefix16-aligned-r2 | 1m-c32-keepalive | -4.64% |

All benchmark preflight and warm/load checks passed. Three pipelined nonuniform 1 MiB responses on one real socket matched exactly; this is not a full regression. c1 candidates stay around 5855–5913 RPS while baseline varies around 4623–5360. c32 keepalive regresses across both orderings; c32 close is effectively flat. Thus this cannot be retained as a universal improvement. c1 close and c2/4/8/16 keepalive probes are queued to determine whether a repeatable concurrency crossover exists before considering a workload-dependent strategy. No such strategy is implemented.

## Aligned prefix follow-up: reject universal 16 KiB staging

Additional uninstrumented controls, all exact-body and warm/load checks passing:

| Case | Mean RPS change |
|---|---:|
| 1m-c1-close | +1.95% |
| 1m-c16-keepalive | -14.04% |
| 1m-c2-keepalive | -1.98% |
| 1m-c4-keepalive | -4.79% |
| 1m-c8-keepalive | -5.91% |

All tested keepalive concurrency levels above one regress. Do not retain this as a universal change or introduce a benchmark-coordinate branch. Four usable TCP window traces show a strong correlated reversal: for c1, peer window >=1 MiB rises from 0% to 99.83% and notsent >=64 KiB falls from 50.38% to 0.05%; at c32, notsent >=64 KiB rises from 39.11% to 64.85%. These are call-weighted observations, not time fractions, and do not isolate alignment from allocation or initial-burst size. A 32 KiB page-aligned body prefix is the next independent control; the previous rejected 64 KiB staging experiment had an unaligned body offset. No huge pages or global TCP settings are changed.

## Rejected 32 KiB aligned file prefix

The 32 KiB body prefix retains page alignment with a wider staging buffer; all preflight/warm/load checks passed.

| Case | Mean RPS change |
|---|---:|
| 1m-c1-keepalive | -7.45% |
| 1m-c32-close | -4.20% |
| 1m-c32-keepalive | -12.37% |

It also regresses concurrent cases and reintroduces c1 bimodality. Reverted without full network regression. This ends the prefix-size series. Slow c1 samples have negligible runqueue delay (roughly 0.05–0.1 us/request); they spend less server CPU per request, consistent with socket waiting rather than observed CPU scheduling delay, though not a proof of the exact TCP mechanism.

## Rejected 256 KiB sendfile syscall bursts

Keep the accepted prefix and logical completion while limiting each sendfile syscall to 256 KiB, looping while full bursts succeed. All preflight/warm/load checks passed.

| Case | Mean RPS change |
|---|---:|
| 1m-c1-keepalive | -2.08% |
| 1m-c32-close | -1.55% |
| 1m-c32-keepalive | +2.37% |

The c1 and close controls do not support retaining the concurrent keepalive signal; reverted without full network regression. The next small-response control targets CombinedSend, which the earlier rejected final-proxy-FIN patch did not cover (it only handled BodySend and tested >=64 KiB).

## Small closing CombinedSend early FIN: first control

A complete <=4096-byte plaintext Bounded response, with exact CombinedSend frame and retired upstream, uses the existing direct local-response write/early shutdown path. Its generation-authenticated CQE still owns completion/accounting; partial sends keep the existing async remainder. No keepalive/TLS/streaming path is admitted. All preflight/warm/load checks pass.

| Case | Mean RPS change |
|---|---:|
| 1024-c1-close | +2.01% |
| 1024-c32-close | +12.82% |
| 16-c1-close | +2.03% |
| 16-c1-keepalive | -0.21% |
| 16-c32-close | +14.76% |
| 65536-c1-close | -0.13% |
| 65536-c1-keepalive | +0.63% |

This targets the merged small response, unlike the previous >=64 KiB BodySend-only FIN experiment. A new lifecycle regression asserts body and EOF are visible before completion, peer EOF cannot pre-empt accounting, and duplicate completion does not count twice. Full network testing and reverse order are pending; no retention or nginx acceptance claim yet.

## CombinedSend FIN lifecycle gate and fix

The first added test failed before CombinedSend because the hand-built Bounded fixture lacked an exact GET route marker. After correcting the fixture, the test exposed an actual lifecycle defect in the prototype: response batch preparation invalidated the owner on peer EOF before the already-written response’s CQE could account completion. The earlier performance samples therefore describe an unretained, incorrect prototype.

The corrected runtime defers only untagged terminal downstream events for a fully written final CombinedSend with matching source, fd, length, generation, frame and pending operation. Partial direct writes do not acquire this deferral. Upstream surplus/timer validation remains in its normal path; dispatch still accounts the downstream receive event. The exact send completion then accounts and closes once; stale/duplicate generations remain handled by existing ownership checks.

The focused lifecycle test now passes 21 checks; full network regression passes all 1425 tests / 371796 checks. Original failures and passing logs are retained. The corrected binary has its own hash; both performance orders, a send-to-shutdown eBPF comparison, and the 12-coordinate HTTP small-proxy nginx acceptance matrix are queued/running under the shared lock. No runtime retention or full-matrix pass is claimed yet.

## Corrected CombinedSend FIN: eBPF and reverse-order evidence

All four traces are usable, preserve target process identity, and have zero warm/load errors. The interval runs from the most recent front-socket tcp_sendmsg entry to tcp_shutdown entry: it includes send work and completion waiting, and does not measure CPU time or delivery on the wire.

| 16-byte close | Accepted baseline mean | Corrected candidate mean |
|---|---:|---:|
| c1 | 10.288 us | 7.509 us |
| c32 | 398.864 us | 7.691 us |

The c32 reduction supports eliminating delayed FIN while awaiting asynchronous completion. Instrumented throughput is not acceptance evidence. Corrected reverse-order uninstrumented results are archived separately from the incorrect first prototype. Formal nginx comparison remains pending.

Corrected forward-order controls also completed with 28 valid samples, exact-body checks and zero warm/load errors:

| Case | Mean RPS change |
|---|---:|
| 1024-c1-close | +2.22% |
| 1024-c32-close | +14.03% |
| 16-c1-close | +1.95% |
| 16-c1-keepalive | -0.96% |
| 16-c32-close | +13.96% |
| 65536-c1-close | -0.08% |
| 65536-c1-keepalive | -0.71% |

Both orders retain the closing-small-response gain; excluded-path controls show up to about 1% negative variation. The nginx 12-coordinate acceptance run has now started. Runtime retention awaits its result and formatting gate.

## Corrected CombinedSend FIN: formal small-proxy acceptance

All 12 HTTP cells complete, with three valid 5-second samples per engine, clean warmup/load and response checks. Exit 2 reflects the unmet performance target, not invalid measurement. Eight cells meet the 1.10 ratio; all four c1 cells remain below the target. No full 96-coordinate success is claimed.

| Bytes | Scenario | Concurrency | Rut/nginx median RPS | Target |
|---|---|---:|---:|---|
| 16 | proxy-close | 1 | 1.0238 | below 1.10 |
| 16 | proxy-close | 32 | 1.2064 | pass |
| 16 | proxy-close | 128 | 1.3077 | pass |
| 16 | proxy-keepalive | 1 | 1.0022 | below 1.10 |
| 16 | proxy-keepalive | 32 | 1.1866 | pass |
| 16 | proxy-keepalive | 128 | 1.3841 | pass |
| 1024 | proxy-close | 1 | 1.0283 | below 1.10 |
| 1024 | proxy-close | 32 | 1.2083 | pass |
| 1024 | proxy-close | 128 | 1.2672 | pass |
| 1024 | proxy-keepalive | 1 | 1.0010 | below 1.10 |
| 1024 | proxy-keepalive | 32 | 1.1863 | pass |
| 1024 | proxy-keepalive | 128 | 1.3564 | pass |

Both causal orders and the full 1425-test network regression support retaining this closing-small-response optimization. CPU profiling of the corrected binary and front-socket shutdown cost comparison with nginx follow under the same benchmark lock.

## Corrected FIN current user-cycle profile: small proxy close

The 20-second HTTP 16-byte c1 close profile has 16,964 cycles:u samples with zero lost samples and clean warm/load errors. Self shares: io_uring wait 5.59%, response parser 4.36%, coalesced GET phase-1 proof 3.56%, header-name scan 2.99%, policy-bundle validity 2.71%, and memset 1.07%. These percentages describe sampled userspace cycles, not total request latency or a direct nginx comparison. Some DWARF call stacks are incomplete/unknown; use self attribution and do not infer reliable complete call chains. Raw perf.data remains in the lab directory; textual reports and collector/workload logs are retained here. Keepalive profiling and kernel shutdown-cost comparison are still running/queued.

The matching keepalive user-cycle capture has also completed with exact-body and clean warm/load checks. io_uring wait self share is 5.18% and response-parser self share is 5.11%. Its instrumented throughput is diagnostic only. The two workload reports and metrics are archived; the same incomplete-call-stack limitation applies.

## Front TCP shutdown cost and FIN retention

All four shutdown traces are usable with clean warm/load checks. nginx records no front tcp_shutdown calls (its ordinary close path sends FIN). Corrected Rut records 89,275 calls / 61,635 front sends at c1, and 134,702 / 134,684 at c32. Total inclusive tcp_shutdown time is 196,793,000 ns and 421,026,106 ns, respectively. This is a kernel-function measurement, not total shutdown syscall overhead; calls returning before tcp_shutdown are invisible. The excess c1 calls warrant a separate guarded experiment, but do not explain all remaining latency.

Formatting now passes for the two changed runtime/test files, with whitespace-only adjustments after the tested binary was frozen. Retain the corrected CombinedSend early-FIN implementation and lifecycle test based on both causal orders, full network regression, and the formal 12-cell comparison. Remaining 96-cell target failures remain open.

## AVX2 header-name token validation prototype

The current small-proxy profile identifies header-name scanning among the remaining userspace hotspots. Its AVX2 implementation finds the colon in parallel but validates preceding bytes with a scalar table loop. This prototype replaces that loop with low/high-nibble shuffle tables derived at compile time from the existing token table; only bytes before the first colon participate, and the scalar tail is unchanged. No parser policy is relaxed.

A scalar-oracle differential test covers all 256 byte values, 32 starting alignments, lengths around 16/32/64-byte boundaries, mutation before/at/after the delimiter, and both short and full scan bounds. All 217 parser tests / 724747 checks pass. The first uninstrumented causal order compares against the accepted CombinedSend FIN binary; full network regression and retention depend on its results.

## Token validation forward-order control

All 28 samples complete with exact-body and zero warm/load errors. These small effects need the already-running reverse order before a retention decision.

| Case | Mean RPS change |
|---|---:|
| 1024-c1-close | -0.01% |
| 1024-c32-close | +1.18% |
| 16-c1-close | +0.11% |
| 16-c1-keepalive | +0.41% |
| 16-c32-close | +0.34% |
| 65536-c1-close | +0.52% |
| 65536-c1-keepalive | -0.31% |

## Reject vector token validation after reverse control

All 28 reverse-order samples are valid with clean warm/load checks.

| Case | Mean RPS change |
|---|---:|
| 1024-c1-close | -0.00% |
| 1024-c32-close | -1.45% |
| 16-c1-close | +0.20% |
| 16-c1-keepalive | -0.03% |
| 16-c32-close | -0.79% |
| 65536-c1-close | +0.10% |
| 65536-c1-keepalive | +0.05% |

The c32 gains do not repeat and reverse into regressions; c1 effects remain near noise. Revert the runtime prototype and its added differential test, preserving the complete patch, passing parser tests and both causal orders. No full network test or retention is claimed. The frozen vector binary is diagnostic only; the accepted runtime remains 271cd98c / rut-combined-fin-ordered.

## First Bounded plaintext header direct-recv prototype

The initial validated header owner can receive directly into its pinned upstream_recv_buf, capped at the existing one-shot ring limit and using POLL_FIRST. It records destination, length, episode and deadline generation. The backend does not release that ownership for a foreign episode; the matching terminal CQE checks destination, bound, generation and pre-header phase before committing. Subsequent fragmented-header reads keep the existing provided-buffer path. Body and TLS recv selection are unchanged.

All existing 1425 network tests / 371796 checks pass. An additional target-ownership test (foreign episode followed by correct completion, pointer/generation drift, cancellation) is queued for build; it was not included in the preceding full run. The first causal benchmark compares against the accepted FIN runtime. No retention or performance claim yet.

## Direct header first causal order: large-response regression

All 28 exact-body/warm/load controls pass.

| Case | Mean RPS change |
|---|---:|
| 1024-c1-close | +0.07% |
| 1024-c32-close | +0.01% |
| 16-c1-close | +0.30% |
| 16-c1-keepalive | +0.52% |
| 16-c32-close | +0.83% |
| 65536-c1-close | -3.23% |
| 65536-c1-keepalive | -3.87% |

Both the provided-buffer ring and ordinary destination have a 16 KiB capacity, confirmed by their constants and static assertion. A smaller nominal receive limit therefore does not explain the 64 KiB regression. Small-response effects do not justify retaining a universal change with both 64 KiB controls down over 3%. The additional ownership test is compiling; after its result the prototype will be reverted. No nginx acceptance is claimed for this experiment.

The additional direct-header ownership test passes all 96 checks (foreign episode preservation, exact completion, pointer/generation drift and cancellation). The prototype and added test are now reverted because of the measured 64 KiB regressions; the formatted patch and passing focused log are retained. Accepted runtime remains 271cd98c.

## Successful plaintext shutdown deduplication prototype

The earlier eBPF trace observed excess front tcp_shutdown calls at c1. This independent prototype records successful plaintext SHUT_WR until connection reset, skips a repeated call in the normal completion close path, and preserves retry after failure. It does not move Send completion accounting. The existing CombinedSend EOF regression additionally checks that the successful early shutdown is recorded. Full network regression passes; causal and eBPF comparisons are running/queued. A process-wide sys_enter_shutdown counter complements front tcp_shutdown counters, because early-returning syscalls may not reach that kernel function. No performance or retention claim yet.

## Shutdown deduplication first control

All 28 samples finish with clean exact-body/warm/load checks.

| Case | Mean RPS change | Baseline system us/request | Candidate system us/request |
|---|---:|---:|---:|
| 1024-c1-close | +0.38% | 54.08 | 52.18 |
| 1024-c32-close | +0.25% | 31.57 | 31.70 |
| 16-c1-close | -0.01% | 53.66 | 52.08 |
| 16-c1-keepalive | -0.05% | 41.69 | 41.19 |
| 16-c32-close | +0.49% | 31.73 | 31.58 |
| 65536-c1-close | +0.00% | 70.39 | 70.25 |
| 65536-c1-keepalive | +0.20% | 58.57 | 57.93 |

Small c1 system CPU savings require reverse-order confirmation; throughput is essentially flat. eBPF shutdown counting is in progress. A separate accepted-runtime/nginx 64 KiB recv-attempt trace is queued to distinguish header and body request lengths and EAGAIN outcomes before considering body POLL_FIRST.

The four shutdown traces are usable with zero warm/load errors. At c1, process-wide shutdown syscall count falls from 119106 / 59553 front sends (2.0/send) to 60723 / 60723 (1.0/send). At c32 it falls from 261806 / 130903 to 132066 / 132049. Occasional unsuccessful shutdowns can still retry, as intended. This confirms the mechanism; instrumented throughput is not acceptance evidence. Reverse-order uninstrumented controls remain in progress.

## Shutdown deduplication reverse control

All 28 reverse samples finish with exact-body and zero warm/load errors.

| Case | Mean RPS change | Baseline system us/request | Candidate system us/request |
|---|---:|---:|---:|
| 1024-c1-close | +0.40% | 53.64 | 51.94 |
| 1024-c32-close | +0.06% | 31.69 | 31.83 |
| 16-c1-close | -1.29% | 54.33 | 52.68 |
| 16-c1-keepalive | +0.67% | 41.89 | 41.39 |
| 16-c32-close | -0.48% | 32.02 | 32.11 |
| 65536-c1-close | +0.24% | 70.18 | 70.56 |
| 65536-c1-keepalive | +0.07% | 57.89 | 57.44 |

The small c1 system CPU saving repeats, but throughput remains uncertain: the 16-byte close candidate includes a 7543.7 RPS sample versus the other samples around 7730–7750. This sample is retained, not discarded. Static close controls are queued because the same code serves that path. No retention decision yet.

## Accepted 64 KiB proxy recv attempts

All four c1 close/keepalive Rut/nginx traces are usable, exact-body checked and zero warm/load errors. Counts are grouped by requested tcp_recvmsg length and return kind; request normalization uses the overlapping load window (trace edges may add a request). Rut has roughly three positive reads/request and only rare EAGAIN on the body read. This does not support body POLL_FIRST as a significant fix. nginx performs more smaller positive reads, so fewer recv calls alone does not explain the latency gap. Kind 3 combines EOF and other errors and must not be described as EAGAIN. Instrumented throughput is not acceptance evidence.

## Reject universal shutdown deduplication after static controls

All eight static controls pass exact-body/warm/load checks.

| Static case | Mean RPS change | Baseline system us/request | Candidate system us/request |
|---|---:|---:|---:|
| 16-c1-close | -5.15% | 18.34 | 17.59 |
| 16-c32-close | +0.75% | 11.50 | 11.00 |

Both static c1 candidate samples regress against both baseline samples despite lower CPU cost. The mechanism reduces syscalls but does not provide a reliable throughput win across affected paths. Revert runtime and test changes, retaining the patch, full regression, both proxy orders, static controls and eBPF evidence. No causal claim is made about why the lower-CPU static path is slower. The accepted runtime remains 271cd98c. A c1 64 KiB response-stage trace is now queued/running against that accepted binary and nginx.

## 64 KiB response-stage trace and observer limitation

The first four attempts are unusable (two bpftrace type-inference compile failures, then signedness/redundant-cast diagnostics). The original map-name-collision suspicion was disproved by renaming. Explicitly typing the cumulative byte expression and removing the redundant consumer cast resolves the diagnostics. Failed attempts are retained and excluded.

All four r5 traces are usable with zero warm/load errors and exact completed response byte counts. Per-front-socket maps correlate c1 non-pipelined requests from front tcp_recvmsg return through first tcp_sendmsg entry and last successful tcp_sendmsg return, emitted at close or the next request. The intervals include userspace, kernel, waiting and origin work; they do not measure network delivery or CPU time. Rut close first-send/total means are 79.272/118.607 us versus nginx 78.735/124.344 us. This reverses the uninstrumented throughput ordering and is inconclusive about the original gap: nginx performs more recv/send calls and pays more probe work. Do not call the traced ordering a speedup or infer that the uninstrumented tail is faster.

## Full accepted-version formal matrix in progress

The complete 96-coordinate matrix is now running against the accepted 271cd98c runtime frozen as rut-combined-fin-ordered. It covers both transports, all four sizes/scenarios and three concurrency levels, with three 5-second measurements and 2-second warmups per engine. The native-body static and converter-strict proxy profiles, implicit keepalive, no upstream reuse, pinned nginx and >=1.10 target remain unchanged. Load budget is 4032 seconds plus setup/validation/cleanup. The rejected token-vector, direct-header and shutdown-once binaries are not used. No huge pages or kernel tuning are enabled. This entry records a live run, not completed acceptance.

## Full-matrix checkpoint: HTTP 16-byte coordinates

The first 12 coordinates of the full formal run are complete and valid; ten meet >=1.10. In c1/c32/c128 order, static close ratios are 1.1476/1.2720/1.3601, static keepalive 1.5859/2.8637/2.9596, proxy close 1.0252/1.2060/1.2870, and proxy keepalive 1.0043/1.1912/1.3658. Both proxy c1 coordinates remain below the acceptance target. This is an explicit partial checkpoint, not full-matrix completion; the same live process continues through the remaining coordinates.

## Full-matrix checkpoint: HTTP 1 KiB coordinates

The next twelve coordinates complete with valid measurements. Across the first 24 full-matrix coordinates, 19 meet >=1.10. The 1 KiB proxy-keepalive c1 median is 0.9991, marginally below nginx in this run; do not claim stable superiority from a near-tie.

| Scenario | Concurrency | Rut/nginx median RPS | Target |
|---|---:|---:|---|
| static-close | 1 | 1.0623 | below 1.10 |
| static-close | 32 | 1.3122 | pass |
| static-close | 128 | 1.4296 | pass |
| static-keepalive | 1 | 1.5701 | pass |
| static-keepalive | 32 | 3.4852 | pass |
| static-keepalive | 128 | 3.6838 | pass |
| proxy-close | 1 | 1.0268 | below 1.10 |
| proxy-close | 32 | 1.2092 | pass |
| proxy-close | 128 | 1.2579 | pass |
| proxy-keepalive | 1 | 0.9991 | below 1.10 |
| proxy-keepalive | 32 | 1.1769 | pass |
| proxy-keepalive | 128 | 1.3512 | pass |

The same live process continues through the 64 KiB, 1 MiB and HTTPS coordinates. This remains partial acceptance.

## Full-matrix checkpoint: HTTP 64 KiB coordinates

All twelve 64 KiB coordinates complete with valid formal measurements. Both proxy c1 modes remain below nginx; the static c1 modes lead but miss >=1.10.

| Scenario | Concurrency | Rut/nginx median RPS | Target |
|---|---:|---:|---|
| static-close | 1 | 1.0359 | below 1.10 |
| static-close | 32 | 1.1011 | pass |
| static-close | 128 | 1.2023 | pass |
| static-keepalive | 1 | 1.0631 | below 1.10 |
| static-keepalive | 32 | 1.4067 | pass |
| static-keepalive | 128 | 1.4372 | pass |
| proxy-close | 1 | 0.9806 | below 1.10 |
| proxy-close | 32 | 1.3702 | pass |
| proxy-close | 128 | 1.4075 | pass |
| proxy-keepalive | 1 | 0.9713 | below 1.10 |
| proxy-keepalive | 32 | 1.4854 | pass |
| proxy-keepalive | 128 | 1.5545 | pass |

The live full run continues through 1 MiB and HTTPS; this is not final acceptance.

## Full-matrix checkpoint: HTTP complete, HTTPS pending

All 48 HTTP coordinates complete with valid formal measurements; 33 meet >=1.10. 3 have a median below nginx. The remaining HTTPS half is still running.

| HTTP 1 MiB scenario | Concurrency | Rut/nginx median RPS | Target |
|---|---:|---:|---|
| static-close | 1 | 1.0665 | below 1.10 |
| static-close | 32 | 1.1810 | pass |
| static-close | 128 | 1.1740 | pass |
| static-keepalive | 1 | 1.1701 | pass |
| static-keepalive | 32 | 1.0517 | below 1.10 |
| static-keepalive | 128 | 1.0388 | below 1.10 |
| proxy-close | 1 | 1.0431 | below 1.10 |
| proxy-close | 32 | 1.0460 | below 1.10 |
| proxy-close | 128 | 1.0006 | below 1.10 |
| proxy-keepalive | 1 | 1.2137 | pass |
| proxy-keepalive | 32 | 1.1987 | pass |
| proxy-keepalive | 128 | 1.2619 | pass |

The static keepalive c1 ratio passes this run but prior runs showed bimodality/near-ties; this single formal pass does not erase that history. Both concurrent static keepalive and all proxy close 1 MiB coordinates remain below target. No full-matrix success is claimed.
