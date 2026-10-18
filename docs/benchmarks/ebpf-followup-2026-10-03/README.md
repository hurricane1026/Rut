# eBPF follow-up: phases, long flows, sidecar and Rut reference

The agreed next checks are complete. **The current SK_SKB egress-redirection
path does not pass the proposed gate: at least 10% throughput or whole-machine
CPU improvement, with no material p99 regression.** Do not expand its integration
into Rut's normal serving loops on the basis of these results. Keep the compiler
plans, bytecode and opt-in probes for reproducibility and hardware-specific work.

## 1. Locate the extra time

`bench_ebpf_handoff` now reports setup, header processing, copy/ownership handoff,
redirect completion wait, tail forwarding, TCP ordering-barrier wait, peer join
and retirement separately. `control_ns` is commit-call wall time within the
copy/handoff phase; `barrier_ns` is within the tail phase. They must not be added
again when summing phases. Relay, producer and reader thread CPU are reported
separately from process CPU; none includes unbound kernel workers elsewhere.

[initial-phases.jsonl](initial-phases.jsonl) retains the first 36 diagnostic
samples. Its records precede `requested_mode`; use ABBA positions to classify
the intended modes, including eBPF attempts that finish entirely through copy.
The extra wall time is mainly in the redirect-completion phase. This does not
distinguish TCP processing, workqueue scheduling and output backpressure; there
is no call-stack profile. `perf` was unavailable and host `perf_event_paranoid`
was 2; no profiling package or host policy change was introduced.

The initial 4 KiB producer/relay/reader batches amplify the regression. Increasing
all three to 16 or 64 KiB narrows the gap. The new CLI accepts
`--chunk-bytes 4096|16384|65536`; old defaults remain 4096.

## 2. Sustained large streams

[long-flows.jsonl](long-flows.jsonl) contains 72 valid transfers: 16 MiB and
512 MiB, three batch sizes, three cycles of copy/eBPF/eBPF/copy. Each mode has
six samples per coordinate. All successful-copy fallback samples remain in their
intended eBPF group. Every body byte, rewritten header, coalesced 18-byte
successor, half-close and map retirement was checked.

| Body | Batch | Copy time (ms) | eBPF time (ms) | Copy process CPU (ms) | eBPF process CPU (ms) |
|---|---:|---:|---:|---:|---:|
| 16 MiB | 4 KiB | 21.913 | 38.680 | 52.888 | 48.129 |
| 16 MiB | 16 KiB | 17.098 | 20.186 | 36.568 | 33.123 |
| 16 MiB | 64 KiB | 17.064 | 18.246 | 33.566 | 30.928 |
| 512 MiB | 4 KiB | 690.182 | 1248.270 | 1662.377 | 1495.797 |
| 512 MiB | 16 KiB | 525.826 | 615.036 | 1038.785 | 1043.550 |
| 512 MiB | 64 KiB | 515.456 | 538.848 | 991.652 | 951.010 |

At 512 MiB / 64 KiB, eBPF is 4.5% slower and saves 4.1% process CPU, despite
offloading nearly the whole body. Relay-thread CPU drops from 73.815 ms to
1.091 ms, but endpoint CPU dominates the fixture and kernel workers are omitted.
This is a long single response, not repeated HTTP keep-alive ownership handoff;
six samples do not establish p99. It does not demonstrate a whole-machine win.

## 3. Real shared-netns sidecar, including concurrency

The separate `bench_kernel_relay ebpf` experiment admits an entire upstream
TCP stream before forwarding any request, avoiding L7 per-response handoff.
A direct packet verdict redirects response bytes and counts them with a 64-bit
counter; requests remain copied. Before propagating upstream FIN it waits until
TCP output progress covers accepted redirect bytes. This is a request-triggered
HTTP-origin experiment, not a general guarantee for protocols that send banners
or other unsolicited bytes before enrollment, and not a compiler L7 route proof.

The relay joins the pinned nginx origin's container network namespace. The host
wrk client enters its published port. Both copy/eBPF modes run as container root
with only BPF and NET_ADMIN, no-new-privileges, default seccomp and `label=disable`.
Relay CPU 2, origin CPU 3, client CPUs 4/5 are fixed. No privileged container,
new dependency, extra pipe capability or host sysctl change is used.

Each body size has 12 valid samples: two modes, concurrency 1/32, three repeats,
one-second warmup and at least five-second sampling, with alternating mode order.
Full-body, slow-reader, successor, 100-request keep-alive and origin-reuse
preflights passed for every frontend. All timed/warmup error counters are zero;
frontend setup and retirement failures are zero. Cleanup-time client aborts are
recorded separately from timed errors.

| Body | Concurrent | Copy RPS | eBPF RPS | Copy p99 (ms) | eBPF p99 (ms) | Copy observed CPU s/GiB | eBPF observed CPU s/GiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| 256 KiB | 1 | 7638 | 4906 | 0.168 | 0.310 | 1.353 | 1.810 |
| 256 KiB | 32 | 12393 | 5685 | 3.311 | 7.872 | 1.399 | 1.875 |
| 1 MiB | 1 | 2560 | 1410 | 0.509 | 1.118 | 1.206 | 1.715 |
| 1 MiB | 32 | 2730 | 1508 | 17.921 | 83.961 | 1.255 | 1.711 |

Medians are per coordinate. CPU s/GiB divides each sample's whole-host
`/proc/stat` execution delta by its successfully completed body bytes, then takes
the median. It includes endpoints, kernel workers and unrelated host activity;
it is an observation, not exclusive proxy CPU attribution. Lower CPU percentage
at a much lower delivery rate must not be reported as a saving. These observed
per-GiB values worsen by roughly 34–42% in the dedicated-affinity comparison.

See [sidecar-256k-r2](sidecar-256k-r2/) and [sidecar-1m-r2](sidecar-1m-r2/) for
results, environment, commands, isolation, preflights and clean retirement logs.

### Placement hypothesis and controlled check

[cpu-placement](cpu-placement/) is a one-repeat diagnostic with per-CPU counters.
For copy / concurrency 32, CPU 2/3 are about 100%/60% busy. For eBPF they are
about 6%/100%, even though the origin process itself uses only about 44% of a
core. This is consistent with work moving from the proxy core into receive/
kernel work on the upstream core; it does not identify a precise kernel stack.

[cpu-balanced](cpu-balanced/) repeats the 1 MiB comparison three times with
`--origin-affinity shared`: the origin may schedule on CPUs 2/3, while the relay
remains on CPU 2. The total physical core budget is unchanged. This changes
container-local placement only, not host IRQ, RPS or workqueue policy.

At concurrency 32 the eBPF activity spreads across CPUs 2/3, but median throughput
is still 1439 RPS versus copy's 2661 RPS, and p99 is 97.118 ms versus 18.516 ms.
Observed CPU s/GiB is 1.737 versus 1.265. Simply relaxing origin placement did
not recover a benefit.

Linux's [skmsg implementation](https://github.com/torvalds/linux/blob/master/net/core/skmsg.c)
has an egress backlog worker and delayed retry when the destination cannot accept
data. That makes scheduling/backpressure a plausible contributor, not a proven
attribution for this Fedora kernel or evidence that changing that code is safe.

## 4. Actual Rut reference

Actual Rut uses one shard and io_uring, plain native streaming `forward`, upstream
reuse and the existing exact-body/slow-reader/keep-alive validation. Three repeats
per concurrency use the same CPU roles, warmup and duration as above. nginx runs
provide an independent reference in the same harness.

| Body | Concurrent | Rut RPS | Rut p99 (ms) | L4 eBPF prototype RPS | L4 eBPF prototype p99 (ms) |
|---|---:|---:|---:|---:|---:|
| 256 KiB | 1 | 7963 | 0.167 | 4906 | 0.310 |
| 256 KiB | 32 | 13482 | 2.500 | 5685 | 7.872 |
| 1 MiB | 1 | 3188 | 0.380 | 1410 | 1.118 |
| 1 MiB | 32 | 2962 | 11.155 | 1508 | 83.961 |

See [actual-rut-256k](actual-rut-256k/) and [actual-rut-1m](actual-rut-1m/).
These are **reference comparisons**, not Rut-with/without-eBPF A/B tests: the
prototype has fewer L7 features and a different deployment/network path. Rut's
business sockets have not been enrolled. The official native-streaming harness
retains its 256 KiB CLI contract; the isolated
[1 MiB driver](actual_rut_baseline_1m.py) changes that module constant locally,
matching the existing relay runner's body-size override. No language or serving
semantic changes are involved.

## Validation and history

The fixture's larger batches preserve body accounting and exact phase-duration
sums. The relay's new mode either initializes explicitly or fails with its
kernel/capability stage. Black-box lifecycle tests include eBPF automatically
when the test process has permission; the unprivileged host explicitly reports
its denial. Privileged sidecar preflights and retirement checks run separately.
The notification self-test also verifies cleanup with an already removed target
and repeated retirement. Focused checks are retained alongside this report.
The [seven related CTests](ctest.log), [three OFF-build tests](off-ctest.log),
[33 benchmark-harness tests](harness-tests.log) and the final
[probe checks](probe-ctest.log) passed. Focused
[relay](relay-tidy.log)/[fixture](profile-tidy.log) clang-tidy emits no actionable
diagnostics; unrelated-header warnings and documented POSIX public-header
include-cleaner suggestions are suppressed. Formatting, Python compilation and
local links were checked. This is not a full repository check.

Initial smoke runs in [rejected](rejected/) are excluded: root's pipe quota
broke the attempted splice comparison; later eBPF cleanup saw peers disappear
during admission. The implementation now distinguishes a confirmed pre-admission
peer close from setup failure. Map insertion still fails closed for other errors.
Earlier native tests also detected a stale test binary's build fingerprint after
the reference binary was rebuilt; rebuilding the affected tests resolves it.
These failures are not included as successful performance samples.

## Reproduction and limits

- [Relay instructions](../../../scripts/kernel_relay_benchmark.md) describe the
  opt-in eBPF pair and affinity flag. Complete invocation records accompany each
  successful dataset.
- [summary.json](summary.json) contains exact medians, phase and CPU values;
  [manifest.json](manifest.json) records delivered source, evidence and timed
  binary hashes. The frozen fixture/prototype binaries remain in
  `/home/hurricane/private/code/rut-ebpf-20261003/`. Rut reference environment
  files record its hash at measurement time; its build path was later rebuilt.
- There is no physical-NIC, NUMA, TLS, kTLS, HTTP/2 or production epoll/io_uring
  offload/cancellation claim. No full repository test-suite or tidy pass is
  claimed. The remaining kernel-stack attribution needs suitable profiling
  access, and a production hardware conclusion needs its actual network topology.

The current evidence supports stopping expansion of this general sockmap egress
offload path, while retaining it as an opt-in experiment. It does not rule out
other eBPF uses or a different hardware/network placement.
