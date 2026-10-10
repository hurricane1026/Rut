# WebSocket small-message deadline experiments (2026-10-10)

Study build only; all new runtime switches default off. Ordinary HTTP, TLS and inspected WebSocket batches keep their original preparation and scan behavior. No SEND_ZC, response-size prediction, new runtime dependencies or per-connection buffers.

FAST_BATCH recognizes only RelayRead/RelayWrite events in WebSocket-owned auxiliary domains 32/33/96/97. Mixed and timer batches prepare normally. FAST_SCAN additionally skips the full connection scan only after a scan found no pending terminal owners. The sole production publisher now invalidates this negative cache immediately. Existing owners retain full scans until gone; expiry resolution, body pumping, boundary resumption and reclamation still run.

CLI study environment: RUT_STUDY_WS_FAST_BATCH=on and RUT_STUDY_WS_FAST_SCAN=on. The prefix limit experiment supports 4KiB/16KiB and never exceeds actual buffer capacity. Larger knobs were removed. RUT_STUDY_WS_AVAILABLE=on uses FIONREAD, but its extra syscall loses small-message throughput; retained as a disabled experiment.

## Controlled results

Identical frozen Rut/compiler pair and patched tcpkali2, 192 connections, 3 client workers on CPUs 5/6/7; one frontend worker on CPU2 and four Python origin workers on CPUs 3/4/8/9. Frontends run serially in rotated order, with 2s warmup and 8s measurement. Full RTT sampling and binary echo verification; zero errors. nginx buffers512KiB (256KiB for1MiB), buffering off. All Rut profiles use copy-first,4KiB prefix,64KiB pipes and2calls per ordinary turn.

| Payload | Profile | Runs | Messages/s median (range) | MiB/s median | RTT p99 ms median |
|---|---|---:|---:|---:|---:|
| websocket-interactive-64 | base | 3 | 84431 (83548–85044) | 5.2 | 2.86 |
| websocket-interactive-64 | prep | 3 | 83511 (83115–85082) | 5.1 | 2.89 |
| websocket-interactive-64 | scan | 3 | 83868 (83205–84584) | 5.1 | 2.91 |
| websocket-interactive-64 | nginx | 3 | 84367 (83939–85425) | 5.1 | 2.95 |
| websocket-small-16384 | base | 3 | 55181 (53388–55560) | 862.2 | 4.82 |
| websocket-small-16384 | prep | 3 | 56609 (54562–56756) | 884.5 | 4.09 |
| websocket-small-16384 | scan | 3 | 55044 (54328–56599) | 860.1 | 4.48 |
| websocket-small-16384 | nginx | 3 | 42227 (42190–42459) | 659.8 | 5.10 |
| websocket-bulk-64k | base | 1 | 21501 (21501–21501) | 1343.8 | 12.63 |
| websocket-bulk-64k | prep | 1 | 22131 (22131–22131) | 1383.2 | 11.17 |
| websocket-bulk-64k | scan | 1 | 22161 (22161–22161) | 1385.1 | 9.81 |
| websocket-bulk-64k | nginx | 1 | 17604 (17604–17604) | 1100.2 | 11.29 |
| websocket-bulk-1m | base | 1 | 1026 (1026–1026) | 1026.1 | 232.96 |
| websocket-bulk-1m | prep | 1 | 1036 (1036–1036) | 1036.2 | 208.90 |
| websocket-bulk-1m | scan | 1 | 1032 (1032–1032) | 1032.3 | 201.22 |
| websocket-bulk-1m | nginx | 1 | 908 (908–908) | 908.2 | 258.30 |

base: no skips. prep: preparation skip only. scan: both skips.

64B: no stable new throughput or p99 gain over copy-first; Rut/nginx rate ranges overlap.16KiB: preparation-only median throughput improves2.6%, p99 drops15.1%; rate ranges overlap, so a stable rate gain is not established. The earlier independent preparation experiment improved median throughput4.1% with nonoverlapping rate ranges and reduced median p99 by13%; different binaries must not be pooled. Additional full-scan skipping has no clear rate benefit at192connections. Bulk rows are single-run guards. Keep the switches experimental.

## Capacity and CPU diagnostics

Separate diagnostic runs, excluded from confirmations: direct Python origin64B reaches150,815msg/s (p991.61ms), above the proxy path. Native ctypes masking at64B drops to123,475msg/s (p992.31ms), so it is not adopted. The helper remains optional, default threshold4096B.

Whole-command /proc/stat deltas include setup, warmup and teardown: CPU2 is95.5% busy for base Rut and95.4% for scan Rut; roughly36% softirq,55% system,4% user. nginx is94.5% busy,35.6% softirq,51.6% system. Direct origin leaves CPU2 only3.5% busy and effectively zero softirq. These are single-run diagnostic windows, not exact steady-state per-message attribution.

Process-only frontend CPU near60% omits substantial softirq work on the same core. Further64B optimization should investigate packet-processing and I/O submission/wakeup costs. The direct-origin result does not support claiming an origin bottleneck here. No eBPF capture was obtained: sudo -n requires a password; rootless /proc/stat supplied this evidence.

## Validation

Release Rut/compiler and relevant native targets rebuilt. WebSocket and splice CTests passed;214 response-read/boundary tests and17,040 checks passed. Added tests cover prefix/capacity boundaries, FIONREAD gating, mixed/timer fallback, inactive-index reset, publisher invalidation, FIN/reverse traffic, cancellation and actual skip execution. An initially premature coverage assertion was moved after the forced FIN/reverse readiness events; final tests pass.40 benchmark-tool tests passed.

Targeted clang-tidy22 reported no diagnostics in newly changed regions; the existing event-loop header still emits older diagnostics. Full CI and sanitizers have not run. Optional mask helper previously passed36vectors, including unaligned output and1MiB payloads. It is not linked into Rut.

The checkpoint directory retains16 copy/gating screens,24 preparation measurements,32 scan measurements,2 origin probes,4 core probes, manifests, raw client CSVs, logs, runner scripts and frozen binaries.

rut SHA256: 1f385fb3e741177c5ffb862f9fa1af2c55decb333051b4656c6bbb029352f7d1

rut-compile SHA256: 88f808c4175a4bcd557878545dae1be37df37f5d2f52ef3cabb41dfde9fe7360

tcpkali2 SHA256: 8f9433dd9390a0805d9f6619472f16987258e5784980644386a9b847dfb0f3b4
