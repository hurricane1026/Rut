# Full epoll ET experiment — 2026-10-11

Branch: `perf/epoll-full-et`. Isolated worktree: `/tmp/rut-ws-pr-20261010`.

Network socket ET is implemented behind `RUT_STUDY_EPOLL_ET=on`, off by default. Listener, downstream/upstream read/write, connect completion, TLS readiness and response splice use ET. Timerfds remain control events in LT. Nothing has been committed, pushed or merged; prior uncommitted syscall optimizations are retained.

## State and scheduling

Each shard allocates a fixed ring and readiness table indexed by connection side, using existing MappedArray storage. One entry per side is allowed, including cancelled entries still waiting to be popped: queue capacity is twice connection capacity, so duplicate submissions cannot overflow it. A reused slot clears old readiness but retains queue membership until pop. No Connection fields, ordinary heap allocations, language keywords or dependencies are added. Storage is 24 bytes per configured connection (two 8-byte state records plus two 4-byte ring entries), allocated only when ET is enabled.

Readiness and a submitted read are separate state. A callback explicitly submits its next read after consuming/releasing the buffer; readiness alone cannot produce an additional normal read completion. Buffer exhaustion and backpressure preserve readiness until the owner can resume. Every positive plaintext `recv` retains readiness for the next submitted read, including short reads; retries continue until `EAGAIN`, so bytes left by one peer write do not require another edge. TLS likewise retains readiness after positive `SSL_read`; WANT_READ/WANT_WRITE waits for the corresponding kernel notification. EPOLLRDHUP accompanies active network reads to retain EOF information when a short read coexists with FIN.

This is an I/O-semantic optimization, with no URL, response-size history or workload prediction. See the stream-oriented short-read discussion in [Linux epoll(7)](https://raw.githubusercontent.com/mkerrisk/man-pages/master/man7/epoll.7), and [nginx 1.29.7 recv](https://raw.githubusercontent.com/nginx/nginx/release-1.29.7/src/os/unix/ngx_recv.c). nginx also records readiness and [dispatches both read and write events](https://raw.githubusercontent.com/nginx/nginx/release-1.29.7/src/event/modules/ngx_epoll_module.c).

New ADD/MOD registrations already publish current readiness; they do not need a duplicate userspace probe. An unchanged registration re-submission schedules a probe only while read readiness is known. Kernel notifications received while a read is unsubmitted retain readiness for a later submission.

The loop gives kernel readiness an opportunity after eight userspace runnable turns, preserving the existing completion quota and 16-record kernel batch. Listener continuation retains its separate bounded batch and resource-error timer backoff. Send loops retain their existing completion/partial-send semantics. A read/write notification processed first as send keeps the read side runnable; a terminal read does not discard a simultaneous write. Splice owner budget exhaustion explicitly schedules continuation, while EAGAIN waits for a new edge.

Interest-generation fencing and upstream episode validation remain. Cancelling/closing clears work; changing only the other socket side preserves a harvested event which LT would have delivered again. Enabling ET after socket registration is rejected. The original measurements below disable stable upstream watches. The follow-up implementation now supports ET plus stable upstream ownership; see `../epoll-et-optimization-20261011/README.md`. ET must be enabled before allocating stable watches.

## Verification and measurements

The ET-specific socket tests cover full-buffer and short-read resubmission after one peer write, pause/resume without another peer write, queue deduplication and slot reuse, partial send plus reverse data/half-close, preservation of the other side's harvested edge, rejection of late enablement, and refusal to read an unsubmitted buffer. Short reads retain readiness until an `EAGAIN` retry; a regression verifies that buffered remainder arrives without a new peer write. Short-read/FIN behavior and idle stable-upstream handoff with a later harvested terminal event are also covered.

Related RealEpollEpisodeGuard fixtures can enable ET with `RUT_TEST_EPOLL_ET=on`; older tests using separate fixtures retain their original backend configuration. The selected episode/backpressure/splice suites are therefore a mix of ET-enabled integration cases and unchanged unit cases, not 27 independent full-ET tests.

Release checks: test_network, test_splice, test_ws_tunnel_iouring and test_cli_backend. ASan+UBSan: no-JIT Debug test_splice, leak detection disabled. Formatting and diff checks cover affected files. clang-tidy 22 checks epoll_backend.cc/main.cc, treating bugprone/performance diagnostics as errors; unrelated existing warnings are retained. Full CI, GCC/macOS, leak detection, multi-shard stress, HTTP/2 interoperability and exhaustive protocol coverage remain unverified.

Benchmark frontends run strictly serially, untraced: one worker on CPU 2, four shared origin workers on CPUs 3/4/8/9, clients on 5/7, concurrency 128. Measurements last six seconds following two-second warmup. Matched Rut LT/ET variants disable stable upstream registration and enable the same close-response coalescing/validation-reuse/accept-batch-16 settings. io_uring uses the same build. nginx has multi_accept enabled, response buffering off, 16 KiB buffers for small bodies and the prior 1024 KiB large-response setting for 1 MiB. Each cell has one repetition: results are screening only, not a statistical acceptance campaign.

The initial prototype had redundant probes and unconditional read continuations; its results are retained in initial-summary.json. The intermediate explicit-submission implementation is retained in refined-summary.json. Those measurements do not describe the later ready-state/short-read implementation. Frozen binaries, exact diffs, hashes and raw preflight/load logs reside under `/home/hurricane/private/code/rut-performance-checkpoints/epoll-full-et*-20261011`.

## Reproduction

```
RUT_STUDY_EPOLL_ET=on /tmp/rut-ws-pr-20261010-build/src/rut app.rut --backend epoll
```

Screening scripts preserve the local campaign provenance and depend on the existing benchmark binaries and `/tmp/rut-epoll-accept-batch-relay.py`; they are not standalone portable drivers. No default-mode change or performance claim follows just from the ET flag being implemented.

## Current ready-state results

| Workload | Repetitions | Rut LT RPS / p99 ms | Rut ET RPS / p99 ms | Rut io_uring RPS / p99 ms | nginx RPS / p99 ms |
|---|---:|---:|---:|---:|---:|
| 1 KiB, short connections | 1 | 36,127 / 3.604 | 33,222 / 4.162 | 19,965 / 15.452 | 34,427 / 3.887 |
| 1 KiB, persistent | 1 | 64,789 / 2.107 | 64,469 / 2.107 | 103,423 / 1.332 | 59,441 / 2.301 |
| 1 MiB, persistent | 3 | 4,096 / 34.114 | 4,893 / 27.698 | 5,493 / 28.125 | 3,962 / 39.956 |

All 20 cells passed preflight and had zero warmup/load errors. Large-body cells use three rotated repetitions; the small-body cells remain one-pass screening. The 1 MiB median improves ET throughput by 19.5% over LT, with p99 down 18.8%. ET reaches 123.5% of nginx throughput here, below the 150% goal. Its large-body throughput is still 10.9% below io_uring. Small-body persistent throughput is approximately equal to LT; short connections remain about 8% below LT. These comparisons disable stable upstream watches; they do not represent the best previously tuned LT configuration.

## Protocol smoke verification

The final ready-state binary also passed a real HTTPS 1 KiB persistent-proxy preflight/load with BoringSSL fixtures, zero warmup/load errors. The existing protocol checker passed ET WebSocket 64-byte interactive messages, 1 MiB messages, and chunked streaming 64 KiB responses with byte/frame verification and zero errors; all frontend logs confirm ET mode. Those protocol runs use the Python checker for correctness only; their rates are not tcpkali2 performance comparisons and are not acceptance evidence. Logs remain in `epoll-full-et-diagnostics-20261011` and `epoll-full-et-tls-smoke-20261011` external checkpoint directories.

## Syscall audit: 1 KiB short connections

Separate five-second BPF measurements use the same frozen final binary, four origins and accept batch 16. nginx frontend multi_accept is enabled. Trace windows include up to three seconds of idle tail; rates from these runs are not performance evidence. All four audited frontend cells passed preflight/warmup/load without errors, and trace stderr had no warning/error/lost-event reports. epoll_ctl returned no errors.

| Frontend syscall, calls/completed request | LT | ET | nginx |
|---|---:|---:|---:|
| recvfrom | 3.0020 | 3.0030 | 2.0015 |
| epoll_ctl | 3.0020 | 3.0028 | 2.0021 |
| epoll_wait | 0.1304 | 0.1273 | 0.0252 |
| accept4 | 1.0022 | 1.0145 | 1.0261 |
| madvise | 0.0005 | 0.1636 | — |

The ET conversion has not yet reduced pool-transfer epoll_ctl or the extra receive probe relative to LT. Its listener performs additional EAGAIN checks. A large madvise increase is also observed in ET short connections; SlicePool discards ordinary 16 KiB slices when its 256-slice idle cache is full, so changed batching/cache pressure is a plausible follow-up target. Follow-up caller attribution confirmed SlicePool::free at the idle-cache cap; bounded accept scheduling reduced this pressure. See the follow-up record for matched measurements; syscall timing alone does not prove the exact contribution to throughput. Preserve zero-filled reuse and bounded idle retention when investigating it.

Further ET optimization should focus on preserving stable socket registration across owner/mode transfers, scheduling/idle-cache pressure in short connections, and bounded splice continuation. This prototype does not establish that ET is intrinsically faster than io_uring or that any mode beats nginx on every workload.
