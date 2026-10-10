# Event-driven idle upstream reuse — 2026-10-11

Branch `perf/epoll-full-et`, isolated worktree `/tmp/rut-ws-pr-20261010`; no commit/push/merge. Enabled only with existing stable-upstream event watches. Unwatched sockets and other backends retain the synchronous borrow probe.

## Policy

Like [nginx 1.29.7 upstream keepalive](https://github.com/nginx/nginx/blob/release-1.29.7/src/http/modules/ngx_http_upstream_keepalive_module.c#L184-L404), keep an idle read watch and check on known readiness instead of probing every healthy borrow. Pool borrowing calls an existing-context function-pointer hook: skip MSG_PEEK only if the exact descriptor/slot has a live stable idle registration, no pending readiness, no harvested idle event, and an unexhausted owner version. All fallback states keep the probe. No heap allocation or Connection fields added; the pool adds one hook pointer per shard.

Return-to-pool checks retained ET readiness and harvested active events before retirement of their owner version. Known readiness triggers MSG_PEEK once after the pool owns the descriptor: EAGAIN retains it, data/EOF/hard error discards it. Idle event callbacks retain their existing conditional MSG_PEEK. Borrowed sockets still establish a fresh owner/version and episode, preserving stale-event fences. FD close invalidates the watch before release; reload/sweep continue through the pool close hook.

FIN or data not yet harvested can race a borrow, as in nginx; the implementation does not claim a positive liveness guarantee. Existing transport failure handling remains, with retries restricted by existing request replay rules. Synchronous probing also has a probe-versus-send race. This change intentionally removes unconditional pre-borrow rejection when no readiness is known; it does not remove error/cancellation handling or assert that unsolicited bytes can never race ownership.

## Screening

Serial untraced pairs, same frozen ET+stable flags, frontend CPU2, four origins3/4/8/9, clients5/7, C128, 2s warmup + 6s load, three rotated pairs each. No concurrent compilation/tests or nginx frontend. Baseline is the previous ET+stable candidate with unconditional borrow probing.

| Workload | Before RPS / p99 ms | Event-driven RPS / p99 ms |
|---|---:|---:|
| 1 KiB close | 38,541 / 3.587 | 39,190 / 3.491 |
| 1 KiB keep-alive | 74,844 / 1.921 | 74,508 / 2.048 |
| 1 MiB keep-alive | 4,846 / 27.949 | 4,810 / 28.346 |

All 18 cells valid with zero errors. This is not evidence of a substantial throughput improvement. Small persistent p99 is 6.6% higher in the initial screening, requiring confirmation rather than declaring fewer syscalls a performance win. Larger persistent differences are small in these short runs.

## Verification and artifacts

Initial release test_splice 37 tests / 99,658 checks pass; ET stable subset 14 tests / 66,006 checks pass. Covers healthy watched borrowing, exact slot ownership, harvested idle data, idle FIN/data handling, consumed FIN on return, receive submission, full-buffer reads, stale owners, descriptor reuse, reload, generation/version exhaustion and partial sends. Unwatched pool probing retains existing tests.

Frozen binary, full diff/hash and raw logs: `/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-idle-event-20261011`. Local scripts depend on existing absolute-path drivers and are provenance, not portable harnesses. Further confirmation/validation follows below.

## Longer persistent confirmation and syscall evidence

Three rotated 12-second 1 KiB keep-alive pairs: median before 73,351 RPS / p99 1.935 ms, after 74,608 / 1.921 ms (+1.71% throughput, -0.72% p99). All six cells valid with zero errors. Initial 6s screening p99 regression was not reproduced; this does not establish a universal latency guarantee or a substantial throughput gain.

Separate 5s BPF measurements: recvfrom/request 2.0013 (short) and 2.0012 (persistent), down from 3.0022 / 3.0017 in the immediately preceding ET+stable/nginx audit. epoll_ctl/request stays 1.0008 / 0.0004. All trace cells valid, zero errors; these rates are not throughput acceptance evidence. Raw traces: `epoll-et-idle-event-bpf-20261011` external checkpoint. Healthy unconditional peek is removed; conditional idle checks and fallback probes remain.

Additional boundary tests verify FIN racing an unharvested borrow is reported to the new episode, and full-buffer readiness probes EAGAIN on return then permits a healthy borrow. ASan+UBSan no-JIT Debug ET fixtures: 39 tests, 99,678 checks passed (leak detection disabled). clang-tidy 22 backend bugprone/performance checks passed with existing unrelated warnings; full CI/multi-shard/macOS remain unverified.

Real HTTPS persistent-proxy smoke and byte/frame-checked WebSocket 64-byte / 1 MiB plus streaming 64 KiB smoke pass, all zero errors; frontend logs confirm ET and stable-upstream on. These correctness checker rates are not performance acceptance evidence. Protocol runs occurred after timed throughput/BPF cells ended; compilation overlapped correctness smoke only. Formatting and git diff checks pass.

Final release CTest network/splice/ws_tunnel_iouring/cli_backend: all four passed. Final ET stable lifecycle subset: 16 tests, 66,027 checks passed. Runtime implementation is identical to the frozen measured candidate; final validation adds the explicit FIN-racing-borrow and full-read/EAGAIN handoff tests.
