# Event-driven idle upstream reuse — 2026-10-11

Branch `perf/epoll-full-et`, isolated worktree `/tmp/rut-ws-pr-20261010`; no commit/push/merge. Stable-upstream watches eagerly reject known-stale idle sockets; every backend still performs the synchronous borrow probe.

## Policy

Keep an idle read watch and eagerly reject known-stale idle sockets. Readiness handling discards the exact pool slot, whose existing pre-close hook unregisters the descriptor before closing it. Every borrow still performs the nonblocking `MSG_PEEK` liveness/surplus probe: a readiness event not yet harvested cannot prove that no bytes arrived after parking. The probe can reject data, EOF, and hard errors before reuse; a residual probe-versus-send race remains. No heap allocation or Connection fields are added.

Return-to-pool checks retained ET readiness and harvested active events before retirement of their owner version. Known readiness triggers MSG_PEEK once after the pool owns the descriptor: EAGAIN retains it, data/EOF/hard error discards it. Idle event callbacks retain their existing conditional MSG_PEEK. Borrowed sockets still establish a fresh owner/version and episode, preserving stale-event fences. FD close invalidates the watch before release; reload/sweep continue through the pool close hook.

FIN or data not yet harvested can race a borrow, so the borrow-time probe remains as a safety fence. Existing transport failure handling remains, with retries restricted by existing request replay rules. Synchronous probing cannot prevent a later probe-versus-send race.

## Screening

Serial untraced pairs, same frozen ET+stable flags, frontend CPU2, four origins3/4/8/9, clients5/7, C128, 2s warmup + 6s load, three rotated pairs each. No concurrent compilation/tests or nginx frontend. Baseline is the previous ET+stable candidate with unconditional borrow probing.

| Workload | Before RPS / p99 ms | Event-driven RPS / p99 ms |
|---|---:|---:|
| 1 KiB close | 38,541 / 3.587 | 39,190 / 3.491 |
| 1 KiB keep-alive | 74,844 / 1.921 | 74,508 / 2.048 |
| 1 MiB keep-alive | 4,846 / 27.949 | 4,810 / 28.346 |

All 18 cells valid with zero errors. This is not evidence of a substantial throughput improvement. Small persistent p99 is 6.6% higher in the initial screening, requiring confirmation rather than declaring fewer syscalls a performance win. Larger persistent differences are small in these short runs.

## Verification and artifacts

Historical initial release validation: test_splice 37 tests / 99,658 checks passed; ET stable subset 14 tests / 66,006 checks passed. Those results predate the current borrow-probe repair. The current lifecycle run is recorded in `edge-tests.log` below.

Frozen binary, full diff/hash and raw logs: `/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-idle-event-20261011`. Local scripts depend on existing absolute-path drivers and are provenance, not portable harnesses. Further confirmation/validation follows below.

## Longer persistent confirmation and syscall evidence

Three rotated 12-second 1 KiB keep-alive pairs from the original skip-probe candidate: median before 73,351 RPS / p99 1.935 ms, after 74,608 / 1.921 ms (+1.71% throughput, -0.72% p99). All six cells valid with zero errors. These measurements describe that earlier implementation, which skipped the borrow probe; they do not measure the current always-probe policy below. Initial 6s screening p99 regression was not reproduced; this does not establish a universal latency guarantee or a substantial throughput gain.

Separate 5s BPF measurements from the original skip-probe candidate: recvfrom/request 2.0013 (short) and 2.0012 (persistent), down from 3.0022 / 3.0017 in the immediately preceding ET+stable/nginx audit. epoll_ctl/request stays 1.0008 / 0.0004. All trace cells valid, zero errors; these rates are not throughput acceptance evidence. Raw traces: `epoll-et-idle-event-bpf-20261011` external checkpoint. These syscall counts do not apply to the current always-probe policy.

Additional boundary tests verify that FIN racing an unharvested borrow is rejected and closed before a new owner is installed, and that full-buffer readiness probes EAGAIN on return before permitting a healthy borrow. The earlier ASan+UBSan no-JIT Debug ET snapshot passed 39 tests and 99,678 checks (leak detection disabled); it predates the later 43-test splice suite and does not cover these final boundary tests. clang-tidy 22 backend bugprone/performance checks passed with existing unrelated warnings; full CI/multi-shard/macOS remain unverified.

Real HTTPS persistent-proxy smoke and byte/frame-checked WebSocket 64-byte / 1 MiB plus streaming 64 KiB smoke pass, all zero errors; frontend logs confirm ET and stable-upstream on. These correctness checker rates are not performance acceptance evidence. Protocol runs occurred after timed throughput/BPF cells ended; compilation overlapped correctness smoke only. Formatting and git diff checks pass.

Release CTest for network/splice/ws_tunnel_iouring/cli_backend passed 4/4 before removal of the unused readiness-probe callback. After that removal, focused CTests for splice, idle trim, and shard control passed; splice was rerun after the final teardown-test adjustment. The current ET stable lifecycle filter passed 23 tests and 66,101 checks (25 skipped), as recorded in `edge-tests.log`. Current code keeps the synchronous probe on every borrow. The throughput and BPF measurements above came from the earlier skip-probe implementation; they do not measure or establish performance for the current implementation. No current-source performance benchmark has been run.
