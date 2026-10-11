# ET optimization follow-up — 2026-10-11

Worktree `/tmp/rut-ws-pr-20261010`, branch `perf/epoll-full-et`. Experimental flags remain default-off. No commit, push or merge performed.

## Bounded listener scheduling

The ET listener allows 32 existing I/O opportunities between accept batches instead of 16. When no socket work is ready it immediately resumes accepting; this is not a fixed delay. Accept batch remains 16, with existing resource-error backoff. SlicePool cache limits and zero-filled reuse remain unchanged.

Three rotated untraced 1 KiB short-connection pairs: median RPS 34,436 → 36,792 (+6.84%); median p99 4.040 → 3.670 ms (-9.16%). All cells valid with zero errors. One-pass persistent guards were 66,855 → 65,931 RPS (1 KiB), and 4,932 → 4,729 RPS (1 MiB); those guards need repeated follow-up and are not evidence of equivalence.

Separate caller-attributed BPF windows identify 16 KiB MADV_DONTNEED calls in SlicePool::free when cached_count reaches cache_limit. Old ET: 32,722 discards, peak live slices 488; LT control: 156 discards, peak 396; ET with the scheduling adjustment: 138 discards, peak 394. Trace rates are not throughput acceptance evidence. The cache cap stays 256 slices (4 MiB).

## Stable upstream ownership in ET

A pooled upstream socket keeps one kernel registration while ownership changes. Owner version and socket generation still reject stale records before socket reads. Readiness received while the new owner has not submitted receive is remembered rather than consumed. Full-buffer resubmission retains the same registration and queues userspace continuation only for known readiness. Consumer changes preserve harvested ET readiness while fencing the previous mode.

A consumed terminal edge is remembered across active-to-idle handoff. After the pool owns the descriptor, its existing discard path removes such a socket immediately; it cannot wait indefinitely for a repeated FIN edge. Borrow-time MSG_PEEK remains. No response-size prediction, SEND_ZC, new dependency or Connection fields are introduced.

The optional stable table adds one bool, increasing its records from 24 to 28 bytes (256 KiB extra per enabled shard at 65,536 records); the ET runnable record remains 8 bytes. The existing table itself is optional. ET must be configured before stable registrations.

Tests cover paused-owner data+FIN, EOF after a short read, consumed FIN on pool return, unchanged-registration full reads, stale owner/socket tokens, descriptor reuse, version exhaustion, registration failure, partial send and relay consumer changes. Release test_splice: 36 passed; ET stable subset: 13 passed. Further validation and benchmark results will be appended below.

## Provenance

External frozen candidates, full source patches, binary hashes and raw logs:

- `/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-accept-service-20261011`
- `/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-memory-profile-20261011`
- `/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-memory-service-profile-20261011`
- `/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-stable-20261011`

Benchmark frontends strictly serial: one frontend core CPU 2, four origins CPUs 3/4/8/9, clients 5/7, C128, two-second warmup and six-second measured cells. Small body 1 KiB, large body 1 MiB. Both matched variants use the same accept/coalescing/validation-reuse flags. Short experiments do not establish multi-shard or production performance, nor the 150% nginx target.

## Stable registration results

Three rotated serial pairs per workload, untraced. Baseline already includes the 32-I/O listener adjustment; candidate adds ET stable upstream watches. All 18 cells passed preflight and had zero warmup/load errors.

| Workload | Baseline RPS / p99 ms | Stable ET RPS / p99 ms | Throughput change |
|---|---:|---:|---:|
| 1 KiB close | 36,116 / 3.852 | 38,088 / 3.756 | +5.46% |
| 1 KiB keep-alive | 65,503 / 2.147 | 74,738 / 1.898 | +14.10% |
| 1 MiB keep-alive | 4,814 / 28.823 | 4,783 / 28.441 | -0.64% |

Small persistent p99 improves 11.6%; large-body differences are small in this short campaign and do not establish strict equivalence. These are matched ET improvements, not a fresh nginx/io_uring comparison. Previous nginx numbers must not be treated as contemporaneous controls.

Separate BPF short-connection windows: frontend epoll_ctl/request 3.0027 → 1.0008; recvfrom/request 3.0033 → 3.0029; accept4/request 1.0016 → 1.0015. epoll_ctl errors zero. Retained borrow-time probe explains why receive count is unchanged. Discard calls remain low (126 → 144) with bounded cache. Trace results are normalized by completed requests and are not performance acceptance samples. Raw logs reside in `epoll-et-stable-bpf-20261011/{off,on}`.

## Follow-up validation

ASan+UBSan no-JIT Debug test_splice with ET fixtures: 36 tests passed, 99,646 checks; leak detection disabled. clang-tidy 22 backend checks passed with bugprone/performance warnings treated as errors (existing unrelated warnings remain). Affected-file clang-format and git diff checks passed.

Real HTTPS persistent proxy and byte/frame-checked WebSocket 64-byte/1 MiB plus streaming 64 KiB smoke tests all passed with zero errors; frontend logs confirm both ET and stable upstream enabled. Protocol rates are correctness-checker output, not performance comparisons. Protocol fixtures do not exhaust all TLS cancellation and shutdown orders. Full CI, macOS/GCC and multi-shard stress remain unverified.

Release CTest network/splice/ws_tunnel_iouring/cli_backend: all four passed. Timed throughput cells finished before integration compilation or sanitizer/tidy work began. Protocol smoke rates were intentionally not used while compilation ran.

ET-enabled RealEpollEpisodeGuard integration selection: 27 selected tests passed (140,314 checks); some selected cases use unchanged separate fixtures, so this is not 27 independent full-ET integration tests. StableEpollFixture explicitly enables ET for all 13 selected stable lifecycle tests.
