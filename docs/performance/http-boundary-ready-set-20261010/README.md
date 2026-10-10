# HTTP boundary ready bitmap experiment

Candidate `6f98ab13`; opt-in `RUT_STUDY_HTTP_BOUNDARY_READY_SET=on`,
default off. One bit per slot records exact publication from
`maybe_publish_http1_boundary_ready`; traversal preserves ascending slot order
and complete-CQ-batch admission. The terminal-scan experiment is disabled.
The default path still maintains the bitmap for experimental comparison, so
this candidate has additional bookkeeping versus its parent; it is not a
proposed production default yet.

Release build and test_network, test_splice, test_cli_backend,
test_ws_tunnel_iouring pass. New test covers slots 63/64, readiness that becomes
blocked again before admission, republication and invalidated readiness.
Callback-driven republication ordering, forced allocation failure and full
sanitizer validation remain untested specifically for this experiment.

Serial one frontend CPU 2, four origin workers CPUs 3,4,8,9, clients CPUs 5,7,
128 implicit HTTP/1 keep-alive connections, static origin bodies 512B/4KiB/1MiB,
2s warmup and 6s measurement. Frozen binary hashes and all 12 rows included.
Zero reported errors during measurements and warmups.

**Important outcome:** shutdown reports `visited=0` at all three sizes.
These ordinary streaming proxy workloads never enter deferred HTTP/1 boundary
recovery. The on/off throughput differences therefore do not demonstrate a
bitmap optimization benefit. No repeat campaign or default promotion is
justified on these workloads. Preserve this implementation for targeted
retirement/deadline workloads, and pursue the actual ordinary HTTP hot path.

Separate diagnostic runs enable `RUT_STUDY_IO_STATS=on`; their throughput is
not mixed into the uninstrumented comparison. Shutdown counters include
warmup/preflight and are approximate workload indicators, not timed-only
latency attribution:

| Body | wait calls | events | events/wait | empty waits | enter calls |
|---|---:|---:|---:|---:|---:|
| 512B | 52022 | 3454262 | 66.4 | 19 | 51999 |
| 1MiB | 92119 | 182851 | 1.98 | 8815 | 75986 |

Next investigation: large-body splice readiness/progression and fine-grained
waits; distinguish readiness, cancellation, timer and empty batches before
altering batching. These counters alone do not establish a cause. No SEND_ZC
or response-size prediction.

The nginx 1MiB p99 again exceeds 500ms; retain this anomaly rather than claiming
a latency advantage until wrk raw histogram/endpoint behavior is explained.
Raw logs/runners/binaries are in the matching checkpoint directory and its
`-diagnostics` sibling under `/home/hurricane/private/code/rut-performance-checkpoints`.
