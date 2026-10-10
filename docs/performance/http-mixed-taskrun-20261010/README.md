# Cooperative TASKRUN relay scheduling study

Candidate 17d2e0a5, default off: RUT_STUDY_HTTP_TASKRUN_YIELD=on.
Peek the real TASKRUN/CQ_OVERFLOW flags without clearing them; execution and
CQ consumption remain owned by backend.wait. A real-ring fixture with an
empty CQ checks taskrun and overflow readiness, unchanged flag/CQ ownership,
and unrelated NEED_WAKEUP exclusion. Related CTests, build and format pass.

Same serial 1MiB /proxy + 4KiB /small, 96/32 persistent connections, one
frontend CPU 2, four origin workers 3,4,8,9, large clients 5,7 and small client 6.
Three rotations, 8s measurement / 2s warmup, nginx /small buffer 16KiB.
All 18 measurements and warmups report zero errors.

| Profile | Median GiB/s | Small p99 median ms |
|---|---:|---:|
| uring128 | 3.161 | 1.553 |
| byte80 | 5.760 | 5.887 |
| task80 | 5.081 | 4.209 |
| task40 | 3.751 | 1.712 |
| task20 | 3.090 | 1.248 |
| nginx | 3.751 | 46.134 |

Taskrun observations are nonzero in instrumented modes, but this change
does not provide a consistent simultaneous throughput/small-tail improvement.
Keep it experimental; do not promote as a default. Most modes exchange
large-response throughput for small-response service. Origin per-core busy
levels can differ substantially; snapshots identify imbalance but do not
establish it as the sole bottleneck. Frontend CPU 2 remains nearly fully busy
when accounting for softirq.

Next candidate submits already-owned ordinary SQEs at the post-CQ-batch
boundary before synchronous relay computation. It reuses the existing bounded
nonblocking flush, keeping cancellation/partial submission/error accounting
and leaving CQ harvesting to wait. The aim is earlier real I/O overlap,
not another size prediction or response-history heuristic.

Full raw evidence, effective configurations, frozen binaries and runner live
in the matching checkpoint directory. Raw summary SHA256:
1f2615c6bc7c7665bd9c79387668ec9e5c8aaa9a0892d3c65b931b497109eacc
