# Current-response epoll splice forwarding

The retained candidate uses a connection-owned 64 KiB nonblocking pipe to forward large plaintext HTTP/1.1 Content-Length GET responses. Admission happens after the current response header and buffered prefix have drained, with at least 64 KiB of the current body remaining. It uses no response-history predictor or route-size guess. TLS, chunked responses, request uploads, throttling and strict response-policy/deadline owners keep their existing paths.

Each callback performs at most four splice syscalls. Downstream backpressure parks upstream reads; read readiness parks downstream write interest while retaining hard-close detection. Relay tokens retain the upstream episode, so stale readiness cannot advance a reused connection. Completion retains an empty pipe for the next eligible response on that connection; connection close and shard shutdown reclaim it.

The fallback receive path starts with ordinary 16 KiB storage and may promote based on the current response to the existing 256 KiB bulk pool. Overwrite loans forward only committed bytes, while ordinary loans remain zero-filled. An upstream buffer pinned by a partial downstream send is paused rather than closed on unconsumed ENOBUFS.

## Validation and measured scope

The retained 64 KiB candidate passed 78 allocator tests and 1591 network tests. Tests cover admission exclusions, stale episode readiness, downstream backpressure, parked write interest, close handling and allocator privacy. Full CI and sanitizer validation remain outstanding; preserving this candidate does not imply merge approval.

Against main aa8b8c10, a serial single-worker HTTP comparison used concurrency 128, 4 KiB and 1 MiB bodies, short and persistent connections, three repetitions of 2 seconds warmup plus 10 seconds measurement, and the same pinned nginx origin with multi_accept on for every frontend. All 48 measurement samples and warmups had zero errors. At 1 MiB, median RPS was:

| Connection | Main epoll | Retained splice candidate | nginx |
|---|---:|---:|---:|
| Short | 2740 | 3351 | 3109 |
| Persistent | 2991 | 3320 | 3685 |

Earlier persistent timeouts were reproduced before splice admission, while waiting for upstream response headers. Origin accept queues reached 82 connections. An origin-only multi_accept intervention eliminated those timeouts in six repetitions; the original failures remain in the external benchmark artifacts.

Whole-core sampling then showed that the single-worker origin consumed nearly an entire core, including softirq time. With the SAME two-worker origin on CPUs 3/4 for all frontends, the retained candidate reached median 4269 RPS versus main epoll 3000 and nginx 4014. Candidate p99 was 30.5–31.0 ms versus nginx 33.4–35.4 ms; all nine measurement samples and warmups had zero errors. This is an origin-capacity comparison, not a new code optimization gain; the single-worker-origin end-to-end result above remains valid.

Increasing pipe capacity to 128 KiB, increasing callback syscall budget to eight, and coalescing currently readable segments did not improve persistent throughput consistently. Those experiments are excluded from the retained implementation. io_uring progression and SEND_ZC are not changed.

Raw data, binary/compiler pairs and scripts are preserved under /home/hurricane/private/code/rut-performance-checkpoints/. Relevant directories are origin-multiaccept-comparison-20261008 and epoll-keepalive-two-origin-workers-20261008. No PR was published or merged for this candidate.
