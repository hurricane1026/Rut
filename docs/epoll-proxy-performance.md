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

## Idle upstream terminal-event fast path

On top of the #794 merge (`ac7c0292`), an idle watched upstream receiving
`EPOLLRDHUP`, `EPOLLHUP`, or `EPOLLERR` is discarded directly. An idle upstream
with a closed receive side cannot serve a subsequent request, including when
unread bytes precede EOF. Ordinary readability still uses `MSG_PEEK` to
distinguish unexpected bytes from exhausted readiness. Active upstreams retain
their existing data-before-EOF handling and ownership checks.

A focused socket-pair regression parks an upstream, sends eight unsolicited
bytes, and half-closes the peer. It verifies pool removal, descriptor closure,
and absence of receive dispatch to either connection. Running this same test
with an external `recv` counter measured one `MSG_PEEK` call on the baseline
and zero on the candidate. This establishes the removed syscall for this
specific close path; this syscall comparison alone does not establish an
end-to-end throughput or latency gain.

Clang 22 Release verification passed all 1606 network tests in both default
and ET test modes, all 49 splice tests in both modes, and 62 WebSocket frame
and termination tests. The network executable requires stderr to remain a
pollable descriptor: two existing callback tests use `dup(2)` as their test
fd. Redirecting stderr to a regular log file fails those tests on both the
baseline and candidate; capturing stderr through a pipe passes them.
Changed C++ lines pass clang-format and the diff passes whitespace checks.
Sol's read-only review reported no findings. Raw comparison and test logs,
the external counter source, and the patch are retained in
`/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-idle-terminal-20261011/`.

A subsequent isolated event benchmark used the same Release runtime archive
except for the baseline/candidate epoll object, pinned to CPU 2. Seven samples
per variant alternated execution order; each sample discarded 1000 warmup
iterations and timed 30000 already-harvested idle events. Socket setup,
parking, peer writes, and epoll_wait were outside the timed interval.
Median terminal-event processing fell from 1404.89 ns to 1097.50 ns (-21.88%).
The exhausted-readability control rose from 216.53 ns to 228.13 ns (+5.36%),
so the extra branch has a measured cost in that control. This is a narrow
event-processing comparison, not evidence of improved HTTP RPS or p99.
The standalone source, binaries, hashes and individual samples are archived
alongside the test evidence as `idle_bench.cc` and `idle-benchmark.json`.

The HTTP RPS follow-up used a single Rut worker on CPU 2, four pinned-image
nginx origin workers on CPUs 3/4/8/9, and wrk on CPUs 5/7. Both variants enabled
ET, stable upstream events and stable relay events. The workload was a 4 KiB
native-streaming proxy response at concurrency 128, with upstream reuse on
and an omit-Connection request policy. Five paired rounds alternated variant
order; each cell had one second of warmup and five seconds of measurement.
All 20 measured samples and their warmups had zero errors and passed the
harness's response and origin-reuse preflights.

| Downstream connection | Baseline median RPS | Candidate median RPS | Change |
|---|---:|---:|---:|
| Short | 24,766 | 24,949 | +0.74% |
| Keep-alive | 65,622 | 66,308 | +1.05% |

These short samples do not establish a repeatable throughput gain: paired
short-connection changes ranged from -6.25% to +8.51%, and keep-alive changes
from -1.78% to +3.89%. The workload exercises steady origin reuse rather than
deliberate asynchronous idle-origin closure. Source, matching compiler and
converter binaries, binary hashes, commands, preflights, samples and summary
are archived in `http-rps/` beneath the evidence directory above.

The follow-up also fixed a benchmark wrapper callback binding: the native
origin verifier and its API wrapper previously captured the same reassigned
local name, causing recursive verification before any load could run. A
regression checks that the composed native wrappers delegate exactly once;
all 68 benchmark tool tests pass. This harness fix applies equally to both
RPS variants and does not skip any preflight.
