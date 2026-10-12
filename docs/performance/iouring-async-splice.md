# io_uring asynchronous response splice experiment

This experiment submits plaintext HTTP/1.1 Content-Length body relay operations
through `IORING_OP_SPLICE`. It keeps the existing eligibility rules, including
the default 64 KiB remaining-body threshold, serialized header/prefix completion, and
exclusion of TLS, throttled, transformed, and upload responses. Normal startup enables linked asynchronous relay, hard links, queue-capacity
admission, adaptive segments, slice-derived admission and relay TCP_NODELAY.
The loop constructor keeps experiment fields off so isolated fixtures can
select their own path; main applies `enable_async_response_splice_defaults()`.
Runtime probe failure retains synchronous relay and its old admission rule.
Slow-response reporting has its own explicit
`RUT_STUDY_HTTP_ASYNC_SPLICE_REPORT=on` switch and stays silent otherwise.

## Compatibility

`IORING_OP_SPLICE` was introduced in Linux 5.7. This is the opcode's minimum
version, not the minimum version of the complete Rut io_uring backend.
CMake checks the opcode and SQE splice fields and defines
`RUT_HAVE_IORING_OP_SPLICE`. The opcode is an enum value, so an `#ifdef` of
`IORING_OP_SPLICE` would not test header support correctly. Runtime registration
of `IORING_REGISTER_PROBE` additionally verifies opcode support. Unavailable
support preserves the synchronous splice path.

`IOSQE_IO_HARDLINK` predates the splice opcode (Linux 5.5). Unlike a soft link,
it continues the output operation after a positive short input completion or
an input EAGAIN. Preparation/submission failures can still break a hard link.
See the [kernel io_uring API documentation](https://www.man7.org/linux/man-pages/man2/io_uring_enter.2.html).

## Ownership and completion

Each connection owns a nonblocking pipe. A linked pair reserves two SQ slots
before publishing either operation. Both CQEs must retire before the pair
advances, irrespective of dispatch order. The output completion is bounded by
the actual input byte count; short output and EAGAIN retain the unread pipe
bytes for continuation. Soft-linked short input cancels the output, which is
then resubmitted for the actual input length. Hard-linked output consumes only
the bytes present in the private pipe.

Cancellation retains the pipe and source descriptor until its target/cancel
ledger drains. The client descriptor remains held until all connection
operations retire. This prevents a queued io-wq operation from using a reused
descriptor number after logical connection closure.

## Experiment switches

- `RUT_STUDY_HTTP_ASYNC_SPLICE=on`: submit individual asynchronous operations.
- `RUT_STUDY_HTTP_ASYNC_SPLICE_LINK=on`: enable asynchronous relay and paired SQEs.
- `RUT_STUDY_HTTP_ASYNC_SPLICE_HARDLINK=on`: use hard links for those pairs.
- `RUT_STUDY_HTTP_ASYNC_SPLICE_QUEUE_BUDGET=on`: derive call admission from SQ
  capacity, retaining the FIFO time guard and older-owner admission rule.
- `RUT_STUDY_HTTP_ASYNC_SPLICE_ADAPTIVE_CHUNK=on`: bound the segment by remaining
  body bytes, actual pipe capacity, and half the existing relay byte budget
  (the budget accounts for both input and output). No machine-specific batch
  size is selected.
- `RUT_STUDY_HTTP_ASYNC_SPLICE_SLICE_THRESHOLD=on`: experimentally admit a
  remaining body of at least one ordinary receive slice (16 KiB), only when
  asynchronous splice and runtime opcode support are both enabled. This targets
  medium responses excluded by the default remaining-byte rule.
- `RUT_STUDY_HTTP_ASYNC_SPLICE_NODELAY=on`: enable TCP_NODELAY at relay admission.

The separate CONTINUE and MORE switches remain experimental; existing trials
did not establish a throughput improvement. No FIONREAD availability probe is
retained: it increased syscall count and reduced throughput in its comparison.

## Evidence and limits

On an isolated loopback network without the host's generic XDP program, the
adaptive asynchronous soft-link candidate averaged 10,072 requests/s for
1 MiB responses, versus 7,026 for original commit `3c2b4ec` and 4,613 for pinned
nginx. Three cyclic 30-second repetitions used one frontend CPU, four origin
CPUs and three load-generator CPUs. Every warmup and measured run had zero
errors with wrk's two-second timeout. These figures describe that workload and
network environment, not TLS, small responses or the host XDP path.

A separate three-repeat comparison measured hard links at 10,046 requests/s
versus soft links at 9,870 (+1.8%), with zero errors; hard links won two of the
three repetitions. This does not establish a robust throughput advantage.
An eBPF diagnostic comparison counted 2.76 raw syscalls/request with hard links
versus 3.81 with soft links, and zero canceled output operations versus 1.71
per request. Instrumented runs are diagnostic evidence, not acceptance
throughput measurements. Hard links are included in the production configuration: their throughput
advantage alone is small, but they reduce canceled operations and raw syscalls.

The focused splice suite passes 67 tests, including real kernel completions,
empty-source EAGAIN, positive short reads, three-mode output backpressure,
reverse completion dispatch, pipe capacity bounds, unsupported-opcode fallback,
cancellation/descriptor retirement, and slice-threshold admission/fallback. Macro-disabled backend compilation also
passes. Initial 4 KiB, 64 KiB and 256 KiB single-repeat screens also had zero errors.
The 64 KiB screen remained slower than nginx, motivating the separate
slice-threshold experiment. These screens do not establish repeatable gains.
Full CI, older-kernel execution and mixed-workload performance remain
to be verified.

The slice-threshold experiment subsequently averaged 51,583 requests/s for
64 KiB, versus 26,026 with the previous threshold and 40,074 for nginx in two
cyclic 10-second repetitions. Both repetitions improved, and all warmup and
measured errors were zero. This is promising screening evidence (+98% against
the previous candidate, +29% against nginx); longer repetitions are still required before changing defaults. A separate
eBPF diagnostic confirmed raw syscalls decreased from 1.075 to 1.035 per
request, with approximately two splice opcode submissions per request and
zero canceled output operations. Both diagnostic runs had zero errors.

Three cyclic 30-second 64 KiB repetitions subsequently averaged 51,817
requests/s for the slice-threshold candidate, 25,610 for the old threshold and
41,989 for nginx. The candidate led both comparators in every repetition; every
warmup and measured run had zero errors. This confirms the medium-response
gain in the isolated no-XDP environment (+102% versus the previous threshold,
+23.4% versus nginx). Mixed-load and production-default validation remain open.

An independent CMake Release build with JIT disabled passes the seven selected
runtime checks: network (1,609 tests), splice (66 tests), idle trimming, drain,
fault injection, shard control and the runtime state model. That broader run
found a misplaced pending-operation guard in batch pinning; the guard now
belongs to slot reclamation, restoring same-batch accept/reuse protection.
The corrected build passes all seven checks. Sanitizers and full CI remain open.

The paced mixed-load screen (1 MiB saturated traffic plus 5,000 planned 4 KiB
requests/s) failed its strict completeness gate. The candidate increased bulk
throughput, but its small-request p99 increased versus the original, and some
planned arrivals were not issued by the end of warmup or measurement. Nginx
delivered only about 30% of the planned small load. Zero transport errors do
not make these incomplete runs pass; the next experiment compares the existing
byte budget with queue-capacity admission before selecting defaults.

The user accepts some latency increase for substantial throughput gains.
The production configuration therefore retains the throughput-oriented policy
instead of adopting the latency study policy, which did not show consistent
benefit in its paired mixed-load diagnostic. Data integrity, cancellation and
the two-second transport timeout remain required. The paced completeness
failures above remain recorded and are not reported as passes.

Every asynchronous splice environment switch accepts `on` and `off`.
`RUT_STUDY_HTTP_ASYNC_SPLICE=off` overrides a simultaneous LINK=on independent
of environment order, restoring the legacy relay path. CONTINUE and MORE stay
off; diagnostic REPORT stays off. The production-configuration splice test
checks exact medium and large body bytes through the same helper main uses.

Normal-startup screens without study environment measured 53,381 requests/s
for 64 KiB (26,156 original; 41,128 nginx) and 10,744 for 1 MiB
(6,945 original; 4,570 nginx), all errors zero. These are single-repeat
screens, distinct from the earlier longer opt-in comparisons. Normal 4 KiB
showed a roughly 4.4% regression against the original in a three-repeat
follow-up, while still beating nginx; small-response admission rejection is
being evaluated separately and has not yet established a stable improvement.

An eBPF diagnostic of normal 64 KiB startup counted 1.035 raw syscalls/request
versus 1.074 for the original, about two splice SQEs/request and zero canceled
output operations. A same-binary comparison with ASYNC_SPLICE=off and LINK=on
confirmed zero splice opcode submissions on the explicitly disabled path,
versus about two on the enabled path. Both had zero transport errors. Normal
server logs contained no async slow-response or terminal-scan diagnostics.
The final production-configuration source passes the independent seven-check
runtime run, including 1,609 network tests and 67 splice tests.

Debug ASan+UBSan builds of `test_splice` and `test_fault_injection` also pass
with leak detection and halt-on-error enabled; no sanitizer report was emitted.
This covers the focused real-kernel splice/cancel/fd-reuse tests, not the full
network suite under sanitizers or GitHub CI.

The same-binary 4 KiB on/off comparison averaged 113,066 versus 117,215
requests/s (-3.5% enabled), all errors zero, with substantial per-run variation.
A lazy activation of relay budgets then averaged only +0.3% against the retained
configuration and won one of two repetitions. That change was reverted; the
failed/neutral experiment remains in the external checkpoint artifacts. Small
response profiling remains open rather than treating the regression as resolved.
