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

### First native response receive

With asynchronous splice available, the first ordinary plaintext GET response
receive is capped at two ordinary provided buffers (8 KiB). Subsequent header
fragments retain the full available receive capacity. TLS, transformed and
throttled responses, unsupported kernels and an explicitly disabled splice path
retain their previous receive sizing. This leaves more body bytes in the socket
for splice without splitting a typical 4 KiB response and its headers.

In three cyclic 10-second private-network repetitions at 64 KiB, this candidate
averaged 57,636 requests/s versus 51,464 for the retained 16 KiB prefix and 38,914
for pinned nginx: +12.0% and +48.1%, respectively. All repetitions were valid and
had zero errors. The corresponding 4 KiB comparison averaged +0.7%, with two
wins and one loss; that is not evidence of a stable small-response improvement.
The per-size target of at least +50% over nginx remains unfulfilled.

The 64 KiB eBPF diagnostic measured 1.0381 raw syscalls/request versus 1.0352
with the prior prefix (+0.28%), approximately two splice submissions/request,
and no canceled writes. Diagnostic throughput is not acceptance evidence.
Independent Release network and splice CTest targets pass. A real socket
validation sends 9–12 KiB headers in 3,000-byte fragments and verifies exact
4 KiB, 64 KiB and 1 MiB bodies on one persistent downstream connection. These
follow-up changes have not yet been checked under sanitizers or GitHub CI.

A two-repeat, order-rotated eBPF check of the same 8 KiB-prefix binary at 4 KiB
does not reproduce an enabled-splice enter regression. Enabled enter/request
was 0.0382 and 0.1173, versus 0.0534 and 0.2677 when explicitly disabled. The
disabled path itself changed from 56.1 to 11.2 submitted SQEs/enter between
repetitions; enabled batches averaged 78.5 and 25.6. Neither mode submitted a
splice operation, and all transport errors were zero. The earlier single-trace
enter difference therefore cannot establish configuration as its cause. These
instrumented runs identify batching variability for further investigation,
not a new throughput acceptance result.

### Retained-source long matrix

Three cyclic 30-second repetitions per engine and size, with the same private
network and resource configuration, give the following retained-source results:

| Body size | Rut requests/s | Original Rut requests/s | Pinned nginx requests/s | Rut over nginx |
| --- | ---: | ---: | ---: | ---: |
| 4 KiB | 108,206 | 110,840 | 79,838 | +35.5% |
| 64 KiB | 56,406 | 25,823 | 40,451 | +39.4% |
| 256 KiB | 31,493 | 22,737 | 13,786 | +128.4% |
| 1 MiB | 10,483 | 7,013 | 4,622 | +126.8% |

All 36 measurements and their warmups pass the existing validity/error gates.
Both smaller sizes remain below the requested +50% target; the 64 KiB short
screen's +48.1% must not substitute for this longer matrix. Large-response
advantages do not prove that every size meets the objective. Full mixed-load
acceptance and GitHub CI also remain outstanding.

An external raw-syscall TCP experiment confirms one-shot io_uring
`MSG_PEEK | MSG_DONTWAIT` results for an empty stream (EAGAIN), two peeks of the
same retained byte, and EOF after consuming that byte and receiving FIN. This
is API evidence for a possible batched idle-socket authentication experiment;
it does not validate Rut integration, cancellation ownership or performance.

The subsequent opt-in idle-probe integration was rejected. It used the existing
connect completion/cancellation identity and deferred request send until an
EAGAIN probe CQE. Its focused suite passed 69 tests and 100,335 checks, including
healthy-probe-before-send and close-after-probe coverage. Three cyclic 10-second
4 KiB same-binary on/off comparisons averaged 109,387 versus 112,411 requests/s
(-2.69%), all errors zero. The eBPF diagnostic confirmed synchronous recv calls
fell from about one/request to zero, but enter/request rose from 0.0646 to
0.2748; total raw syscalls/request fell from 1.0653 to 0.2755. Fewer syscalls did
not establish a throughput benefit. Both the integration and unused submission
primitive were removed; the external checkpoint retains the complete patch,
binary pair, test evidence and traces. Dirty-candidate integration and broader
network validation were not completed before rejecting this candidate.

The ordinary small-request synchronous-send experiment was also rejected.
Its same-binary 4 KiB short screen averaged +1.57%, but three cyclic 30-second
comparisons against the retained source averaged 111,784 versus 113,913
requests/s (-1.87%); pinned nginx averaged 80,590. All errors were zero. eBPF
confirmed one fewer Send SQE/request, but total syscalls/request increased from
1.1148 to 2.0249 because of the added direct send. The 69-test focused suite
covered exact continuation of a written prefix and deferred full-send closure.
The candidate was removed; the checkpoint retains its patch, binaries and
measurements. The short screen does not establish a retained throughput gain.

### Ordinary native direct receive

`RUT_STUDY_HTTP_DIRECT_NATIVE_RECV=on` makes eligible ordinary plaintext native
GET one-shot receives target their existing connection-owned slice directly.
It preserves receive-length limits, including the 8 KiB first-response limit,
and uses the existing direct-receive pinning and cancellation ownership. TLS,
WebSocket and transformed responses retain their previous selection. The
ordinary provided-buffer-ring-to-slice copy and buffer return are avoided.
This remains opt-in while larger-size comparisons are outstanding.

Three cyclic 30-second comparisons against retained source and pinned nginx:

| Body size | Candidate requests/s | Retained requests/s | nginx requests/s | Candidate over retained | Candidate over nginx |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4 KiB | 114,682 | 105,588 | 80,985 | +8.6% | +41.6% |
| 64 KiB | 61,886 | 59,358 | 41,992 | +4.3% | +47.4% |

All measurements and warmups are valid with zero errors. These sizes still
do not meet the requested +50% over nginx. An eBPF on/off diagnostic confirms
about one direct upstream completion/request instead of a selected-buffer
completion, with unchanged recv SQE counts. Raw syscalls/request were 1.0621
versus 1.1199 at 4 KiB and 1.0358 versus 1.0368 at 64 KiB; these single traces
do not establish a repeatable batching/syscall reduction.

The independent seven runtime CTest checks pass. The focused splice suite now
passes 69 tests and 100,303 checks, including ordinary-slice append integrity
and close/cancel pinning before slot reuse. ASan+UBSan splice and fault-injection
checks pass with leak detection; the full network suite was not run under
sanitizers. Real-service validation preserves fragmented 9–12 KiB headers and
exact 4 KiB, 64 KiB and 1 MiB bodies over one downstream keep-alive connection.

Larger-size follow-up comparisons do not justify a global default change:
three cyclic 30-second repetitions averaged 30,722 versus 32,072 requests/s
at 256 KiB (-4.21%), and 10,453 versus 10,584 at 1 MiB (-1.23%). Both remain
over twice pinned nginx (+110.9% and +125.1%), with all measurements valid and
errors zero, but small-response improvements do not erase the larger-size
regression evidence. The feature remains opt-in. An additional same-binary
1 MiB eBPF diagnostic records exactly 8,192 bytes for every positive upstream
receive in both modes: unselected completions when direct, selected-buffer
completions otherwise. Different first-receive lengths do not explain the
observed throughput difference; its cause is not yet established.

### Adaptive native receive follow-up (rejected)

An opt-in per-connection hint selected direct owned-slice receive after a parsed
non-bulk response and buffer selection after a bulk response. Unknown responses
used buffer selection; framing always used the current parsed response. Focused
validation passed 70 tests / 100,344 checks, and alternating 4 KiB, 64 KiB, 1 MiB,
64 KiB, 4 KiB responses with fragmented large headers preserved exact bytes.

A same-binary cyclic 3 x 15 s private-network comparison against disabled hints
and pinned nginx completed all 36 rows with zero measurement/warmup errors.
Relative to disabled hints: 4 KiB +0.19%, 64 KiB +4.34%, 256 KiB +0.09%,
1 MiB -2.77%. Relative to nginx: +39.43%, +49.64%, +99.18%, +123.59%.
The implementation was rejected rather than enabled globally.

Separate eBPF diagnostics confirmed direct receive for steady small responses
and buffer selection for bulk responses. Syscalls/request (enabled / disabled)
were 1.060854 / 1.086435, 1.052332 / 1.039113, 1.081786 / 1.077513, and
3.468852 / 3.752502 respectively. These single traces do not prove a stable
syscall reduction or identify the cause of bulk throughput variation. Frozen
binaries, final patch, wire results, full matrix and trace summaries remain in
the external `adaptive-native-v1` checkpoint artifacts.
