# Pipe-backed bounded body relay: integration plan

Status: storage, transport, receive/send custody, fallback and production admission are implemented in the candidate. Live HTTP and kernel eBPF confirm execution; the first two-coordinate causal probe improves over the accepted Rut baseline. **Retention across the full unchanged matrix is not yet established.** Earlier progress sections below describe their historical stage.

## Initial eligibility

Use only Linux io_uring, plaintext downstream, pipeline depth/generation 0, validated BoundedPositiveBody with its pinned canonical response header already sent, no mutation/inspection/TLS/range/full-buffer requirement, and a large declared body. Switch only when no upstream recv or downstream send owns the ordinary buffers. Preserve any existing memory prefix and receive subsequent bytes into the pipe; output must drain the memory prefix before pipe bytes. The original proposal required an entirely empty ordinary buffer, but `bounded_response_release_bytes` rounds header+received down to a 4096-byte boundary. For example header=146 and received=524288 permit release of 524142 body bytes, leaving 146 ordinary bytes even after every eligible byte is sent. Requiring emptiness can therefore prevent entry despite a drained eligible prefix. This is an arithmetic/code-path finding, not a measured runtime hit rate. Actual transition hit counts must be measured before interpreting throughput.

Keep the ordinary path for all other cases and for pipe allocation failure before transition. No huge pages, global pipe-size changes, upstream connection reuse, workload exclusions or concurrency-specific benchmark policy.

## Required accounting and ownership

- Introduce explicit pipe-backed storage; do not disguise a pipe as a user pointer or forge an existing Full memory-copy witness.
- Track committed pipe bytes separately from receive reservations and in-flight sends. Count pipe bytes in the buffered-body invariant without presenting a readable pointer.
- Cap upstream splice by remaining declared Content-Length and available bounded capacity. Never consume bytes of a following response.
- Preserve `bounded_response_release_bytes`, header-relative publication units, short hold timer, incomplete-prefix/clean-EOF semantics, and the current read-ahead pause/resume contract.
- Receive completion must validate connection slot, upstream episode, deadline generation/profile/method and the exact pipe receive owner before publishing bytes or refreshing inactivity deadlines.
- Send completion must retain the existing send generation, account each byte once and preserve partial-write continuation. A pipe transfer itself is not permission to publish beyond the release boundary.
- Keep pipe descriptors/storage and connection ownership alive until all operations/cancel completions drain. Handle close/reset/reused slot, stale and duplicate completions, SQ-full submission rollback and allocation failure.
- Honor per-user pipe limits: requesting a per-pipe capacity does not justify raising global limits. Record actual capacity; safely fall back before transition when the required storage cannot be obtained.
- io_uring splice uses worker execution on this kernel. Keep workers within the measured shard CPU budget; do not gain throughput by adding uncounted CPU capacity.

## Code paths requiring integration

1. Storage/resource owner and connection reset/deferred reclamation; preserve ordinary-buffer ownership and avoid perturbing small-response layout without measuring it.
2. Backend splice input/output SQEs, partial completion and cancellation decoding.
3. Post-header direct-body receive arming, batch witnesses and bounded release/terminal completion paths.
4. Existing body-length/front-data consumers: pipe data must be routed explicitly, including final completion and error paths, rather than allowing a null or fabricated data pointer into a memory send.

## Storage and primitive progress

`ResponseBodyPipe` now owns the nonblocking close-on-exec pipe and separate input/output reservation phases. SQ rollback is distinct from completion of a submitted operation; partial transfers update committed bytes only once. Zero/error completions retire an operation without inventing progress. Operation serials survive close/reopen and refuse wraparound. The eventual caller still must authenticate connection, episode, deadline and send ownership before applying a completion; local serials are not a substitute for that integration.

Pipe page slots can fill before the requested byte limit. The regression test actually exhausts an 8 KiB pipe with one-byte fragments from separate pages. `drain_into` migrates committed bytes into ordinary storage only when no input/output owns the pipe. Production fallback must preserve origin-received counters and must not refresh network inactivity time for this memory migration. Disable splice reentry for the response after fragmentation fallback to avoid a repeated loop.

Two real TCP/io_uring tests verify declared-length capping with trailing bytes, publication credit, EOF, EAGAIN and cancellation of a queued splice linked behind POLLIN. Workers use the test process's allowed affinity. Link members are published in one submission; an initial test harness incorrectly submitted the two members separately and was corrected. The cancellation test does not cover canceling a running blocking worker: the intended primitive is nonblocking, and the production design still needs an explicit readiness owner for EAGAIN. The tests use a separate small raw ring, not the runtime dispatcher.

Storage/primitive stage result: 9 tests, 224 checks, zero failures and zero skips on this Linux host. Runtime executable SHA256 still matches the accepted baseline. No production hit count or throughput improvement is claimed.

## Backend transport progress

`IoUringBackend` now submits nonblocking splice, one-shot readiness poll and exact-token cancel SQEs. Eight raw token kinds distinguish input/output, their readiness waits and each target's own cancel SQE. Tokens retain the full 32-bit operation serial and 24-bit connection ID. They are disjoint from both existing upstream episode tokens and downstream send generations. `wait()` decodes them into `BodyPipeTransport` events without changing committed bytes, application pending counts, response timers or copy witnesses. Partial transfers remain visible to the future semantic owner; the ordinary Send proactor does not resubmit them.

Before splice is admitted, `bind_body_pipe_workers` must successfully register the current thread's allowed CPU mask for io_wq. Failed registration disables admission. A SQ-full failure preserves a reservation for explicit rollback. Malformed raw flags, zero serials and out-of-range connection IDs fail the backend before publication. Exact serial cancellation of an old readiness wait cannot cancel a successor. The transport event cannot resume a JIT yield.

No response-path caller exists yet. Raw pipe dispatch now supports teardown custody (see below), but does not interpret pipe records as successful response I/O. Before enabling a caller, add authenticated semantic receive/send progress and convert EAGAIN into readiness/fallback rather than origin failure. Do not infer live-response deadline correctness from transport or teardown tests alone.

## Connection teardown custody progress

`ConnectionBase` now holds a lazily allocated `ResponseBodyPipeOwner` and a persistent operation-sequence high-water mark. The owner uses the existing shard SlicePool with explicit placement construction; it snapshots the connection descriptors, upstream episode and response-deadline identity for later semantic admission. Teardown preserves the owner through connection reset, keeps transfer/readiness targets separate from their cancellation SQEs, and retires each exact record once. Both target/cancel completion orders retain the slot until all owners drain. Generic pending-count exhaustion alone cannot bypass the pipe owner check.

Close rolls back reservations that never reached the kernel and cancels submitted targets by exact token. SQ-full cancellation gets a retry registration; retry scanning is skipped when no owner needs it. A target finishing before a cancel can be submitted removes that retry obligation. Once queued, the cancel keeps its own ownership until its CQE arrives, even if the target is already terminal. Positive bytes arriving after close update storage custody only, without advancing response progress. Sequence exhaustion disables new pipe allocation on that slot rather than wrapping.

After ring teardown, forced shutdown releases the process's pipe descriptors before destroying the pool. Pipe SQEs never contain pointers into the owner; kernel operations retain their own file references. This forced shutdown path is distinct from normal CQE-driven slot reuse and does not fabricate semantic completion.

Semantic integration must preserve two timing boundaries: receive evidence must be materialized before the existing whole-batch deadline arbitration; physical output completion must not remove bytes from the logical buffered-body invariant before the corresponding send callback accounts for them. Preserve the ordinary-memory prefix in front of pipe bytes and represent the pipe source explicitly in both Bounded release and terminal-body paths. The current live-transport dispatch deliberately closes instead of pretending that an unintegrated operation successfully forwarded a response.

## Pipe receive evidence and ordered storage progress

Buffered response accounting now includes committed pipe bytes. The ordinary receive buffer and body chain remain the front prefix; only after that prefix drains does `buffered_response_front_is_pipe()` become true. A pipe front has an explicit length and a null memory pointer. The future send router must select splice explicitly; pipe storage cannot masquerade as an ordinary send source.

For a current admitted Bounded plaintext body after the canonical header, backend `wait()` validates both the existing response-read policy owner and the pipe's captured descriptor/episode/deadline/profile/method tuple before retiring an exact input token. Positive completion establishes `IoEventCopyWitness::Pipe` with its serial and pre/post logical buffer boundaries. The existing batch ledger accepts this distinct storage witness only when those saved boundaries and identity match. No Full memory-copy witness is forged. EOF remains a neutral terminal receive; EAGAIN, cancellation and stale/overrun input remain raw transport records and cannot refresh a deadline. Kernel custody can still retire rejected data during abort without publishing it as response progress.

Close also distinguishes a raw pipe input owner from an already translated semantic UpstreamRecv event. Only the latter retains ordinary recv accounting; a raw pipe target must not acquire a fictitious second generic recv cancel.

Still pending before production admission: receive rearming/readiness and fragmentation fallback, physical-versus-logical output accounting, explicit pipe send routing through both Bounded release and terminal-body paths, and end-to-end timeout/backpressure regression. The isolated batch tests cannot substitute for that complete response integration or a runtime path-hit benchmark.

## Correctness and retention gates

- Exact response payload and prefix ordering; partial reads/writes, EAGAIN and EOF.
- Declared-length cap with trailing bytes, truncated origin, stalled origin and bounded first-byte behavior.
- Backpressure, bounded memory, actual pipe capacity and allocation/SQ exhaustion.
- Cancellation and shutdown while input/output is in flight; stale episode/generation, duplicate events and reused slot safety.
- Unchanged TLS, complete-buffered 206, small responses, native/static and epoll fallback.
- Full relevant regression plus causal candidate/baseline orders for 1 MiB close/keepalive at c1/c32/c128 and excluded-path controls.
- eBPF verification that the intended pipe path executes and reduces the measured copy path under the real Rut workload.
- Retain only demonstrated improvements without material control regressions, then update the existing 96-coordinate acceptance matrix. Standalone relay throughput cannot substitute for this gate.

## Logical pipe output progress

Output now routes through explicit release/terminal frames, retaining physical completion bytes in logical buffered length until the matching callback acknowledges the whole frame. Partial transfers, EAGAIN polls and exact-token cancellation preserve the frame and connection custody. Real-ring callback tests and the full network suite pass; see `pipe-send-validation.json`. The combined memory-send shortcut excludes pipe storage. Production admission is still disabled.

The next integration must replace body receive arming consistently at all four Bounded call sites, without setting the ordinary direct-memory receive flag for a pipe operation. EAGAIN readiness must retain logical receive ownership without refreshing inactivity time; page-slot exhaustion must migrate bytes in order after outstanding transfers settle. Never append an ordinary receive behind nonempty pipe bytes without first completing that migration. Admission hit counts are essential: current release-before-rearm ordering may have a memory-prefix send in flight at the natural transition point, so a blanket no-send admission condition needs review against actual event ordering rather than assuming the path will execute.

## Live receive integration progress

All four body receive sites now select pipe/chain ownership consistently. Pipe input has explicit EAGAIN readiness, ordered migration after output settles, per-response fallback disabling and independent terminal cancellation. Late input after terminal selection cannot expand logical buffered response bytes. Admission allows an authenticated ordinary memory-prefix send to remain pinned. io_wq affinity is registered after the shard's first backend wait, because registering before that thread has entered the ring returned EINVAL in the first real candidate.

The candidate now has verified real splice hits on the budgeted CPU, 1438 passing network tests, live byte-exact close/keepalive/slow-reader checks, abort cleanup, fragmentation/EOF/stall/backpressure diagnostics and a first causal comparison at 1 MiB close c1/c32. See `pipe-input-validation.json` for exact scope and results. Remaining gates are larger concurrency/keepalive and excluded-path controls, normalized copy-path comparison, and the original complete 96-coordinate acceptance run. The 1-second timeout is confined to a diagnostic configuration copy; it is not a revised acceptance workload.

## Concurrent successor admission restriction

Expanded c32 keepalive load exposed repeated early successors reaching strict preflight at depth 2, which the retained policy rejects. Pipe admission now excludes any nonzero pipeline depth or successor generation; already pipelined responses keep ordinary transport. The original benchmark workload and strict policy have not changed. Repeated c32/c128 keepalive checks and the full suite pass, and expanded large-response controls remain faster than the accepted Rut baseline. See `pipe-pipeline-guard-validation.json`. Full acceptance and excluded-path/copy controls remain outstanding.
