# Pipe-backed bounded body relay: integration plan

Status: feasibility probe passed; pipe storage owner, io_uring transport, connection teardown custody and real-kernel tests implemented; **not connected to the production response path yet**. This is a proposed optimization of the existing matrix, not a replacement matrix or relaxed protocol contract.

## Initial eligibility

Use only Linux io_uring, plaintext downstream, validated BoundedPositiveBody with its pinned canonical response header already sent, no mutation/inspection/TLS/range/full-buffer requirement, and a large declared body. Switch only when no upstream recv or downstream send owns the ordinary buffers. Preserve any existing memory prefix and receive subsequent bytes into the pipe; output must drain the memory prefix before pipe bytes. The original proposal required an entirely empty ordinary buffer, but `bounded_response_release_bytes` rounds header+received down to a 4096-byte boundary. For example header=146 and received=524288 permit release of 524142 body bytes, leaving 146 ordinary bytes even after every eligible byte is sent. Requiring emptiness can therefore prevent entry despite a drained eligible prefix. This is an arithmetic/code-path finding, not a measured runtime hit rate. Actual transition hit counts must be measured before interpreting throughput.

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

The next semantic integration must preserve two timing boundaries: receive evidence must be materialized before the existing whole-batch deadline arbitration; physical output completion must not remove bytes from the logical buffered-body invariant before the corresponding send callback accounts for them. Preserve the ordinary-memory prefix in front of pipe bytes and represent the pipe source explicitly in both Bounded release and terminal-body paths. The current live-transport dispatch deliberately closes instead of pretending that an unintegrated operation successfully forwarded a response.

## Correctness and retention gates

- Exact response payload and prefix ordering; partial reads/writes, EAGAIN and EOF.
- Declared-length cap with trailing bytes, truncated origin, stalled origin and bounded first-byte behavior.
- Backpressure, bounded memory, actual pipe capacity and allocation/SQ exhaustion.
- Cancellation and shutdown while input/output is in flight; stale episode/generation, duplicate events and reused slot safety.
- Unchanged TLS, complete-buffered 206, small responses, native/static and epoll fallback.
- Full relevant regression plus causal candidate/baseline orders for 1 MiB close/keepalive at c1/c32/c128 and excluded-path controls.
- eBPF verification that the intended pipe path executes and reduces the measured copy path under the real Rut workload.
- Retain only demonstrated improvements without material control regressions, then update the existing 96-coordinate acceptance matrix. Standalone relay throughput cannot substitute for this gate.
