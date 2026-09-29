# Pipe-backed bounded body relay: integration plan

Status: feasibility probe passed; **no runtime implementation yet**. This is a proposed optimization of the existing matrix, not a replacement matrix or relaxed protocol contract.

## Initial eligibility

Use only Linux io_uring, plaintext downstream, validated BoundedPositiveBody with its pinned canonical response header already sent, no mutation/inspection/TLS/range/full-buffer requirement, and a large declared body. Switch only at an empty memory-buffer boundary, with no upstream recv or downstream send owning those buffers. Existing memory/header data must drain in order first. For the 1 MiB workload, a read-ahead pause/resume boundary may provide this entry; actual hit counts must be measured before interpreting a throughput result.

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

## Correctness and retention gates

- Exact response payload and prefix ordering; partial reads/writes, EAGAIN and EOF.
- Declared-length cap with trailing bytes, truncated origin, stalled origin and bounded first-byte behavior.
- Backpressure, bounded memory, actual pipe capacity and allocation/SQ exhaustion.
- Cancellation and shutdown while input/output is in flight; stale episode/generation, duplicate events and reused slot safety.
- Unchanged TLS, complete-buffered 206, small responses, native/static and epoll fallback.
- Full relevant regression plus causal candidate/baseline orders for 1 MiB close/keepalive at c1/c32/c128 and excluded-path controls.
- eBPF verification that the intended pipe path executes and reduces the measured copy path under the real Rut workload.
- Retain only demonstrated improvements without material control regressions, then update the existing 96-coordinate acceptance matrix. Standalone relay throughput cannot substitute for this gate.
