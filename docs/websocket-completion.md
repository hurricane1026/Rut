# HTTP/1.1 WebSocket completion criteria

This is the implementation checklist for completing WebSocket as a peer of the
existing Rut concepts. HTTP/2 Extended CONNECT is outside this iteration, as
confirmed by the user. Checked entries require executable evidence; this list
does not turn target syntax into supported syntax. The language card and
[terminate guide](websocket-terminate.md) describe the current surface.

- [x] Strict RFC 6455 opening handshakes and subprotocol selection.
- [x] Complete Text/Binary message concepts, typed kind/direction and borrowed Bytes.
- [x] Ordinary pure helper typing, optional bindings, JSON projection and predicates.
- [x] Fragmentation, masking, UTF-8 validation, controls and bounded close draining.
- [x] Ordinary HTTP admission without a separate expression whitelist, with zero
  WebSocket upstream connections on rejection and no request-view capture.
- [ ] General message expressions, local evaluation and control flow through the
  normal compiler; preserve short-circuit, optional/error and helper semantics.
- [x] General bounded Text/Binary output with owned asynchronous send storage.
- [x] Connection and close context with explicit callback/session lifetimes.
- [x] RFC 7692 compression negotiation and bounded encode/decode resources.
- [x] Bounded messages beyond a single I/O slice, backpressure and cancellation.
- [ ] Interoperability and malformed-input validation for both Linux backends,
  source/JIT and native programs, feature-disabled builds and sanitizer checks.
- [ ] Review the complete diff, create a GitHub PR and leave it unmerged.

Existing bounds are part of the API contract, but implementation shortcuts must
not silently change ordinary concept semantics. Unsupported forms remain explicit
compile errors until their execution and lifetime rules have been implemented.

Dynamic scalar Text/Bytes output and runtime close arguments now use shared IR.
Results are copied into owned send storage; close reasons have separate drain
storage, and backpressure is checked before the next callback. The configured message limit now reaches 262130 bytes using the existing bulk pool. General error and helper evaluation integration and
string interpolation still need separate work; the broad criteria above remain
open until those semantics and the remaining protocol resources are verified.

General optional JSON expressions now use shared IR, including dynamic pointers,
edits, independent Json values and concrete struct decoding. Callback bindings
retain values across later JSON operations; the generic path uses normal source
limits rather than specialized recipe-table limits. Helper-internal evaluation
and general error semantics remain open.

General String regex expressions now share the normal Vectorscan operation in
message IR. Its message entry retains a tri-state scan result and closes before
Boolean negation on scan/resource failure; HTTP keeps its existing Boolean API.
The raw-message recipe path also preserves failures. Regex locals, dynamic JSON
string sources and callbacks beyond recipe tables use this same behavior.

Pure helper local/guard producers and reached actual arguments now retain lexical
evaluation in general callbacks, including unused resource producers and ordered
arguments. Common String concatenation/predicates use shared IR and bounded
owned arena storage. Error/effect/yield integration, interpolation and the broader
protocol/resource criteria above remain open.

Closed message-kind/direction domains now use ordinary match analysis, including
contextual case patterns and coverage checks shared with helpers/HTTP routes.
Lexical helper/callback match selectors retain reached single evaluation.

HTTP chain-after response effects now share admission rejection and accepted-101
commit behavior. Source/native tests on both backends cover zero-connect denial,
keepalive reuse, stabilized values across request rewrites, coalesced messages
from both peers and refusal to publish mutated handshake-critical headers. The
ordinary HTTP wait/for restrictions on chain-after effects remain unchanged.

Fallible helper results now retain error/nil carriers in lexical callback lets,
aliases and helper-local recovery. `guard let`, `if let`, `.or(default)` and
named-error `guard match` share ordinary analysis; the latter retains HTTP's
final-wildcard rule. Reached producers run once even for unused results.
Response/effect/yield helper semantics and the broad criteria remain open.

Message connection context now projects typed downstream IP/port, TLS and the
negotiated subprotocol through ordinary borrowed helper/alias analysis. Values
come from the live connection in either direction; no HTTP request views escape
admission. The combined lifecycle criterion remains open for open/close events.

Cache reads and reached bare writes now share ordinary typing/IR in callbacks,
using a connection IP key. Compiled access binds declaration identity across
registry reorder/removal, and writes retain lexical guard/branch ordering.
Virtual-clock tests verify the existing per-invocation time latch refreshes for
the next message in both source and native callbacks. Cache remains lossy and
per-shard, not session storage.

Peer Close replies now preserve the exact received status/reason, including an
empty body when no status was sent. Reply bytes are connection-owned across
inspector reset and deferred sends. Each leg now waits for its peer's valid Close
separately from send completion, with local closing Ping/Pong handling and one
fixed deadline. Downstream FIN is independent of upstream progress. TLS now
flushes local close_notify before FIN using existing output ownership, with
strict source/native wire tests and bounded failure/cancellation handling.
Lifecycle callbacks now have synchronous open/close entries, described below.

The runtime now retains each leg's first received Close status/reason separately
from local closing policy, including empty (1005) and absent (1006) cases.
Pre-teardown cleanup borrows this owned metadata; inspector reset and deferred
sends cannot overwrite it. Synchronous `onOpen` and `onClose` trailing closures now expose the connection
and close contexts through ordinary helper/guard/if/match/Cache/time analysis.
Open runs before buffered messages; close runs once before terminal resource
retirement. Only open can initiate closing; hooks cannot forward data or yield.
AST/HIR ownership transfers, phase errors, linear sequential control flow and
runtime ordering are exercised in `test_ws_lifecycle` and
`test_ws_shutdown_deadline`. Source/native × epoll/io_uring wire tests observe
hook effects through ordinary HTTP Cache reads, including TLS. RFC 7692 remains required.

Explicit `maxMessageSize` values now accept 1 through 262130 bytes; the default
remains 16370. Large routes atomically acquire four bulk message/output buffers,
with no smaller-limit fallback. Both Linux backends stream ordinary I/O slices
into complete-message storage. io_uring uses bounded reads while preserving
its downstream ring and cancellation validation. Tests cover allocation rollback,
whole-message callbacks, 64-bit wire lengths, UTF-8 across fragments, interleaved
controls, deferred-send retirement and source/native × TLS × both backends.
The end-to-end matrix now contains 310 passing cases; RFC 7692 is still open.

The internal RFC 7692 raw-DEFLATE codec now uses a pinned static C zlib with
`Z_SOLO` and a custom allocator confined to one existing bulk slice per leg.
The existing compress-only zstd cannot supply DEFLATE. The codec tests cover
RFC vectors, received context history, BFINAL streams, negotiated window sizes,
decoded/wire work budgets and incompressible output fallback. The frame engine now decodes before application dispatch and independently
compresses destination output. Recompression uses the completed message buffer
only after copying the result into disjoint owned send storage; bounded attempts
retain the original frame for incompressible fallback. Controls remain uncompressed,
and closing discards application bytes without running the codec. Extension
negotiation and session ownership now run independently on each leg, with atomic
codec admission before 101 and teardown integrated with deferred output ownership.
Source/native × TLS × both Linux backends cover independent negotiation, dropped
history, fragmented data/control interleaving, windows 8/15, incompressible maximum
messages, a maximum frame coalesced with 101, invalid streams, UTF-8 and decoded
limits. The maximum-frame test found and fixes an io_uring completion-order stall:
another callback can consume bytes copied for a terminal recv, so the empty-input
callback must still restore its receive owner. Full regression/sanitizer and final
review evidence is recorded separately before checking the broad criteria.


Session compression validation now passes 462 end-to-end cases with no skips.
Normal and ASan/UBSan runs pass codec/inspection, extension grammar/rewrite,
frame, bulk allocation and asynchronous shutdown tests. A WebSocket/JIT-disabled
build and its inspection baseline also pass, and both ordinary runtime binaries
retain a libc-only ELF dependency list. The remaining language audit compares
against implemented ordinary expression/helper behavior: source interpolation
and non-response statement effects inside helpers currently fail in both HTTP
and WebSocket, so they are shared language limitations rather than an accepted
WebSocket behavior. Phase-specific Request/Response access and yielding remain
explicitly unavailable after upgrade.
