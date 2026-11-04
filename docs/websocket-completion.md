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
- [ ] General bounded Text/Binary output with owned asynchronous send storage.
- [ ] Connection and close context with explicit callback/session lifetimes.
- [ ] RFC 7692 compression negotiation and bounded encode/decode resources.
- [ ] Bounded messages beyond a single I/O slice, backpressure and cancellation.
- [ ] Interoperability and malformed-input validation for both Linux backends,
  source/JIT and native programs, feature-disabled builds and sanitizer checks.
- [ ] Review the complete diff, create a GitHub PR and leave it unmerged.

Existing bounds are part of the API contract, but implementation shortcuts must
not silently change ordinary concept semantics. Unsupported forms remain explicit
compile errors until their execution and lifetime rules have been implemented.

Dynamic scalar Text/Bytes output and runtime close arguments now use shared IR.
Results are copied into owned send storage; close reasons have separate drain
storage, and backpressure is checked before the next callback. The current
single-slice limit remains. General error and helper evaluation integration and
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
Lifecycle callbacks remain open.

The runtime now retains each leg's first received Close status/reason separately
from local closing policy, including empty (1005) and absent (1006) cases.
Pre-teardown cleanup borrows this owned metadata; inspector reset and deferred
sends cannot overwrite it. This is the runtime foundation for close context;
language lifecycle callbacks remain pending.
