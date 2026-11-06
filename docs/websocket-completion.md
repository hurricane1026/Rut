# HTTP/1.1 WebSocket completion criteria

This is the implementation checklist for completing WebSocket as a peer of the
existing Rut concepts. HTTP/2 Extended CONNECT was outside that iteration; the
subsequent HTTP/2 increment is tracked below. Checked entries require executable evidence; this list
does not turn target syntax into supported syntax. The language card and
[terminate guide](websocket-terminate.md) describe the current surface.

- [x] Strict RFC 6455 opening handshakes and subprotocol selection.
- [x] Complete Text/Binary message concepts, typed kind/direction and borrowed Bytes.
- [x] Ordinary pure helper typing, optional bindings, JSON projection and predicates.
- [x] Fragmentation, masking, UTF-8 validation, controls and bounded close draining.
- [x] Ordinary HTTP admission without a separate expression whitelist, with zero
  WebSocket upstream connections on rejection and no request-view capture.
- [x] Ordinary supported message expressions, lexical evaluation and control flow
  through the shared compiler, preserving optional/error/helper semantics.
- [x] General bounded Text/Binary output with owned asynchronous send storage.
- [x] Connection and close context with explicit callback/session lifetimes.
- [x] RFC 7692 compression negotiation and bounded encode/decode resources.
- [x] Bounded messages beyond a single I/O slice, backpressure and cancellation.
- [x] Interoperability and malformed-input validation for both Linux backends,
  source/JIT and native programs, feature-disabled builds and sanitizer checks.
- [x] Review the complete diff and prepare an unmerged PR submission.

Existing bounds are API contracts. General callbacks use the shared compiler,
not the specialized recipe limits. Unsupported normal language syntax remains a
compile error; protocol integration does not turn planned syntax into support.

## Implemented scope

- HTTP admission reuses ordinary Request/Response helpers, guards, mutations and
  chain effects before upgrade. Rejected admission opens no WebSocket upstream.
- Complete message, kind/direction, connection and close concepts use ordinary
  borrowed typing, helpers, immutable aliases and matches.
- Shared lexical MIR/RIR retains selected-arm execution, reached once-only
  producers/arguments, optional/error carriers, JSON values, String/regex
  operations, Cache effects and per-invocation time.
- Dynamic Text/Bytes results and close arguments publish into owned output.
  Limits are 16370 bytes by default, explicitly 1 through 262130; received Text
  and published Text are checked as UTF-8.
- Strict opening/subprotocol handling, fragmentation/controls, bounded closing
  and TLS close_notify retain independent per-leg progress and send retirement.
- RFC 7692 agreements are independent per leg. Pinned static C zlib uses one
  bounded existing bulk slice per codec pair, acquired before 101. Decoded and
  wire-work bounds, received context history and incompressible fallback are
  covered by codec and wire tests.

## Phase and shared-language boundaries

Post-upgrade callbacks cannot borrow HTTP Request/Response values, capture request
views, yield into HTTP I/O or retain borrowed concepts outside their synchronous
invocation. These are phase/lifetime rules. Source interpolation and
non-response statement effects in helpers currently fail in both ordinary HTTP
and WebSocket; they remain shared language limitations. No WebSocket-only
workaround or alternate syntax is advertised.

## HTTP/2 follow-up

- [x] RFC 8441 settings, pseudo-headers, version and subprotocol validation.
- [x] Opaque H2-to-H2 duplex forwarding, pooled upstreams and ordinary admission.
- [x] Independent flow control, cancellation and half-close on multiplexed streams.
- [x] H2-to-H1 WebSocket handshake and transport translation, including verified TLS.
- [x] Per-stream message/connection/close callbacks, owned outputs and compression.
- [x] H1 GET Upgrade to H2 upstream translation, opaque/inspected and plaintext/TLS.

Ordinary request-body consumers remain outside CONNECT tunnel semantics and get
503. H1-downstream to H2-upstream bridging uses the same callbacks and pooled
stream transport, including TLS, handshake validation and independent cancellation.
See the [HTTP/2 transport guide](websocket-terminate.md#http2-transport).

## Evidence and remaining delivery checks

The HTTP/2 follow-up adds real-socket H2-to-H1/H2 sessions on epoll and io_uring,
with plaintext and verified TLS upstreams. Tests exercise source/JIT message
payload output and connection/onOpen helpers, required subprotocols, rejection
body framing, sibling-stream admission and cancellation. Stream-engine tests
cover messages larger than a flow-control window, input-credit return,
independent compression legs, owned dynamic output, acceptance/send completion,
Close metadata, truncated-frame EOF and allocation rollback. A dedicated native
wire harness links the production native loader without LLVM. It compiles through
rut-compile, removes the source before opening sockets, and runs the same 27 H2
WebSocket checks, including both backends, plaintext/TLS and both bridge directions.
The serving process checks that no LLVM image is loaded. Follow-up HTTP requests
observe Cache writes from onClose, verifying exactly-once execution and the close
code/wasClean facts after stream cancellation and clean Close handshakes.
Reverse-bridge real-socket tests cover coalesced pre-101 messages, actual FIN/TLS
close_notify after Close, two H1 clients sharing one H2 session, and malformed
Key/version, local admission denial, upstream subprotocol failure, absent settings
and opening deadlines. Capacity rejection checks that no CONNECT reaches the
upstream, existing tunnels continue, and shutdown releases concurrency slots and
configuration epochs. The full network test target also compiles the reduced
Loop fixtures, guarding against accidental bridge-template instantiation.

The latest HTTP/2 frame, connection and gRPC/WebSocket transport run passed
19 + 111 + 102 cases, plus the 27 native harness checks. The original three
runtime suites passed under ASan/UBSan with leak detection, and with JIT/WebSocket
disabled (feature cases skipped).

After synchronization with current main, the wire suite passed 462 cases with
no skips. Full frontend (1259 tests), JIT (603), native artifact (81), loader
(140) and RIR (80) regressions passed. Runtime and ASan/UBSan unit runs passed
bulk allocation (5/1556 checks), codec/inspection (12/2045), extension parsing/
rewrite (6/761), retirement (27/605), frame primitives (38/4185) and baseline
inspection (85/80159). Lifecycle tests passed; focused network/TLS checks passed
100 and 91 cases. Filter exclusions are not unavailable-backend evidence.

The WebSocket/JIT-disabled runtime and inspection baseline passed. Ordinary
runtime ELF dependency lists contained libc only. Affected files passed
formatting, and changed production lines were checked with clang-tidy. The
combined private native artifact ABI is 18, retaining current-main authentication
metadata and WebSocket lifecycle symbols. Final compiler cleanup passed the shared compiler regressions and focused native
wire checks. The PR must remain unmerged; publication status belongs to GitHub.
