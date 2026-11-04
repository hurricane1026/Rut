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
- [ ] Ordinary HTTP admission without a separate expression whitelist, with zero
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
single-slice limit remains. General JSON/regex/error helper integration and
string interpolation still need separate work; the broad criteria above remain
open until those semantics and the remaining protocol resources are verified.
