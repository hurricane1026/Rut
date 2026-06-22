# WebSocket terminate mode — `.rut` frame handlers (Phase 4 design)

Status: **Designed** (not yet implemented). The runtime engine and route API exist and are
merged (#137/#139/#140); this document specifies the missing piece — the `.rut` **language
surface** that lets a program author per-message terminate logic instead of registering it
through the C++ `add_ws_terminate(...)` API.

Related: DESIGN.md §3.4.8 (passthrough/terminate runtime semantics),
`include/rut/runtime/ws_terminate.h` (engine), `route_table.h` (`add_ws_terminate`).

---

## 1. Scope

**In scope (this design):** the surface syntax, the `frame` programming object, the
verdict terminators (`forward` / `drop` / `close`), per-direction handling, and the
compilation path (parse → type-check → RIR → a new frame-handler JIT ABI → `add_ws_terminate`).

**Out of scope (later phases):** subprotocol negotiation, frame **injection** (emitting new
frames the peer never sent), terminate combined with `@throttle`, and frame-handler I/O
(`notify` / external state lookups from inside a frame handler).

**Already done (runtime, merged):**
- `ws_inspect` reassembles each message and calls a handler
  `WsFrameAction (*)(void* ctx, WsOpcode op, const u8* payload, u64 len)` returning
  `Forward` / `Drop` / `Close`.
- `add_ws_terminate(path, method, upstream_id, handler, max_message_size)` registers a
  terminate route carrying that handler pointer (`RouteConfig::ws_frame_handler`).
- Re-framing, UTF-8/close-code validation, response-authoritative arming, extension reject,
  fragmented-header reject, and a bidirectional **Close handshake** (a `close` verdict already
  emits a Close frame to both peers and tears down once both drain).

So Phase 4 is **entirely a front-end / codegen task**: teach the compiler to emit a
frame handler. No new core tunnel logic.

---

## 2. Why an imperative frame handler (not a declarative policy)

Surveyed the two reference programmable gateways:

- **APISIX** — WebSocket is opaque passthrough (`enable_websocket`); plugins act on the
  **handshake** (auth, `limit-conn`), never on individual frames. No per-frame programmability.
- **Kong** — the programmable benchmark: direction-aware phases (`ws_client_frame` /
  upstream equivalent), a frame PDK (`get_frame` / `set_frame_data` / drop / close / size
  cap), **and** declarative plugins layered on top (WebSocket Size Limit, WebSocket Validator).

Kong steers common needs (size, JSON-schema validation) into *declarative* plugins and keeps
the imperative PDK as an escape hatch — **because it runs Lua**: a dynamically-typed,
unbounded, GC'd plugin on the per-frame hot path can crash a worker, block the event loop, or
leak memory. Declarative is Kong's way of *not letting users program the frame path*.

That safety tax **does not apply to Rut**, and the three axes all point the same way:

| Axis | Lua / Kong | Rut |
|------|-----------|-----|
| **Safety** | user frame code can crash/block/leak → prefer declarative | strong types + bounded execution (no `while`/recursion/closures/FFI) + handler-local `var` → a frame handler **cannot** loop forever, escape its arena, or corrupt the shard. Bugs are *compile errors*. |
| **Performance** | interpreted per-frame → real overhead → prefer config | JIT-specialized: route constants (`maxSize`, schemas) fold into native code, dead branches are eliminated, the body inlines into the flat state machine. A generic C++ policy check is the *interpreter* path; the JIT handler is the *specialized* path — and both are dominated by the O(payload) unmask/copy/re-mask the engine already does, so the per-message indirect call is noise. |
| **Expressiveness** | imperative > declarative | same |

**Conclusion: for Rut, the imperative `frame` handler is the primary surface; declarative
kwargs (if any) are thin sugar that lowers to the same JIT path — not a safety or performance
necessity.** This inverts Kong's layering (imperative-as-core vs imperative-as-escape-hatch)
and turns Rut's strong typing + bounded execution into the product differentiator.

---

## 3. Surface syntax

A `websocket(<upstream>)` call with **no trailing block** is passthrough (today's behavior,
unchanged). A **trailing block** turns it into terminate mode — the block is the per-message
handler. Per DESIGN.md §3.6, the block is a *compile-time construct*, not a closure; the
current message is the implicit binding `frame`.

```swift
route "/ws" {
    websocket(chat, maxMessageSize: 64.KB) {
        // runs once per reassembled message, both directions
        guard frame.text else { return drop }                       // opcode filter
        guard frame.len <= 16.KB else { return close(.tooBig) }     // size → close 1009
        guard validate(frame.json, OrderSchema) else {              // schema → close 1007
            return close(.invalidData)
        }
        return forward
    }
}
```

Direction-aware (one handler, distinguished by `frame.fromClient`):

```swift
websocket(chat) {
    if frame.fromClient {
        guard frame.text else { return drop }      // only police client→upstream
    }
    return forward
}
```

Terse single-message form (sugar, optional — lowers to the same handler):

```swift
websocket(chat, frame: => frame.text ? forward : drop)
```

### `maxMessageSize`
Required-ish kwarg (defaults to a route/global cap). It bounds the reassembly buffer and is
enforced by the engine **before** the handler runs (an over-cap message is failed closed
without dispatch). `frame.len` inside the handler is the post-reassembly length, always
`<= maxMessageSize`.

---

## 4. The `frame` object

Read-only in v1 (verdict-only); see §6 for modify.

| Member | Type | Meaning |
|--------|------|---------|
| `frame.opcode` | `WsOpcode` (`.text` / `.binary` / control) | the message opcode |
| `frame.text` | `string?` | the payload as UTF-8 text **iff** it is a Text frame, else `nil` (engine already UTF-8-validates Text) |
| `frame.binary` | `bytes?` | the payload **iff** Binary, else `nil` |
| `frame.payload` | `bytes` | raw reassembled payload |
| `frame.len` | `ByteSize` | payload length |
| `frame.fromClient` | `bool` | direction: client→upstream (`true`) vs upstream→client (`false`) |
| `frame.json` | `Json?` | payload parsed as JSON (`nil` on parse failure) — *depends on a JSON builtin (see §8)* |

`frame.text` / `frame.binary` are typed accessors that double as opcode guards — the
`guard let s = frame.text else { ... }` idiom mirrors `req.body(User)`.

---

## 5. Verdicts

Every control-flow path through the handler must yield exactly one verdict (a handler that
falls off the end is a compile error, like an HTTP handler that never returns a `Response`).
A top-level implicit `forward` fallthrough is a possible ergonomic option (TBD §10).

| Verdict | Engine action (already implemented) |
|---------|-------------------------------------|
| `return forward` | re-serialize the message for the peer and send it on |
| `return drop` | silently discard (the peer never sees it) |
| `return close(code)` | emit a Close frame (status `code`) to **both** peers, drain, tear down — the merged bidirectional Close handshake |

`close` takes an optional RFC 6455 status code as a domain enum: `.normal` (1000),
`.tooBig` (1009), `.invalidData` (1007), `.policyViolation` (1008), … (default `.normal`).
Maps to the engine's close path, which already sends a coded Close to both sides.

---

## 6. Frame modify (Phase 4b — designed, gated)

Kong's `set_frame_data` (rewrite the in-flight frame before forwarding) is the natural next
capability and Rut's mutation idiom already exists for requests (`req.bodyRaw = newBody`). The
surface:

```swift
websocket(chat) {
    guard var s = frame.text else { return forward }
    frame.text = s.redact(re"\\b\\d{16}\\b")   // rewrite payload before forwarding
    return forward
}
```

Runtime requirement: today `ws_inspect` re-frames the **same** reassembled bytes. Modify means
the handler writes a (possibly shorter/longer) payload that the engine re-frames instead. The
engine already owns an output buffer per direction; modify routes the handler's output buffer
into the re-frame step. **Recommend landing inspect-only (verdicts) first, then modify as 4b**
— modify changes the engine's data path; verdicts do not.

Injection (emitting frames the peer never sent — heartbeats, fan-out) is explicitly **later**;
it needs the engine to interleave gateway-originated frames with the tunnel stream.

---

## 7. Compilation pipeline

The crux: a frame handler compiles to a **different, smaller** function than an HTTP handler.

```
HTTP handler ABI:   u64 (*)(void* conn, HandlerCtx*, const u8* req, u32 len, void* arena)
Frame handler ABI:  WsFrameAction (*)(void* ctx, WsOpcode op, const u8* payload, u64 len
                                      [, bool from_client])   ← +direction (small ABI bump)
```

No arena, no Response building, no async — the frame handler is a *pure verdict function*, so
its codegen is a **subset** of the existing handler codegen. Stages:

1. **Parse** — `websocket(<name>, <kwargs>) { <stmts> }` → a `WsTerminate` AST node carrying
   a frame-handler statement block. Bare `websocket(<name>)` stays the existing
   `ForwardUpstream` (passthrough).
2. **Type-check** — bind `frame` to a `Frame` type in the block's scope; allow only
   `forward` / `drop` / `close` terminators; require a verdict on every path; permit reads of
   `frame.*`, comparisons, `guard`/`if`/`match`, and pure builtins (regex, `validate`, `json`).
   Forbid I/O (`forward`, `wait`, `notify`, state mutation) in v1.
3. **RIR** — lower the verdict graph; map `frame.opcode/payload/len/fromClient` to the ABI
   args; `return <verdict>` → a `WsFrameAction` constant; constant-fold route kwargs.
4. **JIT codegen** — emit a function matching the frame-handler ABI; the route's
   `ws_frame_handler` pointer is its address.
5. **Route wiring** — emit `add_ws_terminate(path, method, upstream_id, <jit_ptr>, maxMsg)`
   instead of the passthrough forward; bare `websocket(x)` keeps emitting passthrough.

The route table is already shaped for this (`RouteConfig` holds both `jit::HandlerFn fn` and
`WsMessageHandlerFn ws_frame_handler`).

---

## 8. Dependencies / open runtime needs

- **Direction in the ABI** — `WsMessageHandlerFn` gains a `bool from_client` (or a richer
  `ctx`); the engine passes which leg it is on. Small, mechanical runtime change; required for
  `frame.fromClient`. (Without it, ship v1 *without* `fromClient` and add later.)
- **JSON builtin** — `frame.json` / `validate(_, Schema)` need a JSON value type + parser.
  Regex (`re"..."`, Vectorscan) already exists. If JSON isn't ready, ship `frame.text` +
  regex-based validation first and add `frame.json` when the JSON builtin lands.
- **Modify data path** (§6) — only for Phase 4b.

---

## 9. Slices (smallest-first, each its own PR)

| Slice | Layer | Deliverable | Size | Risk |
|-------|-------|-------------|------|------|
| **A** | parser | `websocket(){…}` block + kwargs → `WsTerminate` AST; bare form unchanged | S | low |
| **B** | type checker | `Frame` type + `frame.*` accessors + `forward`/`drop`/`close(code)` verdicts + exhaustiveness | M | med (new typed object + terminator rules) |
| **C** | RIR + JIT | frame-handler ABI emission (verdict function); map `frame.*`→args | M | **highest** (new handler kind through codegen) |
| **D** | compiler→runtime | emit `add_ws_terminate` with the JIT pointer; passthrough unchanged | S | low |
| **E** | tests | `.rut` fixtures compiled+JIT'd+run e2e over a socket (forward/drop/close, direction) | M | low |
| **4b** | runtime+lang | `frame.text =`/`frame.payload =` modify → engine re-frames handler output | M | med (touches engine data path) |

Recommended order: A → B → C → D → E (inspect-only v1), then direction ABI, then 4b modify.

---

## 10. Open decisions

1. **Implicit `forward` fallthrough?** Require an explicit verdict on every path (safer,
   matches "handlers must return a Response"), or default to `forward` when the block ends
   (terser, since most messages pass)? *Leaning: explicit, with `=> forward` sugar for the
   common one-liner.*
2. **`fromClient` in v1 or deferred?** It needs the small ABI bump (§8). *Leaning: include it
   — direction-awareness is core to the real use cases (Kong's size/schema plugins are
   per-direction).*
3. **Modify (§6) in Phase 4 or 4b?** *Leaning: 4b — keep v1 verdict-only so the engine data
   path is untouched.*
4. **Declarative sugar surface** — offer `maxMessageSize:` / `allow:` / `drop: re"..."`
   kwargs that lower to a generated handler, or none for v1? *Leaning: only `maxMessageSize:`
   (already a runtime field); defer other sugar until a real ergonomic need appears.*

---

## 11. Example programs (target syntax)

```swift
// Chat moderation: drop profanity client→upstream, pass everything else.
route "/chat" {
    websocket(chatBackend, maxMessageSize: 32.KB) {
        guard frame.fromClient else { return forward }
        guard let text = frame.text else { return drop }   // binary not allowed from clients
        guard not text.matches(re"(?i)\\b(badword|slur)\\b") else { return drop }
        return forward
    }
}

// API protection: every client message must be a valid Order JSON, else close 1007.
route "/orders/stream" {
    websocket(orderService, maxMessageSize: 64.KB) {
        if frame.fromClient {
            guard validate(frame.json, OrderSchema) else { return close(.invalidData) }
        }
        return forward
    }
}
```
