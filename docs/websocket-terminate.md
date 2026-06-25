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

### 1.1 v1 runtime constraints (inherited from in-place re-framing)

`ws_inspect` re-frames **in place** over one slice (the #140 design decision), which bounds
what a v1 frame handler can see. These are **hard limits of the merged runtime**, not
language choices — the design must stay inside them or call out the specific runtime change:

- **Single-frame messages only.** The tunnel arms the inspector with `reject_fragmented = true`
  (both directions), so a fragmented WebSocket message (`FIN=0` / continuation) **fails closed
  before the handler** — it does *not* run "once per reassembled message". The assembler can
  already reassemble fragments within the cap; what's missing is a separate per-direction
  **output** buffer (in-place re-frame overflows the final read), so this is **independent** of
  the size cap below (§8).
- **Max message ≈ one slice (~16 KB).** `ws_arm_terminate` clamps the cap to
  `SlicePool::kSliceSize - kWsMaxHeaderSize` (~16 KB); a larger `maxMessageSize` is silently
  clamped and an over-cap message fails closed. Lifting it needs **both** a multi-slice
  reassembly buffer **and a larger/streaming input path** — `ws_inspect` only acts once
  `avail >= header_len + payload_len`, and the callers feed it one slice-backed recv buffer, so
  an unfragmented 64 KB frame never becomes fully available to inspect (§8).
- **Text / Binary only.** The engine passes Ping/Pong/Close **through** before the handler
  path, so a frame handler is *never* invoked for control frames — `frame.opcode` is only
  `.text` or `.binary`.
- **`close` carries no status code today, and the two legs differ.** `WsMessageHandlerFn`
  returns only `WsFrameAction`, so the handler has no channel for a code. On a `Close` verdict,
  `ws_inspect` emits an **empty (no-status) Close** to the *forward* peer
  (`emit_frame(..., WsOpcode::Close, msg_buf, 0, ...)` — that peer sees **1005 No Status**),
  while the queued **echo** to the other peer uses `ws_emit_close_frame` (**1000**). So even
  bare `close` is not uniformly 1000. `close(code)` needs the code threaded through the handler
  return path **and** both emit sites (the `ws_inspect` forward Close *and* `ws_emit_close_frame`)
  — see §8.

### 1.2 What Phase 4 actually is

The **inspect-only verdict handler** — single-frame Text/Binary ≤ ~16 KB, returning
`forward` / `drop` / bare `close` (no status code — forward leg 1005, echo 1000; see §5) — is
a **pure front-end / codegen task**: no new
tunnel logic. Each richer capability (`close(code)`, `frame.fromClient`, >16 KB / fragmented
messages, modify) needs **one specific, small runtime change**, enumerated in §8 — they are
*not* free, and the design tags each one rather than implying "no core changes".

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
route GET "/ws" {
    websocket(chat, maxMessageSize: 8kb) {   // ≤ ~16 KB in v1 (one slice; see §1.1)
        // runs once per (single-frame) Text/Binary message, both directions
        guard let text = frame.text else { return drop }   // .text is error-capable: not-Text → drop
        guard frame.len <= 4096 else { return close }      // bytes (see frame.len note in §4)
        return forward
    }
}
```
(Route form: `route GET "/path" { … }` — a method is required. **Grammar note:** today main
parses only `return websocket(<ident>)` (no block); the *proposed* Slice A (PR #144, not yet
merged) adds the `return websocket(x) { … }` block form, where the terminator must be the
route's last statement. The bare `websocket(x) { … }` shown here is the target spelling,
pending the decision in §10.6.)

Direction-aware (one handler, distinguished by `frame.fromClient` — needs the §8 ABI bump):

```swift
websocket(chat) {
    if frame.fromClient {
        guard let _ = frame.text else { return drop }   // only police client→upstream
    }
    return forward
}
```

Opcode dispatch via `match` (the unambiguous form — `frame.opcode` is only `.text`/`.binary`):

```swift
websocket(chat) {
    match frame.opcode {
        .text   => return forward
        .binary => return drop      // this app is text-only
    }
}
```

Terse single-message form (sugar, optional — lowers to the same handler). Rut has no `? :`
ternary (`?` is reserved for nil checks), so the one-liner uses a `match` expression:

```swift
websocket(chat, frame: => match frame.opcode { .text => forward, .binary => drop })
```

### `maxMessageSize`
**Required in v1.** `add_ws_terminate` rejects `max_message_size == 0` and there is no
route/global WebSocket default for the compiler to fall back on, so omitting the kwarg would
lower to an unusable route. Slice D must therefore either require `maxMessageSize:` on every
terminate route or pass a fixed nonzero default (recommended: **the v1 cap, ~16 KB / one
slice**). It bounds the reassembly buffer and is enforced by the engine **before** the handler
runs (an over-cap message fails closed without dispatch). `frame.len` is the post-reassembly
length, always `<= maxMessageSize`. **v1 hard cap: ~16 KB** — the runtime clamps to one slice
(`SlicePool::kSliceSize - kWsMaxHeaderSize`); a larger value is silently clamped. Lifting the
cap is a runtime item (§8).

---

## 4. The `frame` object

Read-only in v1 (verdict-only); see §6 for modify. The handler is invoked **only for
single-frame Text or Binary messages** (§1.1) — control frames and fragmented messages never
reach it.

| Member | Type | Meaning |
|--------|------|---------|
| `frame.opcode` | `WsOpcode` — **only** `.text` / `.binary` | the message opcode (control frames never reach the handler) |
| `frame.text` | error-capable `string` | the payload as UTF-8 text; **errors if the frame is Binary** (engine already UTF-8-validates Text). Use with `guard let`. **Partly implemented:** the regex-match guard form `guard [not] frame.text.matches(re"…") else { … }` works today (content filtering) — it scans the message payload bytes via the existing Vectorscan `matches()` path and respects a leading `not` (the blocklist form). The `guard let text = frame.text` *binding* form is still pending. NOTE: like every `matches()`, it is **full-string** (the helper wraps `^(?:…)$`), so substring filters need `re".*X.*"`; and v1 scans the payload regardless of opcode, so pair with `guard frame.isText` for text-only. |
| `frame.binary` | error-capable `bytes` | the payload; **errors if the frame is Text** |
| `frame.payload` | `bytes` | raw reassembled payload (always valid) |
| `frame.len` | integer (bytes) | payload length (`<= maxMessageSize`). **v1 is a plain integer** so `frame.len <= 4096` parses with the existing expression grammar — `4kb` is *not* a valid expression literal today (the `IntLit + kb/mb` ByteSize form is special-cased for decorator/kwarg parsing, not general expressions). Typing it `ByteSize` + allowing `4kb` in handler expressions is a Slice B dependency (deferred). |
| `frame.fromClient` | `bool` | direction: client→upstream (`true`) vs upstream→client (`false`) — **implemented** (the `dir` slice, §9): the handler ABI carries a `bool from_client` param the engine sets per leg. Usable as a bare guard condition: `guard frame.fromClient else { … }` |
| `frame.json` | error-capable `Json` | payload parsed as JSON; errors on parse failure — *depends on a JSON builtin (§8)* |

`frame.text` / `frame.binary` / `frame.json` are **error-capable** (not optional), so they
compose with `guard let` exactly like `req.body(User)`: `guard let t = frame.text else { … }`
runs the `else` for a Binary frame. This deliberately matches DESIGN.md §3.3.7 — `guard`
handles the error/`nil` boundary; these accessors are error-capable so the guard idiom is
correct (an *optional* would need `frame.text?` / `match` instead — see decision §10.5).

---

## 5. Verdicts

Every control-flow path through the handler must yield exactly one verdict (a handler that
falls off the end is a compile error, like an HTTP handler that never returns a `Response`).
A top-level implicit `forward` fallthrough is a possible ergonomic option (TBD §10).

| Verdict | Engine action |
|---------|---------------|
| `return forward` | re-serialize the message for the peer and send it on — **implemented** |
| `return drop` | silently discard (the peer never sees it) — **implemented** |
| `return close` | emit a Close to **both** peers, drain, tear down — the merged bidirectional Close handshake — **implemented (see status note below)** |
| `return close(code)` | the same, with a chosen RFC 6455 status — **implemented** (the `code` slice) |

**`close(code)` now wires the status to the wire (both legs).** Rather than widen the JIT
return (which has no room for a 16-bit code), the code travels as a **per-connection
side-channel**: `frame.close(code)` is validated + stored in `HirWsHandler.close_code`,
`serve_loader` passes it to `add_ws_terminate`, the route's `ws_close_code` seeds **both**
`WsInspector`s' `close_code` at arm time, `ws_inspect` emits a 2-byte status body on the
*forward* leg and reports `echo_close_code` for the *echo* leg, which
`ws_drive_close` feeds to `ws_emit_close_frame`. A **peer-sent** Close is unchanged — its own
code is relayed verbatim on the forward leg and the echo stays 1000. This works for any Close
verdict (guard else or default); the frontend only lets the **default** verdict carry an
explicit code, so a guard's bare `close` uses the route's configured code (or 1000).

**Tiny-message fallback (forward leg only).** The forward Close is re-framed *in place* over
the recv buffer, whose capacity is bounded by the consumed input. A coded 2-byte Close is
larger than a 0/1-byte data frame, so when the status body won't fit, the forward leg falls
back to a **no-status Close** (which always fits — same header as the data frame it replaces).
The **echo leg uses a dedicated buffer and always carries the configured code**; only the
in-place forward leg degrades, and only for those 0/1-byte messages. Lifting this needs the
separate per-direction output buffer that modify/fragmentation also want (§8).

---

## 6. Frame modify (Phase 4b — designed, gated)

Kong's `set_frame_data` (rewrite the in-flight frame before forwarding) is the natural next
capability and Rut's mutation idiom already exists for requests (`req.bodyRaw = newBody`). The
surface:

```swift
websocket(chat) {
    guard let s = frame.text else { return forward }
    var redacted = s.redact(re"\b\d{16}\b")    // mutable local for the rewrite
    frame.text = redacted                       // rewrite payload before forwarding
    return forward
}
```

Runtime requirement (larger than "wire an existing buffer"): today `ws_inspect` re-frames the
message **in place over the recv buffer** — there is **no separate per-direction output slice**
(see `connection_base.h` / `callbacks_impl.h`: the in-place single-slice constraint). A
modified payload can be **longer** than the consumed input, so in-place output is unsound.
Modify therefore needs the runtime to **own bounded output storage per direction** (an output
slice, sized within the message cap) plus the **send-drain state** to flush it — not just
routing into a buffer that already exists. **Recommend landing inspect-only (verdicts) first,
then modify as 4b** — modify adds real buffer + data-path machinery; verdicts do not.

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
   `forward` / `drop` / bare `close` terminators (no `close(code)` in v1 — §5/§9); require a
   verdict on every path; permit reads of `frame.opcode/text/binary/payload/len`, comparisons,
   `guard`/`if`/`match`, and the regex builtin (`re"…"`, already exists). **`frame.json` /
   `validate(_, Schema)` are NOT in v1** — they need the JSON builtin (§8), scheduled after A–E.
   Forbid I/O (`wait`, `notify`, state mutation) in v1.
3. **RIR** — lower the verdict graph; map `frame.opcode/payload/len` to the ABI args
   (**not** `fromClient` — that arg only exists after the dir-slice ABI bump);
   `return <verdict>` → a `WsFrameAction` constant; constant-fold route kwargs.
4. **JIT codegen** — emit a function matching the frame-handler ABI; the route's
   `ws_frame_handler` pointer is its address.
5. **Route wiring** — emit `add_ws_terminate(path, method, upstream_id, <jit_ptr>, maxMsg)`
   instead of the passthrough forward; bare `websocket(x)` keeps emitting passthrough.
   **Caveat (Slice D is not a one-line swap):** `add_ws_terminate` registers a *direct Proxy*
   route with **no HTTP handler**, and the runtime only arms terminate for `RouteAction::Proxy
   && ws_terminate`. So any **pre-upgrade route logic** in the `.rut` body (auth, `guard`s,
   `@decorator`s before the `websocket` terminator) would be **dropped**. v1 must therefore
   either (a) **forbid** pre-upgrade statements on a terminate route (the `websocket` block is
   the whole body), or (b) add a **JIT-route arm path** that runs the route's handler and then
   enters terminate. *Recommend (a) for v1* — flagged as decision §10.7.

The route table is already shaped for this (`RouteConfig` holds both `jit::HandlerFn fn` and
`WsMessageHandlerFn ws_frame_handler`).

---

## 8. Dependencies / runtime work each capability needs

The inspect-only v1 (single-frame Text/Binary ≤ ~16 KB; `forward`/`drop`/bare-`close`) needs
**no runtime change**. Everything richer maps to one specific, small runtime item:

| Capability | Runtime work | Without it |
|------------|--------------|------------|
| `frame.fromClient` | ~~`WsMessageHandlerFn` gains a `bool from_client` (or richer `ctx`); engine passes the leg~~ — **DONE** (the typedef + JIT ABI gained `bool from_client`; `ws_arm_terminate` sets it `true` on `ws_c2u`, `false` on `ws_u2c`; `ws_inspect` passes `st.from_client`) | ~~ship v1 with no direction~~ |
| `close(code)` | ~~extend the handler return path to carry an RFC 6455 code~~ — **DONE** via a per-connection side-channel (route `ws_close_code` → both `WsInspector.close_code` → `ws_inspect` forward body + `echo_close_code` → `ws_emit_close_frame`), not a return-type change | ~~bare `close` only: forward 1005, echo 1000~~ |
| Fragmented messages (within the ~16 KB cap) | a **separate per-direction output buffer** — the assembler already reassembles fragments into its message buffer, but in-place re-framing can overflow the final read, which is why `reject_fragmented` is set; an output buffer (the *same* one modify needs) lifts it | fragmented messages fail closed before the handler |
| Messages > ~16 KB | a multi-slice reassembly buffer **and a larger/streaming input path** — `ws_inspect` waits for `avail >= header_len + payload_len` and the callers feed one slice-backed recv buffer, so a 64 KB *unfragmented* frame never becomes fully available; reassembly storage alone isn't enough (or require clients to fragment into slice-sized frames). *Independent* of the fragmentation/output-buffer work | `maxMessageSize` clamped to ~16 KB; larger messages fail closed |
| `frame.json` / `validate(_, Schema)` | a JSON value type + parser builtin (regex `re"…"`/Vectorscan already exists) | ship `frame.text` + regex-based validation first |
| `frame.text =` / modify (§6) | **add** a bounded per-direction output slice + send-drain state (none exists — re-frame is in-place; modified output can exceed the input) | verdict-only; no payload rewrite |

These are all *small and independent*; the recommended path lands the no-runtime-change v1
first, then adds direction + `close(code)` (both tiny). The **output buffer** (fragmentation +
modify) and the **multi-slice reassembly buffer** (>16 KB) are *separate* pieces — adding the
output buffer lifts `reject_fragmented` without touching the size cap, and vice versa.

---

## 9. Slices (smallest-first, each its own PR)

| Slice | Layer | Deliverable | Size | Risk |
|-------|-------|-------------|------|------|
| **A** | parser | `websocket(x){…}` block → `WsTerminate` AST; bare form unchanged. (PR #144 — kwargs deferred; `maxMessageSize:` is added with D and must parse via the existing `IntLit + kb/mb` ByteSize path, since `8kb` is two tokens, not a single literal) | S | low |
| **B** | type checker | `Frame` type + `frame.*` accessors + `forward`/`drop`/**bare `close`** verdicts + exhaustiveness. NO `close(code)` (needs the §8 runtime change) and NO `frame.fromClient` (needs the §8 ABI bump) in v1 | M | med (new typed object + terminator rules) |
| **C** | RIR + JIT | frame-handler ABI emission (verdict function); map `frame.opcode/payload/len`→args | M | **highest** (new handler kind through codegen) |
| **D** | compiler→runtime | emit `add_ws_terminate` with the JIT pointer (+ required `maxMessageSize`); passthrough unchanged | S | low |
| **E** | tests | `.rut` fixtures compiled+JIT'd+run e2e over a socket: forward / drop / bare close. **No direction** (it needs the ABI bump, which lands after E) | M | low |
| **dir** ✅ | runtime+lang | `WsMessageHandlerFn` direction-ABI bump + `frame.fromClient` + its e2e coverage — **DONE** (`from_client` param threaded through the typedef, JIT ABI param 4, and both tunnel legs; `frame.fromClient` guard in analyze/codegen; tests in test_ws_terminate / test_serve_loader / test_frontend) | S | low |
| **code** ✅ | runtime+lang | `close(code)` — **DONE** (per-connection side-channel: route `ws_close_code` → both inspectors → forward Close body + echo; peer-Close echo unchanged at 1000; tests in test_ws_terminate / test_serve_loader) | S | low |
| **4b** | runtime+lang | `frame.text =`/`frame.payload =` modify → new output slice + send-drain + re-frame from handler output | M | med (touches engine data path) |

Recommended order: **A → B → C → D → E** is the inspect-only v1 (single-frame, no direction,
bare `close`, no modify — *zero runtime change*). Then **dir** (direction ABI + `fromClient`),
**code** (`close(code)`), the **output buffer** (lifts fragmentation; shared with **4b** modify),
the **multi-slice reassembly buffer** (lifts the >16 KB cap, independent), and JSON — each its
own slice. Direction and `close(code)` are intentionally **out of A–E** because they need the
runtime changes A–E deliberately avoid.

---

## 10. Open decisions

1. **Implicit `forward` fallthrough?** Require an explicit verdict on every path (safer,
   matches "handlers must return a Response"), or default to `forward` when the block ends
   (terser, since most messages pass)? *Leaning: explicit, with `=> forward` sugar for the
   common one-liner.*
2. **`fromClient` in v1 or deferred?** ~~Deferred to the dedicated `dir` slice~~ — **RESOLVED /
   DONE.** The `dir` slice landed after E: the handler ABI gained a `bool from_client` param
   (kept distinct from the inspector's `masked` flag on purpose — masking is wire-format,
   direction is routing), and `guard frame.fromClient` is now a valid bare guard condition.
3. **Modify (§6) in Phase 4 or 4b?** *Leaning: 4b — keep v1 verdict-only so the engine data
   path is untouched.*
4. **Declarative sugar surface** — offer `maxMessageSize:` / `allow:` / `drop: re"..."`
   kwargs that lower to a generated handler, or none for v1? *Leaning: only `maxMessageSize:`
   (already a runtime field); defer other sugar until a real ergonomic need appears.*
5. **`frame.text`/`binary`/`json`: error-capable or optional?** This design makes them
   **error-capable** so `guard let t = frame.text else { … }` works per DESIGN.md §3.3.7
   (`guard` handles the error boundary, not `nil`). The alternative is to type them optional and
   require `frame.text?` / `match frame.opcode` at every site. *Leaning: error-capable — it
   keeps the guard idiom consistent with `req.body(User)`; confirm against the final optional
   semantics in DESIGN.md §3.3.7.*
6. **`return websocket(x) { … }` vs bare `websocket(x) { … }`?** The current parser requires
   `return` for terminators and they must be the route body's last statement, so the proposed
   Slice A (PR #144) uses the `return` form. The examples here use the bare form (matching
   DESIGN.md's `websocket { }` sketch), which reads cleaner — only the frame verdicts are
   `return`s, not the route terminator. *Leaning: decide before Slice B — either accept the
   nested-`return` form, or add a bare-`websocket`-statement terminator. Examples should track
   whichever wins.*
7. **Pre-upgrade route logic on a terminate route?** `add_ws_terminate` makes a direct Proxy
   route with no HTTP handler, so route-body statements before the `websocket` terminator
   (auth, `guard`s, `@decorator`s) would be dropped. *Leaning: forbid them in v1 — the
   `websocket(){}` block is the whole terminate route body — and add a JIT-route arm path later
   if pre-upgrade logic is needed (§7 Slice D caveat).*

---

## 11. Example programs (target syntax)

Sizes stay under the v1 ~16 KB cap (§1.1); `fromClient`, `close(code)`, and `frame.json`
are tagged with the §8 runtime item they need.

```swift
// Chat moderation: drop profanity client→upstream, pass everything else.
// (needs the direction slice for fromClient)
route GET "/chat" {
    websocket(chatBackend, maxMessageSize: 8kb) {
        guard frame.fromClient else { return forward }
        guard let text = frame.text else { return drop }   // .text errors for Binary → drop
        guard not text.matches(re"(?i)\b(badword|slur)\b") else { return drop }
        return forward
    }
}

// API protection: every client message must be valid Order JSON, else close.
// (needs the direction slice, JSON builtin, and the close(code) slice for the 1007 status)
route GET "/orders/stream" {
    websocket(orderService, maxMessageSize: 8kb) {
        if frame.fromClient {
            guard let order = frame.json else { return close(.invalidData) }  // 1007
            guard validate(order, OrderSchema) else { return close(.invalidData) }
        }
        return forward
    }
}

// Pure v1 (no runtime changes): text-only, size-bounded, bare close.
route GET "/echo" {
    websocket(echoBackend, maxMessageSize: 4kb) {
        guard let _ = frame.text else { return close }   // bare close (forward leg: 1005; echo: 1000)
        return forward
    }
}
```
