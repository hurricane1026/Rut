# WebSocket terminate mode — application messages

The DSL exposes complete WebSocket application messages. Wire frames belong to
`src/runtime/ws_frame.cc` and the terminate engine; they are not a language API.

## Surface

```swift
upstream chat at "127.0.0.1:9000"
route GET "/ws" {
    return websocket(chat, maxMessageSize: 4kb) { message in
        guard message.len <= 2048 else { message.close(1009, "message too large") }
        guard !message.fromClient || !message.isText || message.text != "blocked" else {
            message.drop()
        }
        message.forward()
    }
}
```

A bare `websocket(chat)` remains a transparent tunnel. The trailing block opts
into message inspection and its bounded buffering costs.

- `message.fromClient` identifies the sender: client or upstream.
- `message.isText` / `message.isBinary` select application message types.
- `message.len` is the complete payload length in bytes, excluding frame headers
  and masking keys. The limit applies across all fragments of one message.
- `message.text` supports the bounded predicates and rewrite recipes documented
  in [the language card](language-card.md). Current predicates compare payload
  bytes; add `message.isText` to restrict them to Text messages.
- `message.forward()` forwards one complete message. The runtime chooses its
  wire framing; original frame boundaries are not preserved.
- `message.forward(text)` replaces one complete message. Fixed literals and
  compile-time-known route-local strings may surround one `message.text` reference
  using String `+`. Replacement output must fit the message and single-slice limits.
- `message.drop()` discards the complete message.
- `message.close(code, "reason")` requests connection shutdown. The runtime emits
  and drains Close frames to both peers. It does not expose raw frame creation.

The binding is `{ message in ... }`. The former `{ frame in ... }` syntax and
`.opcode` comparisons are rejected. Use `isText` / `isBinary` for message types.
There is no public FIN, mask, continuation, Ping or Pong accessor.

## Bounded JSON validation

`guard json.parse(message.text) != nil else { message.close(1007) }` rejects
messages whose payload fails the existing JSON parser. `== nil`, mirrored operand
order and logical conditions are supported. A JSON `null` document is valid and
is distinct from a parse failure. The handler does not gain a bound `Json` value.

The parser limits remain 8 KiB input, 2048 nodes and depth 64; exceeding any limit
fails validation. Duplicate decoded object keys are rejected. For Text-only
validation, combine the condition with `message.isText`; ordinary payload text
predicates continue to operate on raw bytes. Validation happens after reassembly,
so fragmentation cannot turn a malformed complete JSON message into valid pieces.

## Runtime boundary

The engine unmasks and reassembles data frames before calling the message
handler. One complete Text/Binary message causes one call, independent of its
fragmentation. Text must pass UTF-8 validation before delivery. Partial reads,
fragment headers, protocol errors and resource bounds are handled by the engine.

Ping/Pong/Close frames bypass the application handler. Control frames may occur
between fragments without creating an application message. Protocol errors and
oversized messages fail the tunnel; user code cannot bypass these checks.

Inspection currently uses bounded single-slice storage (approximately 16 KB),
with separate per-direction output buffers. `maxMessageSize` cannot lift that
storage cap. Supporting larger messages requires a separate buffering design.

The native/JIT message handler ABI may continue using internal `WsOpcode` and
`WsFrameAction` values. They are implementation details, not DSL types. The
public rename does not change the native artifact layout.

## Verification

Frontend tests accept message predicates/actions and reject legacy frame bindings
and wire properties. Loader and native-artifact tests exercise those policies,
including retained constants after source removal. Runtime tests cover partial
reads, fragmented messages, interleaved control frames, output bounds and both
message directions. Network integration covers epoll and io_uring.
