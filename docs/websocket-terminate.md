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

Graceful shutdown has a one-shot five-second deadline, measured at the timer
wheel's one-second resolution. It begins when a Close handshake or clean TCP EOF
drain starts; later I/O progress and repeated EOF events do not extend it.
Healthy quiet tunnels have no idle timeout. On expiry the runtime uses normal
connection retirement, preserving asynchronous I/O buffer ownership until
operations and cancellation completions retire; bytes that did not drain may be
discarded.

## Bounded JSON validation

`guard json.parse(message.text) != nil else { message.close(1007) }` rejects
messages whose payload fails the existing JSON parser. `== nil`, mirrored operand
order and logical conditions are supported. A JSON `null` document is valid and
is distinct from a parse failure.

Use an optional binding followed by a presence check to require a message field:

```swift
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard json.get(document, "/name") != nil else { message.close(1008, "name required") }
    message.forward()
}
```

Pointers are string literals with the ordinary RFC 6901 rules: `/a/0` selects
an array element, `~0` and `~1` escape tilde and slash, and `""` selects the root.
A present field with value `null` passes `!= nil`; a missing or invalid pointer
does not. Literal escapes, including embedded NUL, are supported. Mirrored
comparisons and short-circuit conditions work as for other message guards.

The document binding must use a fresh name and appears only after its guard.
Bindings count toward the four-guard limit. Each reached check reparses the
bounded complete payload; no parsed document or borrowed payload view is
retained between callbacks.

Unwrapped JSON values can also be decoded as strings for exact routing decisions:

```swift
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let field = json.get(document, "/type") else { message.close(1008) }
    guard let kind = json.string(field) else { message.close(1008) }
    guard kind == "subscribe" else { message.drop() }
    message.forward()
}
```

`json.string(document)` also checks a root JSON string. A `json.get` result must
be unwrapped before it can be passed to `json.string`; missing values, JSON null,
numbers, booleans, arrays and objects fail the string check. A string alias may
be compared with a literal using `==` or `!=` in either operand order, and
supports `.isEmpty`, `.hasPrefix("literal")`, `.hasSuffix("literal")`, and
`.contains("literal")`. Predicates compare the decoded JSON string bytes exactly;
escape forms decode before matching, and Unicode is not normalized. An empty
prefix, suffix, or contains needle matches every valid string. JSON type and
parse checks still run before an empty predicate can match.

Aliases are compile-time paths into the immutable message: each reached check
reparses the bounded payload and retains no JSON node or borrowed string view.
Only `json.get(document, literalPointer)` and `json.string(unwrappedValue)` are
supported in these handlers; nested `get`, general extraction, dynamic paths,
and dynamic predicate arguments remain unsupported. These bindings and
predicates use the existing four-guard and 32-condition-node limits.

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
