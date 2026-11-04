# WebSocket terminate mode — application messages

WebSocket is an HTTP/1.1-upgraded protocol with borrowed message, connection and
close concepts. Its callbacks use the ordinary expression/helper type checker
and shared MIR/RIR backend. Frames, masking keys and fragmentation boundaries
are runtime details, not DSL properties. HTTP/2 Extended CONNECT is outside this
implementation scope.

## Surface and HTTP admission

```swift
upstream chat at "127.0.0.1:9000"
func allowed(_ text: str) -> bool => text.hasPrefix("ok:")
route GET "/ws" {
    guard let origin = req.uniqueHeader("Origin") else { return 403 }
    guard origin == "https://allowed.example" else { return 403 }
    return websocket(chat, maxMessageSize: 4kb) { message in
        guard !message.fromClient || allowed(message.text) else { message.drop() }
        message.forward()
    }
}
```

Bare `websocket(chat)` keeps opaque passthrough behavior. A trailing message body
opts into terminate mode. One final top-level terminating statement owns the
post-upgrade callbacks; nested callback declarations are rejected.

Before upgrade, the route runs the ordinary HTTP admission pipeline: request
bindings, helpers, JSON/regex operations, mutations, decorators and `chain before`
retain their normal typing, evaluation and limits. Rejection returns its local
HTTP response before opening the WebSocket upstream. `chain after` response
header effects apply to rejection and accepted upstream responses, including 101,
with the ordinary HTTP wait/for restrictions. Handshake-critical headers cannot
be rewritten into an invalid accepted handshake.

HTTP request views cannot be captured by a post-upgrade callback. Proven scalar,
String and Bytes constants can cross the boundary. Request/Response access and
HTTP yielding operations are unavailable after upgrade, including in unreachable
branches or through helpers.

## Message and connection concepts

| Concept | Fields |
| --- | --- |
| `WebSocketMessage` | `payload: Bytes`, `text: str`, `len: i32`, `isText: bool`, `isBinary: bool`, `fromClient: bool`, `kind`, `direction`, `connection` |
| `WebSocketConnection` | `remoteAddr: IP`, `remotePort: i32`, `isTls: bool`, `subprotocol: str` |
| `WebSocketClose` | `code: i32`, `reason: str`, `upstreamCode: i32`, `upstreamReason: str`, `wasClean: bool`, `connection` |

`kind` is `WebSocketMessageKind` (`.text`, `.binary`); `direction` is
`WebSocketDirection` (`.clientToUpstream`, `.upstreamToClient`). These closed domains
use ordinary matching, contextual case names and coverage checking. They cannot
be confused with wire opcodes or arbitrary integers.

A message is one complete reassembled, decoded Text or Binary payload. `text`
is a byte view even for Binary input; Binary does not imply UTF-8. `payload`
preserves arbitrary bytes, including empty payloads and NUL. Received Text is
validated as UTF-8 before application dispatch. Ping/Pong and Close bypass the
message callback.

Connection facts describe the downstream client in both message directions. The
port is in host order. `subprotocol` reports the actual selected token, including
optional peer selection when the route did not require one; it is empty if none
was selected. Its owned accepted-header storage survives for the session.

Whole message/connection/close objects are borrowed only for their synchronous
invocation. Immutable aliases, optional bindings and helper parameters can project
them. They cannot be compared as whole objects, published, stored in Cache or
retained across callbacks. Output views are copied before asynchronous I/O.

## Ordinary expression and helper semantics

Callbacks share ordinary supported scalar arithmetic/bitwise operations, String
comparisons and construction, generic constraints, nominal matches, local lets,
guards, `if`/`else`, `if let`, optional/error recovery and helper evaluation.
The selected branch runs; Boolean operations short-circuit. A reached lexical
initializer and each actual argument run once even when unused or read repeatedly.
Missing values preserve their nil/error carrier; false, zero and empty successful
values remain present. Named-error `guard match` keeps HTTP's final-wildcard rule.

String `+`, `.isEmpty`, `.hasPrefix`, `.hasSuffix` and `.contains` compare bounded
bytes and support embedded NUL. `matches(re"...")` uses the existing Vectorscan
full-match backend. Scan/resource failure is retained independently of Boolean
negation and closes before publishing an application result. No secondary regex
engine is introduced.

The ordinary JSON API is available: parsing, dynamic pointer/field selection,
scalar extraction, exact number text, compact serialization, edits, constructed
values and concrete struct decoding. Locals retain their values across subsequent
JSON operations. JSON has its existing 8 KiB input, 2048-node and depth-64 limits;
these are separate from the WebSocket message limit.

```swift
func reply(_ input: str) -> str {
    guard let root = json.parse(input) else { nil }
    guard let name = json.string(root) else { nil }
    "hello:" + name
}
// Inside a message callback:
// if let text = reply(message.text) { message.forward(text) }
// else { message.drop() }
```

Digest/HMAC helpers, supported optional resource producers and ordinary String
helpers can feed dynamic output. `uuid()` keeps the ordinary direct-let contract:
bind its optional result, then unwrap it before use.

`Cache<IP, i64>` reads and bare writes can use `message.connection.remoteAddr`.
A write runs at its reached statement, including inside a selected branch after
guards. Cache remains lossy per-shard state, not durable session storage. Compiled
access retains declaration identity through registry reorder/removal. Counter
locals keep inferred types; explicit user `i64` annotations remain unavailable.
`time.nowMicros()` uses one invocation's clock latch and samples again for the
next callback.

Specialized literal/JSON recipes remain an optimization with four source clauses
and a 32-node condition forest. General expressions use the shared compiler and
ordinary source/local limits instead. Those recipe bounds do not cap a general
callback. General source interpolation, mutable local syntax, byte slicing and
concatenation, and non-response statement effects inside helpers are not added by
this protocol integration. Unsupported ordinary helper syntax remains a compile
error; there is no WebSocket-only alternate meaning.

## Actions and owned output

Every message path ends with one verdict:

| Action | Result |
| --- | --- |
| `message.forward()` | Preserve complete payload and Text/Binary kind |
| `message.forward(text)` | Send a bounded UTF-8 String as Text |
| `message.forward(bytes)` | Send a bounded Bytes value as Binary |
| `message.drop()` | Discard this complete application message |
| `message.close()` | Start closing with status 1000 |
| `message.close(code)` / `message.close(code, reason)` | Start closing with plain runtime arguments |

Dynamic Bytes can come from the payload, literals, aliases, optional bindings or
ordinary helper results; bare forward preserves the input kind. Text is validated
at publication. Runtime invalid Text closes with 1007, oversized output with 1009,
and invalid close arguments with 1002. A reason is at most 123 UTF-8 bytes, with a
valid wire status. Known invalid constants fail compilation.

Output is copied into separate connection-owned storage before returning from the
callback. Close reasons have separate owned drain storage. Another message cannot
reuse output or callback scratch until its send allows progress. io_uring retains
asynchronous output through both target and cancel retirement, in either order.
No message-time process heap allocation is introduced.

`maxMessageSize` accepts 1 through 262130 bytes; the default is 16370. It bounds
complete decoded input and rewritten output. Large routes atomically acquire four
existing 256 KiB bulk message/output buffers, without silently lowering the limit.
Both Linux backends stream ordinary I/O slices into complete-message storage.

## Opening handshake and subprotocol

Terminate admission requires GET over HTTP/1.1, exactly one nonempty Host, an
exact Connection Upgrade token, an Upgrade offer containing bare `websocket`, one
canonical Base64 key encoding 16 bytes, and one WebSocket Version. One
`Content-Length: 0` is allowed; positive/duplicate Content-Length,
Transfer-Encoding, TE and Expect fail with 400. A canonical decimal Version from
0 through 255 other than 13 receives 426 with Upgrade/Connection and
Sec-WebSocket-Version 13. Malformed versions receive 400. Origin remains explicit
application policy.

Repeated/comma-separated subprotocol offers form unique case-sensitive HTTP
tokens. The optional `subprotocol: "chat"` argument requires that offer before
upstream connect, restricts the upstream offer to it, and requires the backend to
select it. Without that argument, a backend may select one offered token or none.

Before publishing 101, the runtime checks the matching Accept, complete header,
exact Upgrade/Connection, selected subprotocol and extension agreement. A failed
backend handshake closes before any accepted 101 bytes escape. Non-101 responses
follow ordinary HTTP forwarding. Coalesced first-frame bytes are retained without
being inspected or forwarded before the handshake is accepted.

## Per-message compression

Terminate mode negotiates RFC 7692 `permessage-deflate` independently with the
client and upstream. It translates between compressed and uncompressed legs.
No DSL option or keyword is required. Bare passthrough keeps opaque extensions.

The client receives a selection from its own offers, never the upstream
agreement. Repeated fields, alternatives and quoted parameters use bounded HTTP
grammar. Unsupported offers can be declined; malformed grammar fails admission.
The upstream receives the gateway's canonical offer:
`permessage-deflate; client_no_context_takeover; client_max_window_bits`.
Its actual response controls receive window/history behavior. Windows 8 through
15 are supported. Outgoing compressors reset per message; received history is
retained unless that leg agreed to no context takeover, even for dropped messages.

Compressed wire input has a separate work budget of `max + max / 8 + 1024` bytes
per message. RSV1 is valid only on negotiated initial data frames, never controls
or continuations. Ping/Pong can interleave compressed fragments. Output is
compressed when smaller and within owned output bounds; incompressible output
keeps its uncompressed frame and full message limit. Partial/invalid decoded
messages cannot reach the application.

Each negotiated leg atomically reserves one existing 256 KiB bulk slice for its
encoder/decoder before sending 101. Large routes additionally require their four
data/output buffers. Pool exhaustion fails admission without smaller-limit
fallback. CPU codecs retire at teardown; asynchronous output retains its normal
send/cancel ownership. The codec is a private pinned static C zlib build with a
pool-backed allocator and no process heap or system zlib link.

## Lifecycle and closing

```swift
return websocket(chat) { message in
    message.forward()
} onOpen: { connection in
    guard connection.remotePort > 0 else { connection.close(1008, "peer port") }
} onClose: { closed in
    let status = closed.code
    let remote: IP = closed.connection.remoteAddr
}
```

Open runs after the accepted 101 has drained and resources exist, before buffered
messages. It may initiate bounded closing but cannot forward data. Close runs
once for an opened session before config/TLS/resource teardown, including on I/O
failure, protocol error or timeout; it cannot reopen closing. Failed admission or
opening produces neither event. Bare return ends a hook; implicit fallthrough is
void. Normal local/helper/optional/error/match/Cache/time semantics apply.

Close context retains each leg's first valid peer status/reason independently of
local policy. Empty Close is 1005; no received Close is 1006. `wasClean` requires
both completed WebSocket handshakes. Reply frames preserve peer payloads,
including an empty body.

Each leg independently waits for its valid Close acknowledgement. Closing handles
Ping/Pong locally and discards bounded application framing without invoking the
decoder or message callback. One fixed approximately five-second deadline bounds
closing/EOF drain; progress cannot extend it. A healthy quiet session has no idle
timeout. TCP EOF stops new application input and drains owned output. TLS flushes
local close_notify before downstream FIN and keeps the opposite leg independent.

## Verification

Frontend, RIR, JIT, loader and source-removed native tests exercise the shared
concept semantics, ownership transfers and phase errors. Runtime tests cover
framing, compressed history, malformed input, UTF-8, bounds, allocation rollback,
backpressure, failure, cancellation, closing and slot reuse. The Python wire suite
covers source/native, epoll/io_uring and TLS, including independent compression
agreements and maximum first frames coalesced with 101. Feature-disabled builds,
ASan/UBSan and ordinary libc-only ELF checks supplement these tests. These are
bounded executable checks, not a claim of exhaustive RFC conformance or HTTP/2
support.
