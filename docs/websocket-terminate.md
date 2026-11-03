# WebSocket terminate mode — application messages

The DSL exposes complete WebSocket application messages. Wire frames belong to
`src/runtime/ws_frame.cc` and the terminate engine; they are not a language API.

## Surface

```swift
upstream chat at "127.0.0.1:9000"
route GET "/ws" {
    guard let origin = req.uniqueHeader("Origin") else { return 403 }
    guard origin == "https://allowed.example" else { return 403 }
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
into message inspection and its bounded buffering costs. Before the terminating
statement, the route can use the existing bounded HTTP guards for request
admission. These guards run before the JIT handler forwards to the WebSocket
upstream; a failed guard returns its static local response without connecting.
`guard let` bindings are available to later HTTP guards only and cannot be
captured by the message handler or its rewrite expressions.

This slice allows immutable compile-time `let` bindings and at most eight
top-level request guards before one final `websocket(...)` statement. Guard
conditions use existing request reads (`method`, `path`, `pathOnly`, headers,
query, cookies and route parameters), literals, prior bindings, comparisons,
boolean operators, and `.or(literal)`. Failure branches must return a static
status or response. Helpers, effects, request body reads, mutation, waits,
loops, conditionals, decorators and chains remain unsupported. The message
handler retains its independent four-guard limit.

The message callback receives a borrowed `WebSocketMessage`. Its Boolean
fields are `fromClient`, `isText` and `isBinary`; `len` is an `i32` byte count
and `text` is a borrowed `str` over the payload, including Binary payloads.
It is now possible to reuse ordinary pure helpers:

```swift
func accepted(_ text: str) -> bool => text.matches(re"allowed[0-9]+")
func permitted(_ msg: WebSocketMessage) -> bool =>
    !msg.fromClient || (msg.isText == true && msg.len <= 2048 && accepted(msg.text))

route GET "/checked-ws" {
    return websocket(chat) { message in
        guard permitted(message) else { message.drop() }
        message.forward()
    }
}
```

The same `accepted(str)` helper can be called from an ordinary HTTP route.
These message predicates use ordinary scalar type checking and helper inlining,
then lower to the bounded condition forest. Boolean literals and equality in
either operand order are supported, as are nested Boolean comparisons,
length/literal comparisons, text/literal equality and text regex matches.
An imported helper works through the normal import namespace. HTTP reads and
response effects cannot run inside a message predicate. The borrowed message
has no storage carrier outside its synchronous callback, and comparing entire
messages is rejected. Callback-local bindings, parameter renaming, general
arithmetic and close-event values remain subsequent work.

`message.kind` has type `WebSocketMessageKind`, whose cases are
`WebSocketMessageKind.text` and `WebSocketMessageKind.binary`. `message.direction`
has type `WebSocketDirection`, with cases `WebSocketDirection.clientToUpstream`
and `WebSocketDirection.upstreamToClient`. Both types support equality and
generic `Eq`, including comparisons in either operand order. They cannot be
mixed with one another, ordered, or implicitly converted to Bool, integers or
strings. Case references currently use the fully qualified names above.
Neither type exposes wire opcodes or control-frame cases. The existing Boolean
properties retain their behavior.

These are ordinary types for helper signatures and HTTP-local values, rather
than selectors recognized only in a message guard:

```swift
func isTextKind(_ kind: WebSocketMessageKind) -> bool =>
    kind == WebSocketMessageKind.text
func fromClient(_ direction: WebSocketDirection) -> bool =>
    direction == WebSocketDirection.clientToUpstream
// Within the message callback:
// guard !fromClient(message.direction) || isTextKind(message.kind) else { message.drop() }
```

The domains carry case identity; they do not borrow payload memory. A generic
identity helper can also return the borrowed `WebSocketMessage` within the same
synchronous callback. Closed-case exhaustive matching and contextual `.case`
inference are not introduced by these typed equality projections.

After the route's HTTP guards pass, terminate mode validates the opening request
before connecting to the selected upstream. The supported request shape is GET
over HTTP/1.1 with exactly one non-empty Host, a `Connection` list containing the
exact `Upgrade` token, an `Upgrade` list containing a bare exact `websocket` token
(other valid `protocol-name[/protocol-version]` offers may coexist),
one canonical standard Base64 `Sec-WebSocket-Key` encoding 16 bytes, and exactly
one `Sec-WebSocket-Version: 13`. Key edge OWS is trimmed; internal whitespace,
URL-safe Base64 and noncanonical padding are rejected. At most one
`Content-Length: 0` is accepted; positive or duplicate Content-Length,
Transfer-Encoding, `TE`, and `Expect` are rejected. These checks do not impose a
DNS/authority grammar on Host. A missing, malformed or duplicate required field
returns 400 and closes the client connection. A decimal Version from 0 through
255 without leading zeroes is syntactically valid; one other than 13, when the
rest of the request is valid, returns 426 with `Upgrade: websocket`, an
`Upgrade` Connection option, `Sec-WebSocket-Version: 13`, and close semantics.
Missing, duplicate, nonnumeric, out-of-range, or leading-zero Version returns
400. Internal crypto or temporary-slice allocation failure returns 503. Any
coalesced bytes after the parsed header remain WebSocket stream data.

Request `Sec-WebSocket-Protocol` fields may repeat and their comma-separated
tokens are combined. Tokens must be nonempty ASCII `tchar` values and unique with
case-sensitive comparison. Before sending a backend 101 to the client, terminate
mode requires one matching `Sec-WebSocket-Accept`, computed from the request key,
and validates a selected protocol: it may be absent, but if present must be one
single offered token. Response Upgrade must select exactly one
`Upgrade: websocket` field, Connection must contain an exact `Upgrade` list item,
and the header block must be complete and untruncated. A nonempty
`Sec-WebSocket-Extensions` response is rejected because terminate mode does not
negotiate extensions. A non-101 response follows ordinary HTTP forwarding.
These terminate-only checks do not make the engine a full RFC 6455
implementation; Origin remains explicit application policy. A failed backend
101 closes before any 101 bytes are sent; the runtime does not synthesize a 502
or WebSocket Close frame. Bare passthrough routes retain generic Upgrade
tunneling.

### Required subprotocol

Terminate routes can require one fixed subprotocol using a string literal:

```swift
return websocket(chat, subprotocol: "graphql-transport-ws", maxMessageSize: 4kb) { message in
    message.forward()
}
```

The value must decode to one nonempty ASCII HTTP token. It is case-sensitive;
whitespace, comma lists, slash, control bytes, and non-ASCII characters are
rejected at compile time. `subprotocol` and `maxMessageSize` may appear in either
order, once each. The option requires a message-handler block.

After HTTP admission guards, the client must offer the required token. Missing
or mismatched offers return 400 and close without connecting upstream. The gateway
replaces all request protocol fields with one field containing only the required
token, preserving any coalesced first message. A backend 101 must select that exact
token; omission, another token, lists, or duplicate selection fields close before
any 101 bytes reach the client. Non-101 responses retain ordinary HTTP behavior.
Omitting the option retains optional negotiation from the client's validated offers.

The policy uses route-owned storage pinned across asynchronous handshake I/O.
Native artifacts retain and relocate the same bytes; native format 15 requires
matching compiler and serving binaries.

## Application messages

- `message.fromClient` identifies the sender: client or upstream.
- `message.isText` / `message.isBinary` select application message types.
- `message.len` is the complete payload length in bytes, excluding frame headers
  and masking keys. The limit applies across all fragments of one message.
- `maxMessageSize` defaults to 16370 bytes (16 KiB slice capacity minus the
  maximum 14-byte WebSocket header). Explicit values from `1b` through `16370b`
  are accepted. Larger values such as `16kb` or `64kb` are rejected; larger-message
  buffering is not implemented.
- `message.text` supports the bounded predicates and rewrite recipes documented
  in [the language card](language-card.md). Current predicates compare payload
  bytes; add `message.isText` to restrict them to Text messages.
- `message.forward()` forwards one complete message. The runtime chooses its
  wire framing; original frame boundaries are not preserved.
- `message.forward(text)` replaces one complete message. Fixed literals and
  compile-time-known route-local strings may surround one `message.text` reference
  using String `+`. Replacement output must fit the message and single-slice limits.
  The same affix form may use one previously unwrapped `json.string` alias as its
  dynamic source; this produces a Text message even when the input was Binary.
- `message.forward(b"\x00\xff")` replaces one complete Text or Binary message
  with Binary. One exact-byte literal is allowed, including an empty payload or
  invalid UTF-8. It must fit both the existing 4096-byte decoded byte-literal cap
  and `maxMessageSize`. The `b` must touch the opening quote; NUL is `\x00`.
  Escapes are `\n`, `\r`, `\t`, `\\`, `\"` and `\xHH`. Concatenation, variables,
  Unicode escapes and interpolation are unsupported. Guard branches can mix
  Binary replacements, Text replacements and bare forwarding. Invalid Text input
  still fails before the handler. Route-owned bytes survive source removal and
  native relocation without enlarging connection state or reserving more slices.
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

A guard-unwrapped `json.string` alias also supports `.matches(re"pattern")`,
using the existing regular expression engine and whole-value matching:

```swift
guard let document = json.parse(message.text) else { message.close(1007) }
guard let field = json.get(document, "/topic") else { message.close(1008) }
guard let topic = json.string(field) else { message.close(1003) }
guard !topic.matches(re"private[.][0-9]+") else { message.drop() }
message.forward()
```

Matching uses decoded UTF-8 bytes, so `"topic\u002e12"` and `"topic.12"`
have the same subject. Embedded NUL is preserved; use the ordinary regex escape
`\x00` to match it. `!`, `&&` and `||` retain short-circuit semantics. Patterns
must be regex literals and receive the existing compile-time validation. Optional
extraction calls, Json values, `numberText`, `stringify` and other scalar aliases
do not support this operation.

The runtime decodes into its existing per-thread JSON workspace and scans during
that synchronous callback. No decoded view escapes to asynchronous I/O. Patterns
use the existing owned regex databases and scratch cache, including in native
artifacts after source removal. A reached decode or scan error closes the tunnel
before negation is applied; an error cannot become a successful negated match.
The four-guard and 32-condition-node limits remain unchanged.

Aliases are compile-time paths into the immutable message: each reached check
reparses the bounded payload and retains no JSON node or borrowed string view.
A `json.get` source may be the document or an earlier guard-unwrapped selected
JSON value. Further `get` calls use literal RFC 6901 pointers relative to that
value; each selection requires its own guard. General extraction, dynamic paths,
and dynamic predicate arguments remain unsupported. These bindings and
predicates use the existing four-guard and 32-condition-node limits.

For example, select a nested name in two steps and forward its decoded text:

```swift
guard let document = json.parse(message.text) else { message.close(1007) }
guard let payload = json.get(document, "/payload") else { message.close(1008) }
guard let field = json.get(payload, "/name") else { message.close(1008) }
guard let name = json.string(field) else { message.close(1003) }
message.forward("hello " + name)
```

Presence conditions such as `json.get(payload, "/name") != nil` use the same
relative lookup, including mirrored comparisons and logical conditions. An empty
pointer selects the source value itself, including JSON null. Escaped tokens,
array indices and embedded NUL retain the ordinary pointer semantics; invalid
pointers and missing children fail the reached guard. Decoded String, Bool, Int
and other typed aliases cannot be used as JSON containers. The binding being
declared is unavailable in its own failure branch.

The compiler folds each selection chain into an immutable root-relative pointer,
with at most 8192 combined decoded pointer bytes. Runtime callbacks still reparse
the complete bounded message and retain no selected node or borrowed view between
calls. The existing four source guards and 32 condition nodes remain the limit;
no native format or handler ABI change is required.

### Direct optional scalar comparisons

`json.string(value)`, `json.bool(value)` and `json.int(value)` can appear directly
in message guard comparisons. The argument must be a previously validated document
or a guard-unwrapped selected Json value. Use `==` or `!=` with a literal of the
matching type, or with `nil`; either operand order and the existing `!`, `&&`, `||`
condition forms are supported. This avoids a separate typed-binding guard:

```swift
guard let document = json.parse(message.text) else { message.close(1007) }
guard let payload = json.get(document, "/payload") else { message.close(1008) }
guard let field = json.get(payload, "/enabled") else { message.close(1008) }
guard json.bool(field) == false else { message.drop() }
message.forward()
```

A failed extraction is nil. Thus `json.bool(field) == false` matches only a JSON
Boolean false; JSON null and other kinds do not match. `json.bool(field) != false`
also matches nil, as ordinary optional inequality does. `json.string(field) != nil`
checks the JSON kind without retaining a decoded string. `json.int(field) == 42`
compares only exact signed 64-bit integer tokens; fractional/exponent forms and
overflow yield nil. Earlier parse and field-presence guards still run first.

String literals use the same escape decoding and byte comparisons as typed
string aliases. Integer literals must fit signed i64. Calls cannot be compared to
other calls, variables, or mismatched literals, and direct optional integer
ordering (`<`, `<=`, `>`, `>=`) remains unsupported. Unwrap an Int alias for
ordering, or a String alias for string predicates and forwarding. Bare optional
Bool calls and `!json.bool(value)` are rejected. All direct comparisons reuse
existing guard accessors, condition-node limits, runtime workspaces and native
helper symbols; they do not materialize values or change the native format.

A successfully unwrapped string alias may also be the sole dynamic source of a
`message.forward(...)` replacement, with fixed UTF-8 literals or route constants
as prefix and suffix:

```swift
guard let name = json.string(field) else { message.drop() }
message.forward("<" + name + ">")
```

Only aliases introduced by an earlier successful guard are visible. The
replacement reparses the complete message and decodes the selected string during
the synchronous callback, then copies the result and affixes into the direction's
owned output slice. Decoder workspace and borrowed string views do not cross the
callback or remain live during asynchronous sends. A valid JSON string from either
a Text or Binary input is emitted as a Text message; parse, lookup, type, decoding,
UTF-8, and output-size failures fail closed.

`json.numberText(documentOrField)` binds only JSON numbers and preserves their exact
source lexeme. `-0`, `1.2300e+999`, and integers larger than `i64` remain unchanged.
The typed alias supports literal string equality/inequality and the existing
`isEmpty`, `hasPrefix`, `hasSuffix`, and `contains` predicates, but no numeric
comparisons or arithmetic. It may be the sole dynamic source in the same fixed
affix rewrite. The runtime copies the raw number token into the owned output slice
during the synchronous callback; Text and Binary JSON inputs both produce Text.
Missing/non-number values, parser-limit failures, and output overflow fail closed.

`json.stringify(documentOrField)` binds the compact serialization of any JSON value
using the ordinary JSON writer. Strings and object keys are escaped as JSON text;
object member order and number lexemes are preserved. The alias supports literal string comparisons and the `isEmpty`, `hasPrefix`,
`hasSuffix` and `contains` predicates, and can be the sole dynamic source in a
fixed-affix rewrite. Serialization is bounded by the existing writer capacity, and
the result is copied to owned output before asynchronous sending.

JSON booleans can be unwrapped with `guard let enabled = json.bool(field) ...`;
`json.bool(document)` checks a root Boolean. Both `true` and `false` are successful
bindings, while missing fields, JSON null, and other JSON kinds fail. A Bool alias
supports bare truth, `!`, short-circuit `&&`/`||`, and `==`/`!=` with a Bool
literal in either operand order. A comparison leaf accepts only the bare alias
and one Bool literal. Each reached condition reparses the complete bounded
message and shares the existing per-thread workspace.

JSON integers can be unwrapped with `json.int(field)` or from a root with
`json.int(document)`. Only exact signed 64-bit integer tokens are accepted;
fractional and exponent notation, overflow, and non-number JSON kinds fail the
binding. Integer aliases compare with Int literals using all six comparisons
(`==`, `!=`, `<`, `<=`, `>`, `>=`) in either operand order, including under
`!`, `&&`, and `||`. Leaves are restricted to one bare alias and one literal;
arithmetic and alias-to-alias comparisons are unsupported. The signed 64-bit
comparison bound is separate from the existing `u32` message and opcode bound.

JSON structure checks can bind a kind label with `json.kind(documentOrField)`
or a direct container size with `json.count(documentOrField)`. Kind aliases use
the fixed lowercase labels `null`, `boolean`, `number`, `string`, `array`, and
`object`; null is a valid kind, and equality with another literal label is false.
Only `==`/`!=` against string literals are supported for kind aliases. Count accepts
only arrays and objects, including empty containers with count zero, and counts
only their immediate elements or members. Its comparison literals must fit
signed i32. Both aliases support the existing logical condition forms; other
extraction, arithmetic, and alias-to-alias comparisons remain unsupported.
Because parse, optional path presence, typed binding, and comparison each use a
source guard, a selected-field chain leaves room for either a kind policy or a
count policy under the four-guard limit. A root document can bind both kind and
count and combine their predicates within that limit because it needs no `get`
presence guard. Every reached check reparses the bounded full message in the
shared thread-local JSON workspace.

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

Inspection currently uses bounded single-slice storage (16370 bytes),
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
