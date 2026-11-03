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
handler retains its independent four-clause limit.

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
messages is rejected. General arithmetic and close-event values remain
subsequent work.

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

### Borrowed payload bytes

`message.payload` is a `Bytes` view over the complete reassembled payload for
either Text or Binary messages. `.count` reports bytes as `i32`; `.isEmpty`
is a Boolean property. Text payloads expose their encoded UTF-8 bytes, while
Binary payloads may contain arbitrary octets. Reading the view does not copy
or decode the payload. The view is valid only within the synchronous callback
and its inlined helper calls. `message.text` retains its existing raw-string
behavior, and `forward()` preserves the original message kind.

```swift
func same<T: Eq>(_ a: T, _ b: T) -> bool => a == b
func isMarker(_ bytes: Bytes) -> bool =>
    !bytes.isEmpty && bytes.count == 2 && same(bytes, b"\x00\xff")
// In the callback:
// guard !message.fromClient || isMarker(message.payload) else { message.drop() }
```

`Bytes` is a common language type: ordinary HTTP locals and helper return values
can also hold byte literals or select between them at runtime. HTTP's
`req.bodyBytes` supplies the real request body to the same Bytes helper, reusing
`req.body`'s complete-body buffering, limits and request-scoped lifetime.
Imported helpers retain their literal bytes after the imported AST disappears. Literals reuse
the existing binary escape rules and 4096-byte decoded limit; the message view
still spans the full single-slice payload, up to 16370 bytes. Equality/inequality
and generic `Eq` compare exact bytes in either operand order. Comparisons with
`str`, implicit conversions, regex scans, ordering, concatenation and indexing
are unsupported. Payload inspections currently lower literal equality, view
reflexivity, count/literal comparisons and emptiness into the bounded condition
forest. Dynamic payload replacement remains subsequent work.

### Callback names and immutable bindings

The trailing block accepts an ordinary identifier, such as `{ packet in ... }`.
Only that parameter is bound; the spelling `message` has no implicit meaning in
a block using another name. The parameter shadows an outer name, including a
built-in namespace if it uses the same name. The value remains a complete
`WebSocketMessage`, even when its parameter is named `frame`.

```swift
func identity<T>(_ value: T) -> T => value
func size(_ bytes: Bytes) -> i32 => bytes.count

return websocket(chat) { packet in
    let msg: WebSocketMessage = identity(packet)
    let payload: Bytes = msg.payload
    let count: i32 = size(payload)
    let client = msg.direction == WebSocketDirection.clientToUpstream
    let allowed = count == 2 && payload == b"\x00\xff"
    guard !client || allowed else { msg.drop() }
    msg.forward()
}
```

Callback `let` bindings use the common expression analyzer, declared-type checker
and pure helper normalization. They currently accept infallible scalar literals,
message aliases and projections, byte counts, equality, ordering of supported
integer projections, and Boolean composition. Bindings are immutable and visible
only after their declaration, through the remainder of this callback. Names
must be fresh across callback lets, JSON guard aliases and captured admission
constants; `json` is unavailable as a local let name. Optional values, HTTP reads
or effects, regex scans and JSON operations cannot be let initializers in this
slice. In particular, fallible scans/decodes keep their existing guard evaluation
and short-circuit behavior. An unused initializer is still checked.

Message aliases may receive verdicts. A borrowed text alias may feed the existing
text rewrite or `json.parse` guard; JSON guard aliases retain their existing
proof and scope rules. Close codes may use constant integer aliases, while close
reasons and fixed Binary replacements retain their existing literal-only forms.
None of these aliases allocate runtime storage, retain a message beyond the
callback, or become HTTP route locals. Compile-time HTTP admission constants
remain capturable; request-borrowed values do not.

The ordinary eight-statement block limit includes lets, guards and the final
verdict. The existing 16-local HTTP admission budget remains independent of the
callback parameter and its at-most-seven lets. JSON guard aliases remain bounded
by the four-clause handler limit; all clauses share a 32-node condition forest. Arbitrary local computation, general nested blocks and lifecycle
callbacks remain subsequent work.

### Conditional verdicts

Message callbacks accept the ordinary `if` / `else if` / `else` syntax with the
same Boolean predicate forms as message guards. An `if` without `else` may
precede later statements when its taken branch ends with a message verdict.
A terminal `if` / `else if` chain must have a final `else`, so every path ends
with a verdict. That complete chain must be the last statement of its callback or branch block.

```swift
return websocket(chat) { msg in
    if msg.payload.isEmpty { msg.drop() }
    if msg.fromClient && msg.kind == WebSocketMessageKind.binary {
        msg.forward(b"\x00\xff")
    } else if msg.text.matches(re"allowed[0-9]+") {
        let text: str = msg.text
        msg.forward("[" + text + "]")
    } else {
        msg.close(1008, "policy")
    }
}
```

Conditions and reached `else if` clauses execute in source order. A selected
verdict ends this callback immediately; later clauses are not evaluated.
Existing `&&` / `||` short-circuit behavior and fail-closed scan errors are
preserved. Conditions may call supported ordinary pure helpers or use earlier
JSON guard aliases. Boolean conditions must have type `bool`. JSON optional bindings also support
`if let` as described below.

Each arm may contain infallible immutable lets, guards and early if statements,
then a verdict or terminal nested `if` / `else` tree. Every callback path must
end in a verdict. Branch-local names do not escape into the condition, later
statements, sibling arms or later `else if` conditions. Sibling arms may reuse
fresh names. Loops and arbitrary expression execution remain unsupported. Every arm is
checked, including an arm made unreachable by a constant condition.

The eight-statement limit applies independently to the callback and each arm.
Each `guard`, `if` or `else if` consumes one of the existing four conditional
clauses; a final `else` consumes none. All clauses share the existing 32-node
condition forest. Branch lets do not consume clause slots or reduce the
16-local HTTP admission capacity. Branch close/forward recipes use the existing
bounded policy tables; a branch `close()` selects 1000 with no reason, independent
of a final else's close code/reason. Existing bare closes in guard-else statements
keep their route-default behavior. No new runtime representation, helper or
native format is introduced by these conditionals.

Nested arms use forward control targets on the existing condition roots. The
parent condition executes once; its selected arm runs without evaluating the
sibling arm. An early outer `if` whose taken arm is a complete nested tree may
precede later guards or a verdict. Its false path skips the entire taken subtree
before continuing. A branch's condition cannot see that branch's later lets.

```swift
return websocket(chat) { msg in
    if msg.fromClient {
        if msg.isBinary { msg.forward(b"\x00\xff") }
        else { msg.drop() }
    }
    guard let document = json.parse(msg.text) else { msg.close(1007) }
    guard let text = json.string(document) else { msg.close(1003) }
    msg.forward(text)
}
```

Here client Binary messages bypass both JSON checks; client Text messages are
dropped. Upstream messages skip the client subtree and reach the JSON guards.
The four-clause and 32-condition-node budgets count the complete source tree,
including both arms, without duplicating ancestor predicates. Each nested block
keeps its own eight-statement bound and lexical scope. The sixteen HTTP admission
locals remain independent of all live callback/branch bindings. All arms remain
statically checked, including unreachable ones. Target validation permits only
forward root edges, forward continuation boundaries, the configured default or
known verdicts; it rejects operand entry, self/backward edges and invalid tags.

### Optional bindings and branch guards

An arm may use ordinary Boolean `guard` conditions or the existing JSON
`guard let` operations. A successful guard continues in that same arm; its
failure verdict ends the callback. `if let name = expression` tests optional
presence and introduces the successful value only in its true arm. A nonterminal
if-let may exit early on success and continue on absence. `else if let` uses the
same rules, and sibling arms may reuse a binding name after its previous scope ends.

```swift
return websocket(chat) { msg in
    if let document = json.parse(msg.text) {
        if let field = json.get(document, "/flag") {
            if let flag = json.bool(field) {
                guard flag == false else { msg.forward("true") }
                msg.forward("false")
            } else { msg.forward("wrong kind") }
        } else { msg.forward("missing") }
    } else { msg.close(1007) }
}
```

The optional initializer subset is shared with message guard-let:
`json.parse(message.text)` (including borrowed text aliases), `json.get` on a
validated value alias with a literal pointer, and `json.string`, `numberText`,
`bool`, `int`, `stringify`, `kind` or `count` on a validated value alias. These are
proof aliases over the immutable message, using the existing JSON parser and
root-relative paths. Ordinary pure helpers may wrap these same projections. They
use the normal parameter types, type checking, generic identity helpers and
import namespaces; JSON arguments must already be unwrapped. Pointer arguments
must normalize to a compile-time string. Helper calls do not consume additional
condition clauses and retain the same absence/wrong-kind behavior.

```swift
func document(_ msg: WebSocketMessage) -> Json => json.parse(msg.text)
func field(_ value: Json, _ pointer: str) -> Json => json.get(value, pointer)
func text(_ value: Json) -> str => json.string(value)
// Inside the callback:
guard let root = document(msg) else { msg.close(1007) }
guard let selected = field(root, "/name") else { msg.drop() }
if let name = text(selected) { msg.forward(name) }
else { msg.drop() }
```

This helper subset normalizes to one parse/get/scalar projection over the same
immutable message. Conditional helper returns, JSON mutation, dynamic pointers,
HTTP reads/effects and other optional computations remain unsupported. A helper
may accept the borrowed message or its text, or an earlier validated JSON alias;
it cannot supply an unrelated JSON document. Initializer-less shorthand bindings
remain unsupported.

Presence is separate from truthiness: a valid `false`, `0`, empty string or empty
collection count binds successfully. A JSON `null` node is present for parse,
get, kind and stringify; type-specific extractors can still return no value.
If-let names are unavailable in the failure arm or after the if statement.
Guard-let names become available only after success, so a guard's failure verdict
cannot use its new binding. Branch bindings cannot escape to sibling arms or
later callback statements. Every arm is checked, including unreachable arms.

Early if statements and guards inside an arm resume at the next statement in
that arm, including a terminal verdict with no intervening predicate. They do
not fall into a sibling arm or the callback's outer default. Guard, guard-let,
if and if-let all share the existing four-clause and 32-node budgets; the
per-block eight-statement limit and literal output limits are unchanged. This
adds no runtime storage, helper, JIT control tag or native-format change.

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
Bindings count toward the four-clause limit. Each reached check reparses the
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
The four-clause and 32-condition-node limits remain unchanged.

Aliases are compile-time paths into the immutable message: each reached check
reparses the bounded payload and retains no JSON node or borrowed string view.
A `json.get` source may be the document or an earlier guard-unwrapped selected
JSON value. Further `get` calls use literal RFC 6901 pointers relative to that
value; each selection requires its own guard. General extraction, dynamic paths,
and dynamic predicate arguments remain unsupported. These bindings and
predicates use the existing four-clause and 32-condition-node limits.

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
count policy under the four-clause limit. A root document can bind both kind and
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
