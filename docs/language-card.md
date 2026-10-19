# Rutlang Language Card

Canonical syntax reference for generating `.rut` code. One blessed idiom per
task — if a form is not on this card, do not invent it. Derived from DESIGN.md
§3 (the authoritative spec); keep the two in sync.

Core contract: **Swift-exact or absent** — anything that looks like Swift
behaves exactly like Swift; near-miss variants do not exist in this language.

**Implementation status**: this card documents the target surface. The
front-end migration is in progress (TODO.md → "Front-End Migration"); forms
marked ⏳ are specified but **not yet accepted by the current compiler** —
they fail to compile today rather than misbehave. Everything unmarked works.

## File anatomy

A `.rut` file is a flat list of top-level declarations (any order, no `main`):

```swift
// PR #184 adds standalone examples; no tokenBucket helper is importable yet.
import "middleware/auth.rut"                        // file stem = namespace: auth.jwtAuth
// Imports nest at most 2 levels deep (main → a → b, kMaxImportNestingDepth);
// a deeper chain is a compile error at the offending `import`, never a crash.

listen :8080                      // one cleartext IPv4 wildcard listener
tls "api.example.com", cert: env("CERT"), key: env("KEY")
defaults { clientMaxBodySize: 10mb }

let users = upstream { "10.0.0.1:8080" }            // ⏳ builder form; current: upstream users at "10.0.0.1:8080"
let buckets = Cache<IP, i64>(capacity: 100000)     // lossy per-key state

struct Ctx { userId: str }        // types
func auth(_ req: Request, role: str) { ... }     // middleware/helpers
timer cleanup, every: 1m { ... }  // background tasks (1s+ intervals; body: no req/forward/wait)
timer push, every: 5s, shard: 0 { ... }   // shard-pinned singleton (default: every shard)
init { ... }    shutdown { ... }  // lifecycle hooks
route GET "/health" { return 200 } // zero or more top-level route declarations
```

`var` is allowed only inside func/handler bodies — never at top level.

## Lexical

```swift
// Literals
42                                      // number (plain integer)
3.14   0xFF   1_000_000                 // ⏳ float / hex / underscored (lexer takes plain digit runs only)
"text"   "\(req.path)/x"                // strings, \() interpolation (ONLY form)
500ms  1s  5m  1h                       // Duration (1d ⏳ — lexer knows ms/s/m/h only)
64b  1kb  16kb  1mb  1gb                // ⏳ ByteSize (no byte-size literal in lexer)
10.0.0.0/8                              // CIDR
:8080                                   // Port
re"^/api/v\d+"                          // Regex (compile-time validated)
true  false  nil
json({ users: [], total: 0 })           // bounded JSON construction; failure is optional

// Operators — each symbol has exactly one meaning in expressions
&&  ||  !                               // boolean (identical to Swift)
|                                       // pipeline ONLY (see below)
+  -  *  /  %                           // arithmetic (i32/i64, same-width operands; wraps on
                                        // overflow; x / 0 == 0, x % 0 == 0; literal / 0 is a
                                        // compile error; -x OK)
i64(x)                                  // widen i32 → i64 (the ONLY conversion; literals that
                                        // don't fit i32 are i64 automatically; no user i64
                                        // annotations; Cache<K,i64> is fixed built-in grammar;
                                        // typed route captures such as :id(i64) are ⏳;
                                        // no narrowing or match on i64; bitwise.* works at
                                        // both widths)
==  !=  <  >  <=  >=                    // comparison
=>                                      // single-expression body / match arm
->                                      // function return type
@                                       // decorator

// Bitwise = named functions, never symbols (i32/i64 same-width, bare
// literals adopt the i64 side; shift amounts share the operand width and
// saturate out of range: shiftLeft → 0, shiftRight → sign fill)
bitwise.and(a, b)  bitwise.or(a, b)  bitwise.xor(a, b)
bitwise.flip(a)    bitwise.shiftLeft(a, n)  bitwise.shiftRight(a, n)
```

Statements end at newline (no semicolons). Blocks need no commas between items.
Comments: `// line only`.

## Bindings and control flow

```swift
let x = 42                    // immutable (default)
var n = 0                     // ⏳ mutable, handler-local only
const key = env("SECRET")     // must be compile-time evaluable

if cond { ... } else { ... }              // bool branch — always braces
if let v = expr { ... } else { ... }      // bind usable value in then-branch; error-capable AND
                                          // pure-optional exprs (req.query/header) both work
guard cond else { return 400 }            // cond MUST be bool; else must exit
guard let v = expr else { return 400 }    // bind or exit; error-capable AND pure-optional
                                          // exprs both work
guard let v else { ... }                  // Swift 5.7 shorthand: rebind v

match status {                            // general dispatch — no `case` keyword
    200      => "ok"                      // pattern => expr
    404      => "gone"
    _        => "other"                   // exhaustive: all cases or _
}

// `for` loops are rejected by the current Core parser.

defer conn.close()                        // ⏳ runs on every exit path, LIFO (no defer in parser yet)
```

Nil/error handling — pick by situation, nothing else exists:

| Situation | Write |
|---|---|
| fallback value | `req.query("page").or("1")` (eager sugar for `any(x, default)`) |
| branch if present | `if let v = expr { ... } else { ... }` |
| stop if absent/failed | `guard let v = expr else { return 400 }` |
| bare presence test | `x != nil` / `x == nil` (nil and error are uniformly "absent"; never-nil sources are a compile error) |
| failure *reason* matters | `match` on the error |

There is NO `x?` postfix, NO `?.`, NO `??`, NO force-unwrap `!x`/`x!`, no
exceptions, no try/catch. `!` is logical not only.

## return vs respond — the one asymmetry to remember

- **Handler** (route entry body): its value IS the response → `return 200`,
  `return 200, body`, `return resp`, `return forward(x)`.
- **Middleware/helper func**: `return` only produces the function's normal
  value (or passes through); to end the whole request immediately use
  **`respond`**: `respond 401` / `respond 401, "expired"` / `respond 401, b"\x00"` /
  `respond resp`.
  A helper-local Response may carry ordered literal `set`/`add`/`remove`
  mutations. A `chain after` helper may receive the runtime `Response` and add
  ordered header effects to a successful handler response.

```swift
struct Claims { sub: str role: str }

func auth(_ req: Request, role: str) -> User {
    let token = req.header("X-JWT").or("")
    guard let document = jwtDecode(token, env("JWT_SECRET")) else {
        respond 401
    }
    guard let claims = json.decode(Claims, document) else { respond 401 }
    guard claims.role == role else { respond 403 }
    return User(id: claims.sub, role: claims.role)   // normal value
}
```

## Functions, UFCS, pipeline

```swift
func f(_ req: Request, limit: ByteSize) { ... }   // first param unlabeled, rest named
f(req, limit: 1mb)                // ⏳ mixed positional+named call args (parser rejects the label)
req.f(limit: 1mb)                 // UFCS: t.f(a) == f(t, a) — use when value
                                  // flows into the FIRST parameter
// ⏳ String prefix built-ins are planned; use the X-JWT extraction above today.

// Pipeline | — use when the value lands in a NON-first position.
// RHS must be a call with an explicit _ / _N placeholder (else compile error).
// ⏳ Prefix pipeline built-ins are planned; this syntax is not currently supported.
```

No closures, no function values (`let g = f` is an error), no recursion, no FFI.
All functions inline at compile time.

## Types

Domain types are first-class: `Duration ByteSize StatusCode Method IP CIDR Port
MediaType Regex Time`. Numeric: `i8..i64 u8..u64 f32 f64`, `str`, `[T]`,
tuples `(a, b)` — ⏳ `.0`/`.1` projection and `let (x, y) = pair` destructuring pending.

```swift
struct User {                 // fields: name: type — newline-separated, no commas
    id: str
    role: str
}
variant NetError {            // closed sum type
    timeout
    refused
    dns(str)                  // case with payload
}
match e {
    .timeout   => log.warn("timeout")
    .dns(host) => log.warn("dns", host: host)
    _          => log.warn("other")
}
protocol Hashable { func hash() -> u64 }
User impl Hashable { func hash() -> u64 => fnv64(self.id) }  // Type impl Protocol (NOT impl T: P)

parseInt("42")        // ⏳ i32? — parse APIs for text (parseFloat, IP.parse,
                      //         CIDR.parse, Duration.parse) all pending
200 as str            // ⏳ infallible conversion (`as` / checked `as?` pending)
```

## Request / Response

```swift
// Typed built-in properties (standard headers)
req.method == .GET          req.path (str)           req.remoteAddr (IP)
req.contentLength (ByteSize)  req.contentType (MediaType)
req.authorization (str?)   req.host  req.userAgent  req.origin (str?)

// Raw headers — function access ONLY (never req.X-Foo property syntax)
req.header("X-Request-ID")   // str?
req.set("X-User-ID", "123")  // ✅ replace/dedupe; statement-only
req.add("X-Tag", "a")        // ✅ preserve existing fields and append
req.getAll("Accept")         // ⏳ [str]

// Route captures / query / cookies / body
req.params.id                // from :id — captures NEVER shadow built-ins
req.query("page")            // str? (first value)
req.queryAll("tags")         // ⏳ [str]
req.cookie("session")        // str?
req.body(User)               // typed parse, error-capable → guard let
req.body                     // raw body as str
req.bodyJson()               // dynamic Json, error-capable
req.ctx.userId               // typed per-request context (user declares struct Ctx)

// Response construction — names are literal; values may be runtime strings
let resp = response(429)          // ✅ literal status
return response(200, body: "static body") // ✅ configured local/static body, ≤ 1 MiB
resp.set("Retry-After", "60")     // ✅ literal replace/dedupe
resp.set("X-Request-Path", req.path) // ✅ dynamic value
resp.remove("Server")             // ✅ literal delete
resp.add("Set-Cookie", "a=1")     // ✅ literal append/multi-value
resp.header("Retry-After")        // ✅ str?; observes prior set/add/remove mutations
resp.body = json(data)            // body
resp.status                       // StatusCode, read/write
return resp
```

Ordinary local HTTP/1 responses mirror the version of a complete strictly
parsed request (`HTTP/1.0` or `HTTP/1.1`). Responses to requests without a
captured valid version keep the HTTP/1.1 fallback. This does not change
keep-alive/close decisions or body framing. Configured strict-local,
redirect, and proxy/failure policy responses remain HTTP/1.1; generic
proxy/upstream errors keep their existing HTTP/1.1 default. Ordinary JIT-local
error publishers, including EventYield invalid-target errors, use the captured
request version. HTTP/2 uses its separate serializer.

Dynamic handler-local Response mutations require a direct route with no guards,
decorators, `wait`, or `for`, exactly one builder, and that builder must be
returned directly. A `chain after` helper must have exactly one `Response`
parameter and may use `set`/`add`/`remove` with literal names and runtime string
values; its effects apply to successful direct and forwarded responses on routes
without `wait` or `for`. Pending mutations are published only by the selected
success terminator, so guard and pre-middleware short circuits cannot inherit
them. Reading or changing a buffered response body/status remains ⏳ and needs a
resumable, stream-owned runtime Response object.

After existing strict inventory and pre-route fail-closed fences, HTTP/1
request admission rejects unsupported or ambiguous `Transfer-Encoding` and
every request combining `Content-Length` with `Transfer-Encoding` using `400`
and connection close before route handlers or upstream effects. A final
`chunked` coding remains supported, including `gzip, chunked`; the transparent
proxy path preserves those request header and body bytes and uses the chunk
boundary to keep any pipelined successor separate. Fragmented headers are
classified only after the complete header arrives. On the parse-error fallback
path, a complete header whose prefix, after optional OWS, begins with a line
break is rejected because its request-line boundary is not trustworthy.
Non-empty malformed first lines without a raw `Transfer-Encoding` field retain
the legacy fallback behavior.

The literal `response(status, body: "...")` form is limited to 1 MiB. Its bytes
are a non-owning view into the loaded program's RIR/module response-body
storage; `LoadedProgram` keeps that storage alive through teardown and reload
retirement. A runtime `str` body such as `req.body` is limited to one 16 KiB
`SlicePool` slice; HTTP/1 response headers share the bounded output buffer, so
the usable body limit can be lower. HTTP/2 copies a dynamic body into
stream-owned storage so it survives flow-control stalls. JSON construction
keeps its separate 8 KiB limit. Dynamic `resp.body` mutation remains ⏳.

For HTTP/2, the current bounded `HEAD` support applies to ordinary local JIT
`ReturnStatus` responses with a configured representation body, including
immediate, deferred-request-body, and timer-resumed handlers. It keeps the
configured `Content-Length` and ends on HEADERS without DATA. Existing route
matching still decides whether a HEAD request reaches a handler. Static,
default, unmatched, firewall, validation, and other status-only results remain
status-only; redirect remains unsupported, and proxy/strict-local behavior is
unchanged. This does not claim HEAD equivalence for every HTTP/2 response path.

`body: "..."` keeps the raw source spelling of backslash sequences. To place
exact bytes — newline, quote, backslash, a `\xNN` byte, or a non-ASCII byte —
use the byte-string form `body: b"..."`, which decodes `\n`, `\r`, `\t`, `\\`,
`\"`, and `\xNN` and is limited to 4096 decoded bytes (the same exact-byte bound
as failure/strict response bodies). Invalid or truncated escapes reject at parse
time, so a bad literal never reaches a published config.

Statuses that cannot carry a representation body — `1xx`, `204`, `205`, and
`304` — are serialized with no representation body. HTTP/1 emits
`Content-Length: 0`; HTTP/2 emits an END_STREAM HEADERS frame with no DATA and
omits `content-length` for the zero length. A configured body for one of those
statuses is dropped on the wire (it is not a commit failure), matching the
ordinary local-response framing for the other no-body statuses.

For ordinary local HTTP/1 responses, a parsed `HEAD` request uses the selected
publisher's status and representation headers, including its representation
`Content-Length`, and emits no response body bytes. Large configured bodies do
not start memory, file, or TLS body continuations for HEAD. This bounded runtime
behavior does not change route matching, the explicit strict-local or proxy
response policies, or GET-only metrics and redirect admission. For HTTP/2, the
bounded ordinary local JIT `ReturnStatus` HEAD case described above is the only
ordinary response path changed; other HTTP/2 publishers and proxy/strict-local
behavior remain unchanged.

## State types (top-level, per-shard, bounded)

```swift
let buckets = Cache<IP, i64>(capacity: 100000)   // lossy per-key slots
let tat = buckets.get(req.remoteAddr).or(0)      // i64? — miss = never-seen OR evicted; ALWAYS handle
buckets.set(req.remoteAddr, v)                   // bare statement, before any guard/wait/for;
                                                 // may evict a colliding neighbor
// Never store anything whose absence yields a wrong answer (sessions,
// in-flight counts). Rate limiting over Cache is implemented in
// examples/ratelimit.rut;
// Counter<K> is deleted; Hash is a RESERVED name (strict table, future).
// A leading set is materialized in the entry prelude and meters every attempt.
// A set inside a selected if/match branch executes on that branch immediately
// before its terminal body, enabling meter-on-accept policies. Cache ops are
// rejected in routes containing wait; branch-local writes are also rejected
// in static-for routes until their unrolled step graph carries effects.
// `return forward(...)` is a terminator, NOT a wait — the rate-limit-then-
// forward proxy pattern composes fine. set is not an expression.

let cache     = LRU<str, str>(capacity: 10000, ttl: 5m, coalesce: true)  // ⏳ pending
let blacklist = Set<IP>(capacity: 100000)          // ⏳ pending (Set<CIDR> = LPM trie)
let seen      = Bloom<str>(capacity: 1000000, errorRate: 0.01)           // ⏳ pending
let flags     = Bitmap(size: 256)                                        // ⏳ pending

notify all blacklist.add(ip)      // fan-out to all shards (eventual)
notify(ip) blacklist.add(ip)      // to owner shard by key hash (expr form;
                                  // bare-statement cache.set does not nest)
// single-owner routing: consistent: true (+ // rut:allow(consistent)); Cache
// remains lossy and separate get/set operations are not an atomic update.
// ⏳ cross-node backend is unspecified until Cache has a freshness contract.
```

## Routing

```swift
route GET "/health" { return 200 }
route "/" { return 404 }                          // all methods (omit METHOD)
route GET "/users/:id" {                         // capture: req.params.id
    return forward(userService)
}

@rateLimit(limit: 1000, window: 1m)               // official decorator applies
route POST "/form" { return 204 }                 // to this one route
```

The shipped parser accepts repeated top-level `route METHOD "pattern"`
declarations and the method-omitted form `route "pattern"`, which matches all
HTTP methods. Literal routes match a complete segment prefix: `/api` matches
`/api` and `/api/x`, but not `/apifoo`; `/` supplies the fallback. This applies
to both scalar and JIT dispatch. Query strings do not affect this selection.
There is no `ANY` route keyword; write the omitted-method form.
The grouped `route { ... }` surface (middleware pattern
bindings, host/path groups, method unions, typed captures, expression entries,
and `_` catch-all) is ⏳ target syntax and must not be emitted yet.

Precedence: literal segment > `:param` > `*rest`; exact host > wildcard > `_`.
Indistinguishable routes are a compile error. Stable middleware uses an explicit
`chain` direction:

```swift
func add_trace(_ req: i32, _ resp: Response) -> i32 {
    resp.set("X-Request-Path", req.path)
    0
}
chain observability { after add_trace(req, resp) }
route GET "/users" use chain observability { return forward(users) }
```

`before` helpers may gate a route; `after` currently supports Response header
effects only. Full buffered body/status middleware remains ⏳.

## Native gRPC forwarding

Use the currently implemented upstream declaration below (the upstream binding
migration shown elsewhere on this card is not required). `protocol: .http2`
selects HTTP/2 to the upstream, using **prior-knowledge h2c** by default;
omitted / `.http11` retains the existing HTTP/1 forwarding path.

```swift
upstream greeter {
    host: "127.0.0.1"
    port: 50051
    protocol: .http2
}
route POST "/helloworld.Greeter/SayHello" { return forward(greeter) }
```

When the host application pre-binds an upstream endpoint, the declaration may
carry protocol metadata without an address:

```swift
upstream greeter { protocol: .http2 }
```

This form requires a matching pre-bound upstream slot at load time. The
compiler applies `.http2` to that slot while preserving its existing address;
an empty upstream block and an addressless configuration with no pre-bound slot
remain load errors.

Downstream native gRPC requires HTTP/2, via h2c or a TLS listener offering `h2`.
Unary, client-streaming, server-streaming and bidirectional RPCs use the same
`forward`. Bodies (including compressed messages) and metadata are opaque;
trailers including `grpc-status` are preserved. Header-only middleware may run
before forwarding; body-reading handlers and HTTP/1-specific forward policies
are outside this streaming path. Native gRPC over HTTP/1 is rejected.
No `.proto`, protobuf dependency, new route keyword or streaming modifier is
needed. Internal bounded protobuf wire primitives and a compiler-side proto3
`FileDescriptorSet` schema loader back the built-in source compiler:

```swift
guard let message = protobuf.decode("message.proto", "example.Message", req.body) else {
    return 400
}
guard let bytes = protobuf.encode("message.proto", "example.Message", message) else {
    return 500
}
```

Paths and fully qualified message names must be literals. Paths resolve relative
to the current `.rut` file. The compiler reads proto3 imports and generates an
internal message type plus field-specialized RIR/LLVM; no protoc or generated
bindings are needed. Both operations are optional. Inferred types support at most
eight fields per message: string/bytes, bool, signed 32/64-bit,
unsigned/fixed 32-bit and acyclic embedded message fields. Unsigned/fixed 32-bit
fields infer i64 with range-checked encoding; repeated scalar/message fields infer `[T]`.
User i64 annotations remain
unavailable. Messages cap at 8 KiB; intermediate request bytes at 256 KiB.
Proto3 defaults, last correctly typed duplicate wins, UTF-8 validation for strings,
and skipping unknown/wrong-wire fields are implemented (group wire types are
rejected); unknown fields are lost on encoding. Embedded messages infer nested
structs (up to eight nesting edges); duplicate
submessages merge, and absent messages expose recursively default-valued structs.
Presence is not exposed: encoding such a default struct emits an empty embedded
message. Floating point, unsigned 64-bit values,
enums, oneof/presence/maps and proto2 are not executable codec shapes yet. See
[the example and source grammar limits](../examples/protobuf/README.md).
Repeated scalar and acyclic message arrays support `.count` (i32), `.isEmpty` (bool) and `.first`
(optional element). `let items: [i32] = message.values` aliases immutable,
request-owned storage. Empty arrays return nil from `.first`; repeated defaults
are retained. Numeric scalar packed/unpacked inputs may mix; encoding emits
unpacked scalars and length-delimited message entries.
Limits: 512 elements per array, 4,096 across the request Arena, and the shared
256 KiB value budget. Decode returns nil on limit/allocation failure. Strings
and bytes own their payloads. Message arrays contain native structs; unwrap
`.first` before accessing its fields. Child arrays and singular messages are
validated recursively, including elements not accessed by the program. Each
contiguous array region must also fit one Arena slice (16 KiB minus the block
header); exceeding the slot-byte limit returns nil. Arrays cannot be grown, mutated, indexed, iterated
or used in routes with explicit `wait`; general array literals remain rejected.
These operations handle protobuf payloads. `grpc.unframe(bytes) -> str?` extracts
one complete, uncompressed native gRPC message payload; `grpc.frame(bytes) -> str?`
adds its five-byte envelope. Both take a non-optional `str` and return nil on
invalid input, size/budget or allocation failure. Unframe rejects compression,
truncation, trailing bytes and multiple messages; an explicit empty message is
valid. The payload limit is 8 KiB (8 KiB + 5 bytes with its envelope). Results
own their bytes in the request arena and may contain arbitrary binary data.
These byte operations do not validate protobuf, dispatch RPC services, generate
`grpc-status` trailers, or perform protobuf JSON mapping. Native forwarding continues to treat payloads as opaque bytes.
JSON transcoding and gRPC health probes are not implemented by this
option; `health_check` with `.http2` is rejected.

Binary and base64-text gRPC-Web can use the same `.http2` upstream through
HTTP/2 or HTTP/1.1 POST requests. Content types are `application/grpc-web` and
`application/grpc-web-text`, optionally suffixed with `+proto`; `+json` is not
supported. The bridge preserves opaque protobuf payloads and converts backend
trailers into the final gRPC-Web body envelope. The incremental base64 request
decoder accepts independently padded flush blocks. HTTP/1.1 accepts
Content-Length or chunked uploads and closes after the response; it does not
provide keep-alive or pipelining for these RPCs. The HTTP/1.1 bridge rejects
routes configured with downstream `throttle` until response pacing is integrated
with the bridge. Browser CORS requires
explicit OPTIONS routes and response headers; see [the browser
example](../examples/grpc-web.rut) and [its
instructions](../examples/grpc/README.md#browser-grpc-web-example).

The request `Content-Type` selects upload decoding, while `Accept` independently
selects binary or base64-text response encoding. Supported Web media ranges use
their q values and specificity; ties prefer the request mode. Missing or
unrecognized Web ranges retain the request-mode response for compatibility.
Malformed supported Web ranges, duplicate q parameters, or a selection with no
acceptable supported representation are rejected. Native gRPC ignores Web
`Accept` values.

Native gRPC upstream sessions with active RPCs send an HTTP/2 PING every five
minutes after connection establishment or the previous probe. Only an ACK with
the same eight-byte payload completes a probe. The existing upstream timeout
(in seconds, checked by the one-second session timer) bounds the ACK wait;
timeout closes the session and fails unfinished RPCs with UNAVAILABLE without
replay. Idle pooled sessions, handshakes and GOAWAY-draining sessions do not
start probes. PING does not implement the protobuf gRPC Health service.

For a TLS upstream, add a `tls` field with explicit trust and identity:

```swift
upstream secureGreeter {
    host: "127.0.0.1"
    port: 5443
    protocol: .http2
    tls: {
        ca: "/certs/ca.pem"
        server_name: "backend.example.com"
        cert: "/certs/client.pem"
        key: "/certs/client.key"
    }
}
```

`ca` and `server_name` are required. Omit both `cert` and `key` for ordinary
server-authenticated TLS; supply both for mTLS. Keys must be unencrypted PEM;
encrypted keys are rejected without an interactive password prompt. Certificate-chain validation,
DNS/IPv4 identity verification and h2 ALPN are mandatory. DNS identities also
send SNI. There is no insecure verification mode, system-CA fallback or protocol
downgrade. Paths are literal strings (maximum 255 bytes), relative to the
process working directory when not absolute. `server_name` is at most 253 ASCII
letters/digits/dots/hyphens; embedded controls and escaped literals are rejected.
TLS is currently supported only with `.http2`. Files are loaded when a new
pooled upstream session is established, and its TLS context remains alive until
session teardown. TLS/configuration-file failures return UNAVAILABLE.

Upstream connections are shared per shard/config/upstream/backend and multiplex
RPCs from different downstream clients. Incomplete HTTP/2 input promotes the
connection's receive slice to 256 KiB when less than 16 KiB of tail space remains;
allocation failure closes that connection. This receive budget is separate
from per-message limits. Each session is bounded to 64 active
streams, header blocks to 16 KiB, and each direction of an RPC to a 65,535-byte
pending DATA queue. Message/body length is not capped by that queue: flow control
returns credit as bytes drain. Client cancellation resets only the mapped RPC.
For a valid incoming `grpc-timeout`, the proxy keeps an absolute deadline and
formats the remaining duration into upstream HEADERS only when they are sent,
including after connection setup or retry. If the field is absent, it stays
absent upstream. An expired deadline before send returns DEADLINE_EXCEEDED
(status 4) without sending request HEADERS. Timers use the existing precise
mechanism (millisecond granularity). Timeout values are rounded down when
encoded in a coarser gRPC unit, so the forwarded budget never exceeds the
remaining proxy deadline and can expire slightly earlier by less than one
selected unit. If a retryable response arrives but its
configured backoff cannot fit strictly before the original deadline, the RPC
ends with DEADLINE_EXCEEDED (status 4), without binding another endpoint or
forwarding the backend status; completion is counted once. Failures use gRPC
status trailers. Before any upstream HTTP/2
preface or other wire bytes are sent, socket creation, connect submission, and
TCP connect failures may advance to another distinct configured endpoint, up
to three endpoints total (or the address count when smaller). This preserves
the same session, queued exchanges, deadlines, and per-RPC accounting; no RPC
is replayed. TLS-configured upstreams can use this TCP-stage failover, but TLS
setup, handshake, certificate-identity, and ALPN failures after TCP connects
end the session without trying another endpoint.

Retries are opt-in on `.http2` upstreams:

```swift
upstream greeter {
    host: "127.0.0.1"
    port: 50051
    protocol: .http2
    grpc_retry: {
        max_attempts: 3
        max_request_bytes: 1048576
        statuses: [14, 8]
        backoff_ms: 100
    }
}
```

All four fields are required when `grpc_retry` is present. `max_attempts` is
the total number of attempts, including the first, and is 2 or 3;
`max_request_bytes` is 1 through 1,048,576 retained native gRPC body bytes,
including each message's five-byte envelope. For grpc-web text requests, text
decoding happens before these bytes are counted. Metadata is excluded from this
limit and is retained separately under its own snapshot bounds. `statuses` is
a nonempty list of distinct gRPC codes 1 through 16 (OK is not retryable), and
`backoff_ms` is 0 through 60,000. Omission disables retries. Replay requires the
complete request body to fit the configured byte limit, a separately retained
metadata snapshot, no committed response, and enough time for the backoff
before the original deadline.
See [the complete example](../examples/grpc.rut).

Optional per-message wire limits are configured on an HTTP/2 upstream:

```swift
upstream bounded {
    host: "127.0.0.1"
    port: 50051
    protocol: .http2
    max_request_message_bytes: 1048576
    max_response_message_bytes: 4194304
}
```

Each field is a positive integer through 4,294,967,295. Omission preserves
native opaque forwarding without envelope validation. Web always validates
framing, with an implicit unsigned 32-bit payload ceiling when omitted.
A configured direction reads
only the five-byte gRPC envelope, across arbitrary HTTP/2 DATA boundaries;
payload contents are never decoded. The limit applies to each message's wire
payload, excluding its envelope. For compressed messages it bounds compressed
bytes, not the decompressed size. Streaming RPCs may contain arbitrarily many
messages within the limit; the existing bounded queues and flow control still
apply. Oversized messages fail that RPC with RESOURCE_EXHAUSTED (8), invalid
compression flags or truncated envelopes/payloads with INTERNAL (13). Earlier
streamed bytes may already have reached the peer; requests are never replayed.

Native gRPC exposes `rut_grpc_started_total`, `rut_grpc_active`,
`rut_grpc_completed_total{grpc_status="..."}` and the
`rut_grpc_duration_seconds` histogram through the existing metrics endpoint.
The existing access log records each admitted RPC's method path, payload byte
counts, lifetime and a separate `grpc_status` field (HTTP status remains 200).
Cancellation/disconnection is recorded as CANCELLED; local deadlines as
DEADLINE_EXCEEDED. RPC retirement means the final response was staged into owned
output or the RPC was cancelled, not delivery acknowledgement. Metrics use
bounded status labels; service/method paths are recorded in logs. Existing
source live-log bytes-only output remains bytes-only. No protobuf decoding is
involved.


## I/O

HTTP policy selectors use contextual enum members (`.case`, lowerCamelCase).
Quoted selectors and bare identifiers are rejected; diagnostics list the
members allowed for the field. There are no legacy string aliases.

| Field | Implemented members (subject to the policy's combination constraints) |
| --- | --- |
| `version` | `.http11` |
| Request `host` | `.upstream`, `.preserve` |
| `connection` | Request: `.omit`; response: `.keepAlive`, `.request`; local/failure: `.request`; redirect: `.close` |
| `framing` | `.contentLength` |
| `date` | `.current`; response also `.preserveOrCurrent` |
| `head_mode` | `.reject`, `.suppressBody` |
| `header_names` | `.lowercase` |
| Request `forwarded_proto` | `.http` |
| Response `header_order`, `status_reason` | `.upstream`, `.canonical`, respectively |
| Response/local/failure `connection_header` | `.closeOnly` |
| Local `header_order` | `.dateServerLength`, `.lengthTypeDateServer` |
| Failure `header_order` | `.lengthTypeDateServer` |
| `content_length_position` | `.afterHost` |
| `retained_header_value` | `.trimSpPreserveHtab` |
| `response_buffering` | `.completeContentLength`, `.bounded` |
| Request `strip_headers` elements | `.connection`, `.keepAlive`, `.te`, `.expect`, `.upgrade`, `.proxyConnection` (last member only with `.preserve`) |
| Redirect `scheme`, `path` | `.http`, `.static`, respectively |
| Redirect `authority` | `.requestHost`, `.static` |
| Redirect `port` | `.actualListener`, `.omit` |
| Redirect `query` | `.preserveRaw`, `.discard` |
| Redirect `header_order` | `.locationThenConnection`, `.connectionThenLocation` |

Header names in open header APIs (`hide_headers`, `set_header`, response
headers), header values, media types, reason phrases, addresses and paths are
data and remain strings; bodies retain their string/byte-literal forms.
Status codes keep their existing checked integer syntax. A request's closed
`strip_headers` policy is not an API for arbitrary header names. Enum members
do not enable a protocol or policy combination absent from this card.

```swift
// Proxy — the transparent forms plus the explicit header-only policy form
return forward(users)                          // zero-copy, terminal
return forward(users, request_policy: {
    version: .http11, host: .upstream, connection: .omit,
    strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]
})                                               // ID1: fixed header-only rebuild
// ID2 adds content_length_position: .afterHost (Content-Length pinned
// right after the rewritten Host line; a request with no Content-Length at
// all is admitted unchanged -- only an explicit Content-Length: 0 is
// rejected).
// ID3 adds retained_header_value: .trimSpPreserveHtab (retained values
// keep leading/trailing HTAB while SP is trimmed; bounded to bodyless GET).
// The two are mutually exclusive and both require host: .upstream.
return forward(users, request_policy: {
    version: .http11, host: .upstream, connection: .omit,
    content_length_position: .afterHost,
    strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade]
})
// host: .preserve is a separate closed combination (Envoy-compatible H1,
// ID4): keeps the client's Host verbatim (fails closed unless exactly one
// non-empty, syntactically valid-authority Host header is present),
// lowercases every forwarded header name, and requires forwarded_proto and
// the six-name strip list together. Drops every header the client's
// Connection value nominates except content-length/host/x-forwarded-for/
// x-forwarded-host/x-forwarded-proto, nominating any of which (or a
// pseudo-header-shaped token starting with `:`) fails closed; keeps `te`
// when any physical TE field's comma-separated tokens contain `trailers` --
// a request-wide decision, not a per-field one: exactly one canonical
// `te: trailers` line (rewritten to that exact lowercase token) is emitted
// at the *first* physical TE field's position whenever any TE field carries
// the token, and every other physical TE field is suppressed (e.g.
// `TE: gzip`, then `X-Middle`, then `TE: trailers` forwards `te: trailers`
// before `x-middle`, not the `gzip` field dropped in place with `trailers`
// kept separately); Transfer-Encoding is NOT canonicalized or dropped the
// way TE is -- any Transfer-Encoding field fails the whole request closed
// (400, no upstream contact) before this serializer runs at all, even on a
// bodyless request, matching every other supported policy's own closed
// contract for it. A Connection nomination of `te` itself does not force a
// drop -- this same trailers check decides its fate, matching Envoy's own
// nomination special case; rejects Connection nominating `upgrade` alongside an Upgrade header
// whose trimmed raw value is non-empty (even with `close`) but admits a bare
// Upgrade header otherwise -- including an Upgrade header present with an
// empty/OWS-only value alongside an `upgrade` nomination -- and always
// strips it (and any nominated Upgrade) from the forwarded request; presence
// is based on the field's trimmed raw value, not the parser's own
// token-skipping flag, so a comma/OWS-only value such as "," or ", ," still
// counts as non-empty and fails closed alongside a nominating Connection
// value;
// rejects more than one X-Forwarded-Proto field, unconditionally, with no
// Connection-nomination exception (nominating x-forwarded-proto is itself
// protected, so it can never be dropped away as an escape hatch); a single
// field's value that
// is not (case-insensitively) exactly "http" or "https" -- empty, OWS-only,
// or otherwise invalid such as "http,https" -- is overwritten in place, at
// that field's original position, with "http" rather than dropped and
// forwarded blank or malformed; a valid value passes through unchanged in
// place; a trailing "x-forwarded-proto: http" is appended only when the
// client sent no such field at all; this "http" fallback is
// connection-derived, so ID4 targets a cleartext (non-TLS) listener only and
// is rejected closed (no upstream contact) on a connection this runtime
// terminated with TLS, rather than ever synthesizing "https"; separately
// rejects a duplicated physical occurrence of any *other* header name Envoy
// stores as a single inline slot (e.g. Content-Type, User-Agent,
// Authorization, Referer, and the remaining X-Forwarded-*/X-Envoy-* names)
// unless the client's Connection value also nominates that name, in which
// case every physical occurrence is dropped instead; rejects a fragment-bearing request
// target; and drops the sixteen client-supplied headers Envoy itself strips
// for external requests, plus one Rut-side hardening addition, seventeen in
// total (`x-envoy-internal`, fourteen more `x-envoy-*` names,
// `x-forwarded-client-cert`, and `x-envoy-external-address`;
// docs/envoy-compatibility.md). ID4 is ordinary-forward-only: pairing it with
// a response read timeout, response buffering, or a target_transform
// (forward(upstream, set_path: "...")) request-target rewrite fails at
// compile time with a dedicated diagnostic -- none of the three has a
// proven interaction with this profile.
return forward(users, request_policy: {
    version: .http11, host: .preserve, connection: .omit,
    header_names: .lowercase, forwarded_proto: .http,
    strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade, .proxyConnection]
})
// Bounded response-policy serialization currently accepts only a cleartext
// HTTP/1.1, origin-form, bodyless non-HEAD request and one final upstream
// HTTP/1.1 response framed by exactly one Content-Length. Requests with a
// body, TLS/H2, interim/Upgrade responses, chunking/trailers, close-delimited
// framing, or unsupported status/header controls fail closed; transparent
// forward(...) remains the default for all other routes. One exception: a
// fixed-Content-Length request paired with `host: .preserve` (ID4) or the
// plain `host: .upstream` strip (ID1) is admitted alongside a
// response_policy too — fully buffered, unchunked, with no pipelined
// successor bytes, and never served from a reused idle upstream socket (see
// `request_policy_body_response_admitted` in callbacks_impl.h).
// response_read_timeout: <1..63s> plus response_buffering: .completeContentLength
// commits the entire upstream response before any downstream byte is sent.
// response_buffering: .bounded (nginx proxy_buffering-on semantics) releases
// body bytes when the cumulative raw upstream response reaches whole 4 KiB
// units; the rewritten header accompanies the first positive release, and a
// complete Content-Length response flushes its final partial unit. A timeout
// or short EOF after release drops the unreleased partial unit and closes.
// The 4 KiB unit controls publication, not retained-memory capacity; slow
// readers still use the existing response-size bound.
// On io_uring, a depth-0 bodyless plaintext GET with .bounded may borrow an
// idle origin connection. A complete, persistent response may return it to
// the pool after its receive ownership settles, even if the client closes.
// Live receive/cancel owners, surplus bytes, EOF, truncation and timeout
// prevent pooling. Fixed uploads and pipelined successors still connect fresh.

return forward(users, response_policy: {
    version: .http11, framing: .contentLength, connection: .request,
    server: "nginx/1.29.7", date: .current, hide_headers: ["Date", "Server", "X-Pad"]
})
// Public HEAD suppression is an explicit paired source contract:
return forward(users,
    response_policy: {
        version: .http11, framing: .contentLength, connection: .request,
        head_mode: .suppressBody, server: "nginx/1.29.7", date: .current,
        hide_headers: ["Date", "Server", "X-Pad"]
    },
    failure_policy: {
        version: .http11, status: 502, reason: "Bad Gateway",
        content_type: "text/html", server: "nginx/1.29.7", date: .current,
        connection: .request, head_mode: .suppressBody, body: b"<html>...</html>"
    })
// head_mode defaults to .reject. .suppressBody is accepted in source only
// when both policies select it; it remains bounded to cleartext H1.1, bodyless
// HEAD with either no Connection field (the HTTP/1.1 default-keepalive shape)
// or exactly one `Connection: close`, one IPv4 upstream, strict success, and
// connect-establishment failure. On a `host: .preserve` (ID4) route only,
// this Connection grammar widens to the same nomination rule the ordinary
// ID4 request-policy path already applies, and to any number of physical
// Connection fields, not just one: every comma-separated, case-insensitive
// token across every physical field present is admitted -- and, along with
// its own field, dropped -- unless it names a protected header
// (`content-length`, `host`,
// the three forwarded-provenance headers, or a pseudo-header-shaped token
// starting with `:`, each of which fails the whole request closed instead),
// is `te` (never dropped along with its field regardless of nomination --
// the TE-trailers canonicalization rule alone decides its fate, exactly as
// without a nomination; a nominated `TE: trailers` still forwards one
// canonical `te: trailers` line, Codex sweep-13 review, PR #696),
// or is a genuine upgrade (a nominated `upgrade` token together with a
// semantically present, non-empty/OWS `Upgrade` field anywhere on the
// request -- e.g. `Connection: close, upgrade` with an absent or
// empty/OWS-only `Upgrade` header is not genuine and is admitted, both
// fields then stripped). Persistence is decided by the `close` token alone,
// independent of whatever else is nominated in the same value --
// `Connection: close, X-Foo` behaves like the plain `Connection: close`
// shape, and `Connection: X-Foo` alone (no `close`) behaves like no
// `Connection` field at all; the same union applies across physical fields,
// e.g. `Connection: TE` followed by a separate `Connection: X-Foo` is
// admitted exactly like one `Connection: TE, X-Foo` field would be -- since
// a nomination such as `te`, `X-Foo`, or
// a genuine-upgrade-free `upgrade` never affects persistence and ID4's own
// request-policy path already forwards the request correctly regardless of
// this response-side contract (canonicalizing a paired `TE` field when
// nominated, for example). While the broader failure rendezvous is not
// part of this contract, timeout, malformed/incomplete/excess response, and
// upload/send/recv failure close before emitting downstream bytes.
// response_policy.connection: .keepAlive requires a keep-alive downstream
// request and emits keep-alive. "request" follows the parsed downstream
// HTTP/1.1 intent, emitting keep-alive by default and close for
// Connection: close. The strict response-domain limits above remain unchanged.
// Valid downstream Upgrade requests are rejected by this policy; Upgrade
// passthrough remains PARTIAL in the first slice.
// header_order: .upstream is a separate closed combination (Envoy-compatible
// H1): preserves upstream header order and lowercases every forwarded name,
// keeps an upstream `date` in place (or appends one when absent), replaces
// the first `server` value in place (a later duplicate is dropped, or
// appends when absent), appends `connection: close` last only when the
// downstream connection is closing, and uses the canonical reason phrase
// instead of the upstream's — including when the upstream sent an empty
// reason phrase, since it is never forwarded. `hide_headers` cannot suppress
// `Content-Length`: it is the sole framing field this profile admits, so a
// hide-list entry naming it is not honored (the fixed-order profile above is
// immune the same way, by never routing Content-Length through its own hide
// check). All five fields below are required together;
// `response_read_timeout` / `response_buffering` / `timeout_failure_policy`
// are rejected with it (ordinary-forward-only, like request_policy
// host: .preserve). The fixed-order layout above (`header_order` omitted)
// is unchanged.
return forward(users, request_policy: {
    version: .http11, host: .preserve, connection: .omit,
    header_names: .lowercase, forwarded_proto: .http,
    strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade, .proxyConnection]
}, response_policy: {
    version: .http11, framing: .contentLength, connection: .request,
    header_order: .upstream, header_names: .lowercase,
    connection_header: .closeOnly, status_reason: .canonical,
    server: "envoy", date: .preserveOrCurrent, hide_headers: []
})
// local_response and failure_policy each accept an Envoy-compatible H1
// header-order combination too: `header_names: .lowercase`,
// `connection_header: .closeOnly`, and `header_order` are optional as a
// closed trio (any one present requires all three); the fixed-order layout
// above (all three omitted) is unchanged. `connection_header: .closeOnly`
// means `connection: close` is appended immediately after `server` only when
// the downstream connection is closing; it is omitted entirely otherwise
// (unlike the fixed-order layout, which always sends one or the other). Its
// place in the overall wire order is layout-specific: last for
// length_type_date_server, but followed by a trailing `content-length: 0` for
// date_server_length below.
//
// local_response header_order: .dateServerLength is the empty-body
// no-route shape (`date, server, [connection: close,] content-length: 0`):
// requires `body: b""` and `content_type` absent, 4xx/5xx status only.
unmatched { return local_response({
    version: .http11, status: 404, reason: "Not Found", server: "envoy",
    date: .current, connection: .request, connection_header: .closeOnly,
    header_names: .lowercase, header_order: .dateServerLength,
    head_mode: .suppressBody, body: b""
}) }
// local_response header_order: .lengthTypeDateServer is the bodied
// shape (`content-length, content-type, date, server, [connection: close]`):
// follows the fixed-order layout's content_type/body rules on a 4xx/5xx
// status (content_type required, body may be non-empty).
//
// failure_policy accepts the same `length_type_date_server` layout, and only
// it: status 503 is admitted paired with it and a non-empty body (Envoy's
// connect-failure representation); 502 stays exactly the fixed-order-only
// contract above. timeout_failure_policy stays fixed-order-only (400..599).
return forward(users, failure_policy: {
    version: .http11, status: 503, reason: "Service Unavailable",
    content_type: "text/plain", server: "envoy", date: .current,
    connection: .request, connection_header: .closeOnly,
    header_names: .lowercase, header_order: .lengthTypeDateServer,
    body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
})

// Explicit request-derived redirects are fully specified (no defaults). The
// first source slice accepts the generic Redirect terminator in the existing
// terminal route/control forms; H1 cleartext serialization is bounded by the
// policy/runtime domain above, while H2 and simulator execution remain
// unsupported.
return redirect({
    scheme: .http, authority: .requestHost, port: .actualListener,
    path: .static, query: .preserveRaw, date: .current, connection: .close,
    status: 301, reason: "Moved Permanently", server: "nginx/1.29.7",
    content_type: "text/html", target_path: "/api/", body: b"<p>moved</p>"
})
let resp = forward(users, buffered: true)      // buffered Response, then return resp
return forward(users, streaming: true)         // ⏳ explicit flag; current transparent forward(users) streams

// Static files / pipes
return read(root: "/var/www")                  // zero-copy (uses *catch-all capture)
guard let content = read(path: "/a/b.html") else { return 404 }   // buffered

// WebSocket proxy
guard req.upgrade == .websocket else { return 400 }
return websocket(chat)                          // transparent
websocket(chat, maxMessageSize: 64kb) { frame in    // per-frame inspection
    if frame.direction == .client && frame.isText {
        guard !frame.text.matches(re"(?i)spam") else { return .drop }
    }
    return .forward       // .forward .drop .close(reason:) .send(t) .inject(t)
}

// HTTP calls — native syntax, async is invisible (no await anywhere)
let res = post http://orders/create {
    Content-Type: application/json
    Body: order
    Timeout: 10s
}
guard let res else { return 502 }
guard res.status == 200 else { return 502 }

fire post http://audit/log { Body: json(evt) } // fire-and-forget, non-terminal

// Concurrency — submit/wait, single yield point
let h1 = submit get http://svc-a/x
let h2 = submit get http://svc-b/y
let (r1, r2) = wait(h1, h2)
guard let r1 else { return 502 }
guard let resp = any(wait(h1, 5s)) else { return 504 }   // timeout race
wait(2s)                                                  // sleep

// Raw TCP/UDP
guard let conn = tcp("redis:6379") else { return 502 }
defer conn.close()                             // ⏳ (no defer in parser yet)
conn.send("PING\r\n")
guard let data = conn.recv(maxSize: 4kb) else { return 502 }

// Bandwidth limit (inside handler, before the I/O)
throttle(downstream: 100kb per 1s, burst: 256kb)

// Background / lifecycle
timer checkHealth, every: 5s, shard: 0 { ... }   // shard: omitted = every shard
init { ... }         // per-shard, before accepting
shutdown { ... }     // per-shard, after drain
```

## Rate limiting in Rut (the blessed algorithms — examples/ratelimit.rut)

```swift
let buckets = Cache<IP, i64>(capacity: 100000)

route GET "/api" {                                   // GCRA token bucket
    let now = time.nowMicros()                       // latched per request
    let tat = max(buckets.get(req.remoteAddr).or(0), now)
    if tat - now <= 600000 {                         // tau = emit
        buckets.set(req.remoteAddr, tat + 600000)    // emit = 600ms/token
        return 200
    } else { return 429 }
}
```

For equivalent parameters, this matches `@rateLimit`, including leaving TAT
unchanged after a rejection (verified by JIT execution tests). Move the set to
the leading statement region when a deliberately punitive policy should meter
every attempt. The Rut form also supports custom policies such as per-tier
limits and composite conditions. See
examples/ratelimit.rut for the packed fixed-window variant, which permits
boundary bursts and is not a sliding-window limit.

## Cache state (per-key counters/timestamps — DESIGN.md §3.3.6)

```swift
let buckets = Cache<IP, i64>(capacity: 100000)   // top-level; per-shard lossy slots

route GET "/api" {
    let prev = buckets.get(req.remoteAddr).or(0) // i64? — a MISS IS NORMAL
    buckets.set(req.remoteAddr, prev + 1)        // bare set: before guards/for;
                                                 // ALL cache ops reject wait routes
    if prev + 1 > 100 { return 429 } else { return 200 }
}
```

- `get -> i64?`: nil means never-seen OR evicted — the two are indistinguishable
  by design; `.or(default)` / `guard let` are the only ways to consume it.
- Entries may be evicted by colliding writes at any occupancy: never store
  anything whose absence gives a wrong answer. Capacity = slot count (rounded
  up to a power of two); provision ~2× your expected key count.
- A leading state write runs at handler entry and must precede guards/for. A
  write inside a selected `if`/`match` branch runs only on that branch, after
  its local prelude guards and before its terminator. Routes containing
  `wait`/`wait any` reject every cache op, including ops textually before the
  wait; branch writes in static-for routes remain unsupported. Per-shard state:
  effective limits ≈ limit × shard count.

## Built-ins (call them, never reimplement)

```
string:  s.len s.isEmpty s.contains s.upper()/lower()/trim()
         s.replace/split/slice s.matches(re"") s.match(re"")
         ⏳ s.hasPrefix/hasSuffix/trimPrefix/trimSuffix
hash:    md5 sha1 sha256 sha384 sha512 fnv32 fnv64 | hmacSha256/384/512
jwt:     jwtDecode(tok, secret) -> Json? (HS256/384/512 verified claims;
         decode with json.decode/json.get). ⏳ publicKey/RS/ES and jwtEncode
crypto:  aesGcmEncrypt/Decrypt randomBytes(n) uuid()
encode:  base64 base64url hex urlEncode urlDecode htmlDecode unicodeNormalize
time:    time.nowMicros() -> i64 (monotonic µs; latched per invocation — all
         uses in one request see the same value)  max(a, b)  min(a, b)
         — now()/time(s)/Duration arithmetic still ⏳
misc:    env(k) json(v) log.info/warn/error(msg, key: val, ...)
admin:   stats() metrics() reload() upstream_status() config_dump() shard_stats()
```

`env("NAME")` is resolved when the program is analyzed/loaded, not per
request. The name must be a string literal and the variable must exist; a
missing variable is a compile error. The resolved value is embedded as a
constant, so changing the environment requires recompilation or reload.

## Do NOT write (compile errors — with the fix)

| Wrong (foreign habit) | Right |
|---|---|
| `and` / `or` / `not` | `&&` / `\|\|` / `!` |
| `x?` , `x?.y` , `a ?? b` , `x!` | `guard let` / `if let` / `.or(default)` / `!= nil` |
| `guard claims else {}` (non-bool) | `guard let claims else {}` |
| `req.X-Request-ID` | `req.header("X-Request-ID")` |
| `resp.Server = nil` | `resp.remove("Server")` |
| `req.id` (route capture) | `req.params.id` |
| `return 401` inside middleware | `respond 401` |
| `respond 200` inside handler | `return 200` |
| `case 200 => ...` | `200 => ...` (no `case` keyword) |
| `switch` | `match` |
| `while cond {}` | `for x in xs {}` (bounded) or `timer` |
| `a & b`, `a << 2`, `~a` | `bitwise.and(a, b)`, `bitwise.shiftLeft(a, 2)`, `bitwise.flip(a)` |
| `x \| f(y)` (no placeholder) | `x \| f(y, _)` — show where the value lands |
| `cond ? a : b` | `if cond { ... } else { ... }` or `match` |
| `async` / `await` / callbacks / closures | plain sequential code — compiler handles async |
| `let g = f` (function value) | call `f` directly; no function values |
| recursion | unroll or restructure; all calls inline |

## Minimal complete example

```swift
listen :80                         // one cleartext IPv4 wildcard listener
let users = upstream { "10.0.0.1:8080" }          // ⏳ current: upstream users at "10.0.0.1:8080"
// A standalone Cache/GCRA implementation lives in examples/ratelimit.rut.
// ⚠ Unmatched methods/paths currently use Rut's default 200 OK handler; there
// is no shipped top-level catch-all syntax yet. Configure the surrounding
// listener/proxy to return 404 for traffic outside these declared routes.

route GET "/health" { return 200 }

@rateLimit(limit: 1000, window: 1m)
route GET "/users/:id" { return forward(users) }

route POST "/users" {
    guard let user = req.body(User) else { return 400 }
    return forward(users)
}

struct User {
    id: str
    role: str
}
```

## Builtin test workload responses

Use `return workload(bytes: N)` in a route to return HTTP 200 with a
compile-time generated deterministic binary body and `application/octet-stream`.
`N` must be a literal integer from 1 through 1048576. Generated workload bodies
are limited to 16 MiB per analysis tree, including imports. This contextual
builder does not reserve `workload` as a global keyword.

```swift
route GET "/static4k" { return workload(bytes: 4096) }
route GET "/static1m" { return workload(bytes: 1048576) }
route GET "/api4k" {
    wait(1ms)
    return workload(bytes: 4096)
}
```

This is a synthetic test handler, not filesystem serving or upstream proxying.
Each 4096-byte block starts with its little-endian 32-bit block index; subsequent
bytes are `(blockIndex * 17 + payloadOffset * 29) & 255`, with payloadOffset
starting at zero after the index. The final block may be partial. Bodies are
owned by the compiled program; generation performs no per-request allocation.
Use existing `wait` for application delay. Timed response fragments are not
provided by this builder.

## Experimental compiler eBPF diagnostics

Linux builds with `-DRUT_ENABLE_EBPF=ON` (and `RUT_ENABLE_JIT=ON`) support
`rut app.rut --ebpf-plan` and `rut app.rut --emit-ebpf PREFIX`.
These analyze verified, inlined RIR and optionally export raw body-transfer
bytecode; they add no language syntax. Fixed terminal forwards can be body
candidates while routing and headers stay in userspace. A candidate does not
activate kernel forwarding: live socket handoff remains ⏳. `firewall {}`/XDP and
kTLS integration also remain unimplemented. See [ebpf.md](ebpf.md).


### Local unary gRPC responses over HTTP/2

A local handler can return `response(200, headers: {"content-type":
"application/grpc+proto", "grpc-status": "0"}, body: framed)` after composing
`grpc.unframe`, protobuf decode/encode and `grpc.frame`. For these explicitly
marked responses, HTTP/2 emits the status as trailing HEADERS after all DATA.
An empty response with the same headers is a trailers-only response; use a
nonzero status for a failed RPC. Status values must be canonical decimal 0–16,
with exactly one content type and one grpc-status. Nonempty bodies must contain
one complete uncompressed envelope with at most 8 KiB of payload. Invalid output
fails closed with HTTP 500 before publishing a response body.

Bodies and the pending numeric status survive flow-control stalls, queued
response promotion and cancellation. Trailers consume no DATA flow-control
credit. This local path uses ordinary HTTP request/response accounting, not the
upstream gRPC proxy exchange counters. It does not automatically bind service
schemas, enforce grpc-timeout for local work, expose streaming RPC handlers,
convert grpc-web, or perform HTTP/JSON transcoding. See
[the local endpoint](../examples/grpc-local.rut) and
[client instructions](../examples/grpc/README.md#local-unary-rpc).
