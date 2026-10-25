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
accessLog { path: "/var/log/rut/access.log", format: downstreamRequestBytes, publication: live }
```

`var` is allowed only inside func/handler bodies — never at top level.

`accessLog` is optional process-start metadata in the main source file. The
current reliable `live` publisher accepts `downstreamRequestBytes` (the
existing request-length line) and `downstreamHost` (the bounded H1 Host
observation profile described below). Imported files cannot declare it.

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

for item in order.items {                 // ⏳ finite collections only, no while
    if item.qty == 0 { continue }         // ⏳ break / continue allowed
    guard item.qty > 0 else { return 400 }
}

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
  `return 200, body`, `return resp`, `return forward(x, load_balance: .roundRobin)`.
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

## Process access log

```swift
accessLog {
    path: "/var/log/rut/host.log",
    format: downstreamHost,
    publication: live
}
```

`downstreamHost` emits one versioned ASCII line per completed strict HTTP/1
request:

```text
host1 request_bytes=<decimal> status=<decimal> host_state=<state> host_length=<decimal> host_hex=<hex-or-dash> upstream_history=unavailable
```

The Host value is the observed downstream semantic value after HTTP optional
whitespace trimming. `host_hex` uses lowercase hex so arbitrary bytes cannot
create a second line. States are `complete`, `empty`, `absent`, `duplicate`,
`over_limit`, `unavailable`, and `invalid`; only `complete` carries bytes.
`downstreamHost` does not change request acceptance, validate Host authority,
or claim upstream-attempt history. H2 stream publication is not part of this
profile. The existing `downstreamRequestBytes` output remains byte-identical.

## Request / Response

```swift
// Typed built-in properties (standard headers)
req.method == .GET          req.path (str)           req.remoteAddr (IP)
req.contentLength (ByteSize)  req.contentType (MediaType)
req.authorization (str?)   req.host  req.userAgent  req.origin (str?)

// Raw headers — function access ONLY (never req.X-Foo property syntax)
req.header("X-Request-ID")   // str?
req.uniqueHeader("X-API-Key") // str?; missing or duplicate fields yield nil
req.set("X-User-ID", "123")  // ✅ replace/dedupe; statement-only
req.add("X-Tag", "a")        // ✅ preserve existing fields and append
req.remove("Authorization")  // ✅ delete every matching field before forwarding
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
and connection close before route handlers or upstream effects. HTTP/1.0
requests with any `Transfer-Encoding` are rejected. For HTTP/1.1, a final
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
not start memory, file, or TLS body continuations for HEAD. This contract also applies to the closing 500 fallback when a dynamic JSON response
cannot be published; that fallback preserves the captured HTTP/1 version.
This behavior does not change route matching, the explicit strict-local or proxy
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
    return forward(userService, load_balance: .roundRobin)
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
route GET "/users" use chain observability { return forward(users, load_balance: .roundRobin) }
```

`before` helpers may gate a route; `after` currently supports Response header
effects only. Full buffered body/status middleware remains ⏳.

## Explicit load balancing at each forward call

Every `forward` requires an explicit `load_balance` named argument. The only
accepted values are `.roundRobin` and `.leastRequests`. Legacy `forward(api)`
is a compile error, including for single-backend upstreams.

```swift
upstream api {
    backends: ["127.0.0.1:9001", "127.0.0.1:9002"]
}

route GET "/catalog" {
    return forward(api, load_balance: .roundRobin)
}
route POST "/jobs" {
    return forward(api, load_balance: .leastRequests)
}
```

Every forward site must explicitly name one policy, including single-backend
and host-bound upstreams. `upstream` contains backend/connection configuration;
it does not contain or supply a selection policy. The `at "ip:port"` upstream
form can remain: its callers must supply the argument. There is no default,
inheritance, string spelling, numeric spelling, or policy alias.

Round-robin cursors are per forward site and shard. Least-request counts are
shared across routes using the same upstream backend set on that shard and
count active requests/RPCs, not pooled connections. The policy is part of the
forward operation, including suspended JIT handlers and native gRPC streams.
Least-request ties rotate at the forward site. Connecting attempts count as
active; completion, failure, cancellation, and reset release the count once.
Retries release the failed attempt before selecting again. Both algorithms
skip ejected backends when healthy ones exist and retain the existing fail-open
behavior when all are ejected. Empty backend sets remain invalid. See [DESIGN.md §3.4.1](../DESIGN.md#341-listening-tls-and-upstream).

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
route POST "/helloworld.Greeter/SayHello" { return forward(greeter, load_balance: .roundRobin) }
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
are outside this streaming path. HTTP/1 requests cannot use an HTTP/2 upstream.
No `.proto`, protobuf dependency, new route keyword or streaming modifier is
needed. gRPC-Web, JSON transcoding and gRPC health probes are
not implemented by this option; `health_check` with `.http2` is rejected.

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
`grpc-timeout` is enforced with the existing precise timer mechanism (millisecond
granularity); failures use gRPC status trailers. Calls are never automatically
replayed. See [the complete example](../examples/grpc.rut).

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
return forward(users, load_balance: .roundRobin)                          // zero-copy, terminal
return forward(users, load_balance: .roundRobin, request_policy: {
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
return forward(users, load_balance: .roundRobin, request_policy: {
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
// (forward(upstream, load_balance: .roundRobin, set_path: "...")) request-target rewrite fails at
// compile time with a dedicated diagnostic -- none of the three has a
// proven interaction with this profile.
return forward(users, load_balance: .roundRobin, request_policy: {
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

return forward(users, load_balance: .roundRobin, response_policy: {
    version: .http11, framing: .contentLength, connection: .request,
    server: "nginx/1.29.7", date: .current, hide_headers: ["Date", "Server", "X-Pad"]
})
// Public HEAD suppression is an explicit paired source contract:
return forward(users, load_balance: .roundRobin,
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
return forward(users, load_balance: .roundRobin, request_policy: {
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
return forward(users, load_balance: .roundRobin, failure_policy: {
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
let resp = forward(users, load_balance: .roundRobin, buffered: true)      // buffered Response, then return resp
return forward(users, load_balance: .roundRobin, streaming: true)         // ⏳ explicit flag; current transparent forward(users, load_balance: .roundRobin) streams

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

A route supports at most four stacked `@rateLimit` decorators. A fifth is a
compile-time error reported at that decorator; rules are never silently omitted.
The limit is per route, not per file.

An active `@rateLimit(..., scope: global)` rule requires the process-shared
limiter. If a runtime caller omits it, enforcement fails closed with 429 before
spending any other rule's budget; it never falls back to per-shard enforcement.
Disabled rules do not require shared state. Normal `rut` startup supplies it.

Names in rate-limit `by: header/query/cookie/param("name")` components are
limited to 32 bytes. A longer name is a compile-time error at the name literal,
not a truncated lookup. The native key-spec builder also rejects it without
appending a component.

Invalid `by:` source kinds, a fifth key component, invalid `scope` values, and
unknown named arguments are compile-time errors at the offending token. Their
diagnostics list the accepted source forms, the four-component limit, the two
scope values, or the accepted named arguments respectively.

Key extraction follows the corresponding request accessors: header names are
case-insensitive (including the persisted rate-limit namespace) and optional whitespace around values is ignored; duplicate
`Authorization` fields are ambiguous, matching `req.header`; query,
cookie, and route-parameter names are exact byte matches. Query and cookie
lookups use the first matching field in request order (including all Cookie
fields), and cookie parsing uses the same optional-whitespace handling as
`req.cookie`.
Missing and explicitly empty values intentionally share the documented
unattributed bucket.
Query extraction uses the validated raw request target when available; a
separately supplied path is used only when its producer explicitly marks it
trusted (for example, a validated HTTP/2 `:path`). Recovered paths from
malformed HTTP/1 metadata and synthetic harness routing fields are not trusted
fallbacks.

The built-in shard limiter has 8192 direct-mapped slots. A colliding new key
is rejected until the previous bucket fully recovers (`tat <= now`); it cannot
reset active state to obtain fresh burst credit. This is conservative capacity
failure, not an exact per-key table. The global limiter shares atomic slots
within one process; colliding keys share budget and may throttle one another.
Neither mechanism supplies cross-node or strict lossless state. Rut `Cache`
examples remain a separate, deliberately lossy state mechanism.
Rate-limit emission intervals use the exact ceiling of `window / limit` in
microseconds, so a non-divisible window is never shortened. Configuration is
rejected when `(burst - 1) * emit_interval` cannot fit in the runtime's u64
GCRA state; oversized rate-limit duration literals are rejected rather than
saturated to a shorter window. Sub-second rate-limit durations retain the
existing round-up-to-one-second behavior. Runtime conformance and state advancement are
overflow-safe near the maximum monotonic timestamp and fail closed if the next
timestamp cannot be represented.
The compiler diagnoses a zero limit, a window whose rounded whole-second value
falls outside 1..4294967295, and a burst too large for the selected
limit/window with actionable parameter errors. Sub-second windows such as
`1ms` remain valid and round up to one second.
The shard limiter table belongs to its event-loop instance: HTTP/1 and HTTP/2
dispatch on that loop share the table, while separate loop instances remain
isolated even when they run on the same thread.

Limiter buckets are identified by an immutable semantic namespace, not by the
route's array index. The namespace serializes the route method and stored path,
the complete rule policy and scope, the ordered key components, and the
duplicate-rule rank. Therefore a config reload preserves history for an
unchanged route/rule when routes or stacked rules are reordered, while a
changed or new policy gets a distinct namespace. The bounded shard/global
tables may still collide or reject under capacity pressure, so this does not
promise a fresh physical slot. Removing and later re-adding the same semantic
rule may retain its old history while that slot remains live.
Native hand-built configs must finalize rate-limit IDs before publication;
missing IDs fail closed before spending any budget. A process-shared global
limiter is retained across shard config adoption and is never reset per shard.

Stacked built-in rules meter each request attempt independently. Enforcement
checks every active rule even if an earlier rule rejects: each conforming rule
consumes one token, with no rollback when the final response is 429. A rule
already over limit does not advance its own GCRA timestamp or accumulate debt.
The request passes only when every rule passes. Disabled rules consume nothing;
a missing required global limiter fails preflight without spending any budget.
This does not change the policy chosen by Rut code over Cache.

When a built-in rule rejects with a known finite wait, HTTP/1 and HTTP/2 return
429 with an integer-second `Retry-After` advisory rounded up from the remaining
GCRA wait. The wait is the maximum post-charge recovery wait across every active
stacked rule, including rules that accepted and consumed a token. Missing semantic
IDs, missing global state, and timestamp overflow omit the header. The value is a
snapshot and is not a reservation under concurrent traffic. The runtime exposes
fixed-cardinality per-shard attempt, rejection, and rejection reason counters
through `/metrics`; reason counters have stable labels and never include routes
or metering keys. Rule-level counters are likewise fixed-cardinality, labelled
only by `scope` (`shard`/`global`) and the three actual rule reasons
(`budget`, `shard_collision`, `state_overflow`). They count every
active stacked rule reached, including rules after an earlier rejection;
missing semantic IDs or global state fail in preflight and add no rule counts.

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

## Constant-time equality

`constantTimeEqual(a, b) -> bool` accepts two unwrapped `str` values. Use
`guard let` or `.or(default)` before passing optional/error-capable values.
For equal public lengths up to 16 KiB it calls the existing static OpenSSL
`CRYPTO_memcmp`, with no early exit based on contents. Different lengths or
lengths above 16 KiB return false; lengths are not secret. Empty strings compare
equal and embedded NULs are ordinary bytes. No normalization or encoding
conversion occurs. The call allocates no storage and keeps no references.

```swift
route GET "/compare" {
    guard let left = req.header("X-Left") else { return 400 }
    guard let right = req.header("X-Right") else { return 400 }
    guard constantTimeEqual(left, right) else { return 403 }
    return 200
}
```

Explicit-placeholder pipes work: `left | constantTimeEqual(_, right)`. A user
function/binding with the same name shadows the builtin. Equality alone is not
authentication: credential policies must also reject missing/empty credentials
and supply a trusted expected value.

## UUID v4 (implemented)

Runnable example: [examples/uuid.rut](../examples/uuid.rut).

`uuid() -> str?` generates 36 lowercase ASCII bytes using the OS CSPRNG (RFC 9562, version 4 and RFC variant). Handle entropy failure, missing request arena, shared-budget exhaustion and SlicePool exhaustion explicitly:

```swift
route GET "/id" {
    let pending = uuid()
    guard let id = pending else { return 503 }
    return response(200, body: id)
}
```

Linux makes one nonblocking `getrandom` call; macOS uses `getentropy`. Failures, including short reads, return nil without fallback or retry. Each call is fresh; reusing a bound local preserves its value. Results use the existing request-owned JSON arena and share its 256 KiB used-byte budget (40 bytes per UUID after alignment). Views remain valid until request retirement/reset, and HTTP/2 local responses copy their body into stream-owned storage before that reset.

The call must directly initialize a top-level route `let`, as above. Calls in `guard let`/`if let` expressions, inside helpers, and nested in larger expressions are rejected until single evaluation of fresh values is supported there. ID values already generated may be passed to ordinary helpers. No arguments or implicit pipe stage are accepted. User functions/bindings named `uuid` shadow it. `wait` routes reject UUID calls; timers and randomness inside `chain after` header effects are unsupported. Request set/add still require literal values, so UUID generation does not yet provide complete request-ID forwarding middleware. Random UUIDs do not promise absolute uniqueness or ordered IDs. `randomBytes(n)` remains a target API, not an alias for `uuid()`.

## Built-ins (call them, never reimplement)

```
string:  s.len s.isEmpty s.contains s.upper()/lower()/trim()
         s.replace/split/slice s.matches(re"") s.match(re"")
         ⏳ s.hasPrefix/hasSuffix/trimPrefix/trimSuffix
hash:    md5/sha1/sha224/sha256/sha384/sha512(data) -> str? (lowercase hex)
         hmacMd5/hmacSha1/hmacSha224/hmacSha256/hmacSha384/hmacSha512(key, data) -> str?
         ⏳ fnv32 fnv64
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
route GET "/users/:id" { return forward(users, load_balance: .roundRobin) }

route POST "/users" {
    guard let user = req.body(User) else { return 400 }
    return forward(users, load_balance: .roundRobin)
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

## Unique credential headers

`req.uniqueHeader("Name") -> str?` accepts a literal HTTP token field name and
returns a value only when exactly one case-insensitive occurrence exists.
Duplicate identical values are also absent. Use this read for custom API key
headers; ordinary `req.header` keeps its first-field behavior for other fields.
Authorization is always a singleton: both `req.authorization` and
`req.header("Authorization")` return nil for duplicate Authorization fields.
Request-header mutation does not change these original-request reads.

## Static authentication helpers

See [examples/authentication.rut](../examples/authentication.rut) and
[examples/middleware/auth.rut](../examples/middleware/auth.rut). These are ordinary
Rut functions returning `Identity { consumerId, credentialId, method }`:

- `auth.apiKey(authorization, key, consumerId, credentialId)` verifies an opaque
  Bearer key. Scheme spelling is case-insensitive and accepts 1*SP.
- `auth.headerKey(req.uniqueHeader("X-API-Key").or(""), key, consumerId, credentialId)`
  verifies a custom header key. Do not replace uniqueHeader with first-field reads.
- `auth.basic(authorization, credentials, consumerId, credentialId)` takes configured
  `user:password` bytes; password may contain colons or be explicitly empty.
- `auth.rotatingApiKey(authorization, currentKey, previousKey, consumerId, currentId, previousId)`
  supports two credential slots. Empty keys disable slots; both IDs must be nonempty.
  Current wins if both keys match. Clear the old key and activate new configuration
  to revoke it; the current CLI requires restart.
- `auth.apiKeyOrBasic(authorization, key, credentials, consumerId, keyId, passwordId)`
  accepts either Bearer or Basic for the same configured consumer. Empty credentials
  disable that method; both IDs are required even for a disabled method. Both
  methods disabled returns 503. Rejection returns 401 with two ordered
  `WWW-Authenticate` fields (Bearer, then Basic). Read only the unique
  `req.authorization` field: duplicates reject the whole request, with no fallback
  to another header, query parameter, or anonymous identity.
- `auth.requireConsumer(identity, allowedConsumerId)` permits one exact,
  case-sensitive consumer ID; `auth.denyConsumer(identity, deniedConsumerId)`
  excludes one exact ID. Both return the unchanged verified identity on success,
  403 on policy rejection, and 503 for an empty policy ID. Chain deny checks for
  multiple exclusions. Chain allow checks mean AND, not an allow-list union.
  Authenticate first: these ordinary helpers trust the supplied Identity and do
  not prove its origin. They do not implement a Consumer/group registry or RBAC.

Use `req.authorization.or("")` for authorization arguments. Invalid credentials
return 401 with a Bearer, Basic (realm `rut`), or ApiKey challenge. Empty credentials,
consumer/credential IDs, or two disabled rotation slots return 503. Other malformed
configured credentials never authenticate. Identity comes from verified configuration,
not client identity headers, and never includes a secret.

`bearerMatches(authorization, key)` and `basicMatches(authorization, credentials)`
accept two unwrapped strings and return bool. Bearer keys use RFC 6750 b64token
syntax and are limited to 4096 bytes. Basic credentials require a nonempty user-id,
a colon, no control bytes, and at most 1024 bytes. Encoding is byte-exact without
normalization. Comparing canonical Base64 rejects malformed encoding, nonzero pad
bits and missing/extra padding, without decoding attacker bytes. Encoded temporary
credentials are cleansed; equal-length comparisons use the existing crypto primitive.
Both operations allocate no memory and preserve no references.

`bearerToken(authorization) -> str?` extracts a borrowed, validated Bearer token
(up to 24 KiB) for the existing `jwtDecode`. Missing/malformed input returns nil;
use guard-let or `.or("")`. Its lifetime is that of the input string. The builtin
reuses the optional-string helper ABI and can compose with existing JSON/JWT calls.
All three builtins can be shadowed by user functions. No keyword or library is added.

The example resolves secrets with existing compile-time `env()`. Missing variables
reject compilation, and compiled artifacts contain these constants. Serve credentials
through TLS. Dynamic Consumer storage, live revocation, and automatic identity or
credential forwarding are outside this static helper layer.

## Credential stripping before forwarding (implemented)

This covers the header-credential hiding use case documented by
[Kong Key Auth](https://docs.konghq.com/hub/kong-inc/key-auth/configuration/)
and [APISIX key-auth](https://apisix.apache.org/docs/apisix/plugins/key-auth/),
using explicit Rut request mutations.

`req.remove("Authorization")` and `req.remove("X-API-Key")` delete all fields
with that name, case-insensitively, from the upstream request. Missing fields
are a no-op; removal is distinct from setting an empty value. Ordered
set/add/remove effects share the existing bounded request mutation log. Overflow,
invalid direct-IR names/modes, aliased views, or unusable request framing fail
closed before forwarding. Content-Length, Transfer-Encoding and Connection remain
reserved. The HTTP/1 path and HTTP/2-to-HTTP/1 bridge share the same rewrite.

Place removals in the leading route statements before guards/auth helper calls,
or in an already-supported selected match arm; names must be literal safe
HTTP tokens. Like set/add, removal after guards/waits/for remains rejected.
Authentication reads (`req.authorization`, `req.uniqueHeader`) still observe the
original request. Therefore declare stripping first, then verify credentials,
then forward only on success. A rejected authentication response is never
forwarded. Removal modes reset at each request/HTTP/2 stream boundary.

See [examples/auth-proxy.rut](../examples/auth-proxy.rut). Explicitly remove each
configured credential source and any client identity fields you do not trust.
Query/body credentials and dynamically forwarding verified Identity fields are
separate capabilities; this helper only removes named header fields.

## JWT resource-server claims profile

`jwtDecode(token, secret)` retains its existing signature-only semantics.
After verifying the signature, `jwtClaimsValid(claims, issuer, audience) -> bool`
applies an explicit strict resource-server profile. Arguments are an unwrapped
Json and two unwrapped strings; user functions can shadow the builtin.

The profile requires a nonempty string `sub`, an exact case-sensitive decoded
`iss` match, a matching `aud` string or nonempty array of nonempty strings, and
`exp > now`. Optional `nbf` and `iat` must be integer dates no later than now.
All dates are signed 64-bit integer Unix seconds; fractions, exponents and
out-of-range values are rejected. Clock skew is zero. The shared JSON parser
rejects duplicate decoded member names (including escaped aliases), malformed
UTF-8, and byte/node/depth overflows. Empty configuration, invalid input, a failed
CLOCK_REALTIME read, or an invalid/nonpositive epoch clock returns false.
This profile does not verify a signature or provide revocation/JWKS by itself.

The check borrows its inputs, reuses existing bounded per-shard JSON scratch,
and returns a scalar without requiring a request arena or allocation. It does
not use monotonic `time.nowMicros()` for NumericDate comparisons.

`auth.jwtIdentity(verifiedClaims, issuer, audience, credentialId)` in the middleware
library applies this profile and typed subject decoding, then returns `Identity`
with method `"jwt"` and consumerId from the verified `sub`. Pass only the output
of a successful `jwtDecode`, never arbitrary parsed JSON. The credentialId is
trusted configuration, not an attacker-supplied JOSE header. Empty configuration
returns 503 and invalid claims return 401 with a Bearer challenge. The runnable
example first calls `auth.jwtDocument(authorization, secret)`, which composes
`bearerToken` and `jwtDecode` and returns verified Json or a challenged 401.
Then it calls the separate identity helper. Existing HS256/384/512 support is unchanged.
See [examples/jwt-claims-auth.rut](../examples/jwt-claims-auth.rut).

## JWT scope authorization (implemented)

`jwtHasScope(claims: Json, required: str) -> bool` checks one complete,
case-sensitive token in the top-level `scope` string. Use it only after
`jwtDecode` and `jwtClaimsValid` (or `auth.jwtDocument` and `auth.jwtIdentity`).
It does not authenticate a document. `&&` composes all-required scopes; `||`
composes alternatives. No implicit scopes or substring matching apply.

The full decoded list must follow [RFC 6749 section 3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3):
nonempty ASCII scope tokens separated by one space. Quotes, backslashes,
control/non-ASCII bytes, empty tokens, missing/wrong-type claims, duplicate
JSON keys and invalid required tokens fail closed. Array-valued `scp`/`scope`
claims are not part of this profile. Parsing reuses bounded JSON scratch;
there is no allocation or retained view.

The `/orders` example in `examples/jwt-claims-auth.rut` first verifies the
signature and identity profile, then uses `guard jwtHasScope(...)` with a 403
response and `WWW-Authenticate: Bearer error="insufficient_scope"`, following
[RFC 6750 section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1).
Invalid authentication remains 401; an authenticated identity lacking the
required scope is denied with 403. Validate dynamic policy configuration
separately; an empty required token always returns false.

Literal `response(..., headers: {...})` values decode string escapes like
ordinary expressions, including quoted challenge parameters. Decoded values
are validated again; escaped CR/LF/NUL cannot introduce header fields.

## HMAC-SHA256 and webhook authentication (implemented)

`hmacSha256Matches(message, key, signature)` returns bool. An optional fourth
string argument sets an exact wire-format prefix. All arguments are unwrapped
`str` values. It verifies HMAC-SHA256 over exact message bytes, including NUL
and non-UTF-8 bytes. The
signature must be exactly 64 lowercase hex characters, optionally preceded by
the exact fourth argument (a trusted prefix up to 64 bytes, empty by default). The
algorithm is fixed; no attacker-selected digest, decoding, normalization or
truncation is supported. Empty messages are valid; empty keys, invalid spans,
keys over 4096 bytes and messages over 1 MiB return false. Hashing uses stack
scratch with the pinned static OpenSSL SHA-256 primitive; equal-length digest
contents use `CRYPTO_memcmp`, and secret scratch is cleansed before return.
This builtin adds no grammar or dependency.

`auth.hmac(message, signature, key, consumerId, credentialId)` publishes an
Identity only after verification. `auth.rotatingHmac(...)` evaluates current
and previous slots, prefers current on a tie, and supports revocation by
removing the previous key. Both disabled slots or empty identity metadata
return 503; verification failure returns 401.

`auth.githubWebhook(body, signature, key, consumerId, credentialId)` requires
the exact `sha256=` prefix before the digest. Supply raw `req.body` and
`req.uniqueHeader("X-Hub-Signature-256").or("")`; duplicate headers reject even
when identical. See [webhook-auth.rut](../examples/webhook-auth.rut). Verify
before parsing or transforming JSON; payload signatures do not prevent replay.
Durable delivery deduplication remains the receiving application's duty.
The 1 MiB primitive bound does not extend the runtime's request-body limit.

This is not the Kong/APISIX canonical HTTP-signature protocol or Standard
Webhooks: those additionally define signed header lists, timestamp/nonce
validation, encoding and replay state. Their full profiles remain pending in
[auth coverage](auth-coverage.md).

## Digest and HMAC builtins (implemented)

The six digest calls `md5(data)`, `sha1(data)`, `sha224(data)`, `sha256(data)`,
`sha384(data)` and `sha512(data)` each take one unwrapped `str`. Their HMAC
counterparts `hmacMd5`, `hmacSha1`, `hmacSha224`, `hmacSha256`, `hmacSha384`
and `hmacSha512` take **key first, data second**. Each returns `str?`, containing
lowercase hexadecimal on success. The algorithm is fixed by the function name;
there is no default algorithm or implicit protocol decoding.

```swift
route POST "/sha256" {
    guard let digest = sha256(req.body) else { return 503 }
    return response(200, body: digest)
}
route POST "/signed" {
    let key = env("HMAC_SECRET")
    guard key != "" else { return 503 }
    guard let expected = hmacSha256(key, req.body) else { return 503 }
    guard constantTimeEqual(expected, req.uniqueHeader("X-Signature").or("")) else { return 401 }
    return 204
}
```

This example's custom X-Signature field contains bare lowercase hex. Protocols
such as GitHub Webhooks need their own header parsing policy. Hash/HMAC calls
accept no HTTP headers, prefixes or algorithm parameter. Use constant-time
comparison, rather than ordinary equality, for authentication signatures.

Input strings are exact byte spans: embedded NUL, non-UTF-8 and empty data are
valid. HMAC also mathematically supports an empty key; authentication modules
must explicitly reject disabled/empty credentials as above. No Unicode
normalization, JSON reserialization, base64 conversion or truncation occurs.
Digest lengths are 32/40/56/64/96/128 hex characters respectively.

Runtime data is limited to 1 MiB per call and HMAC keys to 4096 bytes. Exceeding
limits, unavailable result storage or exhausting the shared 256 KiB request
arena budget yields nil. Each result owns separate arena storage until request
retirement; later calls cannot overwrite it. Scratch hashing is allocation-free
and secret context/intermediates are cleansed. Request-body ingress limits are
independent. No new dependency or language keyword is added.

Calls may appear in ordinary request helpers, nested expressions after optional
unwrapping, and route local bindings. User functions/bindings shadow builtin
names. Hashing in `const`, timers and routes with `wait` is not implemented;
these fail at compilation. SHA-3, SHA-512/224, SHA-512/256 and arbitrary digest
selection are not part of this implemented set. MD5/SHA-1 remain compatibility
algorithms; authentication modules select their permitted algorithms explicitly.
See [hashing.rut](../examples/hashing.rut).


### Explicit JWT algorithm policy

`jwtDecode(token, secret, algorithm) -> Json?` binds verification to one trusted
algorithm string: exactly `HS256`, `HS384` or `HS512`. The third argument must
be provable at compile time (a literal, constant local or resolved `env()`);
request-derived values and dynamic helper parameters are rejected. Use the
fixed-algorithm middleware helpers when wrapping verification. The decoded JOSE `alg`
must match it. Empty, unsupported, case-mismatched or malformed policy returns
nil, even for an otherwise valid signature. The existing minimum key lengths
and strict JOSE/Base64url/JSON checks still apply. Algorithm policy is configuration,
never a value copied from the token or request. This follows
[RFC 8725 section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1).

The two-argument overload retains its existing HS256/384/512 behavior for
compatibility. Prefer the three-argument overload for new deployments.
`auth.jwtDocumentHs256` / `auth.jwtDocumentHs384` / `auth.jwtDocumentHs512`
bind the selected algorithm in configuration; empty secrets map to 503 and
invalid tokens to a challenged 401.
`examples/jwt-claims-auth.rut` pins HS256 before checking issuer, audience,
expiry and scopes. Signature verification does not replace claims policy.
This adds no algorithm, keyword, dependency, allocation or key-refresh mechanism;
asymmetric JWT/JWKS remain separate work.
