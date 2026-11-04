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
import "middleware/auth"                            // prefers .rut; falls back to an existing suffixless file
// Explicit .rut suffixes remain supported; if both files exist, .rut wins.
import "middleware/auth.rut"                        // namespace: auth
import Crypto                                      // built-in, statically linked crypto module
// Imports nest at most 2 levels deep (main → a → b, kMaxImportNestingDepth);
// a deeper chain is a compile error at the offending `import`, never a crash.
// The built-in Crypto module is not a filesystem import and does not consume
// an import nesting level.

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

`Bytes` is an immutable raw-byte view, distinct from `str`. Construct constants
with the existing `b"\x00\xff"` literal syntax (at most 4096 decoded bytes per
literal). `.count` is an `i32` byte count; `.isEmpty` is a Bool property.
Equality, inequality and generic `Eq` compare exact bytes, including NUL and
non-UTF-8 bytes. Helpers may accept/return Bytes, imports preserve its type,
and ordinary HTTP locals can hold Bytes values. `req.bodyBytes` borrows the
request body as Bytes under the same buffering/lifetime rules as `req.body`.
There is no implicit text conversion, ordering, concatenation, indexing or
regex API for Bytes.

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
req.set("X-User-ID", "123")  // ✅ replace/dedupe; statement-only; string values may be dynamic
req.add("X-Tag", "a")        // ✅ preserve existing fields and append; literal value
req.remove("Authorization")  // ✅ delete every matching field before forwarding
req.getAll("Accept")         // ⏳ [str]

// Route captures / query / cookies / body
req.params.id                // from :id — captures NEVER shadow built-ins
req.query("page")            // str? (first value)
req.queryAll("tags")         // ⏳ [str]
req.cookie("session")        // str?
req.body(User)               // typed parse, error-capable → guard let
req.body                     // raw body as str
req.bodyBytes                // raw body as Bytes; same request-body buffering rules
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
values (`set` also accepts an optional string, with nil meaning removal); its effects apply to successful direct and forwarded responses on routes
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

### Inbound mTLS pinned identity

The server accepts `--tls-client-ca PATH` with its existing TLS certificate
and key options and requires a client certificate during the TLS handshake.
The verified peer certificate's DER SHA-256 fingerprint is exposed as
`req.tlsClientCertSha256: str?`; it is nil on cleartext and ordinary
server-only TLS. The fingerprint is connection-owned and contains 64 lowercase
hexadecimal characters, with a fixed 64-byte inline slot cost even on cleartext
and ordinary TLS connections.
`auth.pinnedMtlsIdentity` compares it to a static canonical pin with
`Crypto.sha256HexValid`, returning 403 for a
missing/mismatched certificate and 503 for invalid pin configuration. The CA
file is read at listener startup; replacing
it requires listener restart. Route pin changes take effect for the next
request while the connection fingerprint remains fixed. Session resumption,
tickets and renegotiation are disabled for this profile. CRL/OCSP, SAN mapping
and durable revocation are not provided. See
[`mtls-pinned-auth.rut`](../examples/mtls-pinned-auth.rut).

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

// Current terminate handlers: up to 4 guard/if clauses over direction, text/binary type,
// message.len (< > == <= >= != integer literal, either side), text.matches(re),
// text ==/!= string literal (either side), text.isEmpty, and
// text.hasPrefix("literal"), text.hasSuffix("literal"), text.contains("literal").
// Text predicates
// compare raw payload bytes; use message.isText for text-only filtering.
// Literal predicates decode ordinary escapes, including embedded NUL.
// Empty prefixes/suffixes/substrings match every message; arguments must be literals.
// Conditions support !, &&, ||, parentheses and left-to-right short-circuiting.
// ! binds tighter than comparisons; && binds tighter than ||.
// At most 32 condition nodes (leaf predicates + binary operators); nesting is bounded.
// `message` has the built-in borrowed type WebSocketMessage. It is supplied only
// by this callback, never constructed or stored as an HTTP/connection value.
// Fields: fromClient/isText/isBinary: bool, len: i32 (payload bytes), text: str
// (borrowed raw bytes, also available for Binary messages).
// payload: Bytes — the complete payload for either message kind, borrowed only
// during the synchronous callback. payload.count and payload.isEmpty use byte
// semantics; compare with b"..." or pass to a Bytes helper. No UTF-8 decoding or
// copy occurs when reading the view. Text messages expose their encoded bytes.
// kind: WebSocketMessageKind (.text / .binary); direction: WebSocketDirection
// (.clientToUpstream / .upstreamToClient). Spell cases with their full type name:
// message.kind == WebSocketMessageKind.text. Both types support ==/!= and Eq
// helpers, with no integer/string/Bool coercion or ordering. They also work as
// ordinary helper parameters, return values and HTTP locals. They expose no
// control-frame cases. Existing fromClient/isText/isBinary remain conveniences.
// Pure helpers may accept the message or its scalar fields. Their inlined
// predicates support these fields, bool literals/equality (either order),
// Boolean composition, len/literal comparisons, text/literal equality and
// text.matches(re). Ordinary type checking is shared with HTTP helpers.
// The callback parameter may use any identifier; `message` is not implicitly
// bound when another name is chosen. Immutable callback lets support typed scalar
// literals/projections, message aliases, byte counts, comparisons and Boolean
// composition, including pure helper results in that subset. Lets require fresh
// names (json is reserved), and do not escape the callback. Text aliases can feed
// json.parse guards and text rewrites; message aliases can receive verdicts.
// Eight statements per block, including lets/guards/final verdict. Captured
// compile-time HTTP values keep their separate 16-local admission budget.
// The four-clause/32-condition-node limits remain. Optional, JSON and regex
// ordinary-let initializers remain unsupported. Bounded if/else verdict branches are supported:
// an if without else may exit early; a terminal if/else-if chain needs a final
// else. Each arm allows lets followed by a verdict or complete nested if/else
// tree, with its own lexical scope; every nested path must end in a verdict.
// A complete if/else chain must end its current block. Conditions use supported
// bool/helper/JSON predicates. Later arms are lazy; all arms are type checked.
// Each guard/if/else-if shares the same four-clause and 32-node budgets. The
// eight-statement block limit applies to each arm too. Branch close() uses 1000
// independently of the final else's close policy. Nested arms evaluate each
// parent condition once and skip sibling arms; an early nested tree's false path
// resumes after the whole subtree. Both arms count toward the existing limits.
// Arms may contain guards and early if statements before their terminal verdict.
// JSON if-let and else-if-let support the same parse/get/scalar initializer subset
// as guard-let. If-let names exist only in the true arm; guard-let names exist
// after success within their current block, never in the failure verdict. Present
// false, zero and empty string values bind successfully. Early-if false paths and
// guard success paths resume within the same arm, including its terminal verdict.
// Optional initializers may call pure helpers that normalize to these same JSON
// projections, including imported helpers and generic identity on unwrapped
// arguments. JSON arguments require earlier proof aliases; pointers must normalize
// to compile-time strings. The source must remain this message or its borrowed
// text. Helpers can conditionally return one projection, with nil on the other
// path; nesting and Boolean guard ... else { nil } are supported. Selectors use
// supported message predicates, run once when reached and skip extraction on nil.
// All selector/AND/presence nodes share the 32-node budget; one binding call still
// consumes one of four clauses. Helpers also support JSON guard-let / if-let
// with nil failure paths. Successful bindings can feed later get/scalar calls or
// be returned; presence proofs remain scoped to the success continuation and
// distinguish JSON paths. Returning the unwrapped binding does not repeat its
// presence check. Helpers may select different JSON projections and use supported
// projections as optional-binding fallback arms. Guard-let, terminal/early if-let
// specialize the continuation per selected kind/path; selectors run once, sibling
// alternatives stay lazy, and a missing selected value takes the caller failure.
// Present null/false values do not take optional-binding fallbacks. Copies count
// original source clauses once, but generated control/condition nodes and absence
// joins share 32 nodes; all recipes share the existing bounded policy tables.
// Nullable pure helpers may also return supported infallible immutable values:
// scalar/Bytes literals, borrowed message/fields, byte counts and supported
// comparisons/Boolean composition. Ordinary if-let/guard-let publishes these
// values only on success. False, zero and empty str/Bytes are present.
// Scoped helper bindings can feed later selectors, message text parsing and
// literal JSON pointers. Within nullable helpers, .or(default) / any(value, default)
// accepts the same infallible immutable defaults. Ordinary eager semantics are
// preserved: regex scans, effects and other fallible defaults remain rejected.
// JSON mutations, dynamic pointers, general optional computations, binding
// shorthand, loops and general computation remain unsupported.
func messageDocument(_ msg: WebSocketMessage) -> Json => json.parse(msg.text)
func jsonField(_ value: Json, _ pointer: str) -> Json => json.get(value, pointer)
func jsonText(_ value: Json) -> str => json.string(value)
// Inside callback: guard let doc = messageDocument(message) else { message.drop() }
// guard let field = jsonField(doc, "/name") else { message.drop() }
// if let text = jsonText(field) { message.forward(text) } else { message.drop() }
// HTTP reads/effects and message verdicts in helpers are rejected. Helpers cannot
// retain a message/payload past the callback.
func allowedMessage(_ msg: WebSocketMessage) -> bool =>
    !msg.fromClient || (msg.isText == true && msg.len <= 2048)
// Inside the callback: guard allowedMessage(message) else { message.drop() }
func isTextKind(_ kind: WebSocketMessageKind) -> bool => kind == WebSocketMessageKind.text
// Inside the callback: guard isTextKind(message.kind) else { message.drop() }
func isMarker(_ bytes: Bytes) -> bool => bytes.count == 2 && bytes == b"\x00\xff"
// Inside the callback: guard isMarker(message.payload) else { message.drop() }
// A terminate route can run up to eight existing top-level HTTP guards before
// websocket. These request reads and static failure responses run in the
// ordinary JIT handler before it connects to the WebSocket upstream. A
// guard-let binding is visible to later HTTP guards only; it cannot be captured
// by the separate message handler. Only compile-time lets and bounded request
// guards are supported here; helpers, effects, body reads, mutation, waits,
// loops, conditionals, decorators, and chains remain rejected. Bare websocket
// passthrough routes continue through the ordinary HTTP route pipeline.
guard let origin = req.uniqueHeader("Origin") else { return 403 }
guard origin == "https://allowed.example" else { return 403 }
return websocket(chat) { message in
    guard !message.fromClient || !message.isText || !message.text.matches(re".*spam.*") else {
        message.drop()
    }
    guard !message.fromClient || message.text != "ping" else { message.drop() }
    guard message.isText else { message.close(1008, "text only") }
    guard message.len <= 4096 else { message.close() }
    message.forward()
}

// After HTTP guards pass, terminate mode validates GET/HTTP/1.1, exactly one
// non-empty Host, exact Connection token and an Upgrade offer containing bare
// websocket (other valid protocol/version offers may coexist), one canonical
// 16-byte Base64 key, and one WebSocket Version before connecting upstream.
// One Content-Length: 0 is
// allowed; positive/duplicate Content-Length, Transfer-Encoding, TE and Expect
// are rejected with 400. A decimal Version from 0 to 255 without leading zeroes
// but other than 13 gets 426 with Upgrade, Connection: Upgrade, and
// Sec-WebSocket-Version: 13 (plus close semantics); malformed versions get 400.
// Protocol offers may use repeated fields or
// comma lists; nonempty ASCII tokens must be unique case-sensitively. A backend
// 101 is sent only with one matching Accept, a selected protocol that was offered
// (if any), exact Upgrade/Connection checks, a complete header, and no extensions.
// Invalid 101 closes before send. Non-101 remains ordinary HTTP; Origin stays an
// explicit application guard. Bare websocket(chat) passthrough keeps generic
// Upgrade behavior. This bounded supported shape is not full RFC 6455 conformance.

// Require one case-sensitive subprotocol on a terminate route. The string literal
// must decode to one nonempty ASCII HTTP token. Both named arguments may appear
// in either order, once each. Missing client offers get 400 before upstream
// connect. The backend receives only this offer and must select it in its 101;
// omission or mismatch closes before sending 101. The option requires a block.
return websocket(chat, subprotocol: "graphql-transport-ws", maxMessageSize: 4kb) { message in
    message.forward()
}
// Omitting subprotocol keeps optional, backend-selected negotiation.

// The runtime bounds a graceful Close or clean-EOF drain to about five
// seconds; a healthy quiet tunnel has no idle timeout.

// Validate a complete message with the existing JSON parser. Only presence
// comparisons and the document bindings shown below are supported here.
// JSON null is a valid document, so json.parse("null") succeeds.
// Parsing uses the ordinary JSON limits: 8 KiB input, 2048 nodes, depth 64.
// Values exceeding those bounds count as parse failures, even if valid JSON.
return websocket(chat) { message in
    guard !message.fromClient || !message.isText || json.parse(message.text) != nil else {
        message.close(1007, "invalid JSON")
    }
    message.forward()
}
// == nil, either operand order, !, && and || are supported with short-circuiting.
// Text payload access retains its raw-byte semantics; use isText to select Text messages.

// Unwrap a complete message's JSON, require a field (JSON null counts as present),
// then route on an exact JSON string value. Literal RFC 6901 pointers support
// nested objects, array indices, ~0 and ~1; an empty pointer selects the root.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let field = json.get(document, "/type") else { message.close(1008) }
    guard let kind = json.string(field) else { message.close(1008) }
    guard kind == "subscribe" else { message.drop() }
    message.forward()
}
// json.string(document) also checks a root JSON string. A get result must be
// unwrapped before json.string; missing, null, number, bool, array and object fail.
// String aliases support literal == / != plus isEmpty, hasPrefix, hasSuffix and
// contains with string literals. The predicates compare decoded bytes exactly.
// Bindings require fresh names and count toward the four-guard limit. Each reached
// check reparses within the JSON bounds; no document or borrowed string survives.
// Empty contains needles match every valid string; a failed/non-string JSON value
// still fails its binding. json.get accepts a previously guard-unwrapped Json
// selection too; its literal pointer is relative to that value. Dynamic paths,
// arbitrary extraction and mutation remain unsupported; no Unicode normalization occurs.

// Match an unwrapped JSON string's decoded bytes with a regex literal. Matches
// cover the whole value; use .* for substring rules. Escaped JSON characters,
// Unicode and NUL are decoded before scanning, without normalization.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let field = json.get(document, "/topic") else { message.close(1008) }
    guard let topic = json.string(field) else { message.close(1003) }
    guard !topic.matches(re"private[.][0-9]+") else { message.drop() }
    message.forward()
}
// !/&&/|| short-circuit. Patterns use existing compile-time regex validation.
// Only guard-unwrapped json.string aliases support this operation; optional calls,
// Json values, numberText/stringify and other scalar aliases reject. A reached
// decoding/scan error closes before applying negation. The existing workspace,
// regex database ownership, native relocation and guard/node limits are retained.

// Select nested JSON values with separate optional guards. Empty pointers retain
// the source value, including JSON null. Escaped tokens, indices and NUL work as
// ordinary RFC 6901 pointers. Presence comparisons also accept selected Json aliases.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let payload = json.get(document, "/payload") else { message.close(1008) }
    guard let field = json.get(payload, "/name") else { message.close(1008) }
    guard let name = json.string(field) else { message.close(1003) }
    message.forward("hello " + name)
}
// The chain folds at compile time into a root-relative path, capped at 8192 bytes.
// Four guards and 32 condition nodes remain the limit. Typed scalar aliases cannot
// be containers, and a binding is unavailable in its own failure branch.

// Compare optional JSON scalar extraction directly, avoiding a typed-binding guard.
// Sources must be validated document/selected Json aliases. Both operand orders,
// ==/!= with a matching String/Bool/Int literal or nil, and !/&&/|| are supported.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let payload = json.get(document, "/payload") else { message.close(1008) }
    guard let field = json.get(payload, "/enabled") else { message.close(1008) }
    guard json.bool(field) == false else { message.drop() }
    message.forward()
}
// json.string(field) == "subscribe" and json.int(field) == 42 work the same way.
// Failed extraction is nil: == false requires actual false; != false also matches
// nil. A parse/missing-field guard still fails first. json.int accepts only exact
// signed i64 integer tokens; fraction/exponent/overflow is nil. String escapes and
// comparisons retain the existing byte semantics. ==/!= nil tests extraction success.
// Bare optional Bool/!json.bool(field), direct integer ordering, mismatched literal
// types and call-to-call comparisons reject. Unwrap an alias for ordering, string
// predicates or forwarding. The four-guard / 32-condition-node limits remain.

// Forward one previously guard-unwrapped JSON string alias, optionally with fixed
// UTF-8 affixes. The value is decoded again only when this rewrite is selected.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let field = json.get(document, "/name") else { message.close(1008) }
    guard let name = json.string(field) else { message.close(1003) }
    message.forward("hello " + name + "!")
}
// json.string(document) may select a root string. A rewrite can use one previously
// successful String alias or one message.text source, never both or two aliases.
// Document/selected-value and other typed aliases, calls, and dynamic paths are
// rejected. Fixed literals and compile-time route strings may surround the source.
// Binary input may produce Text from a JSON string; message.text still requires Text.
// The selected value is parsed and copied synchronously into the existing output
// slice; no borrowed JSON document/string survives the callback.

// Preserve a JSON number's exact source lexeme as a typed text alias. No float or
// Int conversion occurs: -0, 1.2300e+999 and values larger than i64 stay unchanged.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let field = json.get(document, "/amount") else { message.close(1008) }
    guard let amount = json.numberText(field) else { message.close(1003) }
    message.forward("amount=" + amount)
}
// numberText aliases support literal string comparisons and existing string
// predicates, not numeric comparisons, arithmetic or alias-to-alias comparisons.
// One prior alias may be the dynamic source with fixed UTF-8 affixes; its exact token
// is copied synchronously to the owned output slice. Binary JSON also emits Text.

// Bind the ordinary compact serialization of any JSON value, then use it for both
// a literal predicate and a fixed-affix rewrite.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let encoded = json.stringify(document) else { message.close(1003) }
    guard encoded.contains("\"ok\"") else { message.drop() }
    message.forward("payload=" + encoded)
}
// Strings and object keys are escaped as JSON text; member order and number lexemes
// are preserved. Serialization is bounded, and the result is copied to owned output
// before asynchronous sending.

// JSON Bool fields are type-checked; false is a successfully unwrapped value.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let field = json.get(document, "/enabled") else { message.close(1008) }
    guard let enabled = json.bool(field) else { message.close(1003) }
    guard enabled else { message.drop() }
    message.forward()
}
// A Bool alias supports bare truth, !, && / ||, and == / != with a Bool literal
// on either side. Comparison leaves are limited to the bare alias and one literal.
// json.bool(document) checks a root Bool. Missing/null/non-Bool values fail binding.

// Signed 64-bit JSON integer range checks use exact integer tokens.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let field = json.get(document, "/count") else { message.close(1008) }
    guard let count = json.int(field) else { message.close(1003) }
    guard count >= 1 && count <= 1000 else { message.drop() }
    message.forward()
}
// json.int(document) checks a root integer. Integer aliases compare to Int literals
// with == / != / < / <= / > / >= in either order. No arithmetic or alias comparison;
// fractions, exponents and values outside signed i64 fail the binding.

// Apply both kind and cardinality checks to a root array within four guards.
return websocket(chat) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let tag = json.kind(document) else { message.close(1003) }
    guard let amount = json.count(document) else { message.close(1003) }
    guard tag == "array" && amount <= 32 else { message.drop() }
    message.forward()
}
// json.kind(document) also checks the root and binds one of null/boolean/number/
// string/array/object; JSON null is a successful "null" kind. Compare its alias
// only to string literals with == / !=. json.count checks direct array elements
// or object members; empty containers bind zero. Its Int literals must fit i32.
// Selected-field chains need json.get too, so only one complete selected-field
// kind/count check fits under the four source-guard limit.

// Fixed text replacement in the final verdict or a guard branch. Empty literals
// emit empty Text messages; binary input becomes Text. Literals must fit maxMessageSize
// and the single-slice cap. General expressions/interpolation remain unsupported.
return websocket(chat, maxMessageSize: 4kb) { message in
    guard message.fromClient && message.isText else { message.forward() }
    message.forward("message replaced")
}

// Fixed Binary replacement reuses exact-byte literals, including immutable aliases
// and pure helper results normalized to those literals. It accepts arbitrary bytes,
// including NUL and invalid UTF-8, and emits Binary even for Text input.
return websocket(chat, maxMessageSize: 4kb) { message in
    guard message.fromClient else { message.forward() }
    guard message.len != 0 else { message.forward(b"") }
    message.forward(b"\x00\xff")
}
// A replacement must normalize to one adjacent b"..." literal, at most 4096 decoded
// bytes, and fit maxMessageSize. Supported escapes: \n, \r, \t, \\, \" and \xHH (NUL is \x00).
// Byte concatenation, Unicode escapes and interpolation remain unsupported.
// Guard branches choose independent Text/Binary replacements; bare forward()
// preserves the original type and payload. Invalid Text input is still rejected.

// The complete borrowed payload may also be sent as Binary, including aliases,
// pure helper results and successful optional bindings of that Bytes value.
return websocket(chat) { message in
    let bytes: Bytes = message.payload
    message.forward(bytes)
}
// Equivalent: message.forward(message.payload). Text input becomes Binary without
// changing its encoded bytes; Binary input is preserved byte-for-byte. Empty Bytes
// emits an empty Binary. Bare forward() still preserves the original message kind.
// Only the current message's complete payload is supported dynamically; slicing,
// concatenation and unrelated/request-borrowed Bytes output remain unsupported.
// Reassembly/output must fit maxMessageSize and the existing single-slice cap.

// Terminate mode defaults to 16370 bytes (16 KiB slice minus the maximum 14-byte
// WebSocket header). Explicit `maxMessageSize` values must be 1b through 16370b;
// values such as 16kb or 64kb are rejected because larger-message buffering is not implemented.

// Add fixed UTF-8 affixes around one complete Text message, using String +.
// Parentheses, concatenated literals, and compile-time-known route let strings
// (including aliases) are accepted, with at most 32 expression nodes.
// Request-derived strings, optional values, and calls are rejected.
// At most one message.text reference may appear; repeated references/interpolation reject.
// Binary messages selected for this operation fail the tunnel; guard the opcode first.
// The complete rewritten output must fit maxMessageSize and the single-slice cap.
let label = "audit:"
return websocket(chat, maxMessageSize: 4kb) { message in
    guard message.isText else { message.forward() }
    guard !message.text.hasPrefix("audit:") else { message.forward("[" + message.text + "]") }
    message.forward(label + message.text)
}

// Each guard may choose its own replacement; the first failing guard wins.
return websocket(chat) { message in
    guard message.text != "ping" else { message.forward("pong") }
    guard message.text != "hello" else { message.forward("welcome") }
    message.forward()
}

// Guard branches can choose independent close codes and fixed UTF-8 reasons.
// close(code) uses an empty reason; a bare close() keeps the route's default policy.
return websocket(chat) { message in
    guard message.len <= 4096 else { message.close(1009, "message too large") }
    guard !message.text.contains("secret") else { message.close(1008, "policy violation") }
    message.forward()
}

// Close with a status and fixed UTF-8 reason (also accepted in guard branches).
// Reason length is at most 123 UTF-8 bytes; empty reasons and NUL are supported.
// Handler closes send the configured code/reason to both peers. Peer closes
// retain their original forwarding and normal-closure echo behavior.
return websocket(chat) { message in
    guard message.fromClient && message.text.contains("secret") else { message.forward() }
    message.close(1008, "policy violation")
}

// Transparent proxy: no application message processing.
return websocket(chat)
// Message handlers above see complete Text/Binary payloads. No frame binding,
// wire opcode, FIN, mask, continuation, or ping/pong API is exposed.

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

## Math library (implemented)

Import the ordinary source library relative to your file. From `examples/`:

```swift
import * as math from "../lib/math.rut"

// All arguments to each helper must have the same type conforming to Ord.
let low = math.min(3, 5)
let high = math.max(3, 5)
let bounded = math.clamp(9, 2, 6)  // 6
```

Use a namespace alias to keep the global integer `min` and `max` builtins
available alongside the generic helpers. Ordinary or selective imports named
`min`/`max` shadow those unqualified builtins.

The library exports `min<T: Ord>`, `max<T: Ord>` and `clamp<T: Ord>` through
the existing file namespace and selective-import mechanisms. Helpers inline
through the normal compiler pipeline; no runtime math ABI or dependency is
added. Current generic type binding supports i32 and other ordered types such
as strings, but rejects i64. For i64, use the existing global integer `min/max`
builtins and compose clamping as `max(lower, min(value, upper))`.

`clamp(value, lower, upper)` is `max(lower, min(value, upper))`. The interval
is closed; equal or reversed bounds return `lower`. Validate `lower <= upper`
separately when configuration requires rejection of reversed bounds.

Existing global integer `min/max` builtins remain available with their literal
width adoption and single-evaluation behavior. The source library uses ordinary
helper inlining and its existing evaluation rules. `abs`, `sqrt` and `pow` are
not provided. Runnable example: [math.rut](../examples/math.rut).

## Built-ins (call them, never reimplement)

```
string:  s.len s.isEmpty s.contains s.upper()/lower()/trim()
         s.replace/split/slice s.matches(re"") s.match(re"")
         ⏳ s.hasPrefix/hasSuffix/trimPrefix/trimSuffix
hash:    md5/sha1/sha224/sha256/sha384/sha512(data) -> str? (lowercase hex)
         hmacMd5/hmacSha1/hmacSha224/hmacSha256/hmacSha384/hmacSha512(key, data) -> str?
         ⏳ fnv32 fnv64
jwt:     jwtDecode(tok, secret) -> Json? (HS256/384/512 verified claims;
         decode with json.decode/json.get). jwtVerifyRs256(tok, policy) -> Json?
         (static JWKS + claims policy); jwtVerifyEs256(tok, policy) -> Json?
         (local P-256 JWKS + claims policy). jwtHasGroup(claims, required) -> bool.
         Fixed-profile HS256 jwtIssueHs256(subject, issuer, audience, key,
         ttl:i32) -> str?; Crypto.issueJwtHs256 qualified wrapper;
         jwtIssueHs256WithId(subject, issuer, audience, tokenId, key,
         ttl:i32) -> str?; Crypto.issueJwtHs256WithId qualified wrapper;
         jwtIssueHs256WithIdAndScope(subject, issuer, audience, tokenId, scope,
         key, ttl:i32) -> str?; Crypto.issueJwtHs256WithIdAndScope wrapper;
         ⏳ other RS/ES algorithms and arbitrary-claims DSL jwtEncode
crypto:  aesGcmEncrypt/Decrypt randomBytes(n) uuid()
encode:  base64 base64url hex urlEncode urlDecode htmlDecode unicodeNormalize
time:    time.nowMicros() -> i64 (monotonic µs; latched per invocation — all
         uses in one request see the same value)
         — now()/time(s)/Duration arithmetic still ⏳
math:    max(a, b) min(a, b) (integer builtins; imported lib/math.rut also
         provides generic math.min/max/clamp)
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

`req.headerCount("Name") -> i32` counts all case-insensitive occurrences in
that original request. Its nonempty literal name must contain only HTTP token
bytes. A missing field returns 0; a single empty field still returns 1;
duplicates return 2 or more, including identical values. Invalid/incomplete
request parsing returns -1, never 0. Test `== 0` to prove absence, not `<= 0`.
The existing parser's 64-field bound is unchanged; overflowing it fails parsing
rather than hiding an extra credential. The native helper also rejects invalid
field names with -1. This count is not credential validation: combine count 1
with the corresponding singleton read and verifier. Counts observe original
headers even after set/add/remove mutations and work in ordinary helpers;
timer/request-free contexts reject the operation. No keyword or dependency is
added, and the synchronous bounded scan allocates no memory and retains no views.

## Static authentication helpers

See [examples/authentication.rut](../examples/authentication.rut) and
[examples/middleware/auth.rut](../examples/middleware/auth.rut). These are ordinary
Rut functions returning `Identity { consumerId, credentialId, method }`:

- `auth.apiKey(authorization, key, consumerId, credentialId)` verifies an opaque
  Bearer key. Scheme spelling is case-insensitive and accepts 1*SP.
- `auth.apiKeyOrAnonymous(count, authorization, key, consumerId, credentialId, anonymousId)`
  takes `req.headerCount("Authorization")` and `req.authorization.or("")`
  from the same original request field. Only count 0 with an empty value returns
  `Identity(consumerId: anonymousId, credentialId: "", method: "anonymous")`.
  Count 1 requires valid Bearer verification; empty/invalid/duplicate fields or
  parsing failure return 401 with a Bearer challenge, never an anonymous fallback.
  Empty configuration or identical authenticated/anonymous Consumer IDs returns
  503. The anonymous ID must be explicitly allowed by downstream policy; an
  existing `requireConsumer` check can reject it with 403.
  See [anonymous-auth.rut](../examples/anonymous-auth.rut).
- `auth.multiAuthOrAnonymous(count, authorization, first, second, anonymousId)`
  combines the two-Consumer Bearer/Basic policy below with absence-only anonymous
  access. Read count and singleton value from the same original Authorization
  field. Count 0 and an empty value returns the configured guest with empty
  credential ID and method `anonymous`; count 1 must pass `multiAuth`.
  Empty, malformed, wrong or duplicate credentials, parse failures and
  inconsistent count/value inputs return 401 with both Bearer and Basic
  challenges. Invalid Consumer configuration, an empty guest ID, or a guest ID
  equal to either configured Consumer ID returns 503 even without credentials.
  Disabled slots cannot authenticate and never trigger guest fallback.
  Authorization remains explicit: `requireAnyConsumer(identity, firstId, secondId)`
  can reject guests with 403. Request credential removal does not change the
  original presence evidence. See [optional-multi-auth.rut](../examples/optional-multi-auth.rut).
- `auth.headerKey(req.uniqueHeader("X-API-Key").or(""), key, consumerId, credentialId)`
  verifies a custom header key. Do not replace uniqueHeader with first-field reads.
- `auth.multiHeaderKey(presented, first, second)` accepts one singleton custom
  header key for either of two configured Consumers. Use
  `auth.HeaderKeyConsumer(consumerId: ..., key: ..., credentialId: ...)` values;
  pass `req.uniqueHeader("X-API-Key").or("")`. Empty keys disable a Consumer,
  but both IDs must be nonempty and distinct, and at least one key must be
  enabled. Identical enabled keys are a 503 configuration error. Failure is a
  challenged 401; success uses configured identity metadata and method `apiKey`.
  Strip the credential explicitly with `req.remove("X-API-Key")` before
  forwarding when the upstream should not receive it.
- `auth.rotatingHeaderKey(presented, currentKey, previousKey, consumerId, currentId, previousId)`
  reads the same singleton custom field and verifies either configured opaque
  key. Empty keys disable slots, even for an empty/missing presented field.
  Both credential IDs must remain nonempty; current wins when both keys match.
  Removing the previous key revokes it after configuration reload/restart.
  Failure returns 401 with `WWW-Authenticate: ApiKey`; missing metadata or two
  disabled slots return 503. Unlike Bearer authentication, the presented value
  is the raw key with no scheme prefix or Base64 transformation.
- `auth.headerKeyOrAnonymous(count, presented, key, consumerId, credentialId, anonymousId)`
  pairs `req.headerCount("X-API-Key")` with
  `req.uniqueHeader("X-API-Key").or("")` from the same original request field.
  Only count 0 and an empty value returns the configured guest, empty credential
  ID and method `anonymous`. Count 1 must match the nonempty configured key.
  Empty/wrong/duplicate fields, parsing failure and inconsistent count/value
  arguments return a challenged 401. Empty configuration or equal authenticated
  and guest IDs returns 503, including on the anonymous path. Successful key
  authentication retains method `apiKey`. Downstream authorization may deny
  the guest with 403. Removal effects do not change original presence evidence.
  Only the selected custom header participates: Authorization, query and body
  values are not alternative sources. See
  [header-key-policies-auth.rut](../examples/header-key-policies-auth.rut).
- `auth.basic(authorization, credentials, consumerId, credentialId)` takes configured
  `user:password` bytes; password may contain colons or be explicitly empty.
- `auth.rotatingBasic(authorization, currentCredentials, previousCredentials, consumerId, currentId, previousId)`
  checks both configured `user:password` slots. Empty slots are disabled; both
  IDs must be nonempty. Current wins a tie; removing the previous slot revokes it.
  Invalid credentials receive a Basic challenge; invalid configuration returns 503.
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
- `auth.multiAuth(authorization, first, second)` accepts two trusted
  `auth.ConsumerCredentials(consumerId: ..., key: ..., credentials: ...,
  keyId: ..., passwordId: ...)` values. Each Consumer may use Bearer or Basic;
  empty secrets disable slots. Consumer IDs must be distinct, all IDs nonempty,
  and at least one slot enabled. Sharing a nonempty same-method secret across
  Consumers returns 503. Missing/invalid/duplicate Authorization returns 401;
  success returns the matched Consumer, credential ID and method. This is a
  fixed two-Consumer configuration, with restart-based rotation/revocation.
  See [multi-consumer-auth.rut](../examples/multi-consumer-auth.rut).
- `auth.headerKeyAndBasic(presentedKey, authorization, key, credentials, consumerId, policyId)`
  requires both an opaque header key and Basic credentials for the configured
  Consumer. Use `req.uniqueHeader("X-API-Key").or("")` and
  `req.authorization.or("")`; neither factor is optional. Either failure returns
  401; empty configuration returns 503. The returned method is `apiKeyAndBasic`,
  and credentialId is the configured ID of the required pair.
- `auth.requireAnyConsumer(identity, first, second)` permits either exact,
  case-sensitive configured Consumer ID after authentication. It preserves the
  Identity, returns 403 outside the set and 503 for an empty policy ID.
  This is a two-member allow union; chained single-consumer allow checks remain
  intersections. It does not provide dynamic group membership.
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
Query/body credentials require separate handling. To forward a verified Identity,
use `req.set("X-Consumer-ID", identity.consumerId)` in a selected match arm
after authentication, as in the example. Replacement removes every client-supplied
field with that name. Runtime values are validated and copied into bounded
request-owned storage; invalid values or exhausted storage fail forwarding closed.

## Password verification prefix

`passwordVerifyHeader(header, record, timeoutMs) -> i32` is supported as the
initializer of the first direct route `let`. All three arguments must resolve
at compile time: a 1–128-byte HTTP field-name token, a canonical fixed-profile
password record, and an integer timeout of 1–60000 milliseconds. `env("...")`
may supply the record at compilation/load time. A user function may shadow the
builtin. Calls in helpers, guards, later statements, timers or pipelines, and
routes containing explicit `wait`, are rejected. No new keyword is added.

```rut
route POST "/login" {
    let result = passwordVerifyHeader("X-Password", env("PASSWORD_HASH"), 5000)
    guard result != -1 else { return 503 }
    guard result != -2 else { return 504 }
    guard result == 1 else { return 401 }
    return 200
}
```

The helper reads exactly one case-insensitive matching request header. Missing,
duplicate, empty or over-1024-byte credentials return `0`. HTTP parsing applies
its normal field-value whitespace rules; this transport is not an arbitrary
binary password API. Serve credential routes over TLS.

The result is `1` for a match, `0` for rejection, `-1` for unavailable service
or exhausted capacity, and `-2` when the original monotonic deadline expires.
Only `1` authenticates. Pending verification suspends before later route effects
and retries the constant-only prefix using existing timer yields (at most 10 ms).
It never runs PBKDF2 on the shard, extends a deadline on retry or exposes Pending
to Rut. At exact expiry even a completed match is rejected.

Each requiring shard automatically owns one worker and eight task slots. Startup
or the first requiring reload starts it off-shard before publishing the config.
The service survives config retirement and stop/join, and joins/wipes on shard
shutdown. HTTP/1 request generations and HTTP/2 stream IDs fence abandoned work;
HTTP/2 retains its existing single suspended stream limit. Compiler/JIT/native
artifact metadata carries this requirement. See
[the password example](../examples/password-header-auth.rut) and
[auth coverage](auth-coverage.md#rut-password-verification-and-worker-lifecycle).

Hash creation remains offline, through the native API or the
[`rut-password` provisioning tool](password-provisioning.md). The tool is not a
Rut builtin and cannot run on the shard. This prefix uses one fixed record;
user lookup/persistence, registration, reset/change, automatic rehash and session
or JWT login orchestration are not implemented by it. Basic auth keeps its
existing static credential semantics.

### Fixed-account password/JWT composition

`auth.passwordIdentity(result, consumerId, credentialId)` maps the terminal result
of the prefix to an `Identity` with method `"password"`. Only result `1` succeeds;
`0` returns 401 with `Cache-Control: no-store`, `-2` returns 504, and unavailable
or unknown states return 503. Empty configured IDs return 503. This pure Rut
helper performs no KDF and accepts an ordinary integer; call it only with the
actual verifier result. Neither integers nor constructible Identity values carry
authentication provenance.

[password-jwt-login.rut](../examples/password-jwt-login.rut) composes existing
primitives for one configured account. `PASSWORD_HASH`, `PASSWORD_SUBJECT` and
`JWT_ISSUE_KEY` resolve at load/compile time. Its POST `/login` route uses the
actual peer IP with a process-shared `@rateLimit`: five initial attempts, then
one per twelve seconds. Admission runs before the handler/KDF; missing,
duplicate and incorrect credentials spend the same budget. Forwarding and
identity headers do not select the account or limiter key. Limits are bounded
and process-local, with the collision semantics documented above; there is no
cross-node quota or durable lockout.

After verification, the route generates a UUID v4 `jti` and issues HS256 for
the trusted subject, issuer `rut-password-login`, audience `orders`, scope
`orders.read` and a 300-second lifetime. The compact JWT response has Content-Type
`application/jwt`, `Cache-Control: no-store` and `Pragma: no-cache`. The GET
`/private` route pins HS256, validates issuer/audience and age/lifetime, then
requires the configured scope. Serve the login route over TLS. Provision hashes
offline with the native random-salt API and protect resolved native artifacts.

This is a fixed-account composition, without registration, password reset/change,
a user database, refresh tokens, cookies or a durable session/revocation store.
Changing the password prevents future login with the previous password; already
issued tokens retain their original lifetime unless separately revoked or their
signing key is removed. There is no implicit logout or password-change revocation.

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

`jwtClaimsValidWithLifetime(claims, issuer, audience, maxAge, maxLifetime) -> bool`
adds mandatory positive integer `iat`, `iat <= now < exp`, and inclusive maximum
token-age and token-lifetime limits. The builtin takes nonoptional `i64` seconds
and can use dynamic `i64` values; convert an `i32` explicitly with `i64(value)`.
The helper samples CLOCK_REALTIME once and fails closed on an
invalid clock or claims. It has the same strict issuer, audience, and expiry
profile described above. The middleware
`auth.jwtIdentityWithLifetime(verifiedClaims, issuer, audience, credentialId,
maxAge, maxLifetime)` takes positive `i32` configuration limits, applies the
policy to signature-verified JSON, decodes
the typed subject and returns `Identity` with method `"jwt"`; invalid config
returns 503 and invalid claims return 401 with Bearer `invalid_token`.
As with `auth.jwtIdentity`, verify the signature first and pass only that
verified document. See [examples/jwt-lifetime-auth.rut](../examples/jwt-lifetime-auth.rut).

The native `jwt_claims_valid_with_lifetime` API additionally requires a
positive integer `iat`, `iat <= now < exp`, and inclusive maximum token-age and
token-lifetime limits. This is a stricter Rut policy choice; [RFC 7519 §4.1.6](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6)
does not make `iat` mandatory or define these bounds for every JWT. The helper
checks claims only and does not verify signatures.

`auth.requireUnrevokedJwt(document, first, second)` rejects a verified JWT with
an absent, non-string or empty `jti`, or an exact case-sensitive match to either
nonempty configured revoked ID, with a Bearer `invalid_token` 401. Empty slots
are disabled. Call it only after signature and issuer/audience/time validation,
and keep each static revoked-ID snapshot scoped to that trusted issuer. Updating
the snapshot requires configuration replacement; it is limited to two IDs and
does not provide live, durable, cross-node revocation. [RFC 7519 §4.1.7](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7)
defines `jti` as a JWT identifier, but does not itself provide a revocation store.

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

`jwtHasGroup(claims: Json, required: str) -> bool` checks an exact,
case-sensitive nonempty string in the top-level `groups` array. Every array
entry must be a nonempty string; a malformed entry fails the whole check even
after a match. Repeated array values are allowed. Use it only after signature
verification and the required issuer, audience, and time checks. Authentication
failures remain 401; a verified identity without the required group receives
403. It does not authenticate a document or read client-supplied identity
headers. See [examples/jwt-groups-auth.rut](../examples/jwt-groups-auth.rut).

Literal `response(..., headers: {...})` values decode string escapes like
ordinary expressions, including quoted challenge parameters. Decoded values
are validated again; escaped CR/LF/NUL cannot introduce header fields.

## Crypto system module (implemented)

`import Crypto` exposes bounded operations backed by Rut's statically linked C
crypto ABI. It does not allow arbitrary foreign symbols or dynamic libraries.
Functions can be called as `Crypto.digestSha256(data)` or by their unqualified
names. A local declaration with the same name takes precedence unqualified;
the qualified form still selects the module function. Digest and MAC functions
return optional lowercase hex strings with request-owned storage:

- `digestMd5`, `digestSha1`, `digestSha224`, `digestSha256`, `digestSha384`, `digestSha512` take one `str`.
- `macMd5`, `macSha1`, `macSha224`, `macSha256`, `macSha384`, `macSha512` take key and data `str` values.
- `equal(a, b)` compares bounded strings in constant time; `hmacSha256Valid(message, key, signature, prefix)` and `webhookValid(id, timestamp, signature, body, rawKey)` verify the profiles below.
- `signedRequestValid(method, target, authorization, date, digest, body, keyId, key)` verifies the fixed signed-request subprofile below.
- `jwtAny(token, secret)`, `jwtHs256`, `jwtHs384`, `jwtHs512`, and `jwtRs256(token, policy)` retain the existing JWT verification profiles and return optional `Json`.

The existing global operations remain available for compatibility. The module
is compiler-owned and does not depend on a source file in the deployment.

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

`standardWebhookValid(id, timestamp, signature, body, rawKey)` returns a nonoptional
`bool` and requires five unwrapped `str` arguments. It exposes the native bounded
Standard Webhooks symmetric profile with the exact original body and decoded secret
bytes (not `whsec_` serialization). The synchronous runtime samples `CLOCK_REALTIME`,
fails closed on clock failure or nonpositive time, and enforces the fixed inclusive
300-second freshness tolerance. Use `req.uniqueHeader(...).or("")` for each webhook
field to reject duplicates. This verifies freshness and integrity; callers must
deduplicate verified IDs durably across shards and nodes before side effects.
`auth.standardWebhook(id, timestamp, signature, body, rawKey, consumerId, credentialId)`
returns a configured `Identity` after verification; empty key configuration or
empty identity metadata returns 503, while malformed input, an oversized key,
or invalid signatures return 401.
`auth.rotatingStandardWebhook(id, timestamp, signature, body, config)` with an
`auth.WebhookRotation` configuration checks both configured key
slots and reports the matching configured credential ID; current wins a tie.
Empty keys disable individual slots, and two disabled slots or empty identity
metadata return 503. Removing the previous key revokes that slot.
See [standard-webhook-auth.rut](../examples/standard-webhook-auth.rut). The builtin
uses dedicated HIR/MIR/RIR lowering and adds no keyword or dependency.

`Crypto.signedRequestValid(method, target, authorization, date, digest, body,
keyId, key)` and `auth.signedRequest(keyId, key, consumerId, credentialId)`
implement a fixed native APISIX-style HMAC-SHA256 signed-request subprofile.
The low-level `Crypto` call verifies only the values supplied to it; use the
request-bound `auth.signedRequest` policy or reject unsupported framing and
ensure the supplied body is complete yourself.
`auth.signedRequest` reads the implicit request's actual `req.method`, original `req.path` including
query, unique Authorization/Date/Digest fields, and complete `req.body`; it
rejects chunked HTTP/1 bodies and requires the compiler/runtime body completion
gate. Rut-exposed bodies are limited to 16 KiB; larger bodies fail closed. The
native API independently supports up to 1 MiB bodies. Unknown, duplicate, or
missing Authorization parameters, duplicate singleton headers, malformed
canonical Date/Digest/signature values, stale or future dates, and unsupported
methods fail with 401 and `WWW-Authenticate: Signature`. Empty trusted key or
identity metadata returns 503. Identity fields come only from configuration;
downstream authorization remains explicit and can return 403. Remove the
Authorization field before forwarding credentials to an upstream. Freshness
does not prevent replay. This is not full APISIX or Kong plugin compatibility
or full HTTP Message Signatures, and does not add remote key discovery or
replay storage. Host/authority and nonce are not signed; scope trusted keys to
an endpoint or route, and use durable deduplication for replay-sensitive side
effects. See
[signed-request-auth.rut](../examples/signed-request-auth.rut).

`auth.SignedRequestRotation` provides trusted `currentKeyId`, `currentKey`,
`previousKeyId`, `previousKey`, `consumerId`, `currentId`, and `previousId`
fields for `auth.rotatingSignedRequest(config)`. A key ID and its key must both
be empty to disable a slot, or both nonempty to enable it. At least one slot is
required, and enabled key IDs must differ. All identity metadata is required
even when its slot is disabled. Configuration errors return 503 before request
verification; invalid or revoked credentials return 401 with the Signature
challenge. Both enabled slots verify the same captured request fields, and the
matching credential ID is returned. Clearing the previous pair revokes it.
This policy has no remote key refresh or replay store. See
[`signed-request-rotation.rut`](../examples/signed-request-rotation.rut).

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

`auth.rotatingGithubWebhook(body, signature, currentKey, previousKey, consumerId,
currentId, previousId)` adds a static two-key window with that same strict wire
profile. Supply the same original raw body and singleton signature field to both
slots. Empty keys disable slots; both credential IDs must stay nonempty even for
a disabled slot. Current wins if both keys match. Two disabled keys or empty
identity metadata returns 503; all verification failures return 401. Removing
the previous key revokes it after configuration reload/restart. Successful
identity metadata comes from the matched configuration, with method `hmac`.
Neither slot accepts bare hex, SHA-1, uppercase hex, duplicate fields or changed
body bytes. No delivery-ID, timestamp or replay store is added. See
[github-webhook-rotation-auth.rut](../examples/github-webhook-rotation-auth.rut).
The example inherits the existing HTTP/1 buffered-body admission profile:
chunked requests receive 400 before the authentication handler runs.
The 1 MiB primitive bound does not extend the runtime's request-body limit.

Kong/APISIX canonical HTTP-signature protocols define additional signed header
lists, timestamp/nonce validation, encoding and replay state; those profiles
remain pending in [auth coverage](auth-coverage.md). Standard Webhooks freshness
does not enforce ID uniqueness, so durable replay storage remains the receiver's responsibility.

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
Other asymmetric algorithms remain separate work; configured RS256 verification
and its bounded remote-JWKS profile are described below.

The native `jwt_hs256_issue` API and Rut/JIT `jwtIssueHs256` builtin emit a
compact HS256 token with only
`sub`, `iss`, `aud`, `iat` and `exp`, and a fixed `alg=HS256`, `typ=JWT`
header. It requires a 32–4096-byte key, nonempty valid UTF-8 claim strings,
positive Unix time, and a 1–86400-second TTL with checked expiry addition.
NUL and ASCII controls are rejected; quotes and backslashes are escaped.
Payload and output are bounded to 8192 and 11004 bytes respectively. The
builtin samples realtime once per request and stores successful output in the
request-owned JSON arena. The qualified `Crypto.issueJwtHs256` wrapper and
`auth.jwtForIdentityHs256` helper use the same five-claim profile. `Identity`
is constructible and carries no authentication provenance; call that helper
only after successful authentication.

The C++ API `jwt_hs256_issue_with_id` adds exactly one caller-provided `jti`
string under the same bounds and validation rules, using caller-owned output
and retaining no input or output views. Rut/JIT wrappers for this six-claim
profile are described below.

`jwt_hs256_issue_with_id` and the Rut/JIT
`jwtIssueHs256WithId(subject, issuer, audience, tokenId, key, ttl)` variant add
exactly one nonempty `jti` string claim. The ID follows the same UTF-8, control
character, escaping, payload-size and output-lifetime rules as other claim
strings. Issuance provides no ID uniqueness or replay protection.
`auth.jwtForIdentityHs256WithId` uses `identity.consumerId` as `sub` and the
provided token ID as `jti`; call it only after successful authentication,
because Identity has no authentication provenance.

`jwtIssueHs256WithIdAndScope` emits exactly `sub`, `iss`, `aud`, `jti`, `scope`,
`iat` and `exp`. Scope must be one nonempty ASCII OAuth scope-token using the
same character grammar as `jwtHasScope`; it comes from trusted issuer
configuration, not request input. Invalid scopes fail issuance. The identity
helper `auth.jwtForIdentityHs256WithIdAndScope` uses `identity.consumerId` as
`sub` and should be called only after authentication. Validate signature,
issuer/audience/lifetime and configured jti revocation before scope policy.

### Static HS JWT secret rotation

`auth.rotatingJwtDocumentHs256(authorization, currentSecret, previousSecret)`
and the corresponding `Hs384` / `Hs512` helpers accept either configured secret
while pinning exactly one algorithm. Pass `req.authorization.or("")` so duplicate
Authorization fields fail closed. Empty secrets disable slots; two disabled slots
return 503 before token verification. Removing the previous secret revokes that
slot after reloading/restarting the compiled configuration. Nonempty secrets
retain the verifier's minimum lengths (32/48/64 bytes); short or incorrect
keys cannot verify. Token `kid` and URL hints do not select or fetch keys.

Both verification calls run eagerly; the first successful optional Json is
selected. Each successful result has independent request-arena-owned claims
bytes, so a later failed verification cannot invalidate earlier claims. Equal
secrets are valid. Two successful decodes can retain two bounded claims copies;
an allocation failure cannot publish claims from that decode.
The result proves signature verification only: apply `jwtIdentity` for the trusted
issuer/audience/time/subject policy and `jwtHasScope` for authorization before
using or forwarding an identity. These helpers do not report which secret matched.

See [the rotation example](../examples/jwt-secret-rotation-auth.rut), which resolves
separate algorithm-specific secrets from compile-time environment values. Protect
the resulting artifacts, which contain those secrets. This is a static two-key
window, not remote JWKS refresh, live revocation or persistent key storage.

## Public HTTP response cache (implemented)

```rut
@cache(ttl: 30s)
route GET "/assets" {
    return forward(origin, load_balance: .roundRobin)
}
```

`@cache` accepts one `ttl:` argument: a whole-second duration from `1s` to
`24h` (`s`, `m`, `h`). It requires an explicit GET route without `wait`.
Handlers, guards and rate limits run before lookup. Only forwarded responses
are cached; local `return` responses are not cached.

This is a bounded, per-shard, in-memory cache for public anonymous content.
Requests with `Authorization`, `Proxy-Authorization`, `X-API-Key`, cookies,
bodies, range/conditional headers, or `no-cache`/`no-store` bypass it. Use it
only on public routes: custom credentials in query parameters or other header
names are not recognized automatically. Request `only-if-cached` returns 504
on a miss. Request `max-age` and `min-fresh` can tighten freshness.

Only complete 200 responses with `Content-Length`, a valid IMF-fixdate `Date`,
and a wire size at most 16 KiB minus 256 bytes are stored. `private`,
`no-cache`, `no-store`, `Set-Cookie`, `Vary: *`, chunked, incomplete and
unsupported responses are forwarded without storage. Origin `s-maxage`,
`max-age`, `Expires`, `Date` and `Age` affect freshness; `ttl` is the default
and upper bound. Hits include an updated `Age` header. HTTP/1 requests can use the cache with
committed Set/Remove mutations for `Access-Control-Allow-Origin`,
`Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`,
`Access-Control-Allow-Headers`, `Access-Control-Max-Age`, or
`Access-Control-Expose-Headers`, and Add of `Vary: Origin`. The raw
upstream response is stored and the current request's mutations are applied on
each hit. If the decorated hit exceeds the bounded send buffer, the connection
closes before sending its response. Other response mutations and HTTP/2 response
mutations bypass the cache. For requests with these committed mutations, `only-if-cached` retains
the bypass behavior and can contact upstream.

Keys include configuration, route, upstream, peer address, transport, exact
path/query and end-to-end request headers, so header variants remain separate.
Each shard holds up to 64 entries; capacity pressure may evict entries before
TTL. Forwarded unsafe requests invalidate that shard's entries for the same host, both
at dispatch and on successful response headers. Other shards are independent;
this is not cross-shard write coherence. Configuration reloads start a new
cache namespace. HTTP/1.1 and HTTP/2 clients work with both I/O backends.

Revalidation (304), stale serving, request coalescing, configurable capacity,
private caches, persistence and distributed invalidation are not implemented.

### Unified CORS policy

Import `middleware/cors.rut` from the examples directory. Define the policy once,
then use the same function in both chain steps:

```swift
import "middleware/cors.rut"
func browserPolicy() -> cors.Policy {
    cors.Policy(origins: "https://app.example.com, https://admin.example.com",
                methods: "GET, POST", headers: "Authorization, Content-Type",
                exposeHeaders: "X-Request-ID", maxAge: "600", credentials: true)
}
chain browser {
    before requirePolicy(req, browserPolicy())
    after applyPolicy(req, resp, browserPolicy())
}
route OPTIONS "/api" use chain browser { return 204 }
route GET "/api" use chain browser { return 200 }
```

Declare OPTIONS explicitly; the shared chain supplies preflight validation and
headers. Every actual route that should participate must use the same chain.
The module's functions are ordinary imported helpers, not new keywords or
built-in decorators. See `examples/cors.rut` for a proxy example.

`origins` is a comma-separated exact allow-list, at most 4096 bytes/32 entries.
HTTP(S) DNS/IPv4-style and bracketed IPv6 origins with optional ports (0–65535)
are supported; origins are compared exactly without normalization. Use browser-
serialized values. Paths, userinfo, query, fragments and malformed entries reject.
An explicit `null` is supported but shared by unrelated opaque origins. Public
wildcard mode uses exactly `origins: "*", credentials: false`; wildcard plus
credentials, wildcard mixed with origins, or other invalid policy returns 503.

`methods`, `headers`, and `exposeHeaders` are explicit HTTP token lists, each
limited to 4096 bytes/64 tokens, with no wildcard semantics. Methods must be
nonempty and match case-sensitively. Header names match ASCII case-insensitively;
empty header/exposure lists are allowed. `maxAge` is a 1–5 digit decimal **seconds
string**, e.g. `"600"` or `"0"`, representing 0–99999 seconds. `credentials` is bool.

Malformed or duplicate preflight fields return 400; nonmatching origin/method/
headers return 403. Duplicate actual Origin returns 400. Preflights never reach
the upstream. Successful actual responses emit the approved Origin and configured
exposed headers; credentialed mode adds Allow-Credentials: true. Anonymous mode
removes upstream credential headers. Preflight-only fields are removed from
actual responses. Missing Origin removes upstream CORS fields. Existing Vary
values are preserved. `applyPolicy` independently validates the policy and unique
Origin, so it can decorate explicit local `return 401`, `return 403`,
`return 429`, or `return 503` routes even without a before step. Invalid policy,
missing/duplicate Origin, and unapproved Origin emit no CORS permission headers.
After-only OPTIONS decoration also requires a valid, permitted preflight method
and request-header list, with unique preflight fields. Explicit status returns
in guard failure bodies (including `respond` in before helpers) also commit
chain-after headers. The response helper still independently validates
Origin and policy on these paths. A policy-free upstream TCP connect failure
that synthesizes the legacy 502 also applies committed chain-after headers when
no upstream response bytes exist. Policy-free HTTP/1.1 and HTTP/2 ordinary
upstream timeouts that synthesize the legacy 504 also apply committed chain-after
headers before any upstream response bytes arrive. Custom failure/timeout
policies, cache-only 504s, and other runtime failures remain undecorated. Guard
forward/redirect terminators do not gain automatic CORS decoration. CORS does not
replace auth.

For chain-after helpers, `resp.set("Name", optionalString)` now replaces when
present and removes when nil. Present empty strings remain empty header values.
`add` still requires a non-optional string. Local Response builder restrictions
are unchanged. This reuses existing optional expression syntax; no `if` statement
with conditional Response effects is added.

The lower-level boolean helpers remain available:

```swift
httpOriginListAllows("https://a.example, https://b.example", "https://b.example", true)
httpOriginListAllows("*", "https://a.example", true)              // false
httpTokenListAllows("GET, POST", "POST", true)                    // true
httpTokenListAllows("GET, POST", "post", true)                    // false
httpTokenListAllows("Authorization, X-Trace", "x-trace", false)   // true
httpTokenListAllows("X-Trace", "X-Trace,", false)                 // false
```

Both builtins take two unwrapped `str` values and an unwrapped `bool`, returning
`bool`. The third origin-list argument controls credential mode; the third token-
list argument controls case sensitivity. An empty origin validates configuration
alone. Token-list empty inputs are valid, and `*` is an ordinary token. Both
validate complete lists, fail closed at their bounds and retain no views or
mutable state. `uniqueHeader(...).or("")` alone cannot distinguish absence from
duplicates when empty is allowed; the policy module checks uniqueness explicitly.

### Static Consumer groups

The imported `auth` module provides `ConsumerGroups(consumerId: ..., first: ...,
second: ...)`, `requireGroup(identity, required, first, second)`,
`requireAnyGroup(identity, firstRequired, secondRequired, first, second)`, and
`requireAllGroups(identity, firstRequired, secondRequired, first, second)`. Supply a
verified `auth.Identity` and trusted static membership records. This bounded
policy maps two distinct Consumers to up to two exact, case-sensitive groups
each. Empty slots disable membership. Unknown Consumers and missing membership
receive 403; invalid configuration receives 503. Replacing the trusted snapshot
revokes membership. Client identity/group headers never populate the registry.
`requireAnyGroup` allows membership in either of its two required groups;
`requireAllGroups` requires both distinct groups in one record belonging to the
same Consumer; equal required names are invalid configuration (503), while
`requireAnyGroup` permits equal names. Groups from separate Consumers cannot be
combined. `requireGroup` checks one group. See `examples/consumer-group-auth.rut` and
`examples/consumer-group-all-auth.rut` (relative to the repository root).

`denyGroup(identity, denied, first, second)` rejects one exact group;
`denyAnyGroup(identity, firstDenied, secondDenied, first, second)` rejects either
of two exact groups. Both preserve the full verified identity on success. The
Consumer must exist in the same trusted two-Consumer snapshot: an unregistered
Consumer receives 403 even when neither denied group matches. A registered
Consumer with no memberships may pass a deny check. Empty denied names, empty
or duplicate Consumer IDs, and duplicate nonempty memberships within a record
are configuration errors (503); repeating a denied name is valid and idempotent.
Authenticate first, then chain deny checks before allow checks: a Consumer in
both an allowed and denied group still receives 403. Missing, malformed or
duplicate credentials remain 401, and an anonymous identity is not implicitly
registered. Membership names are case-sensitive exact bytes, not prefixes.
See [the deny-policy example](../examples/consumer-group-deny-auth.rut). These
ordinary functions require a verified identity; they do not establish its origin
or provide dynamic membership storage.


### RS256 with a configured trust policy

`jwtVerifyRs256(token, policy) -> Json?` verifies RS256 and claims together.
Both arguments are unwrapped `str`; policy must be compile-time configuration,
including through inlined helpers. Use a literal, constant, or `env()` snapshot.
A request-derived policy is a compile error. The JSON policy requires these four fields, with optional revocation and
remote-JWKS controls described below:

```json
{"issuer":"https://issuer.example","audience":"orders","kids":["current","previous"],"jwks":{"keys":[]}}
```

Replace the empty example `keys` with public RSA JWKs whose `kid` matches every
approved ID. Empty/missing/duplicate kids, invalid selected keys, empty issuer or
audience, extra policy members and duplicate decoded JSON names are rejected
before serving. Policy text is at most 8192 bytes; at most 8 distinct policies
per configuration, 16 keys per JWKS, kid 1–128 decoded bytes, issuer/audience
1–1024 decoded bytes each. Approved keys require `kty=RSA`, `alg=RS256`, exponent
65537, 2048–4096 bit modulus, canonical base64urlUInt; private parameters are
rejected. Optional `use`/`key_ops` must be `sig`/`["verify"]`.

The protected JOSE header must contain exactly RS256 and an approved kid. URLs
and embedded keys never create trust. No algorithm, default-key or unknown-kid
fallback occurs. Compact tokens use canonical unpadded base64url, object header
≤1024 bytes, claims ≤8192 bytes, and total input ≤24 KiB; duplicate member names
and `crit`/`b64` extensions fail closed. Claims require nonempty string `sub`,
exact trusted `iss`, matching string or string-array `aud`, integer `exp` later
than the current Unix second, and optional integer `nbf`/`iat` no later than now.
Clock failure rejects. No skew is allowed. Any signature/claims failure returns
nil; no partially verified document is published. Success returns claims as Json
with the existing request-arena lifetime.

`auth.jwtDocumentRs256(authorization, policy)` challenges invalid Bearer input
with 401. Pass `req.authorization.or("")` to reject duplicate Authorization
fields. `auth.jwtIdentityRs256(authorization, policy, scope, credentialId)` also
requires an exact scope (403 plus Bearer insufficient_scope on rejection) before
returning Identity with verified subject, configured credentialId, and method
`jwtRS256`. Empty scope/credentialId configuration returns 503. See
[jwt-rs256-auth.rut](../examples/jwt-rs256-auth.rut).

Key parsing runs during configuration loading; each shard activates independent
verification scratch before serving, including reloads. Policy bytes and keys
are retained through in-flight requests, for both JIT and native programs.
Replace configuration to rotate/remove approved keys; old in-flight readers
finish against their original policy. The bounded remote-JWKS and revocation-snapshot extensions are described below.
OIDC, online revocation, replay prevention, other RSA/EC algorithms and broader
JWT signing policies remain separate work.


### RS256 policy revocation snapshots

Optional `revokedJtis` is a trusted array of at most 64 distinct, nonempty JWT
IDs, each at most 128 decoded UTF-8 bytes. Its presence, including `[]`, requires
every accepted token to carry a nonempty string `jti` within the same byte limit.
Matching uses exact decoded, case-sensitive bytes; duplicate decoded IDs in the
configuration are invalid. A matching token is rejected before claims/identity
publication. Omitting the field preserves the existing optional `jti` behavior.

Optional `issuedAfter` is a positive signed-64-bit integer Unix second. It
requires an integer `iat` strictly greater than that cutoff; equality, an older
issuance, or a missing `iat` rejects. The existing `iat <= now` rule still applies.
It works independently of `revokedJtis` and can invalidate older tokens without
removing their signing key. For example, add
`"revokedJtis":["compromised-token-id"],"issuedAfter":1700000000` to the policy.
Malformed controls reject the configuration, rather than disabling revocation.
These are application policy controls over the registered `jti`/`iat` claims in
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html), not an OAuth revocation endpoint.

Revocation is an immutable configuration snapshot. Adopt a replacement configuration
to update it; in-flight requests retain their old policy under the existing RCU
rules. Every node must receive the new configuration before revocation is effective
there. Persist and distribute the source policy through the configuration system;
this API supplies no mutable denylist, background synchronization or replay store.
Omitting an ID in a later snapshot permits it again until expiry unless another
policy rejects it. Signature, issuer, audience, time and revocation checks must all
succeed before any claims are returned; revocation failure is the usual nil/401.


### Remote RS256 and ES256 JWKS refresh

The compile-time `Crypto.jwtRs256(token, policy)` and
`Crypto.jwtEs256(token, policy)` policies can include an optional `remoteJwks`
object with exactly these eight required members:

```json
{"address":"192.0.2.10","port":443,"serverName":"issuer.example",
 "ca":"/etc/rut/issuer-ca.pem","path":"/.well-known/jwks.json",
 "refreshSeconds":60,"maxAgeSeconds":300,"timeoutSeconds":10}
```

The enclosing policy still requires `issuer`, `audience`, `kids` and `jwks`.
The initial public JWKS validates the explicitly approved kid inventory; remote
mode **rejects all tokens until its first successful authenticated fetch**. It
never serves those initial keys as an offline cache. Endpoint fields are trusted
configuration, never token/HTTP-request data. The address is a literal IPv4;
there is no blocking DNS, discovery, redirect following or token-driven fetch.
The CA file and TLS server name are mandatory and certificate verification cannot
be disabled. Only HTTP/1.1 is offered over TLS; absent ALPN is allowed. HTTPS is
implicit and cleartext endpoints are unavailable.

`port` is 1–65535; `refreshSeconds` is 1–3600; `maxAgeSeconds` is 1–86400 and
strictly greater than the refresh interval; `timeoutSeconds` is 1–60. Address,
server name, CA path and request path are owned, bounded strings with no embedded
NUL; paths start with `/` and cannot contain whitespace, controls, fragments or
backslashes. The entire enclosing policy retains its 8192-byte bound. CA files
are loaded at shard activation. Failure leaves that shard's policy row unavailable.

Each shard owns its own bounded fetch and verification workspace. Between handler
batches, a function-pointer state machine advances at most 16 nonblocking I/O
steps per maintenance call. It never waits for readiness or retains a kernel I/O
buffer. Progress follows gateway batch/timer wakeups, so a quiescent gateway can
advance at one-second intervals; configure a timeout that allows several such
steps. There is at most one outstanding request per policy per shard. Requests
and unknown kids cannot trigger extra refreshes. No network I/O or key import
occurs in the token verifier.

The response must be status 200 with one `application/json` or
`application/jwk-set+json` Content-Type. Headers are bounded to 8192 bytes, body
to 8192 bytes, and total decoded HTTP wire bytes to 16384. Content-Length,
chunked and authenticated TLS-close-delimited bodies are supported. Duplicate or
conflicting framing, truncated headers, redirects, 304, compression, malformed
chunks and unclean EOF are rejected. No ETag, Cache-Control-derived lifetime,
HTTP/2 or compressed response handling is advertised by this profile.

A fetched set contains at most 16 objects with distinct nonempty bounded kids.
Only the intersection with the configured approved kids can become trusted;
unknown keys never expand trust. Selected keys retain their algorithm-specific
strict RS256 or ES256 public JWK profile. Preapprove future kids through
replacement configuration before rotating to them. An otherwise valid empty
intersection is authoritative removal and immediately denies all tokens, rather
than falling back to old keys.

A replacement verifier is completely prepared on the owning shard before its
cache is switched. Signature/claims/revocation checks remain unchanged. Fetch,
HTTP, JSON, key-import and activation failures retain the last successful cache
only until its configured maximum age. Only successful validation of a fresh 200
response renews that age. At exact expiry, before first success, after clock
failure or after authoritative key removal, verification returns nil (the auth
wrapper challenges with 401). A failed refresh never extends a lease. Age uses
monotonic time; JWT claim dates still use realtime. There is no stale-forever or
static-key fallback.

Configuration adoption cancels the retired generation's fetch on its shard;
shutdown and destruction also release pending TLS/socket resources. Existing
claims documents own their payload bytes and do not borrow mutable key-cache
storage. Retired generation readers retain that generation's own policy/cache
and its expiration. Each shard refreshes independently; this API does not provide
cross-node synchronization, OIDC discovery, online Token revocation or signing.


### Configured ES256 resource-server verification

`jwtVerifyEs256(token, policy) -> Json?` and `Crypto.jwtEs256(token, policy)`
accept the same trusted compile-time four-field policy shape as RS256: `issuer`,
`audience`, approved `kids`, and a local public `jwks`. Optional `revokedJtis`
and `issuedAfter` have the same immutable snapshot semantics. Optional
`remoteJwks` uses the bounded authenticated HTTPS refresh contract above,
including its eight endpoint fields, approved-kid intersection and maximum age.
Remote mode rejects tokens until the first successful authenticated fetch;
selected keys must satisfy the ES256 public JWK profile below.

Approved keys require `kty=EC`, `alg=ES256`, `crv=P-256`, and canonical unpadded
base64url `x`/`y` coordinates of exactly 32 bytes each (including leading zeros).
Optional `use`/`key_ops` must be `sig`/`["verify"]`. Private parameters, invalid
points, wrong curves/algorithms, missing approved IDs, duplicate decoded keys
or IDs, and malformed policies fail compilation/loading. At most 16 approved
keys and 8192 policy bytes are accepted. No token header imports a key or URL.

The protected header requires exactly ES256 and a configured `kid`. Compact
JWS parsing retains the 1024-byte header / 8192-byte claims bounds and canonical
base64url rules; `crit` and `b64` extensions reject. Signatures are the 64-byte
JOSE `R || S` form, with both integers in 1..n-1. DER signatures reject. Both
mathematically valid S representatives are accepted; signature bytes are not a
replay/session identifier.

Verification applies the existing resource-server claims rules before publishing
Json: nonempty `sub`, exact issuer/audience, integer future `exp`, valid optional
`nbf`/`iat`, and a positive Unix clock with zero skew. Use the existing lifetime
and scope/group helpers for additional policy. `auth.jwtDocumentEs256` returns
verified claims or a challenged 401; `auth.jwtIdentityEs256` additionally checks
scope (403 on insufficient scope) before publishing method `jwtES256` and the
trusted credential ID. Duplicate Authorization fields fail closed through
`req.authorization.or("")`. See [jwt-es256-auth.rut](../examples/jwt-es256-auth.rut).

Initial key parsing occurs before configuration publication; remote replacements
are parsed during shard maintenance, never during token verification. Each shard
activates its own preallocated and warmed curve/bignum workspace before
accepting or adopting that configuration. There is no lazy request-time initialization. Failed rows
remain unavailable. Configurations and request-owned Json follow the existing
RCU/arena lifetimes. Local key removal and revocation require configuration
adoption; remote key removal takes effect at the next successful refresh.
In-flight readers keep their generation and its cache expiration. Native artifact
version 17 serializes owned policy bytes and reconstructs keys after compiler
exit; mutable crypto workspaces and pointers are never serialized. This adds verification,
not ES256 signing, OIDC, online revocation, persistent sessions or replay state.


### RS256 protected token type policy

The `Crypto.jwtRs256(token, policy)` configuration accepts an explicit type:

Optional `requiredType` pins the signed protected-header `typ` to one trusted
nonempty string of at most 128 decoded visible ASCII bytes (0x21–0x7e). For
example, add `"requiredType":"at+jwt"` when that is the exact type your issuer
uses. Missing, wrong-type, empty or mismatching token `typ` rejects before claims
publication; duplicate decoded header names also reject. Escaped JSON names and
values compare after decoding. A payload `typ`, `cty` or HTTP header cannot
satisfy this policy. Signature, approved kid, issuer/audience/time, revocation
and scope checks still apply.

Matching is exact and case-sensitive: `JWT`, `AT+JWT` and `application/at+jwt`
are distinct from `at+jwt`. This deliberately narrow allowlist performs no media
type normalization or alias expansion. Pin the precise wire value agreed with
the issuer. Invalid configuration (empty, non-string, whitespace/control/non-ASCII,
oversize or duplicate names) rejects loading; omission preserves existing header
handling. Configuration owns the type bytes under the same RCU lifecycle as its
keys. This implements explicit application type binding following
[RFC 8725 section 3.11](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.11),
not the complete OAuth JWT access-token profile or nested JWT handling.
