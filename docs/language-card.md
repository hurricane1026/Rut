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

Before LLVM code generation, every handler passes RIR structure and modeled
wait-protocol checks. Yielding handlers also pass progress-cycle checks and
bounded completion/cancel/close exploration for two consecutive waits. Invalid
resume mappings, wait-arm mismatches, yielding progress cycles and exhausted
verification budgets are compile failures. Known finite peer contracts can be
attached through the compiler API for mutual-wait checks; unknown network peer
behavior is not inferred. See
[verification coverage](user-code-formal-verification.md#current-compiler-checks).

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

Unwrapped `str` values also support `+` concatenation, `.hasPrefix(str)`,
`.hasSuffix(str)`, `.contains(str)` and `.isEmpty`. These operations compare
bytes; concatenation owns bounded arena storage and stops on allocation failure.
They do not implicitly convert Bytes or optional values. Source interpolation
remains restricted to the separately documented forms.

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
Checked single-byte [subscripts](#bytes-subscripts) and
[field slice/search methods](#bytes-field-extraction) are supported. There is no
implicit text conversion, ordering, `+` concatenation or regex API for Bytes.
Bounded owned concatenation is available with `concatBytes` below.

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

parseInt("42")             // i32? — strict decimal, str or Bytes
parseInt64(b"9223372036854775807")  // i64? — inferred wide result
// ⏳ parseFloat, IP.parse, CIDR.parse and Duration.parse remain pending
200 as str            // ⏳ infallible conversion (`as` / checked `as?` pending)
```

## Decimal integer parsing

`parseInt(value)` returns `i32?`; `parseInt64(value)` returns `i64?`.
Both accept an unwrapped `str` or `Bytes`, without imports, allocation or text
conversion. The **entire** input must match `[+-]?[0-9]+` and fit the signed
result range. Leading zeros and signed zero are accepted. Empty input, spaces,
CRLF, embedded NUL, non-ASCII digits, suffixes, fractions, exponents and overflow
return `nil`; there is no trimming, wrapping, clamping or partial parsing.
They do not modify `netError()`. Ordinary user functions can shadow these names.

```swift
route POST "/number" {
    guard let count = parseInt(req.query("count").or("20")) else { return 400 }
    guard let sequence = parseInt64(req.bodyBytes) else { return 400 }
    guard count > 0 && sequence >= 0 else { return 422 }
    return 204
}
```

Use `guard let`, `if let`, `== nil` or `.or(...)` to handle failure. The existing
`i64(...)` builtin widens an `i32`; it does not parse text. Source-level `i64`
type annotations and unsigned 64-bit results remain unsupported. See
[the parsing contract and performance study](parse-integers.md).

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

notify all blacklist.add(ip)      // ⏳ target: fan-out to all shards (eventual)
notify(ip) blacklist.add(ip)      // ⏳ target: to owner shard by key hash (expr form;
                                  // bare-statement cache.set does not nest)
// ⏳ single-owner routing: consistent: true (+ // rut:allow(consistent)); Cache
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
encrypted keys are rejected without an interactive password prompt. Certificate-chain validation and
DNS/IPv4 identity verification are mandatory. HTTP/2 additionally requires h2 ALPN. DNS identities also
send SNI. There is no insecure verification mode, system-CA fallback or protocol
downgrade. Paths are literal strings (maximum 255 bytes), relative to the
process working directory when not absolute. `server_name` is at most 253 ASCII
letters/digits/dots/hyphens; embedded controls and escaped literals are rejected.
TLS supports `.http2`, ordinary `.http11` forwarding, and H1 upstreams of the
H2 WebSocket bridge. For HTTPS origins using HTTP/1.1, omit `protocol` or select
`.http11`; the same `tls` block applies. Both HTTP/1.1 and HTTP/2 downstream
clients can reach an H1 HTTPS origin. Ordinary H1 HTTPS uses a dedicated pooled
Connection slot per request; idle TLS sessions are not returned to the plaintext
upstream socket pool. Request and response streaming retain the existing bounded
HTTP framing and request admission rules. Epoll and io_uring share the HTTP
callbacks; io_uring bounds each ciphertext receive by available TLS input space.

An H1 request is sent only after TLS handshake, certificate-chain, hostname/IP,
and ALPN checks succeed (`http/1.1` or no ALPN). A failed connect/handshake produces
the existing HTTP proxy failure (normally 502); the ordinary upstream timeout
still applies. Explicit `response_read_timeout` profiles are not yet supported
by this transport and fail before contacting the origin. H1-to-H1 WebSocket TLS
is unchanged; the existing H2 WebSocket bridge keeps its separate transport.
Files are loaded for each new TLS session, and its context outlives its SSL
object. HTTP/2 TLS/configuration-file failures retain gRPC UNAVAILABLE.

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

`auth.rotatingPinnedMtlsIdentity(currentPin, previousPin, consumerId, currentId,
previousId)` provides a static two-pin renewal window for one Consumer. Empty
pin strings disable individual slots; at least one pin and all three metadata
strings must be nonempty. Every nonempty pin must be exactly 64 lowercase hex
characters, even when the other pin matches. Invalid configuration returns 503
before certificate matching. A missing/unverified or unmatched certificate returns
403 when HTTP routing is reached; a listener requiring client certificates may
reject it during the TLS handshake instead.

The helper reads only `req.tlsClientCertSha256`, never client-supplied headers.
Success returns method `mtls`, the configured Consumer ID, and the credential ID
for the matched slot. Both pins may be equal; current wins that tie. Current-only
and previous-only configurations are supported. Disabled slots still require
stable nonempty credential IDs. See [the rotation example](../examples/mtls-rotating-auth.rut).

Deploy both approved pins during renewal, then clear the old slot and adopt a
replacement configuration to end the window. In-flight requests retain their
original RCU generation; each node must adopt the new configuration. Existing
connections keep their verified fingerprint, but subsequent requests use the
adopted route policy. This rotates the route's pin allowlist, not the listener CA
bundle, which still requires restart to change. It provides no automatic rotation
timer, certificate issuance, CRL/OCSP service or cross-node revocation protocol.

### Two-Consumer mTLS identity mapping

Import `"middleware/mtls.rut"` for this composition. It imports the base auth
module and exposes the existing Identity and Consumer/group policy helpers
under the `mtls` namespace, for example `mtls.requireConsumer`. A separate base
`auth.rut` import is unnecessary.

`mtls.Consumer(consumerId: ..., sha256: ..., credentialId: ...)` is a
trusted static record. `mtls.identity(first, second)` maps the
verified TLS certificate fingerprint to one of two distinct Consumers. Both
Consumer IDs must be nonempty and different, and both credential IDs must be
nonempty even when a pin is disabled. Empty pins disable individual slots;
at least one must remain enabled. Every enabled pin must be exactly 64 lowercase
hex bytes. A nonempty pin cannot belong to both records. All configuration is
validated before reading or matching the connection identity; ambiguity or
invalid metadata returns 503 even if a different slot would match.

The helper reads only `req.tlsClientCertSha256` and returns the matched record's
Consumer/credential IDs with method `mtls`. Missing/unverified/unmatched
certificates return 403 if routing is reached; a mandatory-mTLS listener can
reject them during the handshake. Identity headers cannot select a record.
Use the returned Identity with `requireConsumer`, `denyConsumer` or group policy
to apply authorization after authentication. The [runnable example](../examples/mtls-consumers-auth.rut)
allows both Consumers at `/private` and only the first at `/first-only`.

Records are compiled configuration, not a Consumer registry. Disabling a pin
and adopting a replacement config retires it for subsequent requests; existing
RCU readers finish on their original snapshot. CA trust still belongs to the
listener and requires restart to change. This adds no guest fallback, CA reload,
SAN mapping, CRL/OCSP or durable revocation. Do not construct records from
untrusted request data; ordinary Identity values have no verification provenance.

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

// WebSocket uses HTTP/1.1 Upgrade or HTTP/2 Extended CONNECT. Bare websocket(chat)
// is opaque passthrough; the same trailing message/lifecycle callbacks inspect H2 streams.
// HTTP/2 downstream routes are methodless (wire CONNECT), with an H2 or H1 upstream:
upstream chatH2 { host: "127.0.0.1", port: 9001, protocol: .http2 }
route "/ws" { return websocket(chatH2) }
// Ordinary header/path admission and local rejection run before the tunnel opens.
// H2 peers negotiate SETTINGS_ENABLE_CONNECT_PROTOCOL. Acceptance is HTTP 2xx,
// without Key/Accept or Connection/Upgrade headers; DATA carries WebSocket frames.
// H1 upstreams receive a fresh GET Upgrade; a validated 101 becomes H2 status 200.
// Each H2 stream owns its callbacks, buffers, negotiated subprotocol and per-leg codecs.
// Dynamic output, connection/close facts and message limits match HTTP/1.1 behavior.
// Independent flow control, END_STREAM and RST_STREAM preserve sibling requests.
// TLS H1 upstreams validate identity and negotiate http/1.1 (or no ALPN); H2 requires h2.
// Ordinary request-body consumers still get 503: CONNECT DATA belongs to the tunnel.
// H1 GET Upgrade also bridges to H2 upstreams, translating H2 2xx back to a validated 101.
// Both directions retain bounded DATA buffering, cancellation and per-leg close semantics.
// No frame binding, opcode, FIN, masking, continuation or ping/pong API is exposed.
return websocket(chat)

// `message` is a borrowed WebSocketMessage (any parameter name is valid).
// fromClient/isText/isBinary: bool; len: i32; text: str; payload: Bytes.
// Text is validated UTF-8 before dispatch. Binary can contain arbitrary bytes;
// text is still its raw byte view, not an assertion that Binary is UTF-8.
// payload.count / payload.isEmpty measure bytes; no implicit Bytes/String cast.
// kind: WebSocketMessageKind.text / .binary; direction:
// WebSocketDirection.clientToUpstream / .upstreamToClient. Closed domains share
// ordinary Eq, matching, contextual case names and coverage checks with HTTP/helpers.
func fromDownstream(_ direction: WebSocketDirection) -> bool {
    match direction {
        .clientToUpstream => true
        .upstreamToClient => false
    }
}
func allowedMessage(_ message: WebSocketMessage) -> bool =>
    !fromDownstream(message.direction) || (message.isText && message.len <= 2048)

// The route runs ordinary HTTP admission before its final top-level websocket:
// Request lets/guards/helpers, JSON/regex, mutations, decorators and chain-before
// keep normal typing/evaluation/limits. Rejection opens no WebSocket upstream.
// chain-after Response headers apply to rejection and accepted 101, with ordinary
// HTTP wait/for restrictions. Handshake-critical headers cannot be invalidated.
route GET "/ws" {
    guard let origin = req.uniqueHeader("Origin") else { return 403 }
    guard origin == "https://allowed.example" else { return 403 }
    return websocket(chat, maxMessageSize: 4kb) { message in
        guard allowedMessage(message) else { message.drop() }
        message.forward()
    }
}
// Runtime HTTP bindings cannot escape into callbacks. Proven scalar/String/Bytes
// constants can cross admission. Request/Response reads, mutations and HTTP yields
// are unavailable after upgrade, including hidden reads through helpers or dead arms.
// Whole message/connection/close values are invocation-borrowed: project fields;
// do not compare/publish/store them or retain views for another callback.

// General callbacks use shared MIR/RIR and the ordinary helper analyzer:
// arithmetic/bitwise/comparison, immutable lets, guards, if/else, if let, closed
// matches, optional/error carriers, String/Bytes, JSON and digest/HMAC operations.
// Selected arms are lazy; reached initializers and actual arguments run once,
// including unused producers. False, zero, empty String and JSON null stay present.
// guard let / if let / .or(default) keep ordinary recovery. Named-error guard match
// keeps HTTP's final-wildcard rule. Unwrap before using a plain success value.
// uuid() retains the ordinary direct-let initializer and optional unwrap contract.
// Ordinary parser/local bounds apply; recipe tables do not cap general callbacks.
// String + / hasPrefix / hasSuffix / contains require unwrapped str; isEmpty is a
// property. Construction uses bounded arena storage. Allocation failure stops work.
// matches(re"...") uses Vectorscan full-match; reached scan failures close before
// Boolean negation can turn them into acceptance. No second regex engine is used.

// Ordinary optional JSON APIs include parse/get/at, scalar/kind/count/keys,
// exact numberText, stringify, member/set/remove/append, value construction and
// concrete struct decoding. Runtime RFC 6901 pointers and independent Json values
// are supported. JSON keeps its 8192-byte / 2048-node / depth-64 parser limits.
// Locals preserve decoded/edited values across later JSON operations in the callback.
func messageLabel(_ message: WebSocketMessage) -> str {
    guard let document = json.parse(message.text) else { nil }
    guard let name = json.string(document) else { nil }
    "hello:" + name
}
return websocket(chat) { message in
    if let label = messageLabel(message) { message.forward(label) }
    else { message.drop() }
}
// General source interpolation, mutable local syntax and Bytes `+` concatenation
// are not introduced here. Checked Bytes slicing is available as described below. Non-response statement effects inside ordinary helpers
// remain unsupported in HTTP and WebSocket alike. No alternate WS-only syntax.

// connection: borrowed WebSocketConnection. remoteAddr: IP, remotePort: i32,
// isTls: bool and subprotocol: str describe the downstream client in BOTH directions.
// The port is host order. subprotocol is the actual selected token, including
// optional peer selection without a required route token; none is empty String.
// IP can be passed through ordinary helper signatures, just like other scalar fields.
// Cache<IP,i64> reads and bare writes use the callback shard. Writes run at their
// reached statement (including after guards/inside selected branches), not as a
// prelude; set is not an expression. Inferred counter types work; explicit user
// i64 annotations are absent. Cache is lossy state, not durable session storage.
let messages = Cache<IP, i64>(capacity: 1024)
return websocket(chat) { message in
    let key = message.connection.remoteAddr
    let count = messages.get(key).or(0)
    guard count < 100 else { message.drop() }
    messages.set(key, count + 1)
    message.forward()
}
// Compiled cache access keeps declaration identity across registry reorder/removal.
// time.nowMicros() latches once per invocation and refreshes for the next message.

// Verdicts terminate each message path. Bare forward preserves kind and payload;
// a str argument emits Text, a Bytes argument emits Binary. Dynamic values can
// come from literals, payloads, aliases, optional bindings or ordinary helpers.
return websocket(chat) { message in
    if message.fromClient { message.forward("echo:" + message.text) }
    else { message.forward(message.payload) }
}
// message.forward(b"\x00\xff") emits exact Binary octets, including NUL/invalid UTF-8.
// Byte literals use adjacent b"...", at most 4096 decoded bytes, with \n/\r/\t,
// \\, \" and \xHH escapes; Unicode escapes/interpolation are unavailable in Bytes.
// message.drop() discards one complete application message.
// close(), close(code), close(code, reason) accept plain runtime i32/str values.
// Status must be valid on wire and reason <=123 UTF-8 bytes. Invalid runtime
// arguments close with 1002; invalid Text with 1007; oversized output with 1009.
// Known invalid literals fail compilation. Codes 1005/1006 are observations only.
// Output is copied before asynchronous I/O; close reasons own separate drain bytes.
// Backpressure precedes another callback. io_uring output survives target/cancel
// retirement in either order; callback/JSON/input views never become send owners.

// maxMessageSize: explicit 1b...262130b; default 16370 bytes. This bounds complete
// decoded input and rewritten output. Large routes atomically acquire four existing
// 256 KiB bulk message/output buffers; exhaustion cannot silently lower the limit.
// Both Linux backends stream I/O slices into complete-message storage.
// Optional subprotocol: "chat" requires that client offer before upstream connect,
// restricts the backend offer to it and requires selection. Without it, selection
// may be one offered token or absent. Both named arguments are optional/unique.
return websocket(chat, subprotocol: "chat", maxMessageSize: 64kb) { message in
    message.forward()
}
// Terminate admission validates GET/HTTP/1.1, one nonempty Host, exact Upgrade/
// Connection tokens, canonical 16-byte Base64 key and WebSocket Version 13. One
// Content-Length: 0 is allowed; positive/duplicate length, TE/Transfer-Encoding and
// Expect fail with 400. A canonical decimal version 0...255 other than 13 gets 426
// with version 13/Upgrade/Connection headers. Malformed versions fail with 400. Origin
// remains explicit policy. A backend 101 needs matching Accept, complete headers,
// valid selected protocol and independent extension agreement before publication.
// Non-101 stays ordinary HTTP. Coalesced early frames are retained until acceptance.

// RFC 7692 permessage-deflate is independently negotiated with each leg, with no
// new DSL option. The callback sees decoded bytes. Windows 8...15 and received
// context takeover (including across dropped messages) are supported. Controls
// and continuations cannot set RSV1. Output compresses only when smaller and bounded;
// incompressible output falls back without lowering the message limit. Compressed
// wire work is limited separately to max+max/8+1024 bytes per message. Before 101,
// each negotiated leg reserves one 256 KiB codec slice in addition to large-route
// data buffers. The private pinned static C codec uses existing pools, no heap.

// Swift multiple trailing closures expose optional lifecycle entries.
return websocket(chat) { message in
    message.forward()
} onOpen: { connection in
    guard connection.remotePort > 0 else { connection.close(1008, "peer port") }
} onClose: { closed in
    let peer: IP = closed.connection.remoteAddr
    let code: i32 = closed.code
    let reason: str = closed.reason
    let clean: bool = closed.wasClean
}
// Open runs after accepted 101/resources, before buffered messages; it can close
// but cannot forward data. Close runs exactly once for an opened session before
// config/TLS/resource teardown, including on failure/timeout, and cannot reopen it.
// Failed admission/upgrade has neither event. Bare return ends a hook; fallthrough
// is void. Ordinary helper/guard/if/match/optional/error/Cache/time semantics apply.
// WebSocketClose.code/reason are the first downstream peer Close; upstreamCode/
// upstreamReason are the other leg. Empty Close is 1005, absent is 1006; wasClean
// requires both complete WebSocket handshakes. Local policy remains independent.
// Closing preserves peer payloads, acknowledges legs independently, handles controls
// locally and discards bounded application data without decoder/callback dispatch.
// One fixed approximately 5s deadline bounds closing/EOF drain; progress cannot
// extend it. Quiet healthy sessions have no idle timeout. TLS drains close_notify
// before downstream FIN while allowing the other leg to finish independently.
// The message/lifecycle callback surface above currently applies to HTTP/1.1.

// HTTP calls — native syntax, async is invisible (no await anywhere)
let res = post http://orders/create {
    Content-Type: application/json
    Body: order
    Timeout: 10s
}
guard let res else { return 502 }
guard res.status == 200 else { return 502 }

fire post http://audit/log { Body: json(evt) } // fire-and-forget, non-terminal

// ⏳ Target concurrency syntax: handles, submit, all/any are not implemented.
let h1 = submit get http://svc-a/x
let h2 = submit get http://svc-b/y
let (r1, r2) = wait(h1, h2)
guard let r1 else { return 502 }
guard let resp = any(wait(h1, 5s)) else { return 504 }   // timeout race

// Implemented event waits suspend the handler and return to the shard loop.
// A matching event resumes the continuation; other connections can progress.
wait(2s) // timer sleep
wait(downstream.recv())
wait(downstream.send()) // even an empty send resumes on a later loop turn
// Scheduler safety/progress has bounded TLC coverage plus concrete runtime tests.

// Implemented bounded OR wait: downstream recv versus timer (integer ms).
wait any {
    downstream.recv() => { return 204 }
    timer(250) => { return 408 }
}
// Every handler passes native CFG/protocol checks before LLVM emission.
// CI also cross-checks protocol models exported from actual compiled fixtures.
// io_uring retirement has separate bounded TLC and concrete completion-order checks.
// Known peer contracts can reject mutual waits; unknown network peers retain
// an eventual completion/failure assumption. TLA+ is a CI design/reference
// check, not proof of arbitrary source programs or kernel/backend behavior.

// TCP/UDP clients — configured IPv4/DNS endpoints, request-owned handles (implemented).
// DNS: bounded A/CNAME, TTL cache, UDP/TCP fallback; no AAAA/SRV or dynamic targets.
// See net-clients.md for resolver bounds, UDP and TLS policies.
let pending = tcp(env("SERVICE_ENDPOINT"), 1000)
guard let conn = pending else { return 502 }
let pendingSend = conn.send(b"PING\r\n", 1000)
guard let sent = pendingSend else { return 502 }
let pendingRead = conn.readLine(128, 1000)
guard let data = pendingRead else { return 502 }
let closed = conn.close()                       // also automatic on terminal exit

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
- Synchronous WebSocket callbacks share this Cache API, including pure read
  predicates accepting `IP`. Counter values keep inferred `i64` types; explicit
  user `i64` annotations remain unsupported. Bare writes execute at their reached source
  position, after successful guards and only on selected branches. Cache remains
  lossy per-shard state; it does not retain connection/session objects.
- Compiled reads/writes carry their declaration name identity across hot reload.
  A moved declaration is resolved in the current registry snapshot; a removed
  declaration reads as a miss and ignores writes. Old handlers cannot address
  another named cache merely because its slot was reused. Moving/resizing a
  declaration may discard entries, as with other cache eviction.

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
         s.hasPrefix(str) s.hasSuffix(str)
         ⏳ s.trimPrefix/trimSuffix
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
         uses in one request or message callback see the same value)
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
- `header_auth.multiHeaderKeyOrAnonymous(count, presented, first, second, anonymousId)`
  is provided by `import "middleware/header_auth.rut"`, which also exposes
  `header_auth.HeaderKeyConsumer` and existing auth policy helpers. It extends
  the two-Consumer policy with absence-only guest access. Pass
  `req.headerCount("X-API-Key")` and `req.uniqueHeader("X-API-Key").or("")`
  from the same original field. Only count 0 plus an empty value creates the
  configured guest with empty credential ID and method `anonymous`. Count 1
  must verify one enabled key. Empty, wrong or duplicate credentials, parsing
  failure and inconsistent count/value arguments receive 401 with an ApiKey
  challenge, never anonymous fallback. The full pair is validated before guest
  access; invalid configuration, an empty guest ID or a guest ID matching either
  Consumer returns 503. Successful key identities retain configured metadata
  and method `apiKey`. Authorization remains separate and may deny guests with
  403. Leading removal effects preserve original presence evidence; other
  headers, query and body are not fallback sources. See
  [optional-multi-header-key-auth.rut](../examples/optional-multi-header-key-auth.rut).
- `header_auth.requireBoth(firstPresented, secondPresented, config)` requires two
  distinct nonempty opaque keys for one Consumer. Import `middleware/header_auth.rut`;
  config is `header_auth.RequiredHeaderKeys(consumerId: ..., firstKey: ...,
  secondKey: ..., policyId: ...)`. Read each input with `uniqueHeader(...).or("")`
  from its own distinct original custom header. Missing/empty/duplicate/wrong
  credentials return 401 plus `WWW-Authenticate: ApiKey`. Empty config fields or
  identical configured keys return 503; no slot can be disabled. Success preserves
  the configured Consumer, names the pair with credential ID `policyId`, and uses
  method `apiKeyAndApiKey`. Authorize afterward; client headers cannot supply
  metadata. The helper receives values and cannot enforce distinct source names.
  Use TLS, strip both secrets before forwarding, and replace config to rotate or
  revoke. Two shared keys do not imply MFA. See
  [required-header-keys-auth.rut](../examples/required-header-keys-auth.rut).
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
- `identity_auth.requireSameConsumer(firstIdentity, secondIdentity, policyId)` binds two
  successful verifier results in the same trusted Consumer ID namespace. Import
  `middleware/identity_auth.rut`, which also exposes the existing auth helpers. Both
  identities need nonempty Consumer/credential/method fields; `anonymous` and
  unequal Consumer IDs return 403 without a challenge. Matching is exact and
  case-sensitive. Empty trusted `policyId` returns 503. Success returns the shared
  Consumer, credential ID `policyId`, and method `boundCredentials`. Authenticate
  both sources first, preserving their 401 failures, then apply Consumer/group
  authorization. This helper does not verify credentials, prove provenance or
  guarantee independent MFA. Never construct inputs from client identity headers
  or equate unrelated issuer/local identity namespaces. See
  [bound-credentials-auth.rut](../examples/bound-credentials-auth.rut).
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
`iat` and `exp`. Scope is a nonempty OAuth scope list, for example
`"orders:read orders:write"`, using the same list grammar as `jwtHasScope`:
ASCII tokens separated by exactly one ASCII space. Leading/trailing/repeated
spaces, tabs, controls, quotes, backslashes and non-ASCII bytes fail issuance,
including malformed suffixes after a valid token. Order and duplicate token
values are preserved exactly. Single-scope inputs retain their previous bytes
and signature; the combined escaped payload remains capped at 8192 bytes.
The list comes from trusted issuer configuration, not request input. The identity
helper `auth.jwtForIdentityHs256WithIdAndScope` uses `identity.consumerId` as
`sub` and should be called only after authentication. Validate signature,
issuer/audience/lifetime and configured jti revocation before scope policy.

Set `JWT_ISSUE_SCOPE="orders:read orders:write"` for the shipped
[jwt-issue-auth.rut](../examples/jwt-issue-auth.rut) issuer to grant both
permissions. Resource routes can require either exact token, or require both
with `jwtHasScope(claims, "orders:read") && jwtHasScope(claims, "orders:write")`.
This broadens the existing issuance argument, adding no keyword, builtin,
claim, algorithm, or OAuth endpoint. Missing or invalid authentication remains
401; authenticated callers lacking a permission receive 403. The password/JWT
example keeps its existing single read permission by default.

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
object with these eight required members (and the optional trusted DNS/discovery
fields described below):

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
there is no blocking DNS, redirect following or token-driven fetch. Optional
`dnsAddress`/`dnsPort`/`allowedAddresses` enable bounded A-only DNS; optional
`discoveryPath`/`discoveryIssuer` enable exact issuer and pre-authorized JWKS URI
validation. Neither profile accepts request-selected destinations. See
[JWKS DNS/discovery](jwks-discovery.md) for schema, ownership and failure limits.
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

### ES256 protected token type policy

`Crypto.jwtEs256(token, policy)` optionally accepts `"requiredType":"at+jwt"`
in its trusted configuration. This requires the signed protected header `typ`
to match that exact decoded string. Types are 1–128 decoded visible ASCII bytes
(0x21–0x7e). Invalid configuration, including empty/non-string values, whitespace,
controls, non-ASCII, excessive length or duplicate decoded field names, fails
compilation/loading. The policy owns the bytes until its configuration generation
retires; native handlers reconstruct the policy from the serialized snapshot.

Enabled policies reject missing, non-string or mismatching `typ` before claims
publication. Escaped JSON names and values compare after decoding; duplicate
header names reject. Payload `typ`, HTTP headers and JOSE `cty` cannot satisfy the
policy. Matching is case-sensitive and performs no media-type normalization or
alias expansion: `JWT`, `AT+JWT` and `application/at+jwt` do not match `at+jwt`.
Configure the precise type your issuer emits. Omitting the field preserves
existing ES256 behavior. Signature, approved kid, issuer/audience/time, revocation
and scope/group authorization remain required at their existing layers.

The type policy applies to static keys and refreshed remote JWKS on each shard,
without request-time key parsing, allocation or I/O. This is explicit application
type binding as described in [RFC 8725 section 3.11](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.11),
not full OAuth access-token profile conformance, nested JWT support or replay
protection. See [the example](../examples/jwt-es256-auth.rut).

### Client-bound JWT identity

`auth.jwtClientIdentity(verifiedClaims, issuer, audience, allowedClientId,
credentialId) -> auth.Identity` is ordinary imported Rut policy. Verify the
signature first with a pinned `Crypto.jwtHs*`, `Crypto.jwtRs256` or
`Crypto.jwtEs256` policy (or the corresponding auth document wrapper). The
helper validates the existing issuer/audience/subject/expiry profile and requires
a nonempty string `client_id` in the signed payload. It compares exact decoded,
case-sensitive bytes against the trusted configured `allowedClientId`.

Success returns consumerId from verified `sub`, configured credentialId and
method `jwt`. `client_id` never replaces the user identity, and neither subject,
`azp`, a protected-header `client_id`, nor HTTP fields substitute for it. Escaped
names/values compare after JSON decoding; duplicate decoded names reject under
the shared strict JSON parser. Empty configuration returns 503 when the helper
runs; invalid claims and missing/empty/non-string client IDs return 401 with
Bearer `invalid_token`. A valid token naming a different client returns 403.
Apply scope/group authorization separately; the example challenges insufficient
scope with 403. Existing lifetime/revocation policies may also be applied before
publishing identity.

```rut
let document = auth.jwtDocumentHs256(req.authorization.or(""), env("JWT_SECRET"))
let identity = auth.jwtClientIdentity(document, "https://issuer.example", "orders",
                                      "orders-web", "issuer-key")
```

The signed client identifier follows the `client_id` claim in
[RFC 9068 section 2.2](https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2).
This is a fixed resource authorization policy, not an OAuth/OIDC login flow,
full access-token profile validator, `azp` inference, or sender proof of possession.
A bearer token remains replayable by anyone holding it until other policy rejects
it. `Json` has no compiler-enforced verification provenance: never pass arbitrary
parsed request JSON. All policy arguments must come from trusted configuration,
not request fields. See [the runnable example](../examples/jwt-client-auth.rut).

## Forward-auth prefix

`forwardAuthHeader(header, policy, timeoutMs) -> i32` consumes an external HTTPS
response before continuing a direct route. Like `passwordVerifyHeader`, it must
initialize the first direct route `let`, with compile-time arguments and no
explicit `wait`, helper wrapping or pipeline. User functions may shadow it.
No keyword or dependency is added. JIT and exported native handlers use the same
verified, constant-only replay prefix and asynchronous authentication service.

```rut
route GET "/private" {
    let decision = forwardAuthHeader("Authorization", env("RUT_FORWARD_AUTH_POLICY"), 1000)
    guard decision != -2 else { return 504 }
    guard decision != -1 else { return 503 }
    guard decision != -3 else { return 403 }
    guard decision == 1 else { return 401 }
    return forward(backend, load_balance: .roundRobin)
}
```

`policy` is a strict JSON object, resolved at load/compile time:

```json
{"address":"127.0.0.1","port":9443,"serverName":"auth.example.com","caFile":"/etc/rut/auth-ca.pem","path":"/authorize","identityHeader":"X-Consumer-ID"}
```

All fields except `port` (default 443) are required. Unknown/duplicate fields,
invalid fixed IPv4/HTTPS endpoint, unsafe header names, identical credential and
identity fields, and timeouts outside 1–60000 ms are rejected. `identityHeader`
is exactly one allowlisted `X-*` response/request field, excluding transport and
original-context fields. There is no DNS, discovery, redirect, HTTP fallback,
client-supplied URL or fail-open mode.

The service receives `GET` at the fixed path, exactly one selected credential
field (maximum 2048 bytes), and gateway-produced `X-Original-Method` and
`X-Original-URI` (including query, maximum 2048 bytes). Client-supplied original
context and identity fields are never copied to this request. Other headers,
cookies, body and forwarding IP/host claims are not sent. Protect the configured
service and avoid putting secrets in query strings. Missing, empty, oversized or
duplicate credentials return `0` without a callout.

Result `1` requires a completely framed HTTP 200 response with exactly one
nonempty, valid allowlisted identity field (maximum 1024 bytes). The field name
and value are copied into request-owned storage, replacing every client field
of that name; the selected credential field is removed before upstream
forwarding. Other response headers, cookies and response body are not propagated.
Reads such as `req.header` still observe the original client request; do not use
them as authenticated identity. Applications must trust only the configured
identity field downstream and strip any other identity conventions themselves.
Always gate forwarding on the actual result being `1`; ordinary integers carry
no authentication provenance.

A complete 401 returns `0`, 403 returns `-3`, timeout returns `-2`; TLS failure,
capacity exhaustion, invalid/missing identity, other status codes or malformed
responses return `-1`. No external response body is exposed. Framing remains
bounded to 8 KiB headers/body and 16 KiB wire, with ambiguous lengths,
compression and hop-by-hop identity nomination rejected. Close-delimited bodies
require authenticated TLS close_notify. The JWKS JSON-only profile is unchanged.

Each requiring shard's existing asynchronous authentication service owns eight
callout slots and a background worker. TLS allocation, CA loading and nonblocking
network progression occur off-shard. The shard copies bounded inputs and polls
via existing timer yields (at most 10 ms); one original monotonic deadline covers
queueing, connect, TLS and response. Exact expiry rejects even completed allows.
Request generations and HTTP/2 stream IDs fence abandoned results; close/reset
cancels work, worker shutdown joins before storage is released, and configuration
views are never retained by the worker. HTTP/2 keeps its existing single
suspended-stream restriction. This profile does not implement OAuth introspection,
OPA JSON envelopes, multiple identity fields, response challenges or auth caching.
See [the example](../examples/forward-auth.rut).

## JWT group union and intersection policies

Import `middleware/jwt_groups.rut` alongside the existing auth library.
`jwt_groups.requireAny(document, first, second)` permits either exact signed
`groups` membership; `jwt_groups.requireAll` requires both in the same document.
Both return that document unchanged. A repeated name requires that group once.
They authorize only: first verify the signature and issuer/audience/subject/time
claims, for example with `auth.jwtDocumentHs256` followed by `auth.jwtIdentity`.
Use the same verified JSON for the group check, and publish identity only after
it succeeds. RS256/ES256 verified documents can use the same helpers.

Missing, empty, non-array or malformed `groups` and insufficient memberships
return 403 with `Bearer error="insufficient_scope"`. An invalid array element
rejects the entire membership check even after a match. Empty configured group
names return 503. Matching is case-sensitive; neither a `scope` claim nor client
identity/group headers supply membership. Authentication remains separate: the
example rejects invalid signatures/claims and duplicate Authorization with 401
before evaluating group authorization. These helpers do not prove JSON origin.

See [jwt-group-policies.rut](../examples/jwt-group-policies.rut). The focused
`test_jwt_group_policies` matrix exercises JIT and relocated native artifacts,
including deletion of the importing source and helper modules before execution.
The policy is configuration-owned; no dynamic group registry, OIDC session or
persistent membership lifecycle is added.

## Composable HTTPS calls

`httpCall(policy, request, timeoutMs)` returns optional `Json`. It is an ordinary
function call, with no new keyword or `await`. Bind its result with `let` before
an optional guard. It can occur after earlier guards, inside ordinary helpers,
and in selected helper branches. Later calls can consume earlier results. A
suspended call resumes at its own continuation: completed calls, random values,
request mutations and other earlier computations are not replayed.

```rut
func authorize(_ request: Json) -> Json {
    httpCall(env("AUTH_ENDPOINT"), request, 1000)
}
route POST "/check" {
    guard let request = json.parse(req.body) else { return 400 }
    let result = authorize(request)
    guard let reply = result else { return 503 }
    guard let encoded = json(reply) else { return 503 }
    return response(200, body: encoded)
}
```

`policy` must resolve at compilation/load time to a JSON string:

```json
{"address":"127.0.0.1","port":9443,"serverName":"auth.example.com","caFile":"/certs/ca.pem","path":"/authorize"}
```

The path, address and TLS trust/identity are fixed; `port` defaults to 443.
Unknown/duplicate fields, invalid IPv4 addresses, unsafe paths, missing CA or
identity, and literal timeouts outside 1–60000 ms are rejected. Requests cannot
choose a URL, Host, CA, SNI, redirect destination or framing. This profile has no
DNS/discovery, redirects, HTTP fallback, client certificates or connection pool.

The request is an unwrapped `Json` object:

```json
{"method":"POST","headers":{"Authorization":"Bearer explicitly-selected-token","Content-Type":"application/json"},"body":"{\"resource\":\"orders\"}"}
```

`method` is required: GET, POST, PUT, PATCH, DELETE or OPTIONS. `headers` and
`body` are optional (empty by default). Header values and body are strings.
At most 16 fields, 128 bytes per name, 2048 bytes per value, 4096 body bytes and
6144 complete wire bytes are accepted. Header names must be unique ignoring
case. Transport/framing fields are forbidden; the worker produces Host,
Content-Length, Accept-Encoding: identity and Connection: close. No client
credentials, cookies, identity fields or request body are forwarded implicitly.

A fully framed HTTP response, including 3xx/4xx/5xx, produces:

```json
{"ok":true,"status":403,"headers":{"x-role":["reader","writer"]},"body":"denied"}
```

Names are lowercase, values are arrays preserving duplicates and their order;
applications decide which duplicate/empty fields to accept. `ok` means the HTTP
exchange completed, not that authorization succeeded. Response headers/body are
never automatically applied to the downstream response or forwarded request.
Use existing `json.get`, `json.string`, `json.parse`/`json.decode` and request
mutation APIs to map multiple fields or interpret a JSON response body. The
[composition example](../examples/http-call.rut) feeds two selected identity
fields into a second call. Existing request-mutation placement rules still apply.

Failures return `{"ok":false,"status":0,"error":"..."}` with `timeout`,
`capacity`, `invalidRequest` or `transport`. `nil` means result storage
could not be published. A timeout does not prove that a remote POST had no
side effects; there is no automatic retry. One monotonic deadline per call covers
queueing, connect, verified TLS, send and complete response, and cannot be
extended by progress. HTTP headers/body are bounded to 8192 bytes each, wire to
16384 and the complete UTF-8 JSON envelope to 8192. Invalid/ambiguous framing,
compression, informational responses, invalid UTF-8 or excessive envelope size
fail with `transport`; close-delimited bodies require authenticated close_notify.

HTTP/1 and HTTP/2 downstreams use the same eight-slot per-shard service. Network,
TLS allocation and CA loading run on a bounded worker; the shard uses existing
Timer yields (up to 10 ms) without blocking. Close/reset cancels the matching
request generation/stream, and shutdown joins the worker before reclaiming its
storage. Immutable request bytes and live values belong to a bounded request
arena, including across HTTP/2 synthesis and sequential calls. The original
request snapshot and generated value frame are each limited to 8192 bytes,
within the shared 256 KiB request budget; frame exhaustion returns 503 before a
call. HTTP/2 retains its single suspended-stream restriction.

This slice supports sequential calls and conditional selection, not parallel
fan-out, streaming callout bodies, explicit `wait` mixed with calls, timer or
WebSocket callbacks, or the specialized password/forward-auth prefix in the same
handler. Direct `guard let x = httpCall(...)` and equivalent unbound calls in
conditions are rejected: use `let result = ...` then `guard let x = result`.

## JWT group exclusion policy

`jwt_groups.requireExcept(document, required, excluded)` requires a nonempty
valid signed `groups` array containing `required` and not containing `excluded`.
Both configured names must be nonempty (503 otherwise). Exact case-sensitive
exclusion wins on overlap or identical names; malformed or absent groups fail
closed with 403 and the Bearer insufficient-scope challenge. It returns the same
JSON document; authenticate signature and claims first, and publish identity
after success. This ordinary library helper adds no language syntax or runtime
ABI. See [auth coverage](auth-coverage.md#jwt-required-group-with-exclusion) and
[jwt-group-policies.rut](../examples/jwt-group-policies.rut).

### OPA authorization composition

Import `middleware/opa.rut`. `opa.request(input)` constructs an optional OPA Data
API POST request with a serialized `input` envelope; send it with `httpCall` to
a trusted fixed HTTPS policy. Pass the unwrapped callout result to
`opa.requireAllow` for a Boolean `result`, or `opa.requireDecision` for an object
`result` with Boolean `allow`. Explicit false or an undefined result responds
403; malformed/type-mismatched replies, non-200 status and transport failures
respond 503. Success returns the parsed document or authorized decision object,
respectively. Additional fields require explicit validation and mapping. These
are ordinary library functions, not new syntax or implicit authentication. See
[the contract and example](opa-authorization.md). MIR has 32 bounded blocks to
accommodate the existing eight route guards plus continuations and match arms.


### OAuth2 introspection composition

Import `middleware/introspection.rut` and follow
[the executable profile](oauth-introspection.md). `introspection.request` constructs
a bounded RFC 7662 form POST with separate configured service authorization.
Bind its `httpCall` result before unwrapping; `introspection.requireActive` checks
a completed HTTP 200 and exact active/expiry/audience policy, then returns metadata.
`introspection.requireScope` applies existing exact OAuth scope membership.
Missing/invalid client credentials and inactive/invalid metadata produce 401;
missing permission produces 403; service/transport or request-storage errors
produce 503. There is no local allow cache.

The native operations `oauthIntrospectionRequest(token, serviceAuthorization)`
return optional Json; `oauthIntrospectionValid(document, audience)` returns Bool
and uses the current Unix clock. Both retain the existing lexical function-call
syntax and Json carrier. The validator requires `exp`/audience as a local resource
policy, while `iss`, `sub` and `iat` need not be present. Callers must trust the
response source before validating or projecting its identity. No OAuth grants,
OIDC session, automatic identity propagation or new language keyword is added.

### Introspection scope combinations

After `introspection.requireActive`, `requireEitherScope(document, first, second)`
requires at least one configured permission; `requireBothScopes(document, first,
second)` requires both. Success preserves the metadata Json. Both configuration
values must be single valid OAuth scope tokens; invalid configuration or bounded
policy construction failure returns 503 before membership evaluation. Missing
permissions return challenged 403. Case/prefix matching and request-header scope
selection are unavailable; malformed AS metadata still fails the active policy.
These are ordinary library helpers with no new syntax or ABI. See
[the two-permission contract](oauth-introspection.md#composable-two-permission-authorization).

### Introspection issuer/client binding

`introspection.requireBinding(document, issuer, clientId)` is an ordinary library
helper applied after `requireActive`. Both trusted expected strings must be
nonempty (503 otherwise). Exact decoded top-level `iss` and `client_id` string
matches return the same Json; absent, malformed or mismatching fields return
challenged 401. Case, URI spelling and prefixes are not normalized. This does not
change which metadata the base validator requires, authenticate arbitrary Json,
or replace audience/scope checks. See
[the binding example and contract](oauth-introspection.md#optional-issuer-and-oauth-client-binding).

### Upstream OAuth client credentials

Import `middleware/oauth_client.rut`. `oauth_client.clientCredentials(auth)`
constructs a `grant_type=client_credentials` form POST using trusted configured
Basic service authorization and the AS's default scope. Bind and unwrap its
`httpCall` result, then `oauth_client.authorization(reply, requiredScope)` returns
an upstream Bearer header only after strict status/JSON/token/type/expiry/scope
checks. Service token failures return 503; downstream authentication is explicit.
`req.set` replaces Authorization only in the selected authorized forwarding arm.
`oauth_client.clientCredentialsForScope(auth, scopes)` adds an explicit trusted
scope list using `oauthClientCredentialsRequest(scopes: str, serviceAuthorization: str) -> Json?`.
The builtin accepts at most 1024 scope bytes with strict single-space ASCII scope
grammar and at most 2048 visible ASCII bytes of Basic service authorization;
invalid input returns nil and the source helper responds 503. Reserved form bytes
are percent-encoded, preserving order, duplicates and case. The required response
scope check remains mandatory. No keyword, dependency, token cache or refresh flow
is added. See [the contract](upstream-oauth.md), [default example](../examples/upstream-oauth.rut)
and [scoped example](../examples/upstream-oauth-scoped.rut).

`oauth_client.clientCredentialsForResource(auth, scopes, resource)` uses the
three-string overload `oauthClientCredentialsRequest(scopes, auth, resource) -> Json?`.
It adds exactly one independently encoded `resource` form field. The resource is a
trusted HTTPS identifier, not a fetch destination: at most 1024 ASCII bytes, DNS
labels or bracketed IPv6, optional port 1–65535, no userinfo or fragment, and valid
path/query bytes and percent escapes. Combined encoded body is bounded to 4096 bytes.
Malformed inputs return nil; the source helper responds 503 before a call. The AS
and upstream own token audience enforcement; sending the parameter is not proof
of a valid audience. Other schemes and multiple resource parameters are unsupported.
See [the resource contract](upstream-oauth.md#configured-target-resource) and
[example](../examples/upstream-oauth-resource.rut).

### Upstream OAuth access-token exchange

`oauthTokenExchangeRequest(subjectToken: str, serviceAuthorization: str, policy: Json) -> Json?`
constructs a fixed RFC 8693 access-token request. `policy` is exactly
`{scope: str, resource: str}` using trusted configuration; unwrap fallible JSON
construction before calling. Subject, scope and HTTPS resource are bounded to
1024 bytes each, Basic service auth to 2048 bytes, and encoded body to 4096 bytes.
Unknown/duplicate policy fields or invalid input return nil.

`oauth_client.tokenExchange(authorization, serviceAuth, policy)` extracts a singleton
Bearer subject (401 on syntax failure) and responds 503 on construction failure.
Send the result to a fixed verified HTTPS AS using `httpCall`, then call
`oauth_client.exchangeAuthorization(reply, requiredScope)`. It accepts only exact
access-token `issued_token_type`, followed by the shared strict Bearer/expiry/scope
response policy. AS/response failures return 503 without forwarding. The AS owns
subject validation and exchange authorization; the upstream owns audience checks.
No actor token, cache, refresh, new keyword or dependency is added. See
[the contract](oauth-token-exchange.md) and [example](../examples/upstream-oauth-exchange.rut).

### OAuth authorization-server revocation client

`oauth_revocation.revokeRequest(authorization, serviceAuthorization)` builds the
bounded percent-encoded token/access-token-hint form using trusted Basic service
credentials. Send it with `httpCall` to a fixed verified HTTPS revocation policy.
`oauth_revocation.requireSuccess(reply)` accepts completed status 200, regardless
of admitted body contents, and otherwise responds 503. The example returns the
same empty 204/no-store response for revoked and unknown tokens. Invalid client
Bearer syntax returns 401 before a call with valid service configuration.
There is no automatic retry, local blacklist or rollback on timeout/disconnect.
See [the contract](oauth-revocation.md) and
[example](../examples/oauth-revocation.rut). No syntax, builtin or ABI is added.

## mTLS-bound JWT policy

`jwtCertificateBound(document: Json, fingerprint: str) -> bool` compares the
strict `cnf.x5t#S256` claim with a canonical lowercase SHA-256 certificate
fingerprint. Both inputs must be unwrapped; malformed input returns false.
This is metadata validation, not signature or TLS verification.

Import `middleware/jwt_binding.rut` and call `jwt_binding.requireMtls(document)`
after signature verification. It uses only `req.tlsClientCertSha256` from the
verified TLS connection and returns the same Json on success; missing/mismatched
binding returns challenged 401. Apply issuer/audience/time/subject and scope
policies separately. Cleartext and ordinary TLS cannot supply identity through
headers. This adds an ordinary builtin using the existing Json carrier, with no
keyword or dependency. See [the contract](mtls-bound-jwt.md) and
[example](../examples/mtls-bound-jwt.rut).

## Request-scoped TCP and UDP clients

`tcp(policy, timeoutMs) -> TcpConnection?` and
`udp(policy, timeoutMs) -> UdpSocket?` expose generic client I/O for ordinary
`.rut` protocol libraries. Endpoint policy is fixed at compile/load time:
`{"address":"127.0.0.1","port":6379}`; TCP may add verified TLS with `tls:true`,
`caFile` and `serverName`. UDP is connected to one configured peer.

Unwrapped handles provide `send(Bytes-or-str, timeoutMs) -> i32?`,
`receive(maxBytes, timeoutMs) -> Bytes?` and `close() -> bool`. TCP additionally
provides `readExactly(count, timeoutMs)` and `readLine(maxBytes, timeoutMs)`, both
returning optional Bytes. Line reads include LF; surplus bytes remain buffered.
Each operation is bounded to 8192 bytes and a literal 1–60000 ms timeout.
UDP preserves empty datagrams and fails oversized messages without truncation.
Bind before optional guard. Handles can be typed helper parameters and belong
to the current request/stream; automatic cleanup handles every terminal exit.
`netError()` exposes the immediate failure status. There is no automatic retry.
The existing `httpCall` continuation restrictions also apply.

Dynamic `response(200, body: local)` additionally accepts an unwrapped Bytes
local, preserving arbitrary octets through the existing bounded serializer.
See [the full contract](net-clients.md),
[the executable example](../examples/tcp-udp-clients.rut) and
[the Redis PING library](../examples/clients/redis.rut). Generic TCP listeners,
unrestricted destinations, DNS and general-purpose streaming
parsing/iteration are not introduced by this profile. Single-byte subscripting
is supported separately below.

## Bytes subscripts

`bytes[index] -> i32?` reads one raw octet using a zero-based, unwrapped `i32`
index. The receiver must be an unwrapped `Bytes`. A present result is in 0–255;
negative indices and indices greater than or equal to `bytes.count` return nil.
An empty Bytes has no valid index. NUL is the present value 0, never absence;
no UTF-8 decoding or signed-byte conversion takes place.

```rut
route POST "/resp" {
    let bytes = req.bodyBytes
    guard let kind = bytes[0] else { return 400 }
    guard kind == 43 else { return 422 } // ASCII '+': RESP simple string
    let last = bytes[bytes.count - 1].or(-1)
    guard last == 10 else { return 400 } // LF
    return 204
}
```

Subscripts work on byte literals, helper results, `req.bodyBytes`, WebSocket
payloads and unwrapped TCP/UDP read results. Receiver and index are evaluated
once in source order. Use `guard let`, `if let`, a nil test or `.or(...)` before
using the optional byte as an integer. This is the custom read-only Bytes
subscript contract, not Swift Array subscripting: Swift custom subscripts can
[return optional values](https://docs.swift.org/swift-book/documentation/the-swift-programming-language/subscripts/).
No string/array subscripts, subscript assignment, range syntax, or new numeric
types are added. Checked Bytes slice methods are supported separately below.

## Bytes field extraction

`data.slice(start, end) -> Bytes?` extracts a checked half-open byte range:
`0 <= start <= end <= data.count`. Invalid bounds return nil; equal bounds yield
present empty Bytes. `data.find(delimiter[, start]) -> i32?` returns the first
exact match's absolute byte offset at or after start (default zero), or nil.
Starts must be between zero and count inclusive; an empty delimiter matches at
start. Receivers/delimiters are unwrapped Bytes and indices are unwrapped i32.
NUL/high-bit bytes remain binary. There is no implicit str conversion.

```rut
guard let end = line.find(b"\r\n") else { return 400 }
guard let digits = line.slice(1, end) else { return 400 }
guard let count = parseInt(digits) else { return 400 }
```

Slice is a zero-copy immutable view with its input's lifetime. Find reuses the
existing bounded byte search; neither operation allocates, performs I/O or changes
`netError()`. Ordinary helper, HTTP, WebSocket and native execution share the same
contract. These custom Bytes methods use existing call syntax; Swift collection
range syntax is not added. See [the full contract](bytes-fields.md).

## Bounded buffer parsing

`collectBytes(input, initialState, maxItems, step) -> Collected<Item>?` scans a
complete Bytes buffer with a literal 1–64 step budget. `step` is a compile-time
named ordinary function taking `(Bytes, State)` and returning `(State, Item,
bool)?`. A true Boolean completes after including that item; nil, exhausted
budget or storage failure returns nil for the whole result.

`Collected<T>` is an immutable, invocation-owned result type. Unwrap it before
using `.count -> i32` or `.get(i32) -> T?`. Negative/out-of-range indices return
nil. Typed helper parameters/returns and local annotations preserve the exact
element type. str/Bytes leaves in collected records are copied into the existing
bounded arena. This does not add general Array mutation, source `for` loops,
function values, recursion or streaming network reads.

The step must be synchronous and independent of request/response state, I/O,
cache, randomness and nested collection. State/items use concrete scalar/plain
struct shapes; optional/error leaves and nested collections are absent. See
[the full contract](bounded-parsing.md), [RESP2 library](../examples/clients/resp2.rut)
and [executable example](../examples/resp2-decoder.rut).

## Decimal output and explicit Bytes views

`formatInt(value) -> str?` emits canonical signed decimal from an unwrapped i32
or inferred i64, including both signed limits. It owns the actual digits in the
invocation arena; allocation/storage failure returns nil. `Bytes(str) -> Bytes`
exposes an immutable exact byte view without allocation, validation or transcoding;
`Bytes(Bytes)` is identity. Optional inputs must be unwrapped and ordinary user
bindings shadow these builtins. Direct calls are supported; pipe/UFCS forms are
absent. There is no implicit numeric/text conversion or Bytes `+` operator.
See [bounded command construction](resp2-commands.md).

## Incremental byte buffers and parsing

`concatBytes(left, right, maxBytes) -> Bytes?` copies two unwrapped Bytes into a
new immutable invocation-owned buffer. The unwrapped i32 limit must be 1–8192;
invalid bounds or arena/pool exhaustion return nil. There is no text conversion
or mutation, and previous views survive subsequent appends and network reads.
This ordinary builtin supports direct calls; pipe/UFCS forms are absent.

The [incremental RESP2 library](resp2-streaming.md) composes this with
`collectBytes`: `resp2Stream`, `resp2Feed` and `resp2Receive` retain bounded state
across reads. Status 0 means NeedMore, 1 Complete, -1 Invalid. Completed frames
provide typed tokens and exact pipelined remainder bytes. NeedMore at EOF fails.
Network/HTTP operation, arena and verifier budgets still apply; callers choose a
finite read budget. This does not introduce source loops or persistent sessions.

## Built-in Bytes integer reads

Bytes has built-in methods for fixed-width integer reads, with explicit byte
order and byte offsets. No import is required:

```rut
route POST "/number" {
    guard let value = req.bodyBytes.readU16BE(0) else { return 400 }
    guard value == 300 else { return 422 } // bytes 0x01,0x2c
    return 204
}
```

`readU16BE/LE` and `readI16BE/LE` return `i32?`; `readI32BE/LE` also return
`i32?`. `readU32BE/LE` and `readI64BE/LE` return inferred `i64?`. Both BE
(most significant byte first) and LE (least significant byte first) support
unaligned zero-based i32 offsets. Signed reads use two's complement. Negative
offsets or incomplete input return nil without advancing a cursor or doing I/O.
Unsigned 32-bit values retain the full 0–4294967295 range. These methods operate
on unwrapped Bytes and take one unwrapped i32 offset. They do not add numeric
types: unsigned 64-bit decoding and source i64
annotations remain absent. See [ranges and complete semantics](binary-integers.md).


### Certificate-bound opaque-token introspection

`introspection.requireMtls(document)` in `middleware/introspection.rut` returns
the same authenticated AS metadata after matching its `cnf.x5t#S256` to
`req.tlsClientCertSha256`. Call `requireActive` first, then apply this opt-in policy
before subject/scope authorization. Missing client TLS identity, malformed or
mismatching confirmation fails with challenged 401; forwarded certificate headers
cannot satisfy it. Uses the existing `jwtCertificateBound` primitive; no language
or native ABI change is added. See [the contract](oauth-introspection.md#optional-mtls-certificate-binding)
and [the runnable example](../examples/mtls-introspection.rut).


## Explicit TCP/TLS connection pooling

TCP policy accepts optional `poolIdleMs: 1...60000` (UDP rejects it).
`tcp(policy, timeoutMs)` may borrow a matching idle transport; the returned
`TcpConnection` still belongs to the current request/stream and has a fresh token.
After consuming a complete reply in reusable protocol state, bind
`let returned = connection.release()`. This TCP-only resumable method returns
bool, invalidates all aliases, and either parks a clean transport or closes it.
`close()` always destroys; request completion and cancellation do not auto-pool.
There are sixteen idle entries per shard worker, independent of sixteen active
leases; endpoint/TLS identity and configuration epoch isolate pools. Reload
retires idle transports and prevents old-config leases returning into new pools.
No command replay or application-state reset is performed. See
[pooling ownership and limits](net-clients.md#explicit-cross-request-tcptls-pooling).


### Requiring a complete scope list

`jwtHasAnyScope(verifiedDocument, candidateScopes) -> bool` permits any exact
permission from a nonempty configured OAuth scope list, bounded to 1024 bytes.
It shares the grammar and whole-list validation below with `jwtHasAllScopes`.
Both the candidate list and granted `scope` must be valid in full, even when an
early token matches. Missing/non-string/malformed scopes and invalid policy lists
return false; ordering and duplicates do not change membership. This is metadata
authorization only, after signature/claims policy or authenticated introspection.
It requires unwrapped `Json`/`str` operands and allows user-name shadowing.

`jwtHasAllScopes(verifiedDocument, requiredScopes) -> bool` checks every exact
permission in a nonempty OAuth scope list. The required string is bounded to
1024 bytes; the granted top-level `scope` string retains existing JSON bounds.
Both lists must use the shared strict scope grammar: nonempty ASCII tokens
separated by single spaces. Empty lists, leading/trailing/repeated spaces, tabs,
controls, quotes, backslashes and non-ASCII bytes fail closed. Every list is
validated in full, including suffixes after a match. JSON names and granted values
are decoded before comparison. Matching is case-sensitive, with no prefix match;
ordering and duplicate tokens do not affect the result. Extra granted permissions
are allowed. A malformed/missing/non-string scope or duplicate JSON member returns
false. The original `jwtHasScope` continues to accept exactly one token.

This is metadata authorization, not signature or claims authentication. Apply it
only to the document already admitted by signature and issuer/audience/time
policy, or to an authenticated AS response. Keep required permissions in trusted
route configuration. The operation is synchronous, has no I/O or heap allocation,
retains no views and returns no optional value. User bindings can shadow its name.

`oauth_client.authorizationForScopes(reply, requiredScopes)` applies this policy
to a completed trusted HTTPS token-endpoint reply, then enforces the existing
Bearer grammar/type, positive integer expiry and absence of OAuth errors. Any
failure produces 503 without forwarding; only the returned Bearer header may
replace downstream Authorization. See
[upstream-oauth-all-scopes.rut](../examples/upstream-oauth-all-scopes.rut).

The ordinary `jwt_scopes` module provides `requireAny(document, scopes)` and
`requireAll(document, scopes)`. Import `"middleware/jwt_scopes.rut"` from an
example. Both validate the complete trusted policy first (invalid/empty/oversized
lists return 503), return 403 with `Bearer error="insufficient_scope"` for missing
membership, and preserve the input document on success. Authenticate first:
invalid signatures, issuer/audience/time or duplicate Authorization remain 401.
The module also accepts authenticated active introspection metadata; it does not
perform network calls or authenticate arbitrary JSON. See
[jwt-scope-lists-auth.rut](../examples/jwt-scope-lists-auth.rut).

## Authenticated Redis library sessions

The ordinary Rut Redis library provides binary AUTH/SELECT builders and typed
state-changing commands, plus `redisSessionGet` / `redisSessionSet`. Each session
validates AUTH/SELECT before its business command, then acknowledges RESET before
returning a clean TCP/TLS transport to the pool. This is library composition,
with no new keyword, builtin or change to the sixteen-I/O profile. Status/setup
replies have a two-receive bound; GET/SET keep four. RESET requires Redis 6.2+;
failures close instead of sharing authentication/database state. See
[session results, budgets and ownership](redis-sessions.md).

## Advanced Redis library profiles

Ordinary source modules add bounded MULTI/EXEC and WATCH controls, RESP3 values
and HELLO 3, dedicated finite Pub/Sub consumption, Cluster MOVED/ASK and Sentinel
master discovery/ROLE verification. They retain the existing sixteen-I/O,
8192-byte and 64-token limits. Topology destinations must match preconfigured
TCP/verified TLS policies; ambiguous writes are never replayed. These add no
source keyword, runtime protocol operation or persistent background task. See
[APIs, ownership and finite limits](redis-advanced.md).

Helper normalization may share local initializers proven independent of outer
lexical bindings. Initializers capturing a `let` or collector binding are
reinstantiated in the active scope; source evaluation semantics are unchanged.

## Memcached library client

Import `"clients/memcache-client.rut"` from an example for bounded GET/GETS,
CAS, multi-key retrieval, unsigned counters, append/prepend, GAT/GATS,
SET/ADD/REPLACE, DELETE and TOUCH. These are ordinary Rut functions over
the existing TCP/TLS and Bytes surface. Typed results preserve misses, empty
binary values, conditional non-storage and distinct failure classes. Successful
commands allow explicit pool return; server/transport/framing errors close the
handle. Four receives and 8192-byte request/reply bounds remain within the
existing I/O profile. CAS/counter fields retain the full unsigned 64-bit range
as validated decimal Bytes; multi-key replies publish only after END and retain
each echoed key. Explicit `MemcacheExpiry` choices distinguish relative seconds
from signed 32-bit Unix timestamps; `WithExpiry` storage/CAS/TOUCH/GAT/GATS
helpers preserve the existing relative-TTL entry points. Redis SET expiry also
supports EXAT/PXAT via validated decimal Bytes, including timestamps beyond i32.
See [Redis SET options](redis-commands.md) and
[Memcache options, TTL limits and examples](memcache-client.md).

## Client diagnostics

Redis `redisPing`, `redisEcho` and `redisInfo` reuse the scalar RESP2 executor.
The separate `clients/memcache-info.rut` library provides VERSION and bounded
STATS (general/settings/items/slabs), publishing at most 128 records only after
END. Both retain 8192-byte frames and four fixed-deadline receives. They add no
language or runtime operations. See [contracts and examples](client-diagnostics.md).

## Bounded multi-key deletion

Redis `redisKeys`/`redisKeysAdd` and `redisDeleteKeys` encode one DEL or UNLINK
command for up to eight binary keys and validate the returned deletion count.
The separate `clients/memcache-delete-batch.rut` library sends up to eight basic
text delete commands and publishes ordered per-key outcomes only after all
acknowledgements. Failures never trigger replay; Memcached batches are not atomic.
Existing frame/I/O limits remain unchanged. See [cache invalidation](client-invalidation.md).

## Authenticated client handshakes

`redisHello3Auth` adds AUTH and optional SETNAME to strict RESP3 negotiation.
`clients/memcache-auth.rut` validates a fresh `-Y` challenge before sending its
credential payload. Its GET/SET session helpers always close after use and never
pool authenticated state. Existing framing/I/O bounds and no-replay behavior
remain unchanged. See [authenticated clients](client-authentication.md).

## Online HS256 JWT session permits

Import `middleware/jwt_session.rut` alongside `clients/redis-client.rut`.
`documentHs256(token, secret, previousSecret, issuer, audience)` pins HS256 and verifies the
existing strict claims policy before any lookup. Invalid tokens return 401;
empty issuer/audience or invalid secrets return 503. Current is mandatory at
32–4096 bytes; previous may be empty or within the same range. Validate both
before selecting current-first pinned HS256 verification.
`key(token, namespace) -> Bytes?` constructs the trusted 1–128-byte namespace,
colon, and lowercase SHA-256 of the exact compact token. An invalid namespace or
hash/storage failure returns nil. It hashes bytes and does not authenticate them.

Use the example's `sessionPermitStatus` only with the terminal `redisSessionGet`
result: exact `.value(b"active")` maps to 1, missing/other values to 0, every
service/protocol/cleanup error to -1. `requireActiveStatus(status)` permits only
1, returns challenged 401 for 0, and returns 503 for every other integer. Supplying
1 manually does not prove a verified session. Authenticate before querying and
wait for acknowledged Redis cleanup before publishing identity. Delete a permit
to reject its next authoritative lookup; a missing permit never enables offline
JWT-only fallback. Provisioning, persistence and failover are external policy.
See [jwt-session-auth.rut](../examples/jwt-session-auth.rut) and
[the full contract](jwt-sessions.md), including TLS and in-flight limitations.

### Self-service JWT logout

The [online session example](../examples/jwt-session-auth.rut) now provides
`POST /logout`. Local HS256 signature/claims verification precedes Redis I/O;
the key comes only from that exact Bearer token and trusted namespace. The
example's `sessionDelete` composes authenticated initialization, one bounded DEL
and acknowledged RESET/release. Only canonical integer 0/1 replies allow its
terminal `.ok` result; only that completed result may reach
`sessionWriteSucceeded`. Both present and already-absent permits receive empty
204 plus `Cache-Control: no-store`. Invalid credentials receive 401; service,
protocol and cleanup failures receive 503, even after deletion may have occurred.
Other tokens for the same subject/jti are untouched. Query/body target selection,
enrollment, automatic retries and cookie/OIDC logout are absent. See
[ownership and ambiguous failure behavior](jwt-sessions.md#self-service-logout).

### Local-AOF durable JWT logout

The online session example additionally provides `POST /logout-durable` for
Redis 7.2+. It verifies the same Bearer JWT before service I/O, writes `revoked`
under the exact-token key with the original signed `EXAT`, and requires
same-connection `WAITAOF 1 0 500` plus acknowledged RESET/release before 204.
Every repeated or absent-key logout writes a tombstone; it never extends the
signed expiry. Only `active` permits authorize resource requests. Every write,
barrier, protocol or cleanup uncertainty returns 503. This composes existing
Rut functions and bounded Redis parsing; it introduces no new builtin or syntax.
The local-instance AOF contract excludes stale replicas, failover, snapshot
rollback and in-flight cancellation. See [durable logout](jwt-sessions.md#local-aof-durable-logout).

### Trusted JWT issuance with online enrollment

The [online session example](../examples/jwt-session-auth.rut) also exposes
`POST /sessions`. Set an independent `SESSION_ISSUE_KEY` Bearer service key
(32–4096 valid bytes, distinct from both signing-key slots) and `SESSION_SUBJECT`; both
are load-time environment snapshots. Singleton Authorization verification and
the process-shared five-attempt peer-IP limiter precede enrollment. Client
metadata cannot choose claims, keys or expiry.

`jwt_session.issueHs256(subject, issuer, audience, tokenId, secret, namespace, scopes)`
returns optional `IssuedSession { token: str, key: Bytes, expiry: Bytes }`, using
the fixed 300-second/seven-claim profile and the caller's once-generated UUID jti.
The signed expiry is preserved as decimal Bytes without i32 narrowing.
Authenticated `SET key active NX EXAT exp` and RESET/release must complete before
200/application-jwt/no-store/no-cache token publication. NX refusal and every
service/protocol/cleanup failure return 503 without a token, even if a bounded
orphan permit was already written. The endpoint does not overwrite permits or
renew tokens. This is trusted fixed-subject issuance, not a password/OAuth login.
See [the full contract](jwt-sessions.md#trusted-fixed-subject-issuance-and-enrollment).

### Online-session HS256 key rotation

The example resolves mandatory `JWT_SECRET` and `JWT_PREVIOUS_SECRET` snapshots;
set the latter to `""` when disabled. Current must contain 32–4096 bytes, and each
nonempty previous slot must satisfy the same bound. Invalid configuration returns
503 before lookup; a valid previous slot cannot replace an empty current slot.
Both HS256 verifications run, with independently owned claims and current-first
selection followed by the unchanged claims and permit policies. Issuance always
signs with current. `SESSION_ISSUE_KEY` must differ from both signing keys.

Old tokens keep their hash-derived permit keys during the grace period and can
still log out. Removing the previous key rejects those signatures before Redis
I/O under the adopted configuration, even with an active permit. There is no
automatic key retirement, token rewriting or permit migration. Coordinate staged
trust/configuration rollout and retain one issuer/audience trust domain. See
[key rotation and in-flight limitations](jwt-sessions.md#hs256-signing-key-rotation).

### Scoped online sessions

Set trusted `SESSION_SCOPES` to a nonempty OAuth scope list of at most 1024 bytes.
The complete list is validated before issuance; malformed/empty/oversize values
return 503 without enrollment. The signed `scope` claim comes only from this
configuration. Client headers, query and body cannot request additional grants.

The example's `GET /read` and `POST /write` require exact `orders:read` and
`orders:write`, respectively. Signature/claims verification, online permit lookup
and acknowledged cleanup precede `jwtHasScope`. Invalid/revoked tokens retain
401, service/cleanup errors retain 503, and missing or malformed grants receive
403 with `Bearer error="insufficient_scope"`. Success is empty 204/no-store.
Whole-list validity, case and exact tokens matter; no prefix/case folding or
client metadata fallback occurs. A valid read-only session cannot write.
Existing scope-less tokens remain identity-only on `/private`; issuer changes do
not rewrite their claims or permits. See [the full policy](jwt-sessions.md#scope-authorization-for-online-sessions).


## Consumer registry authentication (implemented bounded profile)

`consumerAuthenticate(presented, configuration, method) -> Json?` supports
`bearer`, `basic` and exact custom `header` credentials in a version-1 bounded
registry. Registry and method must resolve to trusted compile-time `str` configuration;
invalid JSON/schema or request-derived configuration rejects compilation/loading.
It returns only request-owned `consumerId`, `credentialId`, `method` and `groups`.
Authentication failure is nil; group authorization stays explicit. Pass singleton
request header accessors; duplicates do not become guest access. No query/body
credential source is implicitly enabled by this profile. See [Consumer registry](consumer-registry.md)
for the exact schema, 32-Consumer/64-credential bounds, rotation, disabled state,
RCU/native-program ownership, redaction and current publication interfaces.
The offline `rut-consumers` executable validates, previews redacted replacements,
inspects and transactionally updates immutable private snapshot files; it adds no Rut syntax or automatic
running-gateway publication. See [offline administration](consumer-registry.md#offline-administration).

## Persistent replay claim composition (implemented bounded profile)

The ordinary Rut Redis module exposes `redisReplayClaim` for atomic authenticated
`SET NX EX 601` claims, with terminal status after RESET/release. `replay.key` and
`replay.requireClaimed` compose it after Standard Webhooks or fixed signed-request
verification. Claims use stable signer/profile namespaces and SHA-256 identities;
no gateway Cache or GET-before-SET fallback is used. See [replay claims](auth-replay.md)
for the freshness/retention assumption, failure uncertainty, persistence ownership
and distinction from exactly-once business delivery. These are Rut functions,
not new language keywords or runtime protocol opcodes.

`redisReplayDurableClaim(connection, username, password, database, key) -> i32`
is the optional local AOF-confirmed variant from the same Redis module. Redis
7.2+ must confirm `WAITAOF 1 0 500` after the SET on the same connection, then
RESET/release must succeed before status 1/0. A missing acknowledgement,
unsupported command, disabled AOF, malformed reply or cleanup failure returns -1;
it never falls back to the ordinary claim. The bounded pipeline fits sixteen I/O
operations and leaves uncertain claims in place. See the
[local persistence/recovery contract](auth-replay.md#confirmed-local-aof-profile);
replica failover and exactly-once work are separate.


### Explicit Consumer query/form sources

`consumerAuthenticateQuery(req.path, configuration, name)` and
`consumerAuthenticateForm(req.body, configuration, name)` return optional Json.
Registry/name must be compile-time strings. They authenticate one explicitly
selected URL-encoded raw-key field against registry method `header`, reject all
decoded duplicate names/malformed fields, and return identity plus sanitized
`remaining` fields. The ASCII profile is bounded to 4096 input bytes, 64 fields,
64-byte field names and 512 decoded credential bytes. Form callers require a
singleton expected Content-Type. They do not mutate the original request or add
implicit fallback; use an explicitly rebuilt upstream request, as in
[the source/redaction contract](consumer-registry.md#explicit-query-and-form-credentials).

### Keycloak access-token role helpers

`middleware/keycloak.rut` supplies `hasRealmRole(document, role)` and
`hasClientRole(document, client, role)` for already verified access-token claims.
`requireRealmRole`, `requireClientRole` and `requireRealmAndClientRole` preserve
that document on success, respond 503 for invalid trusted policy and 403 for
missing/malformed/nonmatching selected memberships. Client IDs are bounded
ASCII `[A-Za-z0-9._:-]+`; role names are nonempty exact strings up to 128 bytes.
Realm/client containers are objects and whole role arrays are validated. The
[example](../examples/keycloak-role-auth.rut) authenticates through configured
RS256 before calling them. Roles, azp, headers and query parameters never replace
issuer/audience/signature checks. These are ordinary Rut helpers with no added
builtin or syntax. See [Keycloak role policies](keycloak-roles.md).

The example additionally calls `keycloak.requireBearerAccessToken(document)`
after RS256 validation: the signed payload `typ` must equal `Bearer` exactly.
Missing, non-string, ID-token and refresh-token types receive a challenged 401,
regardless of matching roles. This provider gate is separate from the JWS header
`typ` policy, and neither gate replaces signature/issuer/audience/time checks.
The role metadata helpers alone do not enforce token use.
