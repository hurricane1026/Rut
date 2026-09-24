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

listen :8080                      // one cleartext IPv4 wildcard listener
tls "api.example.com", cert: env("CERT"), key: env("KEY")
defaults { clientMaxBodySize: 10mb }

let users = upstream { "10.0.0.1:8080" }            // upstreams
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
json({ users: [], total: 0 })           // object literal syntax ✅; json() lowering/runtime ⏳

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
  `return 200, body`, `return resp`, `return forward(x)`.
- **Middleware/helper func**: `return` only produces the function's normal
  value (or passes through); to end the whole request immediately use
  **`respond`**: `respond 401` / `respond 401, "expired"` / `respond resp`.
  A helper-local Response may carry ordered literal `set`/`add`/`remove`
  mutations. A `chain after` helper may receive the runtime `Response` and add
  ordered header effects to a successful handler response.

```swift
func auth(_ req: Request, role: str) -> User {
    let token = req.authorization.or("")
    guard token.hasPrefix("Bearer ") else { respond 401 }
    let claims = jwtDecode(token.trimPrefix("Bearer "), secret: env("JWT_SECRET"))
    guard let claims else { respond 401 }
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
req.path.trimPrefix("/api").split("/")            // UFCS chaining

// Pipeline | — use when the value lands in a NON-first position.
// RHS must be a call with an explicit _ / _N placeholder (else compile error).
let parts = req.path | trimPrefix("/api", _) | split(_, "/")
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
req.bodyRaw                  // str, error-capable; assignable before forward
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

Dynamic handler-local Response mutations require a direct route with no guards,
decorators, `wait`, or `for`, exactly one builder, and that builder must be
returned directly. A `chain after` helper must have exactly one `Response`
parameter and may use `set`/`add`/`remove` with literal names and runtime string
values; its effects apply to successful direct and forwarded responses on routes
without `wait` or `for`. Pending mutations are published only by the selected
success terminator, so guard and pre-middleware short circuits cannot inherit
them. Reading or changing a buffered response body/status remains ⏳ and needs a
resumable, stream-owned runtime Response object.

The literal `response(status, body: "...")` form is limited to 1 MiB. Its bytes
are a non-owning view into the loaded program's RIR/module response-body
storage; `LoadedProgram` keeps that storage alive through teardown and reload
retirement. This documents the configured local/static response path and does
not make dynamic `resp.body` mutation available.

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
HTTP methods. There is no `ANY` route keyword; write the omitted-method form.
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

## I/O

```swift
// Proxy — the transparent forms plus the explicit header-only policy form
return forward(users)                          // zero-copy, terminal
return forward(users, request_policy: {
    version: "HTTP/1.1", host: "upstream", connection: "omit",
    strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade"]
})                                               // ID1: fixed header-only rebuild
// ID2 adds content_length_position: "after_host" (Content-Length pinned
// right after the rewritten Host line; a request with no Content-Length at
// all is admitted unchanged -- only an explicit Content-Length: 0 is
// rejected).
// ID3 adds retained_header_value: "trim_sp_preserve_htab" (retained values
// keep leading/trailing HTAB while SP is trimmed; bounded to bodyless GET).
// The two are mutually exclusive and both require host: "upstream".
return forward(users, request_policy: {
    version: "HTTP/1.1", host: "upstream", connection: "omit",
    content_length_position: "after_host",
    strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade"]
})
// host: "preserve" is a separate closed combination (Envoy-compatible H1,
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
// kept separately). A Connection nomination of `te` itself does not force a
// drop -- this same trailers check decides its fate, matching Envoy's own
// nomination special case; rejects Connection nominating `upgrade` alongside an Upgrade header
// whose trimmed value is non-empty (even with `close`) but admits a bare
// Upgrade header otherwise -- including an Upgrade header present with an
// empty/OWS-only value alongside an `upgrade` nomination -- and always
// strips it (and any nominated Upgrade) from the forwarded request;
// rejects more than one X-Forwarded-Proto field; a single field's value that
// is not (case-insensitively) exactly "http" or "https" -- empty, OWS-only,
// or otherwise invalid such as "http,https" -- is overwritten in place, at
// that field's original position, with "http" rather than dropped and
// forwarded blank or malformed; a valid value passes through unchanged in
// place; a trailing "x-forwarded-proto: http" is appended only when the
// client sent no such field at all; rejects a fragment-bearing request
// target; and drops the sixteen client-supplied headers Envoy itself strips
// for external requests, plus one Rut-side hardening addition, seventeen in
// total (`x-envoy-internal`, fourteen more `x-envoy-*` names,
// `x-forwarded-client-cert`, and `x-envoy-external-address`;
// docs/envoy-compatibility.md).
return forward(users, request_policy: {
    version: "HTTP/1.1", host: "preserve", connection: "omit",
    header_names: "lowercase", forwarded_proto: "http",
    strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade", "Proxy-Connection"]
})
// Bounded response-policy serialization currently accepts only a cleartext
// HTTP/1.1, origin-form, bodyless non-HEAD request and one final upstream
// HTTP/1.1 response framed by exactly one Content-Length. Requests with a
// body, TLS/H2, interim/Upgrade responses, chunking/trailers, close-delimited
// framing, or unsupported status/header controls fail closed; transparent
// forward(...) remains the default for all other routes. One exception: a
// fixed-Content-Length request paired with `host: "preserve"` (ID4) or the
// plain `host: "upstream"` strip (ID1) is admitted alongside a
// response_policy too — fully buffered, unchunked, with no pipelined
// successor bytes, and never served from a reused idle upstream socket (see
// `request_policy_body_response_admitted` in callbacks_impl.h).

return forward(users, response_policy: {
    version: "HTTP/1.1", framing: "content_length", connection: "request",
    server: "nginx/1.29.7", date: "current", hide_headers: ["Date", "Server", "X-Pad"]
})
// Public HEAD suppression is an explicit paired source contract:
return forward(users,
    response_policy: {
        version: "HTTP/1.1", framing: "content_length", connection: "request",
        head_mode: "suppress_body", server: "nginx/1.29.7", date: "current",
        hide_headers: ["Date", "Server", "X-Pad"]
    },
    failure_policy: {
        version: "HTTP/1.1", status: 502, reason: "Bad Gateway",
        content_type: "text/html", server: "nginx/1.29.7", date: "current",
        connection: "request", head_mode: "suppress_body", body: b"<html>...</html>"
    })
// head_mode defaults to "reject". "suppress_body" is accepted in source only
// when both policies select it; it remains bounded to cleartext H1.1, bodyless
// HEAD with either no Connection field (the HTTP/1.1 default-keepalive shape)
// or exactly one `Connection: close`, one IPv4 upstream, strict success, and
// connect-establishment failure. On a `host: "preserve"` (ID4) route only,
// this Connection grammar widens to the same nomination rule the ordinary
// ID4 request-policy path already applies: every comma-separated,
// case-insensitive token is admitted -- and, along with its own field,
// dropped -- unless it names a protected header (`content-length`, `host`,
// the three forwarded-provenance headers, or a pseudo-header-shaped token
// starting with `:`, each of which fails the whole request closed instead)
// or is a genuine upgrade (a nominated `upgrade` token together with a
// semantically present, non-empty/OWS `Upgrade` field anywhere on the
// request -- e.g. `Connection: close, upgrade` with an absent or
// empty/OWS-only `Upgrade` header is not genuine and is admitted, both
// fields then stripped). Persistence is decided by the `close` token alone,
// independent of whatever else is nominated in the same value --
// `Connection: close, X-Foo` behaves like the plain `Connection: close`
// shape, and `Connection: X-Foo` alone (no `close`) behaves like no
// `Connection` field at all -- since a nomination such as `te`, `X-Foo`, or
// a genuine-upgrade-free `upgrade` never affects persistence and ID4's own
// request-policy path already forwards the request correctly regardless of
// this response-side contract (canonicalizing a paired `TE` field when
// nominated, for example). While the broader failure rendezvous is not
// part of this contract, timeout, malformed/incomplete/excess response, and
// upload/send/recv failure close before emitting downstream bytes.
// response_policy.connection: "keep_alive" requires a keep-alive downstream
// request and emits keep-alive. "request" follows the parsed downstream
// HTTP/1.1 intent, emitting keep-alive by default and close for
// Connection: close. The strict response-domain limits above remain unchanged.
// Valid downstream Upgrade requests are rejected by this policy; Upgrade
// passthrough remains PARTIAL in the first slice.
// header_order: "upstream" is a separate closed combination (Envoy-compatible
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
// host: "preserve"). The fixed-order layout above (`header_order` omitted)
// is unchanged.
return forward(users, request_policy: {
    version: "HTTP/1.1", host: "preserve", connection: "omit",
    header_names: "lowercase", forwarded_proto: "http",
    strip_headers: ["Connection", "Keep-Alive", "TE", "Expect", "Upgrade", "Proxy-Connection"]
}, response_policy: {
    version: "HTTP/1.1", framing: "content_length", connection: "request",
    header_order: "upstream", header_names: "lowercase",
    connection_header: "close_only", status_reason: "canonical",
    server: "envoy", date: "preserve_or_current", hide_headers: []
})
// local_response and failure_policy each accept an Envoy-compatible H1
// header-order combination too: `header_names: "lowercase"`,
// `connection_header: "close_only"`, and `header_order` are optional as a
// closed trio (any one present requires all three); the fixed-order layout
// above (all three omitted) is unchanged. `connection_header: "close_only"`
// means `connection: close` is appended last only when the downstream
// connection is closing; it is omitted entirely otherwise (unlike the
// fixed-order layout, which always sends one or the other).
//
// local_response header_order: "date_server_length" is the empty-body
// no-route shape (`date, server, [connection: close,] content-length: 0`):
// requires `body: b""` and `content_type` absent, 4xx/5xx status only.
unmatched { return local_response({
    version: "HTTP/1.1", status: 404, reason: "Not Found", server: "envoy",
    date: "current", connection: "request", connection_header: "close_only",
    header_names: "lowercase", header_order: "date_server_length",
    head_mode: "suppress_body", body: b""
}) }
// local_response header_order: "length_type_date_server" is the bodied
// shape (`content-length, content-type, date, server, [connection: close]`):
// follows the fixed-order layout's content_type/body rules on a 4xx/5xx
// status (content_type required, body may be non-empty).
//
// failure_policy accepts the same `length_type_date_server` layout, and only
// it: status 503 is admitted paired with it and a non-empty body (Envoy's
// connect-failure representation); 502 stays exactly the fixed-order-only
// contract above. timeout_failure_policy stays fixed-order-only (400..599).
return forward(users, failure_policy: {
    version: "HTTP/1.1", status: 503, reason: "Service Unavailable",
    content_type: "text/plain", server: "envoy", date: "current",
    connection: "request", connection_header: "close_only",
    header_names: "lowercase", header_order: "length_type_date_server",
    body: b"upstream connect error or disconnect/reset before headers. reset reason: remote connection failure"
})

// Explicit request-derived redirects are fully specified (no defaults). The
// first source slice accepts the generic Redirect terminator in the existing
// terminal route/control forms; H1 cleartext serialization is bounded by the
// policy/runtime domain above, while H2 and simulator execution remain
// unsupported.
return redirect({
    scheme: "http", authority: "request_host", port: "actual_listener",
    path: "static", query: "preserve_raw", date: "current", connection: "close",
    status: 301, reason: "Moved Permanently", server: "nginx/1.29.7",
    content_type: "text/html", target_path: "/api/", body: b"<p>moved</p>"
})
let resp = forward(users, buffered: true)      // buffered Response, then return resp
return forward(users, streaming: true)         // large bodies, no buffering

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
string:  s.len s.isEmpty s.hasPrefix/hasSuffix/contains s.upper()/lower()/trim()
         s.trimPrefix/trimSuffix/replace/split/slice s.matches(re"") s.match(re"")
hash:    md5 sha1 sha256 sha384 sha512 fnv32 fnv64 | hmacSha256/384/512
jwt:     jwtDecode(tok, secret:|publicKey:) jwtEncode(claims, ..., alg: .HS256)
crypto:  aesGcmEncrypt/Decrypt randomBytes(n) uuid()
encode:  base64 base64url hex urlEncode urlDecode htmlDecode unicodeNormalize
time:    time.nowMicros() -> i64 (monotonic µs; latched per invocation — all
         uses in one request see the same value)  max(a, b)  min(a, b)
         — now()/time(s)/Duration arithmetic still ⏳
misc:    env(k) json(v) log.info/warn/error(msg, key: val, ...)
admin:   stats() metrics() reload() upstream_status() config_dump() shard_stats()
```

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
let users = upstream { "10.0.0.1:8080" }
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
