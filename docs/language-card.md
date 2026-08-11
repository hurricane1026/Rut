# Rutlang Language Card

Canonical syntax reference for generating `.rut` code. One blessed idiom per
task — if a form is not on this card, do not invent it. Derived from DESIGN.md
§3 (the authoritative spec); keep the two in sync.

Core contract: **Swift-exact or absent** — anything that looks like Swift
behaves exactly like Swift; near-miss variants do not exist in this language.

**Implementation status**: this card documents both shipped Core and the target
surface. `✅` means the form lowers to an exercised runtime path, `🧩` means the
front end or runtime substrate exists but the form is gated or incomplete, and
`⏳` means target syntax that must not be emitted for a current deployment. An
unmarked form without a status marker is shipped Core; a form in a target survey
does not become current merely because the parser can recognize part of it.

Every `rut` fence is a **front-end** fixture unless it is immediately preceded
by a reasoned `<!-- rut-example: skip ... -->` marker. Unmarked examples parse
and type-check in CI, but that gate alone does not prove MIR/RIR lowering, JIT
code generation, or runtime support. Runtime claims below are backed by focused
lowering or integration tests.

## File anatomy

A `.rut` file is a flat list of top-level declarations (any order, no `main`):

<!-- rut-example: skip target-surface overview mixes pending top-level forms -->
```rut
// PR #184 adds standalone examples; no tokenBucket helper is importable yet.
import "middleware/auth.rut"                        // file stem = namespace: auth.jwtAuth

listen :443                       // ⏳ ports (no top-level listen yet)
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

`var` is ⏳ target syntax for func/handler-local mutation and is never valid at
top level. Current code uses immutable `let` bindings.

## Lexical

<!-- rut-example: skip lexical survey contains expression fragments and pending literals -->
```rut
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
json({ users: [], total: 0 })           // literal object/array serialization ✅
json({ path: req.path })                // ✅ reusable bounded JSON value
json(payload)                           // ✅ declared struct; declaration-order fields
json({ tags: req.queryAll("tag") })     // ✅ ordered bounded string-list array
json({ tags: [req.path, "static"] })    // ✅ bounded Array<T>; nested/struct elements recurse
func envelope(path: str) -> Json => json({ path: path })

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

JSON objects preserve source order; declared structs use field declaration
order, and arrays/string-list views preserve carrier order. Duplicate object
keys are a compile error rather than last-write-wins. Runtime strings are JSON
escaped at the sink. A direct dynamic JSON response is capped at 7 KiB, while a
`Response.body` mutation is capped at 4 KiB so it can remain stream-owned across
resume. An overflow never publishes a partial body and normally fails closed as
500; body-forbidden statuses (informational, 204, 205, and 304) preserve their
status because no dynamic body can be emitted.

## Bindings and control flow

<!-- rut-example: skip control-flow survey contains statement fragments and pending forms -->
```rut
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

for item in [1, 2, 3] {                   // compile-time array only; bounded unroll, no while
    guard item >= 0 else { break }
    guard item != 0 else { continue }
}
// break / continue target the innermost bounded `for`; no labels or loop else

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

<!-- rut-example: skip illustrative helper depends on target JWT and user APIs -->
```rut
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

<!-- rut-example: skip function survey contains fragments and pending call syntax -->
```rut
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

Current named source annotations are `bool`, `i32`, `str`, `Response`, `Json`,
`Server`, and declared struct/variant types. `i64` is a runtime value carrier
produced by large literals, `i64(x)`, time, and `Cache`; it is not a general
user-written annotation yet. Request fields also carry compiler-known domain
types such as `IP`, but those internal carriers are not all declarable source
types. Bounded array `[T]` and tuple annotations are accepted when their element
shapes are composed from supported types.

General first-class `Duration ByteSize StatusCode Method IP CIDR Port MediaType
Regex Time` and the remaining numeric types `i8 i16 i64 u8..u64 f32 f64` are ⏳
target surface as user-written annotations. Tuple `.0`/`.1` projection and
`let (x, y) = pair` destructuring are also ⏳.

<!-- rut-example: skip type survey contains fragments and experimental protocol syntax -->
```rut
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
protocol Hashable { func hash() -> u64 }                    // compatibility/experimental API
User impl Hashable { func hash() -> u64 => fnv64(self.id) } // generated Core uses direct helpers

parseInt("42")        // ⏳ i32? — parse APIs for text (parseFloat, IP.parse,
                      //         CIDR.parse, Duration.parse) all pending
200 as str            // ⏳ infallible conversion (`as` / checked `as?` pending)
```

## Request / Response

<!-- rut-example: skip request-response survey contains route-scoped statement fragments -->
```rut
// Typed built-in properties (standard headers)
req.method == .GET          req.path (str)           req.remoteAddr (IP)
req.contentLength (ByteSize)  req.contentType (MediaType)
req.authorization (str?)   req.host  req.userAgent  req.origin (str?)

// Raw headers — function access ONLY (never req.X-Foo property syntax)
req.header("X-Request-ID")   // str?
req.set("X-User-ID", "123")  // ✅ replace/dedupe; statement-only
req.add("X-Tag", "a")        // ✅ preserve existing fields and append
req.getAll("Accept")         // [str], preserves field order

// Route captures / query / cookies / body
req.params.id                // from :id — captures NEVER shadow built-ins
req.query("page")            // str? (first value)
req.queryAll("tags")         // [str], preserves query order
req.queryAll("tags").len     // i32; empty when no value matches
req.queryAll("tags").first() // str?; `.at(i)` is also bounds-safe
req.cookie("session")        // str?
req.body(User)               // typed parse, error-capable → guard let
req.bodyRaw                  // str, error-capable; assignable before forward
req.bodyJson()               // dynamic Json, error-capable
req.ctx.userId               // typed per-request context (user declares struct Ctx)

// Response construction — names are literal; values may be runtime strings
let resp = response(429)          // ✅ literal status
let initialStatus = resp.status   // ✅ i32; observes the latest pending replacement
let initialBody = resp.body       // ✅ str; initially empty, then pending-aware
resp.set("Retry-After", "60")     // ✅ literal replace/dedupe
resp.set("X-Request-Path", req.path) // ✅ dynamic value
resp.remove("Server")             // ✅ literal delete
resp.add("Set-Cookie", "a=1")     // ✅ literal append/multi-value
resp.header("Retry-After")        // ✅ str?; observes prior set/add/remove mutations
resp.body = "retry later"         // ✅ bounded plain-string body replacement
let body = json({ ok: true, path: req.path })
resp.body = body                  // ✅ reusable JSON; serialized at the body sink
resp.status = 503                 // ✅ StatusCode replacement
return resp
return 200, json({ ok: true, items: [] }) // ✅ compact literal JSON body
```

Dynamic Response header mutations are stored in the resumable handler context,
so pending mutations survive `wait` and remain isolated per request/stream. A
handler-local builder must be returned directly. A `chain after` helper
must have exactly one `Response` parameter and may use `set`/`add`/`remove` with
literal names and runtime string values; its effects apply to successful direct
and forwarded responses. Mutations stay pending until the selected success terminator, so a
guard or pre-middleware short circuit cannot inherit them. Applying any of these
mutations to a forwarded response requires buffered forwarding, either terminal
`return forward(upstream, buffered: true)` or the first-class expression form.
Status/body writes use the same resumable commit boundary as headers and may be
used by `chain after` after a yield. Body replacement owns up to 4 KiB in the
request/stream context; plain `str` and reusable `Json` values therefore survive
resume without borrowing serializer scratch. Overflow or a runtime status
outside 100...599 fails closed as 500. Status/body reads are supported on a
handler-local builder and observe its latest pending replacement; the status
carrier is currently plain `i32`.

Terminal buffered forwarding accumulates and validates the complete upstream
response within the 16 KiB proxy buffer, de-frames chunked bodies, removes
hop-by-hop headers, then applies committed header/status/body mutations. The
HTTP/1 and HTTP/2 paths use the same boundary and preserve effects across
`wait`. Malformed, truncated, upgraded, or over-cap upstream responses fail
closed as 502; invalid or overflowing mutations fail closed as 500. Combining
buffered response handling with `set_path` or `set_header` request rewrites is
rejected until the HTTP/2 request-rewrite path is wired. The expression form
`let resp = forward(upstream, buffered: true)` owns the filtered status, body,
and up to 64 headers in a separate lazy 16 KiB stream slice. Reads, mutations,
and a subsequent `wait` remain valid until `return resp`; the slice is returned
to the pool after final serialization. Unbuffered expression forwarding is
rejected because it cannot provide owned response fields.

## State types (top-level, per-shard, bounded)

<!-- rut-example: skip state survey intentionally includes pending state and notify forms -->
```rut
let buckets = Cache<IP, i64>(capacity: 100000)   // lossy per-key slots
let tat = buckets.get(req.remoteAddr).or(0)      // i64? — miss = never-seen OR evicted; ALWAYS handle
buckets.set(req.remoteAddr, v)                   // bare statement, before any guard/wait/for;
                                                 // may evict a colliding neighbor
// Never store anything whose absence yields a wrong answer (sessions,
// in-flight counts). Rate limiting over Cache is implemented in
// examples/ratelimit.rut;
// Counter<K> is deleted; Hash is RESERVED (strict design accepted, runtime ⏳).
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
// The designed strict Hash.update executes one pure bounded updater on the
// owner shard; it is not implemented yet (docs/hash-state.md).
// ⏳ cross-node backend is unspecified until Cache has a freshness contract.
```

## Routing

<!-- rut-example: skip routing survey includes an intentionally deprecated decorator -->
```rut
route GET "/health" { return 200 }
route GET "/users/:id" {                         // capture: req.params.id
    return forward(userService)
}

@rateLimit(limit: 1000, window: 1m, scope: global) // retain for an exact cross-shard cap
route POST "/form" { return 204 }
```

The shipped parser accepts repeated top-level `route METHOD "pattern"`
declarations. The grouped `route { ... }` surface (middleware pattern
bindings, host/path groups, method unions, typed captures, expression entries,
and `_` catch-all) is ⏳ target syntax and must not be emitted yet.

Precedence: literal segment > `:param` > `*rest`; exact host > wildcard > `_`.
Indistinguishable routes are a compile error. Stable middleware uses an explicit
`chain` direction:

<!-- rut-example: skip chain surface is a focused fragment with external helpers -->
```rut
func add_trace(_ req: i32, _ resp: Response) -> i32 {
    resp.set("X-Request-Path", req.path)
    0
}
chain observability { after add_trace(req, resp) }
route GET "/users" use chain observability { return forward(users) }
```

`before` helpers may gate a route; `after` supports committed Response header,
status, and bounded plain-string body writes, including after a visible yield.
Forwarded responses require the explicit terminal buffered form above. Reading
or incrementally editing an upstream buffered body remains ⏳.

## I/O

Current upstream declarations accept packed endpoints, dictionary-form
IPv4/IPv6/DNS endpoints, bounded backend lists, and verified upstream TLS:

```rut
upstream plain at "127.0.0.1:8080"
upstream secure {
    host: "api.example.com",
    port: 443,
    tls: { server_name: "api.example.com" }
}
```

The TLS `server_name` is sent as SNI and verified against the system trust
store. Upstream client TLS currently uses the epoll path; client certificates,
custom trust roots, and insecure verification modes are ⏳.

<!-- rut-example: skip I-O survey intentionally includes pending capabilities -->
```rut
// Proxy — the ONLY three forms
return forward(users)                          // zero-copy, terminal
return forward(users, buffered: true)          // ✅ bounded terminal buffering + after mutations
let resp = forward(users, buffered: true)      // ✅ first-class bounded Response expression
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

```rut
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

For equivalent shard-scoped parameters, this matches shard-local `@rateLimit`,
including leaving TAT unchanged after a rejection (verified by JIT execution
tests). It does not replace `scope: global`: retain that compatibility decorator
for the process-shared exact cross-shard cap. Move the set to
the leading statement region when a deliberately punitive policy should meter
every attempt. The Rut form also supports custom policies such as per-tier
limits and composite conditions. See
examples/ratelimit.rut for the packed fixed-window variant, which permits
boundary bursts and is not a sliding-window limit.

## Cache state (per-key counters/timestamps — DESIGN.md §3.3.6)

```rut
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

## Built-ins

The current source-to-runtime built-ins are deliberately smaller than the
target library:

| Status | Surface | Current boundary |
|---|---|---|
| ✅ | `s.matches(re"")` | Compile-time validated regex and runtime match |
| ✅ | string-list `len`, `isEmpty`, `first`, `at(i)` | Available on bounded `[str]` request views |
| ✅ | `bitwise.and/or/xor/flip/shiftLeft/shiftRight` | Same-width `i32`/`i64` operations |
| ✅ | `.or(default)`, compatibility `any`/`all` | Eager fallback semantics documented above |
| ✅ | `i64(x)`, `max(a,b)`, `min(a,b)` | Integer conversion/min/max only |
| ✅ | `time.nowMicros()` | Monotonic `i64`, latched per invocation; blocked in wait routes |
| ✅ | `json(v)` | Bounded JSON values and response serialization |
| ✅ | `stats()`, `metrics()` | Bounded, value-only snapshots |
| ✅ | `reload() -> bool` | Route-only and capability-gated by `--allow-route-reload` |
| 🧩 | `upstream.mark(server, healthy:) -> bool` | Timer-only compiler/runtime plumbing; production activation waits on replay lowering |

The following names are ⏳ target library surface and are **not current source
built-ins**: string length/case/trim/prefix/suffix/replace/split/slice helpers;
MD5, SHA, FNV and HMAC helpers; JWT; AES-GCM; `randomBytes` and `uuid`; Base64,
base64url, hex, URL, HTML and Unicode codecs; `env`; structured logging; and
`upstream_status`, `config_dump`, and `shard_stats`. An opcode or design entry
without analyzer, lowering, JIT, and execution coverage is not an available
Rutlang builtin.

`json(stats())` is a handler-entry snapshot for the invoking shard;
`json(metrics())` is the process aggregate captured at the same boundary. Both
use fixed field order and unsigned decimal counters:

```json
{"scope":"shard","shard_id":0,"shard_count":1,"requests":{"total":0,"active":1,"latency_us":{"buckets":[0,0,0,0,0,0,0,0,0,0,0],"sum":0,"count":0}},"connections":{"total":1,"active":1,"closed":0},"memory":{"arena_used":0,"slices_used":0,"slices_free":0,"connections_used":0}}
```

The process form replaces `scope` with `"process"`, omits `shard_id`, and
aggregates the same `requests`, `connections`, and `memory` fields. Serialization
is bounded by the dynamic-response limit and fails the response closed with 500
if the runtime capability is unavailable.

`Server` is an opaque, non-constructible carrier that may be passed through a
typed pure helper. The bounded form below documents the compile-time and runtime
plumbing contract; it is not production-loadable yet because mark replay lowering
has not activated the generated timer metadata:

```rut
upstream users { backends: ["127.0.0.1:8080", "[2001:db8::1]:8080"] }
func check(_ server: Server) -> bool => true
timer health, every: 5s, shard: 0 {
    for server in users.servers {
        guard users.mark(server, healthy: check(server)) else { return 503 }
    }
    return 200
}
```

Hostname backends resolve A/AAAA records when the configuration loads. A load
fails closed if resolution fails or expands beyond the eight-backend limit.

Control-plane mutations use visible boolean failure results and never introduce
hidden waits. Their authority, generation ordering, and replay contract are
specified in `docs/control-plane-mutations.md`; route `reload()` activation is
✅, while `upstream.mark` production activation remains ⏳ until replay lowering
is implemented.

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

```rut
upstream users at "10.0.0.1:8080"
// A standalone Cache/GCRA implementation lives in examples/ratelimit.rut.
// Unmatched methods and paths return 404 when a program is loaded.

route GET "/health" { return 200 }
route GET "/users/:id" { return forward(users) }
```

Typed request-body parsing is still target syntax, so keep the validating
create route explicit but skipped until the compiler implements it:

<!-- rut-example: skip typed request-body parsing is target syntax pending compiler support -->
```rut
upstream users at "10.0.0.1:8080"
struct User {
    name: str
    email: str
}
route POST "/users" {
    guard let user = req.body(User) else { return 400 }
    return forward(users)
}
```
