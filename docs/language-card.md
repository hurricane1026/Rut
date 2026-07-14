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
import { rateLimit } from "stdlib/ratelimit.rut"   // selective import
import "middleware/auth.rut"                        // file stem = namespace: auth.jwtAuth

listen :443                       // ⏳ ports (no top-level listen yet)
tls "api.example.com", cert: env("CERT"), key: env("KEY")
defaults { clientMaxBodySize: 10mb }

let users = upstream { "10.0.0.1:8080" }            // upstreams
let limits = Counter<IP>(capacity: 100000, window: 1m)   // state (per-shard)

struct Ctx { userId: str }        // types
func auth(_ req: Request, role: str) { ... }     // middleware/helpers
timer cleanup, every: 1m { ... }  // background tasks (1s+ intervals; body: no req/forward/wait)
timer push, every: 5s, shard: 0 { ... }   // shard-pinned singleton (default: every shard)
init { ... }    shutdown { ... }  // lifecycle hooks
route { ... }                     // exactly one route block
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
json({ users: [], total: 0 })           // ⏳ object literal (no object-literal production yet)

// Operators — each symbol has exactly one meaning in expressions
&&  ||  !                               // boolean (identical to Swift)
|                                       // pipeline ONLY (see below)
+  -  *  /  %                           // arithmetic (i32/i64, same-width operands; wraps on
                                        // overflow; x / 0 == 0, x % 0 == 0; literal / 0 is a
                                        // compile error; -x OK)
i64(x)                                  // widen i32 → i64 (the ONLY conversion; literals that
                                        // don't fit i32 are i64 automatically; no i64 type
                                        // annotations, no narrowing, no match on i64)
==  !=  <  >  <=  >=                    // comparison
=>                                      // single-expression body / match arm
->                                      // function return type
@                                       // decorator

// Bitwise = named functions, never symbols (all i32; shift amounts
// outside 0..31 saturate: shiftLeft → 0, shiftRight → sign fill)
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
  **`respond`**: `respond 401` / `respond 401, "expired"` (⏳ `respond resp`
  with a Response value is pending — status must be a literal int today).

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
req.set("X-User-ID", "123")  req.add("X-Tag", "a")   req.getAll("Accept")   // ⏳ only req.header is wired up

// Route captures / query / cookies / body
req.params.id                // from :id — captures NEVER shadow built-ins
req.query("page")            // str? (first value)
req.queryAll("tags")         // ⏳ [str]
req.cookie("session")        // str?
req.body(User)               // typed parse, error-capable → guard let
req.bodyRaw                  // str, error-capable; assignable before forward
req.bodyJson()               // dynamic Json, error-capable
req.ctx.userId               // typed per-request context (user declares struct Ctx)

// Response construction — ⏳ only `return response(...)` works today; locals + mutators pending
let resp = response(429)          // ⏳ (no general response() builder; see note above)
resp.set("Retry-After", "60")     // set/replace header
resp.remove("Server")             // delete header
resp.add("Set-Cookie", "a=1")     // append multi-value
resp.body = json(data)            // body
resp.status                       // StatusCode, read/write
return resp
```

## State types (top-level, per-shard, bounded)

```swift
let sessions  = Hash<str, Session>(capacity: 50000, ttl: 30m)
let cache     = LRU<str, str>(capacity: 10000, ttl: 5m, coalesce: true)
let blacklist = Set<IP>(capacity: 100000)          // Set<CIDR> = LPM trie
let limits    = Counter<IP>(capacity: 100000, window: 1m)      // sliding window
let bursts    = Counter<IP>(capacity: 100000, rate: 100, burst: 20) // token bucket
let seen      = Bloom<str>(capacity: 1000000, errorRate: 0.01)
let flags     = Bitmap(size: 256)

sessions.set(k, v)  sessions.get(k) /*V?*/  sessions.delete(k)  sessions.contains(k)
limits.incr(key)    limits.get(key)         bursts.take(key) /*bool*/
guard limits.incr(req.remoteAddr) <= 1000 else { return 429 }

notify all blacklist.add(ip)      // fan-out to all shards (eventual)
notify(key) counters.incr(key)    // to owner shard by key hash
// strong consistency: declare state with consistent: true (+ // rut:allow(consistent))
// cross-node: backend: .redis("redis:6379")
```

## Routing

```swift
route {
    // 1) middleware bindings first: @func[(args)] pattern   (* = all)
    @requestId *
    @waf *
    @auth(role: "user") api.example.com
    @if(env("ENABLE_CORS") == "true")     // compile-time conditional binding
    @cors *

    // 2) entries: method path => expr   |   method path { stmts }
    get /health => 200
    get /users/:id(i64) => forward(userService)   // :name(i32|i64|uuid) typed capture
    get /files/*rest => read(root: "/var/www")    // *rest = catch-all, last segment
    get|post /form { ... }                        // method union

    api.example.com {                             // host group (nesting ok)
        /v1 {                                     // path prefix group
            get /users/:id => forward(usersV1)
        }
    }

    _ => 404                                      // catch-all (any method/path)
}
```

Precedence: literal segment > `:param` > `*rest`; exact host > wildcard > `_`.
Indistinguishable routes are a compile error. Middleware direction is inferred
from signature: has `Response` param → post (forces buffered), else pre.

## I/O

```swift
// Proxy — the ONLY three forms
return forward(users)                          // zero-copy, terminal
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

## Cache state (per-key counters/timestamps — DESIGN.md §3.3.6)

```swift
let buckets = Cache<IP, i64>(capacity: 100000)   // top-level; per-shard lossy slots

route GET "/api" {
    let prev = buckets.get(req.remoteAddr).or(0) // i64? — a MISS IS NORMAL
    buckets.set(req.remoteAddr, prev + 1)        // bare set: ONLY before guards/waits
    if prev + 1 > 100 { return 429 } else { return 200 }
}
```

- `get -> i64?`: nil means never-seen OR evicted — the two are indistinguishable
  by design; `.or(default)` / `guard let` are the only ways to consume it.
- Entries may be evicted by colliding writes at any occupancy: never store
  anything whose absence gives a wrong answer. Capacity = slot count (rounded
  up to a power of two); provision ~2× your expected key count.
- State writes run at handler entry, so a bare `set` after a guard/wait is a
  compile error. Per-shard state: effective limits ≈ limit × shard count.

## Built-ins (call them, never reimplement)

```
string:  s.len s.isEmpty s.hasPrefix/hasSuffix/contains s.upper()/lower()/trim()
         s.trimPrefix/trimSuffix/replace/split/slice s.matches(re"") s.match(re"")
hash:    md5 sha1 sha256 sha384 sha512 fnv32 fnv64 | hmacSha256/384/512
jwt:     jwtDecode(tok, secret:|publicKey:) jwtEncode(claims, ..., alg: .HS256)
crypto:  aesGcmEncrypt/Decrypt randomBytes(n) uuid()
encode:  base64 base64url hex urlEncode urlDecode htmlDecode unicodeNormalize
time:    now() time(s) — Time/Duration arithmetic: now() - t > 1h
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
listen :80                         // ⏳ (no top-level listen yet)
let users = upstream { "10.0.0.1:8080" }
let limits = Counter<IP>(capacity: 100000, window: 1m)

func rateLimit(_ req: Request, max: i32) {
    guard limits.incr(req.remoteAddr) <= max else { respond 429 }
}

route {
    @rateLimit(max: 1000) *
    get /health => 200
    get /users/:id(i64) => forward(users)
    post /users {
        guard let user = req.body(User) else { return 400 }
        return forward(users)
    }
    _ => 404
}

struct User {
    id: str
    role: str
}
```
