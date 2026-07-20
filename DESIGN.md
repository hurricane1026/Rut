# Rutlang: Design Document

> A strongly-typed DSL and high-performance L7 ingress runtime. API gateway, WAF, reverse proxy, mesh sidecar, CDN edge — one language, multiple compilation targets.

## Status and Scope

This document currently serves three roles at once:

- **Normative language/runtime spec** — the intended Rutlang contract
- **Implementation design** — how the compiler, JIT, runtime, and reload path should work
- **Roadmap** — features that are planned but not fully implemented yet

That mix is useful for design exploration, but it is easy to misread aspirational
features as already-shipping behavior. Unless a section explicitly says otherwise,
read the language and runtime chapters below as the **target contract**, not a
statement that the current repository already implements every feature.

### Reading Guide

- **Normative / contract-heavy sections**: language syntax, type system, route semantics, state semantics, compile-time checks
- **Implementation design sections**: runtime architecture, memory layout, I/O backend design, hot reload internals
- **Roadmap-heavy sections**: advanced TLS phases, sidecar integration, some cross-node/distributed features, observability expansion

When the implementation and the design diverge, the repository source of truth is:

1. tests covering current behavior
2. runtime / compiler code paths that are actually reachable
3. this document's intended target behavior

### Implementation Status Matrix

This is intentionally coarse-grained. It exists to separate "designed" from
"implemented enough to rely on today".

| Area | Status | Notes |
|------|--------|-------|
| Runtime event loop, sharding, socket handling | **Implemented** | Core epoll/io_uring runtime exists in-tree |
| HTTP parsing and proxying runtime | **Implemented** | Production-oriented runtime paths and tests exist |
| RIR data model + builder + printer | **Implemented** | RIR is real and exercised by tests |
| LLVM ORC JIT integration | **Implemented** | Userspace handler JIT engine and codegen paths exist |
| `firewall {}` → eBPF / XDP compilation target | **Designed** | Packet-level kernel path is a first-class compilation target in this design |
| Offline manifest → RIR → JIT simulate flow | **Implemented** | Current compile-like path is intentionally narrow |
| Full Rutlang lexer / parser / type checker | **Partial / in progress** | Token surface is declared, but the front-end is not yet complete |
| Route conflict analysis and full diagnostics | **Designed** | Mentioned throughout this doc, not fully enforced end-to-end today |
| Full surface language in examples below | **Designed** | Many examples are target syntax, not necessarily accepted by current code |
| Cross-shard language primitives (`notify`, `consistent`) | **Designed** | Runtime direction is defined here; treat semantics as target contract |
| External state backends (`backend: .redis`) | **Designed** | Not a current repository guarantee |
| Zero-downtime hot reload of full `.rut` programs | **Partially designed / partial runtime pieces** | Runtime has design direction; full language-level flow is not complete yet |

### Document Restructure Plan

Longer term, this document should be split into:

- `LANG_SPEC.md` — grammar, typing, routing, state semantics, diagnostics
- `RUNTIME.md` — shard model, I/O backends, memory, reload, networking internals
- `ROADMAP.md` — future phases, optional features, deployment/sidecar expansion

This file currently remains the umbrella design doc until that split happens.

## 1. Project Overview

### 1.1 Goals

- Replace nginx configuration files and OpenResty Lua with a single strongly-typed language
- Catch most errors at compile time (type errors, route conflicts, invalid values)
- Keep the language low-ambiguity: the same gateway problem should usually have
  one obvious solution, and at most one or two accepted idioms
- Make programs mechanically inspectable: control flow, IO waits, routing, and
  failure behavior should be reducible to a small state machine
- Make correctness testable by replay and simulation: captured traffic should
  exercise the same route semantics as production execution
- Be safe for LLM-assisted generation: prefer constrained constructs,
  deterministic diagnostics, and verifier-friendly semantics over expressive
  freedom that creates plausible but wrong code
- High performance: C100K+ capable, minimal latency overhead
- Hot reload without downtime
- Minimal dependencies, maximal control

### 1.2 Non-Goals

- General-purpose programming language
- L4 load balancer (this is L7 HTTP only)
- DPDK / kernel bypass networking (not worth the trade-off in cloud environments)
- Compatibility with nginx configuration format
- Multiple equivalent language surfaces for the same operation
- Accepting ambiguous code and relying on style guides, runtime behavior, or LLM
  prompts to resolve intent
- Requiring external general-purpose formal tools to validate normal user code

---

## 2. Architecture Overview

```
                          ┌─────────────────────────────┐
    .rut source ───▶   │  Compiler (embedded in proc) │
                          │  parse → type check → IR     │
                          └───────┬───────────┬─────────┘
                                  │           │
                                  │           └──────────────▶ eBPF bytecode
                                  │                            (`firewall {}` → XDP / kernel hook)
                                  ▼
                         ┌──────────────────────┐
                         │  JIT (LLVM ORC JIT)   │
                         └──────────┬───────────┘
                                    │ native function pointers
                                    ▼
  ┌────────────────────────────────────────────────────────┐
  │                    Rutlang Runtime                    │
  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
  │  │  Shard 0  │ │  Shard 1  │ │  Shard 2  │ │  Shard N  │  │
  │  │ io_uring  │ │ io_uring  │ │ io_uring  │ │ io_uring  │  │
  │  │ Router    │ │ Router    │ │ Router    │ │ Router    │  │
  │  │ Handlers  │ │ Handlers  │ │ Handlers  │ │ Handlers  │  │
  │  │ ConnPool  │ │ ConnPool  │ │ ConnPool  │ │ ConnPool  │  │
  │  │ Memory    │ │ Memory    │ │ Memory    │ │ Memory    │  │
  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
  │              share-nothing, per-core                    │
  └────────────────────────────────────────────────────────┘
```

### 2.1 Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Runtime | Custom C++ (not Seastar) | Seastar too complex for this use case; only ~30% of Seastar code is relevant; custom runtime is ~5000 lines fully controlled |
| Networking | io_uring (preferred) + epoll (fallback) | io_uring is optimal for Linux 6.0+; epoll fallback for older kernels (3.9+); both use kernel TCP stack |
| Thread model | per-core shard, share-nothing | Proven by Seastar/Envoy/nginx; eliminates locks and race conditions |
| Userspace codegen | LLVM ORC JIT | Same C++ toolchain, zero FFI overhead, lazy compilation support for L7 handlers |
| Packet-path codegen | eBPF / XDP | Compile `firewall {}` blocks to kernel-level packet filters for earliest-drop semantics |
| HTTP parser | Custom (~500 lines) | llhttp is callback-based (bad fit), picohttpparser lacks strict mode; custom parser integrates directly with our Slice buffer + Arena, supports SIMD, full control over strictness (anti-smuggling) |
| C++ stdlib | `-nostdlib++`, musl libc only | Full memory control, faster compilation |
| Compiler flags | `-fno-exceptions -fno-rtti` | No overhead from unused C++ features |

---

## 3. The Rutlang Language

This chapter defines the **intended Rutlang surface language and semantics**.
Some subsections describe features that are only partially implemented or not yet
wired through the current front-end. When in doubt, treat examples here as the
target language contract and verify current support against the implementation
status matrix above.

### 3.1 Design Principles

- **Low ambiguity first**: every feature should have a narrow role, predictable
  grammar, and a small number of accepted idioms. If two constructs solve the
  same common problem equally well, one should usually be removed or made
  clearly secondary.
- **LLM-safe by construction**: Rut should reduce the blast radius of generated
  code by constraining the language, making invalid intent easy to diagnose, and
  avoiding clever surface forms that look plausible but mean different things.
- **Swift-inspired syntax where it reduces ambiguity**: guard statements, named
  parameters, and string interpolation are useful when their semantics remain
  mechanically simple. Symbol-heavy convenience forms stay non-core until they
  prove clearer than named forms.
- **HTTP concepts are native objects**: methods, status codes, headers, URLs, CIDR, media types are first-class language constructs, not strings
- **All functions inline at compile time**: no runtime function calls, each route compiles to a single flat state machine
- **Async suspension is explicit**: no async/await/future/promise, but every
  operation that can suspend a handler must be visible as `wait`, `forward`, or
  another explicit async boundary. The compiler lowers these points into state
  machines; ordinary helper functions should not hide new yield points.
- **Strong typing with domain types**: Duration, ByteSize, StatusCode, IP, CIDR, MediaType with compile-time validation
- **Middleware = ordinary functions**: `respond <status>` short-circuits the request; falling through (or plain `return`) passes through. `return` keeps a single meaning everywhere — produce the function's value
- **Bounded execution**: no `while`, no recursion, `for` only iterates finite collections — every handler has a compile-time execution bound, cannot stall a shard
- **Replay and simulation are first-class**: route semantics should be
  deterministic enough that captured traffic can be replayed through the same
  decision logic used in production, with differences treated as bugs or
  explicitly modeled environment effects.
- **Verifier-friendly semantics**: user code should lower to a compact control
  graph with explicit terminal responses, waits, forwards, and failure paths.
  Features that cannot be represented in that graph should be rejected, bounded,
  or isolated behind explicit escape hatches.
- **Three-layer model**: `listen` (downstream/client) → .rut file (gateway logic) → `upstream` (backend). No `gateway` or `downstream` keyword — the .rut file IS the gateway, `listen` IS the downstream config
- **Minimal keyword set**: `func`, `let`, `var`, `const`, `guard`, `struct`, `variant`, `protocol`, `impl`, `type`, `route`, `match`, `if`, `else`, `for`, `in`, `break`, `continue`, `return`, `respond`, `defer`, `upstream`, `listen`, `tls`, `defaults`, `forward`, `websocket`, `fire`, `submit`, `wait`, `timer`, `init`, `shutdown`, `firewall`, `throttle`, `per`, `notify`, `import`, `using`, `as`, `package`, `nil`, `true`, `false`
- **Swift-exact or absent**: any surface form that looks like Swift must behave
  exactly like Swift. Near-miss variants (Swift-looking syntax with different
  semantics) are removed rather than documented, because they are the primary
  source of LLM-generated errors.

### 3.2 File Extension

`.rut`

### 3.2.1 Lexical Conventions

```swift
// Comments — line comments only, no block comments
// This is a comment

// Strings — double-quoted, with escape sequences
"hello world"
"line one\nline two"           // \n \t \r \\ \" supported
"\(req.path)/\(req.method)"    // string interpolation with \()

// Regex literals — re prefix
re"^/api/v\d+/"

// Anonymous object literal — ONLY as a call argument (typically json()).
// Never a statement, never a response/header map, never a bare expression.
json({ users: [], total: 0 })

// Number literals
42                              // i32
3.14                            // f64
0xFF                            // hex integer
1_000_000                       // underscores for readability

// Duration / ByteSize literals (domain types)
500ms    1s    5m    1h    1d   // Duration
64b    1kb    16kb    1mb    1gb // ByteSize

// Statements separated by newlines — no semicolons
let x = 42
let y = "hello"

// Long expressions: wrap in parentheses for continuation
let result = (
    someVeryLongFunction(req, arg1: value1, arg2: value2)
)

// Boolean
true   false   nil

// Operators
&&   ||   !                     // boolean (identical to Swift)
|                               // pipeline (shell intuition) — RHS must be a
                                // call with a _ placeholder
+   -   *   /   %              // arithmetic
==  !=  <  >  <=  >=           // comparison
=                               // assignment
@                               // decorator prefix
=>                              // single-expression body / branch result
->                              // function return type

// Bitwise — the built-in `bitwise` namespace, not symbols (same style as
// log.info / trace.span). Bit twiddling is rare in gateway code; naming it
// frees | to mean pipeline only and removes an entire class of operator
// ambiguity.
bitwise.and(a, b)    bitwise.or(a, b)    bitwise.xor(a, b)    bitwise.flip(a)
bitwise.shiftLeft(a, n)    bitwise.shiftRight(a, n)
```

Arithmetic is total over `i32` and `i64`: overflow wraps two's-complement, and
`x / 0` / `x % 0` evaluate to `0` — no traps, no undefined behavior (a SIGFPE
would take down the whole shard; totality is the eBPF-style boundary the
runtime needs). `INT_MIN / -1` wraps to `INT_MIN`; `INT_MIN % -1` is `0` (same
at 64 bits). A literal zero divisor is a compile-time error. Unary minus is
ordinary negation (`-x` is `0 - x`); `-2147483648` is a valid literal.

The two integer widths never mix implicitly:

- An int literal types as `i32` when it fits, else `i64` (`60000000000` just
  works); beyond the i64 range it is a compile error.
- `i64(x)` is the conversion (Swift-initializer style): it widens an i32
  value, folds on literals, and is identity on i64. A user function named
  `i64` shadows the builtin. There is no narrowing conversion yet.
- Arithmetic and comparisons require same-width operands; mixing a non-literal
  i32 with an i64 is a compile error with an `i64(x)` fix-it. A bare int
  literal adopts the i64 side (`i64(x) + 1` works).
- `i64` is deliberately unavailable in user-declared type positions (like
  ByteSize): no annotations, struct fields, or function parameters. Built-in
  grammar may still require it as a fixed marker (`Cache<K, i64>`). Planned
  typed route captures (`:id(i64)`) are ⏳ and likewise will not make arbitrary
  i64 annotations legal. `match` on an i64 subject is rejected for now.
  `bitwise.*` follows the same same-width rule as arithmetic (shift amounts
  share the operand width and saturate out of range) — the substrate for
  packing multi-field algorithm state into one i64 slot (§3.3.6).

`time.nowMicros()` returns monotonic microseconds as i64, latched per
handler invocation (all uses within one request observe the same value —
required for correctness of rate-limit algorithms, and a consequence of
the compiler re-materializing local initializers at use sites).
`max(a, b)` / `min(a, b)` are same-width integer builtins with single
evaluation. Duration/ByteSize arithmetic (§3.3) is a separate, later
surface.

Rut Core intentionally avoids symbolic optional chaining, null-coalescing, and
force-unwrap. Use named fallback and explicit binding instead:

- `value.or(default)` for "usable value or fallback"
- `if let x = expr { ... }` to branch on and bind a usable value
- `guard let x = expr else { ... }` when absence/failure must stop the route
- `x == nil` / `x != nil` for a bare presence test
- `match` when the reason for absence/failure matters

The symbolic forms `?.`, `??`, and postfix `!` remain reserved — rejected with a
fix-it pointing at the named forms above. There is deliberately no other postfix
`?` operator: a construct that looks like Swift must either behave exactly like
Swift or not exist.

### 3.2.2 Core Control-Flow Surface

Rut keeps a small set of branching constructs with clear roles:

- `if` — the lightweight boolean branch
- `if let` — branch on "a usable value exists", binding it (Swift-identical)
- `guard` / `guard let` — fail-fast branch: the condition must be a bool, or
  `guard let` binds a usable value; `else` must terminate (Swift-identical)
- `match` — the general multi-branch construct
- `for` — bounded iteration over finite collections; `break` / `continue` are
  allowed (Swift-identical — they only shorten iteration, so the compile-time
  execution bound is preserved)

`switch` is not a language keyword. Where a traditional switch would normally be
used, Rut uses `match`.

`=>` has one uniform meaning across the language: it introduces a single-expression
body or branch result. It is not function-specific syntax.

Examples:

- `func id(x: i32) -> i32 => x`
- `get /health => 200`
- `.ok(v) => v` (match arm — Rut has no `case` keyword)

Where a construct uses `=>`, the right-hand side is interpreted as a single
expression body with implicit result/return semantics appropriate to that
construct.

`match` is the general form:

- `if` is the boolean special case users will usually prefer for simple two-way conditions
- `match` handles general value dispatch, structured variants, and richer multi-way branching
- `match const` is the compile-time form for branching on compile-time-known values

Likewise, `if const` is the lightweight compile-time boolean branch.

The current implementation covers the route-local static array subset and lowers
supported shapes by compile-time unrolling. For that implemented subset, see
[docs/for-loops.md](docs/for-loops.md).

### 3.3 Type System

#### 3.3.1 Built-in Domain Types

HTTP concepts are native types with member functions. All implemented as runtime
C++ builtin structs — compile-time validated literals, zero-overhead access.

**IP** — IPv4/IPv6 address

```swift
let ip = req.remoteAddr              // IP
ip.isV4                              // bool — is IPv4
ip.isV6                              // bool — is IPv6
ip.isPrivate                         // bool — RFC1918 (10.x, 172.16.x, 192.168.x)
ip.isLoopback                        // bool — 127.0.0.0/8 or ::1
ip.in(10.0.0.0/8)                    // bool — CIDR containment
ip.octets                            // [u8] — 4 or 16 bytes
ip as string                         // "10.0.0.1"
IP.parse("10.0.0.1")                // IP? / error-capable parse, depending on context
```

**CIDR** — network range

```swift
let cidr = 10.0.0.0/8               // CIDR literal
cidr.network                         // IP — network address
cidr.prefix                          // i32 — prefix length (8)
cidr.contains(req.remoteAddr)        // bool
cidr as string                       // "10.0.0.0/8"
```

**Duration** — time interval

```swift
let d = 30s                          // Duration literal (also: ms, m, h, d)
d.ms                                 // i64 — 30000
d.seconds                           // i64 — 30
d.minutes                            // f64 — 0.5
// Arithmetic: d + 1s, d - 500ms, d * 2, d > 1m, d == 30s
```

**ByteSize** — data size

```swift
let b = 16kb                         // ByteSize literal (also: b, mb, gb)
b.bytes                              // i64 — 16384
b.kb                                 // f64 — 16.0
b.mb                                 // f64 — 0.015625
// Arithmetic: b + 1kb, b > 1mb, b == 16kb
```

**StatusCode** — HTTP status

```swift
let s = resp.status                  // StatusCode
s.code                               // i32 — 200
s.isSuccess                          // bool — 2xx
s.isRedirect                         // bool — 3xx
s.isClientError                      // bool — 4xx
s.isServerError                      // bool — 5xx
```

**Method** — HTTP method

```swift
req.method                           // Method
req.method == .GET                   // bool
req.method as string                 // "GET"
```

**MediaType** — content type

```swift
let mt = req.contentType             // MediaType
mt.type                              // string — "application"
mt.subtype                           // string — "json"
mt as string                         // "application/json"
```

**Time** — timestamp

```swift
let t = now()                        // Time
t.unix                               // i64 — epoch seconds
t.unixMs                             // i64 — epoch milliseconds
t as string                          // ISO 8601
now() - t                            // Duration — time difference
t + 1h                               // Time — add duration
```

**Regex** — compiled pattern

```swift
let r = re"^/api/v\d+"              // Regex literal, compile-time validated
```

**Port** — 1..65535

```swift
let p = :8080                        // Port literal
p.number                             // i32 — 8080
```

#### 3.3.2 User-Defined Types

```swift
struct User {
    id: string
    role: string
    name: string
}

struct Order {
    items: [OrderItem]
    total: f64
}

struct OrderItem {
    sku: string
    qty: i32
    price: f64
}
```

**variant** — closed sum type; `match` dispatches on cases and must be
exhaustive (all cases or a `_ =>` fallback):

```swift
variant NetError {
    timeout
    refused
    dns(string)          // case with payload
}

let e = NetError.dns("no such host")
match e {
    .timeout   => log.warn("timeout")
    .dns(host) => log.warn("dns failure", host: host)
    _          => log.warn("net error")
}
```

Case references are `.case` (short form) or `Type.case` (qualified); bare case
names are not accepted. Payload binding is single-layer.

**protocol / impl** — explicit interface conformance:

```swift
protocol Hashable {
    func hash() -> u64
}

impl User: Hashable {
    func hash() -> u64 => fnv64(self.id)
}
```

Conformance is always explicit via `impl Type: Protocol` — never structural or
inferred. Duplicate `impl` for the same Type + Protocol pair is a compile
error. Generics, associated types, and the type-level `match` alias facility
are specified compiler-side in §11.1.4–§11.1.9; this section is only the
surface summary.

#### 3.3.3 Tuple

Ordered, fixed-size, heterogeneous collection. Compile-time known layout.

```swift
let pair = (200, "ok")                       // (i32, string)
let triple = (user, orders, stock)           // (User, [Order], Stock)

// Destructuring
let (status, msg) = pair

// Index access
let first = pair.0                           // i32
let second = pair.1                          // string
```

Used as return type for `wait()` with multiple handles. Arena-allocated,
zero heap overhead.

#### 3.3.4 Request Object

Request is a built-in type. Standard HTTP headers are native properties with correct types:

```swift
// Standard headers — accessed as properties, typed correctly
req.method              // Method
req.path                // string
req.remoteAddr          // IP
req.contentLength       // ByteSize (not string)
req.contentType         // MediaType (not string)
req.authorization       // string? (optional — header may not exist)
req.host                // string
req.userAgent           // string
req.origin              // string?
req.ifModifiedSince     // Time?
req.accept              // MediaType?

// Custom headers — explicit function access. (A hyphen inside a property
// name would parse as subtraction in a Swift-shaped grammar, so raw header
// names never appear as identifiers.)
req.header("X-Request-ID")   // string?
req.header("X-User-ID")      // string?
req.header("X-Timestamp")    // string?

// Setting headers
req.set("X-User-ID", "123")
req.set("X-Request-ID", uuid())

// Route parameters — path captures live in the req.params namespace,
// so a capture can never shadow a built-in property (req.path, req.host, ...)
// Route: get /users/:id/posts/:postId
req.params.id           // string (from :id)
req.params.postId       // string (from :postId)

// Query string
req.queryString         // string? — raw query string: "page=1&limit=20"
req.query("page")       // string? — first value of the parameter
req.queryAll("tags")    // [string] — all values (?tags=a&tags=b), like getAll for headers

// Body
req.body(User)          // parse body as User struct, error-capable
req.bodyRaw             // raw body as string, error-capable
req.bodyRaw = newBody   // replace body before forward (recomputes Content-Length)

// Cookies
req.cookie("session_id") // string?

// Multi-value headers
req.getAll("Accept")    // [string] — all values for a header
req.add("X-Tag", "a")   // append (doesn't replace existing)

// Request-level context — typed struct, shared across middleware and handler
req.ctx.userId          // fields from user-declared Ctx struct
req.ctx.startTime       // set by decorators, read by handler
```

The request context `req.ctx` requires a user-declared `Ctx` struct:

```swift
struct Ctx {
    userId: string
    userRole: string
    startTime: Time
}
```

The compiler verifies that fields read in a handler were set by a decorator in
the chain. Accessing an unset field is a compile error.

#### 3.3.5 Response Object

```swift
// Simple responses
return 200                           // empty body
return 401, "custom message"         // with body string
return 200, json(data)               // with JSON body

// With headers — build response object, no { } ambiguity
let resp = response(429)
resp.set("Retry-After", "60")
return resp

let resp = response(200)
resp.set("Content-Type", "application/json")
resp.body = json(stats())
return resp

// Redirect
let resp = response(301)
resp.set("Location", "https://example.com\(req.path)")
return resp

// Multi-value headers on response
resp.add("Set-Cookie", "a=1; Path=/")
resp.add("Set-Cookie", "b=2; Path=/")

// Delete header
resp.remove("Server")
```

`response(status)` is a built-in function that creates a Response object.
A `{ }` after a status is never a header map — braces in statement position are
always code blocks. Anonymous object literals `{ key: value }` exist only as
call arguments (see §3.2.1), not as response construction.

#### 3.3.6 State Types

> **Revised 2026-07 (decisions in docs/state-types.md):** the taxonomy is
> restructured around "algorithms in Rut, primitives in the runtime".
> `Counter<K>` is deleted — token bucket / fixed window are `.rut`
> library code over `Cache` (see `examples/ratelimit.rut`). Gauge-style
> in-flight counting will get an exact Array-style table, not lossy slots.

All persistent state is declared as top-level typed containers with compile-time
capacity bounds. Inspired by eBPF maps: typed, bounded, per-shard by default.

**Cache\<K, i64>** — lossy per-key state slots (implemented; the substrate for
rate-limit algorithms written in Rut, see `examples/ratelimit.rut`).

```swift
let buckets = Cache<IP, i64>(capacity: 100000)

buckets.get(key)      // i64? — nil means "never seen OR evicted"; the two
                      // are indistinguishable by design — always handle it
                      // (blessed idiom: .or(0))
buckets.set(key, v)   // bare statement, before any guard/for; a colliding set
                      // may evict a neighbor; wait routes reject all cache ops
```

Under fixed capacity there is no third option: when capacity or a collision
budget is exceeded, either the write fails visibly or old data dies (eBPF's
`HASH` vs `LRU_HASH` split). `Cache` evicts — so **never store anything in
a `Cache` whose absence yields a wrong answer** (sessions, in-flight
counts). Multi-field algorithm state can pack into the single i64 using
`bitwise.*`. Expiry is lazy (window index in the value), there is no `ttl:`.
The name `Hash` is **reserved** for a future strict, visible-failure table:
"hash map" carries a lossless prior this structure does not honor. (The
former `Hash<string, Session>` example is retired for a second reason:
per-shard KV gives wrong answers for cross-connection sessions; that use
case needs `consistent:`/`backend:` machinery.)

**LRU<K, V>** — key-value with LRU eviction when full.

```swift
let responseCache = LRU<string, CachedResponse>(capacity: 10000, ttl: 5m)

responseCache.set(key, resp)
let cached = responseCache.get(key)   // V? — hit refreshes access time
```

Optional `coalesce: true` — request coalescing (singleflight). Prevents thundering
herd on cache miss: only one request fetches from upstream, others wait for the result.
Same pattern as nginx `proxy_cache_lock`.

```swift
let cache = LRU<string, string>(capacity: 10000, ttl: 5m, coalesce: true)

get /users/:id {
    let key = "/users/\(req.params.id)"
    // miss + in-flight → auto wait for first request
    if let cached = cache.get(key) { return 200, cached }
    let resp = forward(userService, buffered: true)
    cache.set(key, resp.body)        // stores result + wakes all waiting connections
    return resp
}
```

Implementation: per-shard, single-threaded. On `cache.get()` miss with pending
in-flight request for same key, the runtime suspends the connection (adds to
intrusive linked list). On `cache.set()`, resumes all waiters with the value.
No mutex needed — single thread per shard.

**Set\<T>** — membership testing.

```swift
let blacklist = Set<IP>(capacity: 100000)
let trustedNets = Set<CIDR>(capacity: 1000)

blacklist.contains(req.remoteAddr)     // bool
trustedNets.contains(req.remoteAddr)   // bool — CIDR set does longest prefix match on IP
blacklist.add(ip)
blacklist.remove(ip)
```

Compiler picks implementation by element type: `Set<IP>` / `Set<string>` → hash set,
`Set<CIDR>` → LPM trie (longest prefix match tree).

**Rate limiting** is not a state type: GCRA token buckets and packed
fixed windows are ordinary `.rut` code over `Cache<K, i64>`. Working
examples and their real-socket parity test live in `examples/ratelimit.rut`;
`@rateLimit` remains the concise built-in form.

**Bloom\<T>** — probabilistic set, memory-efficient for large cardinalities.
No false negatives; possible false positives.

```swift
let seenRequests = Bloom<string>(capacity: 1000000, errorRate: 0.01)

seenRequests.add(key)
seenRequests.mayContain(key)           // bool — "not in" is certain, "in" may be false positive
```

Use cases: request deduplication, cache penetration defense, large-scale blacklists.

**Bitmap** — fixed-size bit array.

```swift
let features = Bitmap(size: 256)

features.set(12)                       // set bit
features.clear(12)                     // clear bit
features.test(12)                      // bool
features.count()                       // popcount — number of set bits
```

Use cases: feature flags, upstream health status, compact boolean arrays.

**Common parameters:**

| Parameter | Applies to | Description |
|-----------|-----------|-------------|
| `capacity:` | all (required) | Max entries, compile-time bound |
| `ttl:` | LRU | Entry expiry time (Cache has no ttl — expiry is lazy, packed into the value) |
| `errorRate:` | Bloom (required) | False positive rate, determines memory usage |
| `size:` | Bitmap (required) | Number of bits |
| `persist: true` | all | Preserve data across hot reload; compile error if struct layout changed |
| `consistent: true` | Cache, Set | Single-owner routing by key hash (removes shard divergence; lossy containers stay approximate); SPSC round-trip cost; compiler warning, suppress with `// rut:allow(consistent)` |
| `coalesce: true` | LRU | Request coalescing — on cache miss with in-flight request for same key, suspend and wait instead of sending duplicate upstream request |
| `backend: .redis(addr)` | — (reserved) | ⏳ Future cross-node storage; no Cache form is specified until reads have an explicit freshness/refresh contract |

**All state is per-shard by default.** Each shard owns an independent copy, single-threaded access,
zero locking. Per-shard counters are approximate (effective limit ≈ `limit × shard_count`).

**Cross-shard communication: `notify`**

`notify` is Rutlang's only cross-shard primitive. Two forms:

```swift
notify all expr                    // all shards — eventual consistency
notify(key) expr                   // hash(key) → owner shard — targeted

let blacklist = Set<IP>(capacity: 100000)

post /admin/ban {
    guard let ip = req.body(IP) else { return 400 }
    blacklist.add(ip)              // local shard — immediate
    notify all blacklist.add(ip)   // all other shards — next event loop tick
    return 200
}
```

- `notify all` — fan-out to N-1 shards, eventual consistency
- `notify(key)` — hash(key) to determine owner shard, send to that shard only

Implementation: each shard pair has a wait-free SPSC (single-producer single-consumer)
ring buffer. `notify` enqueues the operation using `relaxed` stores with `release`
on the tail pointer. Receiving shards drain their queues on each event loop tick
with `acquire` on the tail read. No `seq_cst`, no full barrier, no cache line
contention (head and tail on separate cache lines).

Cost: `notify all` = N-1 relaxed writes. `notify(key)` = 1 relaxed write.
Propagation latency is one event loop tick (~microseconds).

**Single-owner state: `consistent: true`**

To remove per-shard divergence (all shards see one copy of the state),
declare with `consistent: true`. Operations route to the owner shard
(determined by key hash), processed sequentially — no locks, just SPSC
message round-trip. On a `Cache` this is single-owner but still
approximate (see below); exact global limiting is future work.

```swift
// rut:allow(consistent)
let ownerBuckets = Cache<IP, i64>(capacity: 100000, consistent: true)

get /api/*path {
    // Compiler generates: hash(remoteAddr) → owner shard → SPSC send → yield → receive
    let tat = ownerBuckets.get(req.remoteAddr).or(0)
    // ... GCRA over tat (see examples/ratelimit.rut)
    return forward(userService)
}
```

`consistent: true` on a `Cache` removes per-shard divergence (one owner
shard holds the state) — it does NOT make the state exact: the slot table
stays lossy (a colliding `set` can still evict a bucket, and `.or(0)`
restarts it), and a read-modify-write built from separate `get`/`set`
round-trips can interleave between shards, losing updates. Exact global
limiting needs a strict (visible-failure) table plus an owner-shard atomic
update primitive — both future work; until then `consistent:` Cache is
"single-owner, still lossy".

Cost: 1 SPSC round-trip when current shard != owner shard (local ops are free).
Compiler emits a warning — user must acknowledge with `// rut:allow(consistent)`.

**Three-tier cost model:**

| Mode | Declaration | Cost | Consistency |
|------|-------------|------|-------------|
| per-shard | default | zero | approximate |
| notify all | `notify all expr` | N-1 SPSC writes | eventual |
| notify(key) | `notify(key) expr` | 1 SPSC write | eventual, targeted |
| consistent | `consistent: true` | 1 SPSC round-trip | single-owner (lossy containers stay approximate) |

All three use SPSC message passing with minimal atomics (relaxed stores +
release/acquire on queue tail pointer). No mutexes, no STM, no contended locks.

**Cross-node state: `backend:` parameter (⏳ future)**

Per-shard and cross-shard state only works within a single Rut process.
`backend:` is reserved for a future external-storage design; it is not a
blessed Cache declaration today. In particular, a local-first Redis cache
without a TTL, invalidation, or refresh bound could serve stale limiter state
indefinitely. The syntax and cost model stay unspecified until that freshness
contract and the required atomic read-modify-write behavior are defined.

##### 3.3.6.1 State Failure and Ordering Semantics

The state APIs above need explicit failure behavior. Without this, the syntax is
clear but the contract is underspecified.

**Ordering**

- Operations issued by one shard to one destination shard are processed in send order
- `notify(key)` preserves per-key send order only insofar as all operations for that key hash to the same owner shard
- `notify all` does **not** provide a single global total order across all shards

**Queue pressure**

- `notify` is best-effort only if the program opts into lossy behavior explicitly
- Default language contract: if the cross-shard queue is full, the operation is a runtime failure for that request path, not silent drop
- Future syntax may allow `notify all?, lossy: true` or equivalent, but silent loss should not be the default

**`consistent: true`**

- A consistent operation either completes on the owner shard and returns its result, or fails the request-visible operation
- Timeouts on cross-shard round trips must surface as runtime failures, not stale success
- Reads and writes routed through the owner shard observe owner-shard program order

**External backends**

- `backend:` changes the consistency model from purely in-process semantics to backend-mediated semantics
- Any future `backend: .redis(...)` contract must surface write-through failure to the request unless it explicitly documents degraded-local mode
- Reads may be satisfied from local cache only while an explicit TTL, invalidation, or refresh rule proves the entry fresh; because Cache has no such rule today, no backend Cache form is currently valid

**Reload / shutdown**

- Hot reload must not silently discard acknowledged consistent operations
- In-flight best-effort `notify` operations may be dropped during shutdown unless the API used is documented as durable
- Persistent state schema incompatibility remains a compile-time reload rejection, not a best-effort migration

These rules are deliberately conservative. They keep the language contract tighter
than the current implementation so runtime shortcuts do not accidentally become
part of the public semantics.

#### 3.3.7 Error Handling: values, nil, error, and guard

No exceptions. No try/catch. Rut is primarily a value-flow language: most ergonomic
syntax works in terms of values and `nil`, not explicit `Result<T, E>` plumbing in
ordinary user code.

The language still has a standard built-in `Error` type. A function that can produce
an `error(...)` value is error-capable, and the compiler may normalize such code in
HIR to `Result<V, Error>` internally. That normalized form is mainly for compiler
semantics, analysis, and lowering, not the default surface syntax that ordinary
users are expected to write every day.

**Nil vs Error**

- `nil` means "there is no usable value here"
- `error(...)` carries failure information

In surface value-flow syntax, errors are treated as producing no usable value. The
short forms therefore work on the value channel and naturally see failure as `nil`.
Users who care about the precise error reason enter an explicit error-handling path
with `guard` (and later possibly `match`).

**Value-flow surface**

| Syntax | Meaning |
|--------|---------|
| `x.or(default)` | provide a fallback when no usable value exists |
| `if let x = expr { ... }` | branch on and bind a usable value |
| `guard let x = expr else { ... }` | bind usable value or terminate |
| `x == nil` / `x != nil` | bare presence test |
| `a \| f(_, ...)` | pipeline over the usable value channel |

These operators intentionally optimize for the common case: keep the normal logic
flowing without forcing local `if/else`, `match`, or `guard` at every step.

That means a pipeline or optional-style expression may ignore detailed error causes
and simply continue in terms of "value present" vs "value absent":

```swift
let name = req.query("name").or("anonymous")
let parts = req.path | trimPrefix("/api", _) | split(_, "/")
let user = findUser(id).or(GuestUser)
let userName = user.profileName.or("guest")
```

Pipeline and UFCS have distinct blessed roles — they are not two spellings of
the same thing:

- **UFCS chaining** (`a.f().g()`) when the value flows into the **first**
  parameter of each step
- **`|` pipeline** when the value lands in a **non-first** position (explicit
  `_` placeholder makes the position visible) or when value-channel
  short-circuiting across stages matters

`|` follows the shell-pipe intuition, and in expression position it means
**pipeline only** — bitwise operations live in the built-in `bitwise` namespace
(`bitwise.or(a, b)` etc., §3.2.1), so there is no second reading to confuse it
with. (`get|post` in route
position is a method union — a different syntactic context that never overlaps
with expressions.) The right-hand side must be a call containing a `_` / `_N`
placeholder; anything else is a compile error with a fix-it. The mandatory
placeholder means a pipeline stage always shows where the value lands.

When a caller needs to care about the failure reason rather than just the absence
of a usable value, they should switch to explicit handling:

```swift
guard let user = req.body(User) else {
    log.warn("bad body")
    return 400              // in a handler; inside middleware: respond 400
}
```

`guard let` is therefore the main bridge from the ergonomic value-flow world into
the explicit failure-handling world.

Tuple values remain ordinary values. Numbered placeholders such as `_1` and `_2`
only project tuple slots; they do not introduce a separate error model.

**`if let` / `guard let` — the only binding forms (Swift-identical)**

Rut keeps the binding surface exactly as Swift users expect:

- `guard <expr> else { ... }` requires a **bool** condition. A non-bool
  expression in guard position is a compile error — there is no implicit
  truthiness and no implicit narrowing of a bare value.
- `guard let x = expr else { ... }` binds the usable value of `expr` (whether
  `expr` is optional or error-capable) or runs `else`, which must terminate
  control flow (`return`, `respond`, `continue`, or `break`).
- `guard let x else { ... }` is the Swift 5.7 shorthand for
  `guard let x = x else { ... }` — rebinding an already-bound optional name.
- `if let x = expr { ... }` (and the `if let x { ... }` shorthand) is the
  branching form of the same rule.
- Neither form implicitly unwraps optional payloads *inside* the bound value.

Both forms treat "failed with `error(...)`" and "`nil`" uniformly as "no usable
value" — one binding idiom covers both channels. When a caller needs to
distinguish *which* error occurred, they should use `match` rather than trying
to overload `guard` with pattern semantics.

**`or(...)`**

`or(...)` is the standard value fallback operation:

- if a usable value exists, return it
- if the expression yields `nil`, return the fallback
- if the expression fails with `error(...)`, also return the fallback

Examples:

```swift
let page = req.query("page").or("1")
let n = parseInt(raw).or(0)
let user = findUser(id).or(GuestUser)
let name = user.profileName.or("guest")
```

`or(...)` is deliberately value-oriented. It does not expose or classify the error.

**Runtime bugs**

Out-of-bounds access and similar programming bugs are not modeled as ordinary
`error(...)` values. They remain runtime faults. Integer division by zero is the
exception: it has a defined result (`0`, see §3.2.1) because a hardware fault
would kill the whole shard process.

#### 3.3.8 Compile-Time Constants

`const` declares a value that **must** be computed at compile time. The result is
embedded directly in the binary. No runtime cost.

```swift
const secretHash = sha256(env("STATIC_SECRET"))
const jwtPublicKey = env("JWT_PUBLIC_KEY")
const maxItems = 100
const apiPrefix = "/api/v1"
```

`const` expressions can only contain: literals, `env()`, pure functions (sha256,
base64, string operations), and other `const` values. I/O is a compile error:

```swift
const x = sha256(env("KEY"))              // ✅ pure function + env
const y = get http://config/value         // ❌ compile error: I/O in const
```

`let` without `const` is also evaluated at compile time when possible — the
compiler optimizes pure expressions automatically. `const` is an explicit
assertion: "this must be compile-time; error if it can't be."

#### 3.3.9 Control Flow Constraints

Rutlang guarantees bounded execution — every handler has a finite execution bound
at compile time. This prevents a buggy handler from stalling a shard.

- **`let`** — immutable binding (default).
- **`var`** — mutable binding, **handler-local only**. Not allowed at top level.
  Protects share-nothing: no global mutable state, no cross-shard mutation.
- **`for ... in` only** — iterates finite collections (arrays, struct fields). No `while`, no `loop`.
- **`break` / `continue` allowed** — Swift-identical loop control. They only
  shorten iteration, so the compile-time execution bound is unaffected.
- **No recursion** — all functions inline at compile time. A function calling itself is a compile error.
- **No closures** — no first-class functions, no callbacks. Keyword-specific trailing blocks (e.g., `websocket { frame in }`) borrow Swift's trailing-closure surface but are compile-time constructs, not runtime closures.

```swift
// var — handler-local mutable variable
get /api/data {
    var score = 0                          // ✅ local, any type
    var msg = "violations:"
    if input.matches(re"(?i)UNION\s+SELECT") {
        score += 5
        msg = "\(msg) sql_injection"
    }
    guard score <= 10 else { return 403, msg }
    return forward(userService)
}

// ❌ top-level var — compile error
var globalCounter = 0                      // ERROR: var not allowed at top level

// OK — bounded iteration over array
for item in order.items {
    guard item.qty > 0 else { return 400 }
}

// Compile error — while not supported
while queue.hasNext() { ... }

// Compile error — recursion not supported
func foo(_ req: Request) {
    foo(req)    // ERROR: recursive call detected
}
```

**`defer` — cleanup on any exit path:**

`defer` registers a statement to execute when the handler exits, regardless of
which `return` is taken. Multiple `defer` statements execute in reverse order (LIFO).
Inspired by Go/Swift/Zig.

```swift
get /api/data {
    activeConns.incr(req.remoteAddr)
    defer activeConns.decr(req.remoteAddr)     // runs on ANY exit

    let start = now()
    defer log.info("done", duration: now() - start)  // runs after decr (LIFO)

    guard req.authorization != nil else { return 401 }   // defer still runs
    guard req.contentLength <= 1mb else { return 413 } // defer still runs
    return forward(userService)                        // defer still runs
}
```

Compiler inlines `defer` statements at every `return` site. No runtime stack,
no allocation — pure compile-time code duplication.

### 3.4 Syntax

#### 3.4.1 Listening, TLS, and Upstream

**Listening**

```swift
// Simple
listen :80

// With connection-level security (anti-DDoS / slowloris)
listen :443 {
    maxConns: 100000             // global max connections
    maxConnsPerIP: 256           // per-IP connection limit
    headerTimeout: 10s           // header must arrive within this
    bodyTimeout: 30s             // body must arrive within this
    idleTimeout: 60s             // keep-alive idle timeout
    maxHeaderSize: 8kb           // max total header size
    maxHeaderCount: 100          // max number of headers
    maxUrlLength: 4kb            // max URL length
    minRecvRate: 1kb/s           // close connections slower than this
    strictParsing: true          // reject ambiguous HTTP (anti-smuggling)
}

// Internal port for metrics/admin
listen :9090

// PROXY Protocol — parse HAProxy PROXY v1/v2 to get real client IP behind L4 LBs
// After parsing, req.remoteAddr reflects the original client IP, not the LB's IP
listen :443, proxyProtocol: true
```

**TLS Certificates (SNI)**

TLS certificate declarations are top-level, separate from routing. The compiler generates
an SNI callback table from these declarations. Priority: exact domain > wildcard > default.

```swift
// Per-domain certificates — compiler builds SNI lookup table
tls "api.example.com",   cert: env("API_CERT"),      key: env("API_KEY")
tls "admin.example.com", cert: env("ADMIN_CERT"),     key: env("ADMIN_KEY")

// Wildcard — matches *.example.com not matched by an exact entry
tls "*.example.com",     cert: env("WILDCARD_CERT"),  key: env("WILDCARD_KEY")

// Default — used when SNI doesn't match any domain, or client sends no SNI
tls default,             cert: env("DEFAULT_CERT"),   key: env("DEFAULT_KEY")

// Single-domain shorthand (when only one cert is needed)
tls cert: env("CERT"), key: env("KEY")

// OCSP stapling — runtime periodically fetches OCSP response from CA,
// staples it in TLS handshake for client certificate revocation checking
tls "api.example.com", cert: env("CERT"), key: env("KEY"), ocsp: true
```

**Global Defaults**

Shared configuration inherited by all routes. Per-upstream or per-proxy values override.

```swift
defaults {
    forwardBufferSize: 16kb      // per-connection forward buffer size
    clientMaxBodySize: 10mb      // default max body size
    compress: .auto(             // response compression
        types: [text/html, text/css, application/json, application/javascript]
        minSize: 256b
        level: 4
    )
    errorPages: "/var/www/errors/"   // custom error pages: {dir}/{status}.html
    tracing: .otlp(endpoint: "http://collector:4318")  // or .zipkin(...) or .off
    cache: .auto(capacity: 10000, maxSize: 10mb)       // RFC 7234 auto caching
}
```

**Error pages:** when a handler returns status >= 400, runtime looks up
`{errorPages}/{status}.html`. If found, serves its content as response body.
If not found, sends default plain text. One line config, zero Rutlang code.

**Request priority:** under high load, the runtime can shed low-priority requests
first. Configured via `@priority` decorator on routes or groups:

```swift
route {
    @priority(.high)
    api.example.com/payments { ... }

    @priority(.normal)                    // default
    api.example.com/users { ... }

    @priority(.low)
    api.example.com/analytics { ... }
}
```

When the accept queue or per-shard connection count exceeds a threshold, the runtime
rejects new `.low` priority connections with 503, then `.normal` if load continues.
`.high` priority routes are shed last.

Compression is applied automatically based on `Accept-Encoding` header and
the `types` list. To opt-out for a specific route (e.g., already-compressed
images or streaming responses), use `compress: .off` in the response:

```swift
get /files/:id {
    forward(storageService, compress: .off)          // skip compression for this proxy
}

get /images/*path {
    read(root: "/var/www/images", compress: .off)  // images are already compressed
}
```

**Upstream**

```swift
let users = upstream {
    "10.0.0.1:8080", weight: 3
    "10.0.0.2:8080"
    balance: .leastConn
    health: .active(get: "/ping", every: 5s)              // active — timer probes
    health: .passive(failures: 5, recover: 30s)            // passive — mark unhealthy after consecutive errors
    breaker: .consecutive(failures: 5, recover: 30s)
    retry: .on([502, 503, 504], count: 2, backoff: 100ms)
    connectTimeout: 3s           // override default
    readTimeout: 30s             // per-upstream read timeout
    sendTimeout: 10s             // per-upstream send timeout
    keepalive: 64                // max idle connections per shard
}

// Upstream with mTLS — present client cert when connecting
let internalService = upstream {
    "10.0.0.5:8443"
    tls: .mtls(cert: env("CLIENT_CERT"), key: env("CLIENT_KEY"), ca: env("CA_CERT"))
}

let orders = upstream { "10.0.1.1:8080" }
```

**Load balancing algorithms:**

All standard algorithms are built-in. The runtime tracks per-target state
(connection count, latency, weight) per shard.

| Algorithm | Declaration | Description |
|-----------|-------------|-------------|
| Round Robin | `balance: .roundRobin` | Sequential rotation (default) |
| Weighted Round Robin | `balance: .weightedRoundRobin` | Distribute proportional to `weight:` |
| Least Connections | `balance: .leastConn` | Target with fewest active connections |
| Random | `balance: .random` | Uniform random selection |
| Power of Two (P2C) | `balance: .powerOfTwo` | Random 2 targets, pick the one with fewer connections |
| IP Hash | `balance: .ipHash` | Consistent hash on client IP (session affinity) |
| Consistent Hash | `balance: .hash(expr)` | Consistent hash on arbitrary field (e.g., `req.header("X-User-ID")`) |
| EWMA | `balance: .ewma` | Lowest exponential weighted moving average latency |

**Custom load balancing:**

Users can implement custom algorithms in Rutlang. Instead of `forward(upstream)`,
select a target manually using `upstream.servers` and `forward` to a specific address:

```swift
// Custom: route to the target whose name matches a header
func selectByHeader(_ req: Request, up: Upstream) -> Server {
    for server in up.servers {
        if server.addr == req.header("X-Target-Server") {
            return server
        }
    }
    return up.servers[0]    // fallback to first
}

get /custom {
    let target = selectByHeader(req, up: users)
    return forward(target)
}
```

`upstream.servers` exposes the target list as `[Server]`. `Server` has fields:
`addr` (string), `weight` (i32), `healthy` (bool), `activeConns` (i32),
`latencyEwma` (Duration). The user can read these to implement any selection logic.

`upstream.mark(server, healthy: bool)` manually overrides a target's health —
used by custom health checks running in `timer` blocks.

**Health check modes:**

- `.active(get: path, every: Duration)` — timer-driven HTTP probe to each target
- `.passive(failures: N, recover: Duration)` — runtime tracks forward() errors per
  target; after N consecutive failures, marks unhealthy; recovers after Duration

**Slow start:**

```swift
let backend = upstream {
    "10.0.0.1:8080"
    slowStart: 30s    // newly healthy target ramps weight from 0 to configured over 30s
}
```

When a target recovers from unhealthy, its effective weight increases linearly
from 0 to its configured `weight:` over the `slowStart:` duration. Prevents
overwhelming a freshly started server with full traffic.

**Outlier detection:**

More sophisticated than passive health checks — tracks per-target success rate
over time, ejects targets that perform worse than average.

```swift
let backend = upstream {
    "10.0.0.1:8080"
    "10.0.0.2:8080"
    outlier: .successRate(
        threshold: 0.9,         // eject if success rate < 90%
        interval: 30s,          // evaluation window
        minRequests: 100        // minimum samples before evaluating
    )
}
```

**Retry budget:**

Prevents retry storms — limits total retries as a percentage of normal traffic.

```swift
let backend = upstream {
    retry: .on([502, 503], count: 2, backoff: 100ms)
    retryBudget: .percent(20)   // retries cannot exceed 20% of total requests
}
```

**Locality-aware routing:**

Prefer upstreams in the same zone/region. Reduces cross-zone latency and egress costs.

```swift
let backend = upstream {
    "10.0.0.1:8080", zone: "us-east-1a"
    "10.0.0.2:8080", zone: "us-east-1b"
    "10.0.0.3:8080", zone: "us-west-2a"
    locality: .preferLocal      // prefer targets in same zone as this shard
}
```

**Happy Eyeballs (RFC 8305):**

Dual-stack connect racing — try IPv4 and IPv6 simultaneously, use first to connect.

```swift
let backend = upstream {
    "api.example.com:8080"      // DNS returns A + AAAA records
    happyEyeballs: true         // race IPv4/IPv6 connect, use winner
}
```

**Cluster warming:**

New target waits for first health check to pass before receiving any traffic.

```swift
let backend = upstream {
    health: .active(get: "/ping", every: 5s)
    warming: true               // don't route until health check passes
}
```

**Full upstream example:**

```swift
let userService = upstream {
    "10.0.0.1:8080", weight: 3, zone: "us-east-1a"
    "10.0.0.2:8080", weight: 1, zone: "us-east-1b"
    balance: .ewma
    health: .active(get: "/ping", every: 5s)
    health: .passive(failures: 5, recover: 30s)
    outlier: .successRate(threshold: 0.9, interval: 30s, minRequests: 100)
    breaker: .consecutive(failures: 5, recover: 30s)
    retry: .on([502, 503], count: 2, backoff: 100ms)
    retryBudget: .percent(20)
    connectTimeout: 3s
    readTimeout: 30s
    keepalive: 64
    slowStart: 30s
    warming: true
    locality: .preferLocal
    happyEyeballs: true
    tls: .mtls(cert: env("CLIENT_CERT"), key: env("CLIENT_KEY"), ca: env("CA_CERT"))
}
```

#### 3.4.2 Functions (Middleware and Helpers)

All functions are inlined at compile time. No runtime function call overhead.

**`respond` — the only way to short-circuit.** Inside a function, `respond`
terminates the whole request immediately with a response:

- `respond 401` / `respond 401, "expired"` — status (+ optional body)
- `respond resp` — a built `Response` object (e.g. a CORS preflight `204`)

`return` keeps its single ordinary meaning: produce the function's value (or
nothing) and continue normal flow. A function's declared return type describes
only its normal value — `respond` is a separate exit channel and never
participates in the return type. Inside a route handler, the handler's value
*is* the response, so handlers use `return`; `respond` in a handler is a
compile error with a fix-it (and vice versa for status-`return` in middleware).

Two types of middleware, distinguished by whether the signature contains `Response`:
- **Request middleware**: signature has no `Response` parameter — runs before handler. `respond <status>` to short-circuit, fall through to pass. E.g., `func auth(_ req: Request, role: string)`.
- **Response middleware**: signature contains a `Response` parameter — runs after handler, before sending to client. Can modify response headers, body, status. Valid signatures: `func f(_ resp: Response)` or `func f(_ req: Request, _ resp: Response)`.

`guard ... else { respond ... }` is the idiomatic way to express "check or reject".

```swift
func auth(_ req: Request, role: string) -> User {
    let token = req.authorization.or("")
    guard token.hasPrefix("Bearer ") else { respond 401 }

    let claims = jwtDecode(token.trimPrefix("Bearer "), secret: env("JWT_SECRET"))
    guard let claims else { respond 401 }
    guard claims.exp >= now() else { respond 401, "token expired" }
    guard claims.role == role else { respond 403 }

    req.set("X-User-ID", claims.sub)
    req.set("X-User-Role", claims.role)
    return User(id: claims.sub, role: claims.role)
}

// Rate limiting: use the official @rateLimit decorator today. GCRA in Rut
// over Cache<IP, i64> lands with the pending state/library stack; Counter is
// deleted (§3.3.6).

func requestId(_ req: Request) {
    if req.header("X-Request-ID") == nil {
        req.set("X-Request-ID", uuid())
    }
}

func cors(_ req: Request, origins: [string]) {
    guard let origin = req.origin else { return }
    guard origins.contains(origin) else {
        if req.method == .OPTIONS { respond 403 }
        return
    }

    if req.method == .OPTIONS {
        let resp = response(204)
        resp.set("Access-Control-Allow-Origin", origin)
        resp.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        resp.set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        resp.set("Access-Control-Max-Age", "86400")
        respond resp                       // short-circuit with a full response
    }

    req.set("Access-Control-Allow-Origin", origin)
    req.set("Vary", "Origin")
}

func verifySig(_ req: Request, secret: string) {
    guard let ts = req.header("X-Timestamp") else { respond 401 }
    guard now() - time(ts) <= 5m else { respond 401, "expired" }

    let payload = "\(req.method)\n\(req.path)\n\(ts)"
    guard hmacSha256(secret, payload).hex == req.header("X-Signature") else {
        respond 401, "bad signature"
    }
}

func ipAllow(_ req: Request, cidrs: [CIDR]) {
    guard cidrs.contains(req.remoteAddr) else {
        respond 403
    }
}

func maxBody(_ req: Request, limit: ByteSize) {
    guard req.contentLength <= limit else { respond 413 }
}

// In-flight concurrency limiting needs the exact gauge table (§3.3.6 /
// docs/state-types.md D3) — NOT Cache (an evicted incr leaks the count).
// Upstream max-inflight → 503 exists today as a proxy feature.

// --- Response middleware (takes both Request and Response) ---

func securityHeaders(_ req: Request, _ resp: Response) {
    resp.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    resp.set("X-Content-Type-Options", "nosniff")
    resp.set("X-Frame-Options", "DENY")
    resp.set("X-XSS-Protection", "1; mode=block")
    resp.set("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.remove("Server")      // strip server info
}

// --- Security middleware examples ---

// Flood control is the same GCRA pattern as rate limiting, keyed per-IP.
// Exact global request-rate limiting needs a strict table plus an atomic
// owner-shard GCRA update (§3.3.6). A gauge measures in-flight concurrency,
// not request rate, and cannot replace a window/refill algorithm.

func waf(_ req: Request) {
    let path = req.path
    guard !path.contains("/../") else { respond 403, "path traversal" }
    guard !urlDecode(path).contains("/../") else { respond 403, "encoded traversal" }

    let input = "\(path) \(req.queryString.or(""))"
    guard !input.matches(re"(?i)UNION\s+SELECT|DROP\s+TABLE|<script|javascript:") else {
        log.warn("waf blocked", addr: req.remoteAddr)
        respond 403
    }
}

func blockBots(_ req: Request) {
    let ua = req.userAgent.lower()
    guard !ua.isEmpty else { respond 403 }
    let blocked = ["bot", "spider", "crawler", "scraper"]
    for word in blocked {
        guard !ua.contains(word) else { respond 403 }
    }
}
```

#### 3.4.3 UFCS (Uniform Function Call Syntax)

Any function whose first parameter is type `T` can be called as `t.func(remaining args)`.
The compiler rewrites `t.func(args)` to `func(t, args)`. Pure syntax sugar, zero overhead.

```swift
// These are equivalent:
auth(req, role: "user")
req.auth(role: "user")

// Chaining reads naturally:
req.requestId()
req.auth(role: "user")
req.maxBody(limit: 10mb)

// Works for any type, not just Request:
let clean = req.path.replace(re"/+", "/")    // replace(req.path, re"/+", "/")
```

UFCS does not add methods to types — it's a calling convention. The function must
exist and its first parameter type must match.

#### 3.4.4 Route Definition

`route` is pattern matching on requests. The block has two sections:

1. **Middleware bindings** (top) — `@decorator pattern` declarations
2. **Route entries** (below) — `method path { handler }` or `method path => expr`

No commas between items (Swift style).

**Middleware bindings:**

At the top of a `route` block (before any route entry), `@decorator pattern`
binds a middleware function to all routes matching the pattern. `*` matches all.

```swift
route {
    // Middleware bindings — top of block
    @requestId *                           // all routes
    @waf *                                 // all routes
    @apiGuard api.example.com              // scoped to host
    @adminGuard admin.example.com          // scoped to host
    @maxBody(limit: 1mb) api.example.com/orders  // scoped to host + path

    // Route entries below...
}
```

`@decorator` can also be placed directly on a route entry or group for one-off cases:

```swift
route {
    @requestId *

    @maxBody(limit: 100mb)                  // only this route
    post /files/upload => forward(storageService, streaming: true)

    get /users/:id => forward(userService)  // gets @requestId from binding
}
```

**Pre vs post middleware — inferred from function signature:**

One rule: **if the signature contains a `Response` parameter (any position),
it is post-middleware. Otherwise, it is pre-middleware.**

```swift
// Pre — no Response in signature
func requestId(_ req: Request) { ... }

// Post — signature contains Response
func addSecurityHeaders(_ resp: Response) {
    resp.remove("Server")
    resp.set("X-Content-Type-Options", "nosniff")
}

// Post — also contains Response (req available too)
func logResponse(_ req: Request, _ resp: Response) {
    log.info("responded", status: resp.status, path: req.path)
}

// Same @ syntax for both — compiler infers from signature
route {
    @requestId *                // Request → pre
    @addSecurityHeaders *       // Response → post

    get /users/:id => forward(userService)
}

// Expands to:
//   requestId(req)              ← pre
//   handler                     ← forward
//   addSecurityHeaders(resp)    ← post
```

**Post-middleware forces buffered mode.** When a post-middleware is bound to a
route that uses zero-copy `forward`, the compiler automatically switches to
buffered mode and emits a warning:

```
⚠ warning: post-middleware @addSecurityHeaders forces buffered mode for
            'get /users/:id => forward(userService)'. Zero-copy disabled.
            To silence: use forward(userService, buffered: true) explicitly.
```

**Conditional decorators: `@if`**

`@if(expr)` conditionally applies the decorator below it. The expression is
evaluated at compile time (`env()` values resolved when .rut is compiled).
If false, the decorator binding is eliminated — zero runtime cost.

```swift
route {
    @requestId *

    @if(env("ENABLE_WAF") == "true")
    @waf *

    @if(env("ENV") == "production")
    @addSecurityHeaders *

    api.example.com {
        get /users/:id => forward(userService)
    }
}
```

**Route parameters** support optional type constraints:

```swift
//   :name          — captures any segment as string
//   :name(i32)     — captures only if segment is a valid i32
//   :name(i64)     — captures only if segment is a valid i64
//   :name(uuid)    — captures only if segment is a valid UUID
//   *rest          — captures remaining path segments as string (must be last)

get /users/:id(i64) {         // req.params.id is i64, returns 404 if not numeric
    return forward(userService)
}

get /files/*rest {            // req.params.rest captures "docs/2024/readme.md"
    return read(root: "/var/www")  // req.path is still the full "/files/docs/…"
}
```

**Pattern prefix grouping:**

A host name or path prefix followed by `{ }` groups routes sharing that prefix.
Groups can nest.

```swift
route {
    api.example.com {
        /v1 {
            get /users/:id => forward(usersV1)
        }
        /v2 {
            get /users/:id => forward(usersV2)
        }
    }

    *.example.com {
        get|post /** {
            let resp = response(301)
            resp.set("Location", "https://www.example.com\(req.path)")
            return resp
        }
    }

    _ => 444
}
```

Parser rule: inside `route { }`:
- `@decorator pattern` (no `{` or `=>` after pattern) → middleware binding
- `@decorator` + route entry or group `{` → direct decorator
- `identifier.identifier... {` → host group
- `/path {` without method keyword → path group
- method keyword (`get`, `post`, `get|post`, ...) → route entry
- `_` → catch-all

**Full route example:**

```swift
route {
    // Middleware bindings
    @requestId *
    @apiGuard api.example.com
    @adminGuard admin.example.com

    // Routes
    get /health => 200

    api.example.com {
        get /users/:id(i64) => forward(userService)

        post /orders {
            guard let order = req.body(Order) else { return 400 }
            for item in order.items {
                guard item.qty > 0 else { return 400, "invalid quantity" }
            }
            return forward(orderService)
        }
    }

    /admin {
        get /stats => 200, json(stats())
        post /reload {
            reload()
            return 200
        }
    }

    _ => 404
}
```

##### 3.4.4.1 Route Dispatch Semantics

The examples above describe syntax. The dispatch contract also needs explicit
precedence rules so the compiler, simulator, and runtime agree on which route wins.

**Method matching**

- The **language contract** is exact HTTP method matching
- `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS` are supported keywords
- Multiple methods via `|`: `get|post /path { ... }`
- `_` is the catch-all (matches any method and path)
- No `ANY` keyword — omitting the method in a path group matches all methods for that group

**Path matching**

- A literal segment outranks a parameter segment
- A parameter segment outranks a catch-all segment
- `*rest` matches the remainder of the path and must be the final segment
- Query strings are not part of route matching unless a construct explicitly says otherwise

**Precedence**

For routes in the same host scope and method scope, the compiler must select the
most specific match using this precedence order:

1. More static path segments
2. Fewer parameter segments
3. No catch-all over catch-all
4. Earlier declaration order only as the final tiebreaker when two patterns are otherwise equivalent

Two routes that are semantically indistinguishable after applying these rules are
a compile-time error, not "first match wins".

**Examples**

```swift
get /users/me           // outranks:
get /users/:id

get /files/:id          // outranks:
get /files/*rest

get /users/:id
get /users/:name        // compile error: conflicting route patterns
```

**Host precedence**

- Exact host beats wildcard host
- Wildcard host beats `_` catch-all
- Missing TLS material for a host reachable on a TLS listener is a compile-time error

**Current implementation note**

Runtime route dispatch uses canonical method keys, not method-name first bytes:
`0` is the any-method slot and `1..9` map to the supported HTTP methods. Each
terminal stores `route_idx_by_method[method_key]`, so `POST`, `PUT`, and `PATCH`
are distinct even though they share the same first character. Lookup prefers the
method-specific slot and falls back to the any-method slot.

Method masks are reserved for policy-style checks such as `limit_except`,
`allowed_methods`, or future `GET|HEAD` grouping. They are not the primary route
dispatch representation because Rut routes may attach different actions to the
same path for different methods.

#### 3.4.5 Response Modification

`forward` has two modes:

- **Zero-copy** — `return forward(upstream)`. Data spliced directly between sockets,
  never enters userspace. No response modification possible.
- **Buffered** — `forward(upstream, buffered: true)`. Response read into memory,
  returned as `Response` object. Full modification, then explicit `return`.

```swift
// Zero-copy — no modification, maximum performance
get /users/:id => forward(userService)

// Buffered — modify headers
get /users/:id {
    let resp = forward(userService, buffered: true)
    resp.remove("Server")
    resp.set("X-Request-ID", req.header("X-Request-ID").or(""))
    return resp
}

// Buffered — modify body, log errors
get /users/:id {
    let resp = forward(userService, buffered: true)
    if resp.status >= 500 {
        log.error("upstream error", status: resp.status, path: req.path)
    }
    if resp.status == 404 {
        resp.status = 200
        resp.body = json({ users: [], total: 0 })
    }
    return resp
}
```

The compiler detects which mode to use:
- `return forward(x)` or `=> forward(x)` → zero-copy
- `let resp = forward(x, buffered: true)` → buffered, `resp` is a regular variable

**Bandwidth limiting** — see §3.4.10 Throttle.

**Response object members (buffered mode):**

```swift
let resp = forward(userService, buffered: true)
resp.status                   // StatusCode — read/write
resp.body                     // string — read/write
resp.header("Server")         // string? — header read
resp.set("Server", val)       // header write (replace)
resp.remove("Server")         // header delete
resp.add("Set-Cookie", val)   // append multi-value header
resp.getAll("Set-Cookie")     // [string] — all values
resp.cookie("session")        // string? — read a Set-Cookie value by name
resp.upstream                 // string — which target served this ("10.0.0.1:8080")
```

`resp.cookie()` and `resp.upstream` provide the observations needed for a
future sticky-session "learn" mode. Rut cannot express that mode today:
`Hash` is reserved for the future strict table (§3.3.6), and lossy `Cache`
must not hold sessions. No copyable declaration is specified until the strict
table and its cross-connection consistency contract exist.

#### 3.4.6 Response Caching

Standard HTTP response caching (RFC 7234) is handled automatically by the runtime,
configured in `defaults`:

```swift
defaults {
    cache: .auto(capacity: 10000, maxSize: 10mb)  // runtime respects Cache-Control headers
}
```

For custom caching logic, use `LRU` state type + `forward(buffered: true)`:

```swift
let responseCache = LRU<string, string>(capacity: 10000, ttl: 5m)

get /users/:id {
    let key = "/users/\(req.params.id)"
    if let cached = responseCache.get(key) {
        return 200, cached
    }
    let resp = forward(userService, buffered: true)
    responseCache.set(key, resp.body)
    return resp
}
```

#### 3.4.7 Traffic Mirroring

`fire` sends a request without waiting for the response (fire-and-forget). Useful for traffic shadowing, async logging, webhooks.

```swift
func mirror(_ req: Request, to: string) {
    fire post http://\(to)\(req.path) {
        Headers: req.headers
        Body: req.bodyRaw
        Timeout: 5s           // timeout for the fire, won't block caller
    }
}

// Usage: mirror production traffic to staging
post /api/orders {
    auth(req, role: "user")
    mirror(req, to: "staging-gateway:8080")   // fire-and-forget
    forward(orderService)               // actual request
}
```

#### 3.4.8 WebSocket Proxying

Transparent WebSocket proxy with optional per-frame inspection and modification.
Ping/pong handled automatically by runtime (RFC 6455).

**Basic — transparent proxy:**

```swift
get /ws/chat {
    auth(req, role: "user")
    guard req.upgrade == .websocket else { return 400 }
    return websocket(chatService)
}
```

**With options:**

```swift
get /ws/graphql {
    guard req.upgrade == .websocket else { return 400 }
    return websocket(graphqlService,
        subprotocol: "graphql-ws",     // Sec-WebSocket-Protocol negotiation
        maxMessageSize: 1mb             // reject frames larger than this
    )
}
```

**Frame inspection and modification:**

The trailing block runs per frame and declares its parameter explicitly,
Swift-trailing-closure style: `{ frame in ... }`. It is compiled into the
route's state machine — not a runtime closure.

```swift
get /ws/events {
    guard req.upgrade == .websocket else { return 400 }
    websocket(eventService, maxMessageSize: 64kb) { frame in
        // --- frame properties ---
        // frame.isText       bool
        // frame.isBinary     bool
        // frame.isPing       bool
        // frame.isPong       bool
        // frame.text         string (for text frames)
        // frame.bytes        [u8] (for binary frames)
        // frame.direction    .client or .upstream

        // --- actions ---
        // return .forward                   pass through unchanged
        // return .drop                      silently discard this frame
        // return .close(reason: "...")       close the connection
        // return .send("modified text")     replace content, then forward
        // return .sendBytes(bytes)          replace with binary, then forward
        // return .inject("extra message")   forward original + inject extra frame

        // Example: filter profanity from client messages
        if frame.direction == .client && frame.isText {
            guard !frame.text.matches(re"(?i)badword|profanity") else {
                return .drop
            }
        }

        // Example: inject metadata into upstream messages
        if frame.direction == .upstream && frame.isText {
            return .send("\(frame.text)\n<!-- gateway: \(now()) -->")
        }

        return .forward
    }
}
```

**Frame action summary:**

| Action | Effect |
|--------|--------|
| `.forward` | Pass frame unchanged to other side |
| `.drop` | Silently discard, other side sees nothing |
| `.close(reason:)` | Close WebSocket connection with reason |
| `.send(text)` | Replace frame content with text, then forward |
| `.sendBytes(bytes)` | Replace frame content with binary, then forward |
| `.inject(text)` | Forward original frame AND send an additional text frame |

**Runtime semantics (passthrough tunnel).**

The current runtime implements transparent **passthrough** (no frame parsing yet;
frame inspection above is the planned terminate mode). After a proxied upstream
answers `101 Switching Protocols`, the connection becomes a full-duplex byte
tunnel: two independent ping-pong loops (read one side → send to the other →
re-read), each with its own buffer for natural backpressure.

- **Upgrade gating.** A `101` is only honored as a tunnel when the *client*
  actually requested the upgrade (`Connection: upgrade`). A `101` to a plain
  keep-alive request is treated as a protocol violation and the connection is
  closed — a misbehaving or hostile backend cannot hijack the connection and
  have pipelined bytes forwarded raw.

- **Backpressure.** Each direction pauses its read while its paired send drains,
  so a slow peer applies TCP flow control to the fast one. Buffered bytes are
  never split or dropped: a send completion consumes only the submitted prefix
  and re-sends any bytes that raced in. On io_uring (provided-buffer recv), a
  buffer-full `-ENOBUFS` means the overflow was already consumed and discarded,
  so the tunnel fails closed there rather than forwarding a corrupted stream.

- **Connection teardown — drain-then-close (nginx model).** WebSocket shutdown
  is an *application-level* event (the RFC 6455 Close-frame handshake), not a TCP
  half-close. So when either peer closes the underlying TCP connection (FIN), the
  tunnel **stops reading new data but flushes all in-flight and buffered bytes in
  both directions, then tears down both sides.** It does *not* keep relaying new
  data after a FIN (true TCP half-close relay), and it never truncates buffered
  data. This matches nginx's upgraded-connection handling; Envoy and AWS ALB
  likewise treat WebSocket as TCP passthrough that relies on Close frames for
  orderly shutdown (Envoy offers optional half-close *relay* for generic
  `tcp_proxy`, but it is not required for WebSocket). On the level-triggered
  epoll backend the closing fd's read interest is dropped (so the FIN cannot spin
  the loop) while any pending send keeps its `EPOLLOUT` so it can finish draining.

#### 3.4.9 Streaming Proxy

For large bodies (file uploads, downloads), stream without buffering:

```swift
post /upload {
    auth(req, role: "user")
    guard req.contentLength <= 100mb else { return 413 }
    forward(storageService, streaming: true)    // body streams through, not buffered
}

get /download/:fileId {
    forward(storageService, streaming: true)    // response streams to client
}
```

#### 3.4.10 Throttle (Bandwidth Limiting)

`throttle` sets per-connection transfer rate. Applies to all subsequent I/O
in the handler. Two directions: `downstream` (gateway → client) and
`upstream` (gateway → backend).

**Syntax:**

```swift
throttle(downstream: ByteSize per Duration)
throttle(upstream: ByteSize per Duration)
throttle(downstream: ByteSize per Duration, upstream: ByteSize per Duration)
```

`per` is a keyword that connects ByteSize and Duration into a Rate,
evaluated at compile time.

**Scenarios:**

```swift
// File download — limit per-user download speed
get /files/:id {
    throttle(downstream: 100kb per 1s)
    return forward(storageService)
}

// Video streaming — pace to match playback rate
get /video/:id {
    throttle(downstream: 5mb per 1s)
    return forward(cdnService, streaming: true)
}

// Upload protection — don't overwhelm slow upstream
post /upload {
    throttle(upstream: 500kb per 1s)
    return forward(legacyService, streaming: true)
}

// Anti-scraping — slow down data extraction
@auth(role: "user")
get /api/products/:id {
    throttle(downstream: 50kb per 1s)
    return forward(productService, buffered: true)
}

// Tiered service — different speeds per plan
get /data/*path {
    match req.ctx.userPlan {
        "enterprise" => throttle(downstream: 10mb per 1s)
        "pro" => throttle(downstream: 1mb per 1s)
        _ => throttle(downstream: 100kb per 1s)
    }
    return forward(storageService)
}

// Both directions
post /sync {
    throttle(downstream: 1mb per 1s, upstream: 500kb per 1s)
    return forward(syncService, streaming: true)
}
```

**Optional burst:**

```swift
throttle(downstream: 100kb per 1s, burst: 256kb)
// Burst allows initial fast transfer, then settles to rate
// Default burst = 2x rate (e.g., 200kb for 100kb/s)
```

**Implementation — two tiers, runtime auto-selects:**

| Tier | Mechanism | When used | Overhead |
|------|-----------|-----------|----------|
| 1. Kernel | `SO_MAX_PACING_RATE` socket option | Linux with FQ qdisc enabled | zero userspace |
| 2. Userspace | Token bucket in shard's timer wheel | always available (fallback) | timer tick per 10ms |

eBPF (XDP/TC) cannot do per-route throttling — it operates at L3/L4 and
doesn't know which HTTP route a connection belongs to. Throttle decisions
come from L7 handlers, so execution is kernel socket option or userspace
token bucket.

**Token bucket** is the primary implementation (same approach as Envoy's
`bandwidth_limit` filter):
- Per-connection bucket: capacity = burst, refill rate = throttle rate
- Timer wheel tick every 10ms refills tokens
- send(): consume tokens for bytes sent; no tokens → yield, wait for refill
- Still zero-copy with sendfile/splice — just paced into chunks
- Always available, no kernel requirements, no special capabilities

**SO_MAX_PACING_RATE** is an optimization when available:
- Requires FQ qdisc on network interface (`tc qdisc show dev eth0 | grep fq`)
- Zero userspace overhead — kernel paces packets using departure timestamps
- Runtime detects FQ at startup (no root needed to check)
- Enabling FQ requires CAP_NET_ADMIN (Node Agent can do this)

**Deployment scenarios:**

| Environment | FQ available? | Throttle implementation |
|-------------|--------------|------------------------|
| Edge gateway (bare metal, root) | Yes — Node Agent enables FQ | SO_MAX_PACING_RATE |
| Edge gateway (cloud VM, root) | Likely — GCP enables BBR+FQ by default | SO_MAX_PACING_RATE |
| K8s sidecar (unprivileged pod) | Depends on node OS | Token bucket (same as Envoy) |
| K8s with Rut Node Agent | Yes — Agent enables FQ on node | SO_MAX_PACING_RATE |
| Serverless (Fargate, Cloud Run) | No — can't modify qdisc | Token bucket |

Token bucket is the core — works everywhere. SO_MAX_PACING_RATE is a
zero-cost upgrade when the infrastructure supports it.

**Compile-time checks:**

| Check | Example | Error |
|-------|---------|-------|
| throttle outside handler | top-level `throttle(...)` | "throttle only valid inside handler" |
| missing per | `throttle(downstream: 100kb)` | "expected 'per Duration'" |
| burst < rate | `throttle(downstream: 100kb per 1s, burst: 50kb)` | warning: "burst smaller than rate" |

#### 3.4.11 File and Pipe I/O

`read` is a unified built-in function for files, pipes, and devices. Two modes
determined by usage, same as `forward`:

- `return read(...)` or `=> read(...)` → **zero-copy** (sendfile/splice)
- `let content = read(...)` → **buffered**, error-capable value

```swift
// Zero-copy — static file serving, data goes directly to client socket
get /static/*path => read(root: "/var/www")
get /favicon.ico => read(path: "/var/www/favicon.ico")

// SPA fallback
get /*path => read(root: "/var/www/dist", fallback: "index.html")

// Cache control via route pattern matching
/static {
    get re".*\.(css|js|woff2)$" => read(root: "/var/www", maxAge: 30d)
    get re".*\.html$"           => read(root: "/var/www", maxAge: 0s)
    get /*path                   => read(root: "/var/www", maxAge: 1d)
}

// Pipe — same interface
get /stream => read(path: "/tmp/data_pipe")

// Buffered — read into memory for modification
get /index.html {
    guard let content = read(path: "/var/www/index.html") else { return 404 }
    let html = content.replace("{{VERSION}}", env("APP_VERSION"))
    let resp = response(200)
    resp.set("Content-Type", "text/html")
    resp.body = html
    return resp
}
```

Parameters:
- `read(root:)` — directory mode: joins `root` + the route's `*` catch-all capture (whatever its name)
- `read(path:)` — specific file/pipe/device
- `fallback:` — file served when target not found (SPA)
- `index:` — default `"index.html"` for directory requests
- `maxAge:` — sets `Cache-Control: max-age=N`
- `maxSize:` — buffered mode only, defaults to 10mb, exceeding returns error

Behavior:
- Auto-sets `Content-Type` by file extension
- Auto-sets `Last-Modified` and `ETag` (regular files only)
- Rejects path traversal (`/../`) → 403
- Does not follow symlinks outside root
- Compiler chooses I/O backend: sendfile (regular file), splice (pipe), io_uring read (buffered)

#### 3.4.12 TCP/UDP I/O

Raw TCP and UDP access for protocols beyond HTTP (Redis, StatsD, syslog, etc.).
Same async safety model — compiler generates yield points, io_uring/epoll backend.

**TCP — connection-oriented, stream:**

```swift
// error-capable TcpConn, compiler yields
guard let conn = tcp("redis:6379") else { return 502 }
defer conn.close()

conn.send("PING\r\n")                  // send data
// error-capable string, compiler yields
guard let data = conn.recv(maxSize: 4kb) else { return 502 }

// With timeout
let h = submit conn.recv(maxSize: 4kb)
guard let data = any(wait(h, 1s)) else { return 504 }
```

`TcpConn` members:
- `.send(data)` — send data, error-capable bytes-sent result
- `.recv(maxSize:)` — receive data, error-capable string result
- `.close()` — close connection
- `.remoteAddr` — `IP`
- `.localAddr` — `IP`

**UDP — connectionless, datagrams:**

```swift
guard let sock = udp() else { return 500 }
defer sock.close()

// Send (fire-and-forget, typical for metrics/logging)
sock.sendTo("10.0.0.1:8125", "myapp.requests:1|c")

// Receive — error-capable `(string, IP)`
guard let data = sock.recvFrom(maxSize: 4kb) else { return 502 }
let (payload, sender) = data
```

**Safety:** same as HTTP calls — no blocking (io_uring async), timeout via
`any(wait(h, Duration))`, memory bounded by `maxSize:`, connection cleanup
via `defer`. No `while` loops prevent unbounded read loops.

**Typical use — Redis client in stdlib:**

```swift
// stdlib/redis.rut
func redisGet(_ req: Request, addr: string, key: string) -> string? {
    guard let conn = tcp(addr) else { return nil }
    defer conn.close()
    conn.send("GET \(key)\r\n")
    guard let resp = conn.recv(maxSize: 16kb) else { return nil }
    return parseRedisReply(resp)
}
```

#### 3.4.13 Terminal Statements

These statements end the handler — code after them is unreachable. The compiler
reports an error if it finds code after a terminal statement.

| Statement | Effect |
|-----------|--------|
| `return N` | (handler) Send HTTP response with status code N |
| `return forward(upstream)` | (handler) Forward request to upstream (zero-copy) |
| `return read(root:)` | (handler) Serve static file/pipe (zero-copy) |
| `return websocket(upstream)` | (handler) Upgrade to WebSocket and proxy |
| `respond N` / `respond N, body` / `respond resp` | (middleware) Short-circuit the request with a response |

In handlers all terminal statements use `return` — the handler's value is its
response. In middleware, `respond` is the terminal statement. `forward`, `read`,
`websocket` without `return` (assigned to `let`) are non-terminal buffered
operations.

```swift
get /users/:id {
    return forward(userService)
    log.info("done")   // compile error: unreachable code after return
}
```

`fire` is NOT terminal — it's non-blocking and execution continues after it.

#### 3.4.14 Conditional Routing

Route to different upstreams based on request attributes:

```swift
let usersV1 = upstream { "10.0.0.1:8080" }
let usersV2 = upstream { "10.0.0.2:8080" }
let canary  = upstream { "10.0.0.3:8080" }
let stable  = upstream { "10.0.0.4:8080" }

// By header
get /api/users/:id {
    let target = match req.header("X-API-Version") {
        "v2" => usersV2
        _    => usersV1
    }
    return forward(target)
}

// Canary release: percentage-based — a two-way bool branch uses if, not match
get /api/** {
    if fnv32(req.remoteAddr) % 100 < 10 {
        return forward(canary)
    }
    return forward(stable)
}

// Blue-green via environment variable
get /api/** {
    let target = match env("DEPLOY_GROUP") {
        "blue" => blueUpstream
        _      => greenUpstream
    }
    return forward(target)
}
```

#### 3.4.15 HTTP Calls (Native Syntax)

HTTP requests use native method + URL syntax. The compiler automatically handles async — no await needed. User writes sequential code.

```swift
// GET request
let res = get http://auth/verify {
    Authorization: token
}

// POST with body
let res = post http://order-service/create {
    Content-Type: application/json
    Body: order
    Timeout: 10s
}

// Using the response — the call itself is error-capable, unwrap first
guard let res else { return 502 }
guard res.status == 200 else { return 502 }
guard let user = res.body(User) else { return 502 }

// Fire-and-forget (non-blocking, don't wait for response)
// On failure (connect refused, DNS error, timeout): auto log.warn, never affects caller.
fire post http://audit-service/log {
    Body: json({ action: "login", userId: user.id, time: now() })
}
```

#### 3.4.16 Regex

Native regex support with `re"pattern"` literals. Backed by Vectorscan (Hyperscan fork
with ARM support). Patterns are compiled at .rut compile time — invalid regex is a compile
error. The compiler auto-merges multiple patterns in the same scope into a single Vectorscan
database for one-pass scanning.

```swift
// Matching
guard req.path.matches(re"^/api/v\d+/") else { return 404 }

// Capture groups — error-capable match extraction
guard let m = req.path.match(re"^/api/v(\d+)/(.*)") else { return 404 }
let version = m[1]    // "2"
let rest = m[2]       // "users/123"

// Replace
let clean = req.path.replace(re"/+", "/")

// In match expressions
match req.userAgent {
    re"(?i)mobile|android|iphone" { forward(mobileBackend) }
    re"(?i)bot|spider"            { return 403 }
    _                              { forward(desktopBackend) }
}
```

**Multi-pattern optimization:** when the compiler sees multiple regex checks in the
same function, it merges them into a single Vectorscan pattern database. One scan
matches all patterns simultaneously.

```swift
// User writes N separate checks:
func waf(_ req: Request) {
    let input = "\(req.path) \(req.queryString.or(""))"
    guard !input.matches(re"(?i)UNION\s+SELECT") else { respond 403 }
    guard !input.matches(re"(?i)DROP\s+TABLE") else { respond 403 }
    guard !input.matches(re"<script") else { respond 403 }
    guard !input.matches(re"javascript:") else { respond 403 }
}

// Compiler merges into one Vectorscan database, one scan → O(input_length),
// regardless of how many patterns.
```

#### 3.4.17 Module System

All top-level `func` and `struct` in a file can be imported by other files.
File name automatically becomes the namespace.

```swift
// Import — file name becomes namespace
import "middleware/auth.rut"            // auth.jwtAuth, auth.basicAuth
import "middleware/security.rut"        // security.cors, security.waf

// Selective import — symbols brought into current scope, no prefix
import { cors, securityHeaders } from "stdlib/security.rut"
import { jwtAuth as authV1 } from "middleware/auth.rut"
import { Hashable as Digestible, Box as AuthBox } from "proto.rut"

// using — create alias for namespaced symbol
import "middleware/v1.rut"
import "middleware/v2.rut"
using authV1 = v1.jwtAuth              // short alias
using authV2 = v2.jwtAuth
```

Rules:
- File name is the namespace: `"path/foo.rut"` → `foo.symbol`
- Selective import (`import { x } from`) puts only the selected top-level symbols in current scope without prefix
- Selective import supports aliasing via `import { x as y } from "file"`; imported functions and top-level type declarations (`struct` / `variant` / `protocol`) can be renamed, and the original imported name is not brought into scope
- Referencing a non-selected name is a compile error
- Selecting a symbol that the imported file does not export is a compile error
- Repeated selective imports of the same file merge selected-name sets; any plain `import "file"` upgrades visibility to the full file
- `using name = module.symbol` creates an alias
- `using` is only for alias/import syntax; it must not be reused for protocol conformance
- Circular imports are a compile error
- Importing a symbol that doesn't exist is a compile error
- Duplicate imports of the same file are silently deduplicated
- Relative `import` is resolved from the importing file path
- The current first-stage multi-file implementation merges imported top-level functions and makes imported `struct` / `variant` / `protocol` declarations visible during analysis
- Imported explicit `impl` blocks participate in the same visible conformance set as local `impl` blocks
- Any visible overlap in explicit `impl` for the same `Type + Protocol` pair is a compile error, regardless of whether the overlap is local vs imported, imported vs imported, concrete vs generic, or import order
- `namespace` is the language-level naming model; imports, qualified names, and aliases resolve through namespaces, not through package-specific lookup rules

#### 3.4.18 Package Metadata

Rut may eventually expose a lightweight `package` concept, but only as a
distribution boundary, not as a second namespace system and not as a full
dependency solver.

Intended boundary:

- `namespace` remains the language-level name-resolution concept
- `package` is only a unit of publication / reuse
- imports still resolve to namespaces and module paths
- package metadata must stay lightweight enough for a DSL workflow

The intended first-stage package model is:

- by default, one file is one implicit package unit
- a file may declare `package foo` at the top to join a named package
- multiple files that declare the same `package foo` belong to the same package
- package grouping is explicit in source, not inferred from a directory-only rule
- `package foo` is a file-header declaration and must appear before other top-level declarations
- a package declaration groups files for distribution/reuse, but each file still keeps its own file/module namespace
- no registry protocol
- no semantic-version solving
- no lockfile-driven dependency graph resolution
- no separate package-level namespace rules beyond normal module/namespace lookup

If Rut later adds package-manager metadata for dependencies, the design must
distinguish between:

- a dependency requirement recorded in manifest metadata
- a resolved dependency version recorded by package-management tooling
- downloaded artifact integrity recorded for verification

So a manifest version string by itself is not enough to verify dependency
correctness. Correctness eventually depends on resolver output, lock data, and
integrity checks.

The current design direction is:

- every declared dependency must carry an explicit version requirement
- version requirements may later be exact versions or constrained ranges, but
  manifest requirements are not themselves the final verified install result
- missing dependency versions are invalid
- a future lock step is responsible for recording resolved exact versions
- a future integrity step is responsible for recording source/checksum data

What package metadata is allowed to affect:

- how a file or file-group is identified for publication / reuse
- whether multiple files are grouped into one named package
- future packaging / release tooling
- package-level validation that a set of files intentionally belong together

What package metadata must not affect in the first stage:

- local lexical scope rules
- namespace formation rules
- qualified-name syntax
- import semantics inside a package once the target file/module is resolved
- heavy dependency resolution or transitive version selection

First-stage package validity rules:

- `package foo` must be the first non-comment, non-whitespace declaration in a file
- a file has at most one package declaration
- files that omit `package` remain standalone implicit package units
- files that declare the same package still do not merge into one flat namespace; top-level lookup continues to go through file/module namespaces
- if two files in the same package expose colliding top-level names through the same namespace path, that is still a normal namespace/import conflict, not a special package rule

Current implementation status:

- file-header `package foo` is parsed and recorded in `AstFile` and `HirModule`
- imported files also carry package metadata into `HirImport`
- `HirImport.same_package` is available as a compiler-internal signal when the
  importing file and imported file both declare the same package name
- this `same_package` signal is recorded consistently for plain import,
  selective import, and namespace-alias import
- this signal is currently observational only; it does not yet change import
  resolution, namespace formation, or visibility
- package-aware import resolution, package namespaces, and package-manager
  behavior are intentionally still out of scope

Example:

```swift
// implicit file package unit
func jwtAuth() -> i32 => 200
```

```swift
package auth

func jwtAuth() -> i32 => 200
```

```swift
package auth

func basicAuth() -> i32 => 200
```

In the example above, the first file stands alone as its own package unit. The
last two files belong to the same explicit package `auth`, while still being
separate file/module namespaces.

Possible future package-manager metadata shape:

```swift
package auth

manifest {
    version: "1.2.3"
    root: "src"
    deps: [
        dep("security", "0.4.1"),
        dep("jwt", "1.2.0"),
    ]
}
```

The intent is that package metadata remains self-described in Rut rather than
switching to TOML or YAML. At the same time, this manifest form should stay a
restricted declaration surface, not an arbitrary executable Rut program.

This example only illustrates manifest-level dependency requirements. A future
package manager would still need resolver output and lock/integrity data before
dependency versions are actually reproducible and verifiable.

Package grouping does not replace file/module namespaces. Once a module is
loaded, the compiler still reasons in terms of file/module namespaces such as
`auth.jwtAuth` or `proto.Box`.

So the design target is:

- keep namespace semantics in the compiler
- optionally add package metadata for distribution and reuse
- do not turn Rut into a general-purpose package-managed ecosystem

#### 3.4.19 Current Scope And Name Resolution

Current implementation behavior should be read as:

- a file provides a **top-level declaration namespace**, not a general-purpose local variable scope
- top-level names include declarations such as `func`, `struct`, `variant`, `protocol`, `impl`, `import`, and `using` alias declarations
- imported top-level declarations participate in the same visible lookup set as local top-level declarations, subject to the import rules above

Local variable scope is block-oriented:

- route-body `let` bindings are visible to later statements in the same route body
- function parameters are visible throughout the function body
- function-body `let` bindings are visible to later statements in the same block
- bindings introduced inside `if` / `match` / branch blocks stay inside that branch block
- `match` payload bindings are visible only inside their corresponding arm

Current `guard` scoping rules:

- `guard let x = expr else { ... }` extends `x` into the success path after the guard
- `guard match ... else { ... }` is a control-flow check; it does not itself introduce a new post-guard binding name

Name-resolution consequences:

- a plain file import such as `import "auth.rut"` makes the file stem available as a namespace for value/type references such as `auth.jwtAuth()` and `auth.Box`
- `import * as auth from "auth.rut"` creates an explicit namespace alias
- selective import brings only the selected symbols into the current top-level namespace and does not create a namespace object
- `using` only creates aliases for already-visible names; it is not a second conformance system and is not a local-value binding construct
- package metadata does not replace namespace lookup; imported names still resolve through file/module namespaces and explicit aliases

This is the current implementation contract. A future language-level scope chapter may formalize this more completely, but current tests and compiler behavior already rely on these rules.

#### 3.4.20 Type Conversion

`as` is for value-to-value conversion, not text parsing.

- infallible conversions stay as `as`
- checked conversions use `as?`
- string/domain decoding belongs to parse APIs such as `parseInt(...)`, `IP.parse(...)`, and `Duration.parse(...)`

```swift
// Checked numeric conversion
guard let page = parseInt("42") else { return 400 }

guard let weight = parseFloat("3.14") else { return 400 }

// With value fallback
let limit = parseInt(req.query("limit").or("20")).or(20)

// Number → string (infallible)
let s = 200 as string                         // "200"
let s = 3.14 as string                        // "3.14"

// Domain type parsing
let ip = IP.parse("10.0.0.1")
let cidr = CIDR.parse("10.0.0.0/8")
let dur = Duration.parse("30s")
```

**Standard library:**

Rutlang ships with a standard library of common middleware and utility functions.
All are regular `.rut` files — users can read, modify, or replace them. No magic.

```
stdlib/
├── auth.rut           // basicAuth, jwtAuth, apiKeyAuth
├── security.rut       // cors, securityHeaders, ipAllow, waf
├── request.rut        // requestId, maxBody
└── fault.rut          // faultInject (delay + error injection for chaos testing)
```

```swift
// PR #184 adds standalone rate-limit examples, not an importable tokenBucket helper.
import { cors, securityHeaders } from "stdlib/security.rut"
```

#### 3.4.21 No FFI

Rutlang has no `extern func` or FFI mechanism. The gateway only communicates via
HTTP. External systems (Redis, databases, LDAP, HSM) are accessed through HTTP
calls to proxy services.

Rationale: FFI breaks all compile-time guarantees — bounded execution, memory
safety, share-nothing isolation. A single C++ function call could block, malloc,
segfault, or access shared memory.

#### 3.4.22 Concurrent I/O

`submit` starts an async I/O operation without waiting. `wait` collects results.
Maps directly to io_uring batched submission.

```swift
// Submit — non-blocking, returns handle
let h1 = submit get http://user-service/users/1
let h2 = submit get http://order-service/orders?user=1

// Wait all — single yield point, one io_uring_enter syscall
let (r1, r2) = wait(h1, h2)           // pair of error-capable responses
guard let r1 else { return 502 }
guard let r2 else { return 502 }
return 200, json({ user: r1.body, orders: r2.body })

// Wait any — first response wins, cancel rest
let first = any(wait(h1, h2))         // first-completing error-capable response

// All — wait all, fail-fast on first error (cancel rest)
let (r1, r2) = all(h1, h2)            // both succeed or first error
guard let r1 else { return 502 }
guard let r2 else { return 502 }
```

`wait` also accepts a Duration — compiler generates `IORING_OP_TIMEOUT`:

```swift
// Sleep — pause handler for a duration
wait(2s)

// Timeout — race I/O against deadline, cancel loser
let h = submit get http://slow-service/data
// first to complete wins
guard let result = any(wait(h, 5s)) else { return 504, "timeout" }

// Custom timeout on any I/O (alternative to per-call timeout: parameter)
let h1 = submit forward(userService, buffered: true)
guard let resp = any(wait(h1, 30s)) else { return 504 }
return resp
```

Compiler optimizations:
- Multiple `submit` → batched into single `io_uring_enter` syscall
- `wait(h1,h2,h3)` → single yield point, not three
- `wait(Duration)` → `IORING_OP_TIMEOUT`, single timerfd
- `any(...)` → cancel pending SQEs/timers on first CQE
- `all(...)` → cancel remaining on first failure

For dynamic-length fan-out, use `for` + `submit`:
```swift
for host in healthCheckHosts {
    submit get http://\(host)/health
}
```

#### 3.4.23 Timers

Background periodic tasks. Top-level declaration alongside `listen`, `upstream`, `route`.

```swift
// Health check — runs on shard 0 only, broadcasts results
timer checkHealth, every: 5s, shard: 0 {
    for server in userService.servers {
        let res = get http://\(server)/health
        guard let res else {
            userService.mark(server, healthy: false)
            continue
        }
        if res.status != 200 {
            userService.mark(server, healthy: false)
        }
    }
}

// Per-shard cleanup — runs on every shard independently
timer cleanExpired, every: 1m {
    sessions.evictExpired()
}

// Metrics push
timer pushMetrics, every: 60s, shard: 0 {
    fire post http://metrics-collector/push {
        Body: json(metrics())
    }
}
```

Parameters:
- `every:` (required) — interval as Duration
- `shard: N` (optional) — run on specific shard only; default is every shard

Timer body can use I/O (`get http://`, `fire`, `submit`/`wait`). The compiler
generates a state machine per timer, scheduled by the shard's event loop.

#### 3.4.24 Lifecycle Hooks

`init` runs once per shard at startup, **before** accepting connections.
`shutdown` runs once per shard on graceful shutdown, **after** all connections drain.
Both can use I/O.

```swift
init {
    let resp = get http://config-service/warmup
    guard let resp else {
        log.error("warmup failed")
        return
    }
    userCache.set("config", resp.body)
    log.info("shard ready")
}

shutdown {
    fire post http://metrics-collector/flush {
        Body: json(metrics())
    }
    log.info("shard stopped")
}
```

Execution order:
```
process start
  → shard threads created
  → each shard: init block runs (blocking, sequential)
  → each shard: start accepting connections
  → ... serve requests ...
  → SIGTERM received
  → each shard: stop accepting new connections
  → each shard: drain in-flight requests
  → each shard: shutdown block runs
  → process exit
```

#### 3.4.25 Distributed Tracing

Automatic runtime behavior — the compiler instruments every `forward`, `submit`,
`get http://` call. Users write zero tracing code.

**How it works:**

1. Request arrives → runtime parses `traceparent` / `tracestate` headers (W3C).
   If absent, generates new trace ID.
2. Creates a span for the handler (records start time, route pattern, method).
3. On `forward` / `submit` / `get http://` → injects `traceparent` into upstream
   request headers, creates child span.
4. On response → records status code, duration, closes span.
5. Span exported asynchronously (fire-and-forget) to collector. Per-shard ring
   buffer batches spans before export. Zero hot-path impact.

**Configuration (in defaults):**

```swift
defaults {
    tracing: .otlp(endpoint: "http://collector:4318")
    // or .zipkin(endpoint: "http://zipkin:9411")
    // or .off (default)
}
```

**Concurrent I/O — automatic child spans:**

```swift
let h1 = submit get http://user-service/users/1      // child span: "GET user-service"
let h2 = submit get http://order-service/orders       // child span: "GET order-service"
let (r1, r2) = wait(h1, h2)
// both child spans auto-closed with independent durations
```

**Optional: custom span attributes**

Most handlers need nothing. If custom attributes are needed:

```swift
get /users/:id {
    auth(req, role: "user")
    req.span.set("userId", req.ctx.userId)    // add attribute to current span
    return forward(userService)
}
```

`req.span` is the current request's span, with a single method: `.set(key, value)`.

### 3.5 Built-in Capabilities

Everything a gateway needs, with zero external dependencies:

```swift
// --- I/O ---
get/post/put/delete url { }   // HTTP calls to external services
fire post url { }             // fire-and-forget HTTP (traffic mirroring, async logging)
forward(upstream)                // forward to upstream (zero-copy when returned)
forward(upstream, streaming:)   // streaming proxy (large body, no buffering)
websocket(upstream)           // WebSocket transparent proxy
read(root:, fallback:)        // file/pipe I/O: zero-copy (return) or buffered (let)
tcp(addr) -> TcpConn          // TCP connection (Redis, custom protocols)
udp() -> UdpSock              // UDP socket (StatsD, syslog, DNS)

// --- State (per-shard by default, all bounded) ---
Cache<K, i64>(capacity:)      // lossy per-key state slots (§3.3.6)
LRU<K,V>(capacity:, ttl:)     // key-value with LRU eviction
Set<T>(capacity:)              // membership testing (CIDR → auto LPM trie)
// Counter<K> is deleted — rate limiting is Rut code over Cache (§3.3.6)
Bloom<T>(capacity:, errorRate:) // probabilistic set, memory-efficient
Bitmap(size:)                  // fixed-size bit array

// --- Traffic Control ---
// Response caching: runtime auto (RFC 7234) + LRU state type for custom logic
upstream { breaker: ... }     // circuit breaker (consecutive failures → open → half-open → closed)
upstream { retry: ... }       // retry policy (on specific status codes, with backoff)

// --- Request ---
req.query("key")              // string? — first value of a query parameter
req.queryAll("key")           // [string] — all values of a query parameter
req.queryString               // raw query string
req.cookie("name")            // cookie access

// --- String (runtime C++ built-in functions, not keywords) ---
s.len                             // i32
s.isEmpty                        // bool
s.hasPrefix(prefix)               // bool
s.hasSuffix(suffix)               // bool
s.contains(sub)                   // bool
s.upper()                         // string
s.lower()                         // string
s.trim()                          // string
s.trimPrefix(prefix)              // string
s.trimSuffix(suffix)              // string
s.replace(old, new)               // string
s.split(sep)                      // [string]
s.slice(start, end)               // string
s.matches(re"pattern")            // bool (Vectorscan)
s.match(re"pattern")              // error-capable match object (capture groups)

// --- Type Conversion / Parse ---
42 as string                      // string (infallible conversion)
IP.parse("10.0.0.1")              // typed parse
parseInt("42")                    // typed parse

// --- JSON ---
req.body(Type)                    // typed body parse, error-capable
json(value)                       // serialize to JSON string
resp.body                         // response body string

// --- Regex (Vectorscan) ---
re"pattern"                       // compile-time validated regex literal
s.matches(re"pat")                // bool
s.match(re"(group)")              // match object on success
s.replace(re"pat", replacement)   // string

// --- Hash ---
md5(data)                     // string (hex)
sha1(data)                    // string (hex)
sha256(data)                  // string (hex)
sha384(data)                  // string (hex)
sha512(data)                  // string (hex)
fnv32(data)                   // u32 (non-crypto, for load balancing)
fnv64(data)                   // u64 (non-crypto, for hashing/sharding)

// --- HMAC ---
hmacSha256(key, data)         // string (hex)
hmacSha384(key, data)         // string (hex)
hmacSha512(key, data)         // string (hex)

// --- JWT (multi-algorithm, backed by BoringSSL) ---
jwtDecode(token, secret: key)               // error-capable Claims decode — HS256/384/512
jwtDecode(token, publicKey: pem)            // error-capable Claims decode — RS256/384/512, ES256/384/512
jwtEncode(claims, secret: key, alg: .HS256) // string — sign with HMAC
jwtEncode(claims, privateKey: pem, alg: .RS256)  // string — sign with RSA/ECDSA

// --- Encryption ---
aesGcmEncrypt(key, plaintext, nonce)        // [u8] — AES-256-GCM authenticated encryption
aesGcmDecrypt(key, ciphertext)              // error-capable decrypt + verify tag

// --- Random ---
randomBytes(n)                // [u8] — cryptographically secure random
uuid()                        // string — UUID v4

// --- Encoding / Decoding ---
base64(data)                  // string
base64url(data)               // string
hex(data)                     // string
urlEncode(data)               // string
urlDecode(data)               // error-capable decode
htmlDecode(data)              // string — &#x3C; → <, &amp; → &, etc.
unicodeNormalize(data)        // string — \u003C → <, NFC normalization

// --- Request Body ---
req.body(Type)                // typed parse, error-capable
req.bodyRaw                   // raw body, error-capable (auto-decompresses)
req.bodyJson()                // dynamic JSON, error-capable
req.multipart()               // multipart/form-data, error-capable

// Json — dynamic JSON access (no struct required)
guard let j = req.bodyJson() else { return 400 }
j.field("name")              // Json? — nested access
j.string()                   // error-capable extract as string
j.int()                      // error-capable extract as number
j.array()                    // error-capable extract as array
j.allValues()                // [string] — all leaf values (for WAF scanning)
j.allKeys()                  // [string] — all keys

// Part — multipart form part
// part.name                  // string — field name
// part.filename              // string? — uploaded file name
// part.contentType            // MediaType? — part content type
// part.body                   // string — part body

// --- Time ---
now()                         // current Time
time(string)                  // parse time string
Duration arithmetic           // now() - req.ifModifiedSince > 1h

// --- Utility ---
env(key)                      // environment variable (compile-time resolved)
log.info(msg, key: val)       // structured logging (named parameters)
log.warn(msg, key: val)
log.error(msg, key: val)
json(value)                   // serialize to JSON string

// --- Admin Introspection (runtime built-in functions) ---
upstream_status()             // string (JSON) — all upstreams: targets, health, connections
config_dump()                 // string (JSON) — current compiled config: routes, middleware, TLS
shard_stats()                 // string (JSON) — per-shard: requests, connections, memory, latency
stats()                       // Stats — request/connection counters, json()-serializable
metrics()                     // Metrics — metrics snapshot for push/export, json()-serializable
reload()                      // trigger config hot reload (same as SIGHUP / admin endpoint)

// --- Numeric ---
i8, i16, i32, i64             // signed integers, wrapping overflow
u8, u16, u32, u64             // unsigned integers, wrapping overflow
f32, f64                      // floating point
// Bit operations — built-in `bitwise` namespace (symbols reserved; | is the pipeline):
bitwise.and(a, b)             // a & b
bitwise.or(a, b)              // a | b
bitwise.xor(a, b)             // a ^ b
bitwise.flip(a)               // ~a
bitwise.shiftLeft(a, n)       // a << n
bitwise.shiftRight(a, n)      // a >> n
```

### 3.6 Compile-Time Checks

| Check | Example | Error |
|-------|---------|-------|
| Route conflict | `get /users/:id` + `get /users/:name` | "conflicting route patterns" |
| Route param | `get /users/:id { ... req.params.name ... }` | "route has no param :name (declared: :id)" |
| Flat capture access | `req.id` for route param `:id` | "route captures live in req.params; use req.params.id" |
| Param type | `get /users/:id(i64)` with non-numeric path | returns 404 at runtime; type-checked at use site |
| Type error | `User(id: 123)` | "id expects string, got i32" |
| Domain value | `listen :70000` | "port range 1-65535" |
| Duration unit | `timeout: 30x` | "unknown Duration unit" |
| StatusCode range | `return 999` | "invalid status code" |
| Unreachable route | `_ { 404 }` then `get /after` | "unreachable route after catch-all" |
| Header type | `req.contentLength = "abc"` | "contentLength is ByteSize, not string" |
| MediaType | `req.contentType == text/lol` | "unknown media type" |
| CIDR format | `req.remoteAddr.in(999.0.0.0/8)` | "invalid IP in CIDR" |
| Header spell | `req.athorization` | "warning: did you mean authorization?" |
| Indirect call | `let f = auth; f(req)` | "functions cannot be assigned to variables" |
| guard exhaustive | `guard expr else { ... }` with non-terminating or missing `else` | "guard must have else clause" |
| Optional access | `req.authorization.hasPrefix("B")` | "value may be nil, use if let, guard let, or .or(default)" |
| Optional chaining | `req.accept?.subtype` | "?. is not supported; use if let / guard let" |
| Null coalescing | `a ?? b` | "?? is not supported; use a.or(b)" |
| Force unwrap | `x!` | "postfix ! is not supported; use if let / guard let" |
| Bitwise symbol | `a & b`, `a ^ b`, `~a`, `a << 2` | "bitwise operators are functions in the bitwise namespace; use bitwise.and(a, b) / bitwise.xor(a, b) / bitwise.flip(a) / bitwise.shiftLeft(a, 2)" |
| Pipeline without placeholder | `x \| f(y)` | "right side of \| must be a call with a _ placeholder; write f(y, _) — or f(_, y) — to show where the value lands" |
| Truthiness guard | `guard claims else { ... }` | "guard condition must be bool; to bind a value use `guard let claims = ... else`" |
| Status return in middleware | `return 401` inside a middleware func | "middleware short-circuits with `respond 401`; `return` is only for the function's value" |
| respond in handler | `respond 200` inside a route handler | "a handler's return value is its response; use `return 200`" |
| Response middleware | `func f(_ resp: Response)` applied where only pre-middleware expected | "signature contains Response — this is a post-middleware, will run after handler" (info) |
| TLS without host | `tls "x.com"` but no `x.com { }` in route | warning: "TLS cert declared but no routes for x.com" |
| Host without TLS | `x.com { }` in route but no `tls "x.com"` and listen uses TLS | "no TLS certificate for host x.com" |
| Duplicate TLS | two `tls "x.com"` declarations | "duplicate TLS declaration for x.com" |
| Host pattern | `x.y.z { }` in route with invalid domain chars | "invalid host pattern" |
| Error-capable value ignored | `let x = req.body(User)` and later code assumes a usable value without fallback/guard | "expression may fail; use guard let, if let, match, or a value fallback such as .or(default)" |
| Regex syntax | `re"[unclosed"` | "invalid regex: unclosed bracket" |
| Regex capture | `m[3]` but pattern has 2 groups | "regex has 2 capture groups, index 3 out of range" |
| Recursion | `func foo() { foo() }` | "recursive call detected: foo → foo" |
| While loop | `while cond { }` | "while loops not supported, use for...in" |
| Consistent cost | `Cache<IP, i64>(..., consistent: true)` | warning: "cross-shard round-trip on every op, suppress with // rut:allow(consistent)" |
| Consistent read-only | `Set<IP>(..., consistent: true)` with only `.contains()` | warning: "reads are local, consistent only affects writes, use notify all for rare writes" |
| Broadcast in handler | `notify` inside a route handler | warning: "executes on every request, did you mean to put this in an admin endpoint?" |
| Post-middleware + zero-copy | `@addSecurityHeaders *` bound to `=> forward(x)` | warning: "post-middleware forces buffered mode, zero-copy disabled" |
| State key type | `Cache<Order, i64>` | "Cache key must be scalar type" |
| State no capacity | `Cache<IP, i64>()` | "capacity is required" |
| Persist layout change | hot reload + struct field changed | "persistent state 'sessions': layout changed" |

### 3.7 Async Transparency

The language has no `async`, `await`, `future`, or `promise` keywords. User writes sequential code. The compiler identifies I/O operations (HTTP calls, forward) and automatically generates state machines.

```swift
// User writes:
func auth(_ req: Request, role: string) -> User {
    let token = req.authorization.or("")
    guard !token.isEmpty else { respond 401 }
    let res = get http://auth/verify {     // compiler knows: I/O point
        Authorization: token
    }
    guard let res else { respond 502 }     // error-capable response
    guard res.status == 200 else { respond 401 }
    guard let user = res.body(User) else { respond 401 }   // error-capable body parse
    guard user.role == role else { respond 403 }
    req.set("X-User-ID", user.id)
    return user
}

// Compiler generates (after inlining into route handler):
//
//   void handle_get_users(Connection* c) {
//       switch (c->state) {
//       case 0:
//           if (!get_header(c, "Authorization")) { send(c, 401); return; }
//           prep_http_get(c, "http://auth/verify", ...);
//           c->state = 1;
//           return;  // back to event loop, zero stack usage
//       case 1:
//           if (c->upstream_resp.status != 200) { send(c, 401); return; }
//           // ... inline the rest ...
//       }
//   }
```

### 3.8 Swift Syntax Features Used

The rule is **Swift-exact or absent**: every construct below keeps Swift's exact
semantics. Anything that would look like Swift but behave differently was
removed from the language instead of documented as a variation.

| Feature | Example | Why |
|---------|---------|-----|
| `guard let ... else` | `guard let claims = jwtDecode(token, secret: key) else { respond 401 }` | Middleware "reject or continue"; Swift-identical, incl. the `guard let x else` shorthand |
| `if let` | `if let cached = cache.get(key) { return 200, cached }` | Swift-identical optional binding |
| Boolean operators | `a && b`, `a \|\| b`, `!a` | Identical to Swift — no `and`/`or`/`not` near-miss |
| `break` / `continue` | loop control inside `for ... in` | Swift-identical; only shortens iteration, bound preserved |
| Named parameters | `auth(req, role: "user")` | Self-documenting calls, LLMs generate correct argument order |
| `_` unlabeled param | `func auth(_ req: Request, role: string)` | First param (always req) doesn't need label |
| Named fallback | `req.authorization.or("")` | Core optional fallback surface; `??` / `?.` / postfix `!` remain reserved (rejected with fix-its) |
| `let` / `var` | `let x = ...` (immutable), `var x = ...` (mutable) | `var` only inside func/handler, not at top level |
| String interpolation | `"\(req.method)\n\(req.path)"` | Cleaner than concatenation |
| `.enumCase` | `balance: .leastConn` | Concise enum values |
| Trailing block | `websocket(x) { frame in ... }` | Swift trailing-closure surface; compiled to a state machine, not a closure |
| No commas in blocks | Multi-line blocks don't need commas | Cleaner, less noise |

### 3.9 Complete Example

```swift
// production.rut

import { cors, securityHeaders, ipAllow, waf } from "stdlib/security.rut"
import { requestId } from "stdlib/request.rut"

// ---------- Infrastructure ----------

listen :443
listen :80
listen :9090

tls "api.example.com",   cert: env("API_CERT"),   key: env("API_KEY")
tls "admin.example.com", cert: env("ADMIN_CERT"),  key: env("ADMIN_KEY")
tls default,             cert: env("DEFAULT_CERT"), key: env("DEFAULT_KEY"), ocsp: true

defaults {
    clientMaxBodySize: 10mb
    compress: .auto(types: [text/html, application/json], minSize: 256b)
    errorPages: "/var/www/errors/"
    tracing: .otlp(endpoint: "http://collector:4318")
    cache: .auto(capacity: 10000, maxSize: 10mb)
}

// ---------- Upstreams ----------

let userService = upstream {
    "10.0.0.1:8080", weight: 3
    "10.0.0.2:8080"
    balance: .ewma
    health: .active(get: "/ping", every: 5s)
    health: .passive(failures: 5, recover: 30s)
    breaker: .consecutive(failures: 5, recover: 30s)
    retry: .on([502, 503], count: 2, backoff: 100ms)
    slowStart: 30s
}

let orderService = upstream { "10.0.1.1:8080" }
let storageService = upstream { "10.0.2.1:9000" }
let chatService = upstream { "10.0.3.1:8080" }

// ---------- Types ----------

struct Ctx {
    userId: string
    userRole: string
}

struct User {
    id: string
    role: string
}

struct Order {
    items: [OrderItem]
}

struct OrderItem {
    sku: string
    qty: i32
    price: f64
}

// ---------- State ----------

let blacklist = Set<IP>(capacity: 100000)
let userCache = LRU<string, string>(capacity: 10000, ttl: 5m, coalesce: true)

// ---------- Middleware ----------

func auth(_ req: Request, role: string) {
    let token = req.authorization.or("")
    guard !token.isEmpty else { respond 401 }
    guard token.hasPrefix("Bearer ") else { respond 401 }

    let claims = jwtDecode(token.trimPrefix("Bearer "), secret: env("JWT_SECRET"))
    guard let claims else { respond 401 }
    guard claims.exp >= now() else { respond 401, "token expired" }
    guard claims.role == role else { respond 403 }

    req.ctx.userId = claims.sub
    req.ctx.userRole = claims.role
}

func addSecHeaders(_ resp: Response) {
    resp.set("Strict-Transport-Security", "max-age=31536000")
    resp.set("X-Content-Type-Options", "nosniff")
    resp.remove("Server")
}

// ---------- Timers ----------

timer checkHealth, every: 10s, shard: 0 {
    for server in userService.servers {
        let res = get http://\(server.addr)/ping
        guard let res else {
            userService.mark(server, healthy: false)
            continue
        }
        if res.status != 200 {
            userService.mark(server, healthy: false)
        }
    }
}

// ---------- Routes ----------

// Shipped official-decorator form: directly before one top-level route.
@rateLimit(limit: 1000, window: 1m)
route GET "/limited" { return 200 }

// ⏳ Proposed route-block middleware binding syntax. The shipped parser accepts
// official decorators such as @rateLimit only directly before one route.
route {
    // Middleware bindings
    @requestId *
    @waf *
    @addSecHeaders *

    @if(env("ENABLE_CORS") == "true")
    @cors *

    @auth(role: "user") api.example.com
    @ipAllow(cidrs: [10.0.0.0/8, 172.16.0.0/12]) admin.example.com
    @auth(role: "admin") admin.example.com

    // --- Health ---
    get /health => 200

    // --- API domain ---
    @priority(.high)
    api.example.com {
        get /users/:id(i64) {
            guard !blacklist.contains(req.remoteAddr) else { return 403 }

            if let cached = userCache.get("/users/\(req.params.id)") {
                return 200, cached
            }

            let resp = forward(userService, buffered: true)
            resp.set("X-Request-ID", req.header("X-Request-ID").or(""))
            resp.remove("X-Powered-By")
            userCache.set("/users/\(req.params.id)", resp.body)
            return resp
        }

        post /orders {
            guard let order = req.body(Order) else { return 400 }
            for item in order.items {
                guard item.qty > 0 else { return 400, "invalid quantity" }
            }
            return forward(orderService)
        }

        post /files/upload {
            guard req.contentLength <= 100mb else { return 413 }
            return forward(storageService, streaming: true)
        }

        get /files/:fileId => forward(storageService, streaming: true)

        get /ws/chat {
            guard req.upgrade == .websocket else { return 400 }
            return websocket(chatService)
        }
    }

    // --- Admin domain ---
    admin.example.com {
        get /stats => 200, json(stats())
        post /reload {
            reload()
            return 200
        }
        post /ban {
            guard let ip = req.body(IP) else { return 400 }
            blacklist.add(ip)
            notify all blacklist.add(ip)
            return 200
        }
    }

    // --- Static files ---
    /static {
        get /*path => read(root: "/var/www/static", maxAge: 30d)
    }

    // --- Catch-all ---
    _ => 444
}
```

---

### 3.10 OpenResty/Kong/APISIX Feature Coverage

Evaluation of how our DSL covers features from the OpenResty ecosystem (Kong, APISIX, and common Lua patterns).

#### Fully Covered (built-in)

| Feature Category | DSL Capability |
|-----------------|----------------|
| JWT auth | `jwtDecode()` built-in |
| HMAC auth | `hmacSha256()` built-in |
| Basic auth | `base64` decode + string compare |
| API key auth | header/query access + compare |
| Forward auth | native HTTP calls to auth service |
| IP restriction | `req.remoteAddr.in(CIDR)` native |
| UA restriction | `req.userAgent.contains()` |
| CORS | `guard` + header assignment |
| Rate limiting | `@rateLimit` or Rut GCRA over `Cache<K, i64>` (`examples/ratelimit.rut`) |
| Request size limiting | `req.contentLength` comparison |
| Request ID / Correlation ID | `uuid()` built-in |
| Header add/remove/modify | `req.Header = val` / `= nil` |
| URL rewriting | `req.path` assignment |
| Response header rewrite | `let resp = forward(x, buffered: true); resp.Header = val` |
| Response body rewrite | `let resp = forward(x, buffered: true); resp.body = ...` |
| Request termination (maintenance) | `return 503` |
| Canary release / A/B testing | conditional routing + `fnv32` hash |
| Blue-green deployment | `env()` + conditional proxy |
| Traffic mirroring | `fire` keyword (fire-and-forget HTTP) |
| Circuit breaker | `upstream { breaker: ... }` |
| Retry with backoff | `upstream { retry: ... }` |
| Response caching | runtime auto (RFC 7234) + `LRU` state type for custom logic |
| Stale-while-revalidate | runtime auto (Cache-Control headers) |
| Cache purge | `LRU.delete(key)` or runtime API |
| Streaming proxy | `forward(upstream, streaming: true)` |
| WebSocket proxy | `websocket(upstream)` |
| Access logging | automatic — runtime always logs every request |
| Prometheus metrics | `metrics()` built-in |
| Distributed tracing | auto-instrumentation + `X-Debug` |
| Health checks | `upstream { health: ... }` |
| Dynamic log level | `/internal/log-level` endpoint |
| Structured logging | `log.info/warn/error()` |
| Hot reload | JIT recompile + atomic swap |

#### Covered via HTTP Calls (no special syntax needed)

| Feature | Approach |
|---------|----------|
| OAuth2 / OIDC | HTTP calls to Keycloak/Auth0/Okta |
| LDAP auth | HTTP call to LDAP-HTTP bridge |
| OPA authorization | HTTP call to OPA endpoint |
| Token introspection | HTTP call to OAuth2 introspection endpoint |
| External logging (Kafka, Splunk, etc.) | `fire` to HTTP log collector |
| Webhook delivery | `fire post` to webhook URLs |
| Feature flags | HTTP call to flag service |

#### Phase 2+ (needs HTTP/2 or protocol support)

| Feature | Requirement |
|---------|------------|
| gRPC proxy | HTTP/2 support |
| gRPC-REST transcoding | HTTP/2 + protobuf definitions |
| gRPC-Web | HTTP/2 + gRPC-Web protocol |
| HTTP/2 upstream | HTTP/2 client implementation |
| mTLS (client certs) | OpenSSL client cert validation |
| Dynamic SSL / ACME | ACME protocol + cert management |

#### Out of Scope

| Feature | Reason |
|---------|--------|
| L4 TCP/UDP proxy | This is an L7 HTTP gateway |
| MQTT/Dubbo/Redis protocol proxy | Custom protocol handling |
| Developer portal | Admin UI, separate project |
| Database-backed config | etcd/Postgres, separate concern |
| Multi-language plugin SDK | We have one language + extern FFI |

---

## 4. Runtime Architecture

### 4.1 Shard Model (Share-Nothing)

Each shard is a single OS thread pinned to a single CPU core. Shards do not share mutable state. There are no locks, mutexes, or condition variables anywhere in the hot path.

```
Shard (1 per core):
  ├── 1 OS thread, pinned via sched_setaffinity / pthread_setaffinity_np
  ├── 1 I/O backend (io_uring or epoll, selected at startup)
  ├── 1 listen socket (via SO_REUSEPORT, kernel distributes connections)
  ├── 1 set of connection slots
  ├── 1 upstream connection pool (per upstream target)
  ├── 1 route table pointer (atomically swappable)
  ├── 1 timer wheel
  └── 1 memory region (Arena + Slab + Slice pool)
```

Resource estimation (8 cores, C100K):

| Resource | Per Shard | Total (8 shards) |
|----------|-----------|-------------------|
| Connection metadata | 12,500 x 48B = 600 KB | 4.8 MB |
| SQ ring (16,384 entries) | 1 MB | 8 MB |
| CQ ring (32,768 entries) | 2 MB | 16 MB |
| Provided buffer ring (2,048 x 4KB) | 8 MB | 64 MB |
| Slice pool (1,024 x 16KB) | 16 MB | 128 MB |
| Scratch arena | 64 KB | 512 KB |
| **Total** | **~28 MB** | **~224 MB** |

### 4.2 Accept Distribution

Using `SO_REUSEPORT`: each shard binds and listens on the same port. The kernel distributes incoming connections across shards. Combined with `IORING_ACCEPT_MULTISHOT`, one SQE continuously accepts new connections.

```
┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
│shard0│  │shard1│  │shard2│  │shard3│
│listen│  │listen│  │listen│  │listen│
│:443  │  │:443  │  │:443  │  │:443  │
└──────┘  └──────┘  └──────┘  └──────┘
      ▲       ▲       ▲       ▲
      └───────┴───────┴───────┘
            kernel distributes
            (SO_REUSEPORT)
```

No cross-shard connection migration. A connection accepted on shard N stays on shard N for its entire lifetime.

### 4.3 Handler Crash Isolation

Handler code is JIT-compiled from user-written .rut — it is untrusted code running
inside the shard's event loop. A handler crash (division by zero, array out of bounds,
null dereference) **must never take down the shard**.

**Compile-time prevention:**

The compiler eliminates most crash sources:
- Division by zero → compiler inserts check before every `/`, returns 500 if divisor is 0
- Array out of bounds → compiler inserts bounds check on every `[]` access
- Null/nil access → use `?`, `.or(default)`, `guard let`, or `match`
- Infinite loops → no `while`, no recursion, `for` only on finite collections
- Stack overflow → all functions inline, no call stack depth

**Runtime safety net:**

For any crash the compiler cannot prevent (bug in codegen, hardware fault):
- JIT handler runs inside a signal handler boundary (`SIGSEGV`, `SIGFPE`)
- On signal: runtime catches it, returns 500 to client, logs the crash
- Per-request Arena is reset — no memory leak
- Connection is closed and removed from timer wheel
- Shard event loop continues processing other connections
- No shard restart, no process restart

**State mutation on crash:**

State operations (Cache.set, Set.add) executed before the crash are
**not rolled back**. This is by design:
- A packed GCRA successor already written to Cache may throttle conservatively
  until wall time catches up; it does not rely on a deleted Counter or Cache TTL
- Any other Cache value remains until overwritten or evicted, which is why Cache
  is restricted to algorithms where a miss/eviction is a safe reset
- An idempotent Set.add (for example, an administrator-requested blacklist fact)
  remains applied; callers must not use it as an intermediate transaction step
- Session-like state is never valid in lossy Cache and awaits the future strict
  table, so the runtime promises no rollback semantics for that unsupported form

Transactional rollback would require write-ahead logging on every state operation —
unacceptable overhead on the hot path. State operations are best-effort, idempotent
by convention.

### 4.4 Client Disconnect Cancellation

When the runtime detects the client has disconnected (socket closed, reset, timeout):

1. Cancel all pending I/O for that connection (`IORING_OP_ASYNC_CANCEL` / `epoll_ctl DEL`)
2. Cancel pending upstream requests (close upstream connection or return to pool)
3. Execute `defer` statements (cleanup counters, logging)
4. Reset per-request Arena
5. Remove connection from timer wheel

The handler does not run to completion — all in-flight I/O is cancelled immediately.
This prevents wasting upstream resources on responses nobody will read.

The compiler generates cancellation points at every `yield` (forward, submit, wait).
When the runtime detects disconnect, it resumes the handler's state machine with a
cancellation error, triggering the `defer` chain and cleanup.

### 4.5 Runtime Event Primitives

Two Linux fd-based event mechanisms are used internally by the runtime. Both
available since Linux 2.6.22 — well below Rutlang's minimum kernel requirement
(epoll: 3.9+, io_uring: 6.0+). Not exposed to Rutlang user code.

**signalfd — OS signal handling**

Converts Unix signals into readable fd events. The runtime creates one signalfd
per process, monitored by shard 0's event loop.

```
SIGTERM → signalfd readable → shard 0 initiates graceful shutdown
          → notify all shards to drain connections
          → wait for in-flight requests to complete
          → exit

SIGHUP  → signalfd readable → shard 0 triggers hot reload
          → recompile .rut (or load new .so in sidecar mode)
          → RCU swap compiled config on all shards
```

No signal handler functions (`sigaction`), no async-signal-safety concerns —
signals are processed synchronously in the event loop like any other I/O event.

**eventfd — cross-shard wakeup**

Each shard pair has a SPSC ring buffer for `notify` messages. The eventfd wakes
the receiving shard's event loop when a message is enqueued.

```
Shard 0                              Shard 1
  │                                    │
  ├─ enqueue msg to SPSC[0→1]         │
  ├─ write(eventfd_01, 1)             │  ← eventfd wakes shard 1
  │                                    ├─ io_uring/epoll sees eventfd readable
  │                                    ├─ drain SPSC[0→1]
  │                                    ├─ execute: blacklist.add(ip)
  │                                    ├─ read(eventfd_01) to reset
```

Without eventfd, the receiving shard would only see the message on its next
event loop tick (up to ~1ms latency). With eventfd, wakeup is immediate
(~1μs — kernel schedules the target thread).

One eventfd per shard pair: N shards = N×(N-1) eventfds. For 8 shards = 56 fds.
Negligible resource cost.

### 4.6 I/O Backend Abstraction

The runtime supports two I/O backends behind a compile-time interface (no virtual dispatch):

```cpp
// Compile-time backend selection via template or build flag
// No virtual functions, no runtime overhead

struct IoEvent {
    u32 conn_id;
    u8  type;     // ACCEPT, RECV, SEND, UPSTREAM_CONNECT, UPSTREAM_RECV, TIMEOUT
    i32 result;   // bytes transferred or error code
    u16 buf_id;   // provided buffer id (io_uring only, 0 for epoll)
};

// Backend interface (satisfied by both IoUringBackend and EpollBackend):
//   void init(u32 shard_id);
//   void add_accept(int listen_fd);
//   void add_recv(int fd, u32 conn_id, void* buf, u32 len);
//   void add_send(int fd, u32 conn_id, const void* buf, u32 len);
//   void add_connect(int fd, u32 conn_id, sockaddr* addr);
//   void cancel(int fd, u32 conn_id);
//   u32  wait(IoEvent* events, u32 max_events);  // returns event count
```

#### io_uring Backend (Linux 6.0+, preferred)

```
Characteristics:
  - Completion-based: "I/O is already done when you get the event"
  - One syscall (io_uring_enter) for submit + wait
  - multishot accept: one SQE continuously accepts
  - multishot recv + provided buffer ring: idle connections hold no buffer
  - send_zc: zero-copy send
  - Kernel-side SQ polling (SQPOLL): can reduce to zero syscalls
```

#### epoll Backend (Linux 3.9+, fallback)

```
Characteristics:
  - Readiness-based: "fd is ready, now you do the I/O"
  - Two syscalls per I/O: epoll_wait + recv/send
  - No multishot: must re-arm after each event (EPOLLONESHOT)
    or use level-triggered (default)
  - No provided buffer ring: must pre-assign buffer per connection
    or allocate on readiness notification
  - SO_REUSEPORT still works for accept distribution
```

#### Differences That Affect Upper Layers

```
                        io_uring              epoll
────────────────────────────────────────────────────────────
Event semantics         completion            readiness
Syscalls per I/O        1 (batched)           2 (epoll_wait + read/write)
Idle conn buffer        0 (provided buf ring) must allocate on EPOLLIN
Accept                  multishot (1 SQE)     epoll_wait + accept() loop
recv                    multishot + buf select epoll_wait + recv()
send                    submit + completion   write() + handle EAGAIN
Backpressure            cancel recv SQE       EPOLL_CTL_DEL / stop arming

Upper layers see IoEvent in both cases — the difference is hidden.
```

### 4.4 Event Loop

```cpp
// Generic event loop — works with both backends
// BACKEND is IoUringBackend or EpollBackend (compile-time)

template<typename BACKEND>
void shard_main(int shard_id) {
    BACKEND backend;
    backend.init(shard_id);
    backend.add_accept(listen_fd);

    IoEvent events[256];

    for (;;) {
        u32 n = backend.wait(events, 256);

        for (u32 i = 0; i < n; i++) {
            switch (events[i].type) {
            case ACCEPT:
                handle_new_connection(events[i].result);
                break;
            case RECV:
                handle_recv(events[i].conn_id, events[i]);
                break;
            case SEND:
                handle_send_complete(events[i].conn_id, events[i]);
                break;
            case UPSTREAM_CONNECT:
                handle_upstream_connected(events[i].conn_id, events[i]);
                break;
            case UPSTREAM_RECV:
                handle_upstream_data(events[i].conn_id, events[i]);
                break;
            case TIMEOUT:
                timer_wheel.tick();
                break;
            }
        }
    }
}
```

The event loop code is identical for both backends. All differences are encapsulated inside `BACKEND::wait()` and the `add_*` methods.

### 4.4 Connection Lifecycle

```
State Machine:

  Accept
    │
    ▼
  Idle ◄──────────────────────────────┐  (keep-alive)
    │  multishot recv, no buffer held  │
    │                                  │
    ▼                                  │
  ReadingHeader                        │
    │  provided buffer ring            │
    │  llhttp parse                    │
    ▼                                  │
  ExecHandler                          │
    │  JIT function call               │
    │  scratch arena for temp allocs   │
    ├──► direct response ──► Sending ──┘
    │
    ▼
  Proxying
    │  upstream connect / reuse pool
    │  bidirectional data relay
    │  watermark backpressure
    ▼
  Sending ─────────────────────────────┘
    │  drain send buffer
    │  reset scratch arena
    │  return slices to pool
    ▼
  Idle (or Close)
```

```cpp
struct Connection {
    int      fd;
    u8       state;           // Idle | ReadingHeader | ReadingBody | ExecHandler | Proxying | Sending
    u8       shard_id;
    u16      flags;           // keep_alive, tls, http2, ...
    u32      timer_slot;
    ListNode timer_node;      // intrusive list node for timer wheel
    ListNode idle_node;       // intrusive list node for idle list

    // Only non-null when active
    Slice*   read_slice;
    Slice*   write_slice;

    // Upstream (only when proxying)
    int      upstream_fd;
    u16      upstream_idx;    // index into upstream pool

    // JIT handler state (for async state machine)
    u16      handler_state;
    void*    handler_ctx;     // points into scratch arena
};
// sizeof: 48-64 bytes
```

### 4.6 Idle Connections: C100K Strategy

Most of 100K connections are idle (keep-alive waiting for next request). Idle connections must not hold buffers.

#### io_uring Backend

```
multishot recv + provided buffer ring:

  1. Submit one IORING_OP_RECV with IORING_RECV_MULTISHOT for each connection
  2. Set IOSQE_BUFFER_SELECT flag → kernel picks buffer from provided ring only when data arrives
  3. Idle connections: 1 SQE in kernel, 0 bytes of buffer
  4. Data arrives: kernel grabs a buffer from the ring, fills it, returns CQE
  5. After processing: return buffer to the ring

  Per-shard provided buffer ring:
  // Pre-allocate and register buffer pool
  struct io_uring_buf_ring* buf_ring;
  void* buffers = mmap(NULL, 2048 * 4096, ...);   // 2048 x 4KB = 8MB
  io_uring_register_buf_ring(ring, buf_ring, 2048, BUF_GROUP_ID);

  // Each buffer is 4KB — enough for most HTTP headers
  // If request needs more, allocate from slice pool

  Cost per idle connection: ~0 bytes userspace (1 SQE in kernel)
```

#### epoll Backend

```
epoll does not have provided buffer rings or multishot recv.
Two strategies for idle connections:

Strategy A: allocate on readiness (recommended)
  1. All idle connections registered in epoll (EPOLLIN, level-triggered)
  2. epoll_wait returns ready fds
  3. Only then: grab buffer from slice pool → recv() → parse
  4. After request: return buffer to pool

  Cost per idle connection: 0 bytes buffer (just an epoll entry ~64 bytes in kernel)
  Downside: extra recv() syscall after epoll_wait (vs io_uring where data is already in buffer)

Strategy B: small pre-allocated header buffer
  1. Each connection has a tiny inline buffer (128 bytes) for the first recv
  2. If request header > 128 bytes, spill to slice pool
  3. Covers ~80% of simple GETs without extra allocation

  Cost per idle connection: 128 bytes
  100K × 128 bytes = 12.8 MB — acceptable

  struct Connection {
      // ... other fields ...
      u8 inline_buf[128];    // small inline recv buffer
      Slice* overflow_slice; // nullptr unless header > 128 bytes
  };
```

#### Resource Comparison (8 cores, C100K)

```
                         io_uring          epoll (strategy A)
──────────────────────────────────────────────────────────────
Conn metadata            4.8 MB            4.8 MB
SQ/CQ rings              24 MB             0
epoll fd kernel memory   0                 ~6.4 MB
Provided buffer ring     64 MB             0
Slice pool               128 MB            128 MB
Scratch arena            512 KB            512 KB
──────────────────────────────────────────────────────────────
Total                    ~222 MB           ~140 MB
Syscalls per recv        1 (batched)       2 (epoll_wait + recv)
Zero-copy recv           yes               no
```

---

## 5. Memory Architecture

### 5.1 Design Principles

- No C++ standard library containers (`-nostdlib++`)
- No `malloc`/`free` on the hot path
- All memory pre-allocated at startup via `mmap`
- Per-shard memory isolation (share-nothing)
- Three allocator types for three lifetimes

### 5.2 Compiler and Linker Configuration

```
CXX      = clang++
CXXFLAGS = -std=c++20
           -nostdlib++
           -fno-exceptions
           -fno-rtti
           -fno-unwind-tables
           -fno-asynchronous-unwind-tables
           -ffunction-sections
           -fdata-sections
           -flto

LDFLAGS  = -nostdlib++
           -Wl,--gc-sections
           -static             # static link musl
           -lc                 # libc only (for LLVM)

LLVM_LIBS = -lLLVMOrcJIT -lLLVMX86CodeGen -lLLVMX86AsmParser
            -lLLVMCore -lLLVMSupport
```

Expected binary size: < 500KB without LLVM, ~15-20MB with LLVM statically linked.

### 5.3 Per-Shard Memory Layout

```
┌──────────────────────────────────────────┐
│             Per-Shard Arena              │
│       (single mmap at startup)           │
├──────────┬──────────┬────────────────────┤
│ Provided │ Slab     │ Scratch            │
│ Buffer   │ Pools    │ (per-request)      │
│ Ring     │          │                    │
│ + Slice  │          │                    │
│ Pool     │          │                    │
└──────────┴──────────┴────────────────────┘
```

```cpp
struct PerShardMemory {
    void*  base;
    size_t total_size;

    // 1. io_uring provided buffer ring — for idle connection recv
    //    Kernel auto-selects buffer when data arrives. Zero-copy.
    //    2048 x 4KB = 8MB
    ProvidedBufferRing io_buffers;

    // 2. Slice pool — for active connection read/write buffers
    //    1024 x 16KB = 16MB, free-list recycled
    SlicePool slices;

    // 3. Slab allocators — fixed-size objects
    SlabPool<Connection, 16384>  connections;   // 48-64 bytes each
    SlabPool<UpstreamConn, 4096> upstream_conns;

    // 4. Scratch arena — per-request temporary memory
    //    Reset to zero after each request (one pointer reset)
    Arena scratch;  // 64KB
};
```

### 5.4 Arena Allocator (Per-Request Temporaries)

```cpp
struct Arena {
    u8* base;
    u8* ptr;
    u8* end;

    void* alloc(u32 size) {
        size = (size + 7) & ~7;  // 8-byte align
        void* p = ptr;
        ptr += size;
        return p;
    }

    void reset() { ptr = base; }  // one instruction, "frees" everything
};
```

Used for: parsed request headers, route match params, JIT handler temporary variables. Entire request's temp memory freed with a single pointer reset.

### 5.5 Slice Buffer (Network Data Streams)

```
Each Slice:
┌─────────────────────────────────────┐
│  drained  │   data    │  reservable │
└─────────────────────────────────────┘
            ↑           ↑
           start       end

- Fixed 16KB per slice
- Drain: advance start pointer, O(1)
- Append: advance end pointer, O(1)
- When fully drained: return to free list (O(1))
```

```cpp
struct Slice {
    u8  buf[16384];
    u32 start;
    u32 end;

    u32 len()      { return end - start; }
    u8* data()     { return buf + start; }
    u32 writable() { return sizeof(buf) - end; }

    u32 append(const u8* src, u32 n) {
        u32 to_copy = min(n, writable());
        __builtin_memcpy(buf + end, src, to_copy);
        end += to_copy;
        return to_copy;
    }

    void drain(u32 n) { start += n; }
};

struct SliceBuffer {
    Slice* slices[64];     // max 64 slices = 1MB logical buffer
    u32    head, tail;     // ring buffer indices
    Slice* free_list;      // recycling pool

    void append(const u8* src, u32 n);  // write to tail slice(s)
    void drain(u32 n);                  // consume from head slice(s), recycle empty
};
```

Used for: network recv/send data, proxy body relay. Can be registered with io_uring for zero-copy I/O.

### 5.6 Slab Allocator (Fixed-Size Objects)

```cpp
template<typename T, u32 Capacity>
struct SlabPool {
    T      storage[Capacity];
    u32    free_stack[Capacity];
    u32    free_top;

    T* alloc() {
        u32 idx = free_stack[--free_top];
        return &storage[idx];
    }

    void free(T* obj) {
        u32 idx = obj - storage;
        free_stack[free_top++] = idx;
    }
};
```

Used for: Connection objects, upstream connection objects. Constant-time alloc/free, no fragmentation.

### 5.7 Stdlib Replacement Types

```cpp
// Fixed-capacity vector, no heap allocation
template<typename T, u32 Cap>
struct FixedVec {
    T   data[Cap];
    u32 len = 0;

    void push(T val) { data[len++] = val; }
    T&   operator[](u32 i) { return data[i]; }
    T*   begin() { return data; }
    T*   end()   { return data + len; }
};

// Non-owning string view
struct Str {
    const char* ptr;
    u32 len;

    bool eq(Str other) const {
        return len == other.len &&
               __builtin_memcmp(ptr, other.ptr, len) == 0;
    }
};

// Open-addressing flat hash map, inline storage
template<typename K, typename V, u32 Cap>
struct FlatMap {
    struct Slot { K key; V val; u8 state; };  // 0=empty 1=used 2=deleted
    Slot slots[Cap];
};

// Intrusive linked list (for connection lists, timer wheel, LRU)
struct ListNode {
    ListNode* prev;
    ListNode* next;
};
```

### 5.8 Request Lifecycle Memory Flow

```
  I/O backend recv:
    io_uring: multishot recv → provided buffer (4KB, zero-copy from kernel)
    epoll:    EPOLLIN → alloc slice from pool → recv() into slice
       │
       ▼
  llhttp parse headers → Str slices pointing into buffer (zero-copy)
       │
       ▼
  Arena alloc Request struct + header kv array + route params
       │
       ▼
  JIT handler executes (temp allocs from arena)
       │
       ├── Direct response → write to slice buffer → backend send
       │
       └── Proxy → slice buffer relay between downstream/upstream
       │
       ▼
  Request complete:
       arena.reset()                    ← one instruction
       return buffer to pool/ring       ← one pointer write
       return slices to free list       ← linked list ops

  Hot path: zero malloc, zero free
  io_uring: zero extra syscalls (batched in io_uring_enter)
  epoll:    +1 syscall per recv, +1 per send
```

---

## 6. I/O Backend Implementations

### 6.1 Backend Selection

```
Startup detection:

  1. Try io_uring_setup() syscall
     - Success + kernel >= 6.0 → use io_uring backend
     - Fail (ENOSYS) or old kernel → fall back to epoll

  2. Can be overridden via command line:
     --io-backend=io_uring    # force io_uring (fail if unavailable)
     --io-backend=epoll       # force epoll

  3. Selected once at startup, all shards use the same backend
     (binary contains both implementations, compiled via templates)
```

### 6.2 io_uring Backend (Linux 6.0+)

No liburing dependency. Direct syscall wrapper for full control (~300 lines):

```cpp
struct IoUringBackend {
    int            ring_fd;
    io_uring_sqe*  sq_entries;
    io_uring_cqe*  cq_entries;
    u32*           sq_tail;
    u32*           cq_head;
    u32            sq_mask;
    u32            cq_mask;

    void init(u32 shard_id) {
        io_uring_params params = {};
        params.flags = IORING_SETUP_SQPOLL
                     | IORING_SETUP_SINGLE_ISSUER
                     | IORING_SETUP_COOP_TASKRUN;
        ring_fd = syscall(__NR_io_uring_setup, 16384, &params);
        // mmap sq/cq rings...
        // setup provided buffer ring...
    }

    io_uring_sqe* get_sqe() {
        u32 tail = __atomic_load_n(sq_tail, __ATOMIC_RELAXED);
        io_uring_sqe* sqe = &sq_entries[tail & sq_mask];
        __atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);
        return sqe;
    }

    u32 wait(IoEvent* events, u32 max_events) {
        syscall(__NR_io_uring_enter, ring_fd,
                pending_count, 1,
                IORING_ENTER_GETEVENTS, nullptr, 0);
        // harvest CQEs → convert to IoEvent array
    }

    void add_accept(int fd) {
        // IORING_ACCEPT_MULTISHOT — one SQE, continuous accept
    }

    void add_recv(int fd, u32 conn_id, void*, u32) {
        // IORING_RECV_MULTISHOT + IOSQE_BUFFER_SELECT
        // buffer arg ignored, kernel picks from provided ring
    }

    void add_send(int fd, u32 conn_id, const void* buf, u32 len) {
        // IORING_OP_SEND or IORING_OP_SEND_ZC
    }
};
```

io_uring features used:

| Feature | Purpose | Kernel Version |
|---------|---------|----------------|
| `IORING_ACCEPT_MULTISHOT` | One SQE continuously accepts connections | 5.19 |
| `IORING_RECV_MULTISHOT` | One SQE continuously receives data per connection | 6.0 |
| `IOSQE_BUFFER_SELECT` + provided buffer ring | Kernel auto-selects buffer on recv, idle connections hold no buffer | 5.19 / 6.0 |
| `IORING_SETUP_SQPOLL` | Kernel-side SQ polling, reduces syscalls | 5.11 |
| `IORING_SETUP_SINGLE_ISSUER` | Single-thread optimization | 6.0 |
| `IORING_OP_SEND_ZC` | Zero-copy send | 6.0 |
| `IORING_OP_LINK` | Chain multiple ops, single submission | 5.3 |
| `IORING_SETUP_COOP_TASKRUN` | Cooperative task running, fewer interrupts | 6.0 |
| Fixed file registration | Pre-register fds, skip kernel fd lookup | 5.1 |
| Fixed buffer registration | Pre-register buffers, skip DMA mapping | 5.1 |

### 6.3 epoll Backend (Linux 3.9+)

Fallback for older kernels. ~250 lines:

```cpp
struct EpollBackend {
    int epoll_fd;
    int timer_fd;

    void init(u32 shard_id) {
        epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
        // arm timerfd for 1s ticks
    }

    u32 wait(IoEvent* events, u32 max_events) {
        epoll_event ep_events[256];
        int n = epoll_wait(epoll_fd, ep_events, 256, -1);

        u32 out = 0;
        for (int i = 0; i < n; i++) {
            auto [conn_id, type] = decode(ep_events[i].data.u64);

            if (type == LISTEN && (ep_events[i].events & EPOLLIN)) {
                // accept loop (no multishot, must loop)
                for (;;) {
                    int fd = accept4(listen_fd, nullptr, nullptr,
                                     SOCK_NONBLOCK | SOCK_CLOEXEC);
                    if (fd < 0) break;
                    events[out++] = { .conn_id = 0, .type = ACCEPT, .result = fd };
                }
            }
            else if (ep_events[i].events & EPOLLIN) {
                // readiness notification — do the actual recv here
                Connection* c = &conns[conn_id];
                Slice* s = alloc_slice();       // allocate buffer NOW
                int nr = recv(c->fd, s->data(), s->writable(), 0);
                if (nr <= 0) {
                    free_slice(s);
                    events[out++] = { .conn_id = conn_id, .type = RECV, .result = nr };
                } else {
                    s->end = nr;
                    c->read_slice = s;
                    events[out++] = { .conn_id = conn_id, .type = RECV, .result = nr };
                }
            }
            else if (ep_events[i].events & EPOLLOUT) {
                // writable — do the send here
                Connection* c = &conns[conn_id];
                int nw = send(c->fd, c->write_slice->data(), c->write_slice->len(), MSG_NOSIGNAL);
                events[out++] = { .conn_id = conn_id, .type = SEND, .result = nw };
            }
        }
        return out;
    }

    void add_recv(int fd, u32 conn_id, void*, u32) {
        epoll_event ev = { .events = EPOLLIN, .data.u64 = encode(conn_id, CONN) };
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
        // actual recv happens inside wait() when EPOLLIN fires
    }

    void add_send(int fd, u32 conn_id, const void* buf, u32 len) {
        // try immediate send first (common case: socket buffer not full)
        int nw = ::send(fd, buf, len, MSG_NOSIGNAL);
        if (nw == (int)len) {
            // sent everything, queue synthetic completion event
            pending_completions.push({ .conn_id = conn_id, .type = SEND, .result = nw });
            return;
        }
        // partial send or EAGAIN: register for EPOLLOUT
        epoll_event ev = { .events = EPOLLOUT, .data.u64 = encode(conn_id, CONN) };
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    }
};
```

### 6.4 Backend Comparison

```
                         io_uring              epoll
──────────────────────────────────────────────────────────────
Model                    completion            readiness
Syscalls per I/O         1 (batched)           2 (epoll_wait + recv/send)
Accept                   multishot (1 SQE)     accept4() loop
Idle conn buffer         0 (provided buf ring) 0 (alloc on readiness)
Zero-copy recv           yes                   no
Zero-copy send           yes (SEND_ZC)         no (must copy to kernel)
Kernel version           6.0+                  3.9+ (SO_REUSEPORT)
Code size                ~300 lines            ~250 lines
Latency (per I/O)        lower                 higher (~1 extra syscall)
Throughput               higher                ~80-90% of io_uring
──────────────────────────────────────────────────────────────
Both produce the same IoEvent stream to the event loop.
Upper layers are completely unaware of which backend is active.
```

### 6.5 Reactor vs Proactor Model

The two backends represent two I/O models:

```
Reactor (epoll):
  "fd is ready, you do the I/O"

  epoll_wait() → "fd 5 is readable"
               → you call recv(fd5, buf, ...)     ← you do the I/O
               → "fd 8 is writable"
               → you call send(fd8, buf, ...)     ← you do the I/O

Proactor (io_uring):
  "I/O is already done, here's the result"

  you submit: "read from fd5 into buf"
  io_uring_enter() → "fd5 data is in buf, 1024 bytes read"
                   → "fd8 data sent, 512 bytes written"
```

#### Why Not Choose One?

```
Reactor advantages (pure networking):
  ├── Simpler — you fully control when recv/send happens
  ├── Speculative reads — recv in loop until EAGAIN after readiness
  ├── No SQE/CQ ring memory overhead
  └── Low kernel version requirement (3.9+)

Proactor advantages:
  ├── Fewer syscalls — submit + wait = 1 syscall (vs 2 for reactor)
  ├── Batch submission — 100 sends in one io_uring_enter
  ├── Provided buffer ring — idle connections hold zero buffer
  ├── Multishot — accept/recv without re-submitting
  └── SQPOLL — zero syscalls in extreme case
```

#### Our Design: Unified Completion Interface

```
We don't choose — we use both, behind a unified completion (proactor) API.

  - io_uring backend: native proactor, optimal performance
  - epoll backend: reactor internally, but wait() does the recv/send
    and emits IoEvent completions — "reactor disguised as proactor"

  Upper layers always see completion events (IoEvent).
  Upper layer code is written once.

  ┌──────────────────────────────┐
  │      Event Loop (generic)     │
  │      handles IoEvent[]        │
  └──────────┬───────────────────┘
             │
  ┌──────────┴───────────────────┐
  │    IoEvent abstraction        │
  ├──────────────┬────────────────┤
  │ IoUringBackend│  EpollBackend  │
  │ (proactor)    │  (reactor →    │
  │               │   proactor     │
  │               │   adapter)     │
  └──────────────┴────────────────┘
```

This approach:
- `io_uring` available → best performance, fewer syscalls, zero-copy
- `io_uring` unavailable → epoll fallback, ~80-90% throughput, still correct
- Application code unchanged between backends

---

## 7. Networking

### 7.1 HTTP Parsing

Custom HTTP/1.1 request parser (~500-800 lines C++). No external dependency.

```
Why not llhttp or picohttpparser:
  llhttp:          callback-based API (bad fit), no SIMD, 3000 lines, generated code
  picohttpparser:  better but no strict mode, can't integrate with Slice buffer

Custom parser advantages:
  - Direct integration with Slice buffer (can parse across slice boundaries)
  - Zero-copy: emits Str slices pointing into recv buffer
  - SIMD-accelerated header scanning (SSE4.2/AVX2: find \r\n and ': ' in 16/32 bytes)
  - Strict mode for anti-smuggling (reject ambiguous requests)
  - Only parses requests (not responses — we don't need response parsing on the proxy path)
  - Arena-allocated output (ParsedRequest struct + header array)
```

```cpp
struct ParsedRequest {
    Str method;
    Str path;
    Str query;
    u8  version;         // 0 = HTTP/1.0, 1 = HTTP/1.1
    struct { Str key; Str val; } headers[64];
    u16 header_count;
    u32 content_length;
    bool chunked;
    bool keep_alive;
    u32  header_end;     // offset where body starts
};

// Returns: >0 = complete (header length), 0 = need more data, <0 = error
int parse_request(const u8* buf, u32 len, ParsedRequest* out);
```

### 7.2 Routing

Compile-time built **radix trie**. The JIT compiler can compile the trie traversal into a series of switch/jump instructions.

```
/api/v1/users       → handler_1
/api/v1/users/:id   → handler_2  (captures req.params.id)
/api/v2/users       → handler_3
/health             → handler_4

Compiled to radix trie:
  /
  ├── api/v
  │   ├── 1/users
  │   │   ├── (end) → handler_1
  │   │   └── / :id → handler_2
  │   └── 2/users → handler_3
  └── health → handler_4
```

Compile-time checks:
- Route conflicts (two patterns matching same path)
- Unreachable routes (shadowed by earlier catch-all)
- Parameter name consistency

### 7.3 Upstream Connection Pool

Per-shard, per-upstream-target. No cross-shard sharing.

Connection states (borrowed from Envoy):

```
Connecting → Ready → Busy → Draining → Closed

- Ready: available for new requests
- Busy: currently serving a request
- Draining: no new requests, waiting for in-flight to complete
```

### 7.4 Backpressure (Watermark)

Borrowed from Envoy's watermark buffer design:

```
downstream recv → buffer grows
                     │
          exceeds high watermark (e.g., 64KB)
                     │
          pause downstream recv (cancel io_uring recv SQE)
                     │
          upstream consumes buffer → buffer shrinks
                     │
          drops below low watermark (e.g., 32KB)
                     │
          resume downstream recv (re-submit io_uring recv)
```

This provides end-to-end flow control without explicit coordination.

### 7.5 TLS

Two directions: **inbound** (client → gateway) and **outbound** (gateway → upstream/external service).

#### 7.5.1 Inbound TLS (TLS Termination)

```
Connection flow:

  accept()
    │
    ▼
  TLS handshake (io_uring recv/send + OpenSSL state machine)
    │  ClientHello → ServerHello → Certificate → KeyExchange → Finished
    │  2-4 RTT for full handshake, 1 RTT for session resumption
    ▼
  Handshake complete → plaintext read/write channel
    │
    ▼
  Normal HTTP parsing (identical to plaintext path)
```

Implementation strategy (phased):

```
Phase 2: User-space OpenSSL + BIO_s_mem

  ┌────────────────────────────────────────────────────┐
  │                   Connection                        │
  │                                                     │
  │  io_uring recv → [ciphertext Slice] → BIO_write()  │
  │                                        │            │
  │                        SSL_read() ◄────┘            │
  │                           │                         │
  │                           ▼                         │
  │              [plaintext Slice] → HTTP parser        │
  │                                                     │
  │  HTTP response → SSL_write() → BIO_read()          │
  │                                   │                 │
  │                                   ▼                 │
  │                      [ciphertext Slice]             │
  │                           │                         │
  │                    io_uring send                     │
  └────────────────────────────────────────────────────┘

  OpenSSL integration:
    BIO* rbio = BIO_new(BIO_s_mem());   // read BIO: write ciphertext in
    BIO* wbio = BIO_new(BIO_s_mem());   // write BIO: read ciphertext out
    SSL_set_bio(ssl, rbio, wbio);

    // On recv (ciphertext arrives):
    BIO_write(rbio, ciphertext, len);
    int n = SSL_read(ssl, plaintext, sizeof(plaintext));
    // plaintext now contains decrypted HTTP data

    // On send (plaintext to encrypt):
    SSL_write(ssl, plaintext, len);
    int n = BIO_read(wbio, ciphertext, sizeof(ciphertext));
    // submit io_uring send with ciphertext

Phase 3 optimization: kTLS (kernel TLS)

  After handshake in user-space, switch data path to kernel:
    setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
    setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));

  io_uring recv/send now operate on plaintext directly
  → zero-copy, kernel handles encrypt/decrypt
  → requires Linux 4.13+ (kTLS), 5.x+ (mature), specific cipher suites
  → fallback to user-space OpenSSL if kTLS unavailable
```

SNI (Server Name Indication) — multiple certificates per port:

```swift
// Single certificate (simple)
listen :443, tls(cert: env("CERT"), key: env("KEY"))

// Multiple domains with different certificates
listen :443 {
    tls "api.example.com", cert: "/certs/api.pem", key: "/certs/api.key"
    tls "admin.example.com", cert: "/certs/admin.pem", key: "/certs/admin.key"
    tls default, cert: "/certs/default.pem", key: "/certs/default.key"
}
```

```
SNI implementation:
  - OpenSSL SNI callback (SSL_CTX_set_tlsext_servername_callback)
  - Lookup hostname from ClientHello → select SSL_CTX with matching certificate
  - Per-shard certificate cache (share-nothing)
  - Certificate reload on hot reload (new .rut → new cert paths → reload certs)
```

TLS Session Resumption — avoid full handshake on reconnect:

```
Two mechanisms (both enabled by default):

  Session ID cache:
    - Per-shard in-memory cache
    - Key: session ID (32 bytes) → Value: SSL session state
    - LRU eviction, configurable max size
    - Saves 1 RTT on reconnect

  Session Tickets:
    - Server encrypts session state, sends to client as ticket
    - Client presents ticket on reconnect → server decrypts → resume
    - No server-side storage needed
    - Ticket encryption key rotated periodically (configurable)
    - Key shared across shards (one of the few cross-shard shared items)
```

TLS configuration in language:

```swift
listen :443 {
    tls "api.example.com", cert: "/certs/api.pem", key: "/certs/api.key"

    // TLS security settings
    tlsMinVersion: .tls12           // minimum TLS 1.2 (reject TLS 1.0/1.1)
    tlsCiphers: [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
    ]
    tlsSessionTimeout: 4h          // session cache TTL
    tlsTicketRotation: 12h         // rotate ticket keys
}
```

#### 7.5.2 Outbound TLS (Gateway → External Services)

```
Already designed in Section 13.4. Summary:

  http://  → plaintext connection
  https:// → automatic TLS handshake + server cert verification

  Implementation: same OpenSSL + BIO_s_mem mechanism
  Session caching: per-shard, per-host:port → reuse TLS sessions on reconnect
  mTLS (client cert): optional, via ClientCert parameter in HTTP call syntax

  let res = get https://api.stripe.com/charges {
      Authorization: "Bearer \(env("STRIPE_KEY"))"
  }
  // TLS handled transparently, session cached for future calls to same host
```

#### 7.5.3 Dependency

```
OpenSSL 3.x (dynamic link, ~3MB .so)
  - Most mature TLS library
  - System usually has it installed
  - Security updates via system package manager
  - Alternative: BoringSSL (lighter, Google maintains for Chrome)
    but no stable API guarantee

Not considered:
  - Custom TLS: too complex, security-critical code
  - LibreSSL: less widely deployed
  - mbedTLS: missing some features (kTLS integration)
  - rustls: Rust, would need FFI bridge
```

#### 7.5.4 Memory Impact

```
Per TLS connection (additional to plaintext connection):
  SSL object:          ~2-4 KB (OpenSSL internal state)
  BIO buffers:         2 x 16 KB (read + write)
  Session cache entry: ~200 bytes

C100K with TLS:
  100K × 4KB SSL state  = 400 MB    ← significant
  100K × 32KB BIO       = 3.2 GB   ← too much

Optimization: lazy BIO allocation (same as idle connection strategy)
  Idle TLS connections: SSL object only (~4KB), no BIO buffers
  Active TLS connections: SSL + BIO buffers allocated on demand

  Typical: 100K connections, 5K active
  5K × 36KB + 95K × 4KB = 180MB + 380MB = 560MB
  Acceptable for a TLS-terminating gateway
```

#### 7.5.5 Implementation Phases

```
Phase 1: No TLS
  - Use upstream LB / HAProxy for TLS termination
  - Gateway listens on plaintext only

Phase 2: Inbound TLS + Outbound TLS
  - OpenSSL + BIO_s_mem + io_uring
  - SNI for multi-domain
  - Session ID cache + Session Tickets
  - TLS config in .rut files
  - Outbound HTTPS for HTTP calls

Phase 3: Optimization + Advanced
  - kTLS for data path (zero-copy after handshake)
  - mTLS (client certificate validation)
  - OCSP stapling
  - Certificate hot-reload without connection drop
  - Dynamic certificates (e.g., Let's Encrypt via extern)
```

---

## 8. Cross-Shard Communication

### 8.1 Principle

No locks. No mutexes. No condition variables. Four specific cross-shard scenarios, each with a dedicated lock-free solution.

### 8.2 Global Rate Limiting

**Default: per-shard partitioning (no communication)**

```
// Global limit: 1000 req/s, 8 shards
// Each shard: 125 req/s
// Accuracy: ±8 req/s — acceptable for rate limiting

local limit: u32 = global_limit / shard_count
```

**Optional: precise global counting (atomic)**

```cpp
alignas(64) std::atomic<u32> global_counter;  // own cache line, no false sharing

// Per shard:
u32 count = global_counter.fetch_add(1, std::memory_order_relaxed);
if (count > limit) reject();
```

### 8.3 Global Statistics

Per-shard local counters, aggregated on read:

```cpp
struct ShardStats {
    alignas(64) u64 requests;     // own cache line
    alignas(64) u64 errors;
    alignas(64) u64 bytes_in;
    alignas(64) u64 bytes_out;
};

ShardStats per_shard_stats[MAX_SHARDS];

// Write (hot path): each shard writes only its own, zero contention
per_shard_stats[my_shard].requests++;

// Read (metrics endpoint, low frequency):
u64 total = 0;
for (int i = 0; i < num_shards; i++)
    total += per_shard_stats[i].requests;
```

### 8.4 Configuration Hot Reload

RCU (Read-Copy-Update) pattern:

```cpp
struct Config {
    RouteTable* routes;
    HandlerFn*  handlers;
    u64         version;
};

std::atomic<Config*> current_config;

// Reload (infrequent):
void reload(Config* new_config) {
    Config* old = current_config.exchange(new_config, std::memory_order_release);
    wait_for_all_shards_epoch_advance();  // wait for in-flight requests
    free_jit_code(old);
}

// Per-shard request handling (hot path):
void handle(Connection* c) {
    Config* cfg = current_config.load(std::memory_order_acquire);  // ~1ns
    epoch_enter();
    // ... process request ...
    epoch_leave();
}
```

### 8.5 Health Check Results

**Option A: each shard runs independent health checks (simplest, fully share-nothing)**

8 shards x 1 check/5s = upstream receives 8 health checks per interval. Negligible overhead.

**Option B: single shard checks, notify all via atomic bitmap**

```cpp
alignas(64) std::atomic<u64> healthy_mask;  // up to 64 upstreams

// Shard 0 writes:
healthy_mask.store(new_mask, std::memory_order_release);

// Other shards read:
u64 mask = healthy_mask.load(std::memory_order_acquire);
if (!(mask & (1 << upstream_id))) skip_upstream();
```

### 8.6 Language-Level Exposure

All state types (Cache, LRU, Set, Bloom, Bitmap) are per-shard. No shared
mutable state. Cross-shard communication uses `notify` — the only primitive:

```swift
// All state is per-shard, single-threaded, zero locking
let blacklist = Set<IP>(capacity: 100000)
let buckets = Cache<IP, i64>(capacity: 100000)

// Per-shard mutation — immediate, no cross-core cost
blacklist.add(ip)
let now = time.nowMicros()
let tat = max(buckets.get(req.remoteAddr).or(0), now)
buckets.set(req.remoteAddr, tat + 600000)          // packed GCRA update

// Cross-shard propagation — via SPSC queues, eventual consistency
notify all blacklist.add(ip)    // N-1 relaxed writes, microsecond propagation
```

The compiler generates:
- State mutation → plain memory write (per-shard, single thread)
- `notify all expr` → serialize operation, enqueue to N-1 SPSC ring buffers
  (relaxed store + release on tail pointer, no seq_cst, no full barrier)

---

## 9. Timer Wheel

For managing 100K connection timeouts (keep-alive, request timeout, health check intervals).

```
Timer Wheel:
  Resolution: 1 second
  Slots: 60 (covers 60s keep-alive timeout)
  Each slot: intrusive linked list of connections
  Driven by: single timerfd per shard

  ┌───┬───┬───┬───┬───┬─── ... ───┬───┐
  │ 0 │ 1 │ 2 │ 3 │ 4 │           │59 │
  └───┴───┴───┴───┴───┴─── ... ───┴───┘
    ↑ cursor (advances each second)
```

```cpp
struct TimerWheel {
    ListNode slots[60];
    u32 cursor;

    // Add timeout: O(1)
    void add(Connection* c, u32 seconds) {
        u32 slot = (cursor + seconds) % 60;
        list_append(&slots[slot], &c->timer_node);
    }

    // Refresh on activity: O(1)
    void refresh(Connection* c, u32 seconds) {
        list_remove(&c->timer_node);
        add(c, seconds);
    }

    // Tick (called every second): close all timed-out connections
    void tick() {
        ListNode* node = slots[cursor].head;
        while (node) {
            Connection* c = container_of(node, Connection, timer_node);
            close_connection(c);
            node = node->next;
        }
        cursor = (cursor + 1) % 60;
    }
};
```

All operations O(1). One timerfd drives the entire wheel per shard.

---

## 10. Hot Reload

### 10.1 Overview

No process restart. No fork. No fd passing. No upstream reconnection. Just atomic pointer swap.

Comparison with nginx:

```
                     nginx reload              Our hot reload
─────────────────────────────────────────────────────────────────
Trigger              SIGHUP → master fork      file change → compiler thread
Compilation          master parses new conf     compiler thread: parse → typecheck → JIT
New code activation  fork new worker processes  atomic swap function pointers
Old code retirement  old worker process exits   ref_count → 0, release JIT memory
Connection migration none (old worker drains)   none needed (same shard, new handler)
Upstream connections rebuilt (new worker, new pool) preserved (pool untouched, only handler changes)
Memory during swap   2x (two sets of workers)   + ~100-200KB (one extra JIT code copy)
Activation latency   seconds (fork + init)      milliseconds (atomic swap)
Failure handling     parse fails → no fork      compile fails → no swap
```

### 10.2 Compilation Thread

Compilation runs on a dedicated background thread (not on any shard), so request processing is never blocked.

```cpp
struct CompilerThread {
    std::thread thread;
    int         notify_fd;       // eventfd, triggered by inotify or API call
    Duration    debounce = 500ms; // wait before compiling (coalesce rapid changes)

    void run() {
        for (;;) {
            eventfd_read(notify_fd, ...);

            // Debounce: wait 500ms, restart if file changes again
            while (wait_for_more_changes(debounce)) {}

            auto source = read_file(config_path);
            auto result = compiler.compile(source);

            if (result.has_error) {
                log_error("compile failed", { errors: result.errors });
                // Don't swap — old config keeps running
                // Error visible at /internal/health
                continue;
            }

            initiate_swap(result.config);
        }
    }
};
```

### 10.3 LLVM ORC JIT Compilation

```
Each compilation produces an isolated JITDylib (LLVM dynamic library):

  1. Parse → Typed AST → Inline expand → RIR → Optimize
  2. Generate LLVM IR from RIR
  3. Create new JITDylib: jit->createJITDylib("config_v3")
  4. Add IR module → ORC JIT compiles to native machine code
  5. Resolve function pointers: jit->lookup(dylib, "handle_get_users_id")
  6. Build route table (radix trie) pointing to new function pointers

  Result: CompiledConfig with version, route table, handler pointers, and JITDylib reference
```

```cpp
struct CompiledConfig {
    u64                     version;
    RouteTable*             routes;          // radix trie
    HandlerFn*              handlers;        // function pointer array
    u32                     handler_count;
    llvm::orc::JITDylib*    dylib;           // holds JIT memory
};
```

### 10.4 Atomic Swap

```cpp
// Global atomic pointer — the only cross-shard shared mutable state
alignas(64) std::atomic<CompiledConfig*> g_current_config;

// Swap (on compiler thread):
void initiate_swap(CompiledConfig* new_config) {
    CompiledConfig* old = g_current_config.exchange(
        new_config, std::memory_order_release
    );
    // old goes into pending release queue
    pending_release.push(old);
    log_info("config swapped", { from: old->version, to: new_config->version });
}
```

```
Timeline:

  Shard 0           Shard 1           Compiler Thread
  ─────────         ─────────         ───────────────
  req A (v1)        req C (v1)        compile v2...
  req B (v1)        req D (v1)        done!
                                      swap: g_current_config = v2
  req E (v2) ←── new requests use v2 ──→ req F (v2)
  req A (v1) ←── in-flight stays on v1
  req A done ──→ epoch advance
  req B done ──→ epoch advance
                  req C done ──→ epoch advance
                  req D done ──→ epoch advance
                                      check: all epochs advanced → release v1
```

### 10.5 In-Flight Request Handling

When config swaps mid-request (e.g., async handler yielded, waiting for upstream), the request continues using the config it started with.

```cpp
struct Connection {
    // ... other fields ...
    CompiledConfig* active_config;    // config bound at request start
    HandlerFn       active_handler;   // handler bound at request start
};

void on_request_start(Connection* c, int shard_id) {
    // Bind config for this request's entire lifetime
    shard_epochs[shard_id].epoch++;   // odd = processing (enter)
    c->active_config = g_current_config.load(std::memory_order_acquire);

    // Route match + bind handler
    auto idx = c->active_config->routes->match(c->parsed->method, c->parsed->path);
    c->active_handler = c->active_config->handlers[idx];
    c->handler_state = 0;
    c->active_handler(c);
}

void on_io_complete(Connection* c) {
    // I/O completed (upstream responded), continue same handler (same version)
    c->active_handler(c);
}

void on_request_complete(Connection* c, int shard_id) {
    c->active_config = nullptr;
    c->active_handler = nullptr;
    shard_epochs[shard_id].epoch++;   // even = idle (leave)
}
```

### 10.6 Old JIT Code Release (Epoch-Based Reclamation)

```cpp
// Per-shard epoch counter — each shard only writes its own (no contention)
struct alignas(64) ShardEpoch {
    u64 epoch;          // odd = processing request, even = idle
    u64 padding[7];     // pad to 64 bytes (own cache line, no false sharing)
};
ShardEpoch shard_epochs[MAX_SHARDS];

// Compiler thread records epoch snapshot at swap time
struct PendingRelease {
    CompiledConfig* config;
    u64 swap_epochs[MAX_SHARDS];   // epoch values at swap time
    Timestamp swap_time;
};

// Compiler thread periodically checks if old configs can be released
void try_release_old_configs() {
    for (auto& pr : pending_releases) {
        bool safe = true;
        for (int i = 0; i < num_shards; i++) {
            u64 e = shard_epochs[i].epoch;
            // Shard has advanced past the swap point?
            if (e <= pr.swap_epochs[i] && (e & 1)) {
                safe = false;  // still processing a pre-swap request
                break;
            }
        }
        if (safe) {
            release_jit_code(pr.config);
            pending_releases.remove(pr);
        }
    }
}

void release_jit_code(CompiledConfig* config) {
    // 1. Remove LLVM JITDylib → munmap executable pages → memory returned to OS
    jit->removeJITDylib(*config->dylib);

    // 2. Free route table
    delete config->routes;

    // 3. Free config struct
    delete config;

    log_info("released JIT code", { version: config->version });
}
```

```
Hot path overhead per request:
  atomic load g_current_config:    ~1ns
  local epoch write (enter):       ~1ns
  local epoch write (leave):       ~1ns
  ─────────────────────────────
  Total:                           ~3ns per request
```

### 10.7 Edge Cases

```
1. Compile failure
   → Don't swap, old config keeps running
   → Error reported at /internal/health and in logs

2. Rapid successive changes (5 changes in 10 seconds)
   → Debounce: 500ms wait after last change before compiling
   → At most ~2 compilations per second
   → Multiple old versions can coexist (each ~100-200KB JIT code, trivial)

3. Slow request holds old config (e.g., 60s upstream timeout)
   → Request timeout guarantees eventual completion
   → Old JIT code released within max(request_timeout) after swap
   → Normal case: old code freed in 1-5 seconds

4. Safety net for stuck requests
   → If pending release > 5 minutes: log.warn (but don't force release)
   → Force release = crash (handler code pulled from under running request)
   → Should never happen if timeouts are configured correctly

5. LLVM JITDylib memory actually freed?
   → Yes. removeJITDylib() calls munmap on executable memory pages
   → Symbol tables and metadata freed
   → Verifiable via /internal/shards (shows JIT memory usage)
```

### 10.8 Trigger Methods

```swift
// 1. File watch (automatic)
//    Runtime uses inotify to watch .rut files
//    Change detected → debounce → compile → swap

// 2. API endpoint (manual)
//    POST /internal/reload → immediate compile + swap

// 3. Signal (ops-friendly)
//    kill -HUP <pid> → same as API reload

// Status visible at:
//    GET /internal/health
//    {
//      "config_version": 3,
//      "compile_time_ms": 45,
//      "last_reload": "2026-03-21T10:30:00Z",
//      "pending_release": 0,
//      "pending_error": null
//    }
```

### 10.9 Connection Draining (Graceful Shutdown)

Separate from hot reload — this is for process shutdown/restart.

Borrowed from Envoy: probabilistic drain.

```
During shutdown:
  - New connections: accepted but responded with Connection: close header
  - Existing connections: drain probability increases over time
  - After drain period (configurable, e.g., 30s): force close remaining
  - Once all connections closed: process exits cleanly
```

---

## 11. Compiler Architecture

### 11.1 Pipeline

```
.rut source
    │
    ▼
  Lexer / Parser (hand-written recursive descent)
    │
    ▼
  AST
    │
    ▼
  HIR (resolved + typed language semantics)
    │  - name resolution
    │  - type inference / checking
    │  - route conflict detection
    │  - domain value range checks
    │  - header spell check
    │  - optional access safety
    ▼
  MIR (normalized execution model / CFG)
    │
    │  - explicit control flow
    │  - evaluation order
    │  - early return / guard lowering
    │  - yield boundary placement
    │  - unreachable code detection
    ▼
  Inline Expansion + Lowering
    │
    ▼
  RIR (backend-facing typed IR)
    │
    ▼
    ├── Optimization passes (on RIR)
    │   - dead code elimination
    │   - constant folding / propagation
    │   - state machine construction (I/O points → states)
    │   - instrumentation insertion (metrics, debug, access log)
    │
    ├── --dry-run: dump RIR and stop
    ├── --emit-rir: output RIR for inspection
    │
    ▼
  LLVM IR Generation (from RIR)
    │
    ▼
  LLVM ORC JIT
    │  - lazy compilation (only compile hit routes)
    │  - LLVM optimization passes
    ▼
  Native Function Pointers
    │
    ▼
  CompiledConfig { version, routes, handlers }
```

#### 11.1.1 Layer Responsibilities

The compiler is intentionally split into four semantic layers:

- **AST** — source-structure model. Preserves the user's surface syntax and source spans.
- **HIR** — language-semantics model. Names are resolved, types are known, and Rut-specific objects such as `route`, `upstream`, and `forward` are explicit.
- **MIR** — execution-semantics model. Control flow, evaluation order, short-circuiting, early returns, and yield boundaries become explicit.
- **RIR** — backend contract. A compact, typed, SSA-friendly IR consumed by optimization passes and code generation.

The intended boundary between these layers is:

- **AST answers:** "What did the user write?"
- **HIR answers:** "What does that code mean in Rut?"
- **MIR answers:** "How does that meaning execute?"
- **RIR answers:** "What primitive operations must the backend emit?"

Concrete ownership rules:

- **AST** carries source structure and `span` information, but not resolved symbols, inferred types, or backend opcodes.
- **HIR** carries resolved references, type information, and normalized language semantics, but not SSA numbering or backend instruction selection.
- **MIR** carries blocks, branches, terminators, evaluation order, and temporary values, but not target-specific code generation details.
- **RIR** carries explicit backend-facing operations and source locations, but does not try to model high-level parser recovery state or unresolved language constructs.

`HIR -> MIR` is the key semantic boundary in the compiler:

- `HIR` is where the compiler understands the language.
- `MIR` is where the compiler understands execution.

That split exists so Rut-specific language features can evolve without forcing the backend IR to absorb high-level control-flow lowering, optional semantics, or route-level sugar directly.

#### 11.1.2 Optimization Ownership by Layer

Optimization responsibility is intentionally layered as well:

- **HIR** may perform language-semantic simplifications that depend on type knowledge or constant domain values, but it is not responsible for storage reuse or backend-style value scheduling.
- **MIR** is the first good place for temporary-value cleanup, such as trivial copy propagation, dead temporary elimination, expression flattening, and simplifications that depend on explicit control flow or evaluation order.
- **RIR** is the main optimization IR for backend-independent passes such as dead code elimination, constant folding, guard coalescing, and state-machine construction.
- **Backend / LLVM** owns physical storage reuse: register allocation, stack-slot reuse, frame layout, and related lifetime-based memory optimizations.

In practice this means:

- "Can this temporary value be optimized away?" is usually a **MIR or RIR** question.
- "Can two dead/non-overlapping variables reuse the same storage?" is a **backend allocation** question, typically handled after RIR lowering by LLVM or an equivalent code generator.

#### 11.1.3 Type System Boundaries

Rut's type system is intentionally designed to avoid runtime type uncertainty.

The target model is:

- No inheritance
- No subtype polymorphism
- No runtime RTTI-style type discovery
- No trait objects / erased interface dispatch
- No implicit fallback to dynamic `Any`

This means every expression must have a single, fully known static type by the end of HIR construction.

Failure may still occur in the language, but not because the runtime is discovering the type of a value. The remaining failure categories are:

- value-range checks (for example, narrowing numeric conversions)
- optional absence / `nil`
- parsing failures
- explicitly modeled sum/variant matching, if such types are introduced later

As a result:

- `is` is not a runtime type-test operator in Rut's design
- `as` is not a dynamic cast
- MIR and RIR are not expected to carry runtime type tests as ordinary program operations

Instead, Rut should treat these features as follows:

- **`is`** — a compile-time type/shape predicate only. It answers questions about statically known type relationships and should fold during semantic analysis whenever possible.
- **`as`** — an explicit conversion that is guaranteed to succeed if accepted by the type checker.
- **`as?`** — an explicit checked conversion for cases where the conversion is semantically valid but may fail.
- **`parse`** — text-to-value interpretation. String-to-domain conversions belong here rather than in `as` / `as?`.

That distinction is important:

- `i32 as i64` is a conversion
- `i64 as? i32` is a checked conversion
- `string -> IP` is parsing, not casting

The language should avoid treating text as a universal source type. In particular, most `string -> T` operations for domain types (`IP`, `CIDR`, `Duration`, `StatusCode`, etc.) should be modeled as parse operations rather than casts.

Optionality must also remain explicit in the semantic layers, even if the surface
language sometimes hides it ergonomically. In particular, the compiler must
distinguish:

- `T`
- `T?`
- `Result<T, Error>`
- `Result<T?, Error>`

These are not interchangeable. They imply different control-flow shapes, different
dataflow facts, and different optimization opportunities.

Semantically, the two key questions are independent:

- **optionality** — can this expression yield no usable value (`nil`)?
- **error capability** — can this expression carry failure information?

That means the compiler should treat "may be nil" and "may have error" as separate
dimensions of the internal model rather than collapsing them into one flag.

The same rule applies to function return-type inference.

At the surface level, users may omit the return type or spell it explicitly. But by
the end of HIR construction, the compiler must normalize each function's return
shape using two independent dimensions:

- `may_nil`
- `may_error`

That yields exactly four normalized semantic forms:

- `T` — not optional, not error-capable
- `T?` — optional, not error-capable
- `Result<T, Error>` — error-capable, success value required
- `Result<T?, Error>` — error-capable, success value may still be absent

This means surface syntax may look lightweight, but the normalized semantic return
shape must remain precise for control-flow lowering, diagnostics, and optimization.

However, the *representation* of `T?` is a backend choice, not a language promise.
When the compiler can prove it is safe, it may represent optional values using:

- spare / niche bit patterns
- out-of-range sentinel values
- tagged pointers or equivalent compact layouts

For example, a reference-like type may use `null` as `nil`, while certain bounded
domain values may be able to reserve an impossible value as the `nil` sentinel.

This is purely an implementation optimization. It must not change source-level
semantics. If the compiler cannot prove a niche/sentinel encoding is safe, it must
fall back to an explicit tag or equivalent representation.

#### 11.1.4 Generics and Constraints

Rut still needs abstraction power, even though it avoids runtime type uncertainty.

The intended answer is **compile-time generics with monomorphization**, not subtype polymorphism:

- Generic functions are instantiated at compile time
- Generic structs / enums / sum types are instantiated at compile time
- Generated MIR/RIR always see concrete types after instantiation
- No runtime generic erasure is required

This is important for ergonomics. Without generics, routine language building blocks such as `Option<T>`, `Result<T, E>`, typed collections, and reusable helper functions would force large amounts of duplicated code.

Traits / constraints are still needed, but mainly for people defining abstractions rather than ordinary users writing application logic.

The intended usage split is:

- **Ordinary users** mostly consume generic APIs and usually do not write explicit constraints
- **Library authors / framework authors / large-system authors** define generic abstractions and therefore write constraints

For that reason, constraints should optimize for semantic clarity, extensibility, and diagnostics more than for being the shortest syntax in everyday code.

Rut should therefore distinguish clearly between three different surface concerns:

- `protocol` declares a behavioral contract
- `impl` declares that a type conforms to one or more protocols and optionally provides method bodies
- `using` is reserved for import / alias syntax only; it must not be used to declare protocol conformance

Conformance should therefore use `impl`, not `using`.
If a type only wants to adopt protocol default implementations, it should do so with an empty `impl` block:

```rut
Box impl Hashable {}
```

Rut should therefore use a single semantic core for constraints:

- predicate-based constraint solving inside the compiler
- trait-like surface syntax only as sugar, if desired

In other words, the compiler should not maintain two separate type-system mechanisms for "traits" and "constraints". There should be one internal constraint model, with optional lighter surface syntax layered on top.

Examples of the intended layering:

- User-facing sugar: `func contains<T: Eq>(xs: [T], needle: T) -> bool`
- Canonical semantic form: `func contains<T>(xs: [T], needle: T) -> bool where Eq(T)`

The second form is the semantic core. The first is optional sugar. The current
front-end accepts both spellings for direct type-parameter predicates and
normalizes them into the same HIR constraint metadata.

First-stage `where` predicates are intentionally narrow:

- `where Eq(T)`, `where Ord(T)`, `where Error(T)`
- `where CustomProtocol(T)`
- namespace-qualified protocol names, such as `where auth.Hashable(T)`
- comma-separated predicates, such as `where Eq(T), Hashable(T)`

They do not introduce arbitrary value expressions, overload selection rules, or
C++-style substitution failure. A failed predicate is a normal type error.

**Protocol Conformance and Default Implementations**

Rut should support explicit protocol conformance blocks in type-first form:

```rut
Box impl Hashable {
    func hash(self: Box) -> i32 => self.value
}
```

A single block may list multiple protocols:

```rut
Box impl Hashable, Adder {
    func hash(self: Box) -> i32 => self.value
    func add(self: Box, x: i32) -> i32 => x
}
```

First-stage conformance rules:

- `impl` itself declares conformance; no separate conformance declaration syntax is needed
- an empty `impl` block is valid when all required protocol methods have default implementations
- if a required protocol method has no default implementation, the `impl` block must provide it
- one type may conform to multiple protocols, but if two protocols in the same `impl` block define the same method name, the block must be rejected as ambiguous
- `using Type as Protocol` is not protocol syntax and must remain invalid for conformance

Dispatch rules for the first stage:

- dispatch is static
- concrete receiver calls may resolve to either an explicit `impl` method or a protocol default method
- explicit `impl` methods take precedence over protocol default methods
- generic receiver calls may dispatch through protocol constraints when the generic type is known to conform
- imported explicit `impl` blocks are visible to the importing file for both concrete receiver dispatch and generic constraint satisfaction
- empty imported `impl` blocks may adopt protocol default methods just like local empty `impl` blocks
- explicit `impl` uniqueness is global within the current visible import graph: if two visible explicit `impl` blocks overlap on the same `Type + Protocol`, the program must be rejected rather than selecting one by priority
- dynamic dispatch, witness tables, and trait objects are out of scope for the first stage

#### 11.1.5 Type-Level Computation for Constraints

If Rut supports generic constraints seriously, the compiler needs internal type predicates and type computation utilities.

At minimum, the type checker needs internal operations such as:

- type equality
- "is this type comparable / hashable / optional / numeric?"
- "what is the inner type of `Optional<T>`?"
- "can `T` be compared to `U`?"
- "is this cast total, checked, or forbidden?"

These capabilities are primarily compiler infrastructure. They do not imply that the language must immediately expose a full user-programmable type-level function language.

The intended order of exposure is:

- internal type predicates and type computations first
- user-visible generic constraints second
- only later, if truly needed, richer user-facing type-level expressions

This keeps the implementation coherent while avoiding premature complexity in the surface language.

#### 11.1.5A Associated Types and Type-Level Conditionals

Rut should support the common library-design cases that C++ traits solve, but it
should not inherit C++ template matching, partial specialization, SFINAE, or
overload-ranking as the way to express type logic.

The preferred model is explicit and predicate-based:

```rut
protocol Iterable {
    type Elem
    func first(self) -> Elem
}

Array<T> impl Iterable {
    type Elem = T
    func first(self: Array<T>) -> T { ... }
}

func head<C>(c: C) -> C.Elem where Iterable(C) {
    c.first()
}
```

Current implementation status: the front-end records protocol associated type
requirements and validates matching `impl` bindings. Generic impl bindings may
refer to the impl target's type parameters, such as `type Elem = T` in
`Box<T> impl Iterable`. Protocol method requirements may use their own
associated types directly, such as `func first() -> Elem` or
`func push(x: Elem) -> i32`, and impl method signatures are checked against the
impl's associated type bindings. Function return types and parameter types may
project associated types with `C.Elem` when `C` has a matching protocol
constraint; at call sites, concrete impl bindings and direct generic impl
bindings such as `type Elem = T` are resolved through the receiver's instantiated
type arguments.
Bindings that wrap the target parameter in a generic struct or variant, such as
`type Elem = Wrap<T>` or `type Elem = Result<T>`, are also concretized through
the same receiver argument mapping.

For conditional type-level decisions, Rut should expose explicit static
branching rather than making failure-to-match part of overload resolution:

```rut
type Storage<T> match {
    T: Copy => Inline<T>
    T: MoveOnly => Box<T>
    _ => Ref<T>
}

func clone_or_move<T>(x: T) -> T {
    if const T: Clone {
        x.clone()
    } else {
        x
    }
}
```

Type-level `match` arms use the same `pattern => ...` spelling as value-level
`match` — there is no `case` keyword at either level.

Rules for this family of features:

- conditions are type predicates, such as `T: P`, `T == U`, or `T.Elem == U`
- selected branches are fully type checked after generic binding
- unselected branches may be syntax checked and deferred semantically
- ambiguous matches are compile errors unless a construct explicitly defines order
- these features must not participate in C++-style overload viability or ranking
- implementation remains monomorphized; no trait objects or erased dispatch are implied

Current implementation status: the front-end supports top-level generic type
aliases and ordered type-level `match` aliases, using the same caseless
`pattern => ...` arm spelling as value-level `match` (a legacy `case` prefix
is rejected with the no-`case` fix-it):

```rut
type Storage<T> match {
    T: Eq => Inline<T>
    _ => Ref<T>
}

type Choice<T, U> match {
    T == U => Same<T>
    _ => Diff<T, U>
}

type Selected<C, U> match {
    C.Elem == U => Hit<U>
    _ => Miss<C, U>
}
```

The implemented matcher currently supports generic type parameters,
protocol-predicate arms (`T: Eq => ...`, `T: Error => ...`, and
custom protocol predicates when conformance metadata is available), type
equality arms (`T == U => ...`), associated-type equality arms
(`C.Elem == U => ...`) once impl associated type bindings are available,
and a wildcard fallback. Alias expansion works in ordinary type positions such
as `let` annotations, function parameters, function return types, protocol method
requirements, impl associated type bindings, struct fields, and variant payloads.
Match selection works for concrete alias arguments and for
generic arguments using the constraints available on those generics;
unconstrained generics fall through to later arms such as `_`. Type equality and
associated-type equality arms also work when the compared values contain generic
parameters, including generic impl bindings such as
`Box<T> impl Iterable { type Elem = T }`. Expansion preserves generic type
parameters inside generic struct or variant targets. The front-end now
pre-registers local impl conformance and associated-type binding metadata before
function signature analysis, so associated-type equality arms are usable in
function signatures as well as later expression-local type positions. Type match
aliases are also
imported through the ordinary relative/selective import path for library-defined
traits-style helpers. Imported alias targets and custom protocol predicate arms
are remapped through namespace aliases and selected-name renames. This remains a
type-alias facility, not overload selection.

#### 11.1.6 Pipeline Placeholder Rules

Rut supports the shell-style pipeline operator `|` for staged dataflow. The placeholder rules are explicit and compile-time checked.

The intended placeholder model is:

- `_` is syntax sugar for `_1`
- `_N` refers to pipeline input slot `N`
- placeholders are positional, not named

The key rule is:

- a pipeline stage may only reference input slots that are statically provided by the value on the left-hand side

For the first-stage design this means:

- a non-tuple value provides only slot `_1`
- a tuple value with arity `K` provides slots `_1 ... _K`
- the maximum placeholder index referenced by the right-hand stage must be `<=` the left-hand input arity

Examples:

- `x | f(_)` is valid because `_` means `_1`
- `x | f(_1)` is valid
- `x | f(_2)` is invalid because a single value only provides one slot
- `(a, b) | f(_1, _2)` is valid
- `(a, b) | f(_3)` is invalid

The compiler should reject placeholder misuse during semantic analysis, before MIR/RIR lowering.

This placeholder system is intentionally future-friendly:

- single-input pipelines stay simple
- multi-input pipelines can later reuse the same numbered-slot model
- the syntax does not need to be redesigned when tuple-fed stages are introduced

In expression position `|` means pipeline only — bitwise operations are named
functions (§3.2.1), so no contextual disambiguation is needed. The right-hand
side of `|` must be a call expression containing at least one placeholder;
anything else is a compile error with a fix-it suggesting a placeholder stage
(`f(_, ...)`). This is a validation rule, not a disambiguation rule, and it
keeps a clear path for stream-style lowering and fusion optimizations.

#### 11.1.6A Recursive Tuple Type Shapes

Rut's current tuple handling may begin with a flat internal representation such as:

- `tuple_len`
- `tuple_types[]`
- `tuple_variant_indices[]`
- `tuple_struct_indices[]`

That flat form is acceptable as an implementation starting point, but it is not
the right long-term semantic model.

The target model is a recursive type-shape graph:

- `Bool`
- `I32`
- `Str`
- `Generic`
- `Variant`
- `Struct`
- `Tuple([TypeShape, ...])`

In particular, tuple element shapes must be allowed to contain:

- nested tuples
- concrete generic instances
- qualified imported types
- structs and variants with their own concrete payload/field shapes

Examples that should be representable directly in the type model:

- `(i32, i32)`
- `(Box, i32)`
- `((Box, i32), i32)`
- `Result<Box<i32>>`
- `Result<(Box<i32>, i32)>`

This matters because a flat tuple metadata scheme creates avoidable special cases:

- nested tuple elements become artificially forbidden or awkward
- tuple equality / ordering lowering needs ad hoc parallel arrays
- imported qualified generic type arguments become harder to preserve
- tuple fields, tuple payloads, tuple params, and tuple returns drift apart semantically

So the intended invariant is:

- **HIR semantic type identity must be expressible using recursive type shapes**
- backend-facing flattened tuple metadata may still exist temporarily as lowering cache or compatibility data
- but flattened metadata must not be treated as the semantic source of truth forever

The recommended migration order is:

1. Introduce a recursive `TypeShape` pool in HIR.
2. Record function parameter and return shapes there first.
3. Extend the same shape model to struct fields, variant payloads, locals, and expressions.
4. Keep flat tuple arrays only as compatibility fields until MIR/RIR lowering fully consumes recursive shapes.
5. Remove duplicated flat semantic metadata once lowering no longer depends on it.

During the migration period, both representations may coexist, but the rule should be:

- new type-system features must attach to the recursive shape model first
- flat tuple arrays exist only to preserve existing lowering paths until they are retired

Current implementation status for this migration is intentionally split into two
separate signals:

- `is_concrete`
  - means the recursive shape is fully concrete as a type
  - examples: `i32`, `Box<i32>`, `Result<Box<i32>>`
  - this does **not** imply lowering can already materialize every required runtime carrier

- `carrier_ready`
  - means lowering may safely consume that shape without violating the current
    build order for struct/variant runtime carriers
  - this is stricter than `is_concrete`
  - it is currently computed in MIR, not inferred ad hoc in lowering

That distinction exists because a shape may be fully concrete while still depending
on a struct definition or variant carrier that has not yet been materialized in the
current lowering pass.

The current intended lowering rule is:

- prefer recursive shape metadata when `carrier_ready` is true
- otherwise fall back to the legacy flat metadata / existing build-order checks

At the moment, that `carrier_ready` gate is already used in conservative lowering
entry points such as:

- shape-sensitive comparison / field-access helpers
- struct field type selection during user-struct build
- variant payload carrier selection for tuple / struct / variant payload paths

More concretely, the current `lower_rir` implementation already prefers
shape-derived views at these call sites:

- top-level binary `Eq` / `Lt` / `Gt` dispatch after MIR values are materialized
- tuple-valued `materialize_value(...)` paths before tuple lowering lookup
- struct field `Eq` / `Ord` recursion
- variant payload `Eq` / `Ord` recursion
- struct-build field type selection
- variant payload carrier selection

And it still intentionally keeps legacy flat tuple metadata as the primary source
in a few narrower places:

- tuple comparison / ordering recursion at individual tuple-slot level
- tuple lowering cache keys and tuple-shape equality checks
- variant pre-scan logic that merges multiple tuple payload cases into one
  lowering record

Those remaining flat-metadata paths are not accidental. They still operate on
slot-level tuple metadata without an existing standalone `FlatMirShape` value, so
they have been left in place until that representation is promoted cleanly rather
than patched ad hoc.

Current analyzer-side shape refresh rules are also important here:

- generic struct instantiation and generic struct refresh recompute `field.shape_index`
  from the instantiated field type, rather than inheriting a template-era shape index
- generic variant instantiation and generic variant refresh recompute
  `payload_shape_index` from the instantiated payload type for the same reason
- generic function instantiation recomputes expression `shape_index` after named
  struct/variant instances are concretized, so inlined generic call results do not
  retain template-era shape indices
- concrete generic struct / variant instances now also record per-type-argument
  `instance_shape_indices[]`, instead of only base kind + flat tuple metadata
- helper paths that reconstruct generic bindings from existing concrete instances
  are expected to preserve those `instance_shape_indices[]`, not silently drop
  back to shape-less bindings
- declaration-side `TypeArgRef.shape_index` is no longer just transitional storage:
  deferred named-type instantiation and generic-binding reconstruction helpers are
  expected to reuse an existing `shape_index` first, and only recompute shape when
  a legacy path still leaves it absent
- analyzer-side generic binding reconstruction is now partially centralized through
  `fill_bound_binding_from_type_metadata(...)`; current high-traffic users include:
  explicit generic `StructInit`, explicit generic `VariantCase`, function
  parameter/return named-generic paths, and declaration-side struct-field / variant
  payload named-generic paths
- that helper coverage now also extends into lower-frequency reconstruction paths:
  explicit call-site `generic_bindings`, imported target instance bindings,
  concrete instance refresh, concrete generic type-ref instantiation,
  impl generic binding reconstruction, named-instance concretization, and the
  `Self` fallback binding used during method-body instantiation
- transitional tuple metadata remains semantically relevant during this migration:
  `tuple_types[]`, `tuple_variant_indices[]`, and `tuple_struct_indices[]` must
  stay in sync across generic binding, named type concretization, and instance reuse

This matters because `carrier_ready` is only meaningful if the shape attached to
an instantiated field / payload / expression is itself the instantiated shape.
If template-era shape indices leak through, MIR may stay artificially conservative
even when the concrete type graph is already safe to consume.

The same is true for the flat tuple compatibility layer:

- tuple elements with `Variant` kind must use `tuple_variant_indices[i]`
- tuple elements with `Struct` kind must use `tuple_struct_indices[i]`
- generic struct / variant instance equality and reuse must compare both arrays,
  not only the variant-side indices

Until recursive `TypeShape` fully replaces the old tuple metadata, these flat
arrays remain part of the implementation contract and cannot be treated as
optional compatibility trivia.

The current observed consequence is:

- simple concrete type-decl paths such as `(Box, i32)` can now become `carrier_ready`
- imported nested generic payload paths such as `Result<Box<Result<i32>>>` can also
  become `carrier_ready` once their instantiated payload shapes are recomputed
- the generic-instance readiness path now has an explicit shape-based chain:
  HIR `instance_shape_indices[]` -> MIR `instance_shape_indices[]` ->
  MIR fixed-point `carrier_ready` -> lowering-side generic-instance gates
- analyzer helper code is in a mixed state:
  high-frequency generic-binding paths now prefer existing `shape_index` values,
  and several formerly low-frequency paths now share the same reconstruction helper;
  remaining outliers are expected to be genuinely specialized sites rather than the
  old repeated "copy flat metadata then recompute shape" pattern
- readiness is still allowed to remain conservative where the recursive shape is not
  yet fully propagated or where lowering still depends on legacy compatibility data

But the migration is not complete yet:

- recursive shape metadata is the semantic source of truth
- legacy flat tuple metadata still remains a compatibility layer for older lowering paths
- lowering must continue to prefer explicit safety gates over guessing readiness from
  `Unknown`, missing indices, or similar indirect signals

#### 11.1.7 Error Model and Pipeline Short-Circuiting

Rut's surface language should not force ordinary users to spell `Result<T, E>`
everywhere, but the compiler still needs one clear semantic failure model.

The intended split is:

- **Surface language** may use ordinary values, `nil`, and explicit `error(...)`
- **HIR** may normalize error-capable expressions and functions to `Result<V, Error>`

This means `Result<V, Error>` remains the compiler's internal semantic model even
when the user-facing syntax is lighter and more DSL-like.

The built-in `Error` type is standard language infrastructure:

- it is not the same as `nil`
- it may carry structured information
- it is the common failure payload used by the compiler's normalized `Result<V, Error>` form

The semantic distinction still matters:

- `nil` is the absence of a usable value on the value channel
- `error(...)` is structured failure information
- HIR is allowed to preserve and analyze that failure information explicitly

But the ergonomic value-flow surface intentionally works in terms of the value
channel:

- `|` and `.or(default)` are value-oriented syntax
- they optimize for "keep going if a usable value exists"
- in these forms, failure behaves like "no usable value", so the expression flows as `nil`

This is a deliberate usability tradeoff for gateway-style code, where many failures
are tolerated locally and only need logging, counting, or fallback behavior.

Explicit failure handling remains available:

- `guard let` is the primary entry into explicit error handling
- future `match` may expose error details more directly where needed

So Rut keeps one semantic failure model for the compiler, while allowing the common
surface syntax to treat failure as absence when that is the more ergonomic thing to do.

#### 11.1.8 Standard Error Model

Ordinary users should not need to define a custom error type just to return a
failure. Rut therefore needs a standard concrete `Error` struct in the language.

The standard `Error` should contain at least:

- `code`
- `msg`
- `file`
- `func`
- `line`

`code` and `msg` are the semantic identity of the error. `file`, `func`, and
`line` are source-origin diagnostics and should normally be injected automatically
by the compiler at the error-construction site.

The preferred ordinary-user construction path is a lightweight built-in
constructor:

- `error(.badRegex)`
- `error(.badRegex, "invalid regex")`

That constructor builds the standard `Error` value and fills source-location fields
automatically.

Rut should also have an `Error` protocol so advanced users can define custom error
types. Those custom types are not the default path; they are for library authors
and specialized modules that need more payload or domain-specific structure.

The standard `Error` struct should satisfy the `Error` protocol, and custom error
types may satisfy it as well, typically by composition rather than inheritance.

Finally, error-side type aggregation is allowed:

- if a function may produce multiple distinct error kinds, the compiler may
  aggregate the error side into a generated variant
- this auto-aggregation applies to **errors**, not to ordinary success return values
- ordinary success return values still require an explicit `variant` declaration if
  multiple normal shapes are intended

This gives Rut a simple default error path for most users while still allowing
precise typed error handling where it is actually useful.

#### 11.1.9 Variants and Match

Rut needs a first-class way to represent "one of several named cases", but it does
not need the full complexity of a Rust-sized enum system on day one.

The language should therefore have a `variant` keyword as part of the core syntax.

The intended use is:

- model mutually exclusive named cases
- optionally attach payload values to each case
- use `match` as the general branching construct over those cases

Important constraints:

- ordinary success return values do **not** automatically become a variant
- if a function needs multiple normal return shapes, the user must declare an explicit `variant`
- error returns may still be aggregated by the compiler as part of the error model

`match` is not variant-only magic. It is the language's general multi-way branching
construct:

- `if` is the lightweight boolean special case
- value dispatch that might look like a traditional `switch` is handled by `match`
- variant dispatch is also handled by `match`

So Rut does not need a separate `switch` keyword.

The first-stage `variant` / `match` surface should stay deliberately small.

**Variant case spelling**

- short form: `.timeout`
- fully qualified form: `NetError.timeout`
- bare names like `timeout` are not accepted as variant cases

This keeps variant-case references explicit without forcing full qualification in
every local context.

**First-stage `match` forms**

Rut should support (there is no `case` keyword — arms use the uniform
`pattern => ...` form from §3.2.2):

- `match expr { ... }`
- `<literal> => ...`
- `.variant => ...`
- `.variant(x) => ...`
- `Type.variant => ...`
- `_ => ...` as fallback

Payload binding is intentionally shallow in the first stage:

- single-layer payload binding is supported
- deep nested destructuring is not
- OR-patterns, range patterns, and pattern guards (`pattern if cond =>`) are not part of the first stage

`match` is initially a statement form. It does not need to be an expression in the
first implementation.

**Exhaustiveness**

For `variant`-based matches, the compiler should require either:

- all cases are covered, or
- a `_ =>` fallback is present

That exhaustiveness check is one of the main reasons to have `match` at all, and it
should be part of the first-stage design.

#### 11.1.10 Compile-Time Branching

Rut should support compile-time branching in a small, explicit form.

The preferred surface direction is:

- `if const` for compile-time boolean branching
- `match const` for compile-time multi-way branching

In both forms, the condition / matched value must be known at compile time. If it
is not, compilation fails.

These are true compile-time branches, not ordinary runtime branches that are merely
optimized later.

That means:

- they are valid for type-based specialization
- they are valid for compile-time configuration values
- they are valid for results produced by compile-time-evaluable pure functions
- they are not valid for request data or other runtime-only values

To preserve their usefulness for specialization, only the selected branch is
required to pass full semantic and type checking for the current instantiation. An
unselected branch does not need to type-check under that same compile-time choice.

This provides enough power for specialization and compile-time configuration
without turning the language into a large meta-programming system.

#### 11.1.11 Response Shorthand

HTTP responses are common enough in Rut that they should have a high-level surface
form instead of always being assembled from raw status/header/body pieces.

Rut should support response shorthand such as:

- `return .ok`
- `return .unauthorized`
- `return .notFound`
- `return .ok(json: user)`
- `return .tooManyRequests(retryAfter: 1m)`

These forms are not just printer sugar. The compiler should preserve them as
high-level response intent in HIR, then lower them later to concrete status codes,
headers, and body construction.

That keeps routine gateway code compact while still giving the compiler explicit
HTTP semantics instead of losing intent too early.

### 11.2 Rutlang IR (RIR)

A lightweight, flat, typed IR between MIR and LLVM IR. Each route handler compiles to one RIR function — a linear sequence of blocks with explicit control flow.

#### 11.2.1 Why RIR

```
1. Optimization target
   AST is tree-shaped, hard to optimize
   LLVM IR is too low-level for domain-specific optimizations
   RIR is flat + typed — easy to analyze and transform

2. Backend independence
   RIR → LLVM IR  (current)
   RIR → Cranelift (future option)
   RIR → custom bytecode VM (future option)
   Switch backend without touching parser/type checker/optimizer

3. Debuggability
   --dry-run / --emit-rir dumps human-readable IR
   Users and developers can see exactly what the compiler produced
   Each instruction maps back to source location

4. Instrumentation insertion point
   Compiler inserts metrics/tracing/debug code at RIR level
   Optimization passes can then simplify (e.g., remove debug code in release mode)
```

#### 11.2.2 RIR Design

```
RIR concepts:
  Function   — one per route handler (after full inlining)
  Block      — a basic block: sequence of instructions, ends with a terminator
  Instruction — typed operation
  Terminator — branch, return, yield (I/O suspend point)
```

```
RIR types (mirrors language types):
  str, i32, i64, u32, u64, f64, bool
  ByteSize, Duration, Time, IP, CIDR, MediaType, StatusCode, Method
  Struct(name, fields)
  Optional(inner)
  Bytes
```

```
RIR instruction set:

  // --- Values ---
  %0 = const.str "Bearer "
  %1 = const.i32 401
  %2 = const.duration 5m
  %3 = const.bytesize 1mb

  // --- Request access ---
  %4 = req.header "Authorization"         // → Optional(str)
  %5 = req.param "id"                     // → str
  %6 = req.method                         // → Method
  %7 = req.path                           // → str
  %8 = req.remote_addr                    // → IP
  %9 = req.content_length                 // → ByteSize
  %10 = req.cookie "session_id"           // → Optional(str)

  // --- Request mutation ---
  req.set_header "X-User-ID", %val
  req.set_path %new_path

  // --- Operations ---
  %11 = str.has_prefix %4, %0             // → bool
  %12 = str.trim_prefix %4, %0            // → str
  %13 = str.interpolate [%6, "\n", %7]    // → str  (string interpolation)
  %14 = cmp.eq %6, Method.GET             // → bool
  %15 = cmp.gt %9, %3                     // → bool (ByteSize > ByteSize)
  %16 = time.now                          // → Time
  %17 = time.diff %16, %ts               // → Duration
  %18 = cmp.gt %17, %2                    // → bool (Duration > Duration)
  %19 = ip.in_cidr %8, 10.0.0.0/8        // → bool
  %20 = hash.hmac_sha256 %secret, %13    // → Bytes
  %21 = bytes.hex %20                     // → str
  %22 = jwt.decode %12, %secret            // → Result(Claims) — built-in
  // --- Struct operations ---
  %23 = struct.field %user, "role"         // → str
  %24 = struct.create User { id: %s1, role: %s2 }  // → User
  %25 = body.parse Order                  // → Order (parse request body)
  %26 = array.len %items                  // → i32
  %27 = array.get %items, %idx            // → OrderItem

  // --- Control flow (terminators) ---
  br %cond, block_then, block_else         // conditional branch
  jmp block_next                           // unconditional jump
  ret.status 401                           // return HTTP status
  ret.status 429, { Retry-After: %w }      // return with headers
  ret.forward %upstream, { timeout: 10s }    // proxy to upstream

  // --- I/O (suspend points → state machine boundaries) ---
  %28 = yield.http_get "http://auth/verify", { Authorization: %token }
  %29 = yield.http_post "http://svc/create", { Body: %data }
  %30 = yield.forward %upstream

  // --- Debug/instrumentation (inserted by compiler) ---
  trace.func_enter "auth"
  trace.func_exit "auth", %result
  trace.io_start "http://auth/verify"
  trace.io_end "http://auth/verify", %status, %duration
  metric.histogram_record %route_hist, %duration
  metric.counter_incr %route_counter
  accesslog.write %entry
```

#### 11.2.3 Example: auth function after inlining into a route

Source (`@rateLimit` is top-level route metadata, not a user helper):
```swift
@rateLimit(limit: 100, window: 1m)
route GET "/users/:id" {
    let user = auth(req, role: "user")
    req.set("X-User-ID", req.params.id)
    return forward(userService)
}
```

RIR output (after inlining + state machine construction):

```
func handle_get_users_id(req: Request)
  rate_limit = { limit: 100, window: 1m, by: ip, scope: shard }
{
  entry:
    // -- inlined: auth --
    %token = req.header "Authorization"
    br %token.is_nil, block_reject_401, block_check_prefix

  block_check_prefix:
    %has_pfx = str.has_prefix %token, "Bearer "
    br %has_pfx, block_decode_jwt, block_reject_401

  block_decode_jwt:
    %raw = str.trim_prefix %token, "Bearer "
    %secret = const.str env("JWT_SECRET")
    %claims = jwt.decode %raw, %secret
    br %claims.is_nil, block_reject_401, block_check_exp

  block_check_exp:
    %now = time.now
    %expired = cmp.lt %claims.exp, %now
    br %expired, block_reject_401_expired, block_check_role

  block_check_role:
    %role = struct.field %claims, "role"
    %role_ok = cmp.eq %role, "user"
    br %role_ok, block_auth_ok, block_reject_403

  block_auth_ok:
    req.set_header "X-User-ID", %claims.sub
    req.set_header "X-User-Role", %claims.role

    // -- remaining handler --
    %id = req.param "id"
    req.set_header "X-User-ID", %id
    ret.forward upstream("users"), { timeout: 10s }

  block_reject_401:
    ret.status 401

  block_reject_401_expired:
    ret.status 401, "token expired"

  block_reject_403:
    ret.status 403

}
```

```
State machine (derived from yield points):

  This example has no yield (jwt_decode is synchronous; rate limiting is
  enforced from Function metadata before handler dispatch).
  If auth called an external HTTP service instead:

    %res = yield.http_get "http://auth/verify", { Authorization: %token }

  Then the function splits into two states:
    state 0: everything before yield → submit HTTP request → suspend
    state 1: everything after yield → process response → continue or proxy

  The yield instruction is where the RIR optimizer inserts the state boundary.
```

#### 11.2.4 RIR Optimization Passes

```
Pass 1: Dead Code Elimination
  Remove blocks that are never reached
  Remove unused variable assignments

Pass 2: Constant Folding
  env("KEY") → resolved at compile time if env is known
  const comparisons: cmp.eq "admin", "user" → false → simplify branch

Pass 3: State Machine Construction
  Find all yield instructions
  Split function into states at yield boundaries
  Generate state enum and dispatch switch

Pass 4: Instrumentation Insertion
  Insert trace.* instructions at func/IO boundaries
  Insert metric.* instructions at entry/exit
  Insert accesslog.write at function exit
  (All guarded by debug_flags check — branch predicted not-taken)

Pass 5: Guard Coalescing
  Multiple sequential guards on the same rejection code:
    br %a, reject_401, next1
    br %b, reject_401, next2
  → merge into single block with combined condition
```

#### 11.2.5 RIR Dump (--emit-rir)

```
$ rut --emit-rir gateway.rut

=== handle_get_users_id ===
  params: [:id]
  io_points: 0 (all sync)
  states: 1
  blocks: 7
  instructions: 18

  entry:
    %0 = req.header "Authorization"             // line 42
    br %0.is_nil, block_reject_401, block_1     // line 42 (guard)
  block_1:
    %1 = str.has_prefix %0, "Bearer "           // line 43
    br %1, block_2, block_reject_401            // line 43 (guard)
  ...

=== handle_post_orders ===
  params: []
  io_points: 0
  states: 1
  blocks: 10
  instructions: 26
  ...
```

### 11.2 LLVM Dependency Management

LLVM is the heaviest dependency. Strategies:

| Strategy | Binary Size | Notes |
|----------|-------------|-------|
| Dynamic link `libLLVM.so` | Runtime < 1MB | System install required |
| Static link (X86 target + ORC only) | ~15MB | Custom LLVM build |
| Replace with Cranelift (via C API) | ~3MB | Lighter, faster compile, Rust FFI |
| Custom bytecode VM | 0 external deps | Lower performance ceiling |

Recommended: start with LLVM ORC JIT (dynamic link), consider Cranelift if LLVM proves too heavy.

### 11.3 C++ Integration API

```cpp
class RutEngine {
public:
    // Compile .rut source, returns compile result (errors or config)
    CompileResult compile(std::string_view source);

    // Atomically load new config to all shards (RCU swap)
    void reload(CompiledConfig* config);

    // Current config version
    uint64_t current_version() const;
};

// No register_native / FFI — Rutlang communicates with external systems
// via HTTP (get/post), TCP (tcp()), or UDP (udp()). See §3.4.21 No FFI.
```

### 11.4 LSP Server

A Language Server Protocol implementation for editor support and LLM integration:

- Autocompletion (directives, header names, upstream references)
- Diagnostics (type errors, route conflicts)
- Hover (type information)
- Go-to-definition (upstream, middleware references)

---

## 12. Dependencies

### 12.1 Full Dependency List

| Dependency | Type | Size | Purpose |
|------------|------|------|---------|
| Linux kernel syscalls | OS | 0 | io_uring (6.0+) or epoll (3.9+), mmap, clone3, timerfd, signalfd, inotify |
| musl libc | Static link | ~600KB | C standard library (needed by LLVM) |
| Custom HTTP parser | Built-in | ~500-800 lines C++ | HTTP/1.1 request parsing (SIMD-accelerated, zero-copy, strict mode) |
| LLVM ORC JIT | Dynamic link | ~50MB .so | JIT compilation |
| Vectorscan | Static link | ~2MB | Regex engine (multi-pattern, SIMD-accelerated, O(n) guaranteed) |
| libdeflate | Static link | ~100KB | gzip response compression (3-5x faster than zlib) |
| google/brotli | Static link | ~300KB | Brotli response compression |
| zstd | Static link | already in tree | zstd response compression + access log compression |
| Custom DNS client | Built-in | ~200 lines C++ | Async DNS resolution (UDP over io_uring, A/AAAA queries) |
| OpenSSL / BoringSSL (Phase 2) | Dynamic link | ~3MB .so | TLS for inbound + outbound |

Total external dependencies: **7-9**

### 12.2 What We Don't Depend On

```
❌ C++ standard library (std::)
❌ libevent / libev / libuv
❌ liburing (own wrapper)
❌ protobuf / grpc
❌ OpenSSL (Phase 1)
❌ tcmalloc / jemalloc (own allocators)
❌ heavy package manager / dependency solver
```

---

## 13. External Service Integration

### 13.1 Overview

The DSL's HTTP calls and proxy operations depend on a set of runtime capabilities to work reliably in production. These are transparent to the user — the language syntax stays simple while the runtime handles complexity.

```swift
// User writes:
let res = get http://auth-service/verify {
    Authorization: token
    Timeout: 3s
}

// Runtime handles:
//  1. DNS: resolve "auth-service" → IP(s)
//  2. Connection pool: reuse existing connection or create new one
//  3. TLS: if https://, perform TLS handshake (or reuse session)
//  4. Timeout: enforce connect + read + total timeouts
//  5. Retry/breaker: if using a service declaration
```

### 13.2 DNS Resolution

Async DNS resolution, never blocking the event loop.

```swift
// Optional global DNS configuration
dns {
    servers: ["8.8.8.8", "8.8.4.4"]    // default: system resolv.conf
    cache: 30s                          // minimum cache TTL
    timeout: 2s                         // DNS query timeout
}
```

```
Implementation:
  - Custom async DNS client (~200 lines C++, UDP over io_uring)
  - Per-shard DNS cache (share-nothing)
  - Cache key: hostname → [IP], expires at max(DNS TTL, configured minimum)
  - On cache miss: async resolve, queue pending requests for same hostname
  - On failure: use last known good result (with warning log)
  - Supports /etc/hosts and /etc/resolv.conf
  - Phase 1: A/AAAA records (sufficient for Kubernetes)
  - Phase 2: SRV records (for service discovery)
```

### 13.3 Connection Pooling

Per-shard, per-host:port connection pools for both proxy and HTTP calls.

```swift
// Global connection pool configuration (optional, sensible defaults)
connections {
    maxIdlePerHost: 16       // keep-alive idle connections per host
    maxConnsPerHost: 128     // max total connections per host (active + idle)
    idleTimeout: 90s         // close idle connections after this
}

// Upstream-specific override
let users = upstream {
    "10.0.0.1:8080"
    maxConns: 256
    idleTimeout: 60s
}
```

```
Implementation:
  struct ConnPool {                         // per-shard
      host_port → {
          idle: ListNode[Connection]        // intrusive list of idle conns
          active_count: u32
          max_idle: u16
          max_total: u16
      }
  }

  HTTP call / proxy flow:
    1. Lookup pool[host:port]
    2. Idle connection available → reuse (remove from idle list)
    3. No idle + under max → create new connection
    4. At max → queue request, wait for a connection to become available
    5. Response complete + keep-alive → return to idle list
    6. Response complete + close → destroy connection
    7. Timer wheel checks idle connections → close if expired
```

### 13.4 TLS for Outbound Connections

```swift
// Automatic: http:// = plaintext, https:// = TLS
let res = get https://api.stripe.com/charges {
    Authorization: "Bearer \(env("STRIPE_KEY"))"
}
// TLS handshake automatic, server cert verified against system CA store

// mTLS (client certificate):
let res = get https://internal-service/data {
    ClientCert: tls(cert: env("CLIENT_CERT"), key: env("CLIENT_KEY"))
}

// Skip verification (dev only — compiler emits warning):
let res = get https://dev-service/test {
    TLSVerify: false     // ⚠️ warning: insecure TLS
}
```

```
Implementation:
  - OpenSSL / BoringSSL via BIO_s_mem (non-blocking, io_uring compatible)
  - Per-shard TLS session cache (per host:port)
    → Reuse TLS session on reconnect: saves ~5ms per connection
  - Connection pool preserves TLS state
    → Idle keep-alive connections retain TLS session
  - Phase 1: No TLS outbound (use http:// to internal services)
  - Phase 2: TLS outbound with session caching
  - Phase 3: mTLS outbound
```

### 13.5 Timeout Control

```swift
// Simple: one timeout covers everything
let res = get http://auth-service/verify {
    Timeout: 3s
}

// Fine-grained:
let res = get http://slow-service/compute {
    ConnectTimeout: 1s       // TCP handshake
    ReadTimeout: 30s         // waiting for response data
    Timeout: 60s             // total wall-clock limit
}

// Upstream-level defaults:
let users = upstream {
    "10.0.0.1:8080"
    connectTimeout: 1s
    readTimeout: 10s
    sendTimeout: 5s
}

// Request-level timeout via any(wait()):
let h = submit forward(userService, buffered: true)
// 5s deadline, cancel if exceeded
guard let resp = any(wait(h, 5s)) else { return 504 }
```

```
Implementation:
  - Total timeout: single timer wheel entry per request
  - Connect timeout: timer set when io_uring connect SQE submitted
  - Read timeout: timer reset on each data chunk received
  - Send timeout: timer reset on each data chunk sent
  - All timers go through the per-shard timer wheel (O(1) operations)
  - Timeout hit → cancel io_uring SQE → return 504 (proxy) or error (HTTP call)
```

### 13.6 Service Declarations

For external services called frequently, `service` provides retry, circuit breaker, and connection pool configuration in one place — more than a raw HTTP call, less than an `upstream`.

```swift
// Declare a service with resilience policies
let authService = service("http://auth-service") {
    timeout: 3s
    retry: .on([502, 503], count: 2, backoff: 100ms)
    breaker: .consecutive(failures: 5, recover: 30s)
    maxConns: 64
}

// Use like a typed HTTP client — same syntax, but with retry + breaker:
func auth(_ req: Request, role: string) -> User {
    let token = req.authorization.or("")
    guard !token.isEmpty else { respond 401 }

    let res = authService.get("/verify") {
        Authorization: token
    }
    // If auth-service returns 502 → auto-retry up to 2 times
    // If 5 consecutive failures → circuit opens → instant 503 for 30s

    guard let res else { respond 503 }
    guard res.status == 200 else { respond 401 }
    return res.body(User)
}

// Raw HTTP calls (no retry, no breaker) still work:
let res = get http://one-off-service/check { }
```

```
Comparison:

  Raw HTTP call         service declaration       upstream
  ──────────────        ────────────────────      ────────
  No retry              Retry ✅                  Retry ✅
  No breaker            Breaker ✅                Breaker ✅
  No health check       No health check           Health check ✅
  Single target         Single base URL           Multiple targets
  For: one-off calls    For: frequently called    For: proxy destinations
                        external services
```

### 13.7 Service Discovery

```swift
// Phase 1: Static addresses + DNS A records (Kubernetes-ready)
let users = upstream { "user-service.default.svc:8080" }
// DNS resolves to Pod IPs, refreshed per DNS TTL

// Phase 2: DNS SRV records
let users = upstream {
    discover: .dnsSrv("_http._tcp.user-service")
    balance: .roundRobin
}
// SRV records provide port + weight + priority

// Phase 3: External discovery via HTTP call to Consul/etcd API
// Periodic refresh using timer:
timer refreshUsers, every: 10s, shard: 0 {
    let res = get http://consul:8500/v1/health/service/user-service
    guard let res else { return }
    // update upstream targets from Consul response
}
```

### 13.8 Implementation Phases

```
                        Phase 1         Phase 2         Phase 3
────────────────────────────────────────────────────────────────
DNS resolution          ✅ A/AAAA       SRV records     -
DNS caching             ✅ per-shard    -               -
Connection pooling      ✅ per-shard    -               -
Connection pool config  ✅ defaults     user-tunable    -
Timeout (total)         ✅              -               -
Timeout (fine-grained)  -              ✅               -
HTTP outbound           ✅ http://      -               -
HTTPS outbound          -              ✅ OpenSSL       mTLS
TLS session caching     -              ✅               -
Retry (upstream)        ✅              -               -
Retry (service)         -              ✅               -
Breaker (upstream)      ✅              -               -
Breaker (service)       -              ✅               -
Service discovery       DNS A           DNS SRV         extern (Consul, etc.)
fire (async calls)      ✅              -               -
```

---

## 14. Observability and Debugging

### 13.1 Design Principles

- Zero external dependencies (no OpenTelemetry SDK, no Prometheus client library)
- Zero overhead on normal requests (~10ns: one branch + histogram update)
- Debug mode is per-request, triggered by header, no global perf impact
- All metrics per-shard, lock-free, aggregated on read
- Compiler auto-instruments I/O points — user doesn't write tracing code

### 13.2 Language-Level Logging

```swift
// Structured logging — built into the language
func auth(_ req: Request, role: string) -> User {
    let token = req.authorization.or("")
    guard !token.isEmpty else {
        log.warn("missing auth token", path: req.path, addr: req.remoteAddr)
        respond 401
    }

    let res = get http://auth/verify {
        Authorization: token
    }
    guard let res else { respond 502 }

    guard res.status == 200 else {
        log.error("auth service rejected",
            status: res.status, path: req.path, upstream: "auth-service")
        respond 401
    }

    guard let user = res.body(User) else { respond 502 }
    log.debug("auth ok", userId: user.id, role: user.role)
    return user
}

// Log levels: debug, info, warn, error
// Level switchable at runtime without reload
// debug level can be filtered by path pattern
```

### 13.3 Request-Level Tracing

```swift
// Automatic: compiler inserts trace points at every func call and I/O point
// No user code needed for basic tracing

// Manual spans for fine-grained tracing:
func processOrder(_ req: Request) {
    trace.span("validate_order") {
        guard let order = req.body(Order) else { respond 400 }
        guard !order.items.isEmpty else { respond 400 }
    }

    trace.span("check_inventory") {
        let res = post http://inventory/check {
            Body: order.items
        }
        guard let res else { respond 503 }
        guard res.status == 200 else { respond 503 }
    }

    forward(orders)
}
```

### 13.4 Per-Request Debug Mode

```
Triggered by X-Debug header — only affects that single request:

  X-Debug: true     → verbose log output for this request
  X-Debug: trace    → full trace with timing in response header
  X-Debug: timing   → per-step timing breakdown

Curl example:
  curl -H "X-Debug: trace" http://gateway/users/123

Response includes X-Debug-Trace header:
  X-Debug-Trace: [
    {"fn": "requestId",  "duration_us": 2,    "result": "pass"},
    {"fn": "cors",       "duration_us": 1,    "result": "pass"},
    {"fn": "auth",       "duration_us": 1234, "result": "pass",
     "io": [{"url": "http://auth/verify", "status": 200, "duration_us": 1200}]},
    {"fn": "rateLimit",  "duration_us": 1,    "result": "pass", "count": 42},
    {"fn": "proxy",      "duration_us": 5678, "upstream": "users",
     "target": "10.0.0.1:8080", "status": 200}
  ]

Implementation:
  Compiler inserts at every func/I/O point:
    if (c->debug_flags) emit_trace_event(c, ...);
  Normal requests: one branch, predicted not-taken, ~0 cost
  Debug requests: ~1-5μs overhead to record full trace
```

### 13.5 Runtime Metrics

Per-shard, lock-free counters and histograms. Aggregated when read.

```
Request metrics:
  requests_total                 // by method + path pattern + status code
  requests_active                // currently processing
  request_duration_us            // latency histogram (log-scale buckets)

Connection metrics:
  connections_total              // total accepted
  connections_active             // currently active
  connections_idle               // keep-alive waiting

Upstream metrics:
  upstream_requests_total        // by upstream name + target + status
  upstream_duration_us           // upstream response latency histogram
  upstream_connections_active    // active connections to upstream
  upstream_health                // per-target health status

Memory metrics:
  memory_arena_used              // scratch arena current usage
  memory_slices_used             // slice pool usage
  memory_slices_free             // slice pool available
  memory_connections_used        // connection slab usage

I/O backend metrics (io_uring):
  iouring_sq_pending             // SQ entries pending submission
  iouring_cq_pending             // CQ entries pending consumption
  iouring_buf_available          // provided buffer ring available count
```

Latency histogram uses log-scale buckets:
```
  [<100μs, <500μs, <1ms, <5ms, <10ms, <50ms, <100ms,
   <500ms, <1s, <5s, ≥5s]

  Per-shard array, each bucket is a u64 counter
  Recording: one subtract + clz to find bucket, one atomic increment
  ~3ns per request
```

### 13.6 Access Log

High-performance access log — separate from application logging:

```
Architecture:
  Each shard writes to a per-shard ring buffer (64KB)
  Background thread (not on any shard) batch-flushes to file/stdout
  Zero allocation, zero syscall on the request path

Format: one JSON line per request
  {
    "ts": "2026-03-20T15:30:00.123Z",
    "method": "GET",
    "path": "/users/123",
    "status": 200,
    "duration_us": 1234,
    "req_size": 256,
    "resp_size": 1024,
    "addr": "10.0.0.5",
    "upstream": "users",
    "upstream_duration_us": 1100,
    "request_id": "abc-123",
    "shard": 3
  }
```

Access logging is automatic — the runtime logs every request. Format and output
are controlled by runtime flags (`--access-log-format`, `--access-log-output`),
not in .rut source files.

### 13.7 Internal Endpoints

Built-in HTTP endpoints for runtime inspection. Can be on a separate port or protected by middleware.

```swift
// Option A: separate internal port (recommended)
listen :9090

// Option B: on main port with access control
route {
    /internal {
        ipAllow(req, cidrs: [10.0.0.0/8])

        get /metrics  { metrics() }     // Prometheus format
        get /health   { health() }      // JSON health status
        get /shards   { shards() }      // per-shard state
        get /upstreams { upstreams() }   // upstream status
        get /routes   { routes() }      // route table + hit counts
        post /log-level {               // dynamic log level
            setLogLevel(req.body(LogLevelConfig))
            return 200
        }
    }
}
```

Endpoint details:

```
GET /internal/metrics — Prometheus exposition format
  # TYPE requests_total counter
  requests_total{method="GET",path="/users/:id",status="200"} 12345
  # TYPE request_duration_us histogram
  request_duration_us_bucket{le="100"} 1000
  request_duration_us_bucket{le="500"} 4500

GET /internal/health — JSON
  {
    "status": "healthy",
    "uptime": "3d 4h 22m",
    "version": 3,                    // config version (reload count)
    "shards": 8,
    "connections": { "active": 1234, "idle": 98000 },
    "upstreams": {
      "users": { "healthy": 2, "unhealthy": 0 },
      "orders": { "healthy": 1, "unhealthy": 0 }
    }
  }

GET /internal/shards — per-shard breakdown
  {
    "shards": [
      {
        "id": 0, "core": 0,
        "connections": { "active": 150, "idle": 12300 },
        "memory": {
          "arena": "12KB / 64KB",
          "slices": "45 / 1024",
          "connections": "12450 / 16384",
          "provided_buffers": "1980 / 2048"
        },
        "requests": { "total": 1234567, "active": 150 },
        "iouring": { "sq_pending": 3, "cq_pending": 0 }
      }
    ]
  }

GET /internal/upstreams — upstream target status
  {
    "users": {
      "targets": [
        {"addr": "10.0.0.1:8080", "healthy": true, "active_conns": 12,
         "weight": 3, "requests": 500000, "avg_latency_us": 1200},
        {"addr": "10.0.0.2:8080", "healthy": true, "active_conns": 4,
         "weight": 1, "requests": 170000, "avg_latency_us": 1350}
      ]
    }
  }

GET /internal/routes — route table with stats
  {
    "routes": [
      {"method": "GET", "pattern": "/health", "hits": 50000, "avg_us": 5},
      {"method": "GET", "pattern": "/users/:id", "hits": 800000, "avg_us": 1500},
      {"method": "POST", "pattern": "/orders", "hits": 200000, "avg_us": 3200}
    ],
    "config_version": 3
  }

POST /internal/log-level — dynamic log level change
  { "level": "debug" }                              // global
  { "level": "debug", "path": "/orders/*" }          // per-path filter
  No reload needed. Takes effect immediately on all shards.
```

### 13.8 Dry-Run Mode

Compile-time validation without starting the server:

```
$ rut --dry-run gateway.rut

✓ Parsed 3 files
✓ Type check passed
✓ Routes:
    GET  /health        → inline (no I/O)
    GET  /users/:id     → 2 I/O points (auth verify, proxy)
    POST /users         → 2 I/O points (auth verify, proxy)
    POST /orders        → 2 I/O points (auth verify, proxy)
✓ State machines:
    handle_get_users_id:  3 states
    handle_post_users:    3 states
    handle_post_orders:   3 states
✓ No route conflicts
✓ All upstreams referenced
✓ Estimated memory per shard: ~28MB
```

### 13.9 Compiler Auto-Instrumentation

The compiler automatically inserts instrumentation at key points. Users don't write tracing code for standard metrics.

```
What the compiler inserts for every route handler:

  Entry:
    record start timestamp
    increment requests_active
    check debug_flags (one branch, predicted not-taken)

  Each inlined func call (debug mode only):
    record func entry/exit timestamp
    record result (pass/reject)

  Each I/O point (always):
    record upstream URL, start/end timestamp, response status

  Exit:
    compute duration
    update latency histogram (one array increment, ~3ns)
    decrement requests_active
    increment requests_total[method][path][status]
    write access log entry to ring buffer

Overhead on normal (non-debug) requests:
    ~10ns total (timestamp + histogram + counter increments)
```

---

## 15. Implementation Phases

### Phase 1: Minimal Runtime (target: working proxy)

```
├── I/O backend: io_uring (~300 lines) + epoll (~250 lines) + abstraction (~100 lines)
├── Per-core shard threads (~200 lines)
├── Memory allocators: Arena + SlabPool + SlicePool (~500 lines)
├── Custom HTTP parser with SIMD (~500-800 lines)
├── Connection management + state machine (~1000 lines)
├── Static route table (hardcoded, no JIT yet) (~500 lines)
├── Proxy to upstream (~1000 lines)
├── Basic config loading (~500 lines)
└── Total: ~5050 lines C++

Deliverable: can accept HTTP requests, proxy to upstream, return responses.
```

### Phase 2: Language + JIT

```
├── Lexer + Parser for .rut (~2000 lines)
├── Type checker (~1500 lines)
├── LLVM IR codegen (~2000 lines)
├── JIT loading + hot reload (~1000 lines)
├── State machine transform (async → states) (~1000 lines)
├── Radix trie route compiler (~500 lines)
└── Total: ~8000 lines

Deliverable: .rut files compiled and loaded, hot reload works.
```

### Phase 3: Production Hardening

```
├── TLS termination (OpenSSL integration)
├── HTTP/2 support
├── Graceful shutdown + connection draining
├── Backpressure (watermark buffers)
├── Observability: access log (ring buffer + background flush)
├── Observability: per-shard metrics + Prometheus endpoint
├── Observability: per-request debug tracing (X-Debug header)
├── Observability: /internal/* inspection endpoints
├── Observability: compiler auto-instrumentation
├── Observability: dynamic log level control
├── TLS termination (OpenSSL integration)
├── HTTP/2 support
├── Graceful shutdown + connection draining
├── Backpressure (watermark buffers)
├── Resource limits (max connections, max request size)
├── NUMA awareness
└── LSP server for editor integration
```

---

## 16. Service Mesh Deployment (Sidecar Mode)

Rut can operate as a lightweight mesh sidecar, replacing Envoy in Istio-style
service meshes. The key insight: .rut source is compiled centrally, pre-compiled
native code is distributed to sidecars. Sidecars contain no compiler.

### 16.1 Architecture

```
┌──────────────────────────────────────────────────┐
│                 Rut Control Plane                 │
│                                                    │
│  Watch K8s resources → Generate .rut → Compile    │
│  LLVM JIT only here → Produce .so binaries        │
│  Watch Endpoints → Push target lists              │
│  Manage certs → Push cert updates                 │
└────────┬──────────────┬───────────────┬───────────┘
         │ push .so     │ push endpoints│ push certs
   ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
   │Rut Sidecar│  │Rut Sidecar│  │Rut Sidecar│
   │ no compiler│  │ no compiler│  │ no compiler│
   │ pure runtime│ │ pure runtime│ │ pure runtime│
   │ dlopen .so │  │ dlopen .so │  │ dlopen .so │
   │ atomic swap│  │ atomic swap│  │ atomic swap│
   └───────────┘  └───────────┘  └───────────┘
```

### 16.2 Sidecar Binary Composition

| Component | Control Plane | Sidecar |
|-----------|:---:|:---:|
| Lexer / Parser | ✅ | ❌ |
| Type Checker | ✅ | ❌ |
| RIR | ✅ | ❌ |
| LLVM JIT | ✅ | ❌ |
| io_uring / epoll runtime | ✅ | ✅ |
| HTTP Parser (SIMD) | ✅ | ✅ |
| Memory allocators (Arena/Slab/Slice) | ✅ | ✅ |
| State types (Cache/LRU/Set...) | ✅ | ✅ |
| TLS (BoringSSL) | ✅ | ✅ |
| Compression (zstd/brotli/libdeflate) | ✅ | ✅ |
| Vectorscan (regex) | ✅ | ✅ |

Estimated sidecar binary: **~5MB** (vs Envoy ~50MB).

### 16.3 Dynamic Update Protocol

Three update channels, all HTTP (Rut only speaks HTTP). Sidecar listens on
an internal port (e.g., :15000) for control plane messages.

```
1. Code push — route/middleware/policy changes (infrequent)
   POST /rut-sidecar/code
   Body: compiled .so binary
   Sidecar: dlopen → extract handler function pointers → RCU swap

2. Endpoint push — pod IP changes (frequent, seconds)
   POST /rut-sidecar/endpoints
   Body: { upstream: "userService", targets: ["10.0.0.1:8080", ...] }
   Sidecar: atomic update upstream target array, zero compilation

3. Certificate push — cert rotation (periodic, hours)
   POST /rut-sidecar/certs
   Body: { domain: "api.example.com", cert: "...", key: "..." }
   Sidecar: TLS context hot swap
```

### 16.4 Performance Comparison with Envoy

**Per-request processing:**

```
Envoy:  route table lookup → traverse filter chain → dynamic dispatch per filter
        → virtual function calls → runtime config interpretation
        ↑ every request pays interpretation cost

Rut:    compiled handler function pointer → direct jump → all middleware inlined
        → zero dynamic dispatch → zero config interpretation
        ↑ every request runs pre-compiled native code
```

**System call efficiency:**

```
Envoy:  libevent (epoll), 2 syscalls per I/O operation
Rut:    io_uring, batched submission, 1 syscall for N operations
```

**Memory model:**

```
Envoy:  malloc/free per request (headers, buffers, filter state)
Rut:    Arena bump-allocate, one pointer reset per request, zero free
```

**Estimated single-core performance:**

| Metric | Envoy | Rut (estimated) | Source of difference |
|--------|-------|-----------------|---------------------|
| Small request QPS | ~50K/core | ~150-200K/core | Inlined handlers + zero malloc + io_uring batch |
| P99 latency | ~200μs | ~50μs | No filter chain traversal, no allocation jitter |
| Throughput (streaming) | ~5Gbps/core | ~10-15Gbps/core | kTLS + splice zero-copy |
| Idle connection memory | ~50KB/conn | ~0B/conn | io_uring provided buffer ring |

**Cluster-wide sidecar overhead (1000 pods):**

| Resource | Envoy sidecars | Rut sidecars |
|----------|---------------|-------------|
| Total binary storage | 50GB | 5GB |
| Total idle memory | 50-150GB | 5-10GB |
| Startup time per sidecar | seconds (xDS sync) | milliseconds (dlopen) |
| Config error detection | runtime (may crash) | compile-time (pre-deployment) |

**10× lighter, 3-5× faster** — the architectural advantage of compiled DSL
over runtime config interpretation.

### 16.5 Kernel-Level Packet Filter (`firewall` block)

Rutlang provides a `firewall` block for network-level packet filtering. The
compiler generates eBPF bytecode from this block, loaded into the kernel's
XDP (eXpress Data Path) hook — the earliest packet processing point, before
TCP stack. Users don't need to know eBPF exists.

```swift
// firewall — network-level rules, compiled to eBPF, runs in kernel
firewall {
    // IP blacklist — line-rate filtering
    guard !blacklist.contains(src.ip) else { drop }

    // CIDR filtering
    guard !badNetworks.contains(src.ip) else { drop }

    // Port whitelist — only allow declared listen ports
    guard dst.port == 443 || dst.port == 80 else { drop }

    // SYN flood protection needs an XDP-compatible GCRA primitive. The
    // removed Counter.incr form is not replaced with Cache here: Cache has
    // only get/set, and no supported atomic firewall rate-update surface yet.

    // TLS fingerprinting — block known malware/scanner clients
    if src.isTLS {
        guard allowedDomains.contains(src.tls.sni) else { drop }
        guard !badFingerprints.contains(src.tls.ja3) else { drop }
    }

    // TCP fingerprint — drop non-standard OS signatures (scanners)
    guard src.ttl > 0 else { drop }

    pass
}
```

**`src` / `dst` members (packet-level, not HTTP-level):**

| Field | Type | Description |
|-------|------|-------------|
| `src.ip` | IP | Source IP address |
| `src.port` | Port | Source port |
| `dst.ip` | IP | Destination IP address |
| `dst.port` | Port | Destination port |
| `src.isSYN` | bool | TCP SYN flag |
| `src.isTLS` | bool | Is TLS ClientHello |
| `src.tls.sni` | string? | TLS SNI domain name |
| `src.tls.ja3` | string? | JA3 TLS client fingerprint |
| `src.ttl` | i32 | IP TTL value |
| `src.tcpWindow` | i32 | TCP window size |
| `packet.len` | i32 | Total packet length |

**Compiler constraints — `firewall` block can only:**
- Access `src` / `dst` / `packet` fields
- Use `Set<IP>`, `Set<CIDR>`, `Set<string>` state types
- `guard ... else { drop }` or `pass`
- No HTTP operations (`req`, `forward`, `auth`, regex)
- Violation → compile error: "packet block cannot access HTTP-level data"

**Actions:** `drop` (silently discard packet) or `pass` (continue to TCP stack).

**Two compilation targets from one .rut file:**

```
.rut source → compiler
    ├→ firewall { } block   → eBPF bytecode (.bpf) → kernel XDP hook
    └→ route { } block   → native code (.so)     → userspace L7 handler
```

**Impact — blocked traffic never reaches userspace:**

```
With firewall:    NIC → XDP eBPF → DROP (kernel, zero TCP, zero buffer)
                                → PASS → TCP stack → Rut L7 handler
                ↑ line-rate filtering: 10M+ packets/sec

Without:        NIC → TCP → accept → HTTP parse → guard → 403
                ↑ each blocked request consumes connection + CPU
```

**eBPF WAF capabilities:**

| Technique | How | Blocks |
|-----------|-----|--------|
| IP blacklist | `Set<IP>` → hash map | Known bad actors |
| CIDR filtering | `Set<CIDR>` → LPM trie | Network ranges, GeoIP |
| SYN flood | ⏳ Future strict atomic GCRA update in the XDP target | Connection exhaustion |
| Port filtering | `dst.port` check | Port scanning |
| SNI filtering | Parse ClientHello, check domain | Unknown domains (saves TLS CPU) |
| JA3 fingerprint | Hash ClientHello fields | Malware, scanners, bots |
| TCP fingerprint | TTL + window + options | OS-level scanner detection |
| Protocol filter | No UDP listener → drop all UDP | Amplification attacks |

**Fallback:** if kernel lacks XDP support or process lacks `CAP_BPF`, the
`firewall` block is silently skipped — all filtering happens in L7 handler
(same guards, just at HTTP level instead of packet level). The `.rut` code
is correct either way.

**Degradation principle:** silent fallback is allowed ONLY when a higher layer
provides equivalent protection (firewall → L7 guards, SO_MAX_PACING_RATE →
token bucket). Control-plane delivery/synchronization operations (`notify`,
`consistent: true`, and future strict-table writes) must surface failures for
the caller to handle. `Cache.set` is deliberately different: it has no error
channel, and collision eviction is part of its documented lossy semantics.

### 16.6 Mesh Three-Component Architecture

```
┌───────────────────────────────────────────────────┐
│                 Rut Control Plane                  │
│  K8s watch → generate .rut → compile .so + .bpf   │
│  Push endpoints, certs, eBPF maps                  │
└────┬─────────────────┬────────────────┬───────────┘
     │ push .bpf       │ push .so       │ push endpoints
     │ + map data      │               │ + certs
     ▼                 ▼                ▼
┌──────────┐    ┌───────────┐    ┌───────────┐
│Node Agent │    │  Sidecar  │    │  Sidecar  │
│(DaemonSet)│    │ (per pod) │    │ (per pod) │
│ ~2MB      │    │ ~5MB      │    │ ~5MB      │
│ CAP_BPF   │    │ no privs  │    │ no privs  │
│ XDP+eBPF  │    │ L7 handler│    │ L7 handler│
└─────┬─────┘    └───────────┘    └───────────┘
      │ XDP in kernel
      ▼
┌──────────────────────────────┐
│ NIC → XDP → DROP/PASS       │  ← blocked IPs dropped at line rate
│        ↓                     │
│    TCP stack → Sidecar       │  ← clean traffic to L7
└──────────────────────────────┘
```

**Three components:**

| Component | Size | Privileges | Role |
|-----------|------|-----------|------|
| Control Plane | ~50MB (has LLVM) | cluster admin | Compile .rut → .so + .bpf, push to nodes |
| Node Agent | ~2MB (has libbpf) | CAP_BPF + CAP_NET_ADMIN | Load XDP programs, manage eBPF maps |
| Sidecar | ~5MB (pure runtime) | none | Execute L7 handlers, zero-copy forward |

**Dynamic eBPF map updates:**

When a handler adds an IP to a blacklist, both userspace Set and kernel eBPF map
are updated:

```swift
post /admin/ban {
    guard let ip = req.body(IP) else { return 400 }
    blacklist.add(ip)               // userspace Set (immediate)
    notify all blacklist.add(ip)    // all shard userspace Sets
    // compiler auto-generates: update eBPF map via Node Agent
    return 200
}
```

Sidecar → Node Agent (HTTP on localhost) → `bpf_map_update_elem`. The IP is
blocked at kernel level within microseconds.

**Fallback:** if Node Agent is absent or kernel lacks XDP support, the system
works without eBPF — pure L7 filtering in sidecar. Same model as io_uring/epoll
fallback.

---

## 17. Design Decisions Log

| # | Decision | Alternatives Considered | Rationale |
|---|----------|------------------------|-----------|
| 1 | Custom runtime, not Seastar | Seastar | Only ~30% of Seastar is relevant; too complex; future/promise overhead unnecessary |
| 2 | io_uring, not DPDK | DPDK | DPDK gives <1% improvement for L7 proxy; requires dedicated cores (expensive in cloud); io_uring + DPDK is broken in Seastar (issue #1890) |
| 3 | io_uring preferred, epoll fallback | epoll-only | io_uring: completion-based, fewer syscalls, zero-copy; epoll: wider kernel support (3.9+); both behind compile-time abstraction |
| 4 | Kernel TCP, not userspace | Seastar native stack | Kernel TCP has mature congestion control (BBR, CUBIC); standard tooling works (tcpdump, ss); containers just work |
| 5 | `-nostdlib++` | Full C++ stdlib | Full memory control; faster compilation; no hidden allocations |
| 6 | LLVM ORC JIT | Cranelift, custom VM | Same C++ toolchain; zero FFI overhead; lazy compilation; mature |
| 7 | State machines, not coroutines | Stackful/stackless coroutines | Zero overhead; no stack allocation per connection; 48 bytes vs 2-8KB per connection |
| 8 | Share-nothing shards | Shared-memory with locks | Eliminates all race conditions; proven by Seastar/Envoy/nginx |
| 9 | SO_REUSEPORT accept | Single-thread accept + dispatch | Zero cross-shard communication; kernel handles distribution |
| 10 | Arena + Slab + Slice | malloc/free, tcmalloc | Zero allocation on hot path; predictable latency; zero fragmentation |
| 11 | Timer wheel | Priority queue, timerfd per connection | O(1) all operations; single timerfd per shard |
| 12 | RCU for config reload | Locks, fork new process | Lock-free hot path; no process restart; atomic swap |
| 13 | Per-shard rate limit partitioning | Global lock, distributed counter | Zero communication; ±N accuracy acceptable for rate limiting |
| 14 | Radix trie routing | Linear scan (Envoy), hash map | O(path length) lookup; supports prefix matching and parameters; JIT-compilable to jumps |
| 15 | Unified completion (proactor) API | Pure reactor or pure proactor | Upper layers written once; io_uring is native proactor; epoll backend wraps reactor as proactor adapter; no code duplication |
| 16 | Swift-inspired syntax | Go, TypeScript, Rust, custom DSL | guard + named params + trailing closures fit gateway patterns perfectly; high LLM accuracy; clean aesthetics; no commas in blocks |
| 17 | All functions compile-time inlined | Runtime function calls | Each route = one flat state machine; zero call overhead; compiler complexity low (just expand + find I/O points) |
| 18 | HTTP as native objects | Strings for everything | Status codes, methods, headers, CIDR, MediaType are typed; compiler catches typos, range errors, type mismatches |
| 19 | No async/await | Explicit async | User writes sequential code; compiler auto-detects I/O points and generates state machines; simpler mental model |
| 20 | Built-in security/encoding primitives | External dependencies | md5, sha256, hmac, jwt, base64, aes cover 95% of gateway needs; zero external deps |
| 21 | Custom IR (RIR) between AST and LLVM IR | Direct AST → LLVM IR | Enables domain-specific optimizations, backend independence (swap LLVM for Cranelift), debuggability (--emit-rir), and clean instrumentation insertion point |
| 22 | Security as language-level code, not runtime features | Built-in WAF/DDoS modules | WAF rules, bot detection, flood protection are all expressible in the DSL; no hardcoded security logic in runtime; users can customize everything |
| 23 | Response middleware via parameter signature | Separate `onResponse` keyword | `func f(req, resp)` = response middleware; compiler auto-detects; no new syntax needed |
| 24 | Connection-level protection in `listen` config | Runtime-only config | headerTimeout, maxConnsPerIP, minRecvRate, strictParsing are declared in .rut files; compile-time validated; visible alongside routing logic |
