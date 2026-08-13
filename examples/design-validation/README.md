# Rut Design Validation Suite

This directory is the black-box conformance suite for the currently shipped
part of the Rut design. Every positive program is loaded through the LLVM JIT
and exercised through a real server; negative programs must fail at the
documented compiler or loader boundary.

Run it after building `rut`:

```bash
./examples/design-validation/validate.sh ./build/src/rut
```

The runner needs Bash, Python 3, curl with HTTP/2, and OpenSSL-compatible TLS
support in curl. It uses production-default JIT optimization (`--opt 2`). Set
`RUT_VALIDATION_OPT=0` for faster local startup.

## Coverage Matrix

The suite provides capability-level coverage of the public implementation boundary maintained in
`docs/core-capabilities.md` and `docs/language-card.md`:

| Program | Design surface exercised |
|---|---|
| `routing.rut` | matching, captures, query/header lists, fallback, pipe, guard, match, keep-alive, pipelining, concurrency, multi-shard, access log |
| `core.rut` | bounded `for`, regex, `if let`, response reads and ordered header/status/body mutation |
| `data.rut` | structs, variants, arrays, functions, and runtime JSON serialization |
| `request.rut` | request body, cookies, repeated headers, host and HTTP version flags |
| `middleware.rut` | chain `before`/`after`, response status/body/header mutation, timer wait |
| `state.rut` | bounded per-shard `Cache<IP,i64>`, time, arithmetic, and branch-local writes |
| `modules/main.rut` | relative imports and imported function symbols |
| `operations.rut` | shard `stats()` and process `metrics()` snapshots |
| `limits.rut` | JSON/body/status limits and runtime fail-closed behavior |
| `transport.rut` | h2c, TLS ALPN, distinct exact-SNI certificate selection, inbound mTLS and Prometheus endpoint |
| `proxy.rut` | streaming/buffered forwarding, request rewrite, HTTP/2 body forwarding, origin failure and response overflow |
| `proxy-tls.rut` | verified TLS origin, hostname-mismatch rejection and required upstream client identity |
| `websocket.rut` | HTTP/1.1 WebSocket passthrough upgrade plus masked client frame and origin echo relay |
| `invalid/*.rut` | duplicate JSON keys, pending `Hash`, invalid regex, unsafe rewrite header and unresolved upstream diagnostics |
| `reload_probe.py` | capability-gated route reload, immutable symlink activation and generation behavior |

CTest registers this as `test_design_validation`, labeled `conformance`. The
CTest form skips process probes already registered separately and disables the
WebSocket fixture when Rut is configured with `RUT_ENABLE_WEBSOCKET=OFF`.

## Scope Boundary

Passing means the maintained public implementation boundary works end to end;
it does not mean every target form in `DESIGN.md` exists. Strict `Hash`, general
mutable `var`, lifecycle hooks, general outbound HTTP, `submit`/`fire`, and AOT
artifact generation remain outside the deployment surface and are not treated
as expected successes.

Low-level invariants that cannot be observed reliably from a `.rut` process,
including HPACK framing, io_uring fault injection, allocator failures, timer
heap pressure and callback-slot cleanup, remain in the C++ unit/integration
tests. The conformance test complements those tests; it does not duplicate
their internal assertions.

One compatibility wart is visible in `middleware.rut`: request-aware helper
parameters currently use the compiler-recognized spelling `_ req: i32`. A
first-class source `Request` annotation and name-independent request member
lowering are not yet available across this helper path.

An exploratory form also exposed a helper-lowering gap: a route-local
`trimPrefix` chain executes, but `path | trimPrefix(_, "/api")` inside an
ordinary source helper is currently rejected as unsupported syntax.

HTTP/2 requests are deliberately mapped onto HTTP/1.1 request semantics before
JIT dispatch, so `req.http11` is currently true on h2 routes. The runner checks
the negotiated wire protocol separately using curl's `http_version` result.

Override listener ports with `RUT_VALIDATION_BASE_PORT`. Local origins use
`19890`, `19892`, and `19893`; those are fixed because upstream addresses are
compile-time configuration. Set `RUT_VALIDATION_WEBSOCKET=0` to skip the
optional WebSocket build surface or `RUT_VALIDATION_PROCESS_TESTS=0` to skip
the standalone SIGHUP/backend probes.
