# Running a Rut program

This document explains how to build the `rut` binary and run a `.rut`
program with it.

## The execution model (read this first)

Rut does **not** compile a `.rut` file into a standalone executable.
There is one executable — the `rut` server binary — and your program is
the `.rut` file it loads at startup:

```
rut  +  app.rut   ─►   lex → parse → type-check → RIR → LLVM IR → ORC JIT → native handlers
(binary)  (your program)                                                         │
                                                                                 ▼
                                                              per-core shards serve traffic
```

The handlers are JIT-compiled into native code **in memory at startup**,
not ahead of time. So:

- The thing you ship/run is the `rut` binary plus a `.rut` file.
- There is currently **no** `rut build app.rut -o app` AOT command, and
  no "compile to a self-contained binary" mode.
- The mesh-mode AOT path from DESIGN.md (control plane compiles `.rut`
  to a distributable `.so`) is **not implemented yet**.

If you were looking for "how do I produce an executable from my `.rut`":
the answer today is "you don't — you run `rut your.rut`".

## 1. Build the `rut` binary

Prerequisites: `clang++`, `cmake`, `ninja`. LLVM and Vectorscan are
required for the JIT (enabled by default via `RUT_ENABLE_JIT=ON`); the
BoringSSL and zstd dependencies are vendored under `third_party/`.

```bash
./dev.sh build
# or manually:
cmake -B build -G Ninja -DCMAKE_CXX_COMPILER=clang++
ninja -C build
```

This produces the server binary at:

```
build/src/rut
```

For production, build a Release with link-time optimization (cross-module
inlining + dead-code elimination across the runtime; also shrinks the
binary). Requires clang + lld:

```bash
cmake -B build-rel -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Release -DRUT_ENABLE_IPO=ON \
  -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld"
ninja -C build-rel src/rut
```

LTO optimizes the ahead-of-time-compiled runtime (event loop, HTTP
parser, helpers). It is independent of the JIT `--opt` level, which
optimizes the per-program handlers at startup.

> If you build with `-DRUT_ENABLE_JIT=OFF`, the binary still compiles but
> cannot load a `.rut` program (it will refuse a program-path argument).
> Program loading needs the JIT.

## 2. Write a `.rut` program

A program is a set of routes. Common outcomes wired end to end include
**returning a status**, **forwarding to an upstream**, and WebSocket upgrade
handling.

```rut
// app.rut

// Declare upstreams with an address. forward(name) proxies to it.
upstream origin at "127.0.0.1:9090"

route GET "/" {
    return 200
}

route GET "/health" {
    return 204
}

route GET "/proxy" {
    return forward(origin)          // zero-copy proxy to `origin`
}
```

Notes:

- An upstream used by `forward` must have a concrete address —
  `upstream X at "host:port"` or `upstream X { host: "...", port: N }`.
  IPv6 literals use brackets in packed endpoints, for example
  `upstream X at "[2001:db8::1]:8080"`; dictionary-form `host` values are bare.
  A `backends` list may mix IPv4, IPv6, and DNS hostname endpoints. Hostnames
  are resolved to A/AAAA addresses before the configuration is published;
  failure rejects the load, and resolved addresses count toward the eight
  backend limit.
  To connect to an HTTPS origin, add
  `tls: { server_name: "api.example.com" }` to the dictionary form. Rut sends
  that name as SNI and requires the origin certificate to match it and chain to
  the system trust store. TLS upstreams use the epoll backend and are not placed
  in the bare-fd keep-alive pool.
  A name-only upstream makes the program fail to load (fail-closed).
- Requests that match no route return `404`. Running without a `.rut` program
  retains the route-less `200` response used for basic listener checks.
- See `DESIGN.md` for the full language; not every documented construct
  is JIT-backed yet. New and generated programs should follow the profile in
  `docs/syntax-stability.md`; capability gaps are tracked in
  `docs/core-capabilities.md`.

## 3. Run it

Pass the `.rut` path as a positional argument:

```bash
./build/src/rut 8080 app.rut
```

`rut` will:

1. compile and JIT `app.rut` (prints `Loaded program: app.rut`),
2. pick an I/O backend (io_uring if available, else epoll),
3. spin up one share-nothing shard per CPU core,
4. listen on the given port.

Then:

```bash
curl -i http://127.0.0.1:8080/         # -> 200
curl -i http://127.0.0.1:8080/health   # -> 204
curl -i http://127.0.0.1:8080/proxy    # -> proxied response from origin
```

Stop it with `Ctrl-C` (SIGINT) or SIGTERM — it drains connections
gracefully before exiting.

### Command-line options

| Argument | Meaning | Default |
|---|---|---|
| `<port>` (positional) | Listen port (`0` = ephemeral) | `8080` |
| `<path.rut>` (positional) | Program to load and serve | none (route-less) |
| `--shards N` | Number of per-core shards | auto (CPU count) |
| `--no-pin` | Do not pin shard threads to CPUs | pin on |
| `--drain N` | Graceful drain window, seconds | `30` |
| `--opt N` | JIT optimization level: `0` (low, fastest startup) .. `3` (high) | `2` |
| `--pool-prealloc N` | Pre-commit N buffer slices per shard | `0` (lazy) |
| `--backend MODE` | I/O backend: `auto`, `io_uring`, or `epoll` | `auto` |
| `--tls-cert PATH` | TLS certificate (PEM); enables TLS | off |
| `--tls-key PATH` | TLS private key (PEM); required with `--tls-cert` | off |
| `--tls-client-ca PATH` | Trust bundle for required inbound client certificates (mTLS) | off |
| `--tls-sni NAME CERT KEY` | Add an exact SNI certificate identity; repeatable up to 16 | none |
| `--upstream-tls-ca PATH` | Trust bundle for verified upstream TLS | system trust store |
| `--upstream-tls-cert PATH` | Client certificate chain presented to TLS upstreams | off |
| `--upstream-tls-key PATH` | Client private key; required with `--upstream-tls-cert` | off |
| `--access-log PATH` | Write access logs to PATH | off |
| `--access-log-compress` | zstd-compress access logs | off |
| `--access-log-level N` | Access log verbosity | build default |
| `--h2` | Advertise HTTP/2 via TLS ALPN | off |
| `--metrics` | Serve the built-in Prometheus endpoint at HTTP/1.1 `GET /metrics` | off |
| `--allow-route-reload` | Permit source routes to call `reload()` | off |

`--tls-cert`/`--tls-key` must be given together. `--tls-client-ca` enables
inbound mTLS and is valid only when that server identity is configured; every
inbound TLS connection must then present a certificate chaining to the supplied
PEM bundle. `--tls-sni NAME CERT KEY` adds a case-insensitive exact hostname
mapping and requires the default certificate/key. Unknown hostnames and clients
without SNI receive the default identity. Wildcard mappings are intentionally
rejected; up to 16 identities are preloaded at startup, and all identities use
the same ALPN and inbound mTLS policy. Both backends support server TLS.

`--upstream-tls-cert`/`--upstream-tls-key` must also be given together. The
upstream trust bundle and optional client identity are process-wide and apply to
every TLS upstream. `RUT_UPSTREAM_TLS_CA_FILE` remains an environment equivalent
for the CA bundle, with the command-line option taking precedence. Upstream TLS
currently requires epoll. In `auto` mode, Rut also selects epoll when the program
configures active upstream health checks.

With a loaded `.rut` program, `SIGHUP` requests a hot reload through the same
single-flight coordinator used by `reload()`. The program path must be a
single symlink to an immutable version tree; deploy a new version by atomically
replacing that symlink. Route-triggered reload stays disabled unless
`--allow-route-reload` is set; that flag is an operator capability, not
application authentication. Immediately after a symlink replacement, a route
`reload()` or SIGHUP admits a reload intent without reading the filesystem. The
control thread resolves the symlink once after it takes the winning request, so
the reload uses the immutable version current when processing begins. Do not
replace the symlink again until that reload reports its terminal result when a
deployment must activate one specific version.

`--opt` selects how hard the JIT optimizes each handler at startup:

- `--opt 0` — skip the IR optimization pipeline. Fastest startup /
  reload, least optimized handlers. Good for development.
- `--opt 1` — light optimization.
- `--opt 2` — full `default<O2>` pipeline (default). Recommended for
  production.
- `--opt 3` — `default<O3>`; more aggressive, longer startup compile,
  rarely worth it over O2 for this workload.

The level only affects compile time and steady-state handler speed, not
correctness.

Example with TLS:

```bash
./build/src/rut 8443 \
  --tls-cert server.pem --tls-key server.key \
  app.rut
curl -k https://127.0.0.1:8443/
```

Require inbound client certificates:

```bash
./build/src/rut 8443 \
  --tls-cert server.pem --tls-key server.key \
  --tls-client-ca client-ca.pem \
  app.rut
```

Serve an additional certificate selected by SNI:

```bash
./build/src/rut 8443 \
  --tls-cert default.pem --tls-key default.key \
  --tls-sni api.example.com api.pem api.key \
  --tls-sni admin.example.com admin.pem admin.key \
  app.rut
```

Present a client identity to mTLS upstreams while using a private trust bundle:

```bash
./build/src/rut 8080 \
  --upstream-tls-ca upstream-ca.pem \
  --upstream-tls-cert gateway-client.pem \
  --upstream-tls-key gateway-client.key \
  app.rut
```

## 4. Verify a change actually serves

A quick smoke test (no TLS):

```bash
printf 'route GET "/" {\n  return 200\n}\n' > /tmp/hello.rut
./build/src/rut 8080 --shards 1 /tmp/hello.rut &
sleep 1
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/   # 200
```

For the complete black-box conformance suite of the currently implemented
design surface, run:

```bash
./examples/design-validation/validate.sh ./build/src/rut
# or through CTest:
ctest --test-dir build -R '^test_design_validation$' --output-on-failure
```

The suite JIT-loads standalone Rut programs and exercises language, state,
HTTP/1, HTTP/2, TLS/mTLS, forwarding, WebSocket, failure, and reload behavior.
Its exact coverage and target-surface exclusions are documented in
`examples/design-validation/README.md`.

## Caveats / current limits

- **HTTP/2 has distinct cleartext and TLS admission paths.** Cleartext h2c
  prior knowledge is accepted automatically; `--h2` only enables TLS ALPN
  advertisement. HTTP/2 supports static routes, JIT handlers (including timer
  waits), buffered JIT forwarding, and proxy requests with or without bodies.
  Proxy request bodies are buffered before the HTTP/1 upstream request is
  issued. The synthesized HTTP/1 request has a 16 KiB buffer shared by its
  request line, headers, and body, so the effective body limit is less than
  16 KiB and varies with header size; an overflow returns `413`. Only one stream
  per connection may wait for request-body DATA at a time. A second body-bearing
  stream that also needs deferral while this pending-body slot is occupied
  returns `503`, so concurrent/interleaved uploads on one connection are not
  supported. Unbuffered JIT forwarding and non-timer event waits return `503`.
  One async execution slot is available per connection for a timer wait,
  buffered forward, or proxy. The pending-body and async slots are distinct
  states but cannot be occupied together because they share request scratch
  storage. While a body wait is active, other request frames are still processed,
  but a bodyless stream that reaches one of those async operations returns `503`.
  Conversely, while the async slot is occupied, subsequent request frames
  ordinarily remain buffered until the parked stream resumes, causing
  per-connection head-of-line blocking. HTTP/3 is not implemented.
- **WebSocket support is HTTP/1.1 upgrade only.** Passthrough and bounded
  terminate-mode frame handlers are available when built with
  `RUT_ENABLE_WEBSOCKET=ON`. Terminate mode accepts only a single unfragmented
  frame of roughly 16 KiB or less; larger or fragmented messages fail closed.
  HTTP/2 extended CONNECT is not implemented.
- **Inbound and verified upstream TLS are supported.** ALPN is available for the
  opt-in HTTP/2 server path. Inbound mTLS can require a process-wide client CA.
  Up to 16 exact inbound SNI certificate mappings can be preloaded at startup.
  Upstream TLS sends configured SNI, supports a process-wide custom CA and
  optional client identity, and verifies the origin on the epoll backend.
  Wildcard/dynamically reloaded certificate maps, per-upstream TLS profiles,
  insecure upstream verification, and kTLS are not implemented. A TLS upstream
  cannot also enable `health_check`: active probes currently send plaintext
  HTTP, so that combination fails program load.
- **DNS is resolved at configuration load time.** TTL-based refresh, SRV
  records, and dynamic service discovery are not supported yet.
- **Hot reload is bounded and source-based.** `SIGHUP` reloads a loaded
  program, and routes can request the same operation only with
  `--allow-route-reload`. The loaded path must be a single symlink to an
  immutable version tree. File watching, AOT program artifacts, and mutable
  source trees are not live-reload inputs.
- **The built-in Prometheus endpoint is HTTP/1.1-only.** With `--metrics`,
  `GET /metrics` is intercepted ahead of HTTP/1 route matching; HTTP/2 uses
  ordinary route dispatch for that path.
- Some environments (containers/sandboxes) can set up io_uring but not
  complete its operations; if requests connect but never respond, use
  `--backend epoll`, or run on a host with working io_uring.

For what is and isn't implemented across the language and runtime, see
`docs/core-capabilities.md`.
