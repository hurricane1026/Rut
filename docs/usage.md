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

A program is a set of routes. The two route outcomes that are wired end
to end today are **returning a status** and **forwarding to an upstream**.

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
| `--access-log PATH` | Write access logs to PATH | off |
| `--access-log-compress` | zstd-compress access logs | off |
| `--access-log-level N` | Access log verbosity | build default |

`--tls-cert`/`--tls-key` must be given together. Both backends support server
TLS. In `auto` mode, Rut prefers io_uring when available unless the program
configures active upstream health checks, which currently require epoll.

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

## 4. Verify a change actually serves

A quick smoke test (no TLS):

```bash
printf 'route GET "/" {\n  return 200\n}\n' > /tmp/hello.rut
./build/src/rut 8080 --shards 1 /tmp/hello.rut &
sleep 1
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/   # 200
```

## Caveats / current limits

- **HTTP/1.1 only.** No HTTP/2, HTTP/3, or WebSocket upgrade yet.
- **Server TLS only.** No SNI / ALPN / mTLS / kTLS.
- **DNS is resolved at configuration load time.** TTL-based refresh, SRV
  records, and dynamic service discovery are not supported yet.
- **No hot reload of `.rut` at runtime.** Restart to apply changes.
- Some environments (containers/sandboxes) can set up io_uring but not
  complete its operations; if requests connect but never respond, use
  `--backend epoll`, or run on a host with working io_uring.

For what is and isn't implemented across the language and runtime, see
`docs/core-capabilities.md`.
