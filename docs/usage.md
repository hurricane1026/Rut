# Running a Rut program

This document explains how to build the `rut` binary and run a `.rut`
program with it.

## The execution model (read this first)

The `rut` server loads a `.rut` file at startup. Compilation runs in the
sibling `rut-compile` process; the serving process does not link or load LLVM.

```
app.rut → rut-compile: frontend → RIR → LLVM → native code/config → pipe
                                                    ↓ compiler exits
          rut: load native code, rebuild route indices → shards serve traffic
```

The compiler streams native handlers, owned configuration bytes and serialized
Vectorscan databases through a pipe. On Linux, `rut` receives the native image
into a sealed anonymous memfd and loads it through `/proc/self/fd`; the descriptor
and code remain owned until all shards join. There is no `.so` to version,
retain or deploy. The compiler uses private temporary linker files and removes
them before exiting. macOS uses an immediately unlinked temporary load file.
No source, RIR or LLVM engine is retained in the serving process.

The stream carries a protocol version and source/build-configuration fingerprint;
`rut` rejects a mismatched `rut-compile` before loading any native code.

- Ship `rut` and the matching `rut-compile` in the same directory, plus the
  `.rut` source and its imports.
- The startup host needs the compiler's LLVM dependencies and the C compiler
  driver/linker recorded by CMake (`CMAKE_C_COMPILER`). These run only during
  compilation. Vectorscan's compiler is also confined to `rut-compile`.
- `--opt 0..3` still controls handler optimization. `--compile PATH` makes
  automatic compilation explicit; the positional source path remains supported.
  There is no new language syntax.
- The artifact is a private ABI for the same build and host CPU. There is
  still no `rut build app.rut -o app` standalone executable command or
  mesh distribution/hot-reload protocol. `rut-compile` is an internal startup
  helper with binary stdout, not a persistent artifact distribution API.

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

This produces the server and its compiler at:

```
build/src/rut
build/src/rut-compile
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
  A name-only upstream makes the program fail to load (fail-closed).
- Requests that match no route fall through to the default action
  (currently a `200`).
- See `DESIGN.md` for the full language; not every documented construct
  is JIT-backed yet (see `docs/core-capabilities.md` and the gap notes).

## 3. Run it

Pass the `.rut` path with `--compile` or as a positional argument. A source file may declare one
cleartext IPv4 wildcard listener, for example `listen :8080`; port `0` is
allowed for an ephemeral test listener:

```swift
listen :8080
route GET "/health" { return 200 }
```

```bash
./build/src/rut --compile app.rut --shards 4
# The positional form remains supported:
./build/src/rut app.rut
```

`rut` will:

1. start its sibling `rut-compile`, receive the native program over a pipe,
   wait for the compiler to exit, and load the program (prints `Loaded program: app.rut`),
2. pick an I/O backend (io_uring if available, else epoll),
3. spin up one share-nothing shard per CPU core,
4. listen on the source-declared port, or the explicit CLI port/default 8080
   when the source has no listener declaration.

An explicit CLI port may repeat an equivalent source declaration. If both are
present and differ, startup fails rather than silently choosing one.
Because a source listener is explicitly cleartext, `--tls-cert`/`--tls-key`
cannot be combined with a source `listen` declaration; CLI-only TLS remains
supported.

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
| `--compile PATH` | Compile and serve a program using the managed compiler subprocess | none |
| `--shards N` | Number of per-core shards | auto (CPU count) |
| `--no-pin` | Do not pin shard threads to CPUs | pin on |
| `--drain N` | Graceful drain window, seconds | `30` |
| `--opt N` | JIT optimization level: `0` (low, fastest startup) .. `3` (high) | `2` |
| `--pool-prealloc N` | Pre-commit N buffer slices per shard | `0` (lazy) |
| `--max-connections-per-shard N` | Maximum connection slots allocated by each shard (Linux; macOS accepts only the default) | `16384` |
| `--tls-cert PATH` | TLS certificate (PEM); enables TLS | off |
| `--tls-key PATH` | TLS private key (PEM); required with `--tls-cert` | off |
| `--access-log PATH` | Write access logs to PATH | off |
| `--access-log-compress` | zstd-compress access logs | off |
| `--access-log-level N` | Access log verbosity | build default |

The positional CLI port is optional when the source declares `listen :<port>`;
without either declaration the listener defaults to `:8080`.
Both program forms manage compilation automatically; users never need to invoke
`rut-compile` or manage its generated native image themselves.

`--tls-cert`/`--tls-key` must be given together. With TLS enabled the
server uses the epoll backend.

`--max-connections-per-shard` is a startup-only setting. It accepts values
from 1 through 16,777,213 (the runtime maximum) and applies independently to
each shard, so aggregate capacity is approximately the configured value times
the shard count and is also limited by available file descriptors and memory.
Connection metadata scales with this setting; request and I/O buffers are
still committed on demand. HTTP/2 connection and idle-upstream pools have
their own bounded limits and are not changed by this option.

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
- **`forward` upstreams need an address** in the `.rut` (no runtime
  binding / service discovery yet).
- **No hot reload of `.rut` at runtime.** Restart to apply changes.
- Some environments (containers/sandboxes) can set up io_uring but not
  complete its operations; if requests connect but never respond, force
  the epoll backend by running with TLS, or run on a host with working
  io_uring.
- **io_uring ring memory counts against `RLIMIT_MEMLOCK`.** On recent
  kernels each shard's ring costs about 632 KiB at the default
  `--max-connections-per-shard` of 16384 (on 4 KiB pages; slightly more on
  16 KiB / 64 KiB-page kernels, since the charge is rounded to whole pages) of
  the per-user locked-memory budget, shared by all processes of the user and
  not visible in `/proc`. The rings are sized from that option: a 1024-entry
  submission queue and a completion queue of twice the capacity, rounded up to
  a power of two (minimum 2048, maximum 65536), so `--max-connections-per-shard
  1024` costs about 152 KiB per shard. With the common 8 MiB default that is
  twelve shards at the default capacity and over fifty at 1024 (other io_uring
  processes of the same user share the budget). Startup's minimum accounts for
  the required primary buffer ring and optional large-buffer rings retained by
  earlier shards while later shards initialize.
  Plain HTTP with more shards (the default is one per CPU) stops at startup
  with `Failed to init shard N (errno=12, source=2)` plus a diagnostic; with TLS
  the same failure prints the diagnostic and falls back to epoll (TLS). If the
  budget is already fully used, even the one-entry startup probe fails and Rut
  silently runs on epoll. To keep io_uring, raise the limit (`ulimit -l <KiB>`,
  systemd `LimitMEMLOCK=`, container `--ulimit memlock=<bytes>`), grant
  `CAP_IPC_LOCK`, or run fewer shards. Rut never raises the limit itself.
- **Large request bodies on io_uring are a stopgap.** A proxied request body
  that arrives faster than the upstream send drains the 16 KiB receive buffer
  is refused with `413` + `Connection: close` (instead of hanging or being
  closed silently): a client that writes a body above about 16 KiB in one go
  (e.g. `curl --data-binary` of 20 KB or more), or a fast client to a slow
  origin. Bodies up to about 16 KiB and uploads paced below the upstream drain
  rate are forwarded byte-exact; the epoll backend is unaffected. Lossless
  streaming is a tracked follow-up.

For what is and isn't implemented across the language and runtime, see
`docs/core-capabilities.md`.
