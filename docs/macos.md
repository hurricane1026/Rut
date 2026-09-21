# macOS development

Rut runs natively on macOS with a dedicated kqueue backend. This mode is for
writing and testing `.rut` programs locally; Linux remains the production and
performance target. No additional networking or compatibility library is used.

## Build and run

Install Xcode Command Line Tools (`xcode-select --install`) and the existing
project build dependencies. With Homebrew:

```bash
brew install cmake ninja llvm@20 boost ragel
git submodule update --init --recursive
./dev.sh build
./dev.sh test
```

`dev.sh` uses Homebrew's keg-only LLVM 20 for the compiler, JIT library, formatter
and linter. A manual build can use:

```bash
cmake -B build -G Ninja \
  -DCMAKE_C_COMPILER="$(brew --prefix llvm@20)/bin/clang" \
  -DCMAKE_CXX_COMPILER="$(brew --prefix llvm@20)/bin/clang++" \
  -DLLVM_DIR="$(brew --prefix llvm@20)/lib/cmake/llvm"
cmake --build build
ctest --test-dir build --output-on-failure
```

Create `app.rut`:

```swift
route GET "/health" { return 200 }
route GET "/slow" {
    wait(40)
    return 201
}
```

```bash
./build/src/rut app.rut 8080
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/slow
```

The startup banner reports `Backend: kqueue (macOS development)`. Use Ctrl-C to
stop; SIGINT/SIGTERM follow the normal graceful drain path.

## Scope

- The normal compiler, LLVM JIT, BoringSSL TLS, routing, reverse proxy and tools
  are built. `-DRUT_ENABLE_JIT=OFF` is also supported for runtime-only work;
  it cannot load `.rut` programs.
- macOS defaults to one shard and rejects `--shards` values above one. This keeps
  memory use suitable for development and avoids relying on Linux's SO_REUSEPORT
  load distribution. CPU pinning is disabled.
- kqueue uses independent read/write filters, native timers and user-event
  wakeups. Socket I/O is nonblocking and synchronous; Linux io_uring optimizations
  are not emulated. Linux's epoll and io_uring backends are unchanged.
- Linux and macOS share the registration of platform-independent tests, including
  compiler/JIT, protocols, mock network state machines, allocators, logs, fault
  injection, shard control, capture/replay and simulation. `./dev.sh test` runs
  these plus native kqueue and real HTTP/TLS proxy and HTTP/2 tests on macOS.
  Tests that manipulate epoll, io_uring submission/completion rings, procfs,
  Linux capabilities or Docker fixtures remain Linux-only.
- The test fault shims are built as a test-only dylib on macOS so memory-protection
  failures also reach LLVM's dynamic library. This adds no external dependency
  and is not linked into Rut or its tools.
- No system OpenSSL is required; TLS uses the existing BoringSSL submodule.
  Test certificates are checked-in fixtures.
