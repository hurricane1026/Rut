# Testing Notes

## PR checks and full regressions

The CI scope job runs the CI policy/sharding controls before selecting work.
Documentation and CI-selection-tool-only changes skip native builds. Native,
build-system, test and unknown input changes use four isolated Clang Debug
runners. PR CTest selection contains all `unit` tests, both integration smoke
shards, and tests whose command names match directly changed test scripts or
C++ test source stems. This is a bounded PR smoke policy, not complete semantic
impact analysis: other integration tests and other compiler/configuration
combinations are deferred to full regression. Compiler model/mutation checks
run on relevant model/verifier/scheduler/timer/retirement changes. Formatting
and clang-tidy run for C++ source/header changes.

Main pushes, nightly runs (01:11 UTC), and manual CI runs retain the full
Clang/GCC × Debug/Release suite, with four isolated CTest shards per
configuration. Full runs also retain nginx/Envoy differentials, sanitizer,
coverage, no-JIT and no-WebSocket builds. macOS, the pinned Kong baseline and
the privileged IPv4 fixture workflows run on main, nightly and manually,
rather than on every PR. These full regressions are intentionally no longer
PR acceptance checks. The manual diagnostic modes remain available.

Each runner verifies its actual CTest selections are nonempty, disjoint and
complete for the selected scope. Tests stay serial within a runner to retain
fixed-port fixture isolation, resource locks and timeouts. Each job preserves
inventory, scope, deferred-test names, JUnit results and the CTest log. Matrix
fail-fast remains disabled.

```bash
# PR smoke scope, including a directly changed integration script:
python3 scripts/run_ci_shard.py --build-dir build --shard 1 --shards 4 \
    --pr --changed-files-json '["tests/test_redis_resp3.py"]'
# Full regression scope, inventory only:
python3 scripts/run_ci_shard.py --build-dir build --shard 1 --shards 4 --plan-only
python3 -m unittest discover -s tests -p 'test_ci_*.py'
```

The primary matrix uses ccache for C/C++ objects. Keys separate OS,
architecture, compiler and configuration; compiler contents, flags and
included files determine reuse. Configuration, linking and tests still run.
No test results or whole build trees are restored. Shards share immutable
keys and publish after a successful build, before tests. Pinned OpenSSL
retains its existing acquisition/checksum verification. Cold builds still
cost time; cache statistics are logged.

The first full sharded run on PR #1107 passed but took 2 h 11 min end to end.
The PR smoke scope selects 148 tests from the historical 499-test inventory,
including both integration shards, versus repeating all 499 tests in each
of four configurations. New tests change these counts. This substantially
reduces work and runner contention, but a ten-minute end-to-end duration
remains a target pending remote measurement, not a guaranteed timeout.

## Performance measurements

`.github/workflows/benchmarks.yml` runs nightly at 02:23 UTC and can be started
manually. Proxy TLS/io_uring latency, x86/arm64 SIMD scan/dispatch and integer
parser timing no longer run on each PR or main push. The PR integer parser
job still compiles every ISA candidate and runs each supported candidate's
correctness oracle, using `RUT_RUN_BENCHMARKS=0` to skip timing and benchmark
compilation. Manual `integer-parser` mode in CI is also correctness-only;
use the Benchmarks workflow for performance data and optional AVX-512 checks.

Performance-only CMake targets are excluded from the default build; build them
explicitly, for example `cmake --build build --target bench_scan_uri`.
Kernel probe binaries consumed by CTest and tests of benchmark tooling remain
in normal builds/checks because they verify correctness rather than measure
performance. Removing performance jobs reduces runner contention but does not
by itself establish a ten-minute full CI duration.

## Compiler and JIT leak checks

Build the frontend and loader with ASan/UBSan, keeping JIT support enabled
for the loader tests:

```bash
cmake -S . -B build-san-jit -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DRUT_SANITIZE=ON -DRUT_ENABLE_JIT=ON
cmake --build build-san-jit --target test_frontend test_serve_loader
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  build-san-jit/tests/test_frontend
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  build-san-jit/tests/test_serve_loader \
  serve_loader.exact_strict_local_response_source_reaches_runtime_config \
  serve_loader.pre_route_source_installs_full_owned_deduplicated_selector_table
```

The loader selection covers successful LLVM module verification and owned
local/pre-route policy loading. `LLVMVerifyModule` can allocate an empty
diagnostic even on success; the JIT must release it with `LLVMDisposeMessage`
on both success and failure. No LLVM leak suppression is needed for this path.
JIT-generated instructions are not sanitizer-instrumented; the compiler and
loader are. A run with `detect_leaks=0`, including the runtime sanitizer CI job,
provides ASan/UBSan evidence only and does not establish leak cleanliness.

Frontend fixtures own manually constructed HIR/MIR modules through scope guards.
Synthesized protocol and impl function names use the HIR's shared,
mmap-backed generated-name arena. HIR copies retain that owner; dropping its
last reference releases the names together.

## Connection State Invariants

`Connection::state` is debug and metrics state. Runtime dispatch is driven by
the four callback slots:

- `on_recv`
- `on_send`
- `on_upstream_recv`
- `on_upstream_send`

Tests should assert both the state and the slots after representative dispatch
steps. A response can be correct on the wire while still leaving stale proxy or
streaming state behind, so state-only or slot-only assertions are not enough.

The main invariants are:

- `Idle`: client and upstream fds are closed, and all callback slots are null.
- `ReadingHeader`: client fd is live, `on_recv` is `on_header_received`, and all
  send/upstream slots are null.
- `Proxying`: upstream fd is live, and active slots describe the exact proxy
  phase, such as upstream response wait, request body streaming, or early
  response deferral.
- `Sending`: client fd is live, `on_send` is active, and upstream slots are null.
  The explicit exception is streaming response body wait after response headers
  have been sent: state remains `Sending`, `on_send` is null, and
  `on_upstream_recv` is `on_response_body_recvd`.
- `ExecHandler`: a yielded JIT handler keeps all callback slots null while
  `pending_handler_fn` and `handler_state` identify the resume target.

When adding a callback path that sends a 500/502 response, include a focused
state-invariant assertion. The expected shape is `ConnState::Sending` with only
the client send slot active. This catches stale proxy/body-streaming callbacks
that would otherwise be easy to miss in wire-level tests.

## Fault Injection

Shared syscall fault injection lives in `testing/fault_injection.h` and
`testing/fault_injection.cc`. Test files should use the RAII scopes there
instead of defining local `extern "C"` syscall hooks.

Current scopes:

- `ScopedMemoryFault`: fail the Nth `mmap` call, fail `mprotect`, or both.
- `ScopedFakeSocket`: return a specific fd from the next AF_INET stream
  `socket` call.
- `ScopedRecvData`: make `recv` for one fd return optional EINTR failures and
  then deterministic bytes.
- `ScopedIoFault`: make `poll`, `read`, or `write` for one configured fd
  return transient errors, fatal errors, or short I/O. It also covers
  fd-scoped `send`, `connect`, `close`, and `fcntl` failures. Leave
  `IoFaultConfig::fd` at its default `kNoIoFaultFd` to match no fd, or set it
  to `kMatchAllIoFds` only when a test explicitly needs process-wide I/O
  faulting before the fd is known.
- `ScopedSyscallFault`: inject process-wide failures for initialization or
  path-based syscalls such as `epoll_create1`, `epoll_ctl`, `epoll_wait`,
  `timerfd_create`, `timerfd_settime`, `accept4`, `open`, `mkstemp`, and
  `unlink`.

Memory, socket, and `recv` state is thread-local and restored when the scope
exits. `ScopedIoFault` and `ScopedSyscallFault` use process-wide atomic
counters so they can fault I/O performed by helper threads. This keeps fault
setup local to a test case while allowing one shared interpose layer per test
binary.
