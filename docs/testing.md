# Testing Notes

## Primary CI test shards

Each Clang/GCC × Debug/Release configuration runs its non-Docker CTest suite
on four independent runners. Each runner builds the same configuration and
executes one interleaved quarter of the test inventory, using CTest's native
`-I Start,,Stride` selection. Tests remain serial within each runner, so
fixed-port fixtures, `RUN_SERIAL` and `RESOURCE_LOCK` retain their isolation.
The compiler model/mutation checks run once, on Clang Debug shard 1.

```bash
python3 scripts/run_ci_shard.py --build-dir build --shard 1 --shards 4
# Inspect and verify the complete partition without executing tests:
python3 scripts/run_ci_shard.py --build-dir build --shard 1 --shards 4 --plan-only
python3 -m unittest discover -s tests -p test_ci_sharding.py
```

Every shard verifies that the actual CTest selections form a complete,
non-overlapping partition before running. Empty partitions, discovery errors
and test failures fail CI. Each job uploads the inventory, JUnit results and
CTest log, including on failure. Matrix fail-fast is disabled so a failure
does not cancel the remaining coverage. Other CI jobs retain their full suites.

This trades additional builds and runner minutes for shorter elapsed time.
The completed Clang Release baseline from PR #1100 ran 499 tests in 9797.77 s;
the four interleaved groups account for 2314.43, 2352.68, 2750.79 and 2379.60 s
of that historical test time. The largest group is about 46 minutes instead
of 163 minutes. These are estimates from the serial baseline, excluding new
builds, runner queues and machine variation; compare the uploaded results of
the first sharded CI run before claiming an observed speedup.

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
