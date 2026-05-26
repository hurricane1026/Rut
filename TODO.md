# TODO

Outstanding work items, prioritized for the next implementation passes.

## Recently Completed

- [x] epoll partial-send proactor semantics and recv-buffer integration.
- [x] io_uring timerfd timeout events and provided-buffer return path.
- [x] Shard runtime integration: per-core EventLoop, TimerWheel, route table, upstream pool, SlicePool, and SlabPool.
- [x] Connection buffers moved from inline storage to SlicePool-backed slices; idle/free connections hold zero buffer slices.
- [x] Traffic replay now covers static/default paths and explicitly skips proxy routes through `replay_one`.
- [x] Capture persistence now covers raw-header tail zeroing, corrupted/truncated entries, zeroed entries, and EINTR retry for capture read/write.
- [x] Response parser rejects malformed status codes (`XYZ`, non-digit, `<100`, `>599`).
- [x] Simulate engine rejects malformed captured request headers and counts malformed capture entries as failed.
- [x] Proxy 502 paths assert `ConnState::Sending`; upstream connect failure now sets that state in production.
- [x] State invariant tests cover representative static, proxy, body-streaming, JIT-yield, idle, and 502 dispatch transitions.
- [x] Testing notes document the callback-slot/state invariants and the streaming-body exception.
- [x] Runtime debug helpers can snapshot and format connection state, callback slots, armed operations, and buffer lengths.
- [x] Test framework fault injection provides shared mmap/mprotect/socket/recv/poll/read/write/send/connect/epoll/timerfd/accept/open scopes for network/runtime tests.
- [x] Malformed upstream E2E coverage drives real proxy sockets through malformed status, EOF, header, and framing failures.
- [x] Replay/simulate route-action matrix coverage documents Static, Default, Proxy/JIT Forward, JIT ReturnStatus, mismatch, and malformed capture behavior.
- [x] Coverage helper now keeps the runtime threshold gate while printing per-area summaries for runtime, compiler, replay/sim, JIT, and optional changed first-party files.
- [x] Fault injection harness can now inject deterministic `clock_gettime` values and failures; access-log time helpers fail closed on clock errors.

## P0: State Invariant Coverage Follow-ups

**Goal**: Extend the newly added invariant checks to less-common transitions and keep the coverage aligned with future runtime changes.

**Why**: Baseline slot/state invariant coverage is now in place for representative static, proxy, body-streaming, JIT-yield, idle, and 502 dispatch transitions. The remaining work is to widen that coverage so new paths do not drift from the same debug/metrics expectations.

**Work**:
- Add follow-up tests for less-common or newly introduced transitions not yet covered by the representative dispatch cases.
- Reuse the existing invariant helper/check pattern when adding new dispatch paths or callback-slot combinations.
- Audit future state-machine changes for:
  - new `conn.state` values or transitions that need invariant assertions,
  - upstream error/timeout paths that may bypass the representative 502/500 cases,
  - teardown/reset flows where callback slots should be cleared before returning to idle/free states.

**Acceptance**:
- The backlog item is complete when remaining uncovered transitions have explicit invariant assertions or are documented as intentionally exempt.

## P0: Fault Injection Harness

**Goal**: Make OS-level edge cases cheap to add and hard to skip.

**Why**: EINTR, mmap failure, partial I/O, and clock-boundary issues rarely happen on local loopback. Small local shims caught real gaps, but they are currently duplicated per test file.

**Work**:
- Extract reusable test shims for:
  - `read` / `write` / `send` / `recv` one-shot and repeated EINTR.
  - `mmap` / `mprotect` failure injection.
  - deterministic `clock_gettime` boundary values.
- Start with runtime modules that already have retry/failure branches:
  - `traffic_capture`
  - `access_log`
  - `epoll_backend`
  - `io_uring_backend`
  - `SlicePool` / `Arena`

**Acceptance**:
- At least one shared helper replaces ad hoc EINTR counters.
- New tests verify retry or fail-closed behavior without depending on real network permissions.

## P2: Coverage Tooling Hygiene

**Goal**: Make coverage reports actionable instead of broad percentage noise.

**Why**: The project has many generated, third-party, benchmark, and architecture-specific files. Raw coverage can hide runtime gaps or chase irrelevant files.

**Work**:
- Review `scripts/coverage_report.py` exclusions and CI coverage target.
- Keep per-area coverage summaries for runtime, compiler, replay/sim, and JIT actionable as test coverage changes.
- Wire changed-file coverage summaries into CI/PR output if the signal proves useful.

**Acceptance**:
- CI coverage output identifies the lowest-covered first-party runtime files.
- Third-party and benchmark files do not dominate coverage decisions.

## P2: TODO Maintenance

**Goal**: Keep this file as a live backlog, not a history log.

**Rules**:
- Move completed implementation milestones into `Recently Completed`.
- Keep active work scoped, prioritized, and testable.
- When review feedback creates a new recurring pattern, add it here with an acceptance criterion.
