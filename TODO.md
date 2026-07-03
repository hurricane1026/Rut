# TODO

Outstanding work items, prioritized for the next implementation passes.

## P0: Front-End Migration to the Revised Syntax Spec (branch design_syntax)

**Goal**: Migrate lexer/parser/checker to the 2026-07 DESIGN.md §3 revision
("Swift-exact or absent"). `docs/language-card.md` is the target surface;
each item should land with fix-it diagnostics matching DESIGN.md §3.6.

**Work** (roughly in dependency order):
- [x] Lexer: `&&` `||` `!` `!=` `<=` `>=` emitted; `and`/`or`/`not` lex to
  fix-it errors; lone `&`/`^`/`~` → bitwise.* fix-it; `?` → if-let fix-it
  (commit: slice 1). `respond`/`break`/`continue` keywords still pending.
- [x] Parser: `!`/`!=`/`<=`/`>=` desugar to Eq/Lt/Gt (+ `== false` wrap);
  `&&` binds tighter than `||` (slice 1). Caseless match arms at all five
  sites with `case`/`:` fix-its + cross-line-dot arm boundary rule
  (slice 2a). `guard let x` shorthand (slice 2b-1).
- [ ] Parser/analyze: `if let name = expr { }` — plan: parse like guard-let
  into the If stmt (name/bind_value fields), then in EVERY If analysis site
  (analyze.cc ~4483/8630/8726/8831/11180 + nested-match copies) lower cond to
  HirExprKind::HasValue(expr) and inject a narrowed HirLocal (clone the
  guard-let binding block at analyze.cc ~8579) visible only in then-branch
  scoped_locals. Reuse make_guard_bound_init.
- [ ] `respond status[, body] | resp` statement — NEW semantics: today a
  func's `=> 401`-style guard values are the *function's return value*, not
  an HTTP short-circuit. respond needs an HIR terminal (like ReturnStatus)
  legal inside funcs, carried through inlining so the inlined route sends the
  response and stops. Design first: extend HirGuard::FailKind/Term reuse.
- [x] `guard` condition bool-only check + fix-it; guard-let usable-value
  semantics: known nil/error inits fold the condition to false (else always
  runs, binding skipped for known error); runtime error-capable inits lower
  to a HasValue condition with the bound local narrowed (review follow-up).
- [ ] Lowering: opt carrier for pure-optional values (`may_nil` without
  `may_error`) — HasValue/guard-let runtime nil exits currently can't lower
  (emit_opt_is_nil needs an opt-typed carrier). guard-let over such values is
  now REJECTED with a fix-it ("use an error-capable source") rather than
  silently passing; lift the rejection when the carrier lands.
- [ ] Runtime ordering: guard-let over a runtime error value lowers a
  HasValue cond, but the resume-state-0 error prelude intercepts with 500
  before the guard branch. Per spec the guard's else should win; revisit the
  prelude/guard ordering in mir_build.
- [ ] websocket trailing block `{ frame in }`; object literal only in
  call-argument position; pipeline RHS placeholder validation.
- Checker/builtins: `bitwise.and/or/xor/flip/shiftLeft/shiftRight` namespace;
  `req.header/set/add/getAll` + `resp.set/remove/add/header` (remove hyphenated
  header property paths); `req.params.*` capture namespace (flat `req.<capture>`
  becomes an error with fix-it); `req.queryAll`; `respond` legality (middleware
  only) vs status-`return` (handler only); `stats()/metrics()/reload()/
  upstream.mark()` declarations.
- Diagnostics: implement the §3.6 fix-it rows for `?.`, `??`, postfix `!`,
  truthiness guard, bitwise symbols, placeholder-less pipeline, `case`,
  middleware/handler return-respond confusion.
- Tests/examples: migrate `examples/*.rut`, test fixtures, and docs/ topic
  pages (match.md, pipe.md, decorators.md, for-loops.md, ...) to the new
  surface once the front-end accepts it.

**Acceptance**: language-card examples all parse and type-check; old forms
produce the documented fix-its; `./dev.sh test` green.

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

## P1: Rut Core Syntax Reduction

**Goal**: Keep the stable language surface small enough for deterministic
review, verification, replay, and LLM-assisted generation.

**Why**: Rut has accumulated compatibility syntax for decorators, pipe method
stages, tuple-slot pipe placeholders, protocol-style methods, and match
expansions. Some of these are useful, but stable core syntax needs one
canonical spelling for common gateway tasks.

**Work**:
- Treat decorator syntax as compatibility and design `chain` as the stable
  before/after handler middleware model.
- Keep pipe in core, but document generated code around direct function stages:
  `value | fn(_, arg)`.
- Keep method-stage pipe syntax, placeholder-free pipe stages, and tuple-slot
  pipe placeholders out of core examples unless compatibility requires them.
- Revisit protocol/impl exposure so protocol methods do not read like general
  structure member functions in generated Rut code.
- Audit `match` and generic examples for constructs that should be core,
  compatibility, or experimental.

**Acceptance**:
- Core docs distinguish stable core, compatibility, and experimental syntax.
- Generated examples use one canonical spelling for pipe, middleware, fallback,
  and async boundaries.
- Compatibility syntax has a clear lowering or migration path to core forms.

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
