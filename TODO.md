# TODO

Outstanding work items, prioritized for the next implementation passes.

## P0: Front-End Migration to the Revised Syntax Spec (branch design_syntax)

**Goal**: Migrate lexer/parser/checker to the 2026-07 DESIGN.md §3 revision
("Swift-exact or absent"). `docs/language-card.md` is the target surface;
each item should land with fix-it diagnostics matching DESIGN.md §3.6.

**Work** (roughly in dependency order):
- [x] Lexer: `&&` `||` `!` `!=` `<=` `>=` emitted; `and`/`or`/`not` lex to
  fix-it errors; lone `&`/`^`/`~` → bitwise.* fix-it; `?` → if-let fix-it
  (commit: slice 1). `respond` is implemented as a contextual statement word
  so user declarations and members may still use that name; `break`/`continue`
  remain pending with runtime `for` loops.
- [x] Parser: `!`/`!=`/`<=`/`>=` desugar to Eq/Lt/Gt (+ `== false` wrap);
  `&&` binds tighter than `||` (slice 1). Caseless match arms at all five
  sites with `case`/`:` fix-its + cross-line-dot arm boundary rule
  (slice 2a). `guard let x` shorthand (slice 2b-1).
- [x] Parser/analyze: `if let name = expr { } else { }` — parses like
  guard-let (bind_value/name/expr reused on the If stmt at both parse sites).
  Every non-const If analysis site (analyze.cc: analyze_function_body_stmt,
  analyze_match_arm_body, analyze_guard_fail_body, analyze_control_stmt) lowers
  the cond to HirExprKind::HasValue(expr) via analyze_guard_cond (known-value
  folding + pure-optional rejection reused) and injects a narrowed HirLocal
  (make_if_let_local → make_guard_bound_init) into the THEN-branch scope only
  (else/continuation never see it). Terminator-branch sites only swap the cond
  (binding unreferenceable there). Pure-optional carriers are covered by the
  lowering item below.
- [x] `respond status[, body]` statement — contextual parsing, literal-status
  validation, HIR `ReturnStatus`, helper propagation, and respond-capable
  `chain before` steps are implemented. `respond resp` accepts a Response
  builder and preserves its ordered literal `set`/`add`/`remove` header prefix
  through helper propagation. `chain after` helpers with exactly one `Response`
  parameter can apply ordered runtime header mutations to successful direct and
  forwarded responses; short-circuit branches do not publish those effects.
- [x] `guard` condition bool-only check + fix-it; guard-let usable-value
  semantics: known nil/error inits fold the condition to false (else always
  runs, binding skipped for known error); runtime error-capable inits lower
  to a HasValue condition with the bound local narrowed (review follow-up).
- [x] Lowering: opt carrier for pure-optional values (`may_nil` without
  `may_error`) — the Optional<inner> carrier substrate (opt_is_nil/opt_unwrap,
  req.query's Optional<Str>, opt-typed local storage) already existed; the
  guard-let/if-let rejection is lifted: analyze_guard_cond emits HasValue for
  pure-optional sources too, make_guard_bound_init ValueOf-wraps them, and
  the narrowed binding clears may_nil (e2e: guard/if-let over req.query,
  req.header, an optional-struct func result, and the `guard let q`
  shorthand).
- [x] Runtime ordering: guard-let over a runtime error value now wins over
  the resume-state-0 error prelude — RecoveryScan treats a bare
  HasValue(LocalRef) guard condition as a recovering use, so the prelude
  skips locals whose error the guard consumes (e2e: pick(req.http11) ->
  200 / guard else 401).
- [x] Error-prelude suppression: upgrade the linear-dominance walk to real
  per-local exit-dominance so a recovery behind a benign pre-reject
  (`guard ok else { return 403 }` before `wait`/recovery) can suppress the
  prelude WITHOUT letting a terminating sibling that returns success mask
  an unrecovered error (see
  conditional_guard_keeps_error_prelude_on_unguarded_sibling — the two
  shapes are structurally identical to a single-continuation walk; only
  exit-dominance separates them). Until then: conservative over-keep.
- [x] WebSocket terminate trailing blocks require the explicit
  `{ frame in ... }` binding; the legacy implicit-frame block is rejected.
- [x] Object literal syntax is accepted only in call-argument position and
  represented explicitly in the AST; bare/general-expression use is rejected.
  [x] `json()` recursively serializes bounded literal
  bool/int/string/nil/array/object values and can feed `return status, json(...)`.
  Still pending: dynamic values and struct/runtime serialization.
- [x] Pipeline RHS validation requires a call stage with an explicit `_` / `_N`
  placeholder and reports the canonical placement fix-it before call analysis.
- Checker/builtins: [x] `.or(default)` (sugar for eager `any(value, default)`);
  [x] `req.params.*` capture namespace (flat `req.<capture>` is an error with a
  fix-it); [x] `bitwise.and/or/xor/flip/shiftLeft/shiftRight` namespace
  (end-to-end: analyze fold + HIR/MIR/RIR Bit* ops + LLVM codegen; i32/i64
  same-width operands, shifts saturate outside the width, `flip` desugars to
  `xor(a, -1)`; user bindings named `bitwise` shadow the namespace). Still
  [x] `Response` locals with ordered `set/remove/add/header`: literal prefixes
  fold into response-header sets and dynamic string values lower through a
  bounded per-request mutation log for direct routes; [x] `chain after`
  response-header mutation for direct and forwarded responses. Still pending:
  buffered body/status mutation and after middleware on `wait`/`for` routes
  (needs a resumable, stream-owned runtime Response); [x] runtime `[str]`
  request views with ordered `req.queryAll`/`req.getAll`, `.len`, `.isEmpty`,
  `.first()`, and bounds-safe `.at(i)`;
  [x] checker-level `stats()/metrics()/reload()/upstream.mark()` declarations
  (opaque Stats/Metrics types, JSON-serializable metadata, parameter labels,
  statement/value and route/timer context contracts). Runtime lowering remains
  pending: HandlerCtx does not yet expose control-plane services, so MIR rejects
  snapshot values instead of compiling a fake result.
- Diagnostics: [x] §3.6 fix-its for `?.`/`??`, postfix `!`, truthiness
  guards, bitwise symbols, placeholder-less pipelines, and `case`/colon match
  arms; [x] middleware status-`return` and handler `respond` context errors
  with canonical replacement guidance.
- Tests/examples: migrate `examples/*.rut`, test fixtures, and docs/ topic
  pages (match.md, pipe.md, decorators.md, for-loops.md, ...) to the new
  surface once the front-end accepts it.

**Acceptance**: language-card examples all parse and type-check; old forms
produce the documented fix-its; `./dev.sh test` green.

## P1: State and Rate-Limit Semantics

**Goal**: Finish the state semantics exposed by the Cache/rate-limit slices
without presenting lossy or per-shard state as exact shared state.

**Work**:
- [x] Lower `Cache.set` at its branch position instead of only in the route-entry
  prelude. This enables a Rut limiter to commit the successor only on its
  accepted branch; the shipped example now demonstrates that policy.
- Design the strict, visible-failure `Hash` table and an owner-shard atomic
  update primitive before offering exact cross-shard rate limiting or state
  whose absence would be incorrect.
- Keep cross-node `backend:` syntax reserved until reads have an explicit
  freshness/invalidation contract; do not describe Cache as a source of truth.

**Acceptance**:
- A rate-limit test demonstrates both meter-every-attempt and meter-on-accept
  policies without special C++ rate-limit logic.
- Any exact shared-state surface specifies capacity failure, update atomicity,
  shard ownership, and read freshness before parser/runtime implementation.

## Recently Completed

- [x] Literal JSON serialization produces canonical compact JSON with string
  escaping, nested objects/arrays, unique-field validation, and direct response
  body lowering. Dynamic expressions are rejected until the bounded runtime
  serializer lands.
- [x] Handler bodies reject `respond` with a `return` fix-it, while middleware
  functions reject status-`return` with a `respond` fix-it; valid helper
  `respond` propagation and ordinary function value expressions are unchanged.
- [x] `chain after` supports ordered `Response` header `set`/`add`/`remove`
  effects on successful direct and forwarded routes. Effects use the pending
  response mutation log and commit only on the selected success terminator;
  invalid helper shapes, empty-effect helpers, and wait/for routes are rejected
  with targeted diagnostics.
- [x] Dynamic direct-route Response mutations use a two-phase pending/commit
  log: `resp.header()` observes ordered pending writes, while only `return resp`
  publishes them. Guarded source-order lowering remains blocked until effects
  and their dependent reads can move out of the function prelude together.
- [x] Error-prelude exit-dominance now treats literal 4xx/5xx pre-rejects as
  fail-closed while keeping the prelude for success, redirect, dynamic, and
  forward exits that do not recover a fallible local.
- [x] Parser stack-frame slimming moved route statements and match-arm patterns
  into pools, fixing the gcc 16.1 Debug overflow; further slimming is only
  needed if frames grow again (PR #166).
- [x] `respond status[, body]` now short-circuits through helpers and
  respond-capable `chain before` steps; `respond` remains contextual.
- [x] `req.params.*` is the canonical route-capture namespace with a fix-it for
  the removed flat spelling.
- [x] `Cache<IP, i64>` provides bounded, lossy, per-shard state slots; i64
  arithmetic/bitwise operations and `time.nowMicros()` support Rut-written
  rate-limit algorithms.
- [x] `req.set("Name", "value")` and `req.add("Name", "value")` lower through
  HIR/MIR/RIR to the bounded request-header override runtime. `set` replaces and
  deduplicates existing fields; `add` preserves them and appends a new field.
  Both are statement-only, validate literal safe header names and values,
  support leading route statements and selected match-arm effects, and fail
  closed at runtime.
- [x] `let resp = response(status)` creates a compile-time Response builder;
  literal `resp.set/add/remove` mutations and `resp.header` reads fold in source
  order, `return resp` reuses the existing response-header-set ABI, and ordered
  duplicate names preserve multi-value fields such as `Set-Cookie`.
- [x] Dynamic `str` values in `resp.set/add` and ordered dynamic
  `resp.remove/header` lower through HIR/MIR/RIR/JIT into a bounded per-request
  mutation log. HTTP/1 and HTTP/2 merge it with the literal header prefix;
  invalid/overflowing mutations fail closed. Direct routes with guards,
  decorators, `wait`, or `for` remain rejected until mutations are stream-owned.
- [x] `examples/ratelimit.rut` demonstrates GCRA and fixed-window limiting over
  `Cache`; branch-local conditional writes support meter-on-accept policies.
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
- Keep method-stage pipe syntax and tuple-slot pipe placeholders out of core
  examples unless compatibility requires them; placeholder-free stages are
  rejected by the stable grammar.
- Revisit protocol/impl exposure so protocol methods do not read like general
  structure member functions in generated Rut code.
- Audit `match` and generic examples for constructs that should be core,
  compatibility, or experimental.

**Acceptance**:
- Core docs distinguish stable core, compatibility, and experimental syntax.
- Generated examples use one canonical spelling for pipe, middleware, fallback,
  and async boundaries.
- Compatibility syntax has a clear lowering or migration path to core forms.

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
