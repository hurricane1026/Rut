# TODO

Outstanding work only, ordered by the next useful implementation dependency.
Completed detail belongs in Git history and PR descriptions; this file keeps a
short hand-off summary under **Recently Completed**.

## P0: Finish Revised Core Runtime Boundaries

**Goal**: Complete the remaining runtime-backed pieces of the revised syntax
without accepting source forms that cannot be replayed or resumed faithfully.

### Stream-owned Response mutation

The terminal `return forward(upstream, buffered: true)` path now buffers a
bounded complete upstream response and commits resumable `chain after`
header/status/body mutations consistently over HTTP/1 and HTTP/2. Remaining
work is promoting that terminal operation to a first-class expression such as
`let resp = forward(upstream, buffered: true)`, materializing upstream
status/body/header fields in stream-owned storage so they can be read and
mutated before `return resp`.

**Acceptance**:
- A buffered forward can be bound as a `Response` and returned without losing
  upstream fields.
- Buffered field reads and subsequent mutations survive a yield without
  borrowing proxy or serializer scratch.
- Expression-form overflow, upstream failure, and unsupported request-rewrite
  combinations fail with the same documented policy as terminal buffering.

### Control-plane builtins

Connect the declared `stats()`, `metrics()`, `reload()`, and
`upstream.mark()` surface to runtime services. The checker currently validates
their types and contexts, while MIR rejects lowering rather than returning fake
data.

**Acceptance**:
- `HandlerCtx` exposes only the bounded control-plane capabilities each builtin
  needs.
- Snapshot values serialize deterministically and are covered by harness/replay
  observations.
- Reload and upstream mutation define authorization, failure, and shard-ordering
  behavior.

### Remaining syntax migration

- Implement verifier-bounded `for` loops end to end: parser acceptance,
  analyzer proof of a finite static bound, MIR/RIR lowering, and verifier
  rejection of unbounded or runtime-sized iteration.
- Add `break`/`continue` only after that bounded-loop substrate exists, and keep
  both operations inside the verifier-proven loop control-flow region.
- Migrate remaining `.rut` examples and topic docs to
  `docs/syntax-stability.md` Core spellings.
- Add a fixture gate that parses and type-checks every unmarked executable
  example in `docs/language-card.md`.

**Acceptance**:
- Removed or unsupported forms produce the documented prescriptive diagnostics.
- Compatibility forms remain accepted and keep tests for their documented
  lowering or migration behavior.
- Bounded `for` examples parse, lower, and execute with an analyzer-visible
  maximum trip count; unbounded loops remain a source error.
- Core examples parse and type-check in CI.
- `./dev.sh test` remains green with no hidden-yield additions.

## P1: Implement Exact Owner-Shard State

**Goal**: Implement the accepted strict `Hash<K,V>` contract in
`docs/hash-state.md` before exposing exact shared state or an exact global rate
limit.

**Work**:
- Implement fixed-capacity, no-eviction owner tables with visible
  `full`/`placementLimit` failures.
- Implement per-key atomic `Hash.update` using a pure bounded updater thunk.
- Route `consistent: true` operations to the process owner shard with bounded
  queues, completion credits, deadlines, and definite-not-applied failures.
- Enforce reload schema/ownership compatibility and reject shard-count changes
  that require an unimplemented migration.
- Add the exact rate-limit helper only after its failure policy is explicit.

**Acceptance**:
- Concurrent update tests demonstrate one linearization order per key.
- Queue-full, deadline, placement, reload, and shutdown tests never report an
  ambiguous commit result.
- Harness isolation modes and replay model owner routing deterministically.
- Per-shard `Cache` remains documented and typed as lossy, never as a source of
  truth.

## P2: Specify External State Before Enabling `backend:`

**Goal**: Define cross-node semantics before reserving syntax becomes an
implementation promise.

**Work**:
- Specify read freshness, invalidation, atomic update, retry/idempotency,
  partition, deadline, and reload behavior.
- Decide whether external state is a separate type or a `Hash` provider; do not
  attach it to lossy `Cache` by convenience.
- Extend harness capabilities for deterministic backend faults and stale reads.

**Acceptance**:
- A design review can answer whether every failure was applied, not applied, or
  intentionally unknown.
- Source-of-truth examples never depend on an evicting local cache hit.
- The analyzer continues to reject `Cache(..., backend: ...)` until this
  contract and runtime exist.

## Continuous Engineering Gates

- Every new `ConnState` transition or callback-slot combination adds an
  invariant assertion, or documents why it is transport-specific and exempt.
- Upstream error/timeout and free/reset paths assert resource and slot cleanup.
- Coverage CI keeps first-party area summaries, changed-file output, and the
  lowest-covered runtime files visible; gate exclusions remain labeled.
- Review findings that reveal a recurring class add one scoped backlog item with
  an acceptance criterion, not a historical incident log.

## Recently Completed

- [x] Dynamic JSON plans support runtime scalars, declared structs, bounded
  arrays and string lists, preserve documented field order, reject duplicate
  keys, fail closed on overflow, and expose identical bounded body bytes to
  HTTP/1, HTTP/2, replay, and scenario harness oracles.
- [x] Coverage reporting separates informational host/integration coverage from
  the unchanged runtime gate, labels ISA/gate exclusions, reports changed files,
  and publishes the full result in GitHub Job Summary.
- [x] Rut Core syntax now has explicit Core, compatibility, and experimental
  classes with canonical generated spellings and migrations.
- [x] Runtime invariant coverage includes HTTP/2 proxy-timeout teardown of the
  upstream fd, concurrency slot, pinned epoch, async slot, and callbacks.
- [x] `Cache(..., backend: ...)` is reserved with a targeted source-of-truth
  diagnostic; strict `Hash` owner-shard semantics have an accepted design.
- [x] Control-plane builtins have checker declarations and targeted
  not-yet-lowered diagnostics instead of fake runtime results.
- [x] Import analysis moves large route workspaces off the thread stack.
- [x] Request runtime `[str]` views support ordered `queryAll`/`getAll`, `len`,
  `isEmpty`, `first`, and bounds-safe `at`.
- [x] Literal JSON serialization, response builders, dynamic header mutation,
  and ordered `chain after` header effects lower end to end.
- [x] Terminal buffered forwarding applies resumable `chain after`
  header/status/body mutations over HTTP/1 and HTTP/2; malformed, truncated,
  or over-cap upstream responses and invalid mutations fail closed.
- [x] `Cache<IP,i64>`, branch-local writes, `i64` arithmetic/bitwise helpers,
  and monotonic time support Rut-written GCRA and fixed-window examples.
- [x] The common harness provides deterministic handler/scenario execution,
  virtual time, fault injection, resource cleanup checks, and run/group/process
  state isolation.
