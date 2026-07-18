# TODO

Outstanding work only, ordered by the next useful implementation dependency.
Completed detail belongs in Git history and PR descriptions; this file keeps a
short hand-off summary under **Recently Completed**.

## P0: Finish Revised Core Runtime Boundaries

**Goal**: Complete the remaining runtime-backed pieces of the revised syntax
without accepting source forms that cannot be replayed or resumed faithfully.

### Control-plane builtins

Connect the remaining declared `reload()` mutation surface to the process
coordinator. Read-only snapshots and timer-only `upstream.mark()` are connected
end to end.

The authority, visible boolean failure, config-generation ordering, lifetime,
and harness contract is fixed in `docs/control-plane-mutations.md`. Implement
it in the required order documented there; do not reintroduce the old
`Void`/statement-only declarations or a hidden wait.

The shared bounded mutation port, pointer-free `Server`/`Upstream.servers`
runtime model, generation-tagged manual override table, health-selection
priority, HandlerCtx/JIT helper boundary, production injection, and
deterministic harness fixture plus timer-only shard-pinned source lowering are
connected. Generation-carrying shard publication, installation
acknowledgements, and exact HTTP/1 request / suspended HTTP/2 stream program
pins plus terminate-mode WebSocket session pins are connected. The process
coordinator, compatibility validation, SIGHUP activation path, and process
harness are connected. Route-only `reload()` lowering and its explicit CLI
authority flag remain.

**Acceptance**:
- Reload and upstream mutation define authorization, failure, and shard-ordering
  behavior.

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

- [x] One process reload coordinator compiles into a spare program, validates
  timer/Cache compatibility, publishes strict generations to every shard,
  waits for installation acknowledgements and exact old-program pins, reuses
  the retired slot, and drives the same single-slot path from SIGHUP. A real
  process harness covers signal-to-activation and the bounded terminal record.
- [x] Shard config publication acknowledges the generation actually installed
  at the event-loop command boundary, and loaded programs expose exact,
  close-safe HTTP/1 request, suspended HTTP/2 stream, and terminate-mode
  WebSocket session pins for reclamation.
- [x] A shard-pinned timer can enumerate a statically declared upstream's
  pointer-free `Server` values, pass them through pure typed helpers, and
  synchronously publish generation-checked manual health with visible boolean
  failure; route, unpinned, runtime-bound, stale, and foreign uses fail closed.
- [x] `RouteConfig` pins a monotonic generation, `Upstream.servers` produces a
  pointer-free generation-stable view, and both network backends consult manual
  health before shard-local active/passive health; explicitly unhealthy sets
  fail closed when no backend remains.
- [x] Production and deterministic harness execution share one allocation-free
  control-plane mutation port with single-slot reload admission, terminal
  outcome records, generation-tagged manual-health overrides, and fail-closed
  JIT helper entry points; Rut source forms remain gated.
- [x] Control-plane mutations have one explicit contract for authority, visible
  boolean failure, config-generation publication, program lifetime, shard
  ordering, manual-health priority, and deterministic replay; runtime wiring
  remains the P0 implementation task above.
- [x] `language-card.md` Rut fences are front-end fixtures by default; target
  and fragment surveys require an adjacent reasoned skip marker, and every
  unmarked example parses and type-checks in CI.
- [x] Executable `.rut` examples and topic documentation use Rut Core route
  declarations; chain examples attach one explicit chain directly to each
  route instead of teaching grouped-route inheritance.
- [x] Unlabeled `break`/`continue` lower only inside verifier-bounded static
  `for`, work through direct, guard, if, match, and nested-loop CFG paths, and
  always target the innermost loop without introducing runtime back edges.
- [x] Static `for` accepts only compile-time array literals or aliases, unrolls
  under the MIR/verifier block budget, rejects every runtime iterator and wait
  combination, and executes through the same JIT CFG as hand-written guards.
- [x] Expression-form `forward(upstream, buffered: true)` materializes bounded
  status/body/header fields in stream-owned storage, survives later yields,
  replays through the deterministic harness, and preserves the terminal
  buffering failure and request-rewrite policy over HTTP/1 and HTTP/2.
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
- [x] `stats()` and `metrics()` latch value-only shard/process metric snapshots
  at handler entry, serialize fixed-order bounded JSON, survive resumes without
  rereading mutable state, and replay through an explicit harness capability.
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
