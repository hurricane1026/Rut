# User Code Verification

Rut can use the runtime TLA+ model as a reference point, but TLA+/TLC should not
be the primary verification engine for user code. It is too general for Rut's
hot path: it brings a Java dependency, explores more machinery than Rut needs,
and is not shaped around fast per-route feedback.

The tractable product direction is a Rut-specific verifier:

> Compile Rut user-code IR into a small verification automaton and run a
> purpose-built checker that proves Rut protocol properties: legal state
> transitions, callback-slot hygiene, yielded handler wakeups, fail-closed
> behavior, deadlock freedom, and progress under explicit fairness assumptions.

## Source of Truth

The verifier should consume Rut's DSL/RIR, not generated C++ or JIT machine
code. The IR should be the single semantic source for:

- generated runtime/JIT code,
- generated verification automata,
- a manifest that maps IR operations to runtime transitions.

This avoids reverse-engineering implementation details and gives the checker a
small, stable language to reason about.

## Why Not TLA+ as the Main Engine

TLA+ remains useful for the runtime's abstract design, but it is not the right
execution engine for checking every user route:

- It depends on TLC and Java in developer/CI environments.
- It is optimized for general state-space exploration, not Rut's restricted
  event-machine shape.
- The generated specs would still require a translator, so the trusted boundary
  does not disappear.
- Liveness and fairness configuration is easy to make too weak, too strong, or
  too slow.
- The feedback loop should be close to parser/type-checker speed for common
  routes.

Rut should instead keep the TLA+ model as an oracle for validating the checker
design and a source of test vectors for the custom engine.

## Verification Automaton

The first useful handler model can be a finite automaton:

- handler state/basic-block id,
- terminal responses,
- `wait(ms)` and event waits,
- `wait any { ... }` race arms,
- upstream connect/send/recv waits,
- `forward` actions,
- fail-closed error responses.

The verifier should compose this handler automaton with a built-in model of the
Rut runtime protocol. This model should be small enough to live in native code
and run deterministically without external solvers.

Each automaton node should carry:

- the handler program point,
- the abstract runtime state,
- active callback slots,
- pending yield kind and target,
- pending runtime operation class,
- bounded symbolic facts needed by Rut's control-flow rules.

## Properties to Check

Safety properties:

- yielded handlers are in `ExecHandler` with no stale callback slots,
- only declared wait arms can resume a handler,
- upstream events cannot wake a handler waiting on a different upstream target,
- proxy/connect failures move to a closed or `Sending` fail-closed path,
- terminal response paths do not leave proxy or body-streaming callbacks behind,
- keepalive and pipeline recovery return to `ReadingHeader` with clean slots.

Deadlock checks:

- no modeled state is stuck without an allowed next action,
- each submitted timer/connect/send/recv has a modeled completion or failure
  path,
- runtime and handler states agree on which event can advance the system.

Liveness checks:

- under fair timer and IO-completion assumptions, each request eventually
  reaches a terminal response, proxy completion, close, or an explicitly allowed
  waiting state,
- handler event loops that repeatedly yield are distinguishable from cycles that
  never yield, return, or forward.

Fairness must be explicit. Without assumptions such as "an armed timer
eventually fires" or "a submitted send eventually succeeds or fails," any
network program can be modeled as not making progress.

## Custom Checker Shape

The checker can be much simpler than a general-purpose model checker:

- Use an explicit-state graph over Rut's finite protocol state.
- Represent callback slots and pending operations as compact bitsets/enums.
- Use worklist reachability for safety and deadlock checks.
- Use strongly connected components for livelock/progress checks.
- Run route-local checks first, then optionally compose multiple routes only
  where shared runtime resources matter.
- Emit counterexample traces in Rut terms, not TLA+ terms.

This should make checks fast enough for normal CI and eventually for local
developer feedback during compilation.

## Infinite Loops

The custom checker can find finite-state livelocks and cycles in the abstract
handler automaton. It cannot prove termination for arbitrary native code.

Rut should therefore split the problem:

- Static CFG checks reject handler cycles that contain no `yield`, `return`,
  `forward`, or provably bounded progress.
- The verifier checks the remaining event-driven cycles under fairness.
- Runtime watchdogs or fuel limits remain necessary for any native or
  insufficiently restricted user-code escape hatch.

## What This Does Not Prove

This is not a full C++ verifier. It does not prove:

- arbitrary arithmetic or string manipulation correctness,
- memory safety or absence of undefined behavior in generated native code,
- every kernel/network behavior,
- correctness of the IR-to-automaton translator by itself.

The translator risk should be reduced by generation discipline: both runtime
code and verification automata should come from the same IR, and CI should
compare the generated manifest against runtime transition APIs and checked
automaton actions.

## Prior Art

Useful reference points:

- PlusCal: an imperative-looking algorithm language that translates to TLA+ for
  TLC model checking.
- Quint: a typed, executable specification language with TLA-style semantics and
  model-checker integration.
- P: an event-driven state-machine language with systematic exploration of
  asynchronous behaviors.
- Dafny, F*, and Verus: verification-oriented languages where code and
  specifications are part of one workflow.
- Kani/CBMC-style tools: implementation-level model checking for bounded
  program properties, complementary to TLA+'s protocol-level modeling.

The closest shape for Rut is a mix of P's event-machine discipline, PlusCal or
Quint's generated model-checkable actions, and Dafny's single-source semantic
discipline. The implementation should be closer to P's specialized checker than
to invoking TLC for every route.

## Incremental Plan

1. Define a small handler-verification IR covering terminal responses, timers,
   event waits, upstream waits, and forward.
2. Generate a compact handler automaton plus an action manifest from that IR.
3. Implement a native explicit-state checker for safety and deadlock checks.
4. Add SCC-based progress checks for Rut-specific liveness properties under
   explicit fairness assumptions.
5. Cross-check the checker against small TLA+ reference cases while the engine
   is young.
6. Compare the manifest against runtime transition helper names and generated
   JIT metadata in CI.
7. Extend the IR only when the corresponding abstract semantics and checks are
   clear.

The first prototype should model one or two representative handlers, not the
whole language. A good initial target is a handler with `wait any { ... }`, a
timer timeout branch, and an upstream connect/send/recv path.

## Current MVP

The first native verifier entry point is RIR graph validation. It is intentionally
small: it checks route-local block structure before any larger runtime model is
introduced.

Covered today:

- every block has exactly one final terminator,
- branch and jump targets point at existing blocks,
- all blocks are reachable by default,
- RIR yield terminators are lowered to the executable `YieldTimer` state-machine
  boundary; non-lowered yield opcodes are rejected,
- encoded yield kind, next-state, and payload fields match function yield
  metadata for every block, including dead blocks when reachability is relaxed,
- each yield state has exactly one producer: duplicate and missing encoded
  `next_state` values are rejected,
- yield functions declare a supported resume mapping, and verifier reachability
  starts from the same state-zero dispatch root used by codegen,
- lowered yield kinds are restricted to runtime-schedulable wait/event kinds,
- a small runtime-protocol model classifies each lowered yield by pending
  operation, callback slot, and submit/completion/fail-closed transition shape,
  and rejects yield shapes that the event loop cannot safely schedule, such as
  downstream-send event yields and upstream connect/recv/send yields without a
  target payload,
- runtime-protocol verifier failures include a compact Rut-facing trace with
  the yield kind, payload, modeled pending operation, callback slot, and failure
  reason,
- a handler-verification automaton MVP summarizes route terminators, yields,
  resume edges, and runtime transition counts for the next explicit-state
  checker.

This is not yet the full safety/deadlock checker described above. It is the
foundation for that checker: a route automaton must be structurally valid before
Rut can prove callback hygiene, declared resume targets, or progress properties.
The next verifier layer should turn this automaton summary into an explicit-state
safety/deadlock checker with callback-slot hygiene checks.

## TLA+ Role

TLA+ should stay in the project for design-level runtime invariants and for
validating the custom checker's semantics. It should not be required to verify
normal Rut user code.
