# User Code Formal Verification

Rut can use the runtime TLA+ model as the start of a broader verification
pipeline, but the useful target is narrower than "prove arbitrary user code is
correct." The tractable target is:

> Generate an abstract model from Rut's user-code IR and check that it preserves
> the runtime protocol: legal state transitions, callback-slot hygiene, yielded
> handler wakeups, fail-closed behavior, and progress under explicit fairness
> assumptions.

## Source of Truth

The model should be generated from Rut's DSL/RIR, not from generated C++ or JIT
machine code. The IR should be the single semantic source for:

- generated runtime/JIT code,
- generated TLA+ handler actions,
- a manifest that maps IR operations to runtime transitions.

This avoids reverse-engineering implementation details and gives the checker a
small, stable language to reason about.

## What to Model

The first useful handler model can be a finite automaton:

- handler state/basic-block id,
- terminal responses,
- `wait(ms)` and event waits,
- `wait(any(...))` arms,
- upstream connect/send/recv waits,
- `forward` actions,
- fail-closed error responses.

The generated TLA+ module can compose this handler automaton with
`spec/runtime_state.tla`. TLC then checks the combined state space instead of
only the generic runtime state machine.

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

## Infinite Loops

TLA+ can find finite-state livelocks and cycles in the abstract handler
automaton. It cannot prove termination for arbitrary native code.

Rut should therefore split the problem:

- Static CFG checks reject handler cycles that contain no `yield`, `return`,
  `forward`, or provably bounded progress.
- TLA+ liveness checks verify the remaining event-driven cycles under fairness.
- Runtime watchdogs or fuel limits remain necessary for any native or
  insufficiently restricted user-code escape hatch.

## What This Does Not Prove

This is not a full C++ verifier. It does not prove:

- arbitrary arithmetic or string manipulation correctness,
- memory safety or absence of undefined behavior in generated native code,
- every kernel/network behavior,
- correctness of the IR-to-TLA+ translator by itself.

The translator risk should be reduced by generation discipline: both runtime
code and TLA+ should come from the same IR, and CI should compare the generated
manifest against runtime transition APIs and modeled TLA+ actions.

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
discipline.

## Incremental Plan

1. Define a small handler-verification IR covering terminal responses, timers,
   event waits, upstream waits, and forward.
2. Generate a TLA+ handler module plus an action manifest from that IR.
3. Compose the generated handler module with `spec/runtime_state.tla`.
4. Add TLC checks for deadlock, slot invariants, wait/resume legality, and a
   small liveness property under explicit fairness assumptions.
5. Compare the manifest against runtime transition helper names and generated
   JIT metadata in CI.
6. Extend the IR only when the corresponding abstract semantics and checks are
   clear.

The first prototype should model one or two representative handlers, not the
whole language. A good initial target is a handler with `wait(any(...))`, a
timer timeout branch, and an upstream connect/send/recv path.
