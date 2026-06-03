# Design Goals

Rut's language and runtime should be optimized for production gateway behavior
that is easy to reason about, easy to test, and hard to misgenerate.

## Low Ambiguity

Rut should avoid multiple equivalent ways to express the same common operation.
When a feature is added, it should have a narrow role and a clear interaction
with existing constructs.

Necessary gateway capabilities should not be removed merely because they add
language surface. Instead, Rut should refine them into one canonical form with a
small, explicit state-machine meaning.

Guidelines:

- Prefer one canonical construct for each common gateway task.
- Allow at most one secondary idiom when it materially improves readability.
- Reject code whose intent depends on subtle precedence, overload resolution, or
  implicit runtime behavior.
- Prefer explicit domain constructs over strings or user-defined conventions.
- Make diagnostics deterministic and prescriptive.

This is a language-design constraint, not only a style preference. A smaller
surface makes Rut easier for humans, compilers, verifiers, and LLMs to use
correctly.

## Mechanically Reducible Programs

Every route should lower to a compact state machine. The compiler and verifier
should be able to identify:

- terminal responses,
- upstream forwards,
- timer and IO waits,
- wait resume targets,
- fail-closed branches,
- bounded loops over finite inputs.

Features that cannot be represented in this model should be rejected, bounded,
or isolated behind an explicit escape hatch with weaker guarantees.

Suspension points should be explicit in the source. Rut can still let users
write sequential code, but IO that can yield must be declared through constructs
such as `wait`, `forward`, or an explicitly asynchronous operation. Ordinary
helper functions should not hide new runtime yield points.

## Verifier-Oriented Semantics

Rut should not depend on general-purpose formal tools for normal user-code
checks. The target is a native Rut verifier that checks the small automata
generated from Rut IR.

The verifier should focus on Rut-specific properties:

- route state machines cannot deadlock in modeled runtime states,
- event waits can only resume from declared event arms,
- fail-closed branches exist for runtime operation failures,
- callback slots and pending operations stay consistent with runtime state,
- event-driven cycles make progress under explicit fairness assumptions.

TLA+ can remain as a design-level reference for runtime invariants and checker
validation, but Java/TLC should not be required to verify ordinary user code.

The verifier should prefer a small set of capability-specific models over one
large universal model. For example, cross-shard state can start with the modes
Rut needs for production and grow only when replay, simulation, and verifier
semantics are clear.

## Replay and Simulation

Captured traffic and synthetic events should be able to exercise the same route
semantics as production execution. This keeps correctness grounded in concrete
observations and lets CI compare expected behavior with replayed behavior.

Replay and simulation should be used to test:

- routing decisions,
- response status and headers,
- upstream selection and failover branches,
- malformed input handling,
- timeout and wait behavior,
- hot-reload compatibility.

When production behavior cannot be replayed exactly, the difference should be an
explicitly modeled environment effect rather than an accidental gap.

## LLM Risk Reduction

Rut is expected to be used with LLM-assisted generation, so the language should
be designed to reduce plausible wrong code.

Useful constraints:

- narrow grammar,
- small keyword set,
- domain-specific types,
- no unbounded loops or recursion,
- explicit `guard`, `match`, `wait`, and `forward` semantics,
- explicit async declarations for operations that can suspend,
- deterministic formatting and diagnostics,
- route-local verification feedback.

The goal is not merely to make Rut easy for LLMs to write. The goal is to make
incorrect generated code easy to reject, replay, simulate, or prove impossible
within Rut's restricted semantics.

## Feature Acceptance Rule

A new language/runtime feature should answer these questions before it becomes
part of the core surface:

1. Does it introduce another way to solve a problem that already has a canonical
   Rut form?
2. Can it lower to the route state-machine model?
3. Can replay or simulation exercise it deterministically?
4. Can the native verifier check its safety and progress obligations?
5. Does it reduce or increase the chance of LLM-generated plausible wrong code?

If the answer is unclear, the feature should stay experimental or be expressed
as a lower-level escape hatch rather than added to the main language.

## Current Review Decisions

The current design review keeps the following direction:

- Required gateway capabilities should stay in the roadmap, but each one needs a
  canonical, verifier-friendly form.
- Async behavior should be explicit at the source boundary. The compiler may
  lower sequential syntax into states, but it should not discover hidden yield
  points inside ordinary helper code.
- Decorator execution ordering and magic request binding are known risks, but
  are deferred. They should be revisited before decorators become part of the
  stable core surface.
- State consistency should be simplified to the production modes Rut actually
  needs first. Additional consistency/backing-store modes should wait until
  their replay and verifier contracts are precise.
- Optional/fallback syntax remains open. Symbolic forms such as `?.` and `??`
  are concise but may be less clear to new users and LLMs than named forms. The
  core language should prefer whichever form yields the most deterministic
  diagnostics and least ambiguity in generated code.
