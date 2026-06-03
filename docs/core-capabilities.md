# Core Capabilities

Rut should keep the gateway capabilities needed for production, but each
capability needs one canonical syntax and one verifier-visible meaning.

## Core Surface

The stable core surface should prioritize features that lower directly to a
route automaton:

- route matching,
- domain-typed request inspection,
- `let` and handler-local `var`,
- `guard`, `if`, and `match`,
- bounded `for` over finite inputs,
- terminal `return`,
- terminal `return forward(upstream)`,
- explicit `wait(...)` and `wait any { ... }`,
- bounded per-shard state.

## Async Boundaries

Rut code may look sequential, but every operation that can suspend must be
visible at the source boundary.

Canonical core forms:

```rut
return forward(api)

let ev = wait(downstream.recv())

wait any {
    downstream.recv() => { return 204 }
    timer(2000) => { return 408 }
}
```

Non-terminal concurrent work such as `submit`, detached work such as `fire`, and
one-off outbound HTTP calls are required capabilities, but they should share the
same explicit async discipline before they are treated as stable core syntax.
They must produce verifier-visible operations, replay events, and fail-closed
paths.

## Optional And Fallback

Rut Core should prefer named fallback over symbolic optional chaining:

```rut
let page = req.query("page").or("1")

guard let user = req.body(User) else {
    return 400
}
```

The symbolic forms `?.` and `??` are concise, but they are easy to overuse and
harder to diagnose precisely. They should stay non-core/reserved until examples,
diagnostics, and LLM-generated code show that they reduce rather than increase
ambiguity.

`any` and `all` should be reserved for race/concurrency meanings, not ordinary
optional fallback.

## State Consistency

The first stable state model should be the smallest useful production set:

- per-shard bounded state for fast local decisions,
- one exact mode for request-visible consistency when needed.

Additional modes such as broadcast notification, targeted notification, or
external backing stores should be added only when their ordering, failure,
replay, and verifier semantics are explicit.

## Deferred Risks

The current decorator design has two known risks:

- execution order is not yet a strict first-instruction guard chain,
- magic request binding through a parameter named `req` can be shadowed.

These are not blockers for the current design pass, but they should be resolved
before decorators become stable core syntax.
