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
- route `chain` before handler steps,
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

## Handler Chains

Decorator-style middleware is too flexible for Rut Core because binding,
ordering, return-value conventions, and execution timing are not obvious from a
route entry. Core middleware should use explicit chains instead:

```rut
chain secure_upload {
    before decode_body(req) else 400
    before require_auth(req) else 401
}

route {
    use chain secure_upload

    POST "/data" {
        return 204
    }
}
```

The implemented chain boundary is `before` handler. More precise sequencing
belongs inside the handler body. `before` steps may fail closed with an explicit
status. `after` is reserved for handler-adjacent observability or cleanup, but
chains containing it are rejected until response-side lowering exists. Group
chains and entry chains compose in source order.

See [chains.md](chains.md) for the current design direction.

## Deferred Risks

The current decorator design has two known risks:

- execution order is not yet a strict first-instruction guard chain,
- magic request binding through a parameter named `req` can be shadowed.

These are not blockers for compatibility, but decorators should not become
stable core syntax unless they can mechanically lower to the same chain model
without adding hidden ordering or binding rules.
