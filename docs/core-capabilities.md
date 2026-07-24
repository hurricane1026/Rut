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

The symbolic forms `?.` and `??` are deprecated and intentionally unsupported.
Use named fallback such as `.or(default)`, `guard let`, or `match` instead.

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

route POST "/data" use chain secure_upload {
    return 204
}
```

The request-side chain boundary is `before` handler. More precise sequencing
belongs inside the handler body. `before` steps may fail closed with an explicit
status. The implemented `after` slice accepts ordered Response header, status,
and bounded body effects in resumable state, including on routes containing
`wait` or verifier-bounded `for`. A forwarded response must use terminal
`forward(..., buffered: true)`, or bind the same buffered operation as a
first-class `Response` when the handler needs to inspect or mutate owned
upstream fields. A Core route attaches one explicit chain, whose steps execute
in two handler phases: all `before` steps run before the route body and preserve
their relative source order. For the selected handler's normal response, all
`after` steps then run after the body and preserve their relative source order;
top-level handler guard failures and pre-handler short circuits return without
that phase, while verifier-bounded static-loop exits receive the `after`
effects as part of the selected handler response.
Interleaving `before` and `after` declarations does not create one global
source-ordered sequence across phases.

See [chains.md](chains.md) for the current design direction.
The generated-code profile and compatibility migrations are listed in
[syntax-stability.md](syntax-stability.md).

## Compatibility Boundary

The retired custom-decorator model had two known risks:

- execution order was not a strict first-instruction guard chain,
- magic request binding through a parameter named `req` could be shadowed.

Custom decorators are now rejected. The remaining official built-in decorators
are compatibility syntax and lower to route metadata; they must not grow a
second middleware ordering or binding model. New reusable middleware belongs in
`chain`, while route-local policy stays explicit in the handler.
