# Syntax Stability

Rut has one generated-code profile: **Rut Core**. The compiler accepts a wider
surface so existing programs can migrate without a flag day, but acceptance by
the parser does not make a spelling part of the stable core.

## Stability Classes

- **Core**: recommended for new and generated code; has one canonical spelling,
  deterministic lowering, and runtime or frontend coverage.
- **Compatibility**: accepted for existing human-written programs, but not used
  in generated examples. It must lower to core machinery or have an explicit
  source migration.
- **Experimental**: partial or design-only behavior. It may change and must not
  be emitted without a project opting into that exact surface.

## Current Classification

| Capability | Rut Core spelling | Compatibility surface | Experimental surface |
|---|---|---|---|
| Routes | `route GET "/path" { ... }` | grouped `route { ... }` declarations | host/path groups, method unions, expression entries |
| Middleware | `chain` with ordered `before`; bounded response `after`; terminal `forward(..., buffered: true)` when proxying | official built-in decorators | first-class buffered Response expressions |
| Pipe | `value \| fn(_, arg)` | placeholder-free stages, `_.method(...)`, `_1` … `_10` | a dedicated pipe IR or wider runtime tuple projection |
| Fallback | `.or(default)`, `guard let`, `if let`, explicit `match` | none | none |
| Match | flat scalar, boolean, string, or variant arms with an explicit fallback where needed | `match const` and restricted nested route-match expansion | unrestricted nested/pattern match |
| Reuse | concrete direct functions and named builtin helpers | inferred generic helpers and protocol-style calls in hand-written code | custom `protocol`/`impl` or generic constraints as generated-code abstractions |
| Async | explicit `wait(...)`, `wait any`, terminal `forward(...)` | none | outbound HTTP, `submit`, `fire`, raw socket, and lifecycle syntax not wired end to end |

“Compatibility” is not a promise to add more variants. It is a bounded bridge
to the core form.

## Canonical Generated Forms

Generated code should use these spellings consistently.

Pipe the whole value through a direct function stage:

```rut
let tenant = req.header("Host") | tenant_from_host(_)
let safe = tenant.or("unknown")
```

Put reusable request gates in a named chain:

```rut
chain protected {
    before require_auth(req) else 401
}

route GET "/users" use chain protected {
    return forward(users)
}
```

Keep suspension visible at the statement boundary:

```rut
let event = wait(downstream.recv())
guard event.result > 0 else { return 400 }
return 204
```

Use `match` when the alternatives themselves matter, and `.or(default)` when
only a fallback value matters. Do not encode either operation through a pipe or
protocol method.

## Compatibility Migrations

| Existing spelling | Migration |
|---|---|
| custom `@auth` decorator | `chain auth { before auth(req) else <status> }`, then `use chain auth` |
| official `@rateLimit` / `@throttle` | keep only while migrating; spell the policy explicitly with the rate-limit state/helper or `throttle(...)` in the route |
| `value \| fn(arg)` | `value \| fn(_, arg)` |
| `value \| _.method(arg)` | `value \| method(_, arg)` |
| `tuple \| fn(_1, _2)` | bind named locals or pass the tuple to a named helper, then use `_` if another pipe stage is useful |
| generic helper used only once | specialize it to a concrete direct helper in generated code |
| `value \| protocolMethod(_)` where ownership is unclear | call a direct domain helper whose name identifies the operation |
| restricted nested route `match` | bind the outer decision, then use a flat `match` or explicit `if` in the selected branch |

Official decorators lower to route metadata today; custom route decorators are
already rejected. The migration target is explicit source, not a second hidden
middleware model.

## Chain Boundary

`before` is the stable request-side chain operation. `after` is stable for the
implemented bounded response slice: the helper must receive exactly one
`Response` and may perform ordered header, status, and body effects. Effects
survive visible `wait` and verifier-bounded `for` control flow. Streaming
forwards cannot be post-processed; proxy routes must opt into terminal
`forward(..., buffered: true)`. Binding that operation as a first-class
`Response` remains experimental.

## Review Rule

A new core spelling must replace ambiguity rather than add an equivalent form.
It needs deterministic lowering, a replay or simulation story for observable
effects, and a prescriptive diagnostic for unsupported neighboring forms.
