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
| Middleware | `chain` with ordered `before`; bounded response `after`; terminal or first-class `forward(..., buffered: true)` when proxying | official built-in decorators | custom middleware/decorators |
| Pipe | `value \| fn(_, arg)` | `_.method(...)`, `_1` … `_10` | a dedicated pipe IR or wider runtime tuple projection |
| Fallback | `.or(default)`, `guard let`, `if let`, explicit `match` | eager `any(value, default)` and present-only `all(value, next)` | none |
| Match | flat `i32`, boolean, string, or variant arms with an explicit fallback where needed | `match const` and restricted nested route-match expansion | `i64` subjects and unrestricted nested/pattern match |
| Loops | `for item in [compile, time, values]` with verifier-bounded unrolling and unlabeled `break`/`continue` | compile-time array aliases | runtime iterators, `while`, labeled control, and loop `else` |
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
| custom `@auth` decorator | first convert its legacy `i32` status helper to a bool predicate or respond-capable helper, then call that helper from `chain auth` and `use chain auth` |
| official `@rateLimit` | for shard-scoped rules, spell the policy explicitly with supported rate-limit state/helpers; retain the compatibility decorator for `scope: global` |
| official `@throttle` | keep the compatibility decorator; no equivalent Core route call exists yet |
| `any(value, default)` | for a missing-capable receiver with no applicable user `or` member, use `value.or(default)`; otherwise use an explicit presence branch so migration cannot change method dispatch; preserve eager default evaluation |
| `all(value, next)` | preserve static selection: if `value` is known absent, remove the unevaluated `next`; otherwise evaluate `next` before explicit branching, and inline it only when pure |
| `value \| _.method(arg)` | introduce a real named helper that performs the method call, then use `value \| helper(_, arg)` |
| `tuple \| fn(_1, _2)` | retain tuple-slot compatibility, or change the producer to separate values/a named struct; Core projection and destructuring are not available yet |
| generic helper used only once | specialize it to a concrete direct helper in generated code |
| `value \| protocolMethod(_)` where ownership is unclear | call a direct domain helper whose name identifies the operation |
| restricted nested route `match` | bind the outer decision, then use a flat `match` or explicit `if` in the selected branch |

Official decorators lower to route metadata today; custom route decorators are
already rejected. The migration target is explicit source, not a second hidden
middleware model.

Legacy custom decorator helpers use an `i32` convention: zero passes and a
non-zero value rejects. A `chain before` step does not accept that contract. If
the rejection status is fixed, wrap or rewrite the helper as a bool predicate
and attach `else <status>`. If the helper chooses among rejection statuses,
rewrite it as a respond-capable helper whose guards issue `respond <status>`,
then use it as a `before` step without `else`.

Compatibility `all(value, next)` normally evaluates `next` eagerly, so a
behavior-preserving migration must bind/evaluate it before the explicit
presence branch. The exception is a statically known absent left side: existing
analysis selects that absence without evaluating `next`, so migration must drop
the dead RHS rather than bind it. Moving a fallible or effectful RHS across
either boundary changes error/effect behavior.

Compatibility `any(value, default)` is an unconditional builtin, while
`value.or(default)` first respects an applicable user/protocol method named
`or`. The short migration is therefore valid only for the builtin
missing-value receiver path. If member dispatch is possible, spell the
presence/fallback branch explicitly and evaluate `default` beforehand to keep
the compatibility form's eager effects.

## Chain Boundary

`before` is the stable request-side chain operation. `after` is stable for the
implemented bounded response slice: the helper must receive exactly one
`Response` and may perform ordered header, status, and body effects. Effects
survive visible `wait` and verifier-bounded `for` control flow. Streaming
forwards cannot be post-processed; proxy routes must opt into buffered
`forward(..., buffered: true)`. Its first-class expression form owns bounded
upstream fields and may be read or mutated before `return resp`.

## Review Rule

A new core spelling must replace ambiguity rather than add an equivalent form.
It needs deterministic lowering, a replay or simulation story for observable
effects, and a prescriptive diagnostic for unsupported neighboring forms.
