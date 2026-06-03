# Static For Loops

Rut currently supports route-local static `for` loops. They are a compile-time
lowering feature: the compiler proves the iterator is a static array, then
unrolls the loop body into ordinary route control flow during MIR construction,
before RIR lowering. There is no runtime loop carrier or dynamic iterator state
for this feature.

## Syntax

Use `for name in array { ... }`:

```rut
route GET "/x" {
    for item in [1, 2, 3] {
        guard item > 0 else { return 400 }
    }
    return 200
}
```

`inline for` was an older compatibility spelling. It is no longer accepted in
Rut Core; use plain `for` so static loops have one canonical form.

## Iterator Sources

The iterator must be a static array. Array literals are the simplest form:

```rut
route GET "/x" {
    for item in [1, 2, 3] {
        guard item > 0 else { return 400 }
    }
    return 200
}
```

Route-local aliases of static arrays are also accepted, including alias chains:

```rut
route GET "/x" {
    let xs = [1, 2, 3]
    let ys = xs
    for item in ys {
        guard item > 0 else { return 400 }
    }
    return 200
}
```

Typed empty arrays are valid and produce zero body iterations:

```rut
route GET "/x" {
    let xs: [i32] = []
    for item in xs {
        return 201
    }
    return 200
}
```

Array locals are only valid as static iterator sources. They cannot escape into
ordinary runtime expressions.

## Element Values

Loop elements can be scalar values, tuples, structs, or variants.

```rut
struct Box { value: i32 }

route GET "/boxes" {
    let boxes = [Box(value: 1), Box(value: 2)]
    for box in boxes {
        guard box.value > 0 else { return 400 }
    }
    return 200
}
```

```rut
variant Result { ok(i32), err }

route GET "/result" {
    for state in [Result.ok(200)] {
        match state {
        case .ok(code):
            return code
        case _:
            return 500
        }
    }
    return 404
}
```

Tuple elements can be used with tuple-slot placeholders in pipe expressions:

```rut
func second(a: i32, b: i32) -> i32 => b

route GET "/tuple" {
    for pair in [(200, 1), (204, 2)] {
        let code = pair | second(_2, _1)
        guard code == 200 else { return 400 }
    }
    return 200
}
```

## Loop Body

The supported loop body surface is route-oriented:

- `let` bindings scoped to the loop body
- `guard` and `guard let`
- direct route terminators such as `return`
- terminal `if`
- terminal `match`
- nested static `for` loops

For example, loop bodies can introduce locals before guards:

```rut
route GET "/x" {
    for item in [1, 2, 3] {
        let n = item
        guard n > 0 else { return 400 }
    }
    return 200
}
```

Nested loops can reference an outer loop variable in the inner static iterator:

```rut
route GET "/nested" {
    for item in [1, 2] {
        for inner in [item] {
            guard inner == item else { return 400 }
        }
    }
    return 200
}
```

`match` inside a loop supports the current static-loop match subset, including
arm guards and payload bindings. This subset is stricter than ordinary route
`match` today; include a wildcard arm even when the cases look exhaustive.

```rut
variant Result { ok(i32), err }

route GET "/guarded" {
    for item in [1] {
        let state = Result.ok(item)
        match state {
        case .ok(code) if code > 0:
            return 200
        case .ok(_):
            return 422
        case _:
            return 500
        }
    }
    return 404
}
```

Fallible or nil-producing predicates are rejected in loop-body `if` conditions
and match-arm `if` guards. This keeps unrolled route control flow from depending
on invalid failure behavior.

## Ordering

Static loops are lowered in source order with surrounding route statements.
Guards before a loop, guards produced by the loop, and guards after a loop keep
their source order in the generated route control flow.

```rut
route GET "/x" {
    guard true else { return 403 }
    for item in [1, 2] {
        guard item > 0 else { return 400 }
    }
    guard true else { return 401 }
    return 200
}
```

For non-terminating loop bodies, each iteration contributes its generated
control in source order. If the loop body contains a route terminator, lowering
only needs the first iteration's terminal path because the route exits there;
later iterations are unreachable and are not emitted. A zero-iteration loop
contributes no body control.

## Current Limits

Static `for` loops are intentionally narrow today:

- iterators must be static arrays
- non-array iterators are rejected
- dynamic values such as function-call results are rejected as iterators
- field access iterators such as `up.servers` are parsed but rejected by current
  analysis
- loop variables cannot shadow existing route locals
- empty loop bodies, or bodies that produce no supported lowering steps, are
  rejected
- statements after a loop-body terminator are rejected
- routes that combine `wait(...)` and static for-loop lowering are rejected
- block-budget overflow reports the overflowing loop step, guard, or arm

Most of these rejects currently surface through the compiler's existing broad
diagnostic categories. More specific user-facing messages are tracked by issue
[#70](https://github.com/hurricane1026/Rut/issues/70).
