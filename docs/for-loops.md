# Static For Loops

Rut supports route-local static `for` loops. They are a compile-time lowering
feature: the compiler proves the iterator is a static array, then unrolls the
loop body into ordinary route control flow during MIR construction, before RIR
lowering. There is no runtime loop carrier or dynamic iterator state.

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

`inline for` is not accepted; plain `for` is the single canonical spelling.

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
variant Result {
    ok(i32)
    err
}

route GET "/result" {
    for state in [Result.ok(200)] {
        match state {
            .ok(code) => return 200
            .err      => return 500
            _         => return 500
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
- `break` and `continue` loop control (see [Loop Control](#loop-control))

Loop bodies can introduce locals before guards:

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

`match` inside a loop supports the static-loop match subset, including arm
guards and payload bindings. This subset is stricter than ordinary route
`match`: include a wildcard arm even when the cases look exhaustive.

```rut
variant Result {
    ok(i32)
    err
}

route GET "/guarded" {
    for item in [1] {
        let state = Result.ok(item)
        match state {
            .ok(code) if code > 0 => return 200
            .ok(code)             => return 422
            _                     => return 500
        }
    }
    return 404
}
```

Fallible or nil-producing predicates are rejected in loop-body `if` conditions
and match-arm `if` guards. This keeps unrolled route control flow from depending
on invalid failure behavior.

`if let` is not supported inside a static loop body yet: the loop lowering has
no per-iteration binding materialization, so the compiler rejects it rather than
misreading the usable-value test as a boolean condition.

## Loop Control

`break` and `continue` follow their Swift meaning. Because loops are unrolled at
compile time, both are resolved while emitting the iteration steps instead of
introducing a runtime loop carrier:

- `break` leaves the innermost enclosing loop; later iterations are not emitted.
- `continue` skips the remaining steps of the current iteration and resumes at
  the next iteration.
- In nested loops both bind to the innermost loop; the outer loop continues
  normally after the inner loop finishes.

They are accepted as direct loop-body statements, but the useful form is a
guard failure path, which is how a conditional exit reads in Rut:

```rut
route GET "/x" {
    for n in [1, 2, 3, 4] {
        guard n != 2 else { continue }              // skip iteration 2
        guard n != 4 else { break }                 // stop before iteration 4
    }
    return 200
}
```

Direct statements end the body, so nothing may follow them:

```rut
route GET "/x" {
    for item in [1, 2, 3] {
        break                                       // ends the whole loop
    }
    return 200
}
```

For conditional control prefer `guard`, as above: a direct `break`/`continue`
always runs and therefore also makes every later step of the body unreachable.

Loop control is not yet accepted inside loop-body `if` or `match` arms: those
steps are lowered as terminal route branches, and a conditional iteration exit
would need a partial-iteration control graph. A loop body that uses
`break`/`continue` also cannot contain a route terminator (`return`, terminal
`if`, terminal `match`); keep the loop body free of route exits and put them
after the loop.

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

Static `for` loops are intentionally narrow:

- iterators must be static arrays (a literal or a route-local alias)
- non-array iterators are rejected
- dynamic values such as function-call results are rejected as iterators
- field access iterators such as `up.servers` are parsed but rejected
- loop variables cannot shadow existing route locals
- empty loop bodies are rejected by the parser
- statements after a loop-body terminator are rejected
- `if let` inside a loop body is rejected
- loop-body `let` and `guard let` initializers must be non-allocating; bind
  allocating values (for example `req.path.lower()`) before the loop
- loop-body initializers are re-evaluated at each use, so they must also be
  repeatable; `time.nowMicros()` stays allowed because it is latched once per
  invocation (see the language card), so every use observes the same value
- routes that combine `wait(...)` and static for-loop lowering are rejected
- `for` is accepted only in route bodies, not helper/function bodies
- `break`/`continue` are accepted as direct loop-body statements and as a
  `guard ... else` failure path; loop-body `if`/`match` arms reject them for now
- a loop body that uses `break`/`continue` cannot also contain route terminators
- block-budget overflow reports the overflowing loop step, guard, or arm
