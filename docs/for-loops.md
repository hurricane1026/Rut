# For Loops

Rut Core supports bounded `for` loops over compile-time array literals or
aliases of those literals. The compiler statically unrolls the body, so a loop
does not introduce a hidden runtime iterator or an unbounded execution path.

```rut
route GET "/check" {
    let values = [1, 2, 3]
    for value in values {
        guard value > 0 else { return 400 }
    }
    return 204
}
```

The iterator must resolve directly through local aliases to an array literal.
Arrays produced by calls, methods, fields, pipes, waits, or other runtime
sources are rejected even when their eventual length appears bounded. Typed
empty array aliases are accepted as zero-iteration loops.

Loop bodies may use supported local bindings, guards, `if`, `match`, and nested
bounded loops. `break` and `continue` target the innermost loop and may also be
used from guard failure paths and supported conditional branches. A route
terminator exits the route as usual. Statements after an unconditional direct
`break`, `continue`, or route terminator in the same loop body are rejected.

`wait`, response mutation, and runtime array construction are not supported in
a static-loop body. Unrolling is subject to the frontend's fixed route-local and
control-flow block budgets; programs that exceed those bounds fail compilation
instead of falling back to runtime iteration.
