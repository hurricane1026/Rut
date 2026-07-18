# For Loops

Rut Core supports verifier-bounded iteration over a compile-time array literal
or a local alias of one. The compiler unrolls the loop into the ordinary route
CFG; Rut does not add a runtime iterator or an unbounded back edge.

```rut
let statuses = [200, 201, 204]
for status in statuses {
    guard status != 201 else { continue }
    guard status < 204 else { break }
}
return 200
```

`break` exits the innermost loop. `continue` skips to its next statically known
iteration; on the final iteration it exits that loop. Both only shorten the
verified execution bound. They are also valid as the exiting action of a loop
body `guard`, `if` branch, or `match` arm. Labels and loop `else` clauses are not
part of Rut Core.

The iterator must resolve at compile time:

```rut
for item in [1, 2, 3] { ... }  // Core
let items = [1, 2, 3]
for item in items { ... }      // accepted alias
for item in requestItems { ... } // compile error: runtime iterator
```

Loop expansion is subject to the MIR/verifier block budget. A program whose
unrolled CFG exceeds that fixed budget is rejected instead of silently changing
semantics. Static loops also cannot be combined with `wait`; runtime iterators,
`while`, and `loop` remain unsupported.
