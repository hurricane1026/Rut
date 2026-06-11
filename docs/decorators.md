# Deprecated Decorators

Route decorators are deprecated and unsupported in Rut Core.

New design work should use explicit `chain` declarations for `before` handler
checks. See [chains.md](chains.md). For route-local checks that do not belong
in a chain, write the logic explicitly:

```rut
route GET "/users" {
    guard req.method == GET else { return 405 }
    return 200
}
```

Older examples that use `@name` route decorators are kept only as historical
context in the repository history. New code should not use them.
