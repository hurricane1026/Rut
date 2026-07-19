# Match

Rut supports `match` in routes and source functions.

Flat `i32`/boolean/string/variant match is Rut Core. An `i64` subject is not
supported; generated code must compare it with `if`/`guard` instead. `match
const` and the restricted nested-route expansion below are compatibility forms:
generated code should prefer a flat match with values bound in route scope.
When migrating an existing `match const`, preserve compile-time selection by
emitting only the selected arm (or otherwise eliminating dead arms). Ordinary
`match` analyzes every arm, so it is not a semantics-preserving textual
replacement when an unselected arm is invalid.
Unrestricted nested patterns remain experimental. See
[syntax-stability.md](syntax-stability.md).

## Route Match

```rut
route GET "/status" {
    let code = 200
    match code {
    200 =>
        return 200
    _ =>
        return 404
    }
}
```

Route match patterns can be `i32`, boolean, string, and variant cases.
Non-exhaustive scalar matches need a wildcard arm.

```rut
route GET "/path" {
    let path = "/users"
    match path {
    "/users" =>
        return 200
    _ =>
        return 404
    }
}
```

Boolean matches are exhaustive when both `true` and `false` are present.

```rut
route GET "/enabled" {
    let enabled = true
    match enabled {
    true =>
        return 200
    false =>
        return 503
    }
}
```

## Variant Cases

Variant cases can be matched with `.case` when the subject type is already known, or with
`Variant.case` when the variant must be named explicitly.

```rut
variant Auth { ok, denied }

route GET "/auth" {
    let auth = Auth.ok
    match auth {
    .ok =>
        return 200
    .denied =>
        return 403
    }
}
```

Payload cases can bind the payload for the arm body and arm guard.

```rut
variant Result { ok(i32), err }

route GET "/result" {
    let result = Result.ok(200)
    match result {
    .ok(code) if code == 200 =>
        return 200
    _ =>
        return 500
    }
}
```

## Arm Guards

An arm can add `if <bool-expr>` after the pattern. When the pattern matches but the guard is false,
control falls through to the next arm.

```rut
route GET "/guarded" {
    let code = 200
    match code {
    200 if false =>
        return 500
    _ =>
        return 404
    }
}
```

Guarded route matches require a wildcard fallback unless the guard is produced by a supported nested
match expansion.

## Const Match

`match const` selects an arm during analysis. The subject and selected pattern must be compile-time
known.

```rut
route GET "/const" {
    let path = "/users"
    match const path {
    "/users" =>
        return 200
    _ =>
        return 404
    }
}
```

`match const` arms do not support arm guards.

## Nested Route Match

A route match arm can end in another route match. The compiler expands this into guarded outer arms,
so the runtime path remains a flat branch chain.

```rut
variant Auth { ok, denied }

route GET "/nested" {
    let auth = Auth.ok
    let path = "/users"
    match auth {
    .ok =>
        match path {
        "/users" =>
            return 200
        _ =>
            return 404
        }
    .denied =>
        return 403
    }
}
```

Nested route match currently rejects inner arm guards, inner payload bindings, and prefix
statements before the nested match. Keep any values used by the inner match in route scope instead
of declaring them inside the outer arm.

## Source Function Match

Source functions use `=>` arms and return expressions.

```rut
func status(path: str) -> i32 {
    match path {
    "/users" => 200
    _ => 404
    }
}
```

Function match supports arm guards and payload bindings.

```rut
variant Result { ok(i32), err }

func pick(result: Result) -> i32 {
    match result {
    .ok(code) if code == 200 => code
    _ => 404
    }
}
```

If any function match arm uses an `if` guard, include a wildcard arm so unmatched or
guard-false values have an explicit result. Unguarded boolean and variant matches may omit
the wildcard only when all cases are exhaustive.
