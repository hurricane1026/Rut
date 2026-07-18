# Chains

Rut chains are reusable handler-adjacent processing steps. They replace
decorator-style middleware with a smaller model that is explicit, ordered, and
mechanically expandable into route control flow.

## Purpose

A chain groups common work that should run immediately before a route handler:

```rut
chain secure_upload {
    before decode_body(req) else 400
    before require_auth(req) else 401
}
```

`before` steps run before the handler. They may fail closed, so each step must
declare the status returned on failure.

`after` implements the response-header slice of the same chain model. Its helper
must receive exactly one `Response` parameter and use `set`, `add`, or `remove`
header effects. The analyzer rejects body/status-only observers and routes that
combine these effects with `wait` or `for`; those need a resumable, stream-owned
Response object first.

If a route needs more precise control than "before handler" or "after handler",
write that logic directly inside the handler with ordinary `guard`, `wait`,
`forward`, `if`, and `match` statements.

## Use Sites

Chains can be attached to a route group:

```rut
chain common {
    before require_host(req) else 400
}

route {
    use chain common

    GET "/:id" {
        return 200
    }
}
```

An entry can attach a different chain when methods need different behavior:

```rut
chain read_secure {
    before require_auth(req) else 401
}

chain upload_secure {
    before decode_body(req) else 400
    before require_auth(req) else 401
    before limit_body(req, 1mb) else 413
}

route {
    GET "/:id" use chain read_secure {
        return 200
    }

    POST "/upload" use chain upload_secure {
        return 204
    }
}
```

Route-group chains and entry chains compose in source order:

```rut
route {
    use chain common

    POST "/upload" use chain upload_secure {
        return 204
    }
}
```

The expanded order is:

```text
common.before
upload_secure.before
handler
common.after
upload_secure.after
```

Implemented `after` lowering uses this same final chain order. It is not a
reverse wrapper unwind; it follows the code's visible order so review, replay,
and generated code do not need an extra execution model.

## Core Restrictions

Rut Core should keep chains intentionally narrow:

- `before` is the only implemented route-level extension point.
- A `before` step must be a direct call. A bool predicate must declare
  `else <status>` (its only rejection channel); a respond-capable helper
  (one whose body uses `guard ... else { respond <status>[, body] }`) must
  NOT — it carries its own status, and its respond guards expand at the
  chain position. This is the DESIGN "middleware = ordinary functions"
  surface: `respond` short-circuits, `return` passes through.
- `after` is limited to ordered Response header effects and cannot yet be used
  on `wait`/`for` routes.
- Chain order is source order only; there is no priority or phase dispatch.
- A route entry should attach at most one entry chain.
- Chains are statically expanded before route verification.
- Chain functions must not hide new suspension points. Any operation that can
  suspend must be written explicitly in the handler.

This keeps shared gateway behavior reusable without reintroducing decorator,
plugin, or filter-chain ambiguity.
