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

`after` implements the response side of the same chain model. Its helper must
receive exactly one `Response` parameter and may perform ordered `set`, `add`,
or `remove` header effects plus status and bounded body replacement. These
effects live in resumable stream-owned state, so they survive explicit `wait`
and verifier-bounded `for` control flow. A forwarded response must use
`return forward(upstream, buffered: true)` so the runtime can materialize the
complete response before committing the effects. A handler that needs direct
field access may instead bind `let resp = forward(upstream, buffered: true)`,
read or mutate its owned fields across later yields, and `return resp`.

If a route needs more precise control than "before handler" or "after handler",
write that logic directly inside the handler with ordinary `guard`, `wait`,
`forward`, `if`, and `match` statements.

## Use Sites

Rut Core attaches a chain directly to a route declaration:

```rut
chain common {
    before require_host(req) else 400
}

route GET "/:id" use chain common {
    return 200
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

route GET "/:id" use chain read_secure {
    return 200
}

route POST "/upload" use chain upload_secure {
    return 204
}
```

When a route needs checks from multiple policies, declare their complete order
in one route chain rather than relying on grouped-route inheritance:

```rut
chain upload_policy {
    before require_host(req) else 400
    before decode_body(req) else 400
    before require_auth(req) else 401
    before limit_body(req, 1mb) else 413
}

route POST "/upload" use chain upload_policy {
    return 204
}
```

The expanded order is:

```text
require_host
decode_body
require_auth
limit_body
handler
```

Chains have two fixed handler phases. Every `before` declaration runs in source
order before the handler. For a selected handler's normal response, every
`after` declaration runs in source order after the handler. Top-level handler
guard failures and pre-handler short circuits return directly without entering
the post-handler phase; verifier-bounded static-loop exits are part of the
selected handler response and do receive the `after` effects. Interleaving
`after` and `before` declarations does not create a global interleaved order.
The post-handler phase is not a reverse wrapper unwind, so review, replay, and
generated code do not need an extra execution model.

## Core Restrictions

Rut Core should keep chains intentionally narrow:

- The implemented route-level extension points are request-side `before` and
  the bounded response `after` slice described above; there are no arbitrary
  phases. Buffered `Response` expressions are limited to the explicit,
  bounded `forward(..., buffered: true)` form described above.
- A `before` step must be a direct call. A bool predicate must declare
  `else <status>` (its only rejection channel); a respond-capable helper
  (one whose body uses `guard ... else { respond <status>[, body] }`) must
  NOT — it carries its own status, and its respond guards expand at the
  chain position. This is the DESIGN "middleware = ordinary functions"
  surface: `respond` short-circuits, `return` passes through.
- `after` is limited to ordered Response header/status/bounded-body effects;
  streaming forwards are rejected because their bytes may already be on wire.
- Chain order is source order within each of the fixed pre-handler (`before`)
  and post-handler (`after`) phases; there is no priority dispatch.
- A route entry should attach at most one entry chain.
- Chains are statically expanded before route verification.
- Chain functions must not hide new suspension points. Any operation that can
  suspend must be written explicitly in the handler.

This keeps shared gateway behavior reusable without reintroducing decorator,
plugin, or filter-chain ambiguity.
