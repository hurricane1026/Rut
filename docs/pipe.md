# Pipe Expressions

Pipe expressions pass the value on the left into a function call on the right.
They are useful for writing small, named transformation steps in route logic
without nesting calls.

Pipe is resolved during analysis. After type checking, a pipe becomes an
ordinary inlined function-call expression; it does not introduce a separate
MIR/RIR opcode.

## Lowering And Inlining

Pipe is a source-level convenience, not a runtime abstraction. A pipeline such
as:

```rut
let code = 204 | normalize_status(_) | mask_internal_error(_)
```

is analyzed as nested stage application, and each stage function body is
instantiated at the use site. By the time MIR/RIR are built, there is no
`Pipe` node, no call chain, and no pipe dispatch. The route contains the
ordinary expression instructions produced by the stage bodies, such as
constants, comparisons, selects, tuple-slot projections, optional unwraps, and
terminal branches.

For runtime optional/error values, the analyzer still inlines the stage body but
wraps it with presence checks:

```rut
let host = req.header("Host") | tenant_from_host(_)
```

lowers conceptually like:

```rut
if has_value(req.header("Host")) {
    tenant_from_host(value_of(req.header("Host")))
} else {
    missing_of(req.header("Host"))
}
```

where `tenant_from_host(...)` is also expanded into ordinary expression IR.

## Basic Use

The right-hand side must be a function call with exactly one placeholder.
`_` and `_1` both mean "the whole value from the left-hand side":

```rut
func normalize_status(code: i32) -> i32 {
    if code == 204 { 200 } else { code }
}

route GET "/health" {
    let code = 204 | normalize_status(_)
    if code == 200 { return 200 } else { return 500 }
}
```

The same call can use `_1`:

```rut
let code = 204 | normalize_status(_1)
```

## Chaining

Each stage receives the previous stage's output. This keeps request policy code
readable when several small decisions are applied in order:

```rut
func status_for_path(path: str) -> i32 {
    if path == "/users" { 200 } else { 404 }
}

func mask_internal_error(code: i32) -> i32 {
    if code == 500 { 503 } else { code }
}

route GET "/users" {
    let code = req.path | status_for_path(_) | mask_internal_error(_)
    if code == 200 { return 200 } else { return 404 }
}
```

Route terminal control should still spell out the statuses it returns:

```rut
route GET "/users" {
    let code = req.path | status_for_path(_) | mask_internal_error(_)
    if code == 200 { return 200 } else { return 404 }
}
```

## Placeholder Position

The placeholder can appear in any argument position. This is useful when a stage
needs constants or policy values alongside the piped value:

```rut
func allow_if_token(token: str, expected: str, ok_status: i32) -> i32 {
    if token == expected { ok_status } else { 401 }
}

route GET "/admin" {
    let code = req.header("Authorization") | allow_if_token(_, "Bearer root", 200)
    let safe = or(code, 401)
    if safe == 200 { return 200 } else { return 401 }
}
```

## Method Stages

The placeholder can also be the receiver of a method-call stage:

```rut
route GET "/method-stage" {
    let ok = 200 | _.eq(200)
    if ok { return 200 } else { return 500 }
}
```

`_` and `_1` are accepted as method receivers. Tuple-slot receivers such as
`_2.method(...)` are still rejected; use a function stage with tuple-slot
arguments when a pipeline needs to project tuple slots.

## Optional Header Flow

`req.header(...)` returns an optional string. A pipe stage only runs when the
header is present; missing values flow through as `nil` and can be handled with
`or(...)`.

```rut
func tenant_from_host(host: str) -> str {
    if host == "api.example.com" { "api" } else { "unknown" }
}

func status_for_tenant(tenant: str) -> i32 {
    if tenant == "api" { 200 } else { 404 }
}

route GET "/tenant" {
    let code = req.header("Host") | tenant_from_host(_) | status_for_tenant(_)
    let safe = or(code, 404)
    if safe == 200 { return 200 } else { return 404 }
}
```

## Error Flow

Error values also flow through a pipe without calling later stages. Downstream
`or(...)` can turn the error into a concrete fallback:

```rut
func parse_mode(raw: str) -> i32 {
    if raw == "fast" { 1 } else { error(.bad_mode) }
}

func status_for_mode(mode: i32) -> i32 {
    if mode == 1 { 200 } else { 400 }
}

route GET "/mode" {
    let code = req.header("X-Mode") | parse_mode(_) | status_for_mode(_)
    let safe = or(code, 400)
    if safe == 200 { return 200 } else { return 400 }
}
```

Known `nil` and known `error(...)` left-hand values are folded at analysis time
and do not call the stage.

## Tuple Slots

When the left-hand side is a tuple, numbered placeholders select tuple slots.
Indexes are 1-based:

```rut
func status_from_policy(auth_status: i32, default_status: i32) -> i32 {
    if auth_status == 200 { auth_status } else { default_status }
}

route GET "/tuple-policy" {
    let policy = (200, 401)
    let code = policy | status_from_policy(_1, _2)
    if code == 200 { return 200 } else { return 401 }
}
```

Tuple slots can be reordered:

```rut
func prefer_second(primary: i32, secondary: i32) -> i32 => secondary

route GET "/tuple-reorder" {
    let code = (500, 200) | prefer_second(_1, _2)
    if code == 200 { return 200 } else { return 500 }
}
```

Tuple slots can also come from tuple-returning functions:

```rut
func route_policy(path: str) {
    if path == "/tuple-stage" { (200, 401) } else { (404, 401) }
}

func choose_policy(primary: i32, fallback: i32) -> i32 {
    if primary == 200 { primary } else { fallback }
}

route GET "/tuple-stage" {
    let code = req.path | route_policy(_) | choose_policy(_1, _2)
    if code == 200 { return 200 } else { return 401 }
}
```

`_1` through `_10` are accepted by the parser. The analyzer rejects indexes that
are not valid for the left-hand value.

For runtime optional/error left-hand values, only `_` / `_1` is accepted.
Numbered tuple-slot placeholders such as `_2` are rejected because the value has
to be unwrapped before tuple slots can be safely projected.

## Generic Stages

Generic functions can be used as pipe stages when the type shape can be inferred:

```rut
func keep<T>(x: T) -> T => x
func status_for_code(code: i32) -> i32 => code

route GET "/generic" {
    let code = 200 | keep(_) | status_for_code(_)
    if code == 200 { return 200 } else { return 500 }
}
```

## Supported Today

- Function-call stages: `value | fn(_, other_arg)`.
- Method-call stages with a whole-value receiver: `value | _.method(other_arg)`.
- Placeholder position anywhere in the function argument list.
- Single-stage and chained pipes.
- Tuple slot placeholders `_1` ... `_10`.
- Tuple literals, tuple locals, tuple-returning functions, struct fields,
  variant payloads, and generic tuple/struct shapes.
- Optional/error propagation through runtime values.
- JIT execution after lowering through existing call-expression machinery.

## Current Gaps

The following are future work rather than current behavior:

- Placeholder-free stages. A pipe stage must consume the left-hand value
  explicitly.
- Multiple placeholders in a single stage.
- Tuple-slot placeholders for runtime optional/error left-hand values beyond
  `_` / `_1`.
- A dedicated MIR/RIR pipe representation; current lowering intentionally
  rewrites pipe into ordinary expressions before MIR.
