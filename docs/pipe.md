# Pipe Expressions

Pipe expressions pass the value on the left into a function call on the right.
They are useful for writing small, named transformation steps in route logic
without nesting calls.

Pipe is resolved during analysis. After type checking, a pipe becomes an
ordinary inlined function-call expression; it does not introduce a separate
MIR/RIR opcode.

Use `||`, `&&`, and `!` as boolean operators. The near-miss words `or`, `and`,
and `not` are rejected with fix-its, and function-call forms `or(...)` and
`and(...)` are not supported. For optional/error fallback in expressions, Rut
Core uses the named value method `.or(default)`. The names `any` and `all` are
reserved for concurrent/race semantics rather than ordinary value fallback.

## Operator Precedence Notes

`&&` and `||` are parsed before `|`.

- `A && B | C` parses as `(A && B) | C`.
- `A || B | C` parses as `(A || B) | C`.
- `A | B && C` is rejected because `&&` appears on the right side of `|`;
  the pipe RHS must be a call stage such as `f(...)` or `_.method(...)`.
- `A | B || C` is rejected for the same reason.

Write:

```rut
let x = (A | B) || C
```

to make the valid pipe stage grouping explicit before applying boolean
operators.

## Lowering And Inlining

Pipe is a source-level convenience, not a runtime abstraction. A pipe expression
such as:

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

## Core Style

Rut Core uses pipe only as a small expression-composition helper. Generated and
reviewed code should prefer one canonical stage shape:

```rut
value | function_name(_, arg)
```

The right-hand side must be a function call stage with an explicit `_`
placeholder for the whole left-hand value:

```rut
func normalize_status(code: i32) -> i32 {
    if code == 204 { 200 } else { code }
}

route GET "/health" {
    let code = 204 | normalize_status(_)
    if code == 200 { return 200 } else { return 500 }
}
```

Do not use method-stage pipe syntax in core examples:

```rut
let ok = 200 | _.eq(200)
```

Prefer the function-stage spelling instead:

```rut
let ok = 200 | eq(_, 200)
```

Method-stage syntax makes the generated code look like a member call even when
the operation is really a protocol or builtin helper. The function-stage form
keeps name lookup explicit and avoids requiring generated code to guess which
type owns a method.

The implementation currently accepts some broader forms for compatibility, but
Rut Core documentation and generated examples should not introduce them unless
there is no equivalent direct function stage.

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

The `_` placeholder can appear in any argument position. This is useful when a stage
needs constants or policy values alongside the piped value:

```rut
func allow_if_token(token: str, expected: str, ok_status: i32) -> i32 {
    if token == expected { ok_status } else { 401 }
}

route GET "/admin" {
    let code = req.header("Authorization") | allow_if_token(_, "Bearer root", 200)
    let safe = code.or(401)
    if safe == 200 { return 200 } else { return 401 }
}
```

## Method Stages

Method-call stages are implemented today, but they are not Rut Core style. This
shape is accepted for compatibility:

```rut
route GET "/method-stage" {
    let ok = 200 | _.eq(200)
    if ok { return 200 } else { return 500 }
}
```

`_` and `_1` are accepted as method receivers. Tuple-slot receivers such as
`_2.method(...)` are still rejected; use a function stage with tuple-slot
arguments when a pipe expression needs to project tuple slots.

Prefer:

```rut
route GET "/method-stage" {
    let ok = 200 | eq(_, 200)
    if ok { return 200 } else { return 500 }
}
```

## Optional Header Flow

`req.header(...)` returns an optional string. A pipe stage only runs when the
header is present; missing values flow through as `nil` and can be handled with
`.or(default)`.

```rut
func tenant_from_host(host: str) -> str {
    if host == "api.example.com" { "api" } else { "unknown" }
}

func status_for_tenant(tenant: str) -> i32 {
    if tenant == "api" { 200 } else { 404 }
}

route GET "/tenant" {
    let code = req.header("Host") | tenant_from_host(_) | status_for_tenant(_)
    let safe = code.or(404)
    if safe == 200 { return 200 } else { return 404 }
}
```

## Error Flow

Error values also flow through a pipe without calling later stages. Downstream
`.or(default)` can turn the error into a concrete fallback:

```rut
func parse_mode(raw: str) -> i32 {
    if raw == "fast" { 1 } else { error(.bad_mode) }
}

func status_for_mode(mode: i32) -> i32 {
    if mode == 1 { 200 } else { 400 }
}

route GET "/mode" {
    let code = req.header("X-Mode") | parse_mode(_) | status_for_mode(_)
    let safe = code.or(400)
    if safe == 200 { return 200 } else { return 400 }
}
```

Known `nil` and known `error(...)` left-hand values are folded at analysis time
and do not call the stage.

Legacy fallback helpers such as `any(...)` and `all(...)` should not be used for
ordinary value-flow code in Rut Core. If a fallback must be computed lazily or a
side effect must short-circuit, write an explicit `if` branch.

The present-only fallback shape should be spelled explicitly:

```rut
route GET "/all" {
    let token = req.query("x-token")
    let safe = if let value = token { value } else { "" }
    if safe == "" { return 401 } else { return 200 }
}
```

Use explicit branching when the fallback rule is not simple "value or default".

## Tuple Slots

Tuple-slot placeholders are implemented today, but they should stay outside the
core generated style. They make pipe serve as both composition and destructuring.
When tuple values are involved, prefer a named helper that receives the whole
tuple, or bind the tuple fields explicitly before piping.

The compatibility form uses numbered placeholders to select tuple slots.
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

Generic functions can be used as pipe stages when the type shape can be
inferred:

```rut
func keep<T>(x: T) -> T => x
func status_for_code(code: i32) -> i32 => code

route GET "/generic" {
    let code = 200 | keep(_) | status_for_code(_)
    if code == 200 { return 200 } else { return 500 }
}
```

## Supported Today

- Function-call stages with placeholders: `value | fn(_, other_arg)`.
- Placeholder-free function-call stages: `value | fn(other_arg)` passes `value`
  as the first argument.
- Method-call stages with a whole-value receiver: `value | _.method(other_arg)`.
- Placeholder position anywhere in the function argument list.
- Single-stage and chained pipes.
- Tuple slot placeholders `_1` ... `_10`, including multiple placeholders in a
  single stage.
- Tuple literals, tuple locals, tuple-returning functions, struct fields,
  variant payloads, and generic tuple/struct shapes.
- Optional/error propagation through runtime values.
- JIT execution after lowering through existing call-expression machinery.

## Rut Core Recommendation

Generated Rut Core should use the smallest pipe subset:

- Function-call stages only: `value | fn(_, other_arg)`.
- A single whole-value `_` placeholder per stage.
- No method-call stages such as `value | _.method(arg)`.
- No placeholder-free stages such as `value | fn(arg)`.
- No tuple-slot placeholders such as `_1` or `_2`.
- Prefer at most four stages in one pipe chain; longer flows should introduce
  named locals.

The broader implemented surface remains useful for compatibility and targeted
human-written code, but the core subset gives LLM-generated code one clear way
to express value flow.

## Current Gaps

The following are future work rather than current behavior:

- Tuple-slot placeholders for runtime optional/error left-hand values beyond
  `_` / `_1`.
- A dedicated MIR/RIR pipe representation; current lowering intentionally
  rewrites pipe into ordinary expressions before MIR.
