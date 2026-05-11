# `wait(...)` Routes

`wait(...)` pauses a JIT route handler and resumes the same handler state
machine when the requested timer or IO completion event occurs.

## Event Model

The handler can suspend for three classes of events:

- Any currently supported `wait(any(...))` arm: downstream recv or a timer.
- A specific IO completion such as downstream recv/send or upstream
  connect/send/recv.
- A timer deadline.

Timer waits, statement-form event waits, and bound result-valued event waits are
currently wired through the frontend, JIT ABI, and runtime resume path.

The statement forms available today are:

```rut
wait()
wait(downstream.recv())
wait(upstream(api).connect())
wait(upstream(api).recv())
wait(upstream(api).send(req.body))
wait(any(downstream.recv(), timer(250)))
wait any {
    downstream.recv() => { return 204 }
    timer(250) => { return 408 }
}
wait(250)
```

`wait()` resumes when downstream recv completes.
The forms are either operation-start waits or completion waits:

- `wait(downstream.recv())` arms downstream recv and waits for its completion.
- `wait(upstream(api).connect())` opens an upstream socket, starts connecting
  to `api`, and waits for the connect completion.
- `wait(upstream(api).recv())` arms upstream recv on the current upstream
  socket and waits for the recv completion.
- `wait(upstream(api).send(req.body))` sends the current request buffer
  upstream and waits for the send completion.

`wait(any(...))` resumes on any declared supported arm. Today that means
`downstream.recv()` plus an optional `timer(N)` timeout arm; `N` is
milliseconds.

When the route needs different control flow for each winning arm, prefer
statement-form `wait any`. The first slice supports a downstream recv arm and a
timer arm, with direct terminal branch bodies:

```rut
route POST "/upload" {
    wait any {
        downstream.recv() => { return 204 }
        timer(2000) => { return 408 }
    }
}
```

## Result Values

`wait(...)` may be bound to a local. The result currently exposes these fields:

- `kind`: numeric `YieldKind` value for the event that resumed the handler.
  Current resume values are `3 = Timer`, `5 = Recv`, `6 = Send`,
  `7 = UpstreamConnect`, `8 = UpstreamRecv`, and `9 = UpstreamSend`.
  `4 = Any` is only a requested wait kind; resumes report the actual event arm.
- `result`: raw `IoEvent::result`.
- `ok`: true when `result >= 0`.
- `eof`: true only for recv-like events (`downstream.recv` and
  `upstream.recv`) when `result == 0`; false for timer/connect/send events.
- `timer`, `recv`, `send`, `upstream_connect`, `upstream_recv`, and
  `upstream_send`: boolean predicates derived from `kind`, provided so routes
  do not need to hard-code numeric `YieldKind` values.

Wait for downstream activity on the current connection:

```rut
route GET "/stream" {
    let ev = wait()
    guard ev.ok else { return 500 }
    if ev.eof { return 499 } else { return 200 }
}
```

Wait for request body data:

```rut
route POST "/upload" {
    let ev = wait(downstream.recv())
    guard ev.ok else { return 400 }
    if ev.eof { return 400 } else { return 204 }
}
```

Wait for an upstream connection:

```rut
upstream api at "127.0.0.1:9000"

route GET "/proxy" {
    let conn = wait(upstream(api).connect())
    guard conn.ok else { return 502 }
    return 200
}
```

Wait for upstream request send and response recv:

```rut
upstream api at "127.0.0.1:9000"

route POST "/proxy" {
    let up = wait(upstream(api).connect())
    guard up.ok else { return 502 }

    let sent = wait(upstream(api).send(req.body))
    guard sent.ok else { return 502 }

    let response = wait(upstream(api).recv())
    guard response.ok else { return 502 }
    return 204
}
```

Each bound wait result is stored in the handler frame. Older wait results stay
available after later waits:

```rut
route POST "/upload" {
    let first = wait(any(downstream.recv(), timer(2000)))
    let second = wait(downstream.recv())
    if first.timer {
        return 408
    } else {
        guard second.ok else { return 400 }
        return 204
    }
}
```

Wait routes support direct `return`, `if`, and `match` terminal control after
the ordered wait/guard sequence.

## Race Waits

`wait any` is the clearest form when each winning event should run different
route logic:

```rut
route POST "/upload" {
    wait any {
        downstream.recv() => { return 204 }
        timer(2000) => { return 408 }
    }
}
```

The older `wait(any(...))` expression form remains available and returns the same result surface as other event waits:

```rut
route POST "/upload" {
    let ev = wait(any(downstream.recv(), timer(2000)))
    if ev.timer {
        return 408
    } else {
        guard ev.ok else { return 400 }
        return 200
    }
}
```

## Timer Waits

Timer waits suspend for a deadline and then resume the same handler:

```rut
route GET "/sleep" {
    wait(250)
    return 204
}
```

The bare integer form is milliseconds. Duration suffixes are also supported:

```rut
route GET "/a" { wait(500ms) return 204 }
route GET "/b" { wait(2s) return 204 }
route GET "/c" { wait(5m) return 204 }
route GET "/d" { wait(1h) return 204 }
```

The duration is stored as an unsigned 32-bit millisecond payload. `wait(0)` is
rejected.

## Event Waits

Event waits suspend until the requested event kind completes:

```rut
route POST "/upload" {
    wait(downstream.recv())
    return 204
}
```

The event kind is encoded in the JIT yield result:

- `wait()` -> `YieldKind::Any`
- `wait(downstream.recv())` -> `YieldKind::Recv`
- `wait(upstream(api).connect())` -> `YieldKind::UpstreamConnect`
- `wait(upstream(api).recv())` -> `YieldKind::UpstreamRecv`
- `wait(upstream(api).send(req.body))` -> `YieldKind::UpstreamSend`

The runtime stores the pending yield kind and only resumes the handler when a
matching event arrives. In this slice, downstream recv is auto-armed when
entering `wait()` or `wait(downstream.recv())`; upstream connect, upstream
recv, and upstream send with `req.body` start the corresponding operation
before waiting. Starting a downstream response send inside
`wait(downstream.send(...))` is not supported yet.

For this slice, "completion wait" is the important boundary:

- `wait(downstream.recv())` can arm downstream recv and wait for its completion.
- `wait(upstream(api).connect())` starts the upstream connect and waits for
  its completion.
- `wait(upstream(api).recv())` arms upstream recv on the current upstream
  socket and waits for its completion.
- `wait(upstream(api).send(req.body))` sends the current request buffer
  upstream and waits for its completion.
- Upstream recv/send waits preserve the named upstream target and fail closed
  if the current upstream socket was opened for a different target.
- `wait(any(downstream.recv(), timer(250)))` waits for downstream recv and also
  resumes with `kind = 3` when the timeout fires. Upstream arms inside
  `any(...)` are rejected until the arm list is carried through lowering.

## Supported Route Shape

Current wait lowering supports source-ordered top-level guards and waits:

```rut
route GET "/x" {
    let code = 201
    guard req.path == "/x" else { return 404 }
    wait(100)
    guard code == 201 else { return 500 }
    return 201
}
```

In other words:

```text
let* ;
(guard | wait)*; terminal_control
```

`let` bindings may appear before the first `wait`. Top-level guards may appear
before, between, or after waits, and a failing guard returns immediately without
arming later waits. A `let` after a `wait`, or a `wait` after terminal control
(`if` / `match` / `return` / `forward`), is rejected today.

The current codegen re-materializes pure pre-wait local initializers when the
handler reaches the terminal state. Wait result `kind` / `result` pairs are
stored in dedicated `HandlerCtx` frame slots so they survive later waits.

## Runtime Behavior

Timer `wait(...)` compiles to a timer yield:

1. Initial call with `state = 0` enters the first route state. It may return,
   forward, branch through guards, or return `Yield(Timer, ms, next_state = 1)`.
2. The event loop schedules a timer for the raw millisecond payload.
3. When the timer fires, the loop resumes the same handler with `state =
   next_state`.
4. The resumed state continues after the corresponding `wait(...)`.

Both production loops have millisecond-resolution timer paths:

- epoll uses a one-shot `timerfd` plus a min-heap of yield deadlines.
- io_uring uses `IORING_OP_TIMEOUT`.

If a precise timer path is unavailable under pressure, the loops may use the
1-second wheel only when the requested wait can still be represented safely.
Otherwise the request fails instead of resuming early.

Event `wait(...)` compiles to an event yield:

1. Initial call reaches `wait()` or `wait(downstream.*)` / `wait(upstream(...).*)` and returns
   `Yield(event_kind, next_state)`.
2. The runtime clears handler callback slots, records the pending handler,
   state, and event kind, and returns to the event loop.
3. When a matching completion event arrives, the loop records the completion
   kind/result in `HandlerCtx` and resumes the handler with `state =
   next_state`.
4. Non-matching events do not resume the pending handler.

Offline simulation uses the same handler frame shape as production. The
simulator drives each yielded handler state to completion immediately, records a
successful synthetic completion in `HandlerCtx`, and keeps the wait-result
slots allocated across later waits. This lets capture replay exercise branches
such as `first.timer` after a later `wait(...)` without opening sockets or
waiting for real timers.

## Decorators

Decorated wait routes are supported for the direct terminal subset:

```rut
func auth(_ ignored: i32) -> i32 => 0

route {
    @auth "*"
    GET "/sleep" { wait(1000) return 204 }
}
```

Decorator guards run before the first timer yield is armed. Decorated wait
routes currently reject user `let` bindings, user top-level guards, for-loops,
and non-direct terminal control such as `if` / `match`.

## Current Gaps

The following are future work rather than current behavior:

- Rich result payloads beyond the current scalar fields and event-kind
  predicates.
- Response starts inside `wait(downstream.send(response(...)))`; use terminal
  `return response(...)` for downstream responses until route completion can
  model "send and finish" without a second terminal response.
- Exact event subsets inside `wait(any(...))`; today it uses current-connection `Any`
  once the listed forms validate.
- Parameterized IO starts inside `wait(any(...))`; start the operation before a
  later race wait until that payload has a richer representation.
- `wait any` arm result binding such as `r = downstream.recv() => { ... }`.
- Non-wait `let` bindings after a `wait(...)`.
- Waits inside nested blocks, loops, branches, or decorator bodies.
