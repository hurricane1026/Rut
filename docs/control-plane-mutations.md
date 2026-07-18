# Control-Plane Mutation Contract

Status: accepted contract. The shared mutation port, handler ABI capability,
JIT helper boundary, production event-loop injection, and deterministic harness
fixture are implemented; source lowering and the process reload coordinator
remain staged in TODO.md.

Rut exposes control-plane reads (`stats()` and `metrics()`) as bounded values
latched at handler entry. Mutations are different: they change process-wide
state and therefore need an explicit authority, a visible failure result, a
total publication order, and a deterministic harness model.

This document defines those boundaries for `reload()` and
`upstream.mark(server, healthy:)`. An implementation must not accept either
source form until it implements the corresponding contract end to end.

## Source contract

```rut
route POST "/admin/reload" {
    guard reload() else { return 503 }
    return 202
}

timer check_health, every: 5s, shard: 0 {
    for server in users.servers {
        let healthy = check(server)
        guard users.mark(server, healthy: healthy) else { return }
    }
}
```

The canonical signatures are:

```text
reload() -> bool
Upstream.mark(Server, healthy: bool) -> bool
```

Both calls are synchronous, bounded, non-suspending operations. They never hide
a yield and therefore never imply that a reload compile or cross-shard drain
completed before the call returned.

- `reload()` returns `true` only when this invocation claimed the process's one
  pending reload request slot. It returns `false` when route-triggered reload is
  disabled, the process is stopping, or a request is already pending/in flight.
  A `true` result means *accepted*, not *activated*; `202 Accepted` is the
  prescriptive route response.
- `mark` returns `true` only when it atomically published the requested manual
  override for a `Server` belonging to the currently active config generation.
  It returns `false` for a stale/foreign server identity or when control-plane
  mutation is unavailable. A successful call is already visible through the
  process-wide override table; it is not merely queued.

Ignoring either boolean is legal but explicit. The calls are values, not
statement-only special cases, so a route or timer can fail closed.

## Authority

Route-triggered reload is disabled by default and requires an explicit process
capability (the production CLI spelling will be `--allow-route-reload`). This
prevents a source typo or an accidentally exposed route from gaining process
mutation authority merely because the binary supports hot reload.

The flag is not application authentication. Rut source remains responsible for
placing the call behind the intended host/path/authentication policy. Operators
that do not want application-triggered reload leave the capability disabled and
use the separately authenticated process control channel (for example SIGHUP).

`upstream.mark` is timer-only and may appear only in a timer with an explicit
`shard: N` selector. Timer code is trusted program code, while the shard pin
ensures one source-level writer for a manual health override. Route handlers and
un-pinned per-shard timers are rejected by the analyzer.

## Reload coordinator

One process coordinator owns the source path, compiler/JIT, active generation,
and all program lifetimes. Shards never compile and never install a candidate
directly.

The coordinator executes one request at a time:

1. Claim the single request and assign a monotonically increasing request id.
2. Compile/JIT a candidate without changing live registries or shard pointers.
3. Validate the candidate before publication:
   - every timer shard selector is valid for the unchanged process shard count;
   - Cache identities, key/value layouts, and capacities are compatible with
     the active generation;
   - every runtime capability required by the candidate is available.
4. Publish the candidate's immutable config and handler bundle with one new
   generation number, then send that same `(generation, config)` pair to every
   shard.
5. Wait for every shard to acknowledge installation at an event-loop command
   boundary before accepting another reload.
6. Reclaim an old program only after all shards acknowledged a newer generation
   and its HTTP/1 request and HTTP/2 stream pin counts reached zero.

Compilation or validation failure is *definitely not applied*: the active
generation and every live registry remain unchanged. Publication has no
fallible step after the generation becomes visible. This rules out a result
where some shards report the new generation while the coordinator reports that
the same reload failed.

The process may temporarily serve two adjacent generations while shards reach
their command boundaries. Each request/stream pins exactly one program bundle,
so its route table, handler code, Cache schema, and upstream identities never
mix generations. The coordinator does not publish generation `N+1` until all
shards acknowledged `N`; every shard therefore observes the same strict
generation order without skipped updates.

SIGHUP and an accepted `reload()` request use this one coordinator and the same
validation path. They cannot race independent reload mechanisms.

## Manual upstream health

A `Server` value carries an opaque identity:

```text
(config_generation, upstream_id, backend_id)
```

It does not expose a raw runtime pointer. `upstream.mark` first validates the
generation and upstream membership, then writes a process-shared bounded
override slot for that exact identity. All shards consult the override before
their local active/passive health state:

- `healthy: false` forces the target out of normal selection;
- `healthy: true` forces it into normal selection;
- a reload clears all overrides while publishing the new generation.

If every backend is manually unhealthy, selection reports no backend and the
proxy attempt fails closed (503 for a new forward). The existing availability
fallback applies only when shard-local active/passive health ejects every
otherwise eligible backend; it never bypasses a manual unhealthy override.

Manual state has priority over probe and passive-ejection state so a later local
probe cannot silently undo an operator program's verdict. Calls from the one
shard-pinned timer are ordered by program order. The generation check makes a
late timer invocation against a replaced config definitely not applied.

## Failure and observation

| Operation | Result | State change |
|---|---|---|
| reload capability disabled | `false` | none |
| reload already pending/in flight | `false` | none |
| reload accepted | `true` | request slot only; activation is asynchronous |
| candidate compile/validation fails | coordinator failure record | active generation unchanged |
| candidate activates | coordinator success record | all shards converge in generation order |
| mark uses stale/foreign `Server` | `false` | none |
| mark capability unavailable | `false` | none |
| mark succeeds | `true` | shared override atomically updated |

Every accepted reload produces exactly one terminal coordinator record containing
the request id, old generation, candidate generation (if any), and success or a
bounded failure code. Production writes the record to structured logs and
counters. The harness exposes the same record directly to its oracle. No record
stores unbounded compiler text.

## Harness and replay

The harness control-plane port owns the same bounded state machine as
production:

- enabled/disabled/stopping authority state;
- the one-slot reload admission gate;
- deterministic compile/validation outcomes;
- per-shard generation acknowledgements and request/stream pins;
- the current manual-health override table; and
- terminal mutation records.

Handler-layer runs may model admission and `mark` atomics. Reload activation
requires at least the `Process` execution layer because it owns compilation,
shards, and program lifetimes. A lower-fidelity layer must report
`Unsupported`, never synthesize a successful activation.

Replay input records mutation requests and coordinator outcomes, not wall-clock
thread timing. A replay must reproduce the same accepted/rejected calls,
generation order, and terminal records.

## Required implementation order

1. [x] Add the control-plane mutation port and deterministic admission/override
   model to the handler ABI and harness.
2. [x] Implement `Server` identities, `Upstream.servers`, and the shared manual
   health override consulted by both network backends.
3. Lower and execute timer-only, shard-pinned `upstream.mark`.
4. Implement the reload coordinator, generation acknowledgements, program pins,
   compatibility validation, SIGHUP, and process-harness coverage.
5. Lower route-only `reload()` after the same coordinator is the sole activation
   path.
