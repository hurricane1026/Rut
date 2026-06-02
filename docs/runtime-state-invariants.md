# Runtime State Invariants

Rut's runtime dispatch is slot-driven: `Connection::state` is the debug and
metrics label, while the callback slots decide which handler receives the next
event. The formal model in `spec/runtime_state.tla` captures the intended
state/slot/resource shapes for representative transitions.

## Model Boundary

The TLA+ model abstracts one connection. It tracks:

- `state`: the `ConnState` value.
- `slots`: active callback slots.
- `fdAlive` and `upstreamAlive`: whether client and upstream fds are logically
  live.
- `pendingHandler`, `handlerState`, and `yieldArmed`: yielded JIT handler state.
- `pendingOps`: abstract async operation count.

It intentionally does not model HTTP bytes, parser internals, concrete file
descriptor values, buffer contents, TLS state, or the epoll/io_uring kernel
interfaces. Those are implementation details tested elsewhere.

## Consistency Gate

Run:

```bash
python3 scripts/check_runtime_state_model.py
```

The script checks that:

- TLA+ state names match `ConnState` and the debug-name table.
- TLA+ slot names match `ConnSlotMask`.
- Every `@rut.action` marker has a matching TLA+ action definition.
- Every modeled action points at existing C++ implementation or test tokens.

If `tlc` is installed, or `TLA2TOOLS_JAR` points to `tla2tools.jar` and `java`
is available, the same script also runs TLC against `spec/runtime_state.cfg`.

## Proof Contract

The model proves the abstract transition graph preserves the invariants. The
script prevents the most important implementation/model drift, but it is not a
full C++ verifier. To keep the proof meaningful, new runtime state transitions
should update all of these together:

- the C++ transition or callback path,
- the corresponding state-invariant test,
- `spec/runtime_state.tla`,
- `scripts/check_runtime_state_model.py` only if new source surfaces must be
  parsed.

Over time, key state mutations should move behind small transition APIs. Once
that happens, each API can map one-to-one to a TLA+ action and the consistency
gate can become stricter.
