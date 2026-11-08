# Bounded parsing and collected results

`collectBytes(input, initialState, maxItems, step)` performs a finite, synchronous
scan over a complete Bytes buffer and returns `Collected<Item>?`. It introduces
no keywords, runtime function values, closures, recursion, protocol-specific
runtime operations or external dependencies. TCP/UDP reads remain separate.

The fourth argument is a named, non-generic Rut function declared before its
collector helper, with two parameters:
`Bytes` and the initial state's exact type. Its result is a three-element tuple
`(State, Item, bool)`, optionally nil. Each successful step contributes one item,
updates the state and completes when the Boolean is true. The completing item is
included. A nil step, exhausted work/storage budget or allocation failure returns
nil for the whole collection; callers cannot observe a partial result.

`maxItems` must be a literal from 1 through 64. The scanner invokes at least one
step, so empty input is not an implicit empty success. The step decides whether
that input is meaningful. A step that never completes still terminates at the
literal limit, even if it never advances its state.

```rut
func lineStep(_ input: Bytes, _ offset: i32) -> (i32, Bytes, bool) {
    guard let end = input.find(b"\r\n", offset) else { nil }
    guard let value = input.slice(offset, end) else { nil }
    (end + 2, value, end + 2 == input.count)
}
func lines(_ input: Bytes) -> Collected<Bytes> {
    collectBytes(input, 0, 64, lineStep)
}
```

State and item shapes must be concrete primitive values or nonempty plain structs, with
no optional/error leaves, arrays, collected values or recursive shapes. Existing
bool, i32, str and Bytes source types work; an item may also be an inferred i64
result, for example from `parseInt64`. Record storage is capped at 512 bytes,
16 str/Bytes leaves and eight structural nesting levels. These bounds are
checked again for direct RIR consumers. General-purpose Array mutation and
iteration are not added by this API.

Steps cannot use request/response state, network/HTTP calls, timers, cache,
randomness or nested collection. Capability checks cover the retained lexical
body as well as the normalized value body: an unused binding cannot hide I/O.
The function name is selected at compile time; it cannot come from a local
value, closure or runtime dispatch. Ordinary bindings can shadow `collectBytes`
under the existing builtin shadowing rules.

## Read-only collection API

| Expression | Result | Meaning |
| --- | --- | --- |
| `values.count` | i32 | Number of committed items, from 1 to maxItems. |
| `values.get(index)` | Item? | Exact typed item, or nil for a negative/out-of-range i32 index. |

Unwrap the collection before using it. `Collected<i32>` and `Collected<Bytes>`
are distinct types. Helpers may accept and return a concrete `Collected<T>`;
local annotations are supported. Collections cannot be constructed or appended
to directly, compared, subscripted, or substituted for Bytes/Array. The initial
profile does not embed collections inside structs, variants or tuples. The API
is available in ordinary HTTP routes and helpers; WebSocket use remains outside
this initial profile.

The backing storage belongs to the invocation's existing SliceArena. Before a
record is committed, every str/Bytes leaf, including nested struct leaves, is
copied to that arena. Returning an item does not borrow a step's scratch buffer
or mutable parser workspace. Empty views are normalized without dereferencing
an absent pointer. Failed appends do not increment count. The collection's
lifetime cannot extend beyond its owning invocation.

The existing 256 KiB aggregate arena budget and contiguous pool-slice limit
still apply. A backing block includes its header and all `maxItems` record slots;
it must fit in one 16 KiB slice. Each copied string must also fit in an arena
block. Consequently, not every combination of maximum record size, work limit
and payload size can be admitted. Nothing silently truncates or returns a
partial collection. Parsing/storage failure does not alter `netError()`.

## Lowering and verification

The compiler evaluates input and initial state once in source order, then
expands the literal work limit into a forward-only RIR graph. No runtime
function-pointer callback is installed. The existing native automaton verifier
can prove the graph terminates without accepting an unproven backedge.

Collection allocation, count and checked access retain reached branch semantics.
A failed `guard let` cannot speculatively dereference an absent collection.
Checked item access validates its index and element layout before loading data.
The JIT and native loader use the same typed operations and registered helpers;
the runtime stays independent of LLVM.

Expansion trades code size and compilation work for reuse of the existing
acyclic verifier. Complex steps also remain subject to the existing IR and
4096-node automaton budgets. This is a bounded parser primitive, not unrestricted
runtime iteration or a claim of optimal generated-code size.

## RESP2 library example

The [RESP2 decoder](../examples/clients/resp2.rut) implements protocol logic in
ordinary Rut. It follows the [Redis protocol specification](https://redis.io/docs/latest/develop/reference/protocol-spec/)
for simple strings, errors, signed 64-bit integers, bulk strings, arrays and
RESP2 null bulk strings/null arrays. Binary payloads need no text conversion.
`decodeResp2` rejects truncated values, trailing bytes, malformed lengths and
out-of-range integers. Inputs exceeding the 64-node/storage budget also fail.

The result is a preorder collection of `Resp2Token` records:

| Field | Meaning |
| --- | --- |
| `kind` | 1 simple string; 2 error; 3 integer; 4 bulk string; 5 array; 6 null bulk; 7 null array. |
| `data` | Unprefixed string bytes, or the validated integer spelling; empty for array/null nodes. |
| `next` | First byte after this node's header/payload. Array children follow the array header. |
| `children` | Direct array arity, otherwise zero. |

Preorder plus direct arities preserves nesting without recursive heap objects.
The decoder tracks remaining value slots; it finishes only after one complete
root value. `resp2Integer(token)` returns an inferred i64? without losing signed
limits or converting numbers through floating point. An error reply is a valid
protocol value with kind 2; it is not treated as successful command execution.
See the [HTTP example](../examples/resp2-decoder.rut).

This decoder consumes a complete buffer. A TCP `receive` returns only some
available bytes and is not evidence that a complete reply has arrived. Incremental
`NeedMore` state, network iteration, connection pooling, request command building
and a complete Redis driver remain separate work.

## Validation

The Python integration oracle independently decodes wire bytes and checks every
collected node's kind, payload, position and arity. Both epoll and io_uring run
at O0 and O2 after source/import removal. Tests cover nested/empty/null values,
NUL/high-bit bulk bytes, signed bounds, all prefixes of a truncated aggregate,
trailing replies, 64-node limits, stalled steps and arena exhaustion. Runtime
unit tests additionally protect the end of input with an unreadable page, revoke
the original input mapping after collection, and exhaust the backing pool before
publishing a second record. Source and direct-RIR tests reject invalid shapes,
capacities, callback effects and collection type mismatches.
