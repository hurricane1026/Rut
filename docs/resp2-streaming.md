# Incremental RESP2 decoding

Import [clients/resp2-stream.rut](../examples/clients/resp2-stream.rut) or the
shared [clients/resp2.rut](../examples/clients/resp2.rut). The parser
is ordinary Rut using bounded collection, checked Bytes views and owned buffer
concatenation. The runtime contains no Redis parser or protocol callback.

| API | Result and contract |
| --- | --- |
| `resp2Stream(maxBytes)` | `Resp2Stream?`; initialize a single frame with a limit from 1 through 8192 bytes. |
| `resp2Feed(stream, chunk)` | `Resp2Stream?`; append immutable bytes and advance parsing from the saved cursor. |
| `stream.cursor.status` | `0` NeedMore, `1` Complete, `-1` Invalid. |
| `stream.cursor.offset` | Consumed position. During an incomplete token it remains at that token's start. On completion it is the first byte of the next frame. |
| `resp2Result(stream)` | `Collected<Resp2Token>?`; decode the completed prefix using the existing strict decoder. |
| `resp2Remainder(stream)` | `Bytes?`; the untouched bytes after a completed frame. |
| `resp2Finished(stream)` | True only for a complete single frame with no remainder; false at incomplete EOF. |
| `resp2Receive(connection, stream)` | `Resp2Stream?`; at most one TCP receive, only while NeedMore. The current helper uses a literal 1000 ms deadline per receive. |

Use the constructor and returned states in sequence. States are ordinary public
records, not trusted authentication evidence. `resp2Result` validates the actual
completed wire prefix again, rather than trusting a constructed cursor.

A missing API result means invalid API state, transport/EOF failure, byte-limit
or storage exhaustion. A present `Invalid` state reports malformed wire data or
an impossible frame under the configured byte/node limits. Only Complete admits
a decoded result. NeedMore never means that a command succeeded.

## State transitions

The cursor retains aggregate pending counts, completed-node count, line-search
position and a pending bulk payload's exact end offset. It resumes CRLF searches
at the previous last byte, so a delimiter split between CR and LF works. Once a
bulk length is known, intermediate feeds wait for that exact payload and final
CRLF; embedded CRLF, NUL and high-bit payload bytes are ordinary data. Completed
tokens are not rescanned by the framing cursor.

The wire grammar follows the [Redis RESP specification](https://redis.io/docs/latest/develop/reference/protocol-spec/):
RESP2 simple strings, errors, signed 64-bit integers, bulk strings, arrays and
null bulk/array values. Negative lengths other than exact `-1`, signed positive
lengths, invalid terminators and out-of-range integers reject. The 64-node limit
includes array headers and null values; impossible outstanding node counts reject
at the array header. Empty input remains NeedMore. A full buffer which still
needs bytes becomes Invalid. Declared bulk payloads that cannot fit the configured
frame budget reject as soon as their header is complete.

Complete stops at the first root, preserving pipelined replies in the remainder.
Do not feed an already Complete or Invalid parser. Consume the first result,
create a fresh parser, and feed its remainder. Never silently discard a remainder
when a caller expects exactly one reply. At EOF, NeedMore is a truncated frame,
not an empty reply; `resp2Receive` fails on empty TCP receive.

## Ownership and bounds

`concatBytes(left, right, maxBytes) -> Bytes?` is a generic binary operation,
using existing function-call syntax. Both inputs must be unwrapped Bytes; the
limit must be an unwrapped i32 from 1 through 8192. The sum must fit that limit.
A success owns a new immutable arena buffer, including empty success. Inputs are
unchanged; earlier chunks, parser states and result views remain valid across
later appends and I/O. There is no UTF-8 conversion, implicit Bytes `+`, kernel
retention of source pointers, new allocator or dependency. Wrong source/RIR
operand types reject; runtime bounds or arena/pool exhaustion return nil without
altering `netError()`.

The existing 256 KiB invocation budget applies to all copies and parser result
storage. Accumulation copies the prefix on every feed, and `resp2Result` makes
one final token-decoding pass. Thus copy work is proportional to the sum of the
buffer lengths across feeds, not just final frame length. Excessive feeds can
exhaust the arena even below the 8192-byte per-frame limit. This is bounded
incremental framing, not a zero-copy receive ring or an unlimited subscription.

`resp2Receive` composes existing network primitives; it does not retry writes or
open connections. The caller chooses a finite number of calls. Completed/Invalid
states skip further receives. Each receive has its own deadline; there is no
implicit overall-frame deadline. The existing limit of 16 network/HTTP operations
and 4096 verifier blocks still applies. Complex unrolled parser compositions can
hit compiler budgets before the operation limit; use a deliberate small read
budget and fail when the final state is still NeedMore. See the
[executable two-read example](../examples/resp2-stream-client.rut).

## Suspension and verification

Only SSA values needed by a reachable suspension or its polling arguments occupy
the continuation frame. Phi uses are attributed to their incoming edges. Pure
parser temporaries stay local, and non-spilled phi inputs are loaded on their
actual predecessor edges. Already-bound values do not introduce another I/O
operation or turn pure parser branches into effectful branches.

The runtime frame and saved HTTP request remain bounded to 8192 bytes each.
Large pure parser code no longer has the old 1024-total-value restriction: the
compiler admits up to 1048576 SSA values, with arena-backed compact liveness sets
and a separate 256 MiB bitset scratch ceiling. These are compilation budgets;
no runtime frame capacity, socket count or arena budget is raised.

Tests compare decoded tokens with an independent wire oracle and split valid
frames at every byte position through real TCP reads. They also exercise delayed
receive, completed-state no-I/O, timeout, truncated EOF, binary data, nested/null
arrays, integer limits, 64 nodes, invalid/oversized headers and source removal.
Both epoll and io_uring run at O0 and O2.

[Request builders and GET/SET](resp2-commands.md) use a separate bounded scalar
receive helper with a one-node parser work limit and four receive attempts.
The generic `resp2Receive` API and the two-read streaming example keep their
existing contracts.

The shared `resp2Token(bytes, offset)` parser decodes one complete scalar/bulk
node or array header; `resp2Step` retains aggregate bookkeeping. The
[pipeline library](redis-pipeline.md) reuses the same token grammar and streaming
cursor for an explicit number of response roots. Its aggregate byte/node/read
bounds apply to the complete batch.
