# Bounded cache invalidation

Redis and Memcached expose finite multi-key deletion with explicit outcomes.
Both retain the existing 8192-byte frame bound, four receives with fixed 1000 ms
deadlines, invocation-owned results and caller-managed connection pooling.
Neither operation reconnects or replays after failure.

## Redis DEL and UNLINK

Import `clients/redis-client.rut`:

- `redisKeys()` starts an empty `RedisKeys` builder.
- `redisKeysAdd(keys, key: Bytes)` appends a binary-safe key, returning nil on
  builder count/storage limits. There are at most eight keys. Empty and repeated
  keys are permitted, following Redis semantics.
- `resp2DeleteKeysRequest(keys, mode)` formats one request, within 8192 bytes.
- `redisDeleteKeys(connection, keys, mode)` executes it, returning `RedisResult`.
  `RedisDeleteMode.blocking` chooses DEL and `.lazy` chooses UNLINK.

The final client revalidates the complete encoded request before sending.
Public `RedisKeys.arguments` and `count` fields do not prove that the request is
well formed; forged counts, nested arguments or trailing commands are rejected
without writing. As with the existing generic encoder, callers using pure
builders on public records can explicitly validate with `redisRequestValid`.
An empty builder cannot be executed. Header and command-name overhead count
against the frame limit, including for the last added key.

A successful reply must be an integer in `0...keys.count`. Access it with
`redisInteger(reply)` without narrowing. The count reports keys actually
removed; repeated or absent keys do not inflate it. A negative count, a count
larger than the request, a wrong reply type or trailing data closes the handle.
A complete server error leaves the Redis handle usable, while invalid requests
preserve it without sending. Transport and framing failures close all aliases.

```rut
let result = redisDeleteKeys(connection, keys, RedisDeleteMode.lazy)
```

DEL and UNLINK are single Redis commands, not a client-side loop. UNLINK requires
Redis 4.0 or later: key removal is immediate and reclamation can run separately.
There is no fallback to DEL. These contracts follow
[DEL](https://redis.io/docs/latest/commands/del/) and
[UNLINK](https://redis.io/docs/latest/commands/unlink/).
The caller still chooses the node/session. Cluster multi-key restrictions and
CROSSSLOT errors remain server-visible; this helper does not add cross-node
routing or atomicity guarantees.

## Memcached delete batches

Import `clients/memcache-delete-batch.rut`. It composes the existing
`MemcacheKeys` builder and validation with basic-text delete framing. It can be
combined with the ordinary data-operation client using namespace aliases,
since both modules expose shared codec names:

```rut
import * as base from "clients/memcache-client.rut"
import * as batch from "clients/memcache-delete-batch.rut"
```

`memcacheDeleteBatchRequest(keys)` encodes one `delete key\r\n` command for each
key in order. `memcacheDeleteBatch(connection, keys)` sends the whole batch once.
The key set must contain 1–8 unique valid Memcached keys; existing key/record
validation is applied before I/O, including the 250-byte per-key bound.
There is no `noreply` mode and no terminal END line for this batch.

`MemcacheDeleteBatchResult` contains:

- `.reply(MemcacheDeleteBatchReply)`: exactly one DELETED or NOT_FOUND reply per
  requested key has been consumed, with no trailing bytes in the current frame.
- `.serverError(Bytes)`: a validated ERROR/CLIENT_ERROR/SERVER_ERROR line.
- `.requestFailure`, `.transportFailure(i32)` and `.replyFailure`.

`MemcacheDeleteBatchReply` retains `frame: Bytes` and `keys: MemcacheKeys`.
`memcacheDeleteItem(reply, index)` validates those public fields and the whole
reply before returning an optional `MemcacheDeleteItem`: the corresponding request
`key: Bytes` and `deleted: bool`. False means NOT_FOUND, an ordinary miss. Results
remain valid after later I/O and close within the same invocation. No incomplete
prefix is published as a successful batch.

```rut
let result = memcacheDeleteBatch(connection, keys)
```

Memcached processes separate commands, so this batch is not atomic. Some or all
deletes may already have executed when sending/reading fails, even if no complete
result is returned. A server error can occur after earlier deletes succeeded.
Every server/transport/framing error closes aliases and abandons the remaining
reply stream; invalid requests preserve the clean connection. No failure causes
an automatic resend. Retrying can delete a value recreated by another writer.

The framing follows the pinned
[Memcached basic-text protocol](https://github.com/memcached/memcached/blob/1.6.45/doc/protocol.txt).
Eight commands still share four receives; sufficiently fragmented replies can
exhaust that budget and fail closed. This does not increase runtime I/O limits.

## Verification

`test_client_invalidation.py` checks independent wire peers and isolated pinned
Redis 7.2.11/Memcached 1.6.45. It covers 1/3/8-key real deletes and repeated
misses, binary Redis keys, duplicate policies, forged builder counts, exact
request bounds, ordered Memcached access, wrong/negative/excess acknowledgements,
extra replies, partial-prefix errors, EOF, timeout and no replay. The registered
matrix covers epoll/io_uring, O0/O2, TCP and verified TLS. Test gateway sources
are removed after startup.

A separate composition case combines namespaced batch deletion and the ordinary
Memcached GET on one handle, including a returned result retained across that I/O.
