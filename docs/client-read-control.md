# Read control and cache metadata

These ordinary Rut modules use the existing TCP/TLS transport. They introduce no
language syntax, dependencies or runtime protocol operations.

## Redis atomic read mutations

Import `redis-client.rut` and use:

```swift
let previous = redisGetDel(connection, key)
let refreshed = redisGetEx(connection, key, RedisGetExpiry.seconds(60))
let persistent = redisGetEx(connection, key, RedisGetExpiry.persist)
```

Both return `RedisGetResult`: `value(Bytes)`, `missing`, `serverError(Bytes)`,
`requestFailure`, `transportFailure(i32)` or `replyFailure`. Values and keys are
binary-safe, including empty keys/values. GETDEL removes a string atomically with
returning its old value; GETEX returns the value and optionally changes its TTL.
A wrong-type server error preserves the non-string key.

`RedisGetExpiry` admits exactly one option:

| Option | Meaning |
| --- | --- |
| `unchanged` | Keep the existing expiry |
| `persist` | Remove the expiry |
| `seconds(i32)` / `milliseconds(i32)` | Positive relative expiry |
| `unixSeconds(Bytes)` | Positive decimal timestamp, at most 9223372036854775 |
| `unixMilliseconds(Bytes)` | Positive decimal timestamp, at most 9223372036854775807 |

Absolute timestamps reuse the existing SET validation and canonicalization.
Leading zeroes are accepted, signs and overflow rejected. A valid timestamp in
the past can delete an existing key while still returning its old value. SET's
`keepTtl` is deliberately absent from this type; the GETEX default already keeps
TTL. `resp2GetExRequest` exposes the same bounded encoder for explicit composition.

Each operation sends once, accepts one scalar bulk/null/error frame, and reads
at most four times with 1000 ms per operation and an 8192-byte complete-frame
limit. A locally rejected request leaves a clean handle usable; transport or
protocol failure closes it. Valid server errors preserve framing and leave the
handle usable, as with GET. An EOF/timeout does not establish whether a mutation
took effect. No mutation is automatically replayed.

Protocol references: [GETEX](https://redis.io/docs/latest/commands/getex/) and
[GETDEL](https://redis.io/docs/latest/commands/getdel/), available since Redis 6.2.

## Memcached metadata GET

Import `memcache-meta.rut` and call `memcacheMetaGet(connection, key)`. It sends
`mg <key> v f c t` and returns `MemcacheMetaResult`:

- `value(MemcacheMetaItem)`: binary `data`, decimal Bytes `flags` and `cas`,
  and `ttlSeconds: i32`. TTL -1 means no expiry; nonnegative TTL is the server's
  remaining seconds when it handled the request.
- `missing`: the exact EN response, distinct from an empty value.
- `serverError(Bytes)`, `requestFailure`, `transportFailure(i32)` or `replyFailure`.

The CAS token retains the full unsigned 64-bit range and can be passed to the
existing `memcacheCas` APIs. Client flags retain the unsigned 32-bit range. TTL
is bounded to -1 through 2147483647 in this pinned-server profile; it is a
snapshot, not a promise of future availability.

Keys use the basic-text 1..250-byte validation. The reply must contain exactly
one value and each of f/c/t exactly once, in any order. Value framing uses the
declared byte length, so CR/LF/NUL inside data are preserved. Negative/overflowing
numbers, duplicate/missing/unknown metadata, bad terminators, trailing replies
and oversized frames are rejected. In particular a stale X flag fails closed;
this helper does not serve stale or coordinate recaching. No `q`, `N`, `R`, `T`
or other mutation/quiet flags are sent. It can share a connection with basic-text
commands. An authenticated connection must still follow its authentication
module's close-after-use policy.

The complete reply is bounded to 8192 bytes and four receives with 1000 ms per
operation. Local request failure preserves the handle. Server, transport and
protocol failures close it; partial data is never published. Successful values
are invocation-owned and remain valid after another receive and close. There
is no automatic retry or pooling of partial reply state.

This profile is checked against the
[pinned Memcached 1.6.45 protocol](https://github.com/memcached/memcached/blob/1.6.45/doc/protocol.txt#meta-get).
Other meta operations and flags remain outside this helper's contract.

## Validation

`test_client_read_control.py` uses independent protocol peers for exact requests,
fragmentation, binary/empty/missing values, metadata permutations and integer
bounds, exact 8192-byte replies, invalid requests before I/O, malformed/trailing
frames, EOF, timeout, closed aliases and no replay. Live pinned Redis 7.2.11 and
Memcached 1.6.45 check actual key mutation/TTL state, WRONGTYPE preservation and
using returned CAS for a subsequent conditional update. CTest registers both
backends at O0/O2, TLS at O2, and explicit Docker TCP/TLS profiles (20 cases).

```sh
ctest --test-dir build -R '^test_client_read_control_' --output-on-failure -j1
```

See [conditional cache mutations](client-conditional-mutations.md) for the separate
Redis conditional-expiry module and Memcached CAS-protected deletion.
