# Conditional cache mutations

These source helpers add atomic conditions to expiry updates and deletion. They
use the existing TCP/TLS transport and introduce no language or runtime changes.

## Redis conditional expiry

Import `redis-expiry.rut`:

```swift
let extended = redisExpireWithCondition(connection, key, 60, RedisExpireCondition.longer)
let shortened = redisPexpireWithCondition(connection, key, 5000, RedisExpireCondition.hasExpiryShorter)
```

`RedisExpireResult` distinguishes `applied`, `notApplied`, `serverError(Bytes)`,
`requestFailure`, `transportFailure(i32)` and `replyFailure`. Only an integer 1
is applied and 0 is notApplied; other integers and response types are protocol
failures. A missing key also returns notApplied.

`RedisExpireCondition` covers these wire conditions:

| Source option | Wire | Condition |
| --- | --- | --- |
| `always` | no extra arguments | No expiry condition |
| `noExpiry` | NX | Key has no expiry |
| `hasExpiry` | XX | Key has an expiry |
| `longer` | GT | New deadline is later |
| `shorter` | LT | New deadline is earlier |
| `hasExpiryLonger` | XX GT | Existing expiry and later deadline |
| `hasExpiryShorter` | XX LT | Existing expiry and earlier deadline |

NX/XX here concern the expiry, not just whether the key exists. A persistent key
is treated as having an infinite deadline for GT/LT. Incompatible combinations
cannot be represented. The implementation follows the
[Redis 7.2.11 condition checks](https://github.com/redis/redis/blob/7.2.11/src/expire.c#L459);
conditional options require Redis 7 or later.

Durations are signed i32 seconds or milliseconds. Zero and negative values retain
Redis's conditional immediate-deletion behavior. In particular GT may reject a
nonpositive duration while LT accepts it; the client sends the duration and
condition together, without a prior TTL lookup. Keys are binary-safe. Expiry
works for all Redis value types and does not inspect or replace their contents.
`resp2ExpireRequest(key, amount, milliseconds, condition)` is the same bounded
encoder without I/O.

The standalone module avoids increasing the base client's per-file token budget
or import depth. When composing it with the base client, use namespace imports:

```swift
import * as cache from "redis-client.rut"
import * as expiry from "redis-expiry.rut"
```

Use `expiry.RedisExpireCondition` with `expiry.redisExpireWithCondition` or
`expiry.redisPexpireWithCondition`. Existing `cache.redisExpire` and
`cache.redisPexpire` keep their original `RedisResult` contract.

## Memcached CAS-protected deletion

Import `memcache-meta.rut`. After a successful metadata GET or basic `gets`, pass
the returned CAS token to `memcacheDeleteCas(connection, key, cas)`:

```swift
let result = memcacheDeleteCas(connection, key, expectedCas)
```

`MemcacheDeleteCasResult` returns `deleted`, `exists` (CAS mismatch), `missing`,
`serverError(Bytes)`, `requestFailure`, `transportFailure(i32)` or `replyFailure`.
A stale token cannot remove a newer item. Deletion is one server-side command;
there is no client-side GET-then-unconditional-DELETE emulation.

`memcacheDeleteCasRequest(key, cas)` sends exactly `md <key> C<cas>`. It validates
basic-text keys (1..250 bytes, no spaces/control characters) and unsigned-64-bit
decimal CAS bytes without narrowing. No quiet, stale-marking or tombstone flags
are sent. Only exact HD, EX and NF lines are admitted as normal outcomes. Extra
flags, values, trailing replies and basic-text DELETED are rejected. GET and
DELETE have separate parsers while sharing bounded transport reads; neither can
accept the other operation's success frame.

The command profile is checked against the
[pinned Memcached 1.6.45 protocol](https://github.com/memcached/memcached/blob/1.6.45/doc/protocol.txt#meta-delete).
CAS tokens identify versions observed at the server; caller ownership and
cross-key business coordination remain explicit.

## Transport and failure contract

Both helpers send once and consume one complete reply within 8192 bytes, at most
four receives and 1000 ms per I/O operation. Arguments are validated before send.
Local request rejection preserves a clean handle. Transport or protocol failure
closes the handle and invalidates aliases. Redis's fully framed server error
leaves its handle usable; Memcached conservatively closes on server errors.
Ordinary condition rejection and key absence leave the handle usable.

No failure automatically retries a mutation. An EOF or timeout can follow an
applied change, so it does not prove the key or expiry remained unchanged. Reply
bytes remain valid after another receive and close. Authentication, pooling and
lease cleanup retain their existing explicit policies; these helpers do not
infer session identity or implicitly release a connection.

## Validation

`test_client_conditional.py` checks encoders (all seven Redis conditions, both
units and i32 endpoints; binary keys; exact frame bound; full-width CAS),
independent peers (fragmentation, rejected conditions, missing keys, server
errors, invalid integers, wrong-operation frames, trailing replies, EOF,
timeouts, invalidated aliases and no replay), and pinned real services.

Redis live tests compare 168 expiry operations against an independent server
command in equivalent key states, including persistent/volatile/missing keys,
shorter/longer durations, and zero/negative deletion. Memcached live tests update
an item after taking a CAS snapshot, prove stale-token rejection preserves the
replacement, then delete with the current token. They also compose metadata GET
and conditional deletion on the same connection through ordinary Rut helpers.
CTest registers 20 cases across both backends, O0/O2, TCP/TLS and Docker profiles,
plus a namespace-composition regression with the base Redis client.

```sh
ctest --test-dir build -R '^test_client_conditional_' --output-on-failure -j1
```
