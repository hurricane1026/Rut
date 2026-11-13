# General Redis commands and SET options

The ordinary [Redis client library](../examples/clients/redis-client.rut) supports
one-command RESP2 execution, integer key commands and conditional/expiring SET.
It builds on the [request encoder](resp2-commands.md), [incremental decoder](resp2-streaming.md)
and [authenticated session helpers](redis-sessions.md). There are no new language
keywords, runtime protocol handlers or linked dependencies.

## Commands and results

| API | Contract |
| --- | --- |
| `redisExecute(connection, request)` | Send exactly one encoded command, consume exactly one complete RESP2 value. |
| `redisDel`, `redisExists`, `redisTtl`, `redisPttl`, `redisIncr`, `redisDecr` | `(connection, key)`; require an integer response. |
| `redisExpire(connection, key, seconds)` | Signed i32 seconds; zero/negative values retain Redis's immediate-deletion behavior. |
| `redisPexpire(connection, key, milliseconds)` | Signed i32 milliseconds; require an integer response. |
| `redisSetWithOptions(connection, key, value, condition, expiry)` | Require exact simple `OK` or null bulk for an unmet condition. |
| `redisSetGet(connection, key, value, condition, expiry)` | Atomically SET and return the previous string with a typed write outcome. |

General and integer commands return `RedisResult`: `.reply(RedisReply)`,
`.serverError(Bytes)`, `.requestFailure`, `.transportFailure(i32)` or
`.replyFailure`. `RedisReply` retains the invocation-owned `frame` and typed
`root: Resp2Token`. The response remains valid after subsequent I/O or close.

`redisInteger(reply)` returns an inferred signed i64 optional, without narrowing.
`redisBulk(reply)` accepts only bulk strings, preserving empty values separately
from null. `redisValues(reply)` returns `Collected<Resp2Token>?`, a preorder tree
of at most 64 nodes; array nodes give their direct `children` count. Nested server
errors are tree nodes; a top-level error is `.serverError`. Token kinds follow
the [decoder contract](bounded-parsing.md): simple/error/integer/bulk/array/null
bulk/null array are distinct. Integer spelling is validated before publication.

This permits commands such as MGET, HGETALL and EVAL through the generic encoder
without adding a dedicated wrapper for each command. Aggregate traversal remains
explicit and bounded; there are no general source loops or recursive values.

## SET choices

`RedisSetCondition` has `.always`, `.absent` (NX) and `.present` (XX).
`RedisSetExpiry` has `.none`, `.seconds(i32)` (EX), `.milliseconds(i32)` (PX),
`.unixSeconds(Bytes)` (EXAT), `.unixMilliseconds(Bytes)` (PXAT)
and `.keepTtl` (KEEPTTL). `.keepTtl` preserves the existing expiration when
replacing a value; a new key or an already persistent key remains persistent.
It works with all three conditions and requires Redis 6.0 or later. `.none`
uses ordinary SET semantics, removing any existing expiration on a successful
write. EX/PX must be positive, up to i32 maximum. Contradictory conditions or
expiration modes cannot be represented.

Absolute timestamps use decimal Bytes, preserving values beyond i32 without
adding a language numeric type. EXAT accepts `1...9223372036854775` seconds;
PXAT accepts `1...9223372036854775807` milliseconds. EXAT's upper bound prevents
overflow when Redis converts seconds to milliseconds. Leading zeros are
canonicalized; signs, malformed decimals, zero and out-of-range values fail
before I/O. Positive timestamps in the past retain Redis's immediate-expiration
behavior. Both modes require Redis 6.2 or later and work with SET GET and all
three conditions. The client does not read a local clock or retry a write.

`resp2SetOptionsRequest(key, value, condition, expiry)` builds the request without
I/O. Arguments are binary-safe.

```rut
redisSetWithOptions(connection, key, value,
    RedisSetCondition.present, RedisSetExpiry.keepTtl)
```

`RedisSetOptionsResult` has `.ok`, `.notSet`, `.serverError(Bytes)`,
`.requestFailure`, `.transportFailure(i32)` and `.replyFailure`. A Redis null
bulk response maps to `.notSet`; it is an ordinary conditional-write outcome.
Plain `redisSet` retains its existing result and exact acknowledgement contract.
The expiration and conditional semantics follow Redis's
[SET contract](https://redis.io/docs/latest/commands/set/); TTL preserves the
[-1/-2 sentinels](https://redis.io/docs/latest/commands/ttl/) and counters preserve
signed 64-bit results and server overflow errors. Newer server-specific
conditions have no dedicated wrapper in this profile.

## Atomic SET with the previous value

`resp2SetGetRequest(key, value, condition, expiry)` encodes SET GET with the same
closed condition/expiry choices and 8192-byte limit. `redisSetGet` sends that
single command and returns `RedisSetGetResult`:

- `.stored(RedisSetPrevious)`: the new value was written.
- `.notStored(RedisSetPrevious)`: NX or XX rejected the write.
- `.serverError(Bytes)`, `.requestFailure`, `.transportFailure(i32)`,
  `.replyFailure`: retain the ordinary failure distinctions.

`RedisSetPrevious` has `found: bool` and invocation-owned `data: Bytes`.
`found == false` has empty data and means the key was missing before the command;
`found == true` with empty data means the previous string was empty. Data remains
valid after later I/O and connection close.

| Condition | Previous key missing | Previous string present |
| --- | --- | --- |
| `.always` | `.stored`, `found == false` | `.stored`, `found == true` |
| `.absent` (NX) | `.stored`, `found == false` | `.notStored`, `found == true` |
| `.present` (XX) | `.notStored`, `found == false` | `.stored`, `found == true` |

Redis returns the old value even when NX rejects the write. A null bulk is
therefore interpreted using the condition, rather than treated as failure.
WRONGTYPE from a non-string previous value is a server error and the key remains
unchanged, including with NX. Conditional rejection also preserves the value and
expiration. On a successful write, `.none` removes expiration, EX/PX replace it,
and `.keepTtl` preserves it. These follow the linked Redis SET contract.

SET GET requires Redis 6.2 or later; NX with GET requires Redis 7.0 or later.
The library does not probe server versions or fall back to separate GET/SET
commands. It accepts only bulk/null-bulk replies: even simple `OK` is a protocol
contract failure and closes the connection. Framed server errors leave the
connection usable. Transport/protocol failures close it, with no automatic retry.
The existing `redisSet` and `redisSetWithOptions` result types are unchanged.
Applications composing several client modules can use selective imports to
retain room within the existing function budget:

```rut
import { redisSetGet, RedisSetGetResult, RedisSetPrevious, RedisSetCondition, RedisSetExpiry } from "clients/redis-client.rut"
```

## Bounds and connection ownership

Requests must be flat, nonempty arrays containing 1–63 non-null bulk arguments,
including the command name, within 8192 bytes. `redisExecute` validates actual
bytes before sending; malformed, nested, truncated or concatenated commands fail
without writing. The generic `Resp2Command` builder remains usable, but public
record fields alone are not trusted as proof of framing.

Responses are limited to 8192 bytes, 64 total nodes and four receives, each with
a 1000 ms deadline. These are explicit finite budgets, not a total four-second
wall-clock deadline. EOF, malformed/truncated frames, trailing data, node/byte
overflow or exhausted reads close the handle. Transport errors are captured
before close. Invalid requests preserve the connection, and framed server errors
leave it usable. Integer/SET wrappers also close on an unexpected response kind.
There is no automatic command retry, including after a write may have executed.
Scalar wrappers use the existing one-node feed path; generic arrays retain the
full 64-node path. No parser, arena, verifier or I/O budget is increased.

The generic executor does not infer command side effects. Callers must close
after arbitrary state-changing commands, or perform command-appropriate cleanup
before release. In particular, AUTH, SELECT, transactions, WATCH, Pub/Sub and
protocol mode changes cannot be treated as stateless pool operations. Prefer the
existing authenticated session helpers for pooled GET/SET. The single-command
executor does not batch commands; the separate [pipeline module](redis-pipeline.md)
supports finite batches. Transaction handling, subscription streams,
Cluster redirects, Sentinel discovery, RESP3, reconnect and retry policy remain
outside this profile; the separate [advanced modules](redis-advanced.md) provide
bounded transactions, subscriptions, RESP3 events, configured Cluster/Sentinel
routing and explicit recovery decisions. Some
commands cannot fit these finite request/reply/read budgets. This remains a
bounded standalone Redis client, not a complete Redis driver.

## Verification

`test_redis_commands.py` checks strict framing, nested arrays and errors, all
signed integer boundaries, 64-node limits, fragmentation, EOF/deadlines, no replay,
failure closure through handle aliases, request rejection before I/O and server
error recovery against an independent byte-level peer. It checks all twelve
condition/expiry encodings, invalid expiration bounds and bounded KEEPTTL framing.
Source removal after startup and O2 namespace imports check ownership and nominal
type relocation.
CTest registers epoll/io_uring at O0/O2 and verified TLS.

The `docker`-labelled live tests use the immutable official Redis 7.2.11 Alpine
manifest recorded in the test, with an ephemeral container, loopback-only port,
no persistence and no host Redis installation or Python Redis package. They
verify SET conditions and expirations, exact preservation of expiration timestamps
with KEEPTTL (including conditional rejection and persistent/missing keys), TTL
sentinels, key commands, counter overflow, binary MGET, nested Lua replies, ACL
authentication, database selection and RESET before pool return over TCP and TLS. TLS uses the
existing fixture certificate files, without an OpenSSL CLI. The normal CI
selection excludes Docker-labelled tests; run them explicitly with:

```sh
ctest --test-dir build -R '^test_redis_commands_live_' --output-on-failure -j1
```

Individual live runs can also use:

```sh
python3 tests/test_redis_commands.py --server build/src/rut \
  --library examples/clients --backend epoll --opt 2 --real-redis
```

These tests are intentionally serial because helper/collector expansion makes
compiler memory use significant.

`test_redis_set_get.py` reuses the same gateway and pinned Redis harness with a
focused program. Its independent wire peer covers all condition/previous-value
outcomes, binary/empty/null replies, fragmented and maximum-size replies,
unexpected reply kinds, truncation, trailing data, EOF/deadlines, no replay and
failure closure. Encoders cover all twelve option combinations and both sides of
the request byte bound. The four live TCP/TLS/backend configurations each check
48 condition/expiry/previous-state combinations, twelve WRONGTYPE combinations,
binary keys and exact expiration timestamps. Replies are inspected after another
receive and close. CTest registers epoll/io_uring at O0/O2 and TLS, plus explicitly
selected `docker`-labelled live runs:

```sh
ctest --test-dir build -R '^test_redis_set_get_' --output-on-failure -j1
```

The focused `test_client_expiry.py` cases verify EXAT/PXAT decimal and overflow
boundaries, all NX/XX/GET combinations, exact request-size bounds, invalid
requests before I/O and EOF/timeout without write replay. Pinned Redis 7.2.11
checks actual expiry times and the largest timestamps over TCP and verified TLS
on both transport backends.
