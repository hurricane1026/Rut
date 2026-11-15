# Redis and Memcached connection diagnostics

These ordinary Rut libraries add bounded diagnostics to the existing TCP/TLS
client surface. They do not authenticate, discover endpoints, reconnect or return
connections to a pool. The caller owns session initialization and cleanup.

## Redis

Import `clients/redis-client.rut` and use an ordinary, non-subscribed RESP2
connection. The APIs return the existing `RedisResult`:

| API | Request and accepted successful reply |
| --- | --- |
| `redisPing(connection)` | PING; exact simple-string `PONG`. |
| `redisEcho(connection, message: Bytes)` | Binary-safe ECHO; a non-null bulk string. |
| `redisInfo(connection, section: Bytes)` | INFO, optionally with one section; a non-null bulk string. Empty section omits the argument. |

`redisBulk(reply)` accesses ECHO/INFO data. INFO remains opaque text: unknown
sections and future fields are not discarded or interpreted. An empty bulk
reply remains distinct from null. Prefer specific INFO sections when the full
report would exceed the frame budget. The pure builders are `resp2PingRequest`,
`resp2EchoRequest` and `resp2InfoRequest`.

Server errors remain `.serverError(Bytes)` and preserve the handle, including
NOAUTH and LOADING. They do not count as a successful health check. Wrong reply
types, an incorrect PONG, trailing data, incomplete framing, transport failure
and read-budget exhaustion close all handle aliases. An invalid encoded request
returns `.requestFailure` before sending and preserves the handle.

```rut
let result = redisInfo(connection, b"server")
```

These reply contracts follow Redis's [PING](https://redis.io/docs/latest/commands/ping/),
[ECHO](https://redis.io/docs/latest/commands/echo/) and
[INFO](https://redis.io/docs/latest/commands/info/) commands. Subscribed-mode PING
arrays and RESP3 events belong to the existing subscription/event APIs.

## Memcached

Import `clients/memcache-info.rut`; it can be used alongside
`clients/memcache-client.rut` on the same ordinary handle. Diagnostics have a
separate codec so existing data-operation imports keep their current size.

- `memcacheVersion(connection)` returns `MemcacheInfoResult.version(Bytes)`.
- `memcacheStats(connection, section)` returns `.stats(MemcacheStats)`.
  `MemcacheStatsSection` has `.general`, `.settings`, `.items` and `.slabs`.
- The other results are `.serverError(Bytes)`, `.transportFailure(i32)` and
  `.replyFailure`. All three close handle aliases, following the existing
  Memcached client convention.

`MemcacheStats` retains the complete invocation-owned `frame: Bytes` and its
record `count: i32`. `memcacheStatsGet(stats, key: Bytes)` revalidates the frame,
count and terminator before returning an optional value. Unknown fields and
values containing spaces are preserved. A present empty value is not missing;
if a server repeats a name, lookup returns its last value. No numeric narrowing
or version-specific field whitelist is applied. VERSION identifiers and STAT
names must be nonempty tokens of at most 250 bytes, excluding spaces, NUL and
ASCII whitespace. Values are opaque bytes without embedded CR/LF.

The pure builders `memcacheVersionRequest()` and `memcacheStatsRequest(section)`
produce exactly one command. STATS publishes only after a complete `END`.
ERROR/CLIENT_ERROR/SERVER_ERROR are accepted only as the entire reply, before
any records. A late error, malformed line, trailing reply or missing terminator
fails closed; a partial statistics report is never returned.

```rut
let result = memcacheStats(connection, MemcacheStatsSection.settings)
```

The line framing follows the pinned
[Memcached text protocol](https://github.com/memcached/memcached/blob/1.6.45/doc/protocol.txt).
Only the four read-only statistics forms listed above are exposed by this API.

## Bounds, ownership and validation

Both protocols retain the 8192-byte request/reply frame limit and four receives,
each with a fixed 1000 ms deadline. STATS admits at most 128 records. Two
sequential 64-step scans use the existing collector limits; no nested collector,
language feature, runtime opcode or dependency is added. Large reports fail
rather than truncating or increasing the transport budget. Late bytes arriving
after a completed reply are subject to the existing ordinary-connection contract;
these diagnostics do not turn a handle into a subscription or pipeline.

Returned data remains valid within the current invocation after later I/O and
close. No command is replayed after an ambiguous transport failure.

`test_client_info.py` uses independent byte peers plus pinned Redis 7.2.11 and
Memcached 1.6.45. Cases cover binary ECHO, empty/unknown fields, 64/128-record
boundaries, exact frame size, split replies, wrong types, errors, trailing data,
EOF/timeout and connection reuse/poisoning. The registered matrix covers both
backends, O0/O2 and verified TLS; gateway source files are removed after startup.
