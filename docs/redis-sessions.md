# Authenticated Redis sessions

[The Redis library](../examples/clients/redis-client.rut) now composes AUTH,
SELECT, GET/SET and acknowledged RESET using the existing Bytes and TCP/TLS APIs.
The runtime remains protocol-neutral; this adds no keyword, opcode, allocator,
network retry or dependency.

## Commands and initialization

| API | Result | Contract |
| --- | --- | --- |
| `resp2AuthRequest(password)` | `Bytes?` | Encode password-only AUTH, including exact empty/binary arguments. |
| `resp2AuthUserRequest(username, password)` | `Bytes?` | Encode ACL username/password AUTH. |
| `resp2SelectRequest(database)` | `Bytes?` | Encode a nonnegative i32 database number in canonical decimal. |
| `resp2ResetRequest()` | `Bytes` | Encode RESET. |
| `redisAuth(connection, password)` | `RedisCommandResult` | Password-only AUTH; require exact simple `OK`. |
| `redisAuthUser(connection, username, password)` | `RedisCommandResult` | ACL AUTH; require exact simple `OK`. |
| `redisSelect(connection, database)` | `RedisCommandResult` | SELECT; require exact simple `OK`. |
| `redisReset(connection)` | `RedisCommandResult` | RESET; require exact simple `RESET`. |
| `redisInitialize(connection, username, password, database)` | `RedisInitializeResult` | Pipeline AUTH and SELECT, validate both replies before returning ready. |
| `redisInitializeDefault(connection, password, database)` | `RedisInitializeResult` | The same initialization using password-only AUTH. |

Builders retain [RESP2 command bounds](resp2-commands.md): at most 8192 bytes,
byte-counted bulk arguments, immutable construction and no truncated publication.
Negative database numbers fail before sending. The server validates its actual
database range and credentials. No request URI, string concatenation or shell
command is used to encode credentials.

`RedisCommandResult` has `.ok`, `.serverError(Bytes)`, `.requestFailure`,
`.transportFailure(i32)` and `.replyFailure`. These state-changing operations
close on every failure, even a complete server error or construction failure.
An unsuccessful AUTH/SELECT must not expose an earlier identity/database through
a reusable handle. Successful operations leave the connection open.

`RedisInitializeResult` has `.ready`, `.authError(Bytes)`,
`.databaseError(Bytes)`, `.requestFailure`, `.transportFailure(i32)` and
`.replyFailure`. Initialization writes only AUTH and SELECT together; it does
not send a business command optimistically. A framed first error is classified
as authentication failure; a framed second error after accepted AUTH is database
failure. Both replies must be complete and consume the received buffer exactly.
Bulk `OK`, integer acknowledgements, aggregates, truncation and already-buffered
trailing replies fail closed. A failure invalidates aliases and closes the lease.

The command behavior follows the Redis [AUTH](https://redis.io/docs/latest/commands/auth/)
and [SELECT](https://redis.io/docs/latest/commands/select/) contracts. This profile
is for standalone Redis logical databases. It does not implement Redis Cluster,
RESP3, Sentinel discovery, transactions or subscriptions.

## A single command with safe pool return

`redisSessionGet(connection, username, password, database, key)` and
`redisSessionSet(connection, username, password, database, key, value)` each:

1. Build and send the two-command initialization, accepting both acknowledgements.
2. Execute one ordinary GET or plain SET with the existing strict reply checks.
3. Send RESET and accept only its exact simple-string acknowledgement.
4. Call `release()` to park a clean transport or discard it if pooling is disabled/full.

The caller obtains the connection with the ordinary fixed endpoint policy:

```rut
let opening = tcp(env("REDIS_ENDPOINT"), 1000)
guard let connection = opening else { return 503 }
let result = redisSessionGet(connection, Bytes(env("REDIS_USERNAME")),
    Bytes(env("REDIS_PASSWORD")), 1, req.bodyBytes)
```

Every lease authenticates and selects its database, including a reused transport.
RESET restores database zero and deauthenticates before the transport can enter
the generic pool. A subsequent generic borrower therefore inherits neither an
identity nor a selected database. This depends on the server's acknowledged
[RESET semantics](https://redis.io/docs/latest/commands/reset/), introduced in
Redis 6.2; deployments which reject RESET cannot use this pooled session profile.
A failed RESET closes instead of returning the connection.

`RedisSessionResult` is a closed variant with:

- `.value(Bytes)`, `.missing` or `.ok` for completed GET/SET outcomes;
- `.authError(Bytes)` or `.databaseError(Bytes)` for initialization rejection;
- `.serverError(Bytes)` for an ordinary GET/SET server error;
- `.requestFailure`, `.transportFailure(i32)` or `.replyFailure` for command failure;
- `.resetError(Bytes)` for server rejection of RESET;
- `.cleanupFailure(i32)` for transport/protocol/release failure during cleanup.

Cleanup failure code zero means reply/protocol failure; nonzero values retain
the network error captured before close. A transport/reply failure during the
business command already closes and skips further I/O. A complete business
server error or unsent request construction failure still performs RESET before
returning that result. Returned values and server-error Bytes remain owned across
cleanup I/O. A normal `release()` rejection with `netError() == 0` means the
transport was discarded safely and does not turn a successful command into an error.

A SET may already have executed when its acknowledgement or cleanup fails.
No failure result authorizes automatic replay. These helpers do not retry.
Low-level AUTH/SELECT users own session cleanup: close the connection or perform
and validate RESET before release; the generic TCP pool cannot infer Redis state.

## Finite work and ownership

Initialization uses a two-node incremental parser and at most two receives.
Status commands and RESET also use at most two receives; GET/SET retain their
existing four-receive budget. Each send/receive has a 1000 ms operation deadline.
No progress extends an individual deadline, and no unbounded loop is introduced.
A reply split over more receives fails closed even when its byte count is small.

The high-level session fits the existing sixteen-operation static profile:

| Component | Maximum statically present operations |
| --- | ---: |
| `tcp()` | 1 |
| Initialization: send + two reads + failure close | 4 |
| GET/SET: send + four reads + failure close | 6 |
| RESET: send + two reads + failure close | 4 |
| `release()` after accepted RESET | 1 |
| Total | 16 |

There is one business command per session helper invocation. For additional
commands, choose explicit operations within the same profile or a future batch
API; the runtime limit has not been raised. The 8 KiB frame/send and saved HTTP
request limits, 256 KiB invocation budget, shard/request token fences and pool
configuration epochs still apply. Raw library records/results are not independent
authorization evidence.

Credentials are ordinary immutable Bytes; configuration from `env()` is resolved
at load/compile time and is embedded in the artifact like existing configured
secrets. Protect those artifacts and use the existing verified TLS endpoint policy
when credentials cross an untrusted network. The library does not log credentials.

See [the HTTP example](../examples/redis-session-client.rut). The example uses
fixed load-time endpoint, username, password and database; request data supplies
only the key/value. It reports backend/session failures without reflecting secret
inputs or Redis errors into the response.

## Verification

`test_redis_sessions.py` uses an independent stateful RESP2 TCP/TLS peer and
byte-level wire oracle. It checks binary credentials/arguments, password-only and
ACL AUTH, SELECT encoding, typed error stages, strict acknowledgement kinds,
fragmented/truncated/trailing replies, deadlines, failure closure, RESET failure
and absence of replay after an executed SET. Physical connection identities and
observed authentication/database state establish cross-request reuse across two
users/databases and deauthentication before a generic borrower. Results survive
subsequent RESET I/O. Source files are removed after startup; sibling nominal
imports and namespace use are covered. CI covers epoll/io_uring at O0/O2 and
verified TLS. This suite uses a protocol fixture. The separate
[general command suite](redis-commands.md) adds pinned real Redis TCP/TLS
interoperability tests; neither suite claims complete Redis-driver support.

Helper-heavy imports used to expand repeated local initializers recursively during
HIR normalization. Profiling the RESP2 command module found about 10.88 million HIR
expressions before the root module was merged, with the largest request helpers
each expanding to about 5.06 million expressions. Normalization now reuses each
successful local initializer expansion within its function, outside scoped
expression bindings. The same module now uses about 1.48 million expressions and
the full session integration test completed in a 14 GiB, no-swap memory cgroup with
a 3.33 GiB peak. The cache does not apply inside `LetIn` or `CollectBytes` binding
scopes. Tests still compile serially to keep peak use predictable. No runtime or
operation budget has been increased.
