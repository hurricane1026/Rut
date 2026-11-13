# Authenticated message replay claims

[webhook-replay-auth.rut](../examples/webhook-replay-auth.rut) composes the existing
Standard Webhooks v1 signature/freshness verifier with an authenticated Redis
atomic claim. [signed-request-replay-auth.rut](../examples/signed-request-replay-auth.rut)
provides the same claim lifecycle for the existing fixed HMAC-SHA256 signed-request
profile. These are free authentication foundations (#1076), not a managed event
queue or business transaction engine.

Only authenticate first, then call `replay.key` and `redisReplayClaim`. Invalid
signatures, stale/future timestamps, duplicate singleton fields and unsupported
framing never reach the claim store. The Standard Webhooks key is the SHA-256 of
its signed event ID under a trusted signer/profile namespace. Changing the body,
timestamp or signing key cannot re-admit the same event ID. Keep this namespace
stable across key rotation; configure a different one for independent signers.
The gateway exposes no secret-bearing store key.

The signed-request profile lacks a separate nonce. It uses a trusted fixed-POST
namespace and an unambiguous authenticated target/Date/Digest tuple. Changing
Authorization parameter order does not change its key; body/method/target/date
changes describe another signed request. This prevents exact signed-request replay,
not repeated business operations deliberately signed with a fresh timestamp.
Other methods need independent namespaces and method binding.

## Claim and failure contract

`SET key claimed NX EX 601` is one atomic operation on a single authoritative
Redis service. One concurrent request may obtain `OK`; null bulk means an existing
claim. No GET-then-SET race, positive cache, eviction fallback or retry is used.
Every session must finish AUTH/SELECT, the claim, and acknowledged RESET/release
before reporting success. Status 1 means admitted, 0 means duplicate, -1 means any
service, parsing, transport or cleanup uncertainty. The policy maps these to
204, 409 and 503. An integer, aggregate, extra reply, failed initialization or
cleanup never becomes success. Damaged connections are discarded.

The existing verifiers accept at most 300 seconds past/future skew. Retaining a
claim for 601 seconds after admission covers the entire remaining freshness
window, including an initially future-dated message. This requires bounded,
non-adversarial gateway/store clocks; arbitrary backwards clock steps or manual
claim removal invalidate that retention guarantee. There is no promise to fix
clock rollback with a TTL or to reject reuse of an ID forever after expiration.

Claim occurs before side effects. A failed cleanup, disconnect or crash after
SET may retain a claim even though no business action ran. Fail closed, do not
retry automatically, and do not delete the claim to compensate: that could permit
a concurrent replay. This is admission at most once within retention, **not
exactly-once business delivery**. Operators must provision an authoritative store
with no live-key eviction, suitable persistence, and defined failover/rollback
semantics; Redis loss or a stale replica is not durable replay protection.

Use a verified TLS endpoint in deployment. The fixture covers service TLS and
both gateway backends, concurrent requests across two shards, retained claims
across gateway restart, authentication failures, malformed replies, timeout,
applied-but-unacknowledged writes and cleanup failure. Native artifacts execute
after source/module deletion. Claim-store restart/persistence/failover guarantees
belong to the configured service, not an in-memory gateway Cache.

## Confirmed local AOF profile

`redisReplayDurableClaim(connection, username, password, database, key) -> i32`
adds an opt-in local persistence boundary. It uses the same authentication,
database selection, identity key and 601-second claim as `redisReplayClaim`, then
requires acknowledged RESET/release before returning the same 1/0/-1 statuses.
Use [webhook-durable-replay-auth.rut](../examples/webhook-durable-replay-auth.rut)
or [signed-request-durable-replay-auth.rut](../examples/signed-request-durable-replay-auth.rut).
The ordinary profile remains available with its original contract.

The trusted endpoint must be Redis 7.2 or newer, with local AOF enabled, no
live-key eviction and an ACL permitting AUTH, SELECT, SET and WAITAOF. RESET
must remain available for acknowledged cleanup.
Use verified TLS for deployed service connections. The module introduces no new
library, protocol opcode or language syntax; it composes the existing RESP2,
Bytes, bounded collection and TCP/TLS primitives.

After successful initialization, one bounded send contains two sequential
commands on the **same physical connection**, outside MULTI:

```text
SET <identity-key> claimed NX EX 601
WAITAOF 1 0 500
```

The [Redis WAITAOF contract](https://redis.io/docs/latest/commands/waitaof/)
confirms preceding writes from this connection have been fsynced to local AOF.
The 500 ms server wait is finite and stays below each 1000 ms client I/O deadline.
The pinned deployment uses `appendfsync always`. An `everysec`/disabled fsync
policy can exhaust this wait and leave a claimed message with a 503 result;
there is no automatic retry or weaker durability fallback.
Both complete replies must fit 128 bytes and four RESP nodes: one exact SET
`OK`/null-bulk result, one two-element array, and its integer children. The local
count must be exactly 1 and the replica count nonnegative. The client consumes
at most four receives and rejects trailing frames, wrong types/counts, truncated
replies and negative/overflowing acknowledgement counts. This fits the existing
sixteen-I/O initialization/business/cleanup profile without extra round trips.

A timeout count of zero, unavailable/unsupported WAITAOF, disabled AOF, read-only
role, store capacity failure, malformed reply, transport failure or failed cleanup
returns -1/503. There is no downgrade to the ordinary profile. Even a duplicate
requires a successful barrier and cleanup before returning 0/409. A SET may have
applied before any of these failures: keep its claim, do not compensate with DEL,
and do not automatically retry. A held barrier cannot publish 204 before its reply;
successful barrier confirmation alone cannot bypass a failed RESET.

The tested recovery boundary is a **single authoritative instance and its intact
AOF volume**, with normal clocks and no live-key eviction. Pinned Redis 7.2.11
fixtures force SIGKILL after acknowledged admission, restart the same container
and volume, verify the claim and decreasing original TTL, and reject the message
through the still-running gateway and after gateway restart. Both Linux backends,
HTTP/1 and HTTP/2, and verified service TLS are exercised. Independent wire peers
also cover partial/lost acknowledgements, concurrency, permission/shape/timeouts
and cleanup uncertainty; source/modules are removed after native loading. An
isolated real instance with RESET disabled verifies 503 after fsync and retention
of that uncertain claim across SIGKILL/recovery without renewing its TTL.

The helper does not inspect or lock the server's eviction configuration. Local
fsync confirmation does not fence a stale promoted replica, prevent an operator
from restoring old state, preserve a lost/corrupt volume or repair clock rollback.
Replica durability, distributed failover and exactly-once business delivery are
not established by `WAITAOF 1 0 500`; they remain explicit deployment contracts.
