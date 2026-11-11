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
