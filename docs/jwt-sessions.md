# Online JWT session permits

The [executable profile](../examples/jwt-session-auth.rut) combines local HS256
verification with a fresh authenticated Redis session-permit lookup for every
request. A token must pass both checks. An unknown, removed or expired permit
cannot fall back to signature verification alone. This is a resource-server
permit profile with trusted fixed-subject issuance/enrollment and self-service
logout endpoints. End-user login, refresh endpoints, cookie sessions and CSRF
protection remain separate.

## Request flow

1. Read only the original singleton `Authorization` field and extract Bearer.
   Missing, empty, duplicate or malformed credentials return 401 with a Bearer
   challenge. Query, body and client identity/status headers supply no fallback.
2. `jwt_session.documentHs256(token, secret, previousSecret, issuer, audience)` pins HS256 and
   applies `jwtClaimsValid`: nonempty subject, exact issuer/audience, mandatory
   future expiry and the existing optional `nbf`/`iat` rules. Invalid tokens
   return 401 before any service connection. Trusted secrets must contain
   32–4096 bytes. Current is mandatory; previous may be empty to disable its
   slot, otherwise it must also contain 32–4096 bytes. Both slots validate before
   token evaluation; an invalid length or empty issuer/audience returns 503.
3. `jwt_session.key(token, namespace)` returns the Bytes key
   `namespace + ":" + lowercase_hex(SHA256(exact_compact_token))`.
   The trusted namespace is 1–128 bytes; empty/oversize configuration or hashing
   failure returns nil, which the example maps to 503. The complete key is at
   most 193 bytes. The raw token, JWT secret and claims are not sent to Redis.
4. Open the fixed configured endpoint and call the existing `redisSessionGet`.
   Each lease authenticates the configured ACL user and selects its database
   before GET. Its acknowledged RESET and release must also succeed before the
   response can permit access. A malformed/negative database becomes a session
   construction failure; the example returns 503.
5. The example's `sessionPermitStatus` maps only `.value(b"active")` to 1,
   missing or other bulk strings to 0, and every infrastructure/result failure
   to -1. `jwt_session.requireActiveStatus` accepts only 1, denies 0 with 401 and
   `Bearer error="invalid_token"`, and maps every other integer to 503 without
   a challenge. A server error, bad reply, timeout, failed AUTH/SELECT/RESET or
   failed release cannot produce an allow, even if GET previously found `active`.
6. `/private` publishes the verified subject only after the permit check;
   projection/storage failure returns 503. The `/read` and `/write` resource
   routes additionally check signed scope before returning a no-store 204.

The helpers are ordinary imported Rut functions. Import the Redis client and
`middleware/jwt_session.rut` directly, as in the example, to stay within the
existing import-depth bound. The typed Redis-result mapper belongs to the
composing route module. Pass only its terminal status to `requireActiveStatus`;
this function cannot authenticate arbitrary caller-supplied integers. Similarly,
`key` hashes bytes and does not itself verify the token. Callers must preserve the
example's authentication-before-lookup and permit-before-publication order.

## Provisioning and revocation ownership

The trusted issuer/session owner enrolls the exact token before handing it to a
client, either through the fixed-subject endpoint below or a separate trusted
control path. Store the ASCII value `active` under the derived key, with a finite TTL
no longer than the token's remaining validity. Redis [SET with expiration](https://redis.io/docs/latest/commands/set/)
can provision this record. The gateway profile reads it through
[GET](https://redis.io/docs/latest/commands/get/). The `/sessions` endpoint below provides one trusted fixed-subject enrollment
path; clients cannot choose arbitrary keys or claims. Restrict the gateway's Redis ACL to its key namespace and
required AUTH/SELECT/GET/SET/DEL/RESET operations.

Deleting the permit revokes that exact compact token for the next authoritative
lookup. A different token needs its own permit, even when issuer, subject and
`jti` match. No `jti` claim is required, and no delimiter parsing of client claims
forms the key. Give each issuer/application a distinct trusted namespace and
keep its signing key, audience, endpoint, database and service credentials in
configuration. `env()` snapshots are embedded in compiled artifacts; provision
and protect those artifacts accordingly.

Missing/evicted records and store loss reject access. Use an authoritative store
and configure its persistence and failover according to the deployment's needs:
a stale replica or restored pre-revocation snapshot may still contain a permit.
The gateway does not establish linearizability across replicas or prevent an
operator from re-enrolling a revoked token. An in-flight request that already
read an active permit can finish; deletion is not an in-flight cancellation
barrier. All nodes must use the intended authoritative policy/service. There is
no local positive cache, offline allow or cross-node invalidation message.

Use verified TLS for Redis across trust boundaries and HTTPS for bearer clients.
The endpoint's existing `tls`, `caFile` and `serverName` controls apply. The
library keeps its existing bounded per-operation deadlines and finite read
budgets; the example's 1000 ms open timeout is not a total request deadline.
There is no command retry. See [Redis session ownership and cleanup](redis-sessions.md).

## Scope authorization for online sessions

| Resource route | Required exact permission | Successful response |
| --- | --- | --- |
| `GET /read` | `orders:read` | Empty 204 with `Cache-Control: no-store` |
| `POST /write` | `orders:write` | Empty 204 with `Cache-Control: no-store` |

These are executable authorization examples; they do not implement an orders
storage backend. Each route first verifies the same JWT signature/claims and
requires an active online permit with successful session cleanup. Only then does
`jwtHasScope` check the signed document. Authenticated, active sessions without
the required grant return 403 plus `Bearer error="insufficient_scope"`.
A missing/revoked permit returns 401 first; a service or cleanup failure returns
503 first. A scope match alone cannot bypass either prerequisite.

Matching uses the existing exact, case-sensitive OAuth scope grammar and
validates the entire granted list. Missing/empty/non-string claims, malformed
suffixes, repeated separator spaces, case/prefix mismatches and invalid array
claims deny authorization. Valid wider or reordered grants can match; duplicate
permission names do not increase privilege. `X-Scope`, query/body scope values,
identity headers and other client metadata never supply grants.

The shipped issuer grants exactly configured `SESSION_SCOPES`. A read-only token
receives 403 on `/write`, including immediately after successful issuance. Loading
wider issuer configuration affects new tokens; existing compact tokens, claims
and permits are not rewritten. Legacy tokens without scope can still use the
identity-only `/private` route but cannot enter the scoped routes. Logout and
key rotation retain the same token/permit identity. The online permit authorizes
the token's continued use and does not independently grant permissions.

## HS256 signing-key rotation

Set `JWT_SECRET` to the mandatory current key and explicitly set
`JWT_PREVIOUS_SECRET` to the previous key or `""` to disable it. These are
compile/load-time snapshots. Every nonempty slot must be 32–4096 bytes;
a malformed previous key rejects verification with 503 even for a current-key
token. An empty current key rejects instead of serving with previous alone.
The `/sessions` issuer also rejects malformed previous configuration, and its
independent `SESSION_ISSUE_KEY` may equal neither signing key.

Both pinned HS256 verifications are evaluated, selecting current when successful
and previous otherwise. Successful decodes own independent request-arena claims
storage. Equal keys are allowed. The wrapper applies the same issuer, audience,
subject and time checks after selection, then performs the online permit lookup.
No token kid, URL, header or client-selected algorithm can change the trusted
key pair. The signature-only `rotatingClaimsHs256` helper is not the complete
resource policy; callers should use `documentHs256` for configuration/claims
validation before consulting permits.

Issuance always uses the current key. An existing old-key token keeps its exact
compact bytes and therefore its existing permit key during the grace period;
there is no re-signing or permit migration. Old-key logout can still delete that
token's permit during the window. After a new configuration removes the previous
key, later requests under that configuration reject old-key tokens before Redis
I/O, even if their permit remains active. New-key tokens and permits continue to
work. Old in-flight readers may finish with their original configuration; removal
is not an immediate cross-node or in-flight cancellation barrier.

For a staged rollout, first distribute old-current/new-previous verification
trust to all relevant nodes while issuance still uses old-current. Then switch
to new-current/old-previous. Retire old-previous after the desired token lifetime
or deliberate revocation cutoff. Nodes that have not adopted the new trust may
reject new tokens; coordinate snapshots through the configuration system. Both
keys must belong to the same issuer/audience trust domain. This profile adds no
key fetch, automatic retirement timer or extra key-store synchronization.

## Trusted fixed-subject issuance and enrollment

`POST /sessions` authenticates an independent trusted service Bearer credential
from the original singleton Authorization field. Configure `SESSION_ISSUE_KEY`
with a 32–4096-byte valid Bearer key, distinct from both `JWT_SECRET` and any
nonempty `JWT_PREVIOUS_SECRET`, and configure
`SESSION_SUBJECT` for the one subject it may mint. Empty/short/malformed or reused
issuer credentials return 503; missing, wrong or duplicate presented fields
return 401 with a Bearer challenge before Redis I/O. Query/body credentials and
identity/claim headers do not select the credential, subject, namespace or TTL.
Both new environment variables must be supplied when loading the example.

Set `SESSION_SCOPES` explicitly to a trusted, nonempty OAuth scope list of at most
1024 bytes, such as `orders:read` or `orders:read orders:write`. The full list must
use ASCII scope tokens separated by one space. Empty, malformed and oversize
lists reject issuance with 503 before service I/O. Request headers/query/body do
not add or choose grants. This load-time variable is required alongside the
existing issuer/subject/signing-key configuration.

The process-shared peer-IP admission rule allows five initial attempts, then
one per twelve seconds. Rejections and failed enrollment consume budget too;
forwarded client-IP headers do not control admission. This credential grants
issuance authority for the configured subject. Keep this endpoint and its key in
the intended trusted control plane and use verified HTTPS.

After authentication, a direct `uuid()` initialization supplies a fresh jti.
`jwt_session.issueHs256(subject, issuer, audience, tokenId, secret, namespace, scopes)`
returns an optional `IssuedSession` containing the compact token, its exact
permit key and decimal signed expiry as Bytes. Its fixed 300-second HS256 profile
contains `sub`, `iss`, `aud`, `iat`, `exp`, `jti` and `scope`. Claim/configuration, entropy,
hash, JSON or bounded-storage failure returns 503 without publishing a token.
The helper decodes its own signed output to obtain the exact expiry; it does not
narrow the timestamp to i32 or sample a second issuance time.

Enrollment authenticates/selects Redis, then issues exactly
`SET <derived-key> active NX EXAT <signed-exp>`. This uses the existing bounded
bulk encoder/byte builder and Redis 6.2+ [SET expiration and NX](https://redis.io/docs/latest/commands/set/)
semantics. The absolute expiry matches the token's signed exp, even if I/O takes
time. NX never overwrites an existing record. Only an exact simple-string OK
counts as an acknowledgement. NX refusal, integer/bulk acknowledgements,
truncation/trailing data and service failures cannot return a token. As with
logout, acknowledged RESET/release is required before success.

A successful response is 200 with the token body, `Content-Type: application/jwt`,
`Cache-Control: no-store` and `Pragma: no-cache`. Signed claims and the permit key
remain the same throughout asynchronous registration and final publication.
A failed acknowledgement or cleanup may leave an orphan permit after an applied
SET; the response still contains no token, no retry or replacement occurs, and
the orphan expires at the original signed expiry. No renewal, extension or
arbitrary-target enrollment endpoint is provided.

This is a trusted issuer profile, not an OAuth grant or end-user password login.
The existing PBKDF2 header-prefix verifier cannot currently be combined with later
network yields at the codegen security boundary. Its check remains unchanged;
this profile does not route around it or claim that a supplied Identity proves
a password check. The separate password/JWT example retains its existing scope.

## Self-service logout

`POST /logout` requires the same locally verified HS256 signature, issuer,
audience and time claims as `/private`. It derives the permit key from the
presented singleton Authorization token only. Query/body tokens and client
identity headers cannot select another permit. Invalid or duplicate credentials
return 401 without opening a service connection. `GET /logout` is not a logout
operation.

The example's `sessionDelete` performs AUTH/SELECT, a single-key
[DEL](https://redis.io/docs/latest/commands/del/), and acknowledged RESET/release.
It reuses the existing RESP2 command builder and bounded scalar reply reader.
Only canonical integer acknowledgements `:0` and `:1` count as success.
`sessionWriteSucceeded` must consume only the fully completed write-session result. Wrong
shapes, noncanonical/negative/oversize counts, malformed replies and trailing
frames invalidate and close the lease. Framed service errors still undergo
cleanup but cannot produce success. Initialization, transport, timeout, RESET
and release failures all return 503, without an authentication challenge.

Success is always an empty 204 with `Cache-Control: no-store`, whether the permit
was removed or already absent. Repeating logout with a still-valid token is
therefore safe; it does not require an active permit first. This endpoint deletes
only that exact token's permit, leaving other tokens for the same subject or jti
untouched. The token must still pass local claims policy, even for an absent
permit. This is a gateway self-service endpoint, not the RFC 7009 AS client or an
OIDC logout/session endpoint.

A 503 can follow an applied delete, such as when the connection dies before its
reply or RESET fails afterward. It does not claim the permit is still active,
and the gateway does not re-enroll or automatically retry the token. A subsequent
explicit logout may complete with the absent-key acknowledgement. A successful
204 means deletion and cleanup were acknowledged by the configured service;
stale replicas, snapshot restoration and already-admitted requests retain the
limitations described above.

## Local-AOF durable logout

`POST /logout-durable` is an opt-in Redis 7.2+ profile for single-instance
persistent exact-token revocation. It applies the same singleton Bearer,
current/previous HS256, issuer/audience and time policy before opening Redis.
The target key and expiry come exclusively from that verified token. The
existing `/logout` endpoint retains its acknowledged-DEL contract.

After AUTH/SELECT, the profile sends a bounded pipeline on the same connection:

```text
SET <exact-token-key> revoked EXAT <signed-exp>
WAITAOF 1 0 500
```

Every invocation writes, including absent permits and repeated logout. A
no-op DEL would not establish a new write offset on this connection. The
`revoked` tombstone prevents an existing `SET NX` enrollment from reactivating
that exact token while it remains valid; fresh online GETs accept only `active`.
The absolute expiration is always the original signed exp, so repeated calls
never extend the retention window. A valid token that expires during I/O can
leave no record; it remains rejected by local claims verification. Redis rejects
non-integral or unsupported expiration values and the endpoint returns 503.

Only an exact simple-string `OK`, followed by a complete two-integer WAITAOF
array with local count 1 and a nonnegative replica count, then acknowledged
RESET/release can return an empty 204 with `Cache-Control: no-store`.
[WAITAOF](https://redis.io/docs/latest/commands/waitaof/) confirms preceding writes
on that connection. This profile requests local AOF only and never treats a
replica acknowledgement as an additional durability guarantee. It reuses the
replay profile's 128-byte/four-receive bounded reader and existing session
cleanup; there is no retry or rollback. Missing AOF, denied commands, capacity,
read-only service roles, malformed/truncated/trailing replies, timeout and
cleanup failures return 503, even when the tombstone was already applied.
Subsequent explicit logout may write and confirm it again.

Use a fixed authoritative instance with AOF enabled, `noeviction`, storage that
honors fsync, and ACL access limited to the configured namespace and required
AUTH/SELECT/GET/SET/WAITAOF/RESET operations (DEL only for legacy logout).
A successful 204 promises local AOF recovery on that instance and retained
storage, subject to its persistence/storage contract. It does not cover stale
replica reads, failover to unconfirmed replicas, restoring an older snapshot,
operator re-enrollment, disk loss or cancellation of already-admitted work.
All gateway resource routes must consult the same authority. The free profile
adds no distributed consensus, replica routing or positive permit cache.
Issuance still acknowledges enrollment and cleanup without a durability barrier;
a lost enrollment fails closed as a missing permit.

The native fault fixture checks both HTTP/1 versions, exact-token isolation,
present/absent/repeated logout, signed-exp retention, authentication-before-I/O,
write/barrier/cleanup error handling and delayed confirmation. The pinned Redis
fixture checks SIGKILL/AOF recovery, gateway reload, other-token continuity,
tombstone expiry, ACL denial, capacity, read-only role and disabled AOF. Both
backends, O0/O2 wire tests and verified TLS service tests are registered. These
single-instance tests do not establish replication/failover consistency.

## Validation scope

The JIT test uses the example's real typed mapper to cover every
`RedisSessionResult` variant, invalid terminal statuses, exact permit markers,
SHA-256 key bytes and namespace limits including UTF-8 byte counts.

Registered native HTTP tests run on epoll and io_uring at O0/O2, with additional
verified TLS service runs. An independent RESP2 peer checks the actual
AUTH/SELECT/GET-or-DEL-or-SET/RESET sequence. The source and imported files are removed after
native loading. Both HTTP/1 versions exercise valid permits, deletion/re-enrollment,
same-subject/same-jti distinct-token isolation, missing/noncanonical markers,
signature/issuer/audience/expiry failures without service I/O, duplicate
Authorization and valid-token query/body non-fallback. Service errors, malformed
and fragmented replies, timeout, reset failure, lost permits and complete service
outage are tested. Logout tests cover present/absent repeated calls, 204/no-store,
wrong method, valid alternate tokens in query/body, other-permit isolation,
invalid credentials without I/O, canonical single-key counts, lease poisoning
and ambiguous deletion failures. Issuance tests independently verify HS256 claims,
UUID jti, signed trusted scope, exact EXAT/key agreement, distinct tokens, the issuance/access/logout
flow, NX refusal, no-token-on-error, malformed SET acknowledgements and the
shipped five-attempt admission rule. Fault cases use distinct actual loopback
peer IPs rather than modifying that production rule. Rotation tests use sequential
native configuration snapshots sharing the same permit store: old-key access and
logout during grace, current-only signing, old-key rejection before service I/O
after retirement, mandatory current, malformed previous and issuer-key separation.
Scoped-resource cases cover both HTTP/1 versions, read/write separation, missing
and malformed grant shapes, whole-list validation, permission spoofing, revoked
permits and service/cleanup failure precedence. Key-grace snapshots preserve
these checks, and invalid configured issuer scopes fail before any service I/O.
Each snapshot removes its source files after loading. This checks configuration
semantics, not in-process RCU publication or multi-node rollout. This fixture does not replace validation of a deployment's
Redis server persistence, ACL policy, replication or failover.
