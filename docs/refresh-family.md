# Single-authority refresh-family rotation

The [refresh endpoint](../examples/jwt-refresh-family.rut) exposes `POST /refresh`
over TLS. It accepts a single Bearer credential, verifies HS256, issuer,
audience, time, the configured subject and the `refresh` scope, then updates the
family on an authoritative Redis 7.2+ instance. It neither accepts access
tokens nor returns one. An access-token issuer, browser session or other
consumer of this profile must complete its own authorization separately.

## Configure and enroll a family

Set `REFRESH_SECRET` to the refresh issuer's dedicated signing key (32–4096
bytes), `REFRESH_ISSUER` to its issuer, `REFRESH_AUDIENCE` to an audience unique
to the family, `REFRESH_SUBJECT` to its subject and `REFRESH_NAMESPACE` to its
own Redis namespace. Use a separate audience and namespace when enrolling a new
family, even for the same subject. Only the trusted owner and this route should
sign refresh credentials for that family. A client cannot select the family,
signing key, or Redis endpoint. Set `REDIS_ENDPOINT`, `REDIS_USERNAME`,
`REDIS_PASSWORD` and `REDIS_DATABASE` as for [online JWT sessions](jwt-sessions.md).
Serve the endpoint using `rut PORT examples/jwt-refresh-family.rut --tls-cert
CERT --tls-key KEY`. Configure verified TLS for the Redis link in deployment.

A trusted owner authenticates the subject and independently creates the initial
signed refresh credential, with a fresh `jti` and the configured claims. It
uses `SET key v1:<digest> NX PX <lifetime-ms>` to enroll exactly once and
confirms that write before delivering the credential. The Redis key is the
configured namespace, a colon and the lowercase hexadecimal SHA-256 of the
configured subject. The digest is the lowercase hexadecimal SHA-256 of the
exact compact token. Limit the Redis account to its configured key space and
the required AUTH/SELECT/EVAL/GET/PTTL/SET/WAITAOF/RESET operations. Keep
Redis ACL credentials and signing keys out of logs.

## Rotation, reuse and uncertainty

A fixed, bounded Redis operation compares the presented token digest with the
current digest and rotates it to the new signed credential in one operation.
It keeps the existing family TTL. A successfully authenticated noncurrent
credential revokes that family. An absent, expired or already revoked family is
never recreated by the route. In a race between two authenticated presentations
of the same current credential, at most one can receive a new token. The other
revokes the family, which can make the returned token unusable.

New credentials have a five-minute JWT lifetime. The existing Redis family
expiry is still the absolute deadline and can be earlier than a token's
expiry. Expired or otherwise invalid JWTs are rejected before Redis I/O. The
route returns 401 for invalid credentials, expired or absent families and
authenticated reuse. Malformed state, Redis errors and failed transport or
cleanup return 503. A 200 response carries the next token with `no-store`, and
requires confirmation of the local AOF write and connection cleanup. A failed
or lost acknowledgement can leave the remote state changed. The route does
not retry, roll back or issue another token in that case.

Use one authoritative Redis instance with AOF enabled, `noeviction` and
storage that honors fsync. The fixture covers local restart, write
uncertainty, duplicate credentials, Redis expiry and concurrent reuse.
Replica failover, older snapshot restoration, access-token invalidation and
browser refresh are outside this profile.
