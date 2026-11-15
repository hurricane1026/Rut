# Authenticated Redis RESP3 and Memcached sessions

These are ordinary source-library helpers over the existing TCP/verified TLS
client. Endpoints and session ownership remain explicit. Authentication does not
add endpoint discovery, reconnection or automatic command replay.

## Redis HELLO 3 with AUTH and SETNAME

Import `clients/redis-resp3.rut`:

```rut
let result = redisHello3Auth(connection, username, password,
    RedisClientName.value(b"cache-reader"))
```

`resp2Hello3AuthRequest(username, password, name)` builds a single RESP2-encoded
`HELLO 3 AUTH username password`, optionally followed by `SETNAME name`.
Credentials and names are binary-safe arguments. `RedisClientName.unchanged`
omits SETNAME; `.value(Bytes)` includes it, including an empty name to clear it.
The whole request must fit in 8192 bytes. An encoding failure returns
`.requestFailure` before sending and preserves the handle.

`redisHello3Auth` returns the existing `RedisResp3Result`. Success requires the
existing strict HELLO contract: a complete map with exactly one top-level integer
`proto: 3`, with no pending Push or trailing frame. Each handshake sends once and
uses at most two fixed-deadline receives. A protocol mismatch, refused
credentials/name, unsupported HELLO, EOF, timeout or malformed reply closes
aliases. There is no separate AUTH command, retry or silent RESP2 fallback.
Errors remain `.serverError(RedisResp3Event)` rather than being called successful
authentication. The event frame remains valid after later I/O within the same
invocation.

This follows Redis's [HELLO contract](https://redis.io/docs/latest/commands/hello/),
which supports AUTH/SETNAME from Redis 6.0. Use an ordinary non-subscribed handle.
After success, the connection carries authenticated RESP3 state; it must be
closed or explicitly reset/deauthenticated before reuse by a generic RESP2
borrower. This low-level helper never implicitly releases it into a pool.

## Memcached text-token authentication

Import `clients/memcache-auth.rut`. This targets the optional basic-text `-Y`
mode in pinned Memcached 1.6.45, not binary SASL or a meta-protocol extension.
When combining client modules with overlapping codec exports, use namespace
aliases as in the [batch composition example](client-invalidation.md).

The [text authentication protocol](https://github.com/memcached/memcached/blob/1.6.45/doc/protocol.txt)
uses a fake SET whose payload is `username password`. On an ordinary Memcached
server that same request would store the payload. Therefore
`memcacheAuthenticate(connection, username, password)` performs this sequence:

1. Validate and build the complete credential request before any network I/O.
2. Send VERSION without credentials and require the exact complete
   `CLIENT_ERROR unauthenticated` challenge on this connection.
3. Send the credential request only after that challenge; require exact STORED.

An ordinary server's VERSION response, an already authenticated connection,
another error, wrong acknowledgement or extra/truncated challenge is refused
before sending credentials. The gate checks `-Y` behavior on a fresh connection;
endpoint identity still comes from the configured TLS policy. The library does
not probe and then fall back to an ordinary SET or binary authentication.

The result is `MemcacheAuthResult`:

- `.authenticated`: the exact challenge and acknowledgement were consumed.
- `.requestFailure`: invalid credentials/encoding; sends nothing and preserves
  the provided handle.
- `.challengeFailure`: the expected unauthenticated state was not established.
- `.rejected(Bytes)`: the authentication request received a validated server error.
- `.transportFailure(i32)` or `.replyFailure`.

Every failure after I/O closes aliases. Each stage has two receives, each with a
1000 ms deadline; the request/reply bound remains 8192 bytes. The reserved fake
SET key is `__rut_auth`, with zero flags and expiry. It is ignored by `-Y`
authentication; a normal server is never sent this credential payload.
`memcacheAuthRequest` is exposed for inspecting the encoded bytes, not as a safe
standalone command to send to an unverified cache endpoint.

Usernames follow the existing Memcached key-token profile: 1–250 bytes without
ASCII whitespace, controls or DEL. Passwords are 1–4096 bytes, may contain spaces
and colons, and reject NUL/CR/LF. They are not logged or reflected by the library.
Like existing configured secrets, credential literals/load-time env values are
embedded in generated artifacts; use the existing verified TLS endpoint policy
for transport identity/confidentiality.

## Close-after-use Memcached GET/SET sessions

The text protocol provides no deauthentication/reset operation. The safe
conveniences therefore always close their supplied connection, including on
validation, authentication, business-command or transport failures:

- `memcacheSessionGet(connection, username, password, key)`.
- `memcacheSessionSet(connection, username, password, key, value, settings)`;
  settings use the existing `MemcacheOptions` relative-TTL profile.

They return `MemcacheAuthSessionResult`: `.value(MemcacheItem)`, `.missing`,
`.stored`, `.notStored`, `.authError(Bytes)`, `.serverError(Bytes)`,
`.challengeFailure`, `.requestFailure`, `.transportFailure(i32)` or
`.replyFailure`. A miss is distinct from an empty binary value. Business requests
are validated before authentication, so an invalid key cannot send credentials.
Returned values survive the final close within the invocation.

After authentication each session sends exactly one GET or SET and consumes at
most four business-reply receives. The complete session remains within the
existing sixteen-operation profile; no runtime limits are increased. A SET may
have applied before its reply is lost; the session closes and never replays it.
These wrappers never return an authenticated connection to the generic pool.
Low-level `memcacheAuthenticate` callers must also close after use, rather than
release authenticated state to an ordinary borrower.

## Verification

`test_client_auth.py` uses independent TCP/TLS peers and pinned Redis 7.2.11 and
Memcached 1.6.45. It covers canonical/binary HELLO arguments, name omission and
clearing, strict protocol confirmation, bad credentials/acknowledgements, split
and trailing replies, EOF/timeout, challenge gating, invalid requests before I/O,
missing/binary GET values and an executed SET with a lost reply and no replay.
Live tests cover ACL-authenticated RESP3, `-Y` GET/SET, unchanged reserved cache
items, refusal of repeat authentication before another credential SET, and refusal of ordinary cache endpoints without creating a credential
item. Pool-enabled endpoint tests verify that anonymous borrowers remain
unauthenticated after session close. Gateway source/import files are removed
after startup. The CMake matrix covers both backends, O0/O2 and verified TLS.
