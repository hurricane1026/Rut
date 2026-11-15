# Ordered and conditional cache reads

These ordinary source libraries extend the existing Redis and Memcached clients
without new runtime operations, dependencies or language syntax.

## Redis MGET

Import `redis-mget.rut`. Build one to eight keys with the existing immutable
`redisKeys()` / `redisKeysAdd(keys, key)` helpers, then call
`redisMget(connection, keys)`. For example, after opening a connection:

```swift
guard let first = redisKeysAdd(redisKeys(), b"first") else { nil }
guard let keys = redisKeysAdd(first, b"second") else { nil }
let result = redisMget(connection, keys)
```

`RedisMgetResult` returns `reply(RedisMgetReply)`, `serverError(Bytes)`,
`requestFailure`, `transportFailure(i32)` or `replyFailure`. A successful reply
retains the complete invocation-owned `frame` and key `count`. Access a position
with `redisMgetItem(reply, index) -> RedisMgetItem?`:

- `found == true` with binary `data`, including an empty string.
- `found == false` with empty `data` for a missing or non-string key.
- `nil` for an invalid index or a forged/inconsistent public reply object.

Positions follow the request order. Duplicate and empty binary keys are allowed;
a duplicate consumes another one of the eight positions. A non-string key maps
to missing at that position, following the
[Redis MGET contract](https://redis.io/docs/latest/commands/mget/). It does not
produce the single-key GET WRONGTYPE error.

The complete array is validated before publication: exactly the expected number
of children, each a bulk string or null bulk, with no nesting, nested errors,
truncation or trailing data. The accessor revalidates the entire public frame,
including elements after the selected index. `redisMgetRequest(keys)` validates
public key-builder counts and every encoded key before building one MGET;
null/nested/non-bulk key arguments and bytes after the final argument are rejected.

Requests and complete replies are each bounded to 8192 bytes. The reader handles
at most nine RESP nodes (root plus eight values) per feed and four receives,
with 1000 ms per operation. A locally rejected request preserves a clean handle;
transport/protocol failure closes it. A fully framed server error preserves
framing and leaves the handle usable. There is no automatic retry, sharding,
cluster redirection, cross-slot splitting or partial-result publication. Cluster
errors remain ordinary server errors.

Use namespace imports when composing with the base client, and build the keys
through the MGET namespace:

```swift
import * as cache from "redis-client.rut"
import * as multi from "redis-mget.rut"
```

The generic `cache.redisExecute` remains available for other aggregate commands.
This module provides a narrower, ordered string/missing result contract.

## Memcached retrieval conditional on CAS

Import `memcache-meta.rut` and call
`memcacheGetCas(connection, key, knownCas)`. Here `knownCas` is the version whose
value the caller already holds; ordinary `memcacheMetaGet` or `memcacheGets`
can obtain an initial version. The request is `mg <key> v f c t C<knownCas>`.
`memcacheGetCasRequest(key, knownCas)` exposes the same encoder without I/O.

`MemcacheGetCasResult` distinguishes:

| Outcome | Meaning |
| --- | --- |
| `value(MemcacheMetaItem)` | The version differs; the complete current value and metadata are returned. |
| `unchanged(MemcacheMetaItem)` | The version matches; metadata is returned with empty data because no value bytes were transferred. |
| `missing` | The key is absent. |
| `serverError(Bytes)` / `requestFailure` / `transportFailure(i32)` / `replyFailure` | The existing failure stages. |

An unchanged item is a separate outcome from a changed item whose stored value is
empty. Both retain flags, CAS and remaining TTL with the
[metadata GET bounds](client-read-control.md#memcached-metadata-get). This source
result does not impose an HTTP response policy; handlers choose their own status
and body semantics.

Only a complete HD metadata reply with the matching CAS can produce unchanged.
A complete VA value must carry a different CAS. Contradictory peers, missing or
duplicate metadata, stale/unknown flags, trailing frames and values following HD
fail closed. CAS comparison preserves the complete unsigned 64-bit range and
compares admitted decimal tokens numerically, including leading zeroes. Keys
and known CAS are validated before I/O. The profile follows the conditional C
flag in the [pinned Memcached 1.6.45 protocol](https://github.com/memcached/memcached/blob/1.6.45/doc/protocol.txt#meta-get).

No quiet, TTL-changing, vivify or recache flags are sent. The helper uses one
send, at most four receives, 1000 ms per operation and an 8192-byte complete-frame
limit. A locally invalid request leaves a clean handle usable. Server,
transport and protocol errors close aliases. Successful values/metadata remain
valid after another receive and close. Session cleanup and pooling stay explicit;
there is no implicit retry or local value-cache implementation.

## Validation

`test_client_cache_reads.py` uses independent wire peers for request spelling,
ordered binary/empty/missing values, complete-array validation, forged builders
and replies, index bounds, full-width/leading-zero CAS, contradictory HD/VA
replies, fragmentation, exact frame bounds, EOF, timeouts and invalidated aliases.
Live pinned Redis verifies ordering, duplicate/empty keys and non-string MGET
semantics. Live pinned Memcached verifies unchanged metadata without a value,
leading-zero tokens, a changed value after an intervening write, empty values and
missing keys. CTest registers 20 cases across both backends, O0/O2, TCP/TLS and
explicit Docker profiles. Existing meta GET and CAS-delete tests cover the shared
transport modes separately.

```sh
ctest --test-dir build -R '^test_client_cache_reads_' --output-on-failure -j1
```
