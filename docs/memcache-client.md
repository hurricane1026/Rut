# Bounded Memcached client

The ordinary [client library](../examples/clients/memcache-client.rut) follows
the same composition model as the [Redis client](resp2-commands.md): generic
TCP/verified TLS, immutable Bytes, bounded source parsing and explicit pool
return. The [codec](../examples/clients/memcache-codec.rut) implements
[Memcached's basic text protocol](https://docs.memcached.org/protocols/basic/).
There are no new keywords, runtime protocol handlers or linked dependencies.

## API

| Function | Result |
| --- | --- |
| `memcacheGet(connection, key)` | `MemcacheGetResult`: `value(MemcacheItem)`, `missing`, or failure. |
| `memcacheSet(connection, key, value, options)` | `MemcacheStoreResult`: `stored`, `notStored`, or failure. |
| `memcacheAdd(connection, key, value, options)` | Store only if absent; the same typed store result. |
| `memcacheReplace(connection, key, value, options)` | Store only if present; the same typed store result. |
| `memcacheDelete(connection, key)` | `MemcacheCommandResult`: `ok`, `missing`, or failure. |
| `memcacheTouch(connection, key, seconds)` | Change relative expiration; the same typed command result. |
| `memcacheAppend(connection, key, data)` / `memcachePrepend(...)` | Add binary data to an existing item; `MemcacheStoreResult`. |
| `memcacheGets(connection, key)` | Fetch data, flags and an opaque CAS identifier; `MemcacheGetsResult`. |
| `memcacheCas(connection, key, data, options, cas)` | Conditional write; `MemcacheCasResult`. |
| `memcacheIncrement(connection, key, amount)` / `memcacheDecrement(...)` | Modify an existing unsigned counter; `MemcacheCounterResult`. |
| `memcacheGat(connection, key, seconds)` / `memcacheGats(...)` | Fetch and replace relative expiration, without/with CAS. |
| `memcacheMultiGet(connection, keys)` / `memcacheMultiGets(...)` | Fetch up to eight unique keys; `MemcacheManyResult`. |
| `memcacheMultiGat(connection, keys, seconds)` / `memcacheMultiGats(...)` | Fetch and replace expiration for the found keys. |

`memcacheStore(connection, mode, key, value, options)` accepts the closed
`MemcacheStoreMode` choices `set`, `add`, `replace`. A conditional miss is
`notStored`, never a transport error or a successful write. Missing GET and a
present empty value remain distinct.

All result variants also contain `serverError(Bytes)`, `requestFailure`,
`transportFailure(i32)`, and `replyFailure`. The error Bytes retain the complete
validated `ERROR`, `CLIENT_ERROR ...` or `SERVER_ERROR ...` line, without CRLF.
Transport codes use the existing [network error contract](net-clients.md).

`MemcacheOptions(flags: b"0", expirySeconds: 60)` supplies unsigned 32-bit
decimal flags and a relative TTL. Flags are checked decimal Bytes, preserving
the full `0...4294967295` range without adding a language numeric type.
`MemcacheItem` contains `data: Bytes` and `flags: Bytes`. Values are binary-safe,
including NUL, high bytes, empty data and embedded CRLF/END sequences. Returned
views survive later I/O, explicit release and close within the current request.

TTL zero means no expiration. Positive TTL is limited to 2592000 seconds
(30 days). The library rejects negative or larger values before sending:
Memcached interprets larger fields as absolute Unix timestamps, which are
outside this relative-TTL API. Eviction remains possible even with TTL zero.

For explicit expiration, use `MemcacheExpiry.seconds(i32)` (the same relative
`0...2592000` range) or `.unixSeconds(Bytes)` (decimal Unix seconds in
`2592001...2147483647`). The absolute form rejects the relative discriminator
range instead of silently changing its meaning. Leading zeros are canonicalized;
signs, malformed decimals and overflow fail before I/O. A timestamp in the past
expires immediately; no local clock conversion is performed. The pinned
[Memcached 1.6.45 text parser](https://github.com/memcached/memcached/blob/1.6.45/proto_parser.c)
parses expiry as signed 32-bit seconds; later timestamps are rejected locally to prevent premature
expiration after an apparently successful store.

| API | Arguments after `connection` |
| --- | --- |
| `memcacheStoreWithExpiry` | `mode: MemcacheStoreMode, key, value, flags: Bytes, expiry: MemcacheExpiry` |
| `memcacheCasWithExpiry` | `key, value, flags: Bytes, expiry: MemcacheExpiry, cas: Bytes` |
| `memcacheTouchWithExpiry`, `memcacheGatWithExpiry`, `memcacheGatsWithExpiry` | `key, expiry: MemcacheExpiry` |
| `memcacheMultiGatWithExpiry`, `memcacheMultiGatsWithExpiry` | `keys: MemcacheKeys, expiry: MemcacheExpiry` |

These return the same typed results and use the same framing, budgets and
connection-close rules as their relative-TTL counterparts. Invalid expiry sends
nothing and preserves the connection. An ambiguous write failure closes the
connection and never replays the command. The corresponding pure builders are
`memcacheStoreExpiryRequest`, `memcacheCasExpiryRequest`,
`memcacheTouchExpiryRequest` and `memcacheManyExpiryRequest`.

```rut
memcacheStoreWithExpiry(connection, MemcacheStoreMode.set, b"key", b"value",
    b"0", MemcacheExpiry.unixSeconds(b"2147483647"))
```

The expiry field interpretation follows the
[Memcached text protocol](https://docs.memcached.org/protocols/basic/).

## Framing and ownership

Keys must contain 1–250 bytes and no octet 0–32 or DEL. Invalid keys, flags,
TTLs and requests exceeding 8192 bytes produce `requestFailure` before I/O.
The codec exposes `memcacheGetRequest`, `memcacheStoreRequest`,
`memcacheDeleteRequest` and `memcacheTouchRequest` for inspecting encoded Bytes.
Public option records are revalidated rather than treated as trusted builders.

Each command sends once and uses at most four receives, each with a fixed
1000 ms operation deadline. One complete reply, including header, payload and
terminators, must fit in 8192 bytes. A single-key GET accepts exactly one
matching-key VALUE plus END, or END alone. The parser honors the declared byte
length; it never searches the value for a delimiter. Oversized/malformed fields,
extra values, trailing replies, wrong command acknowledgements, truncated EOF
and exhausted read budgets fail closed. Fragmentation requiring more than four
receives is deliberately outside this bounded profile.

Transport, reply and server errors close the handle before returning the typed
result; every alias becomes invalid. Closing on server errors is conservative:
the client does not assume a peer accepted or drained a failed storage request.
A request-validation failure leaves an otherwise clean handle usable.
No command is automatically retried; a failed or timed-out mutation may already
have affected the server.

After `value`, `missing`, `stored`, `notStored`, or `ok`, callers may explicitly
use `connection.release()` with a pool-enabled policy. A rejected release
discards the transport. The transport also checks for unread or late-arriving
data; application framing cannot eliminate peer-close races. This client does
not silently release leases or infer authentication state. The existing
sixteen-I/O and request-arena limits still apply; HTTP headers plus a maximum
body can exceed the outbound continuation's 8192-byte snapshot limit.

The [executable example](../examples/memcache-client.rut) uses
`MEMCACHE_ENDPOINT`, for example:

```json
{"address":"127.0.0.1","port":11211,"poolIdleMs":5000}
```

Verified TLS uses the unchanged `tls`, `caFile` and `serverName` policy fields.
Use a dedicated policy for this unauthenticated basic-text profile. The separate
[authentication library](client-authentication.md) adds challenge-gated `-Y` text
sessions. Binary/SASL, meta commands, arbitrary pipelining, UDP, failover and
background sessions are not provided. It is not an implementation of a
distributed Cache backend.

## CAS, counters and concatenation

`MemcacheGetsResult` distinguishes `value(MemcacheCasItem)`, `missing` and the
ordinary failure classes. An item retains `data`, unsigned-32-bit `flags` and
unsigned-64-bit `cas` as Bytes. Keep the token opaque and pass it to
`memcacheCas`; do not narrow it through a signed integer. CAS requires server
CAS support. `MemcacheCasResult` distinguishes `stored`, `exists` (version
conflict), `missing` (deleted/expired), `notStored` and ordinary failures. A
conflict is not retried. The caller decides whether to re-read and recompute.

The [CAS example](../examples/memcache-cas-client.rut) exposes POST `/gets`
(a decimal CAS line, CRLF, then binary data) and POST `/cas` (`X-Key`, `X-CAS`
and binary body). It returns 409 for a conflict and 404 for a missing item.
Successful CAS applies the supplied flags and relative TTL; the example uses
zero for both. The example uses the same `MEMCACHE_ENDPOINT` policy.

Counter amounts and results are decimal Bytes in `0...18446744073709551615`.
`MemcacheCounterResult.value(Bytes)` preserves this full unsigned range;
`missing` does not create a counter. Increment wraps at 64 bits; decrement
saturates at zero. Non-numeric stored data is a server error. Decimal fields
must contain 1–20 digits, without signs or padding; overflow is rejected before
I/O or as an invalid reply. No source-level unsigned numeric type is invented.
An ordinary GET still returns exact stored data, including any space padding a
server retains after shortening a counter.

Append/prepend return `stored` or `notStored` for an absent item. They preserve
the item's flags and expiration, including when adding empty or binary data.
They take no replacement flags/TTL arguments. The existing three-case
`MemcacheStoreMode` remains unchanged.

## Multiple keys and get-and-touch

Build `MemcacheKeys` with `memcacheKeys()` and `memcacheKeysAdd(keys, key)`.
The immutable builder admits at most eight distinct 1–250-byte keys, totaling
at most 2007 bytes including spaces. `memcacheManyRequest(keys, mode, seconds)`
revalidates public bytes/count fields, delimiters, lengths and duplicates before
I/O. `MemcacheRetrievalMode` is `plain`, `cas`, `touching` or `touchingCas`, for
get, gets, gat or gats respectively. Ordinary callers can use the named wrappers.

`MemcacheManyResult.values(MemcacheManyReply)` is published only after a complete
END-terminated response. `reply.count` counts found values; zero is a successful
all-missing lookup. `memcacheManyItem(reply, index)` returns an optional item
with `key`, `data`, `flags` and `cas`. Items retain server response order rather
than the input key order. The CAS field is empty for plain get/gat. Negative or
out-of-range indices return nil. Views survive later I/O and release/close
within the request. Keep the echoed key when associating results with inputs.

GAT returns the ordinary `MemcacheGetResult`; GATS returns
`MemcacheGetsResult`. Their multi-key equivalents return `MemcacheManyResult`.
They update expiration for found items and keep missing items distinct. Only
the existing relative TTL range is accepted; zero removes expiration. A failed
get-and-touch is a possibly-applied mutation, not a reason to replay it.

The scanner follows declared payload lengths and validates the whole response
before publication: no unrequested/duplicate key, unexpected/missing CAS,
invalid flags/length, partial-error suffix or data after END is accepted. A
multi-key read uses the same four-receive, 8192-byte, fixed-deadline profile as
single-key reads. There is no implicit pipeline, quiet command or retry.

## Validation

`test_memcache_client.py` uses an independent Python TCP/TLS peer to check exact
requests, unsigned flags, binary/empty values, boundaries, fragmented and hostile
replies, error classification, poisoned aliases, no replay and physical pool
reuse after source/import removal. Both epoll and io_uring run at O0/O2; verified
TLS runs at O2. The executable example is tested on both backends.

Live profiles use the official Memcached 1.6.45 Alpine image pinned to
`sha256:084fb554292d1447bc2c68b80c2331b98834514f56c866bc21a61be3c2ee376d`,
with TCP and TLS on both backends. Docker is an existing test mechanism and the
server image is test-only. These profiles check interoperability, conditional
writes, flags, delete/touch and actual expiration; no host OpenSSL CLI is used.

`test_memcache_advanced.py` adds independent wire fixtures and the same live
TCP/TLS/backend matrix for CAS conflicts, full-width unsigned counters,
append/prepend metadata preservation, multi-key membership/order/bounds,
GAT/GATS expiration, fragmentation and poisoned aliases. The CAS example runs
at O2 on both backends. All native tests remove source/import files after startup.

The focused `test_client_expiry.py` matrix covers explicit expiry encoding,
relative/absolute discriminator and overflow rejection, exact 8192-byte request
bounds, invalid requests before I/O, and EOF/timeout without mutation replay.
Pinned real Redis and Memcached tests verify actual expiration over TCP/TLS on
both backends. Memcached helper cases also cover CAS conflicts, TOUCH, GAT/GATS
and multi-key expiry updates, including the largest supported timestamp.

See [connection diagnostics](client-diagnostics.md) for bounded server health and statistics APIs.

See [bounded cache invalidation](client-invalidation.md) for multi-key deletion APIs and partial-write semantics.
