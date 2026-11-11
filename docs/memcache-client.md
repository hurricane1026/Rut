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
Use a dedicated policy for this unauthenticated basic-text profile. Text-token
authentication (`-Y`), binary/SASL, meta commands, CAS/gets, counters, multi-get,
pipelining, UDP, failover and background sessions are not provided by this
initial client. It is not an implementation of a distributed Cache backend.

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
