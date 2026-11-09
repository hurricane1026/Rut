# TCP and UDP client primitives

Rut exposes request-scoped `TcpConnection` and `UdpSocket` values so ordinary
`.rut` libraries can implement client protocols. Runtime primitives contain no
Redis, Memcached or other application protocol logic. No new keywords, external
client libraries, coroutines or LLVM runtime dependency are introduced.

The executable [TCP/UDP example](../examples/tcp-udp-clients.rut) imports a small
[Redis RESP2 PING client](../examples/clients/redis.rut) written in Rut. It is a
protocol-library example, not a complete Redis driver.

## Endpoint configuration

`tcp(policy, timeoutMs) -> TcpConnection?` connects a TCP client.
`udp(policy, timeoutMs) -> UdpSocket?` creates a UDP client connected to one peer.
Both take a policy JSON string resolved at compile/load time and a literal
1–60000 ms timeout. Configuration may come from `env(...)`.

Plain TCP or UDP:

```json
{"address":"127.0.0.1","port":6379}
```

Verified TCP TLS:

```json
{"address":"127.0.0.1","port":6380,"tls":true,"caFile":"/certs/ca.pem","serverName":"redis.internal"}
```

Address is a fixed IPv4 literal and port 1–65535. TLS uses the existing pinned
static OpenSSL, requires both CA and server identity, and never falls back to
plaintext. Unknown/duplicate fields, controls/NUL, missing fields, invalid ranges
and inconsistent TLS fields reject compilation. UDP rejects all TLS fields.
TCP policy may additionally set `poolIdleMs` to an integer 1–60000; absence disables
cross-request reuse. UDP rejects this field. Policy is at most 2048 bytes.
There is no DNS, listener/server API, Unix socket,
DTLS, client certificate or application ALPN selection in this profile. Remote
addresses cannot be selected from request data. A UDP socket sends only to and
receives only from its configured peer; there is no arbitrary `sendTo`/`bind` API.

## Operations

| Operation | Result | Semantics |
| --- | --- | --- |
| `connection.send(data, timeoutMs)` | `i32?` | Send all Bytes or str bytes; return byte count. TCP failure may follow a partial write. UDP performs exactly one datagram send, including an empty one. |
| `connection.receive(maxBytes, timeoutMs)` | `Bytes?` | TCP: return some available bytes, up to maxBytes. Empty success means EOF. UDP: return one whole datagram, which may be empty. |
| `connection.readExactly(count, timeoutMs)` | `Bytes?` | TCP only; accumulate exactly count bytes. Count zero succeeds empty; early EOF fails. |
| `connection.readLine(maxBytes, timeoutMs)` | `Bytes?` | TCP only; accumulate through LF, retaining LF and any preceding CR. Missing LF within maxBytes or truncated EOF fails. |
| `connection.release()` | `bool` | TCP only; explicitly return a clean transport to its configured idle pool. Always invalidates the handle; false closes it instead. |
| `connection.close()` | `bool` | Invalidate the handle immediately and schedule socket cleanup; false for an invalid/already-closed handle. |

Read counts are unwrapped i32 values, checked at runtime: receive/readLine accept
1–8192 and readExactly 0–8192. Send payloads are at most 8192 bytes. Counts may
come from protocol parsing. Timeout is always a literal 1–60000 ms. TCP keeps
surplus bytes in a bounded connection buffer for later operations. UDP never
silently truncates a larger datagram: it fails the operation and closes the
socket. This differs from ordinary stream receive, which can return a prefix.
A successful UDP send only confirms local socket acceptance, not peer receipt.

Bind asynchronous results before unwrapping, as for `httpCall`:

```rut
let pending = tcp(env("SERVICE_ENDPOINT"), 1000)
guard let connection = pending else { return 503 }
let pendingSend = connection.send(b"PING\r\n", 1000)
guard let sent = pendingSend else { return 503 }
let pendingRead = connection.readLine(128, 1000)
guard let reply = pendingRead else { return 503 }
let closed = connection.close()
return response(200, body: reply)
```

Dynamic `Bytes` response locals use the existing bounded body serializer without
UTF-8 conversion. Binary NUL and non-UTF-8 bytes are preserved. A raw network
response is not an authorization decision: protocol libraries must validate the
reply before admitting or forwarding traffic.

## Failures and ownership

Nil means the operation failed; `netError() -> i32` reports the most recent
completed network operation in the current handler invocation:

- `0`: success;
- `-1`: transport/TLS/EOF-framing/truncation failure;
- `-2`: deadline exceeded;
- `-3`: session capacity exhausted;
- `-4`: invalid handle, generation or operation/count.

Read `netError()` immediately on the failure path, before another operation.
Result-storage exhaustion also reports `-3`. It does not persist across yields
on its own: bind its value if needed later.
This is a deliberately small initial error profile. It does not distinguish all
OS errors or imply that a failed write had no remote effects. No network command
is automatically retried. After send success or partial/unknown send, timeout or
cancellation does not undo server-side execution. Application protocol logic
must choose whether any retry is safe.

Handles belong to one HTTP request/HTTP2 stream generation and owner shard.
They can be passed to helpers/imported libraries but cannot access another
request's sockets. Aliases refer to the same connection; closing one invalidates
all. Handles expose no descriptor or constructor. Normal handler completion,
early denial, forwarding, reset/close and shutdown all release remaining sockets.
Successful TCP/UDP opens followed by asynchronous HTTP calls retain their sockets
across the HTTP continuation. Returned byte views own request-arena storage and
survive later reads and suspension. Native-loaded code/config does not depend on
live importing source files.

Every I/O operation has one monotonic deadline, including setup for connect;
progress cannot extend it. Each connection supports one operation at a time.
There are at most 16 live sessions per shard; an independent bounded nonblocking
worker owns all socket/TLS work, including CA loading. The shard suspends using
the existing timer continuation (polling up to 10 ms). Worker storage is mmap
backed and is scrubbed/joined on shutdown. No kernel I/O retains a request-owned
pointer. The existing outbound continuation also bounds the saved complete HTTP
request and generated value frame to 8192 bytes each, within the 256 KiB request budget.
Consequently a maximum-size HTTP body plus its headers can exceed snapshot
capacity even though an individual send allows 8192 bytes. Explicitly released
TCP/TLS transports can survive HTTP requests in the bounded
worker-owned pool described below; leased handles remain request-scoped.

This first client profile inherits outbound-call restrictions: at most 16
sequential network/HTTP operations per handler, no explicit wait, timer or
WebSocket handler, and no specialized password/forward-auth prefix in the same
handler. HTTP/2 retains its existing single suspended-stream restriction.
Use a let binding even for close when its Boolean result is ignored. Unwrapped
read results support `bytes[index] -> i32?`: a zero-based i32 index yields an
unsigned octet (0–255), or nil for a negative/out-of-range index. This lookup
does not perform I/O or change `netError()`. Streaming subscriptions, background
sessions and general parser loops remain separate follow-ups.

The [built-in Bytes methods](binary-integers.md) decode fixed-width integer
fields with big/little endian reads, such as `bytes.readU16BE(0)`. Acquire a complete TCP
field before decoding (for example with `readExactly`); decoding itself does
not perform I/O. UDP fields use offsets in a complete received datagram.

## Validation

`test_net_clients.py` exercises both epoll and io_uring with actual local TCP,
verified TLS and UDP peers. It checks imported protocol helpers/native source
removal, byte-fragmented line/exact reads and surplus buffering, binary/empty/
maximum-size datagrams, oversize rejection, trust failure, timeout, cancellation,
concurrent calls, HTTP/2, TCP sessions retained across HTTP-call suspension and automatic close. Runtime unit tests check strict policy
validation, bounded session capacity and handle owner/generation/close isolation.

[Bytes field extraction](bytes-fields.md) provides checked `slice(start, end)` and
`find(delimiter[, start])` methods. For a CRLF-terminated decimal field, locate
CRLF, slice off the protocol prefix/terminator, then use `parseInt`/`parseInt64`.
A slice retained across another network operation keeps the original read bytes.

[Bounded parsing](bounded-parsing.md) adds synchronous complete-buffer scans and
immutable typed result collections. The [RESP2 library](../examples/clients/resp2.rut)
uses these generic primitives to validate nested replies; it does not turn a
partial TCP receive into a complete frame or introduce I/O inside parser steps.

[Incremental RESP2 framing](resp2-streaming.md) retains parser state and owned
Bytes across receives, distinguishes NeedMore/Complete/Invalid, and preserves
pipelined remainders. `resp2Receive` performs one receive only while NeedMore;
callers choose a finite read budget under the existing operation/frame limits.

[RESP2 command builders and GET/SET](resp2-commands.md) now compose binary-safe
requests, typed command results and bounded scalar replies. Callers can reuse
one handle for sequential commands in the same request. Transport/reply failure
poisons the handle. After a complete accepted result the caller may explicitly
release a pool-enabled connection. No write retries are introduced.

## Explicit cross-request TCP/TLS pooling

For example, configure `{"address":"127.0.0.1","port":6379,"poolIdleMs":5000}`.
The same `tcp(policy, timeoutMs)` call borrows a matching healthy idle transport
or opens a new connection. No new keyword or handle constructor is added.
After consuming a complete reply and restoring the protocol's reusable state:

```rut
let returned = connection.release()
```

`release() -> bool` is a resumable TCP-only operation, bound before use like
other network operations. It uses an internal 1000 ms completion deadline and
counts toward the existing sixteen-operation handler limit. A valid release
invalidates all aliases, including when it returns false. True means that the
transport was parked; false means it was discarded (pool disabled/full, unread
bytes, EOF, transport not clean or retired policy). An invalid handle also
returns false with `netError() == -4`. A completed eligibility rejection sets
`netError() == 0`; failure to complete can report timeout. Ordinary `close()`
always destroys the transport. Abandonment, timeout and cancellation never
implicitly release a lease. A pooled descriptor is never retried after a send.

Each shard's existing I/O worker owns up to sixteen idle transports, separately
from its sixteen live lease slots. Idle entries own descriptor, TLS session and
trust context; they retain no request arena, source/JIT pointer or byte result.
The key is exact IPv4 endpoint, port, TLS enablement, CA path, server identity,
idle policy and configuration epoch. Equal parsed keys share a pool even when
the JSON spelling or environment binding differs. A borrow issues a fresh token fenced to
its new HTTP request/stream; an older token cannot operate on the new lease.
Configuration adoption advances the epoch, sweeps old idle entries, and refuses
returns from old-config requests which are still finishing. Shutdown joins the
worker and destroys both idle and active transports. CA files changed in place
require configuration reload to retire existing verified sessions.

Both release and borrow reject buffered plaintext, buffered TLS data, EOF,
errors and pending socket input. Idle expiration runs on worker turns and is
checked before borrowing. TLS control records which are still pending on the
wire are conservatively discarded as well. These probes cannot eliminate a
peer-close race after borrow; the subsequent operation fails normally without
replaying a command. The transport cannot establish application framing or reset
AUTH/SELECT/transaction/subscription state. Only release after protocol code has
validated and fully consumed its reply and restored the state expected by every
user of that exact policy. Close connections with state that other borrowers
must not inherit.
The plain Redis GET/SET example has no connection-specific authentication or
selection state; malformed and transport-failed replies already close the lease.

`test_net_client_pooling.py` observes physical TCP/TLS connection identities over
separate HTTP/1 requests and HTTP/2 streams at O0/O2 on both backends,
including source removal,
ignored helper arguments, aliases, dirty/EOF/TTL eviction, cancellation, timeout,
policy/TLS identity separation and shutdown cleanup. Runtime tests additionally
cover config retirement, stale request generations and independent active/idle
capacity. The peer is an independent fixture, not a Redis deployment.

[Authenticated Redis sessions](redis-sessions.md) now compose AUTH/SELECT with one
GET/SET and acknowledged RESET before generic pool return. They restore identity
and database state without adding protocol logic to the transport or raising its
sixteen-operation limit.
