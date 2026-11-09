# Binary RESP2 requests and request-scoped Redis operations

[Command construction](../examples/clients/resp2-command.rut) and
[Redis GET/SET](../examples/clients/redis-client.rut) are ordinary Rut libraries.
They use generic Bytes operations, TCP/TLS transport and incremental framing;
the runtime contains no Redis commands or application protocol parser.

## Primitive formatting and views

`formatInt(value) -> str?` emits canonical signed decimal for an unwrapped i32
or inferred i64. Zero is `"0"`; signed limits, including i64 minimum, are exact.
There is no positive sign, whitespace, leading zero, locale, radix or floating
point conversion. The portable kernel divides by 100 and writes digit pairs from
a small lookup table. Unsigned magnitude arithmetic avoids signed-min overflow.
Conversion uses 20 bytes of stack scratch, then copies only the actual digits
into the existing arena. Storage failure returns nil.

`Bytes(text) -> Bytes` is an explicit immutable view of an unwrapped str's exact
bytes; `Bytes(data)` is identity for Bytes. Conversion does not validate UTF-8,
transcode, allocate or perform I/O. NUL and high-bit bytes remain unchanged. The
view inherits the input's lifetime. Types remain distinct, and optional inputs
must be unwrapped first. Both builtins support direct call syntax; pipe/UFCS
forms are outside this profile. User bindings/functions can shadow them.

Formatting calls retain reached branch and eager helper-argument semantics.
Neither builtin alters `netError()`. Packet ownership and bounded failure use
[`concatBytes`](resp2-streaming.md), rather than an implicit Bytes `+` operator.

## Command construction

| API | Result and contract |
| --- | --- |
| `resp2Command(argumentCount, maxBytes)` | `Resp2Command?`; start a command with its array header. Count includes the command name and must be 1–63; limit is 1–8192. |
| `resp2Argument(command, payload)` | `Resp2Command?`; append one exact binary bulk-string argument, returning a new builder. |
| `resp2Request(command)` | `Bytes?`; publish only when the promised number of arguments was supplied. |
| `resp2BulkArgument(payload, maxBytes)` | `Bytes?`; construct an individual bulk string. |
| `resp2GetRequest(key)` | `Bytes?`; encode `GET key`. |
| `resp2SetRequest(key, value)` | `Bytes?`; encode plain `SET key value`. |

For example:

```rut
func request(_ key: Bytes) {
    guard let initial = resp2Command(2, 8192) else { nil }
    guard let named = resp2Argument(initial, b"GET") else { nil }
    guard let keyed = resp2Argument(named, key) else { nil }
    resp2Request(keyed)
}
```

Lengths count stored bytes, including CRLF, NUL and non-UTF-8 payload bytes.
Payload contents never become framing or an additional command. Empty arguments
are valid. There is no escaping or implicit text conversion. Count 63 plus the
array header stays within the existing 64-node decoder profile.

Too few/many arguments, a byte-limit violation or arena/pool exhaustion fails
without publishing a truncated request. Earlier builders and packets are
immutable and remain usable after later appends and network I/O. Failed attempts
can still consume temporary arena storage. As with incremental receive buffers,
copy work is proportional to the sum of constructed prefixes; the existing
256 KiB invocation budget can be exhausted below the maximum argument/byte limits.
Builders are ordinary records, not trusted authorization evidence.

## GET and plain SET

`redisGet(connection, key) -> RedisGetResult` returns one of:

- `.value(Bytes)` for a bulk value, including a present empty value;
- `.missing` for a RESP2 null bulk reply;
- `.serverError(Bytes)` for a framed server error;
- `.requestFailure` before sending an unconstructible request;
- `.transportFailure(i32)` with the captured network error code;
- `.replyFailure` for invalid/unexpected/truncated replies, exhausted read budget
  or unavailable parser/result storage.

`redisSet(connection, key, value) -> RedisSetResult` returns `.ok`,
`.serverError(Bytes)`, `.requestFailure`, `.transportFailure(i32)` or
`.replyFailure`. Only the exact simple string `+OK\r\n` acknowledges plain SET.
GET rejects simple strings, integers and null arrays; SET rejects bulk `"OK"`,
null values and other reply kinds. These choices follow the Redis
[GET](https://redis.io/docs/latest/commands/get/) and
[SET](https://redis.io/docs/latest/commands/set/) contracts for these basic forms.
NX/XX/TTL/GET options, transactions, Pub/Sub and RESP3 remain separate
operations. [Authenticated sessions](redis-sessions.md) add explicit AUTH/SELECT
and acknowledged RESET before pool return; plain GET/SET never infer them.

Replies have a finite budget of four receives, each with a 1000 ms operation
deadline. Already Complete/Invalid states perform no more reads. There is no
implicit overall-frame deadline. Scalar framing reuses the general parser step
with a one-node work limit, and final token decoding also uses one node. This
avoids expanding the 64-node array path for commands which require scalar replies.
A nonempty aggregate, wrong reply kind or already-buffered trailing reply fails.
The existing send/receive, 16-operation and verifier budgets still apply. Two
successive SET/GET operations on one request-scoped handle fit this profile.

The caller opens the existing fixed IPv4 TCP/TLS endpoint and owns normal close.
Transport or reply failure closes the handle before returning, invalidating aliases
so partial or mismatched protocol state cannot be reused. A valid server error
keeps the connection available for another command; request construction failure
also leaves it open because nothing was sent. Error codes are captured before
cleanup: use the `.transportFailure(code)` payload, since a subsequent `netError()`
may report the close operation instead.

No command is automatically retried. A failed send may follow a partial write;
a missing/malformed acknowledgement can follow an executed SET. The application
must decide whether retrying is safe. Normal request completion, cancellation and
shutdown retain the transport's existing cleanup rules. Connections are still
scoped to one request/shard generation. With `poolIdleMs` configured, the caller
may explicitly `release()` after a validated GET/SET result to reuse the transport
in a later request; see [pooling](net-clients.md#explicit-cross-request-tcptls-pooling).

The 8192-byte frame/send limit is independent of the existing 8192-byte saved
HTTP request limit. An HTTP body plus its headers can exceed snapshot capacity
before a client helper starts. Wire size alone is therefore not a promise that
an equally sized HTTP request body can be used as an argument.

See the [HTTP example](../examples/redis-client.rut). It maps typed failures to
HTTP statuses and emits a successful GET's raw Bytes through a direct response
terminator. Server-error payloads remain available to library consumers.

## Library composition and verification

Complete and incremental RESP2 APIs now share `clients/resp2.rut`;
`clients/resp2-stream.rut` remains a compatibility import. Redis imports this
shared module directly, keeping the existing two-level import/memory limit.
Sibling imports relocate concrete record/variant IDs, nested fields and payloads
by exported name before shapes are interned. Namespaced use preserves nominal
type identity; a same-looking record from another declaration is not accepted.

Compiler node addresses remain stable. A separate address-sorted chunk index
makes IR-copy pointer rebasing logarithmic rather than scanning every chunk for
every pointer. Named-error walks visit owning initializers and do not traverse
already-bound references as repeated expression graphs. No runtime allocator,
protocol opcode, dependency, exception or C++ standard-library use is added.

Tests compare decimal formatting with C `snprintf` over 100,000 signed values and
protect scratch bounds with an unreadable page. The independent TCP fixture
checks exact command arrays, binary payload lengths, missing/empty values, strict
acknowledgements, server errors, split replies, cleanup, timeout/EOF and absence
of automatic resends. Tests remove source files after startup, compose sibling
and namespace imports, and run epoll/io_uring at O0/O2. A same-connection SET/GET
round trip and an error payload retained across another command exercise owned
values across suspension. The fixture is a protocol oracle, not an external
Redis installation or a claim of complete Redis-driver compatibility.
