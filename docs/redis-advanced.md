# Redis transactions, RESP3, subscriptions and topology

These ordinary source libraries extend the [Redis client](redis-commands.md).
They use the existing request-scoped TCP/TLS handles, immutable Bytes, bounded
parsing and explicit connection ownership. They add no protocol-specific runtime
operation, keyword or linked dependency. Import the module needed for a handler;
selective imports preserve the existing function/import limits when combining
modules. Endpoints remain fixed policies resolved at compilation/load time.

Runnable examples cover [transactions](../examples/redis-transaction-client.rut),
[RESP3 GET](../examples/redis-resp3-client.rut) and
[one-message subscriptions](../examples/redis-pubsub-client.rut). Configure
`REDIS_ENDPOINT` with the ordinary fixed TCP/TLS policy and run, for example,
`build/src/rut 8080 examples/redis-transaction-client.rut`. Responses contain
binary protocol frames where documented; the subscription example returns the
message payload. Authentication remains caller-owned.

## Transactions

Import `clients/redis-transaction.rut`.

| API | Contract |
| --- | --- |
| `redisTransaction()` | Empty immutable builder. |
| `redisTransactionAdd(batch, request)` | Append one validated command, at most eight. |
| `redisTransactionExecute(connection, batch)` | Acknowledge MULTI, send the batch plus EXEC once, consume every queue acknowledgement and the EXEC result. |
| `redisWatch(connection, key)` | WATCH a single binary key on this physical connection. |
| `redisUnwatch(connection)` | Require exact simple OK before clearing a watch. |
| `redisDiscard(connection)` | Require exact simple OK when cancelling a manually opened MULTI. |

`RedisTransactionResult` distinguishes `executed(Bytes)`, `watchAborted`,
`queueError(Bytes)`, `serverError(Bytes)`, `requestFailure`,
`transportFailure(i32)` and `replyFailure`. Successful Bytes contain the complete
EXEC array, decoded with `decodeResp2`. Nested execution errors stay in that
array: Redis executes the other queued commands and does not roll them back.
A failed queue entry requires EXECABORT; no executed array is accepted in its
place. A null array is a WATCH conflict, not an empty successful transaction.
Neither case is automatically retried. These follow the Redis
[transaction contract](https://redis.io/docs/latest/develop/using-commands/transactions/).

MULTI must return exact simple OK before any business command is sent. A refused
MULTI therefore cannot turn a transaction into ordinary writes. Batches are
revalidated before I/O, including public builder counts. They accept canonical
uppercase GET/SET, key/expiry/counter commands and bounded hash/list/set/sorted-set
operations listed in `redisTransactionCommand`; connection/mode controls,
scripts and nested transactions are excluded. Adding an encoded request never
grants permission to execute an arbitrary control command.

The batch reserves room for EXEC within an 8192-byte send. Request validation
uses at most 64 nodes. Queue acknowledgements plus EXEC must fit in 8192 bytes
and 64 nodes, across at most four receives, each with a 1000 ms deadline. MULTI
and WATCH controls use bounded `readLine` acknowledgements. Transport/framing
failures and refused MULTI close aliases. Confirmed EXEC, WATCH abort and
EXECABORT finish transaction/watch state, but caller-owned authentication and
database state still require the ordinary session cleanup before pool return.
An unfinished WATCH or manually opened MULTI must be cleared or closed.

## RESP3

Import `clients/redis-resp3.rut`; it includes `resp3.rut` and request validation.

`decodeResp3(bytes)` validates one exact value and returns preorder
`Collected<Resp3Value>`. `resp3Frame(bytes)` returns the first complete frame,
its `rest`, and its actual root token. Attributes annotate the following value,
so the root may follow attribute entries. Trailing input is rejected by the exact
decoder and preserved by the frame API.

| Kind | Value |
| --- | --- |
| 1–7 | The existing RESP2 simple/error/integer/bulk/array/null-bulk/null-array kinds. |
| 8, 9 | RESP3 null and boolean. |
| 10, 11 | Double and big-number spelling as exact Bytes. |
| 12, 13 | Binary blob error and verbatim string, retaining the format prefix. |
| 14, 15 | Map and attribute; `children` counts both keys and values. |
| 16, 17 | Set and Push. |

Numbers are validated without inventing unsupported floating-point/source
numeric types. Integer replies retain signed 64-bit validation; big-number and
double decimal segments are bounded to 64 digits. Booleans, nulls, lengths,
verbatim separators, pair counts and CRLF are validated before publication.
Frames are limited to 8192 bytes and 64 tokens. Optional streamed RESP3 encodings
are outside this finite decoder. See the official
[RESP3 specification](https://github.com/redis/redis-specifications/blob/master/protocol/RESP3.md).

`redisHello3(connection)` negotiates HELLO 3 and requires a complete map response
with exactly one top-level integer `proto: 3` entry.
It closes on failed negotiation; there is no silent RESP2 fallback.
`redisResp3Execute(connection, request)` validates and sends one RESP2-encoded
command. `redisResp3Next(connection, buffered)` continues an outstanding event
stream without resending the command. Each uses at most two receives per frame,
with separate 1000 ms deadlines. Results distinguish `reply(RedisResp3Event)`,
`push(RedisResp3Event)`, `serverError(RedisResp3Event)` and ordinary failure classes.
An event retains `frame`, `rest`, the actual root `kind` and its content offset. Error events preserve
their remainder too. Frames survive later I/O and close within the request.

A Push is never published as the pending command's ordinary reply. Carry its
`rest` into Next until that reply is consumed; additional commands must wait.
The same applies to coalesced trailing events. These are explicit events, not
background callbacks or an implicit client-tracking cache. After HELLO 3, use
the RESP3 executor; existing RESP2 GET/SET/pipeline helpers retain their grammar.
Close a RESP3 lease or explicitly restore and acknowledge the protocol/session
before ordinary pool return. Callers authenticate before negotiation when needed.

## Pub/Sub

Import `clients/redis-pubsub.rut`. A `RedisSubscription` stores binary `channel`,
`mode` (1 channel, 2 pattern, 3 sharded channel), and `closing`. It is request
configuration, not a lease or proof that a connection is subscribed.

`redisSubscribe(connection, state)` validates the matching subscription
acknowledgement and count one. `redisSubscriptionNext(connection, state, buffered)`
consumes the next message. `redisUnsubscribe(connection, state, buffered)` begins
matching cancellation; use a copy with `closing: true` for subsequent Next calls.
Interleaved messages remain distinct from the count-zero unsubscribe
acknowledgement. Both RESP2 array messages and RESP3 Push messages are accepted.
Channel, pattern, message kind, arity, payload types and counts must match.

`RedisPubSubResult` distinguishes `subscribed(RedisPubSubFrame)`,
`message(RedisPubSubFrame)`, `unsubscribed`, `serverError(Bytes)` and ordinary
failure classes. Frames contain exact `frame` and buffered `rest` Bytes.
`redisPubSubData(frame)` and `redisPubSubOrigin(frame)` expose payload and actual
origin channel; a pattern subscription retains the matching pattern separately
in its configuration. Never drop `rest` between operations.

`redisSubscribeOnce(connection, state)` acknowledges one subscription, reads one
message and closes the dedicated connection before returning. It leaves room
for explicit authentication under the existing sixteen-I/O profile.
For acknowledged cancellation, compose `redisUnsubscribe` and subsequent Next
calls on an existing dedicated subscription within the same operation budget.
The one-message helper retains its data across close and never replays it.

Frames are bounded to 8192 bytes with at most two receives per event, each with
a 1000 ms deadline. This is finite request-scoped consumption, not a persistent
background subscriber. Transport/protocol failures and acknowledged cancellation
retire the connection. Rejected requests before I/O preserve caller ownership;
the caller must close any existing subscription. Subscribed leases must never
enter a generic idle pool. Pub/Sub
delivery remains [at most once](https://redis.io/docs/latest/develop/pubsub/).

## Cluster, Sentinel and recovery

Import `clients/redis-topology.rut`.

`redisClusterSlot(key)` implements CRC16/XMODEM and Redis hash tags. Hash input
is bounded to 256 bytes; a longer key with a shorter valid hash tag is permitted.
`redisClusterExecute(connection, request, key)` accepts one validated canonical
key command, checks its first key against `key`, and sends once. DEL/UNLINK/EXISTS
are single-key only. It returns `RedisTopologyResult`: `reply(Bytes)`,
`redirect(RedisRedirect)`, `serverError(Bytes)` or ordinary failure classes.
Multi-key routing, script key discovery and automatic transaction routing are
not inferred from arbitrary command Bytes.

A redirect retains `slot`, `endpoint` and `asking`. MOVED/ASK slot numbers must
match the requested key. `redisRedirectResolve` applies the current configured
address to an empty-host redirect. `redisRedirectNode` maps to known configured
endpoint names; unknown targets must be rejected. Open the selected fixed
TCP/TLS policy, then call `redisClusterFollow`. ASK requires exact acknowledged
ASKING before the business request; it is never sent optimistically. A second
redirect is explicit, not an unbounded retry loop. ASK is not a permanent slot
assignment. These follow the
[Cluster protocol](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/).

`redisSentinelDiscover(connection, service)` sends
`SENTINEL get-master-addr-by-name` and returns `master(RedisMaster)`, `unknown`
or a typed failure. Match its address/port with configured policies using
`redisMasterMatches`. After connecting to that node,
`redisSentinelVerifyMaster` checks ROLE before business commands. A replica or
invalid ROLE response closes the connection. Discovery is repeated when
reconnecting; do not retain a previously discovered master as permanent truth.
Applications can try their finite configured Sentinel list, without trusting
arbitrary response addresses. This is the Redis
[Sentinel discovery procedure](https://redis.io/docs/latest/develop/reference/sentinel-clients/).

Topology commands use at most two receives and 8192-byte/64-node response bounds.
Policies keep their existing verified TLS identities, fixed IPv4 addresses and
compile-time admission. DNS, arbitrary newly announced nodes, a shared mutable
slot map, background topology refresh and unlimited failover attempts are not
added. Authentication is caller-owned on every new physical connection; account
for it and cleanup within the same existing operation budget.

`redisRecovery(result, readOnly)` distinguishes completion, redirect,
`reconnectRead`, `unknownWrite` and stop. The read-only classification must come
from trusted application logic, never untrusted request claims. Reopen an admitted
endpoint and redo authentication/discovery before an explicit read retry. A
transport/framing failure after a mutation cannot prove whether the write ran;
it must not cause automatic replay. None of these helpers retries a command.

## Verification

The four `test_redis_{transactions,resp3,pubsub,topology}.py` suites use independent
byte-level peers, native programs after source/import removal, O0/O2 namespace
imports, both Linux backends and verified TLS. Docker-labelled profiles use the
existing immutable Redis 7.2.11 image. Topology live profiles include a real
Sentinel; separate Cluster profiles form three real nodes and exercise MOVED
and an importing/migrating slot's ASKING path over TCP/TLS.

Compiler scope regressions exercise repeated nested local initializers under
different collector bindings and binary inputs. Binding-independent initializer
graphs may be reused; expressions capturing outer lexical values must be
reinstantiated. This changes compiler work, not source semantics or the existing
runtime/parser/arena/I/O limits.
