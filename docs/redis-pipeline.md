# Bounded Redis pipelines

[redis-pipeline.rut](../examples/clients/redis-pipeline.rut) sends 1–8 commands in
one send operation and receives their ordered RESP2 responses. Each response can be a
scalar, null, array or nested aggregate. Server errors remain ordinary response
nodes; subsequent commands still execute. These follow the
[Redis pipelining semantics](https://redis.io/docs/latest/develop/using-commands/pipelining/):
there is no atomicity, rollback or cancellation of later commands after an error.

## Build and execute

Import the pipeline and request encoder as siblings to stay within the existing
two-level import limit:

```rut
import "clients/redis-pipeline.rut"
import "clients/resp2-command.rut"

func setThenGet(_ key: Bytes, _ value: Bytes) {
    guard let write = resp2SetRequest(key, value) else { nil }
    guard let read = resp2GetRequest(key) else { nil }
    guard let first = redisPipelineAdd(redisPipeline(), write) else { nil }
    redisPipelineAdd(first, read)
}
```

| API | Contract |
| --- | --- |
| `redisPipeline()` | Empty immutable `RedisPipeline` builder. |
| `redisPipelineAdd(pipeline, request)` | Append one validated, encoded command; return a new builder or nil. |
| `redisPipelineExecute(connection, pipeline)` | Validate the actual entire batch, send once, consume every response and return `RedisPipelineResult`. |
| `redisPipelineReply(reply, index)` | Exact response frame for zero-based command index, or nil. Validates the entire reply batch before returning a slice. |
| `redisPipelineValues(reply)` | `Collected<RedisPipelineToken>?` containing preorder tokens tagged with their zero-based command index. |

`RedisPipelineResult` has `.reply(RedisPipelineReply)`, `.requestFailure`,
`.transportFailure(i32)` and `.replyFailure`. A successful reply retains the
invocation-owned `frame: Bytes` and `count: i32`. A server `-ERR` is available in
its response frame and as a token of kind 2; it does not discard other responses.

Each `RedisPipelineToken` exposes `.reply` and `.value: Resp2Token`. Descendants
of an array keep their enclosing command's reply index. Existing
`resp2Integer(node.value)` preserves signed 64-bit integers. For a selected frame,
`decodeResp2(frame)` supplies the usual single-response representation. Empty
arrays, null arrays, empty bulk strings and null bulk strings remain distinct.
Frames and token Bytes survive later I/O, RESET and release/close.

## Validation and bounds

Both request and response batches are limited to 8192 bytes and 64 aggregate
nodes. Each array header, bulk/scalar or null counts as one node. The request
limit covers all command arrays and arguments together. Individual requests must
be nonempty flat arrays of non-null bulk arguments. An empty builder cannot
execute. Eight commands with small argument lists fit; larger argument lists may
exhaust the aggregate node or byte budget.

Builder records are public values. The executor validates wire bytes, command
boundaries and the declared count again before I/O, including forged counts,
nested/non-bulk arguments, trailing bytes and concatenated commands hidden in a
single append. An append checks its new request and byte/count limits; execution
also enforces the complete batch's node limit.

The response cursor begins with the exact expected root count and retains state
across at most four receives. Success requires all roots and no buffered trailing
bytes. Each send/receive has a 1000 ms operation deadline; there is no implicit
overall deadline. Incomplete EOF, malformed replies, invalid integers, exhausted
reads, impossible lengths or byte/node overflow close the handle and invalidate
its aliases. Invalid requests write nothing and preserve the connection. Fully
consumed server errors also leave it usable.

After send/read failure, some commands may already have executed. The library
never retries a batch and never publishes a partial batch as success. Callers
must determine application outcomes through their own idempotency or recovery
scheme.

## Authentication and pooling

Initialize and acknowledge the connection's identity/database before sending
business commands. Authentication, protocol-mode changes and subscriptions
belong outside a business batch: failed AUTH would not stop later commands. Use
the existing `redisInitialize` helpers first and acknowledge `redisReset` before
pool return. The executor retains caller ownership and does not release the
connection implicitly.

For MULTI/EXEC with WATCH conflicts, RESP3 events, dedicated subscriptions and
configured topology routing, see the separate [advanced modules](redis-advanced.md).
An ordinary pipeline is not an atomic transaction.

The existing [authenticated helpers](redis-sessions.md) compose through selective
imports, alongside unqualified pipeline/encoder imports:

```rut
import { redisInitialize, redisInitializeSucceeded, redisReset, redisCommandSucceeded, RedisInitializeResult, RedisCommandResult } from "clients/redis-client.rut"
```

Selective imports avoid duplicate shared declarations and preserve the ordinary
function budget. Namespace imports are also exercised by tests. Combining them
with selective authentication requires the authentication helpers' concrete
RESP2/command types, as demonstrated in the integration fixture. Initialization,
one pipeline, RESET and release fit the existing sixteen-I/O profile. No
language, parser, arena or verifier limit is raised. Transactions, subscription
streams, Cluster/Sentinel discovery and RESP3 remain outside this profile.

## Shared token parsing and verification

The shared RESP2 library exposes `resp2Token(bytes, offset) -> Resp2Token?` for
one scalar/bulk node or array header. It reports the next offset and child count;
an array header alone does not prove its descendants exist. The existing
`resp2Step` and `decodeResp2` entry points still validate aggregate completion.
Pipeline scans use this same token grammar to track root indices and selected
byte spans, and validate the full batch even when only its first response is
requested. Single-command request validation is shared through the codec without
another import layer.

`test_redis_pipeline.py` uses a peer that withholds every reply until it has read
every command. This establishes actual pipelining. It checks binary arguments,
nested arrays, integer limits, 1–8 roots, error preservation and recovery, exact
byte/node/read bounds, forged metadata, rejected batches without writes, alias
invalidation and absence of replay after missing replies. Accessors reject a
valid prefix if the remainder is invalid. Source removal, root nominal types,
selective imports and O2 namespace imports exercise metadata ownership and
relocation.

CTest covers epoll/io_uring at O0/O2 and verified TLS. The `docker`-labelled tests
reuse the existing pinned Redis 7.2.11 TCP/TLS harness and fixture certificates,
without a Python Redis package or OpenSSL CLI. They verify ordered SET/GET,
counters and server errors with later successful writes, MGET arrays, eight
commands, authentication/SELECT/RESET and CLIENT ID pool reuse. Run them with:

```sh
ctest --test-dir build -R '^test_redis_pipeline_live_' --output-on-failure -j1
```
