# Workload fixtures and offline policy selection

A URL normally declares one workload class. Mixed testing means different
URLs sharing one gateway/shard, not randomly changing the class of one URL.

A workload describes the application/protocol behavior to exercise. It is not a
prediction of the next upstream response. Production relay admission continues
to inspect the actual response framing and transport eligibility.

Use [the builtin fixture routes](../examples/workload/fixtures.rut) for synthetic
local responses. A local `workload` response does not perform upstream reads or
enter the proxy splice path. To measure proxy policies, use the recorded origin
fixtures through `forward`; do not equate local-handler throughput with proxy
throughput.

| Workload | Fixture | Main question | Metric used to choose a policy |
| --- | --- | --- | --- |
| Tiny response | 512 bytes, immediate | Dispatch/syscall overhead | RPS and response p99 |
| Fast API | 4 KiB, immediate, request-specific header | Small proxy request cost | RPS and response p99 |
| Medium response | 64 KiB | Copy/relay transition | RPS and response p99 |
| Static medium | 256 KiB | Sustained body transfer | RPS, MiB/s, response p99 |
| Static large | 1 MiB | Transfer segment size and fairness | RPS, MiB/s, response p99 |
| Delayed API | 4 KiB after 1 ms application delay | Origin service latency vs gateway scheduling | RPS and response p99, with direct-origin reference |
| Fragmented response | 256 KiB, 16 KiB writes, 0.2 ms source delay | Repeated source readiness | RPS and response p99; source delay is part of the workload |
| Mixed response sizes | 96 large `/proxy` / 32 small `/api4k` persistent connections | Fairness under bulk transfers | Byte-weighted goodput subject to **small-client** p99 bound; retain each URL’s RPS and p99 |
| Interactive WebSocket | 64-byte binary messages, echo round trips | Bidirectional scheduling | Messages/s and message RTT p99 |
| Bulk WebSocket | 64 KiB binary messages, echo round trips | Bidirectional copy throughput | MiB/s and message RTT p99 |
| Chunked bulk stream | 16 chunks × 4 KiB | Incremental publication | MiB/s, first-chunk and chunk-delivery p99 |
| Live stream | 256-byte chunks with 1 ms source cadence, 2048 chunks/response | Long-lived delivery and jitter | Chunk-delivery p99, first-chunk p99, client and source inter-chunk gaps |

The WebSocket fixture is a transparent tunnel, not the runtime's per-message
inspection/termination mode. Timed echo messages carry a sequence number; RTT starts at socket publication
after preparing the masked frame. Masking still consumes client throughput.
Its preflight checks the Upgrade accept, masked
client frames, binary fragmentation, ping/pong, and the close handshake. These
results do not cover TLS, WebSocket compression, text inspection, HTTP/2, or
slow consumers. The streaming fixture uses HTTP/1.1 chunked binary responses;
it is not a claim of SSE application semantics.

Application records are decoded independently of HTTP chunk boundaries: a
proxy may split or coalesce wire chunks without changing the stream.

The live-stream origin timestamps each record immediately before writing it.
Client delivery delay therefore includes the origin write/transport path,
gateway, and client scheduling. It is not gateway-only latency. Source and
client inter-chunk gaps are retained separately to distinguish origin cadence
from additional delivery jitter. No complete-response p99 is assigned to an
ongoing stream.

## Candidate policies

The experimental runtime branch `study/upstream-workload-policy-20261010`
exposes `RUT_STUDY_POLICY`. This variable is an offline experiment setting;
main/production builds do not promise to interpret it. Startup logs must show
the requested policy and actual backend before a result is accepted.

| Policy | Event batch | io_uring body segment | io_uring shared turn budget | Ordinary-CQ observation limit | epoll body segment / owner budget |
| --- | ---: | ---: | --- | ---: | --- |
| `latency` | 32 | 64 KiB | 8 calls / 512 KiB read + write | 20 µs | 64 KiB / 2 calls |
| `balanced` | 64 | 64 KiB | 16 calls / 1 MiB read + write | 80 µs | 64 KiB / 4 calls |
| `current` | 256 | 128 KiB | 16 calls / 1 MiB read + write | 80 µs | 64 KiB / 4 calls |
| `throughput` | 256 | 128 KiB | 32 calls / 2 MiB read + write | Yield disabled | 128 KiB / 8 calls |

A CQ observation limit is a fairness heuristic, not a latency guarantee.
The turn byte budget accounts both read and write operations. Profiles change
several settings together: screening identifies a candidate, not causality.
Further isolated parameter experiments are required to attribute a gain.

Small Content-Length responses, WebSocket tunnels, and chunked streams do not
enter the guarded large Content-Length splice path. In those cases `current`
and `throughput` have identical effective settings, so only the three distinct
event-batch settings are compared. Large-body segment changes cannot optimize
WebSocket message latency by themselves.

## Selection and validation

Frontend runs are serial. The baseline study uses one frontend worker on CPU 2,
four origin workers on four separate physical cores (3, 4, 8, 9), and clients on
cores 5 and 7. CPU numbering is host-specific; inspect topology before reusing
these settings. Never run the HTTP and protocol studies concurrently.

1. Measure direct-origin capacity/reference with the same clients and workload.
2. Screen distinct policies; confirm current, the throughput candidate, and the
   latency candidate with three rotated repetitions. Confirm all four
   policies for the cross-URL mixed workload so intermediate tradeoffs are not
   lost when one policy maximizes small-request count.
3. Throughput selection permits at most a 10% increase in median p99 relative
   to `current`, and requires at least 3% measured throughput improvement to
   replace `current`. Mixed-size workloads use small-client p99 and byte-weighted goodput;
   adding small and large request rates would conceal lost bulk throughput. Streaming
   requires both first-chunk and delivery p99 to satisfy the bound.
4. Retain individual runs and ranges. A median gain alone does not establish
   significance. The recommended throughput policy stays `current` when its rate range
   overlaps the candidate range; retain that candidate separately for further
   testing. Range separation is an observation, not a statistical confidence
   interval. Confirm at other concurrency levels before deployment.
5. Keep a separate latency-priority result; require at least a 5% median p99
   improvement and non-overlapping observed p99 ranges to recommend it. A lower rate may be appropriate for
   a latency-sensitive application, but it must be an explicit choice.

All HTTP results require exact-body/reuse/slow-reader preflight and zero warmup
or measurement errors. WebSocket/stream clients compare every received payload
and stream sequence. Failed cases remain on disk and stop the study; they are
not discarded from a successful-looking table.

The protocol clients and API origins use Python's standard library. Protocol
rates are messages/chunks per second, not wrk HTTP RPS. The direct-origin test
exposes a possible client/origin ceiling; a gateway close to that ceiling cannot
be assigned an unconstrained maximum-throughput claim. Pure delayed/live
workloads can be cadence-limited and need no special gateway policy.

Run the HTTP study with `scripts/nginx_benchmark/workload_strategy.py`; run the
protocol study with `scripts/nginx_benchmark/protocol_strategy.py` afterwards.
For example, on the measured eight-core host:

```bash
python3 scripts/nginx_benchmark/workload_strategy.py \
  --output /tmp/workload-study \
  --relay-script scripts/nginx_benchmark/relay_compare.py \
  --rut /path/to/experimental/rut \
  --converter /path/to/rut-nginx-convert --wrk /path/to/wrk
python3 scripts/nginx_benchmark/protocol_strategy.py \
  --output /tmp/protocol-study --rut /path/to/experimental/rut \
  --harness scripts/nginx_benchmark/run.py
```

Both retain binary hashes, configuration, raw measurements, and selection
summaries. Neither modifies production source or merges a PR.

Per-URL declarations in these examples select workload **handlers**, not runtime
performance policies. The experimental policies currently apply to a whole
shard. A future route/upstream policy table should remain shared configuration;
copying a full policy into every Connection is unnecessary. Shared shard event
batching also cannot honestly be represented as an independent per-URL knob.

## Route selection and optional work queues

A matched route can look up its shared policy once. Avoid moving Connection
objects or storing a full policy per connection. A subsequent request on the
same HTTP connection can select another URL and policy.

Separate ready-work queues would primarily control fairness and batch progress;
saving a few predictable strategy branches alone does not justify them. Keep
the current ownership/callback structure for this study. Consider a small number
of strategy-class queues only if measured cross-URL tail latency requires them,
with ID/episode authentication and the existing cancellation/close ordering.

## Follow-up identified during the study

The retained io_uring scheduler calls `flush_deferred_relay_reads` even when the
relay queue is empty. Its current implementation still reads the clock and
peeks at the CQ in that case. The 64 KiB response logs confirm zero splice calls
while recording these probes. An empty-queue early return is a concrete future
experiment for API/WebSocket/chunked paths; it has not been measured here and
no performance benefit is claimed. It relies on actual ready-work state, not
a URL-based response-size prediction.

## WebSocket receive experiments

The tunnel now enables TCP_NODELAY on its two owned sockets after the actual
101 response. Ordinary HTTP upstream sockets retain their existing default:
36 serial HTTP measurements (512 B, 4 KiB API, 1 MiB, both backends, three
repetitions) did not establish a stable throughput gain from upstream NODELAY.

The io_uring correctness control uses bounded one-shot receive windows. The
experimental multishot cache retains provided buffers when a paired send owns
the fixed receive window or there is insufficient room. It drains those blocks
in connection/direction order into the existing copy/send path. This is not
zero-copy forwarding and does not predict payload size. Metadata is shard-owned;
each retained completion pins its connection slot until delivery. Cache mode
is opt-in in the experimental study binary (`RUT_STUDY_WS_RECV=cache`), not
production configuration. Its performance must be compared with the one-shot
control using the same binary and TCP_NODELAY settings.

Protocol benchmark nginx uses `keepalive_requests 1000000` to maintain its
long-connection workload throughout the timed interval, plus a 65536 descriptor
limit. The default 1000-request limit closed every streaming client connection
in an earlier run; that failed run is retained and excluded from valid results.
This setting is a benchmark control, not a production recommendation.

## Confirmed protocol candidates (2026-10-10)

At one frontend core and 128 connections, three repetitions retain `current`
for both WebSocket sizes and live streaming. io_uring chunked bulk has a
`balanced` throughput candidate: +12.9% median throughput with delivery p99
roughly unchanged; epoll chunked-bulk rate ranges overlap, so retain `current`.

Multishot held-block caching is correct in the exercised burst/backpressure/close
paths, but the current copy-on-drain implementation loses 17.3% large-WebSocket
throughput and increases RTT p99 by 27.5% versus the one-shot control. Keep it
experimental. Direct block sends and fewer completion/copy stages remain
follow-ups; no speedup is claimed for them. These are measured offline choices,
not automatic per-URL runtime policies or global optima.

## Latest WebSocket confirmation

The [retained io_uring relay benchmark](benchmarks/iouring-relay-2026-10-10/README.md)
uses a frozen study binary, one frontend core, four origin cores, and three
rotated repeats with verified tcpkali2 payloads. At 64B, bounded-cache multishot
receive with asynchronous sends measured 97,574 messages/s versus nginx 83,986
(+16.2%), with p99 2.517ms versus 2.729ms. At 1KiB it measured 88,480 versus
77,808 (+13.7%); p99 was effectively unchanged (2.767ms versus 2.777ms).
The immediate-send combination was slower. At 16KiB the existing copy/splice
profile remains substantially faster; do not enable multishot globally.

All runtime strategy switches remain opt-in study settings. These measurements
precede the integration onto current main; correctness checks were rerun on
the integrated branch, but its final head was not performance-confirmed.
