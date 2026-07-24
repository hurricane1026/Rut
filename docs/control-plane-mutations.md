# Control-Plane Mutation Contract

Status: accepted contract; runtime implementation is staged in TODO.md.

Rut exposes control-plane reads (`stats()` and `metrics()`) as bounded values
latched at handler entry. Mutations are different: they change process-wide
state and therefore need an explicit authority, a visible failure result, a
total publication order, and a deterministic harness model.

This document defines those boundaries for `reload()` and
`upstream.mark(server, healthy:)`. An implementation must not accept either
source form until it implements the corresponding contract end to end.

## Source contract

```rut
route POST "/admin/reload" {
    guard reload() else { return 503 }
    return 202
}

timer check_health, every: 5s, shard: 0 {
    for server in users.servers {
        let healthy = check(server)
        guard users.mark(server, healthy: healthy) else { return }
    }
}
```

The canonical signatures are:

```text
reload() -> bool
Upstream.mark(Server, healthy: bool) -> bool
```

Both calls are synchronous, bounded, non-suspending operations. They never hide
a yield and therefore never imply that a reload compile or cross-shard drain
completed before the call returned.

- `reload()` returns `true` only when this invocation claimed the process's one
  pending reload request slot. It returns `false` when route-triggered reload is
  disabled, the process is stopping, or a request is already pending/in flight.
  A `true` result means *accepted*, not *activated*; `202 Accepted` is the
  prescriptive route response.
- `mark` returns `true` only when it atomically published the requested manual
  override for a `Server` belonging to the invocation's pinned, retained config
  generation and override table. It returns `false` for a foreign identity, a
  retired generation/table, or when control-plane mutation is unavailable. A
  successful call is already visible through that table; it is not merely
  queued.

Ignoring either boolean is legal but explicit. The calls are values, not
statement-only special cases, so a route or timer can fail closed.

## Authority

Route-triggered reload is disabled by default and requires an explicit process
capability (the production CLI spelling will be `--allow-route-reload`). This
prevents a source typo or an accidentally exposed route from gaining process
mutation authority merely because the binary supports hot reload.

The flag is not application authentication. Rut source remains responsible for
placing the call behind the intended host/path/authentication policy. Operators
that do not want application-triggered reload leave the capability disabled and
use the separately authenticated process control channel (for example SIGHUP).

`upstream.mark` is timer-only and may appear only in a timer with an explicit
`shard: N` selector. In addition, one compiled program may have at most one
marking timer for a given upstream, including calls reached transitively through
helpers. The analyzer rejects a second marking timer even when the timers use
different shards. Timer code is trusted program code, while the shard pin and
single-timer rule provide one source-level writer and one program order for each
manual health override. Route handlers and un-pinned per-shard timers are also
rejected by the analyzer.

Invocations of that marking timer never overlap. If an invocation is still
suspended when another period expires, production and the harness skip that
tick and emit the same bounded skipped-tick event; they do not start or queue a
second invocation. The next eligible tick may start only after the active
invocation has torn down its program pin. Thus completion order cannot reorder
health publications from nominally later timer periods.

Publication does not invalidate an already admitted predecessor timer
registration. Until the registration's owner shard processes its install
boundary and retires it, an invocation pins that predecessor generation and
validates `Server` values against the retained predecessor table. Retirement
closes further admission before the table can be reclaimed. A predecessor mark
therefore cannot be silently rejected merely because `N+1` was published while
the owner shard was still installing it.

## Reload coordinator

One process coordinator owns the source path, compiler/JIT, active generation,
and all program lifetimes. Shards never compile and never install a candidate
directly.

The coordinator executes one request at a time:

1. Admit the request into the single slot and assign a monotonically increasing
   request id (busy SIGHUP attempts use the explicit terminal path below).
2. Compile/JIT a candidate without changing live registries or shard pointers.
3. Validate the candidate before publication:
   - every timer shard selector is valid for the unchanged process shard count;
   - listener resources are immutable across hot reload: bind address/port,
     transport/TLS policy, connection limits, and other accept-path security
     settings must exactly match the active generation. A change fails
     validation and requires a process restart; no candidate may publish while
     relying on a later fallible bind or on predecessor listener policy;
   - firewall/XDP policy is likewise restart-only in this contract. The candidate
     firewall declaration and compiled policy identity must exactly match the
     active generation; any source change fails validation before userspace
     publication. A future hot-swap design must stage and verify the replacement
     kernel program, then include its atomic attachment swap and rollback in the
     same generation commit. Loading or attaching it after the userspace install
     is forbidden;
   - every `persist: true` state declaration is compatible with the active
     generation. This covers Cache, Set, Bloom, Bitmap, LRU, Hash, and every
     future persistent registry, including declaration identity,
     key/value/struct layout, and type-specific capacity, sizing, hash, seed,
     and ownership parameters. Compatible generations normally retain the same
     shared runtime registry allocation. A replacement allocation is legal only
     behind a coordinator cutover barrier that first closes **whole invocation
     admission**, not merely state-operation admission. Once the barrier is
     visible, no new request, stream, timer callback, WebSocket callback, or
     detached operation may enter generation `N`; accepted transport work waits
     behind a bounded ingress barrier, with overflow receiving an explicit
     protocol-level busy result that is captured. The coordinator then drains
     every old-generation invocation and detached updater. It also tears down and
     drains every state-capable retained session (including an idle
     terminate-mode WebSocket whose next frame can re-enter old code) and every
     future callback or effect that can still acknowledge an `N` mutation. If any
     such pin cannot be closed and drained within the bounded migration policy,
     replacement migration is rejected; it may not copy around the pin. Only
     then does it copy the quiescent registry before publication. The barrier
     reopens only after the indivisible `N+1` install is committed or the
     candidate is abandoned.
     Copying while old pins can still acknowledge mutations, silently rejecting
     a state operation from an already admitted invocation, or attempting a
     post-publication delta transfer from a writable predecessor is forbidden;
   - every state declaration without `persist: true` receives a fresh stable
     allocation in `N+1`, even when its name and layout are unchanged. Its
     `N` allocation remains selected by predecessor pins and is reclaimed only
     after invocations, sessions, and detached operations drain. Publication
     never clears or reuses storage still reachable from `N`;
   - every runtime capability required by the candidate is available.
4. Publish the candidate's immutable config and handler bundle with one new
   generation number, then send one indivisible shard-install command carrying
   `(generation, config, handler bundle, generation-local runtime tables)` to
   every shard. Config and generated handlers are never separate mailboxes or
   separately observable swaps.
5. Wait for every shard to acknowledge installation at an event-loop command
   boundary. Before accepting another reload, also require that publishing it
   would not retain more than two adjacent generations. If generation `N`
   still has invocation or session pins after `N+1` is active, the coordinator
   delays or rejects `N+2` until those pins drain (or an explicit operator drain
   tears down the retaining sessions).
6. Reclaim an old program only after all shards acknowledged a newer generation
   and every invocation pin reached zero. Pins include HTTP/1 requests, HTTP/2
   streams, lifecycle invocations such as health timers that can suspend and
   later resume into the program, and terminate-mode WebSocket sessions that
   retain a route-supplied frame-handler callback. An accepted downstream TLS
   connection also pins the generation before any ClientHello/SNI callback can
   run and retains that pin through handshake completion or connection teardown;
   alternatively each selected SNI table and `SSL_CTX` must carry an equivalent
   independent reference. A WebSocket pin lasts from handler installation
   through session teardown, not merely through the HTTP upgrade request. A
   shard installation acknowledgement does not cancel or drain a suspended
   invocation, TLS handshake, or open WebSocket session.

The generation whose process-startup `init` hook ran is a separate lifecycle
owner. Its compiled lifecycle bundle remains pinned until process shutdown has
run that same generation's paired `shutdown` hook, even if a reload replaces all
request handlers and every ordinary invocation pin reaches zero. Reload does not
run a candidate generation's `init`, substitute its `shutdown`, or reclaim the
startup bundle. A future design may instead define paired per-generation
shutdown/init transitions, but it must complete the old shutdown before reclaim
and the new init before publication; mixing hooks from different generations is
forbidden.

Installation also retires old-generation timer registrations before a shard
acknowledges. The shard removes the old scheduled tick and drains any callback
already queued at its command boundary. If a predecessor invocation is active
or suspended, the replacement remains disabled until that invocation releases
its pin; the final release enables the replacement on its owner shard. Thus an
idle callback can never target reclaimed code, and old and replacement timer
invocations cannot overlap across generations.

Installation also drains every idle upstream connection pooled under the
predecessor generation before acknowledgement. A connection completing after
that drain may return to a pool only when its pinned generation and stable
endpoint identity still match the installed config; otherwise it is closed.
Numeric `(upstream_id, backend_idx)` reuse alone never authorizes pooling, so a
replacement backend cannot inherit a socket connected to the old address.

Every built-in active-health probe owns a pin to the exact generation and probe
table it selected before asynchronous connect/send/receive begins. The pin lasts
through success, failure, timeout, cancellation, and final callback teardown;
closing the transport alone is not retirement while a completion remains queued.
A shard may acknowledge predecessor installation only after it either transfers
all such pins into the retained predecessor bundle or cancels and drains every
predecessor probe callback. Probe state and config identity therefore cannot be
reclaimed or numerically reused while an old completion can still publish.
Transferring a probe pin does not authorize the replacement scheduler to start a
second probe against the retained allocation. Each stable server has a shared
single-flight probe epoch across adjacent generations: `N+1` scheduling remains
disabled until the predecessor flight completes or is cancelled and drained.
Every completion compares its captured start epoch with the table's current
epoch before publishing, so even a stale queued completion that survives
transport cancellation is discarded rather than advancing the verdict/version.

Accepted cross-shard state operations own independent program pins. Enqueueing
an owner-shard `Hash.update` (or another compiled updater thunk) transfers a pin
from the request to the queue entry; client disconnect and request teardown do
not release it. The entry retains the old updater identity and program through
owner execution and until its reserved reply is delivered or explicitly
discarded. These detached pins participate in reclamation and the
two-generation admission bound.

Accepted detached `fire` operations follow the same lifetime rule. Before the
originating invocation can release its pin, each operation either transfers a
pin to the exact generation whose generated request, TLS, upstream, and callback
state it uses, retaining that pin through timeout, cancellation, and final
callback teardown, or materializes a bounded, pointer-free descriptor that owns
every required byte and cannot call generation-owned code. Generation-pinned
`fire` operations participate in predecessor drain and the two-generation
admission bound; request completion alone never makes them reclaimable.

Owner-shard state arbitration is part of capture as well. Every accepted
cross-shard operation records its stable registry allocation and key identity,
source event/request id, owner-assigned dequeue/linearization version, operation
kind, returned outcome, and resulting state version. Replay consumes that exact
owner order instead of reconstructing arrival order from concurrent source
shards. A missing, duplicate, or out-of-order owner record is `Unsupported`.

Compilation or validation failure is *definitely not applied*: the active
generation and every live registry remain unchanged. Publication has no
fallible step after the generation becomes visible. This rules out a result
where some shards report the new generation while the coordinator reports that
the same reload failed.

The process may temporarily serve two adjacent generations while shards reach
their command boundaries. Each request, stream, or yielding lifecycle
invocation pins exactly one program bundle, so its route table, handler code,
Cache schema, and upstream identities never mix generations. The coordinator
does not publish generation `N+1` until all shards acknowledged `N`; every shard
therefore observes the same strict generation order without skipped updates.
Shard acknowledgements alone do not admit `N+2`: retained pins on `N` keep the
admission gate closed, bounding live configs, JIT bundles, and override tables
to the active generation and at most one predecessor.

At a shard command boundary, installation is one release/acquire publication:
the default generation, route/upstream config, generated handler entry points,
timer registry, and generation-local health/override tables become visible
together, followed by one acknowledgement. No request may observe a candidate
config with predecessor code or candidate code with predecessor registries.
Implementations with independent config and JIT swap mailboxes do not satisfy
this contract.

Rate-limit state is generation-aware as well. Per-shard and process-global
buckets are selected by the invocation's pinned generation plus the rule's
stable declaration identity; numeric route/rule indexes alone are never keys.
Validation may map a bucket into the candidate only when the stable identity,
scope, key shape, window, burst, and limit policy are exactly compatible.
Compatible adjacent generations share the same bucket allocation and
linearization sequence; otherwise `N+1` receives a fresh table while `N` keeps
its table until the last predecessor pin drains. Installation must not reset
storage still reachable by old-generation work or let a reordered rule inherit
unrelated TAT state. Capture records every process-global and shard-local bucket
decision with its stable allocation identity, monotonically assigned decision
version, grant/reject result, exact monotonic admission-time sample, and
position in workload-event order. Replay consumes those versions and outcomes
rather than rerunning cross-shard CAS arbitration or local clock-based GCRA
refill; a missing or out-of-order decision or clock record is `Unsupported`.

Mutable upstream-selection state is split by its compatibility boundary.
Policy-specific cursors and PRNG state remain generation-local unless the stable
upstream identity, endpoint ordering, and complete policy are compatible;
reusing an `upstream_id` never aliases a round-robin cursor by numeric
coincidence. Per-server observations that span policies, including active
connection counts and latency/EWMA samples, instead use never-reused stable
server allocations. Compatible adjacent generations share those allocations
when upstream identity, endpoint identity, and the measurement semantics match,
even while both generations still serve traffic. Each acquisition returns a
token naming the exact server-state allocation, and its completion updates that
same allocation after reload. Thus `.leastConn`, `.ewma`, and custom selectors
in `N+1` observe work still owned by `N`; an incompatible endpoint or measurement
policy receives fresh state while the predecessor allocation drains.

Stateful isolation policies are not reset by an unrelated reload. Circuit
breaker and outlier allocations have never-reused stable identities and are
shared by adjacent generations only when the upstream/server identity and the
complete breaker/outlier policy are compatible. The shared allocation carries
failure counters, open deadlines, half-open admission tokens, ejection state,
and its versioned arbitration sequence. An incompatible candidate receives a
fresh allocation while the predecessor allocation remains reachable until its
last pin/token drains. Every transition and half-open admission is captured by
allocation identity and version; replay consumes that order rather than
starting a compatible breaker closed.

Any selection policy whose effective weights depend on monotonic time, including
`slowStart`, records the exact selection-time monotonic sample, the recovery
epochs and effective weights derived from it, and the chosen stable server
identity. Recording an exact chosen result is an equivalent bounded
representation only when the record also identifies the policy-state version
it observed. Replay consumes the recorded sample/weights or exact result and
never resamples its local clock during a ramp; a missing clock or effective
selection input is `Unsupported`.

Randomized policies are captured explicitly. Every `.random` selection records
the draw and chosen stable server identity; every `.powerOfTwo` selection
records both draws, the compared candidates and observed selection inputs, and
the winning stable identity (including the deterministic tie result). Replay
consumes those records instead of advancing a local PRNG. An equivalent format
may checkpoint the generation-local PRNG state at capture start and record every
subsequent draw, but a seed without the exact draw position is insufficient.
Missing, reordered, or incompatible randomized-selection input is
`Unsupported`.

SIGHUP, file-watch reload, and an accepted `reload()` request use this one
coordinator and the same validation path. For SIGHUP, the observable attempt
boundary is one record read from `signalfd`: Linux may coalesce multiple standard
SIGHUP sends before that read, and those unobservable sends are one attempt, not
several missing terminal records. Each observed record is a non-queued admission
attempt; when the slot is busy the coordinator assigns it a request id and
immediately emits its single terminal `busy` record with no candidate generation.
Capture records that observed delivery and replay consumes the same event and
record. An operator API that promises one result per sender action must use a
queueable, sequence-carrying channel (for example a Unix control socket/eventfd
queue or queued realtime signal), not standard SIGHUP semantics.

The inotify adapter may collapse one kernel burst for the same watched source
into one bounded, sequence-numbered file-watch event, but that debounce boundary
is part of capture. Each resulting event is then a non-queued coordinator
admission attempt exactly like SIGHUP: it receives a request id and either the
ordinary terminal result or an immediate terminal `busy` record. It is never
silently dropped, deferred until the active compile finishes, or coalesced with
a later captured event. Replay consumes the recorded source digest, debounce
sequence, admission result, and terminal record. An admitted signal or watch
event follows the ordinary compile, publication, and terminal-record path.
Route `reload()` retains its synchronous `false` busy result and consumes no
accepted-request id.

Shutdown first closes mutation admission. An accepted reload that has not
published is cancelled with a terminal `shutdown` failure record before shard
exit, leaving the active generation unchanged. Once publication is visible it
cannot be rolled back or reported failed: shutdown drives every installation
command to acknowledgement, cancels or drains old timer registrations, and
tears down or drains retaining sessions and detached state operations until the
publication emits its success record. Only then may shards exit and bundle
reclamation proceed.

## Manual upstream health

A `Server` value carries an opaque identity:

```text
(config_generation, upstream_id, backend_id)
```

It does not expose a raw runtime pointer. `upstream.mark` validates the
generation and upstream membership and publishes the process-shared bounded
override slot as one atomic transaction with respect to reload publication.
The event-loop call path must use a bounded nonblocking protocol, such as a
generation-tagged CAS or bounded try-lock. It must never wait for a coordinator
or descheduled shard to release a lock. Exhausted CAS attempts or lock
contention are visible as `false`, without consuming or modifying an override
slot. A reload cannot publish a generation between `mark`'s check and write; a
losing stale call likewise returns `false`. Selection consults the override
table belonging to the invocation or session's pinned generation before local
active/passive health state:

- `healthy: false` forces the target out of normal selection;
- `healthy: true` forces it into normal selection;
- a reload shares the stable override allocation when upstream identity,
  endpoint identity, and marking policy are compatible; replaced endpoints or
  policies receive a fresh empty allocation in the same atomic publication
  transaction that makes that generation active.

Publication does not clear or reuse the old generation's table. Lagging shards
and pinned old-generation work continue consulting it until every shard has
acknowledged the newer generation and all old-generation invocation/session
pins have reached zero. The coordinator then reclaims that table with the old
program bundle. Consequently a shard can never serve an old config after its
manual exclusions have disappeared, and compatible adjacent views preserve the
last published verdict while retaining generation-specific references for
pinned predecessor work.

Each generation table carries a monotonically increasing override version.
Every successful mark publication increments that version in the same atomic
operation as the slot update. A backend-selection capture records the pinned
generation and exact override version observed by its table read. Capture records
**every** mark attempt at its workload-event position, including its stable server
identity, requested verdict, boolean result, and a bounded reason (`published`,
`stale-or-foreign`, `unavailable`, or `contended`). Successful records additionally
carry the published version. Replay consumes failed attempts as well as successful
publication boundaries and orders selection reads by these versions; an omitted
attempt, mismatched reason/result, or unobservable version is `Unsupported`.
Recording only successful publications is not sufficient to reproduce handler and
timer control flow.

Override selection uses the request, stream, WebSocket session, or lifecycle
invocation's pinned config generation—not the shard's latest installed
generation. A shard acknowledgement changes the default generation for new
work only; resumed generation-`N` work continues reading generation `N`'s
retained table even after that shard installs `N+1`.

The active/passive probe-health table follows the same rule. It is keyed by a
stable server identity, not only the numeric `(upstream_id, backend_id)` pair.
Backend selection reads probe state through the invocation pin. Installing
`N+1` shares the stable health allocation when the upstream, endpoint, and
probe/passive-health policy are compatible, preserving active failures and
passive ejections. Replaced endpoints receive fresh state, while the predecessor
view remains valid until its pins drain. Thus a resumed invocation cannot lose
an `N` ejection or consume a verdict for an endpoint that merely reused the same
numeric slot in `N+1`.

Every active-probe completion and passive-failure/ejection mutation publishes a
monotonic version in its generation-scoped probe table. A backend selection
records the exact probe-table version observed together with its chosen stable
server identity; probe callbacks record their source event, resulting state,
published version, and event-loop position. Replay consumes those versions and
positions instead of rerunning callback timing. A missing, duplicate,
out-of-order, or unobservable probe version is `Unsupported`.

Upstream in-flight concurrency accounting is likewise identity-scoped. The
counter is owned by a never-reused stable upstream allocation identity. Its
compatibility predicate is independent of both balancing policy and endpoint
roster and of the configured `max_inflight` value: when validation proves the
same logical upstream and limit scope, adjacent generations share the allocation
even if the candidate changes policy, endpoints, or the limit. Each admission
compares the shared occupancy with the pinned generation's configured limit, so
a lowered `N+1` limit cannot admit new `N+1` work while predecessor acquisitions
already meet or exceed it. Only a changed logical-upstream identity or limit
scope receives a new allocation while its predecessor drains. Endpoint-scoped
selection, health, and measurement state still follows its stricter endpoint
compatibility rules. Every release token
contains the exact concurrency-allocation identity and acquisition version, so
completion decrements precisely the counter it acquired; numeric `(generation,
upstream_id)` coincidence alone never authorizes sharing. Capture records every
process-global acquire and release with that identity, a monotonic arbitration
version, the acquire grant/reject result, and workload-event position. Replay
consumes this order instead of rerunning `fetch_add` races; missing, duplicate, or
reordered arbitration is `Unsupported`.

The capture-start baseline also contains each live concurrency allocation's
counter value and every outstanding acquisition token, including its allocation
identity and acquisition version. A quiescent boundary with zero live tokens is
an equivalent baseline. Replay must establish that baseline before consuming a
release or later grant; absent or inconsistent initial occupancy is
`Unsupported`.

Retry-budget history is owned by a never-reused stable upstream allocation,
not by a numeric upstream slot. Validation shares the allocation across
adjacent generations whenever the logical upstream and complete retry/budget
policies are compatible, independently of endpoint roster changes. Endpoint
selection remains generation-scoped, but adding, removing, or replacing a
backend cannot reset upstream-wide retry history. An incompatible policy starts
a fresh allocation while `N` retains its history through predecessor drain.
Each retry grant/reject records the allocation identity, monotonically assigned
arbitration version, request/attempt identity, counters before and after the
decision, and workload event position. Replay consumes the recorded decisions
rather than rerunning process-global races; missing, duplicate, or reordered
decisions are `Unsupported`.

Manual state has priority over probe and passive-ejection state so a later local
probe cannot silently undo an operator program's verdict. Calls from the one
shard-pinned timer are ordered by program order. The generation check makes a
late invocation apply only to its pinned retained table; a foreign or retired
table is definitely not applied.

## Failure and observation

| Operation | Result | State change |
|---|---|---|
| reload capability disabled | `false` | none |
| reload already pending/in flight | `false` | none |
| SIGHUP while reload busy | terminal `busy` record | none; never queued or coalesced |
| file-watch event while reload busy | terminal `busy` record | none; never queued or deferred |
| reload accepted | `true` | request slot only; activation is asynchronous |
| shutdown before publication | terminal `shutdown` record | active generation unchanged |
| shutdown after publication | terminal success after drain | published generation finishes installation |
| candidate compile/validation fails | coordinator failure record | active generation unchanged |
| candidate activates | coordinator success record | all shards converge in generation order |
| mark uses stale/foreign `Server` | `false` | none |
| mark capability unavailable | `false` | none |
| mark synchronization contended | `false` | none |
| mark succeeds | `true` | shared override atomically updated |

Every accepted reload produces exactly one terminal coordinator record containing
the request id, old generation, candidate generation (if any), and success or a
bounded failure code. Production writes the record to structured logs and
counters. The harness exposes the same record directly to its oracle. No record
stores unbounded compiler text.

## Harness and replay

The harness control-plane port owns the same bounded state machine as
production:

- enabled/disabled/stopping authority state;
- the one-slot reload admission gate;
- deterministic compile/validation outcomes;
- captured SIGHUP/file-watch admission attempts and debounce sequence;
- per-shard generation acknowledgements and invocation pins, including
  request, stream, yielding lifecycle work, TLS handshakes, and retained
  WebSocket callbacks, plus active-health probe transports and queued
  completions;
- atomic config/handler/table installation acknowledgements;
- non-overlapping marking-timer state and skipped-tick events;
- generation-scoped manual-health override tables and observed override
  versions;
- generation-scoped probe health and upstream concurrency identities;
- versioned probe-health mutations and selection-observed versions;
- randomized backend-selection draws/results and PRNG baseline identity;
- versioned global rate-limit decisions and upstream-concurrency
  acquire/release arbitration;
- stable retry-budget allocations and versioned grant/reject arbitration;
- compatible circuit-breaker/outlier allocations, transition versions, and
  half-open admission arbitration;
- detached cross-shard operation pins and retired timer registrations;
- versioned owner-shard state-operation dequeue order and outcomes;
- persistent-registry compatibility, protected capture-start control-plane and
  registry state references, complete invocation checkpoints or a quiescent
  start boundary, and replay-artifact target identity;
- protected request/response, upstream, non-upstream I/O, WebSocket, downstream
  lifecycle, clock, entropy, and control-plane snapshot transcripts;
- complete generation-local load-balancer state, selection-time clock samples,
  effective weights/results, and observed versions;
- monotonic capture sequence and durable loss/gap status; and
- terminal mutation records.

Handler-layer runs may model admission and `mark` atomics. Reload activation
requires at least the `Process` execution layer because it owns compilation,
shards, and program lifetimes. A lower-fidelity layer must report
`Unsupported`, never synthesize a successful activation.

Replay input records mutation requests and coordinator outcomes, not wall-clock
thread timing. For every successful publication it also contains either a
bounded portable source/IR artifact rebuilt through the normal verifier for the
replay target, or a bounded compiled program/config artifact reference whose
digest and exact compatibility identity are covered by a compiler attestation
signed by a configured trusted artifact-store key. The identity includes
runtime build and program ABI versions, compiler/JIT ABI, target triple, pointer
width, endianness, object/relocation format, and required CPU features. Replay
validates the signature, trust root, identity, feature availability, and digest
before loading compiled code. An unsigned artifact, an untrusted signer, a
mismatch, or an unresolved artifact is `Unsupported`; capture-supplied digest
and ABI fields are never treated as provenance. Replay never installs code
merely because its bytes match a digest and never substitutes the initial target
for a later published program.

A portable source artifact is self-contained: it bundles the root source and
the exact bounded transitive import closure, including each importer's canonical
resolution identity/path, package identity, bytes, and authenticated digest.
Replay resolves imports only from that bundle and verifies the recorded closure
before compilation; it never consults the replay target's filesystem or module
cache. A missing, extra, cyclically inconsistent, unresolved, or oversized
closure is `Unsupported`. A self-contained verified IR artifact may omit source
imports only when its attested identity covers the complete lowered program.

Replay artifacts and routine traffic captures are secret-free. They never
serialize compile-time-resolved environment values, TLS private keys, raw
`Authorization`, `Cookie`, `Proxy-Authorization`, `X-API-Key`, or configured
sensitive-header values, or other secret bytes embedded in the live
program/config bundle or request. Sensitive request fields are tokenized before
ring or file serialization; their exact bytes live only in a separately
access-controlled encrypted replay-input provider referenced by an opaque
capability and provider-owned version handle. Redaction alone is insufficient
when a handler observes or forwards the value. The artifact records only the
opaque handle. It does not contain a plain digest, hash, or other offline
verifier of the secret.
Replay asks the access-controlled provider to resolve and validate the handle;
any comparison uses provider-internal state or a keyed verifier unavailable
with the capture. Missing or mismatched capabilities produce `Unsupported`. An
implementation that stores a fully resolved artifact instead
must keep it outside routine capture storage in an explicitly configured,
access-controlled encrypted artifact store; capture references still contain no
secret bytes.

Portable source/IR replay also records opaque protected-provider handles for
every compile-time `env()` input and reconstructs with exactly those resolved
bytes. If any compile-time input is unavailable, portable reconstruction is
`Unsupported`; replay may use only a compatible protected compiled artifact and
never consult the target process environment as a substitute.

Request bodies follow the same protected-input rule because they can contain
credentials and are semantically observable through `req.body` and forwarding.
For every nonempty captured body, the provider stores the exact bounded bytes
and the routine capture stores only its opaque handle and length. If the body is
larger than the configured bound, was not captured completely, or cannot be
resolved during replay, that request or capture is `Unsupported`; replay never
substitutes an empty, truncated, or invented body.

Streaming uploads additionally require an ordered transcript of every client
body read boundary: chunk bytes/length, EOF, read failure, timeout, cancellation,
and its event position relative to upstream sends, early upstream responses,
send completions, and teardown. Replay releases chunks only at those recorded
boundaries. Until that transcript is implemented, capture of a request forwarded
with `streaming: true` is `Unsupported`; final body bytes alone are insufficient.

Exact client network and firewall-visible identity is protected request input
as well. Each admitted connection, request, or stream records address family,
full source and destination addresses and ports, any trusted proxy-derived
address, SNI, JA3, TTL, TCP window, packet length, and every other
packet/ClientHello field inspected by the configured firewall. Replay installs
those exact inputs before firewall, route, rate-limit, or Rut handler
evaluation, using opaque provider handles when sensitive. Any missing inspected
field makes the capture `Unsupported`; replay never substitutes zeros or
target-observed metadata.

Firewall replay also requires the initial attached kernel-map contents and
visible version, not merely the userspace registry allocation. Every dynamic
map update records submission, Node Agent result, publication/version boundary,
and ordering relative to each packet evaluation; replay evaluates a packet
against the recorded visible version. Until this independently visible XDP-map
baseline and update transcript is implemented, beginning or continuing capture
while firewall state can be dynamically updated is `Unsupported`.

Response comparison covers exact observable bytes, not only status and content
length. Before production releases a response buffer, capture stores the
bounded status, headers, trailers, and body bytes in the protected provider and
records an opaque handle plus lengths in the completion record. Streaming
responses use an ordered chunk/trailer transcript. If any observable response
byte is unavailable or exceeds the configured protected-input bound, the
capture is durably incomplete and replay is `Unsupported`; equal lengths are
never evidence that bodies match.

Capture also records downstream disconnect, timeout, send-completion, and
cancellation events in workload-event order. Replay injects the same lifecycle
boundary so suspended handlers take the same cancellation/defer path and cannot
continue normally after a production disconnect. A missing lifecycle event or
ordering edge is `Unsupported`.

Every upstream operation that can affect Rut execution or downstream output has
a correlated protected transcript. It records stable endpoint identity,
connect/TLS outcomes, bytes sent, exact response headers/body/trailers, EOF,
timeout/cancellation/failure, and completion order relative to waits and other
workload events. Replay injects these completions instead of contacting a live
upstream. This applies to buffered forwarding, explicit upstream waits, health
checks, and detached operations. A proxy or upstream-dependent workload without
a complete bounded transcript is `Unsupported`.

Non-upstream operations through `IoPort`, including buffered file reads and raw
TCP/UDP receives, use the same bounded protected transcript and workload-event
ordering. Replay injects their exact results instead of touching the target
filesystem or network. A workload with an unrecorded or oversized result is
`Unsupported`.

Terminate-mode WebSocket capture records every inbound and generated outbound
frame with session identity, direction, opcode, FIN/fragmentation position,
close metadata, and workload-event order. Exact bounded payload bytes live in
the protected provider. Replay recreates frame arrival and callback order and
compares emitted frames byte-for-byte. A session with an omitted or truncated
frame event invalidates the capture; recording only its HTTP upgrade is never a
complete workload.

Passthrough `websocket(upstream)` is a full-duplex byte tunnel rather than a
terminate-mode frame callback. It requires an ordered bidirectional transcript
of client/upstream reads, exact bounded bytes, writes, send completions,
backpressure pauses/resumes, half-closes, failures, and teardown. Until that
tunnel transcript is implemented, any capture that upgrades into passthrough
mode is `Unsupported`; the HTTP upgrade record does not make it complete.

Rut-visible environment results form another protected transcript. Each
invocation records, in call order, every value returned by `time.nowMicros()`,
`randomBytes()`, `uuid()`, and future clock or entropy APIs. Replay consumes
those exact values rather than deriving them from capture completion timestamps
or local entropy. Missing, extra, or reordered calls are `Unsupported`.

Runtime-internal clocks are deterministic inputs too. In particular, capture
records every monotonic sample used by response throttling together with its
bucket update, pause/read decision, timer arm/fire, resume decision, and event
position relative to upstream reads and lifecycle events. Replay consumes those
samples and decisions from the same ordered transcript. A throttled workload
without this complete internal-clock transcript is `Unsupported`, even when all
Rut-visible clock calls were recorded.

Every workload and mutation record carries a monotonic capture sequence number,
correlation identity, and source `shard_id`. A request or HTTP/2 stream receives
both its stable identity and workload-admission sequence **before** generation selection or any
handler, firewall, limiter, or state effect; completion carries that identity
and never allocates the workload sequence retroactively. Timer invocations,
WebSocket frames, detached callbacks, and other workload entries receive their
sequence at the equivalent admission/arrival boundary. Later effect and
completion events have their own event-order positions correlated to that
admission identity, so faster request B completion cannot make B appear to have
entered before yielding request A.

Replay dispatches every admission, frame, timer, and callback to its recorded
source shard before executing it; it never lets the local accept/load-balancing
policy choose another shard. If the recorded shard count or identity cannot be
recreated, replay returns `Unsupported` before workload execution. This preserves
per-shard Cache state, local limiter buckets, snapshots, and other shard-owned
inputs.

For HTTP/2, the protected transcript additionally records every inbound and
generated outbound frame in connection order, including `SETTINGS` and its ACK,
`WINDOW_UPDATE`, `RST_STREAM`, `PING`, and `GOAWAY`, with connection/stream
correlation and the flow-control/HPACK version observed after each frame. Replay
injects that transcript at the recorded event positions. Until this ordered
control-frame transcript and correlated per-stream request/completion records are
implemented, admitting any HTTP/2 connection while capture is enabled durably
invalidates the capture; request records alone are not a complete substitute.

Ring overflow, a truncated-request-header flag, or any other dropped or
truncated record atomically invalidates the capture and persists a loss/gap
marker outside the lossy ring; the writer cannot later present that artifact as
complete. Until production emits the correlated HTTP/2 stream and control-frame
transcript specified above, admission of any HTTP/2 connection while capture is
enabled must set that same durable loss marker. Replay rejects an invalid marker, a
sequence gap, a truncated header block, or a duplicate/out-of-order record as
`Unsupported` before comparing behavior.

Before the first workload event, replay establishes the exact control-plane
baseline. The capture references either a bounded, schema-identified encrypted
checkpoint or a complete ordered pre-capture mutation/install history. It
includes the active and retained program generations and artifacts, each
shard's installed generation, outstanding invocation/session/lifecycle/`fire`
pins, any admitted reload and its request id/phase, the next request and event
sequences, generation-scoped override and probe tables with their versions,
timer/debounce state, and initial rate-limit, retry-budget, and concurrency
arbitration state (including live acquisition tokens), plus complete
circuit-breaker/outlier allocation state: failure counters, open deadlines,
half-open tokens, ejection state, and arbitration versions. It also includes
every generation-local load-balancer cursor and PRNG position, per-server live
connection counts and tokens, latency/EWMA samples, passive-health inputs, and
other mutable field visible to a built-in policy or Rut `Server` value. Each
subsequent mutation carries a monotonically ordered version, and every selection
or custom Rut observation records the exact version it read.

Idle upstream connection pools are baseline state, not an invisible optimization.
Capture must either checkpoint every reusable socket with its stable endpoint,
generation, protocol and negotiated TLS/session identity, pool position, and exact
reusability state, or drain and close all idle upstream pools at the capture
boundary before assigning the first workload-event sequence. Replay restores the
checkpointed pool before admitting work, or starts with the correspondingly empty
pool after a recorded drain. A socket count or generic "idle" marker is
insufficient because it cannot reproduce whether the next operation reuses a
connection or performs connect/TLS setup.

Hostname-backed upstreams additionally require the exact per-shard DNS cache
baseline (address/SRV roster with stable server identities, TTL/expiry and
monotonic sample, negative-cache and last-known-good state) plus every ordered
post-baseline resolution, expiry, refresh, and failure event. Until that bounded
schema and event transcript are implemented, starting or continuing capture
with a hostname-backed upstream is `Unsupported`; replay never consults live DNS
or silently re-resolves a captured hostname.

The automatic RFC response cache used by `cache: .auto` is also baseline state.
Capture must either checkpoint every warm entry with its response bytes,
freshness/age state, `Vary` key and request metadata, eviction/order metadata,
and all later cache mutations, or drain and invalidate the automatic cache before
assigning the first workload-event sequence. Replay restores the checkpoint or
starts from the correspondingly recorded empty cache. Starting from an
unrecorded empty cache when production could serve a warm hit is `Unsupported`.
Each post-baseline lookup also records its monotonic lookup-time sample, selected
entry/version, and exact outcome (`fresh hit`, `stale hit` including any
revalidation scheduling, or `miss`) in workload-event order. Replay consumes
that decision before issuing any corresponding upstream operation; freshness
metadata without the lookup clock and outcome is not a deterministic transcript.

Per-shard and aggregate stats/metrics counters, histograms, and snapshot epochs
are checkpointed in the baseline. As an equivalent bounded representation,
each invocation may record the exact entry-latched `stats()`/`metrics()` snapshot
it observed. Replay never assumes a zero snapshot when capture begins after
traffic. It resolves all baseline state through the protected state provider
and installs it before consuming traffic. Missing, unauthorized, inconsistent,
or unbounded baseline state is `Unsupported`; replay never starts from an empty
control plane or assumes every shard already has the latest generation.

Capture normally starts at a quiescent workload boundary: all idle upstream pools
have also completed the recorded drain described above, and there are no live
accepted client connections (including idle HTTP keep-alive, HTTP/2, TLS, or
WebSocket transports), admitted requests/streams, suspended timer or WebSocket
callbacks, pending completions, or detached operations capable of later
effects. If a live-start mode is offered instead, the protected checkpoint must
contain the complete bounded execution and transport state for every live
connection and outstanding pin: TLS/session state, HTTP parser state, HTTP/2
peer settings, HPACK dynamic tables, stream registry and flow-control windows,
keep-alive/pipeline buffers, program counter/resume state, locals,
request/session and protocol buffers, pending I/O/completion, callback state,
owned effects, and correlation/event sequence. Replay restores connections and
invocations before the first post-baseline event. A pin count, generation id, or
"idle" connection marker alone is insufficient; any live transport or in-flight
state that cannot be checkpointed exactly makes live-start capture
`Unsupported`.

The input additionally records the logical program-publication event, every mark
attempt with its requested verdict, boolean result, bounded failure reason,
workload-event position, and successful publication version when present; the
override and probe-table versions observed by each backend selection; every
probe-health mutation, retry-budget decision, load-balancer state mutation and
observed version, randomized backend-selection draw/result, marking-timer skipped
tick, and each shard's installation acknowledgement in workload-event order.
Post-baseline StatePort operations are
recorded with stable allocation/key identity, owner dequeue version, outcome,
and resulting state version, so concurrent source shards cannot reverse Hash or
other registry effects during replay. It also establishes the persistent state
present when capture begins, but registry contents never enter the routine
traffic capture. An explicitly configured protected state provider stores
either a bounded, schema-identified encrypted checkpoint of every retained
Cache, Set, Bloom, Bitmap, LRU, Hash, and future registry, or an encrypted
complete ordered StatePort effect history that reconstructs the identical
baseline before the first workload event. The capture contains only an opaque,
non-enumerable capability and provider-owned version handle; it contains no
content digest or offline verifier. The protected artifact includes allocation
identity, contents, eviction/order metadata, versions, the exact keyed-hash seed
and every equivalent hashing/set-selection parameter for each allocation, and
any accepted detached operation that can still mutate it. Restoring slots under
a newly initialized seed is forbidden; an implementation that cannot restore the
recorded seed rejects the checkpoint as `Unsupported`. Replay resolves it through
the access-controlled provider, and a missing, unauthorized, mismatched, or
unbounded representation is `Unsupported` rather than starting from empty
state. These boundaries select which adjacent generation
handles every interleaved request, stream, WebSocket frame, or timer resume
without reproducing thread timing. A replay must reproduce the same
accepted/rejected calls, per-shard installations, generation choices, program
artifacts, state effects, arbitration decisions, and terminal records.

## Required implementation order

1. Add the control-plane mutation port and deterministic admission/override
   model to the handler ABI and harness.
2. Implement `Server` identities, `Upstream.servers`, and the shared manual
   health override consulted by both network backends.
3. Lower and execute timer-only, shard-pinned `upstream.mark`.
4. Implement the reload coordinator, generation acknowledgements, program pins,
   compatibility validation, SIGHUP, and process-harness coverage.
5. Lower route-only `reload()` after the same coordinator is the sole activation
   path.
