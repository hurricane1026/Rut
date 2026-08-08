# Control-Plane Mutation Contract

Status: accepted contract. The shared mutation port, handler ABI capability,
JIT helper boundary, production event-loop injection, deterministic harness
fixture, shard-pinned `upstream.mark` source lowering, generation installation
acknowledgements, exact program pins, and the process reload coordinator are
implemented. `upstream.mark` remains unavailable in production compiler output
until capture artifacts persist its ordered replay events.

Rut exposes control-plane reads (`stats()` and `metrics()`) as bounded values
latched at handler entry. Mutations are different: they change process-wide
state and therefore need an explicit authority, a visible failure result, a
total publication order, and a deterministic harness model.

This document defines those boundaries for `reload()` and
`upstream.mark(server, healthy:)`. An implementation must not accept either
source form until it implements the corresponding contract end to end.

## Source contract

```rut
upstream users { backends: ["127.0.0.1:8080", "127.0.0.2:8080"] }
func check(_ server: Server) -> bool => true

route POST "/admin/reload" {
    guard reload() else { return 503 }
    return 202
}

timer check_health, every: 5s, shard: 0 {
    for server in users.servers {
        let healthy = check(server)
        guard users.mark(server, healthy: healthy) else { return 503 }
    }
    return 200
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
  disabled, the process is stopping, a request is already pending/in flight, or
  admitting another candidate would exceed the two-adjacent-generation bound
  because a predecessor remains pinned.
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

Route-triggered reload is disabled by default and requires the explicit process
capability `--allow-route-reload`. This
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
   request id (busy SIGHUP attempts use the explicit terminal path below). At
   this boundary the source provider creates a provider-owned immutable
   snapshot and binds its version handle to the request id. All root and import
   resolution for the request occurs inside that one snapshot; later filesystem
   contents are never consulted.
2. Compile/JIT a candidate without changing live registries or shard pointers.
3. Validate the candidate before publication:
   - every timer shard selector is valid for the unchanged process shard count;
   - listener resources are immutable across hot reload: bind address/port,
     transport/TLS policy, connection limits, and other accept-path security
     settings must exactly match the active generation. Certificate material
     and SNI certificate mappings are the sole exception: validation stages and
     verifies a complete replacement `SSL_CTX` set before publication, while
     existing handshakes retain their selected context. Compatible contexts
     share a stable resumption allocation containing session-ID caches,
     ticket-key epochs, live OCSP staples, validity windows, and refresh
     ownership; publication cannot expose an empty or stale replacement. Any
     other listener-policy change fails validation and requires a restart;
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
     detached operation may enter generation `N`. Accepted HTTP/1 connections
     and requests and HTTP/2 streams wait in one configured bounded FIFO;
     overflow receives `503 Service Unavailable` plus `Connection: close` for
     HTTP/1, and `RST_STREAM(REFUSED_STREAM)` for HTTP/2. An arriving frame for
     an established terminate-mode WebSocket is not queued: the session closes
     with code `1013`. A timer deadline or detached callback that reaches this
     barrier is skipped once with an ordered `cutover-admission-skip` record and
     resumes only at its next ordinary scheduling opportunity. Accepted
     transports already inside the FIFO remain open and wait; no work type has
     an unbounded queue. Every enqueue, overflow, close, skip, and later
     admission is captured with its ingress position. The coordinator then drains
     every old-generation invocation and detached updater. It also tears down and
     drains every state-capable retained session (including an idle
     terminate-mode WebSocket whose next frame can re-enter old code) and every
     future callback or effect that can still acknowledge an `N` mutation. If any
     such pin cannot be closed and drained within the bounded migration policy,
     replacement migration is rejected; it may not copy around the pin.
     Quiescence authorizes a copy only when layout, hashing semantics, and
     capacity are representation-compatible. An incompatible schema requires a
     separately declared, bounded, verifier-approved migration whose capacity
     proof covers every retained entry; without one, validation rejects the
     reload rather than truncating, reinterpreting, or resetting state. Only
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
   rejects `N+2` admission until those pins drain (or an explicit operator drain
   tears down the retaining sessions). Route `reload()` returns `false` without
   claiming the slot or request id. An observed SIGHUP or file-watch attempt
   receives a request id and immediate terminal `generation-limit` record; a
   file-watch attempt also follows the dirty-slot rule below. No source waits in
   the slot for an unbounded predecessor lifetime.
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

The snapshot provider resolves the root and iteratively discovered imports to a
closed manifest containing each canonical path, exact bytes, content identity,
and import edge. Parsing may discover the closure incrementally, but every read
uses the request's immutable provider version. Before compilation succeeds, the
provider seals the complete transitive manifest and rejects path aliases,
resolution outside the snapshot namespace, or an import absent from that
version. The candidate generation records the sealed manifest identity.
Mapping the root and later opening imports from the mutable live filesystem is
forbidden, even if per-file metadata appears unchanged. If the configured
provider cannot supply an atomic immutable view of the entire resolution
namespace, reload admission fails with a source-snapshot terminal error; it
never compiles a best-effort mixture of revisions.

The generation whose process-startup `init` hook ran is a separate lifecycle
owner. At startup, its `init`/`shutdown` code and immutable dependencies are
retained as one dedicated lifecycle artifact, separate from the reloadable
request-handler/config bundle. That artifact owns every immutable object and
runtime allocation transitively reachable by either hook, including otherwise
generation-local Cache, Set, registry, and port tables. It remains pinned until
process shutdown has run the paired `shutdown` hook; a reload is rejected when
those dependencies cannot be separated and retained safely. Unreachable startup
request handlers and config are not retained, and the artifact is not counted as
a served generation. Reload does not run a candidate generation's
`init`, substitute its `shutdown`, or replace the dedicated startup artifact. A
future design may instead define paired per-generation shutdown/init transitions,
but it must complete the old shutdown before reclaim and the new init before
publication; mixing hooks from different generations is forbidden.

Validation rejects a candidate whose request handlers, timers, or runtime tables
depend on side effects that only its unexecuted `init` hook would create. A
reload candidate may depend only on staged resources validated before
publication, retained startup-owned resources, or generation-local allocations
whose construction is part of the indivisible install. Publication never
speculates that candidate initialization will succeed afterward.

Installation also retires old-generation timer registrations before a shard
acknowledges. The shard removes the old scheduled tick and drains any callback
already queued at its command boundary. If a predecessor invocation is active
or suspended, the replacement remains disabled until that invocation releases
its pin; the final release enables the replacement on its owner shard. Thus an
idle callback can never target reclaimed code, and old and replacement timer
invocations cannot overlap across generations.

A periodic timer's stable declaration identity is its canonical source-module
identity plus declared timer name. Matching names reached through a different
module or import alias do not collide. Two matched timers are cadence-compatible
only when their owner shard set, period, scheduling/non-overlap mode, and
compiler-produced semantic identity are identical. That semantic identity
covers the complete lowered timer body, every transitively called helper and
immutable captured declaration, and all timer declaration fields that can
affect execution. Source-location-only changes do not affect it.

Cadence-compatible timers transfer the predecessor's pending monotonic deadline
and cadence phase to the replacement; installation does not restart their
period. Any predicate mismatch makes the timer changed: the predecessor
registration is retired and the replacement anchors its first deadline
explicitly to installation time on its declared owner shard. In particular, a
shard, period, body, helper, or captured-dependency change never inherits the
old deadline. Transfer, cancellation, new deadline, compatibility identities,
and anchor choice are captured as ordered scheduling events.

If that deadline becomes overdue while a predecessor invocation keeps the
replacement disabled, final pin release skips all missed ticks and advances the
deadline by the smallest whole number of periods that places it strictly after
the release-time monotonic sample. It emits one ordered
`timer-overdue-skip(old_deadline, release_sample, missed_periods, new_deadline)`
record. The replacement never fires immediately and never queues catch-up
invocations.

Installation also drains every idle upstream connection pooled under the
predecessor generation before acknowledgement. A connection completing after
that drain may return to a pool only when its pinned generation and stable
endpoint identity still match the installed config; otherwise it is closed.
Numeric `(upstream_id, backend_idx)` reuse alone never authorizes pooling, so a
replacement backend cannot inherit a socket connected to the old address.

Stable endpoint identity covers every input that affects connection
establishment, authentication, wire protocol, or safe pool reuse. It includes
address family and address/port, transport, source bind/interface/namespace and
relevant socket options, PROXY-protocol mode, TLS enablement, SNI, ALPN,
verification policy and name, trust roots, cipher/version policy, client
certificate and key identity, resumption context, and protocol framing or
upgrade mode. The canonical identity also includes any future connection policy
field unless that field has an explicit pool-compatibility rule. A difference
in any such input creates a new endpoint identity; a predecessor connection
that completes after drain is closed and can never enter the replacement pool.

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

For a compatible endpoint and probe policy, the stable scheduler allocation
also transfers the pending deadline, cadence phase, cursor, and single-flight
epoch. A changed policy that still schedules active probes uses an
installation-time anchor, starts in `warming`, retains any predecessor
unhealthy/ejected verdict, and cannot enter normal selection until its first
successful replacement probe publishes; validation rejects the reload if the
replacement policy cannot schedule that probe.

A changed policy that removes active probing never enters that probe-dependent
`warming` state. Installation atomically discards the predecessor's active-probe
verdict and publishes an eligible baseline under the replacement policy. A
passive-only replacement starts with neutral passive counters and can publish
later failure or recovery observations from selected traffic; a policy with no
probing remains normally selectable. Either transition starts a new slow-start
epoch, so disabling active probing cannot strand an endpoint behind a success
event that no scheduler can produce.

A new or replaced endpoint configured with `warming: true` likewise begins
excluded in a fresh allocation and becomes eligible only when its first
successful probe atomically publishes a healthy version and slow-start recovery
epoch; validation rejects `warming: true` when the endpoint has no active probe
capable of publishing that success. Every sweep records its monotonic sample
and, for each due server, the exact launch, already-in-flight,
completion-budget defer, allocation/socket/buffer/submission failure, or
successful-start outcome. A failed start is a recorded defer, not an invisible
no-op.

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
admission gate closed, bounding live request-handler configs, JIT bundles, and
override tables to the active generation and at most one predecessor. The one
dedicated startup lifecycle artifact described above is a fixed process-lifetime
allocation outside this served-generation bound; it contains no request handler
entry points or generation-local runtime state.

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
Validation maps a bucket into the candidate whenever stable identity, scope, and
key shape are compatible. Window, burst, or limit changes conservatively
migrate existing history into the shared allocation and immediately evaluate it
under the candidate policy; they never grant a fresh burst. A scope or key-shape
change is rejected until every predecessor bucket and accounting horizon drains
unless a bounded migration includes predecessor occupancy and history.
Installation must not reset storage still reachable by old-generation work or
let a reordered rule inherit unrelated TAT state. Capture records every
process-global and shard-local bucket
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
server allocations. Compatible adjacent generations share occupancy
unconditionally for a stable endpoint, even when latency measurement policy
changes; only the incompatible latency/EWMA fields reset after a recorded
transition. Each acquisition returns a
token naming the exact server-state allocation, and its completion updates that
same allocation after reload. Thus `.leastConn`, `.ewma`, and custom selectors
in `N+1` observe work still owned by `N`; only an incompatible endpoint identity
receives fresh occupancy state while the predecessor allocation drains.

Stateful isolation policies are not reset by an unrelated reload. Circuit
breaker and outlier allocations have never-reused stable identities and are
shared by adjacent generations only when the upstream/server identity and the
complete breaker/outlier policy are compatible. The shared allocation carries
failure counters, open deadlines, half-open admission tokens, ejection state,
and its versioned arbitration sequence. Policy-only changes conservatively
retain an open/ejected verdict, deadline, live half-open tokens, and failure
history; a candidate cannot reopen an isolated stable endpoint at publication.
A policy that cannot represent that state is rejected until it drains. Only a
changed endpoint identity receives a fresh allocation. Every transition,
scheduled evaluation (including a no-op), ordinary admit/reject decision,
expiry-time monotonic sample, and half-open admission is captured by allocation
identity and version; replay consumes that order rather than starting a
compatible breaker closed.

Any selection policy whose effective weights depend on monotonic time, including
`slowStart`, records the exact selection-time monotonic sample, the recovery
epochs and effective weights derived from it, and the chosen stable server
identity. Recording an exact chosen result is an equivalent bounded
representation only when the record also identifies the policy-state version
it observed. Replay consumes the recorded sample/weights or exact result and
never resamples its local clock during a ramp; a missing clock or effective
selection input is `Unsupported`.

Each stable server owns a never-reused slow-start allocation containing the
recovery epoch id, epoch-start monotonic sample, current ramp state, and
version. Adjacent generations share that allocation only when both the stable
endpoint identity and the complete slow-start policy are identical, including
duration, initial/floor weight, curve, and every event that starts or resets a
ramp. An unrelated compatible reload therefore transfers the live epoch and
cannot restart it or declare it complete.

If the slow-start policy changes while an epoch is active, validation rejects
the reload; an implementation may not silently restart, truncate, or
recalculate the live ramp. Once no epoch is active, a policy change installs a
fresh allocation at the recorded publication boundary. The endpoint remains at
full eligibility at cutover, and only a later recovery trigger starts an epoch
under the new policy. A changed stable endpoint also receives a fresh
allocation. Allocation transfer, rejection, fresh installation, recovery
trigger, epoch id, and cutover sample are recorded for replay.

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
coordinator and the same validation path. The production SIGHUP source provider
resolves the configured source symlink exactly once. The symlink target is a
provider-owned immutable version tree, and every relative import must remain
inside it; mutable regular paths are rejected for live reload. Deployments publish
a new version by atomically replacing the symlink, never by editing an already
published target tree in place.

For SIGHUP, the observable attempt
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
admission attempt. When the slot is busy it emits the terminal `busy` result for
that attempt and also updates one bounded dirty slot to the newest observed
provider-owned source version. After the active request terminates, the adapter
re-admits that dirty version; repeated busy events may coalesce only by replacing
the slot with a newer version, and every replacement is captured. Replay consumes
the debounce sequence, opaque protected source-version handle, dirty-slot
transition, admission result, and terminal record. Routine capture contains no
plain source digest or other offline verifier; validation uses a provider-internal
keyed verifier. An admitted signal or watch event follows the ordinary compile,
publication, and terminal-record path.
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

The current source iterator is deliberately narrower than the runtime view:
`upstream.servers` requires backend addresses in the source declaration so the
verifier can statically unroll the bounded loop in declaration order. A
name-only, runtime-bound upstream is rejected until bounded runtime iteration is
implemented. The `Server` carrier holds upstream/backend identity; the handler
context independently latches the config generation for the whole timer
invocation. Server values cannot be constructed by source or persisted in
state, so a late invocation still fails the generation check without exposing
a pointer.

- `healthy: false` is an absolute exclusion from normal and all-down fallback
  selection;
- `healthy: true` admits the target to normal health consideration, but does not
  bypass an open circuit breaker or active outlier ejection;
- a reload shares the stable override allocation when upstream identity,
  endpoint identity, and marking policy are compatible. A marking-policy-only
  change retains the last verdict for each stable endpoint and stages the new
  writer policy; it never creates an empty selectable window. Replaced endpoint
  identities alone receive fresh empty slots.

A `false` to `true` manual transition atomically publishes a new slow-start
recovery epoch when that upstream uses `slowStart`; selection ramps from zero
using that versioned epoch. If every endpoint is manually excluded, selection
returns the deterministic no-eligible-backend result: HTTP requests receive
`503 Service Unavailable` before any upstream operation, and a replay record
contains the pinned generation, validated override version, and `no-eligible`
outcome. The ordinary ejected-backend fallback never overrides a manual
exclusion.

Publication does not clear or reuse the old generation's table. Lagging shards
and pinned old-generation work continue consulting it until every shard has
acknowledged the newer generation and all old-generation invocation/session
pins have reached zero. The coordinator then reclaims that table with the old
program bundle. Consequently a shard can never serve an old config after its
manual exclusions have disappeared, and compatible adjacent views preserve the
last published verdict while retaining generation-specific references for
pinned predecessor work.

Each generation table carries a monotonically increasing override sequence.
Successful marks publish through a validated snapshot protocol: a writer changes
the sequence to an odd value, updates its slot, then release-publishes the next
even value. Backend selection acquire-reads an even sequence, scans every verdict
it will consume, and accepts the snapshot only when a second acquire-read returns
the same even value; otherwise it retries within a fixed bound and takes the
visible fail-closed contention path: the request receives `503 Service
Unavailable`, no upstream is selected or contacted, and capture records
`selection-contended` with both observed sequence values and the workload-event
position. A custom selector receives the same bounded unavailable result rather
than stale `Server` data. Per-slot atomics followed by an
unvalidated table-version read are not sufficient. A backend-selection capture
records the pinned generation and exact validated even sequence observed by the
accepted snapshot. Capture records **every** mark attempt at its workload-event
position, including its stable server identity, requested verdict, boolean result,
and a bounded reason (`published`, `stale-or-foreign`, `unavailable`, or
`contended`). Successful records additionally carry the published even sequence.
Replay consumes failed attempts as well as successful publication boundaries and
orders selection snapshots by these sequences; an omitted attempt, mismatched
reason/result, or unobservable sequence is `Unsupported`. Recording only
successful publications is not sufficient to reproduce handler and timer control
flow.

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
passive ejections. A health-policy-only change conservatively retains every
unhealthy/ejected verdict and deadline until a replacement-policy observation
explicitly clears it; if the candidate representation cannot do so, validation
rejects the reload. Replaced endpoints receive fresh state under the warming
rule above, while the predecessor view remains valid until its pins drain. Thus
a resumed invocation cannot lose an `N` ejection or consume a verdict for an
endpoint that merely reused the same numeric slot in `N+1`.

Every active-probe completion and passive-failure/ejection mutation publishes a
monotonic version in its generation-scoped probe table. Selection validates the
whole table with the same bounded odd/even snapshot protocol as manual
overrides, or records each consumed slot's verdict and version; reading one
version after a mixed scan is forbidden. Time-based passive expiry additionally
records the exact monotonic sample, deadline, derived verdict, and event
position for every selection or custom `Server.healthy` observation. Probe
callbacks record their source event, resulting state, published version, and
event-loop position. Replay consumes those versions, samples, and positions
instead of rerunning callback timing. A missing, duplicate, out-of-order, or
unobservable probe version is `Unsupported`.

Upstream in-flight concurrency accounting is likewise identity-scoped. The
counter is owned by a never-reused stable upstream allocation identity. Its
compatibility predicate is independent of both balancing policy and endpoint
roster and of the configured `max_inflight` value: when validation proves the
same logical upstream and limit scope, adjacent generations share the allocation
even if the candidate changes policy, endpoints, or the limit. Each admission
compares the shared occupancy with the pinned generation's configured limit, so
a lowered `N+1` limit cannot admit new `N+1` work while predecessor acquisitions
already meet or exceed it. A limit-scope change is rejected until every
predecessor acquisition token drains, unless validation can seed a replacement
allocation with an exact conservative shadow of all predecessor occupancy and
keep it charged until those tokens release. Only a changed logical-upstream
identity receives an independent new allocation. Endpoint-scoped
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
adjacent generations whenever the logical upstream and budget policy are
compatible, independently of endpoint roster, retryable-status, attempt-count,
or backoff changes. Attempt scheduling remains generation-scoped, but changing
it cannot reset upstream-wide retry history. A budget-policy change
conservatively migrates the complete numerator, denominator, window, and
outstanding reservation history into a shared representation that grants no
fresh capacity; if that representation cannot preserve the stricter effective
history, validation rejects the reload until its accounting horizon drains.
Every ordinary first-attempt denominator mutation and every retry
grant/rejection records the allocation identity, monotonically assigned
arbitration version, request/attempt identity, counters before and after the
mutation, and workload-event position. Replay consumes all such mutations
rather than rerunning process-global races; missing, duplicate, or reordered
decisions are `Unsupported`.

Manual exclusion has priority over probe and passive-health state so a later
local probe cannot silently undo it. Manual admission participates in the
remaining breaker/outlier checks and cannot cancel their isolation. Calls from
the one shard-pinned timer are ordered by program order. The generation check
makes a late invocation apply only to its pinned retained table; a foreign or
retired table is definitely not applied.

## Failure and observation

| Operation | Result | State change |
|---|---|---|
| reload capability disabled | `false` | none |
| reload already pending/in flight | `false` | none |
| route reload at generation limit | `false` | no request id or slot claim |
| SIGHUP while reload busy | terminal `busy` record | request-id sequence advances; no candidate or generation change |
| SIGHUP at generation limit | terminal `generation-limit` record | request-id sequence advances; no candidate or generation change |
| file-watch event while reload busy | terminal `busy` record | newest version replaces the bounded dirty slot and is re-admitted after the active terminal record |
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

## Deterministic live state and capture closure

Capture start is an atomic all-shard barrier, not a timestamp sampled by the
writer. The coordinator closes workload admission, obtains an acknowledgement
and last pre-baseline event sequence from every shard, drains or checkpoints the
live state required below, durably commits that baseline, and only then reopens
admission with the first post-baseline sequence. A failed acknowledgement or
checkpoint leaves capture disabled and `Unsupported`; no shard may emit
apparently complete post-baseline traffic against a partial baseline.

Capture stop similarly closes admission and publishes a cutoff sequence plus a
per-shard high-water mark. The artifact remains durably `incomplete` while any
request, stream, timer or WebSocket callback, accepted reload, I/O operation,
detached effect, connection/session pin, or queued completion admitted at or
before the cutoff lacks its terminal event. The coordinator either drains all
such work and records each terminal boundary through the acknowledged shard
watermarks, or stores an exact bounded terminal checkpoint capable of resuming
it. A timeout, uncheckpointable live operation, writer failure, or missing
watermark leaves the artifact incomplete and replay rejects it. Stopping the
writer alone can never create a valid suffix-truncated capture.

Sequencing begins before higher-level workload admission. Every XDP/firewall
packet evaluation receives a packet sequence and records the visible map
version plus `drop`/`pass`; a passed packet is correlated with any later accept
attempt. Every accepted-fd attempt receives an accept sequence before connection
allocation and records either the new connection identity or the exact
resource/batch-limit close outcome. Only after those boundaries does an
admitted HTTP request or stream receive its workload sequence. A dropped packet
or pre-admission close therefore remains ordered even though it never owns an
HTTP identity.

All asynchronous I/O is captured at completion granularity. Each downstream
write and each upstream write records its exact result (positive byte count,
zero progress, or bounded error), buffer offset, resubmission decision, and
event position. Each upstream read records the exact returned bytes through a
protected handle, byte count, EOF or error, parser boundary, rearm/pause
decision, and event position. The transcript retains partial completions rather
than only final assembled bytes. Zero-copy file responses record the exact file
identity/version, offset, bytes exposed by every completion, and final outcome;
if the runtime cannot observe and protect those bytes, capture of that response
is `Unsupported`.

Every internal timer decision is deterministic input: handler `wait` and
timeout races, retry backoff, response throttling, periodic callbacks, breaker
and outlier expiry/evaluation, and active-health scheduling record the
monotonic sample, computed deadline, arm/defer/failure result, fire/cancel/skip
winner, and event position. Latency/EWMA updates record their start and end
samples (or exact measured duration), old value, resulting value, allocation
identity, and version. Replay never samples its local clock for one of these
decisions.

Backend selection consumes a coherent observation. Manual-override and
probe/passive-health tables use a bounded versioned snapshot protocol; exhausting
the bound takes the specified fail-closed `503 selection-contended` path.
Selection over multiple server allocations either validates one coherent table
version or records every consumed stable server identity, field value, and read
version plus the deterministic final result. The same rule applies to
`.leastConn`, `.ewma`, and custom selectors. A single version read after an
unvalidated mixed scan is insufficient.

Every invocation that can call `metrics()` records the exact aggregate snapshot
latched at entry, including its per-shard read versions and order; reconstructing
an aggregate from event order is not permitted. An invocation using only local
`stats()` records its exact local snapshot/version. Each request-latency
histogram or aggregate update records its measured duration, bucket/counter
mutation, version, and event position so later snapshots reproduce the observed
cut.

Runtime-created entropy is part of the transcript even when no Rut API exposes
it. This includes generated trace/span IDs, sampling decisions and their clock
inputs, WebSocket outbound-mask seed acquisition and failure, every mask-key
draw or the exact serialized frame bytes, and every seed/draw used when a
stateful allocation is created. Replay consumes these values and never silently
uses fresh process entropy.

Cross-shard fan-out is represented per destination. For `notify all` and any
future broadcast, capture records each destination shard's enqueue
success/failure, queue identity/version, dequeue sequence, callback outcome, and
local event position. One source or owner dequeue version cannot stand in for
independently ordered destination queues.

Idle upstream pools use stable endpoint-scoped allocation identities until the
reload drain specified above. After the baseline, every put, take, live-socket
probe, sweep, timeout-clock sample, eviction, close, and reuse result is recorded
in workload-event order. Reload drain/close outcomes are recorded too; a pooled
connection is never silently inherited.

Compatible hostname/resolver declarations retain the same per-shard DNS-cache
allocations, including last-known-good answers, negative entries, TTL
deadlines, refresh ownership, and stable endpoint identities. An incompatible
change is validated by staging a complete new resolution and atomically
publishing it, or is rejected; it cannot publish an empty cache and resolve
later. All later DNS transitions remain part of the ordered transcript.

The automatic response cache has a stable allocation identity derived from the
route, cache policy, key/Vary semantics, and response-producing program
compatibility. Exactly compatible generations share the allocation and its
in-flight fills; a program or cache-semantic change atomically drains and
invalidates predecessor entries before new-generation admission (while pinned
predecessor work retains its old allocation), or rejects the reload. It never
serves predecessor-produced bytes to an incompatible handler and never turns a
compatible warm cache into an unrecorded empty one.

This document supersedes every legacy reload description in `DESIGN.md`. Those
sections are historical background only; a conflicting pointer-swap, pool,
lifecycle, or generation-retention statement has no normative force.

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
thread timing. For every successful publication it also contains an opaque,
non-enumerable handle to either a bounded portable source/IR artifact rebuilt
through the normal verifier for the replay target, or a bounded compiled
program/config artifact whose digest and exact compatibility identity are
covered by a compiler attestation
signed by a configured trusted artifact-store key. The identity includes
runtime build and program ABI versions, compiler/JIT ABI, target triple, pointer
width, endianness, object/relocation format, and required CPU features. Replay
validates the signature, trust root, identity, feature availability, and digest
before loading compiled code. An unsigned artifact, an untrusted signer, a
mismatch, or an unresolved artifact is `Unsupported`; capture-supplied digest
and ABI fields are never treated as provenance. Replay never installs code
merely because its bytes match a digest and never substitutes the initial target
for a later published program.

A portable source artifact is self-contained inside the access-controlled,
encrypted artifact provider: it bundles the root source and
the exact bounded transitive import closure, including each importer's canonical
resolution identity/path, package identity, bytes, and authenticated digest.
It also pins the capture-time language semantics, runtime ABI, compiler
frontend/lowering version, standard-library identity, feature flags, and target
identity. Replay resolves imports only from that bundle, verifies the recorded
closure, and reconstructs source only with a compiler whose complete semantic
identity matches; it never consults the replay target's filesystem or module
cache. A compiler mismatch, missing, extra, cyclically inconsistent, unresolved,
or oversized closure is `Unsupported`. A self-contained verified IR artifact
may omit source imports only when its attested identity covers the complete
lowered program.

Routine replay records and traffic captures are secret-free. Protected replay
artifacts may contain the exact source/config bytes required for reconstruction,
but they exist only in the separately access-controlled encrypted provider and
are referenced from routine input by opaque capability and provider version.
Routine records never serialize compile-time-resolved environment values, TLS
private keys, raw
`Authorization`, `Cookie`, `Proxy-Authorization`, `X-API-Key`, or configured
sensitive-header values, or other secret bytes embedded in the live
program/config bundle or request, nor plain digests of those bytes. Sensitive
request fields are tokenized before
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

Inbound TLS execution has its own connection-correlated protected transcript.
For every inbound and outbound TLS record, the protected provider stores the
exact record header and protected payload bytes; the routine capture stores an
opaque handle, direction, length, read/write boundary, and total order. This
includes every handshake message and extension, negotiated cipher/version
traffic, alert, resumption exchange, application-data record, and post-handshake
message, including records emitted before failure. Selected SNI/ALPN,
client-certificate verification inputs and result, resumption decision, failure
or completion, and exact event position relative to reload installation and
teardown are additional metadata and never substitutes for record bytes.

Replay feeds the recorded inbound wire bytes at the recorded boundaries and
requires each outbound record to match the recorded wire bytes exactly before
HTTP admission can advance. If TLS randomness, keys, provider state, or another
protected input required to reproduce those bytes is unavailable, replay does
not accept a semantically similar handshake: the connection is `Unsupported`.
Until this byte-complete transcript and deterministic TLS execution are
implemented, capture of any connection that performs a TLS handshake is
`Unsupported`, including handshakes that never produce an HTTP request.

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

Retry backoff is part of that transcript rather than local replay timing. Each
attempt records the monotonic sample, computed deadline, timer arm, fire or
cancel outcome, and workload-event position that authorizes the next operation.
Missing retry-timer decisions make a workload using `backoff` `Unsupported`.

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
correlation identity, and source `shard_id`. Packet and accept-attempt sequences
are assigned at the pre-admission boundaries above. After a packet passes XDP
and a connection is admitted, a request or HTTP/2 stream receives both its
stable identity and workload-admission sequence before generation selection or
any userspace handler, limiter, or state effect; completion carries that
identity and never allocates the workload sequence retroactively. Timer
invocations, WebSocket frames, detached callbacks, and other workload entries
receive their sequence at the equivalent admission/arrival boundary. Later
effect and completion events have their own event-order positions correlated to
that admission identity, so faster request B completion cannot make B appear to
have entered before yielding request A.

Replay dispatches every admission, frame, timer, and callback to its recorded
source shard before executing it; it never lets the local accept/load-balancing
policy choose another shard. If the recorded shard count or identity cannot be
recreated, replay returns `Unsupported` before workload execution. This preserves
per-shard Cache state, local limiter buckets, snapshots, and other shard-owned
inputs.

For HTTP/1, capture begins at connection reads rather than request admission. A
connection-correlated transcript records each read chunk, parser boundary,
pipeline-buffer append/consume transition, keep-alive reuse, retry, and the
event position at which each parsed request becomes admissible. Replay releases
buffered bytes only at those boundaries. Pipelined or reused connections without
this complete transcript are `Unsupported`.

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

TLS resumption state survives an idle-socket drain and is therefore independent
baseline state. Capture must checkpoint each shard's inbound session-ID cache,
the shared ticket-key generations and rotation epoch, and each outbound-host
session cache, then record every insertion, eviction, rotation, and invalidation
in workload-event order. Alternatively it must explicitly clear all of those
caches and rotate to a recorded fresh ticket-key epoch before assigning the first
workload event. Capture is `Unsupported` when neither a complete checkpoint nor
that recorded reset can be established; replay must not silently replace a
resumed handshake with a full handshake.

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
are checkpointed in the baseline. In addition, every invocation that uses
`metrics()` records the exact entry-latched aggregate snapshot and its per-shard
read order/versions; every invocation that uses local `stats()` records that
exact local snapshot/version. Replay never attempts to infer a mixed aggregate
cut from event order and never assumes a zero snapshot when capture begins
after traffic. It resolves all baseline state through the protected state
provider and installs it before consuming traffic. Missing, unauthorized,
inconsistent, or unbounded baseline state is `Unsupported`; replay never starts
from an empty control plane or assumes every shard already has the latest
generation.

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
workload-event position, and successful publication version when present. It
also records every route `reload()` call, including invocation correlation,
linearization and mutation-event position, returned boolean, bounded failure
reason, and accepted request identity when present; losing concurrent calls are
records rather than inferred from eventual publication. The input records the
override and probe-table versions observed by each backend selection; every
probe-health mutation, retry-budget decision, load-balancer state mutation and
observed version, randomized backend-selection draw/result, marking-timer skipped
tick, and each shard's installation acknowledgement in workload-event order.
Post-baseline StatePort operations are recorded with stable allocation/key
identity, owner dequeue version, outcome,
and resulting state version, so concurrent source shards cannot reverse Hash or
other registry effects during replay. A key derived from protected request or
config data is represented only by an opaque provider handle or provider-keyed
token unavailable with the routine capture; a plain key or deterministic hash
that can verify guesses is forbidden. It also establishes the persistent state
present when capture begins, but registry contents never enter the routine
traffic capture. An explicitly configured protected state provider stores
either a bounded, schema-identified encrypted checkpoint of every retained
Cache, Set, Bloom, Bitmap, LRU, Hash, and future registry, or an encrypted
complete ordered StatePort effect history that reconstructs the identical
baseline before the first workload event. The capture contains only an opaque,
non-enumerable capability and provider-owned version handle; it contains no
content digest or offline verifier. The protected artifact includes allocation
identity, contents, eviction/order metadata, versions, the exact keyed-hash seed
and every equivalent hashing/set-selection parameter for each allocation. For a
TTL-backed LRU it additionally contains every entry's expiration deadline and
monotonic-clock basis; post-baseline lookups record the clock sample, expiry
decision, removal/order transition, and outcome. A TTL allocation without that
state and transcript is `Unsupported`. The protected artifact also contains
any accepted detached operation that can still mutate it. Restoring slots under
a newly initialized seed is forbidden; an implementation that cannot restore
the recorded seed rejects the checkpoint as `Unsupported`. Replay resolves it through
the access-controlled provider, and a missing, unauthorized, mismatched, or
unbounded representation is `Unsupported` rather than starting from empty
state. These boundaries select which adjacent generation handles every
interleaved request, stream, WebSocket frame, or timer resume
without reproducing thread timing. A replay must reproduce the same
accepted/rejected calls, per-shard installations, generation choices, program
artifacts, state effects, arbitration decisions, and terminal records.

## Required implementation order

1. [x] Add the control-plane mutation port and deterministic admission/override
   model to the handler ABI and harness.
2. [x] Implement `Server` identities, `Upstream.servers`, and the shared manual
   health override consulted by both network backends.
3. [x] Lower and execute timer-only, shard-pinned `upstream.mark`.
4. [x] Add generation acknowledgements and exact HTTP/1 request, suspended
   HTTP/2 stream, and terminate-mode WebSocket session program pins.
5. [x] Implement the reload coordinator, compatibility validation, SIGHUP, and
   process-harness coverage.
6. [x] Lower route-only `reload()` after the same coordinator is the sole
   activation path.
