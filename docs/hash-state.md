# Strict Hash and Owner-Shard Updates — Decision Record

Status: **accepted design, implementation in progress** (2026-08-07). The
fixed-capacity, failure-atomic cuckoo table substrate is implemented; the DSL
surface and owner-shard operation protocol remain reserved until their complete
error and reload semantics land.

This record defines the contract required before Rut may expose `Hash` or call
in-process state a source of truth. It does not promise cross-node durability or
freshness; those require a separate external-backend contract.

## D1. `Hash` means no eviction

`Hash<K, V>` is fixed-capacity and preallocated, but unlike `Cache` it never
evicts an existing key. Its basic operations are:

```swift
let sessions = Hash<IP, i64>(capacity: 100000)

sessions.get(key)        // V? plus a possible state-operation error
sessions.set(key, value) // V, error-capable; bare use propagates failure
sessions.remove(key)     // bool, error-capable; false means absent
```

A missing `get` means only "no committed value for this key". A failed insert
does not remove or overwrite another entry. `set` of an existing key does not
need free capacity; insertion of a new key may fail visibly with `full` or
`placementLimit`. Callers may handle failure with normal error-capable
`guard let`/`if let` flow. A bare mutation statement is allowed but still
propagates failure through the route's error prelude; it never means "ignore".

The first implementation may restrict keys and values to the same scalar set as
other state primitives. General structs do not enter the surface until stable
hash, equality, layout, and reload compatibility are specified.

Implementation direction: a preallocated bucketized cuckoo table with two
candidate buckets per key and a fixed relocation budget. Lookup and removal
inspect only those buckets. An insertion first records a bounded relocation
path in scratch storage and commits it only after finding a free slot; exhausting
the budget leaves every existing entry untouched and returns `placementLimit`.
Capacity is rounded to whole power-of-two buckets. There is no hot-path rehash,
allocation, hidden overflow chain, or eviction.

Both candidate hashes are keyed by a process-state seed fixed for the table's
lifetime. The seed is shared by all shards, injectable by the deterministic
harness, and preserved across compatible hot reloads. User-controlled keys
therefore cannot cheaply precompute the table's collision pattern.

## D2. Scope is explicit

The default container remains shard-local. A shard-local `Hash` is lossless
inside that shard, but it is not shared state and must not be described as the
process source of truth.

```swift
let local = Hash<IP, i64>(capacity: 100000)
let process = Hash<IP, i64>(capacity: 100000, consistent: true)
```

With `consistent: true`,
`keyedHash(stateSeed, declarationId, key) % shardCount` selects one owner shard.
Every operation uses the same owner table and semantics.
`capacity` remains a per-owner-table bound, matching existing per-shard state;
process memory and the theoretical aggregate entry count therefore scale with
shard count. A skewed partition may fail before other partitions fill, and that
failure is visible.

This is a single source of truth only inside one running Rut process. It is not
durable across process loss, shared between replicas, or fresh relative to an
external database.

## D3. Separate `get`/`set` is not an atomic update

Owner routing removes divergent copies but does not make a read-modify-write
sequence atomic. Two source shards can both read the same value before either
write arrives. Exact counters and limiters must use one owner-executed update:

```swift
variant HashEdit<V, R> {
    keep(R)
    set(value: V, result: R)
    remove(R)
}

func advance(current: i64?, input: GcraInput) -> HashEdit<i64, Decision> {
    let prior = current.or(input.now)
    // Pure, bounded Rut code computes both the successor and caller result.
    if input.now < prior - input.burst {
        return .keep(.reject)
    }
    let successor = max(prior, input.now) + input.interval
    return .set(value: successor, result: .allow)
}

let decision = buckets.update(key, input, using: advance)
```

The exact spelling may change when generic variant/function-reference syntax is
finalized; the semantic shape may not:

1. Source-shard arguments are evaluated exactly once and copied into a bounded
   message.
2. The owner looks up the current optional value, runs the updater once, and
   applies its `keep`/`set`/`remove` edit in one event-loop turn.
3. The edit and returned result share one per-key linearization point.
4. A new-key `set` that cannot allocate returns a visible error and commits
   nothing. Existing-key updates remain possible when the table is full.

The updater is a compiler-verified pure bounded function: no request access,
state access, I/O, `wait`, `notify`, time sampling, logging, or recursive call.
Inputs such as `time.nowMicros()` are sampled before dispatch and passed as
ordinary values. This keeps algorithms in Rut without shipping an arbitrary
continuation to another shard.

`using: advance` is a state-operation-specific compile-time reference, not a
first-class function value or closure. The compiler monomorphizes it into a
bounded updater thunk available on every shard and puts only its fixed id plus
captured input bytes in the message.

Rut does not initially expose compare-and-swap. A public CAS loop would add ABA,
retry bounds, and repeated cross-shard round trips while still making the safe
idiom harder than `update`.

## D4. Ordering and conflicts

The owner processes one message at a time. The read or committed edit is the
operation's linearization point.

- Operations from one source shard to one owner retain FIFO send order.
- Concurrent sources have no promised arrival order; owner dequeue order wins.
- Updates to one key never interleave inside an updater.
- Different keys do not gain a global total order.
- Plain `get` followed by `set` remains conflict-prone; diagnostics for
  exact-state examples should point to `update`.

This provides linearizable per-key operations, not multi-key transactions.
Multi-key atomicity stays absent until it has an explicit ownership and deadlock
model.

## D5. Failure has no ambiguous-success result

Cross-shard failure is part of value flow, never a log-only event or silent
drop.

- Queue full before enqueue: `queueFull`, definitely not applied.
- Deadline expired when the owner selects the message: `deadline`, definitely
  not applied.
- Hash insertion failure: `full` or `placementLimit`, definitely not applied.
- Reload rejection/drain: `reloading`, definitely not applied.
- Successful owner reply: applied exactly once.

After enqueue, the runtime does not report a timeout that might race a commit.
The owner either rejects the deadline before executing or completes the
operation. A disconnected client does not undo an accepted mutation; the owner
completes it once and may discard the reply. A stuck owner shard is a
process-health failure, not an invented "maybe committed" language result.

Queues reserve completion capacity before accepting a request message, so a
result cannot be lost merely because the return queue fills. The runtime does
not automatically retry an accepted operation. These rules avoid duplicate
updates without requiring an unbounded deduplication ledger.

## D6. Reload and ownership changes

Acknowledged operations are drained before a table is detached. `persist: true`
requires identical declaration identity, key/value layout, hash algorithm, and
seed.

Each accepted update pins the compiled configuration that owns its updater
thunk. On cross-shard enqueue, the queue entry acquires its own pin before the
request can release its pin. A client disconnect therefore cannot detach an
un-pinned updater: the queued operation retains the program through owner
execution and through delivery or explicit discard of its reserved reply.
Reload cannot reinterpret an old numeric updater id against new code; the old
module remains alive until its accepted messages and replies finish.

Changing `shardCount` changes key ownership. A reload that would preserve a
non-empty consistent `Hash` while changing shard count is rejected until the
runtime has a quiescent migration protocol. Non-persistent state may instead be
drained and reset explicitly; it is never silently presented as preserved.

Schema mismatch is a reload rejection, not a best-effort conversion. Shutdown
may abandon replies to disconnected callers, but it must not acknowledge an
operation and then discard its committed state before the configured durability
boundary.

## D7. External backends remain separate

`backend:` remains reserved. An in-process `Hash` cannot solve replica sharing,
process restart durability, or database freshness. Any future backend mode must
separately define:

- backend-side atomic update semantics;
- read freshness, invalidation, or maximum staleness;
- write acknowledgment and retry/idempotency behavior;
- degraded-mode behavior; and
- ownership during network partitions.

Until then, `Hash(..., consistent: true)` is the exact per-key state authority
for one live process only, and `Cache` remains explicitly lossy.
