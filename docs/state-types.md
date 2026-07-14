# State Types — Decision Record

Status: **accepted** (2026-07-13). Implementation: slices 1–2 merged
(#178, #179); slice 4, i64 bitwise, is implemented by PR #182. Slice 3 and
slices 5–6 — the `Cache` substrate, time/max, and `examples/ratelimit.rut` —
remain in flight as PRs #181/#183/#184. This file records the *decisions* and
their reasons. User-facing semantics live in DESIGN.md §3.3.6 and
docs/language-card.md; when the remaining slices land, implementation mechanics
will live beside their code.

## D1. The layering principle

**An algorithm either can be written by users in Rut, or it does not go
into the language.** Full inlining + one thread per shard means Rut-written
GCRA/sliding-window compiles to straight-line arithmetic plus one slot
access — C++-built-in performance; the read-modify-write is race-free by
construction WITHIN a shard (single thread, no suspension between get and
set — wait routes reject cache ops). Cross-shard exactness is explicitly
out of scope until a strict table + owner-shard atomic update exist
(DESIGN.md §3.3.6). Therefore the runtime keeps only irreducible substrate
(keyed state slots, LPM tries, bloom bit math, coalescing); token bucket,
sliding window, and gauge logic are `.rut` library code
(`examples/ratelimit.rut`, pending PR #184). `Counter<K>` is deleted from the taxonomy;
`@rateLimit`/`@throttle` stay, and can later re-sugar over the library.

## D2. The fixed-capacity axiom, and why the type is named `Cache`

A zero-malloc, mmap-preallocated hot path cannot use any of the backstops
general-purpose hash maps rely on (chains, rehash, unbounded probes), so:

> Under fixed capacity there is no third option: when capacity or a
> collision budget is exceeded, either the write fails visibly, or old
> data dies.

eBPF hit the same wall and split the answer into two *names* (`HASH`
returns `-E2BIG`; `LRU_HASH` evicts). We adopt the split: the lossy
slot table is named **`Cache`** — the universal prior for a cache
("entries may vanish; a miss is normal; always handle it") produces
exactly the right calling code, including from LLMs trained on that
prior. **`Hash` is reserved** for a possible future strict table
(visible failure when full) and until then is not a Rut name at all.
A type named `Hash` must honor the lossless prior or must not exist.

The user-facing red line that follows (normative, DESIGN.md §3.3.6):
**never store anything in a `Cache` whose absence yields a wrong answer**
(sessions, in-flight counts). Misses are machine-enforced on the read
side (`get -> i64?`, no force-unwrap); the name covers the write side.

## D3. Gauge does not build on `Cache`

incr/decr in-flight counting is incompatible with lossy slots: an
eviction between incr and decr leaks the count permanently. Gauge keys
are low-cardinality (per-upstream, per-route), so its substrate — when a
use case demands it — is an eBPF-`ARRAY`-style exact indexed table: no
hashing, no eviction, present-from-creation.

## D4. Deliberately rejected (with the eBPF precedent that informed each)

- Cache TTL (`ttl:`) — lazy expiry via timestamps packed into the value,
  the eBPF idiom; ten years of eBPF maps never grew a TTL. This decision does
  not remove the separately documented `LRU(..., ttl:)` API.
- Handler-side iteration/dumps — data-plane gets `get`/`set` only;
  observability belongs to the control plane (eBPF program-side vs
  syscall-side asymmetry).
- Locks and per-element timers — per-shard single thread makes every
  handler straight line a critical section already.
- Dynamic allocation modes — eBPF tried non-prealloc'd maps and reverted;
  latency determinism wins over memory efficiency.
