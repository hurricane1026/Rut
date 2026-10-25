#pragma once

#include "rut/common/types.h"
#include <atomic>

// Token-bucket rate limiter, implemented as GCRA (Generic Cell Rate Algorithm —
// the "virtual scheduling" form of a token bucket). Instead of fractional tokens
// + a timestamp, each key's whole state is a single timestamp `tat` (theoretical
// arrival time): the earliest time the next request may conform. This is what
// makes it cheap and pack-friendly — no fractional math, no per-request divide
// (the emission interval `emit_us` and burst tolerance `tau_us` are precomputed
// once per rule), one u64 of state per key, and (for the global limiter) a CAS on
// that single u64 with no field packing.
//
// Conformance test for a request at time `now_us`:
//   conforming  ⟺  now_us + tau_us >= tat
//   on accept:  tat = max(now_us, tat) + emit_us
// Steady rate = 1 token / emit_us; a fully-idle bucket admits ~tau_us/emit_us + 1
// requests back-to-back (the burst). Versus the old fixed window this removes the
// boundary 2× burst and gives a tunable burst.
//
// Bounded memory: a fixed direct-mapped slot table. A different key may reuse a
// slot only once its previous bucket has fully recovered (tat <= now). Active
// collisions fail closed instead of resetting another key's budget. Capacity
// pressure can therefore reject otherwise-conforming keys.
namespace rut {

// Per-shard limiter (one thread per shard → no atomics). Value-initialized to all
// zeros, which reads as an empty/idle bucket for every key.
struct RateLimiter {
    static constexpr u32 kSlots = 8192;  // 16 B/slot → 128 KB per shard

    struct Slot {
        u64 key;  // metering key (see rate_limit_key()); 0 = empty
        u64 tat;  // GCRA theoretical arrival time, in monotonic µs
    };
    Slot slots[kSlots];

    void reset() {
        for (u32 i = 0; i < kSlots; i++) slots[i] = {};
    }

    // Record one request against a precomputed metering `key` and report whether
    // it conforms. `emit_us` = µs between tokens at the steady rate; `tau_us` =
    // burst tolerance in µs (both precomputed per rule from limit/window/burst).
    // `now_us` is a monotonic microsecond clock. emit_us == 0 disables the rule.
    bool allow_key(u64 key, u64 emit_us, u64 tau_us, u64 now_us) {
        if (emit_us == 0) return true;  // disabled
        u64 h = key * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        Slot& s = slots[h % kSlots];
        if (s.key != key) {
            // Replacing active state would let alternating colliding keys refill
            // their buckets without waiting. Only a fully idle slot is reusable.
            if (s.tat > now_us) return false;
            s.key = key;
            s.tat = 0;
        }
        // Avoid now+tau overflow: a future TAT conforms iff its distance from
        // now fits within the burst tolerance.
        if (s.tat > now_us && s.tat - now_us > tau_us) return false;
        const u64 kBase = (now_us > s.tat) ? now_us : s.tat;
        if (kBase > 0xffffffffffffffffull - emit_us) return false;
        s.tat = kBase + emit_us;
        return true;
    }
};

// Cross-shard limiter for @rateLimit(scope: global). One instance shared by every
// shard in one process; all shards advance the same `tat` for a slot, without
// dividing the configured rate by shard count. Different keys that collide share
// that budget, so this is not an exact per-key table or a cross-node limiter.
// Each slot is a single atomic<u64> `tat`, so a grant is one CAS (no field
// packing) and the throttle path is a *read only* (load + compare, no RMW): a
// flood on a hot key keeps the slot's cache line Shared across cores and never
// writes it; grants are inherently bounded by the rate, so the RMW/barrier rate is
// capped by the slot budget, not by traffic. relaxed ordering — `tat` is the only shared
// datum. Collisions share a slot and can cause conservative throttling.
struct GlobalRateLimiter {
    static constexpr u32 kSlots = 8192;  // 64 KB shared (atomic<u64> per slot)
    std::atomic<u64> slots[kSlots];

    void reset() {
        for (u32 i = 0; i < kSlots; i++) slots[i].store(0, std::memory_order_relaxed);
    }

    bool allow_key(u64 key, u64 emit_us, u64 tau_us, u64 now_us) {
        if (emit_us == 0) return true;  // disabled
        u64 h = key * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        std::atomic<u64>& slot = slots[h % kSlots];
        u64 tat = slot.load(std::memory_order_relaxed);
        for (;;) {
            if (tat > now_us && tat - now_us > tau_us) return false;  // throttle — read-only
            const u64 kBase = (now_us > tat) ? now_us : tat;
            if (kBase > 0xffffffffffffffffull - emit_us) return false;
            const u64 kNext = kBase + emit_us;
            if (slot.compare_exchange_weak(
                    tat, kNext, std::memory_order_relaxed, std::memory_order_relaxed))
                return true;
            // CAS failed: `tat` reloaded with the current value — retry.
        }
    }
};

}  // namespace rut
