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
// Bounded memory: a fixed direct-mapped slot table. On hash collision the new key
// takes the slot (the evicted key restarts) — the standard approximation for
// high-cardinality limiting.
namespace rut {

inline u64 migrate_rate_limit_tat(u64 tat,
                                  u64 last_grant_us,
                                  u64 old_emit_us,
                                  u64 /*old_tau_us*/,
                                  u64 new_emit_us,
                                  u64 /*new_tau_us*/,
                                  u64 /*activation_us*/) {
    if (tat == 0 || last_grant_us == 0 || old_emit_us == 0 || new_emit_us == 0) return 0;
    // Anchor the virtual arrivals at the last actual grant. Using the old burst
    // floor turns unused capacity into debt, while anchoring at activation drops
    // requests whose old cadence has elapsed but whose candidate cadence has
    // not. The distance from the last grant to TAT is the occupied virtual
    // arrival count represented by this bucket.
    const u64 debt = tat > last_grant_us ? tat - last_grant_us : old_emit_us;
    const u64 used = debt / old_emit_us + (debt % old_emit_us != 0 ? 1 : 0);
    if (used > (~u64{0} - last_grant_us) / new_emit_us) return ~u64{0};
    return last_grant_us + used * new_emit_us;
}

// Per-shard limiter (one thread per shard → no atomics). Value-initialized to all
// zeros, which reads as an empty/idle bucket for every key.
struct RateLimiter {
    static constexpr u32 kSlots = 8192;  // 16 B/slot → 128 KB per shard

    struct Slot {
        u64 key;  // metering key (see rate_limit_key()); 0 = empty
        u64 tat;  // GCRA theoretical arrival time, in monotonic µs
        u64 last_grant_us;
        u64 emit_us;
        u64 tau_us;
    };
    Slot slots[kSlots];

    void reset() {
        for (u32 i = 0; i < kSlots; i++) slots[i] = {};
    }

    // Record one request against a precomputed metering `key` and report whether
    // it conforms. `emit_us` = µs between tokens at the steady rate; `tau_us` =
    // burst tolerance in µs (both precomputed per rule from limit/window/burst).
    // `now_us` is a monotonic microsecond clock. emit_us == 0 disables the rule.
    bool allow_key(u64 key, u64 emit_us, u64 tau_us, u64 now_us, u64 migration_time_us = 0) {
        if (emit_us == 0) return true;  // disabled
        u64 h = key * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        Slot& s = slots[h % kSlots];
        if (s.key != key) {  // collision / first use → empty bucket for this key
            s.key = key;
            s.tat = 0;
            s.last_grant_us = 0;
            s.emit_us = emit_us;
            s.tau_us = tau_us;
        } else if (s.emit_us != emit_us || s.tau_us != tau_us) {
            s.tat = migrate_rate_limit_tat(s.tat,
                                           s.last_grant_us,
                                           s.emit_us,
                                           s.tau_us,
                                           emit_us,
                                           tau_us,
                                           migration_time_us != 0 ? migration_time_us : now_us);
            s.emit_us = emit_us;
            s.tau_us = tau_us;
        }
        if (now_us + tau_us < s.tat) return false;  // too early → throttle (429)
        const u64 kBase = (now_us > s.tat) ? now_us : s.tat;
        s.tat = kBase + emit_us;
        s.last_grant_us = now_us;
        return true;
    }
};

// Cross-shard limiter for @rateLimit(scope: global). One instance shared by every
// shard; the bucket is truly cluster-wide (all shards advance the same `tat`), so
// the configured limit is the exact process-wide cap — no divide-by-shard-count.
// A small per-slot spin lock serializes the GCRA update and the rare policy
// migration. This keeps key, TAT, and timing metadata one coherent state across
// shards, including at a live-reload policy boundary.
struct GlobalRateLimiter {
    static constexpr u32 kSlots = 8192;
    struct Slot {
        std::atomic_flag lock = ATOMIC_FLAG_INIT;
        u64 key = 0;
        u64 tat = 0;
        u64 last_grant_us = 0;
        u64 emit_us = 0;
        u64 tau_us = 0;
        u64 migration_time_us = 0;
    };
    Slot slots[kSlots];

    void reset() {
        for (u32 i = 0; i < kSlots; i++) {
            slots[i].key = 0;
            slots[i].tat = 0;
            slots[i].last_grant_us = 0;
            slots[i].emit_us = 0;
            slots[i].tau_us = 0;
            slots[i].migration_time_us = 0;
            slots[i].lock.clear(std::memory_order_relaxed);
        }
    }

    bool allow_key(u64 key, u64 emit_us, u64 tau_us, u64 now_us, u64 migration_time_us = 0) {
        if (emit_us == 0) return true;  // disabled
        u64 h = key * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        Slot& slot = slots[h % kSlots];
        while (slot.lock.test_and_set(std::memory_order_acquire)) {
        }
        if (slot.key == 0) {
            slot.key = key;
            slot.tat = 0;
            slot.last_grant_us = 0;
            slot.emit_us = emit_us;
            slot.tau_us = tau_us;
            slot.migration_time_us = migration_time_us;
        } else if (slot.key != key) {
            // Direct-map collisions conservatively share the existing debt.
            // Translate its occupied-token count to this key's own policy;
            // inheriting an unrelated looser cadence would bypass strict rules.
            slot.key = key;
            slot.tat = migrate_rate_limit_tat(
                slot.tat, slot.last_grant_us, slot.emit_us, slot.tau_us, emit_us, tau_us, now_us);
            slot.emit_us = emit_us;
            slot.tau_us = tau_us;
            slot.migration_time_us = migration_time_us;
        } else if (slot.emit_us != emit_us || slot.tau_us != tau_us) {
            // Shards adopt a generation independently. Only the candidate's
            // activation timestamp may advance shared policy metadata; a late
            // predecessor request must not migrate the slot back.
            if (migration_time_us >= slot.migration_time_us) {
                slot.tat =
                    migrate_rate_limit_tat(slot.tat,
                                           slot.last_grant_us,
                                           slot.emit_us,
                                           slot.tau_us,
                                           emit_us,
                                           tau_us,
                                           migration_time_us != 0 ? migration_time_us : now_us);
                slot.emit_us = emit_us;
                slot.tau_us = tau_us;
                slot.migration_time_us = migration_time_us;
            }
        }
        // During cutover, predecessor requests use the already-installed
        // candidate policy instead of oscillating the shared slot metadata.
        emit_us = slot.emit_us;
        tau_us = slot.tau_us;
        const bool allowed = now_us + tau_us >= slot.tat;
        if (allowed) {
            const u64 base = now_us > slot.tat ? now_us : slot.tat;
            slot.tat = base > ~u64{0} - emit_us ? ~u64{0} : base + emit_us;
            slot.last_grant_us = now_us;
        }
        slot.lock.clear(std::memory_order_release);
        return allowed;
    }
};

}  // namespace rut
