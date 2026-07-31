#pragma once

#include "rut/common/types.h"
#include <atomic>
#include <chrono>
#include <thread>

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
                                  const u64* grants,
                                  u32 grant_count,
                                  bool history_overflow,
                                  u64 old_emit_us,
                                  u64 /*old_tau_us*/,
                                  u64 new_emit_us,
                                  u64 /*new_tau_us*/,
                                  u64 activation_us,
                                  u64 new_window_us) {
    if (tat == 0 || grant_count == 0 || old_emit_us == 0 || new_emit_us == 0) return 0;
    const u64 horizon = new_window_us != 0 ? new_window_us : new_emit_us;
    const u64 cutoff = activation_us > horizon ? activation_us - horizon : 0;
    if (history_overflow) {
        u64 oldest = ~u64{0};
        for (u32 i = 0; i < grant_count && i < 32; i++)
            oldest = grants[i] < oldest ? grants[i] : oldest;
        if (oldest >= cutoff) {
            if (horizon > ~u64{0} - activation_us) return ~u64{0};
            const u64 drain = activation_us + horizon;
            return new_emit_us > ~u64{0} - drain ? ~u64{0} : drain + new_emit_us;
        }
    }
    u64 ordered[32]{};
    u32 count = 0;
    for (u32 i = 0; i < grant_count && i < 32; i++) {
        if (grants[i] < cutoff) continue;
        u32 pos = count++;
        while (pos > 0 && ordered[pos - 1] > grants[i]) {
            ordered[pos] = ordered[pos - 1];
            pos--;
        }
        ordered[pos] = grants[i];
    }
    u64 migrated = 0;
    for (u32 i = 0; i < count; i++) {
        const u64 base = ordered[i] > migrated ? ordered[i] : migrated;
        if (new_emit_us > ~u64{0} - base) return ~u64{0};
        migrated = base + new_emit_us;
    }
    return migrated;
}

inline void record_rate_limit_grant(u64* grants,
                                    u32& grant_count,
                                    u32& grant_head,
                                    bool& history_overflow,
                                    u64 now_us,
                                    u32 capacity) {
    if (grant_count < capacity) {
        grants[(grant_head + grant_count) % capacity] = now_us;
        grant_count++;
    } else {
        grants[grant_head] = now_us;
        grant_head = (grant_head + 1) % capacity;
        history_overflow = true;
    }
}

// Per-shard limiter (one thread per shard → no atomics). Value-initialized to all
// zeros, which reads as an empty/idle bucket for every key.
struct RateLimiter {
    static constexpr u32 kSlots = 8192;  // fixed direct-mapped table
    static constexpr u32 kHistory = 8;

    struct Slot {
        u64 key;  // metering key (see rate_limit_key()); 0 = empty
        u64 tat;  // GCRA theoretical arrival time, in monotonic µs
        u64 emit_us;
        u64 tau_us;
        u64 window_us;
        u64 grants[kHistory];
        u32 grant_count;
        u32 grant_head;
        bool history_overflow;
    };
    Slot slots[kSlots];

    void reset() {
        for (u32 i = 0; i < kSlots; i++) slots[i] = {};
    }

    // Record one request against a precomputed metering `key` and report whether
    // it conforms. `emit_us` = µs between tokens at the steady rate; `tau_us` =
    // burst tolerance in µs (both precomputed per rule from limit/window/burst).
    // `now_us` is a monotonic microsecond clock. emit_us == 0 disables the rule.
    bool allow_key(u64 key,
                   u64 emit_us,
                   u64 tau_us,
                   u64 now_us,
                   u64 migration_time_us = 0,
                   u64 window_us = 0) {
        if (emit_us == 0) return true;  // disabled
        u64 h = key * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        Slot& s = slots[h % kSlots];
        if (s.key != key) {  // collision / first use → empty bucket for this key
            s.key = key;
            s.tat = 0;
            s.emit_us = emit_us;
            s.tau_us = tau_us;
            s.window_us = window_us;
            s.grant_count = 0;
            s.grant_head = 0;
            s.history_overflow = false;
        } else if (s.emit_us != emit_us || s.tau_us != tau_us || s.window_us != window_us) {
            s.tat = migrate_rate_limit_tat(s.tat,
                                           s.grants,
                                           s.grant_count,
                                           s.history_overflow,
                                           s.emit_us,
                                           s.tau_us,
                                           emit_us,
                                           tau_us,
                                           migration_time_us != 0 ? migration_time_us : now_us,
                                           window_us);
            s.emit_us = emit_us;
            s.tau_us = tau_us;
            s.window_us = window_us;
        }
        if (now_us + tau_us < s.tat) return false;  // too early → throttle (429)
        const u64 kBase = (now_us > s.tat) ? now_us : s.tat;
        s.tat = kBase + emit_us;
        record_rate_limit_grant(
            s.grants, s.grant_count, s.grant_head, s.history_overflow, now_us, kHistory);
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
    static constexpr u32 kHistory = 32;
    struct Slot {
        std::atomic_flag lock = ATOMIC_FLAG_INIT;
        u64 key = 0;
        u64 tat = 0;
        u64 emit_us = 0;
        u64 tau_us = 0;
        u64 window_us = 0;
        u64 grants[kHistory] = {};
        u32 grant_count = 0;
        u32 grant_head = 0;
        bool history_overflow = false;
        u64 migration_time_us = 0;
    };
    Slot slots[kSlots];

    void reset() {
        for (u32 i = 0; i < kSlots; i++) {
            slots[i].key = 0;
            slots[i].tat = 0;
            slots[i].emit_us = 0;
            slots[i].tau_us = 0;
            slots[i].window_us = 0;
            slots[i].grant_count = 0;
            slots[i].grant_head = 0;
            slots[i].history_overflow = false;
            slots[i].migration_time_us = 0;
            slots[i].lock.clear(std::memory_order_relaxed);
        }
    }

    bool allow_key(u64 key,
                   u64 emit_us,
                   u64 tau_us,
                   u64 now_us,
                   u64 migration_time_us = 0,
                   u64 window_us = 0) {
        if (emit_us == 0) return true;  // disabled
        u64 h = key * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        Slot& slot = slots[h % kSlots];
        // A rejected flood must not spin indefinitely behind a hot key's cache
        // line, but brief contention must not turn conforming requests into 429s.
        bool locked = false;
        for (u32 attempt = 0; attempt < 128; attempt++) {
            if (!slot.lock.test_and_set(std::memory_order_acquire)) {
                locked = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(50));
        }
        if (!locked) return false;
        if (slot.key == 0) {
            slot.key = key;
            slot.tat = 0;
            slot.emit_us = emit_us;
            slot.tau_us = tau_us;
            slot.window_us = window_us;
            slot.grant_count = 0;
            slot.grant_head = 0;
            slot.history_overflow = false;
            slot.migration_time_us = migration_time_us;
        } else if (slot.key != key) {
            // Direct-map collisions conservatively share the existing debt.
            // Translate its occupied-token count to this key's own policy;
            // inheriting an unrelated looser cadence would bypass strict rules.
            slot.key = key;
            slot.tat = migrate_rate_limit_tat(slot.tat,
                                              slot.grants,
                                              slot.grant_count,
                                              slot.history_overflow,
                                              slot.emit_us,
                                              slot.tau_us,
                                              emit_us,
                                              tau_us,
                                              now_us,
                                              window_us);
            slot.emit_us = emit_us;
            slot.tau_us = tau_us;
            slot.window_us = window_us;
            slot.migration_time_us = migration_time_us;
        } else if (slot.emit_us != emit_us || slot.tau_us != tau_us ||
                   slot.window_us != window_us) {
            // Shards adopt a generation independently. Only the candidate's
            // activation timestamp may advance shared policy metadata; a late
            // predecessor request must not migrate the slot back.
            if (migration_time_us >= slot.migration_time_us) {
                slot.tat =
                    migrate_rate_limit_tat(slot.tat,
                                           slot.grants,
                                           slot.grant_count,
                                           slot.history_overflow,
                                           slot.emit_us,
                                           slot.tau_us,
                                           emit_us,
                                           tau_us,
                                           migration_time_us != 0 ? migration_time_us : now_us,
                                           window_us);
                slot.emit_us = emit_us;
                slot.tau_us = tau_us;
                slot.window_us = window_us;
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
            record_rate_limit_grant(slot.grants,
                                    slot.grant_count,
                                    slot.grant_head,
                                    slot.history_overflow,
                                    now_us,
                                    kHistory);
        }
        slot.lock.clear(std::memory_order_release);
        return allowed;
    }
};

}  // namespace rut
