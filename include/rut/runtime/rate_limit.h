#pragma once

#include "rut/common/types.h"
#include <atomic>

// Per-shard fixed-window rate limiter. Keyed by (route index, client IP) so each
// route enforces its own limit per source address. Bounded memory: a fixed,
// direct-mapped slot table (no allocation, no eviction list). On hash collision
// the incoming key takes the slot, resetting the evicted key's window — an
// approximation that trades exactness for O(1) bounded memory, which is the
// standard trade for high-cardinality rate limiting.
//
// Single-writer per shard (the shard thread), so no atomics. A RateLimiter is
// value-initialized to all zeros, which is already the empty/fresh state.
namespace rut {

struct RateLimiter {
    static constexpr u32 kSlots = 8192;  // ~192 KB per shard

    struct Slot {
        u64 key;               // metering key (see rate_limit_key()); 0 = empty
        u64 window_start_sec;  // monotonic second the current window opened
        u32 count;             // requests counted in the current window
    };
    Slot slots[kSlots];

    // Record one request against a precomputed metering `key` (see
    // rate_limit_key() — it folds the route and the configured key components,
    // e.g. IP / header / param, into one u64) and report whether it is within the
    // limit. `max` requests are allowed per `window_sec`; a window older than
    // window_sec resets. Returns true if allowed, false if it should be throttled
    // (429). `now_sec` is a monotonic second count supplied by the caller.
    bool allow_key(u64 key, u32 max, u32 window_sec, u64 now_sec) {
        if (max == 0 || window_sec == 0) return true;  // disabled
        // Fibonacci-ish hash to spread keys across slots.
        u64 h = key * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        Slot& s = slots[h % kSlots];
        if (s.key != key || (now_sec - s.window_start_sec) >= window_sec) {
            s.key = key;
            s.window_start_sec = now_sec;
            s.count = 0;
        }
        s.count++;
        return s.count <= max;
    }

    // Convenience overload keyed by (route, client IP) — the default metering
    // unit when a route declares no explicit key components. The high bit keeps
    // these keys disjoint from rate_limit_key()'s FNV output space and nonzero.
    bool allow(u32 route_idx, u32 ip, u32 max, u32 window_sec, u64 now_sec) {
        const u64 kKey = (static_cast<u64>(route_idx) << 32) | static_cast<u64>(ip) | (1ull << 63);
        return allow_key(kKey, max, window_sec, now_sec);
    }
};

// Cross-shard rate limiter for @rateLimit(scope: global). One instance shared by
// every shard in the process; `max` is the exact cluster-wide cap (all shards
// increment the same slot, so no divide-by-shard-count approximation). Each slot
// packs the window into one u64 — (window_start_sec << 32 | count) — so a grant
// is a single atomic CAS and the over-limit path is a *read only* (load + compare,
// no RMW): a flood on a hot key keeps the slot's cache line Shared across cores
// and never writes it. Grants are inherently bounded by `max` per window, so the
// RMW (and its barrier) rate is capped by the limit, not by traffic. relaxed
// ordering — the packed counter is the only shared datum, nothing else is
// published through it. Collisions share a slot (rare, bounded) — same
// approximation as RateLimiter, minus the per-key eviction.
struct GlobalRateLimiter {
    static constexpr u32 kSlots = 8192;  // 64 KB shared (atomic<u64> per slot)
    std::atomic<u64> slots[kSlots];

    void reset() {
        for (u32 i = 0; i < kSlots; i++) slots[i].store(0, std::memory_order_relaxed);
    }

    bool allow_key(u64 key, u32 max, u32 window_sec, u64 now_sec) {
        if (max == 0 || window_sec == 0) return true;  // disabled
        u64 h = key * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        std::atomic<u64>& slot = slots[h % kSlots];
        const u32 kNow = static_cast<u32>(now_sec);
        u64 cur = slot.load(std::memory_order_relaxed);
        for (;;) {
            const u32 kStart = static_cast<u32>(cur >> 32);
            const u32 kCount = static_cast<u32>(cur);
            u64 next;
            if (kNow - kStart >= window_sec) {
                next = (static_cast<u64>(kNow) << 32) | 1u;  // fresh window
            } else if (kCount < max) {
                next = cur + 1;  // same window, count++ (low 32 bits; kCount < max)
            } else {
                return false;  // over limit — read-only, no RMW
            }
            if (slot.compare_exchange_weak(
                    cur, next, std::memory_order_relaxed, std::memory_order_relaxed))
                return true;
            // CAS failed: `cur` reloaded with the current value — retry.
        }
    }
};

}  // namespace rut
