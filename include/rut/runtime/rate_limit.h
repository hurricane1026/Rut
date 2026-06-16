#pragma once

#include "rut/common/types.h"

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

}  // namespace rut
