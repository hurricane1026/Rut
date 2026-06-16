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
        u64 key;               // (route_idx << 32) | ip; 0 also = empty
        u64 window_start_sec;  // monotonic second the current window opened
        u32 count;             // requests counted in the current window
    };
    Slot slots[kSlots];

    // Record one request against (route_idx, ip) and report whether it is within
    // the limit. `max` requests are allowed per `window_sec`; a window older than
    // window_sec resets. Returns true if allowed, false if it should be throttled
    // (429). `now_sec` is a monotonic second count supplied by the caller.
    bool allow(u32 route_idx, u32 ip, u32 max, u32 window_sec, u64 now_sec) {
        if (max == 0 || window_sec == 0) return true;  // disabled
        const u64 kKey = (static_cast<u64>(route_idx) << 32) | static_cast<u64>(ip);
        // Fibonacci-ish hash to spread (route, ip) across slots.
        u64 h = kKey * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        Slot& s = slots[h % kSlots];
        if (s.key != kKey || (now_sec - s.window_start_sec) >= window_sec) {
            s.key = kKey;
            s.window_start_sec = now_sec;
            s.count = 0;
        }
        s.count++;
        return s.count <= max;
    }
};

}  // namespace rut
