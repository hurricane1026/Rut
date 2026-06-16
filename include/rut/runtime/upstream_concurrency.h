#pragma once

#include "rut/common/types.h"
#include <atomic>

// Per-upstream in-flight request limiter (concurrency cap). One instance shared
// by every shard in the process, so the cap is the exact cluster-wide number of
// concurrent proxied requests allowed to a backend — the most direct protection
// for a backend that falls over on concurrency/load (more so than any per-client
// rate limit). A gauge, not a window: try_acquire on dispatch, release on every
// completion/failure path. Excess requests are rejected (503) — a bounded
// pending queue (Envoy-style max_pending) is a later refinement.
//
// `inflight` is touched by an atomic fetch_add on dispatch and fetch_sub on
// release (a gauge must move per request — there's no read-only fast path like
// the rate limiter's). relaxed ordering: the count is the only shared datum.

namespace rut {

struct UpstreamConcurrency {
    static constexpr u32 kMaxUpstreams = 64;  // matches RouteConfig::kMaxUpstreams
    std::atomic<u32> inflight[kMaxUpstreams];

    void reset() {
        for (u32 i = 0; i < kMaxUpstreams; i++) inflight[i].store(0, std::memory_order_relaxed);
    }

    // Try to take one in-flight slot for upstream `uid` (cap `max`, 0 = unlimited).
    // Returns false if the backend is already at capacity (caller answers 503).
    bool try_acquire(u16 uid, u32 max) {
        if (max == 0 || uid >= kMaxUpstreams) return true;
        const u32 kPrev = inflight[uid].fetch_add(1, std::memory_order_relaxed);
        if (kPrev >= max) {
            inflight[uid].fetch_sub(1, std::memory_order_relaxed);  // over → undo
            return false;
        }
        return true;
    }

    // Release a slot taken by try_acquire. Callers must release exactly once per
    // successful acquire (the connection's held-flag enforces this), so a plain
    // fetch_sub can't underflow.
    void release(u16 uid) {
        if (uid >= kMaxUpstreams) return;
        inflight[uid].fetch_sub(1, std::memory_order_relaxed);
    }
};

}  // namespace rut
