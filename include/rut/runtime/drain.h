#pragma once

#include "rut/common/checked_arithmetic.h"
#include "rut/common/types.h"

#include <time.h>

namespace rut {

// Drain configuration for graceful shutdown.
// Envoy-style probabilistic drain: after drain begins, each completing
// request has P(close) = elapsed / drain_period. This spreads connection
// teardown over time instead of thundering-herd close.
struct DrainConfig {
    u32 period_secs = 30;  // total drain window before force-close
};

// Monotonic clock — no syscall on modern Linux (vDSO).
inline u64 monotonic_secs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<u64>(ts.tv_sec);
}

// Drain probability: returns true if this connection should be closed.
// Linear ramp: P = elapsed / period. At deadline, always true.
// Uses a simple deterministic hash of conn_id + elapsed to avoid
// needing a PRNG — cheap and good enough for drain distribution.
inline bool should_drain_close(u32 conn_id, u64 drain_start, u64 now, u32 period_secs) {
    if (period_secs == 0) return true;
    // RUT_INTEGER_RANGE: both monotonic timestamps may occupy the full u64 range.
    const auto kElapsed = __int128_t{now} - __int128_t{drain_start};
    if (kElapsed < 0 || kElapsed >= period_secs) return true;

    // Hash conn_id to get a pseudo-random threshold in [0, period_secs).
    // If threshold < elapsed, close this connection.
    // This gives ~(elapsed/period) fraction of connections closing each tick.
    const u32 hash = wrapping_mul(conn_id, u32{2654435761u});
    u32 threshold = hash % period_secs;
    return threshold < static_cast<u32>(kElapsed);
}

}  // namespace rut
