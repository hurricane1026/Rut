/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

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
    u64 elapsed = now - drain_start;
    if (elapsed >= period_secs) return true;

    // Hash conn_id to get a pseudo-random threshold in [0, period_secs).
    // If threshold < elapsed, close this connection.
    // This gives ~(elapsed/period) fraction of connections closing each tick.
    u32 hash = conn_id * 2654435761u;  // Knuth multiplicative hash
    u32 threshold = hash % period_secs;
    return threshold < static_cast<u32>(elapsed);
}

}  // namespace rut
