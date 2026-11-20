#pragma once

#include "rut/common/types.h"

namespace rut {

enum class ActiveHealthType : u8 { Http, Tcp };

constexpr bool valid_active_health_timeout(u32 milliseconds) {
    return milliseconds == 0 ||
           (milliseconds >= 1000 && milliseconds <= 60000 && milliseconds % 1000 == 0);
}

struct ActiveHealthThresholds {
    static constexpr u32 kMax = 255;

    u8 failures = 1;
    u8 successes = 1;

    constexpr bool valid() const { return failures != 0 && successes != 0; }
};

// Explicit, bounded passive policy. Omission preserves legacy connect-only health.
struct PassiveHealthPolicy {
    static constexpr u32 kWords = 7;  // final HTTP statuses 200..599
    bool enabled = false;
    u8 tcp_failures = 0;
    u8 timeouts = 0;
    u8 http_failures = 0;
    u8 successes = 0;
    u64 healthy_statuses[kWords]{};
    u64 unhealthy_statuses[kWords]{};

    static constexpr bool contains(const u64* statuses, u16 status) {
        return status >= 200 && status <= 599 &&
               (statuses[(status - 200) / 64] & (u64{1} << ((status - 200) % 64))) != 0;
    }
    constexpr bool valid() const {
        if (!enabled) return true;
        if (!successes || !(tcp_failures || timeouts || http_failures)) return false;
        bool healthy = false, unhealthy = false;
        for (u32 i = 0; i < kWords; ++i) {
            if (healthy_statuses[i] & unhealthy_statuses[i]) return false;
            healthy |= healthy_statuses[i] != 0;
            unhealthy |= unhealthy_statuses[i] != 0;
        }
        // The last word has only sixteen valid bits (HTTP 584..599).
        if ((healthy_statuses[6] | unhealthy_statuses[6]) >> 16) return false;
        return healthy && (!http_failures || unhealthy);
    }
};
inline bool valid_active_health_check(ActiveHealthType type,
                                      const char* path,
                                      u32 path_len,
                                      u32 interval_ms,
                                      u16 status,
                                      ActiveHealthThresholds thresholds,
                                      u32 timeout_ms) {
    if (!interval_ms || !thresholds.valid() || !valid_active_health_timeout(timeout_ms))
        return false;
    if (type == ActiveHealthType::Tcp) return path_len == 0 && status == 0;
    if (type != ActiveHealthType::Http || !path || !path_len || path[0] != '/' || status < 100 ||
        status > 599)
        return false;
    for (u32 i = 0; i < path_len; ++i) {
        const auto kCh = static_cast<unsigned char>(path[i]);
        if (kCh <= 0x20 || kCh == 0x7f) return false;
    }
    return true;
}

}  // namespace rut
