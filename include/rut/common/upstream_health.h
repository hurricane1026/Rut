#pragma once

#include "rut/common/route_host.h"
#include "rut/common/types.h"

namespace rut {

enum class ActiveHealthType : u8 { Http, Tcp };

constexpr bool valid_active_health_timeout(u32 milliseconds) {
    return milliseconds == 0 ||
           (milliseconds >= 1000 && milliseconds <= 60000 && milliseconds % 1000 == 0);
}

// Preserve the configured spelling while reusing the existing authority parser.
inline bool active_health_host_valid(Str authority) {
    if (!authority.ptr || authority.len == 0 || authority.len > 260) return false;
    for (u32 i = 0; i < authority.len; ++i) {
        const auto c = static_cast<unsigned char>(authority.ptr[i]);
        if (c <= 0x20 || c == 0x7f || c == ',' || c == '*') return false;
    }
    char normalized[254];
    u16 length = 0;
    return route_host_from_authority(authority, normalized, &length);
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
               (statuses[(static_cast<i64>(status) - 200) / 64] &
                (u64{1} << ((static_cast<i64>(status) - 200) % 64))) != 0;
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
struct ActiveHealthStatuses {
    static constexpr u32 kWords = 7;  // final HTTP statuses 200..599
    u64 words[kWords]{};

    constexpr bool contains(u16 status) const {
        return status >= 200 && status <= 599 &&
               (words[(static_cast<i64>(status) - 200) / 64] &
                (u64{1} << ((static_cast<i64>(status) - 200) % 64))) != 0;
    }
    constexpr bool empty() const {
        for (u32 i = 0; i < kWords; ++i)
            if (words[i]) return false;
        return true;
    }
    constexpr bool valid() const { return (words[6] >> 16) == 0; }
};
inline bool valid_active_health_check(ActiveHealthType type,
                                      const char* path,
                                      u32 path_len,
                                      u32 interval_ms,
                                      u16 status,
                                      ActiveHealthThresholds thresholds,
                                      u32 timeout_ms,
                                      ActiveHealthStatuses statuses = {}) {
    if (!interval_ms || !thresholds.valid() || !valid_active_health_timeout(timeout_ms))
        return false;
    if (!statuses.valid()) return false;
    if (type == ActiveHealthType::Tcp) return path_len == 0 && status == 0 && statuses.empty();
    if (type != ActiveHealthType::Http || !path || !path_len || path[0] != '/' ||
        (statuses.empty() ? (status < 100 || status > 599) : status != 0))
        return false;
    for (u32 i = 0; i < path_len; ++i) {
        const auto kCh = static_cast<unsigned char>(path[i]);
        if (kCh <= 0x20 || kCh == 0x7f) return false;
    }
    return true;
}

}  // namespace rut
