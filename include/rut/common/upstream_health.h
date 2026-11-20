#pragma once

#include "rut/common/route_host.h"
#include "rut/common/types.h"

namespace rut {

struct PassiveHealthPolicy {
    u32 eject_ms = 5000;
    u8 failures = 3;
    bool configured = false;

    constexpr bool valid() const { return failures != 0 && eject_ms != 0; }
};

// Preserve the configured spelling while reusing the existing authority parser.
inline bool active_health_host_valid(Str authority) {
    if (!authority.ptr || authority.len == 0 || authority.len > 260) return false;
    for (u32 i = 0; i < authority.len; ++i) {
        const unsigned char c = static_cast<unsigned char>(authority.ptr[i]);
        if (c == 0 || c < 0x20 || c == 0x7f || c == ',' || c == '*') return false;
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

}  // namespace rut
