#pragma once

#include "rut/common/types.h"

namespace rut {

struct PassiveHealthPolicy {
    u32 eject_ms = 5000;
    u8 failures = 3;
    bool configured = false;

    constexpr bool valid() const { return failures != 0 && eject_ms != 0; }
};

struct ActiveHealthThresholds {
    static constexpr u32 kMax = 255;

    u8 failures = 1;
    u8 successes = 1;

    constexpr bool valid() const { return failures != 0 && successes != 0; }
};

}  // namespace rut
