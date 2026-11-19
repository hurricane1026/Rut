#pragma once

#include "rut/common/types.h"

namespace rut {

struct ActiveHealthThresholds {
    static constexpr u32 kMax = 255;

    u8 failures = 1;
    u8 successes = 1;

    constexpr bool valid() const { return failures != 0 && successes != 0; }
};

}  // namespace rut
