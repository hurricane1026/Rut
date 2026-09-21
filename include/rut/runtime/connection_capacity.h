#pragma once

#include "rut/common/types.h"

namespace rut {

// Connection identifiers are 24-bit values. The top three values are reserved
// for cancel, timer, and listener events, so this is the largest usable count.
inline constexpr u32 kDefaultConnectionCapacity = 16384;
inline constexpr u32 kMaxConnectionCapacity = 0xFFFFFD;

constexpr bool validate_connection_capacity(u32 capacity) {
    return capacity >= 1 && capacity <= kMaxConnectionCapacity;
}

template <typename Loop>
constexpr u32 connection_capacity_of(const Loop& loop) {
    if constexpr (requires { loop.connection_capacity; }) {
        return loop.connection_capacity;
    } else {
        return Loop::kMaxConns;
    }
}

}  // namespace rut
