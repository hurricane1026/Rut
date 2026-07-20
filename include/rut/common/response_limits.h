#pragma once

#include "rut/common/types.h"

namespace rut {

// Shared capacity for literal response bodies. The compiler uses this while
// serializing and interning bodies so every accepted RIR module can be copied
// into RouteConfig without discovering a smaller runtime-only limit.
inline constexpr u32 kResponseBodyPoolBytes = 8 * 1024;

}  // namespace rut
