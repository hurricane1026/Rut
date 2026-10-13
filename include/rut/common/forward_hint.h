#pragma once

#include "rut/common/types.h"

namespace rut {
// Performance intent only; protocol and lifetime admission remain mandatory.
enum class ForwardHint : u8 { Auto = 0, Rps = 1, Throughput = 2 };
constexpr bool forward_hint_valid(ForwardHint hint) {
    return static_cast<u8>(hint) <= static_cast<u8>(ForwardHint::Throughput);
}
}  // namespace rut
