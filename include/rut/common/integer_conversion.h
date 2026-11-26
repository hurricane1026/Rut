#pragma once

#include "rut/common/types.h"

namespace rut {

// out must point to writable storage. Write only if the input fits in i64.
[[nodiscard]] constexpr bool try_u64_to_i64(u64 value, i64* out) {
    if (value > u64{INT64_MAX}) return false;
    *out = static_cast<i64>(value);
    return true;
}

}  // namespace rut
