#pragma once

#include "rut/common/integer_types.h"

namespace rut {

// The signed upper bound also proves that the conversion fits in i64.
template <i64 Max = INT64_MAX>
    requires(Max >= 0)
[[nodiscard]] constexpr bool try_u64_to_i64(u64 value, i64* out) {
    if (value > u64{Max}) return false;
    *out = static_cast<i64>(value);
    return true;
}

// Publish a signed value only if its magnitude and sign are representable.
[[nodiscard]] constexpr bool try_signed_magnitude(u64 magnitude, bool negative, i64* out) {
    i64 value;
    if (try_u64_to_i64(magnitude, &value)) {
        *out = negative ? -value : value;
        return true;
    }
    if (!negative || magnitude != (u64{1} << 63)) return false;
    *out = INT64_MIN;
    return true;
}

}  // namespace rut
