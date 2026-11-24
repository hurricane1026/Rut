#pragma once

#include "rut/common/types.h"

// RUT_POSITIVE requires a strictly positive argument at every call.
// RUT_POSITIVE_SUM requires a strictly positive sum when crediting a signed
// field. Direct reset and subtraction may still leave zero. Checked in CI.
#if defined(__clang__)
#define RUT_POSITIVE [[clang::annotate("rut_positive")]]
#define RUT_POSITIVE_SUM [[clang::annotate("rut_positive_sum")]]
#else
#define RUT_POSITIVE
#define RUT_POSITIVE_SUM
#endif

namespace rut {

// Publish the result only when it is in [1, maximum]. out may alias an operand.
[[nodiscard]] constexpr bool checked_positive_sum(i64 left, i64 right, i64 maximum, i64& out) {
    i64 sum;
    if (__builtin_add_overflow(left, right, &sum) || sum <= 0 || sum > maximum) return false;
    out = sum;
    return true;
}

}  // namespace rut
