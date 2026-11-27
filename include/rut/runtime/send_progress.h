#pragma once

#include "rut/common/range_int.h"
#include "rut/common/types.h"

namespace rut {

[[nodiscard]] constexpr bool send_result_fits(i64 total) {
    return total >= 0 && total <= INT32_MAX;
}

// IoEvent::result reports the total as i32, including bytes sent before a retry.
[[nodiscard]] constexpr bool advance_send_bytes(u32& offset, u32& remaining, u32 completed) {
    const auto kOffset = range_int(offset);
    const auto kRemaining = range_int(remaining);
    if (completed == 0 || completed > kRemaining.value() ||
        !send_result_fits((kOffset + kRemaining).value()))
        return false;
    const auto kDelta = range_int(completed);
    offset = (kOffset + kDelta).min(range_int<UINT32_MAX, i64{UINT32_MAX} + 1>{}).to<u32>();
    remaining = (kRemaining - kDelta).max(range_int<0, 1>{}).to<u32>();
    return true;
}

}  // namespace rut
