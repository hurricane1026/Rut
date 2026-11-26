#pragma once

#include "rut/common/range_int.h"
#include "rut/common/types.h"

namespace rut {

constexpr bool send_result_fits(i64 total) {
    return total >= 0 && total <= INT32_MAX;
}

// IoEvent::result reports the total as i32, including bytes sent before a retry.
[[nodiscard]] constexpr bool advance_send_bytes(u32& offset, u32& remaining, u32 completed) {
    if (completed == 0 || completed > remaining ||
        !send_result_fits((range_int(offset) + range_int(remaining)).value()))
        return false;
    const auto kDelta = range_int(completed);
    offset = static_cast<u32>((range_int(offset) + kDelta).value());
    remaining = static_cast<u32>((range_int(remaining) - kDelta).value());
    return true;
}

}  // namespace rut
