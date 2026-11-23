#pragma once

#include "rut/common/types.h"

namespace rut {

constexpr bool send_result_fits(u64 total) {
    return total <= INT32_MAX;
}

// IoEvent::result reports the total as i32, including bytes sent before a retry.
constexpr bool advance_send_bytes(u32& offset, u32& remaining, u32 completed) {
    if (completed == 0 || completed > remaining ||
        !send_result_fits(static_cast<u64>(static_cast<i64>(offset) + static_cast<i64>(remaining))))
        return false;
    offset = static_cast<u32>(static_cast<i64>(offset) + static_cast<i64>(completed));
    remaining = static_cast<u32>(static_cast<i64>(remaining) - static_cast<i64>(completed));
    return true;
}

}  // namespace rut
