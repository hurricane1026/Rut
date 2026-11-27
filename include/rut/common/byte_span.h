#pragma once

#include "rut/common/checked_arithmetic.h"
#include "rut/common/types.h"

namespace rut {

// Empty spans may point to the end of the pool.
template <typename Size>
    requires(sizeof(Size) <= sizeof(u64) &&
             (__is_same(Size, u8) || __is_same(Size, u16) || __is_same(Size, u32) ||
              __is_same(Size, u64) || __is_same(Size, size_t)))
[[nodiscard]] inline bool byte_span_within(const char* pool,
                                           Size used,
                                           const char* data,
                                           Size len) {
    // A span of length len can start no later than used - len.
    Size last_start_offset;
    if (data == nullptr || sub_overflow(used, len, &last_start_offset)) return false;

    const auto pool_address = reinterpret_cast<uintptr_t>(pool);
    const auto data_address = reinterpret_cast<uintptr_t>(data);
    uintptr_t start_offset;
    return !sub_overflow(data_address, pool_address, &start_offset) &&
           start_offset <= last_start_offset;
}

}  // namespace rut
