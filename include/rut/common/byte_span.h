#pragma once

#include "rut/common/types.h"

namespace rut {

// Empty spans may point to the end of the pool. Both lengths fit in i64.
template <typename Size>
    requires(__is_same(Size, u8) || __is_same(Size, u16) || __is_same(Size, u32))
[[nodiscard]] inline bool byte_span_within(const char* pool,
                                           Size used,
                                           const char* data,
                                           Size len) {
    if (data == nullptr || len > used) return false;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(pool);
    const uintptr_t ptr = reinterpret_cast<uintptr_t>(data);
    uintptr_t offset = 0;
    if (__builtin_sub_overflow(ptr, begin, &offset)) return false;

    // The length guard puts the difference in [0, used], within Size.
    const Size remaining = static_cast<Size>(static_cast<i64>(used) - static_cast<i64>(len));
    return offset <= remaining;
}

}  // namespace rut
