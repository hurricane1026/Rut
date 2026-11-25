#pragma once

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
    if (data == nullptr) return false;
    Size remaining;
    if (__builtin_sub_overflow(used, len, &remaining)) return false;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(pool);
    const uintptr_t ptr = reinterpret_cast<uintptr_t>(data);
    uintptr_t offset = 0;
    if (__builtin_sub_overflow(ptr, begin, &offset)) return false;
    return offset <= remaining;
}

}  // namespace rut
