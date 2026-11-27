#pragma once

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"

namespace rut {

// For boundaries that must reject raw addresses whose exclusive end wraps.
// Use relative offsets when checking containment in a live buffer.
[[nodiscard]] inline bool raw_byte_span_address_end(const void* data,
                                                    size_t byte_count,
                                                    uintptr_t* end) {
    return !add_overflow(reinterpret_cast<uintptr_t>(data), byte_count, end);
}

// The caller supplies a live buffer of used bytes. A candidate span may
// come from elsewhere. Publish its offset only after proving containment.
[[nodiscard]] inline bool byte_span_offset_within(
    const void* buffer, u32 used, const void* data, u32 len, u32* out) {
    if (buffer == nullptr || data == nullptr) return false;
    const auto begin = reinterpret_cast<uintptr_t>(buffer);
    const auto address = reinterpret_cast<uintptr_t>(data);
    u32 offset;
    if (sub_overflow(address, begin, &offset)) return false;
    if ((range_int(offset) + range_int(len)).value() > used) return false;
    *out = offset;
    return true;
}

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
