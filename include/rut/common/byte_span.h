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

template <typename Size>
concept ByteSpanSize = sizeof(Size) <= sizeof(u64) &&
                       (__is_same(Size, u8) || __is_same(Size, u16) || __is_same(Size, u32) ||
                        __is_same(Size, u64) || __is_same(Size, size_t));

// The caller supplies a live buffer of used bytes. A candidate span may
// come from elsewhere. The two lengths and the offset have the same width.
// The offset is written only if the candidate fits.
template <ByteSpanSize Size>
[[nodiscard]] inline bool byte_span_offset_within(
    const void* buffer, Size used, const void* data, Size len, Size* out) {
    if (buffer == nullptr || data == nullptr) return false;
    const auto begin = reinterpret_cast<uintptr_t>(buffer);
    const auto address = reinterpret_cast<uintptr_t>(data);
    Size offset;
    if (sub_overflow(address, begin, &offset)) return false;

    if constexpr (sizeof(Size) <= sizeof(u32) && sizeof(Size) < sizeof(ptrdiff_t)) {
        if ((range_int(offset) + range_int(len)).value() > used) return false;
    } else {
        // Bound the last start without adding two potentially full-width values.
        Size last_start;
        if (offset > u64{PTRDIFF_MAX} || sub_overflow(used, len, &last_start) ||
            offset > last_start)
            return false;
    }
    *out = offset;
    return true;
}

// Empty spans may point to the end of the pool.
template <ByteSpanSize Size>
[[nodiscard]] inline bool byte_span_within(const char* pool,
                                           Size used,
                                           const char* data,
                                           Size len) {
    // A span of length len can start no later than used - len.
    Size last_start_offset;
    if (data == nullptr || sub_overflow(used, len, &last_start_offset)) return false;

    const auto pool_address = reinterpret_cast<uintptr_t>(pool);
    const auto data_address = reinterpret_cast<uintptr_t>(data);
    // Compare integer addresses because the candidate may belong to another object.
    uintptr_t distance;
    if (sub_overflow(data_address, pool_address, &distance)) return false;
    if constexpr (sizeof(Size) >= sizeof(ptrdiff_t)) {
        // A positive distance with the sign bit set does not fit ptrdiff_t.
        static_assert(sizeof(ptrdiff_t) == sizeof(uintptr_t));
        const ptrdiff_t start_offset = __builtin_bit_cast(ptrdiff_t, distance);
        if (start_offset < 0) return false;
    }
    return distance <= last_start_offset;
}

}  // namespace rut
