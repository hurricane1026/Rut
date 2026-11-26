#pragma once

#include "rut/common/range_int.h"
#include "rut/common/types.h"

namespace rut {

inline constexpr char last_decimal_digit(u64 value) {
    static constexpr char kDigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    return bounded_remainder<10>(value).at(kDigits);
}

inline constexpr u32 kFormatIntegerBufferSize = [] {
    u32 size = 1;  // Minus sign.
    for (i64 value = INT64_MIN; value != 0; value /= 10) ++size;
    return size;
}();

// Canonical signed decimal into caller-owned scratch: no allocation, NUL or
// padding. The returned view occupies the tail of the buffer. Handle INT64_MIN
// before signed negation since its magnitude requires the high bit of u64.
inline Str format_integer(i64 value, char (&buffer)[kFormatIntegerBufferSize]) {
    struct DecimalPairs {
        char digits[100][2];
    };
    static constexpr auto kPairs = [] {
        DecimalPairs pairs{};
        for (u32 i = 0; i < 100; ++i) {
            pairs.digits[i][0] = last_decimal_digit(i / 10);
            pairs.digits[i][1] = last_decimal_digit(i);
        }
        return pairs;
    }();
    const bool kNegative = value < 0;
    u64 magnitude =
        value == INT64_MIN ? u64{INT64_MAX} + 1 : static_cast<u64>(kNegative ? -value : value);
    char* cursor = buffer + sizeof(buffer);
    auto append_pair = [&] {
        const auto& pair = bounded_remainder<100>(magnitude).at(kPairs.digits);
        cursor -= sizeof(pair);
        __builtin_memcpy(cursor, pair, sizeof(pair));
    };
    while (magnitude >= 100) {
        append_pair();
        magnitude /= 100;
    }
    if (magnitude >= 10)
        append_pair();
    else
        *--cursor = last_decimal_digit(magnitude);
    if (kNegative) *--cursor = '-';
    return {cursor, static_cast<u32>(buffer + sizeof(buffer) - cursor)};
}

}  // namespace rut
