#pragma once

#include "rut/common/types.h"

namespace rut {

// Canonical signed decimal into caller-owned scratch: no allocation, NUL or
// padding. The returned view occupies the tail of the 20-byte buffer. Form the
// magnitude in unsigned arithmetic so INT64_MIN never invokes signed overflow.
inline Str format_integer(i64 value, char (&buffer)[20]) {
    static constexpr char kPairs[] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    const bool kNegative = value < 0;
    u64 magnitude = kNegative ? u64(0) - static_cast<u64>(value) : static_cast<u64>(value);
    char* cursor = buffer + sizeof(buffer);
    while (magnitude >= 100) {
        const u64 kQuotient = magnitude / 100;
        const u32 kRemainder = static_cast<u32>(magnitude - kQuotient * 100);
        cursor -= 2;
        __builtin_memcpy(cursor, kPairs + static_cast<u64>(kRemainder) * 2, 2);
        magnitude = kQuotient;
    }
    if (magnitude >= 10) {
        cursor -= 2;
        __builtin_memcpy(cursor, kPairs + magnitude * 2, 2);
    } else {
        *--cursor = static_cast<char>('0' + magnitude);
    }
    if (kNegative) *--cursor = '-';
    return {cursor, static_cast<u32>(buffer + sizeof(buffer) - cursor)};
}

}  // namespace rut
