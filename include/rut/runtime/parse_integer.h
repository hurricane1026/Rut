#pragma once

#include "rut/common/types.h"

namespace rut {
namespace integer_detail {

// Each caller proves that the complete word is inside the supplied view.
inline bool digits8(const char* data, u32& result) {
    u64 word;
    __builtin_memcpy(&word, data, sizeof(word));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    word = __builtin_bswap64(word);
#endif
    if (((word + 0x4646464646464646ULL) | (word - 0x3030303030303030ULL)) & 0x8080808080808080ULL)
        return false;
    word -= 0x3030303030303030ULL;
    word = word * 10 + (word >> 8);
    result = static_cast<u32>(((word & 0x000000ff000000ffULL) * 0x000f424000000064ULL +
                               ((word >> 16) & 0x000000ff000000ffULL) * 0x0000271000000001ULL) >>
                              32);
    return true;
}

inline bool digits4(const char* data, u32& result) {
    u32 word;
    __builtin_memcpy(&word, data, sizeof(word));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    word = __builtin_bswap32(word);
#endif
    if (((word + 0x46464646u) | (word - 0x30303030u)) & 0x80808080u) return false;
    word -= 0x30303030u;
    word = word * 10 + (word >> 8);
    result = (((word & 0x00ff00ffu) * 0x00640001u) >> 16) & 0xffffu;
    return true;
}

}  // namespace integer_detail

// Strict decimal conversion of the entire non-owning span. No allocation,
// terminator, padding, alignment, locale or CPU feature requirements. On failure
// the output is unchanged. Wide selects the signed 64-bit rather than 32-bit range.
template <bool Wide>
inline bool parse_integer(Str text, i64& output) {
    if (!text.ptr || !text.len) return false;
    const char* data = text.ptr;
    u32 length = text.len;
    const bool negative = *data == '-';
    if (negative || *data == '+') {
        ++data;
        if (!--length) return false;
    }
    u64 number = 0;
    // Protocol fields are commonly short: avoid block setup and range checks
    // when every possible digit sequence already fits in both result types.
    if (length >= 8) {
        if (*data == '0') {
            while (length >= 8) {
                u64 zeros;
                __builtin_memcpy(&zeros, data, sizeof(zeros));
                if (zeros != 0x3030303030303030ULL) break;
                data += 8;
                length -= 8;
            }
            while (length && *data == '0') {
                ++data;
                --length;
            }
        }
        if (length > (Wide ? 19u : 10u)) return false;
        while (length >= 8) {
            u32 block;
            if (!integer_detail::digits8(data, block)) return false;
            number = number * 100000000 + block;
            data += 8;
            length -= 8;
        }
        if (length >= 4) {
            u32 block;
            if (!integer_detail::digits4(data, block)) return false;
            number = number * 10000 + block;
            data += 4;
            length -= 4;
        }
    }
    while (length--) {
        const u32 digit = static_cast<u32>(static_cast<u8>(*data++)) - '0';
        if (digit > 9) return false;
        number = number * 10 + digit;
    }
    constexpr u64 kPositiveLimit = Wide ? 9223372036854775807ULL : 2147483647ULL;
    if (number > kPositiveLimit + static_cast<u64>(negative)) return false;
    // Form the two's-complement representation with unsigned arithmetic, including
    // INT64_MIN, then preserve its bits without a signed overflow.
    output = __builtin_bit_cast(i64, negative ? u64(0) - number : number);
    return true;
}

}  // namespace rut
