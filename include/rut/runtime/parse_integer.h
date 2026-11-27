#pragma once

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"

namespace rut {
namespace integer_detail {

inline u64 wrap_add(u64 a, u64 b) {
    u64 result = 0;
    // RUT_INTEGER_RANGE: packed decimal arithmetic uses the low 64 bits.
    (void)add_overflow(a, b, &result);
    return result;
}

inline u64 wrap_sub(u64 a, u64 b) {
    u64 result = 0;
    // RUT_INTEGER_RANGE: packed decimal arithmetic uses the low 64 bits.
    (void)sub_overflow(a, b, &result);
    return result;
}

// Each caller proves that the complete word is inside the supplied view.
inline bool digits8(const char* data, u32& result) {
    u64 word;
    __builtin_memcpy(&word, data, sizeof(word));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    word = __builtin_bswap64(word);
#endif
    if (((wrap_add(word, 0x4646464646464646ULL) | wrap_sub(word, 0x3030303030303030ULL)) &
         0x8080808080808080ULL))
        return false;
    word = wrap_sub(word, 0x3030303030303030ULL);
    word = wrap_add(static_cast<u64>(word) * 10u, static_cast<u64>(word >> 8));
    result = static_cast<u32>(
        (wrap_add((word & 0x000000ff000000ffULL) * 0x000f424000000064ULL,
                  ((word >> 16) & 0x000000ff000000ffULL) * 0x0000271000000001ULL)) >>
        32);
    return true;
}

inline bool digits4(const char* data, u32& result) {
    u32 word;
    __builtin_memcpy(&word, data, sizeof(word));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    word = __builtin_bswap32(word);
#endif
    if (((wrap_add(word, 0x46464646u) | wrap_sub(word, 0x30303030u)) & 0x80808080u)) return false;
    word = wrap_sub(word, 0x30303030u);
    word =
        wrap_add(static_cast<u64>(static_cast<u32>(word * u32{10})), static_cast<u64>(word >> 8));
    result = (((word & 0x00ff00ffu) * 0x00640001u) >> 16) & 0xffffu;
    return true;
}

struct PortableDigits {
    static constexpr bool kBlock16 = false;
    static bool read8(const char* data, u32& result) { return digits8(data, result); }
};

}  // namespace integer_detail

// Strict decimal conversion of the entire non-owning span. No allocation,
// terminator, padding, alignment, locale or CPU feature requirements. On failure
// the output is unchanged. Wide selects the signed 64-bit rather than 32-bit range.
template <bool Wide, class Digits = integer_detail::PortableDigits>
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
                data += static_cast<i64>(8);
                length = static_cast<u32>((range_int(length) - range_int<8, 9>{}).value());
            }
            while (length && *data == '0') {
                ++data;
                --length;
            }
        }
        if (length > (Wide ? 19u : 10u)) return false;
        if constexpr (Digits::kBlock16) {
            if (length >= 16) {
                u64 block;
                if (!Digits::read16(data, block)) return false;
                number = block;
                data += static_cast<i64>(16);
                length = static_cast<u32>((range_int(length) - range_int<16, 17>{}).value());
            }
        }
        while (length >= 8) {
            u32 block;
            if (!Digits::read8(data, block)) return false;
            number = integer_detail::wrap_add(number * 100000000, block);
            data += static_cast<i64>(8);
            length = static_cast<u32>((range_int(length) - range_int<8, 9>{}).value());
        }
        if (length >= 4) {
            u32 block;
            if (!integer_detail::digits4(data, block)) return false;
            number = integer_detail::wrap_add(number * 10000, block);
            data += static_cast<i64>(4);
            length = static_cast<u32>((range_int(length) - range_int<4, 5>{}).value());
        }
    }
    while (length--) {
        const u8 byte = static_cast<u8>(*data++);
        if (byte < '0' || byte > '9') return false;
        const u32 digit = static_cast<u32>(static_cast<i32>(byte) - static_cast<i32>('0'));
        number = integer_detail::wrap_add(number * 10, digit);
    }
    constexpr u64 kPositiveLimit = Wide ? 9223372036854775807ULL : 2147483647ULL;
    u64 max_magnitude = 0;
    // RUT_INTEGER_RANGE: existing caller discards the overflow status.
    (void)add_overflow(kPositiveLimit, static_cast<u64>(negative), &max_magnitude);
    if (number > max_magnitude) return false;
    // Form the two's-complement representation with unsigned arithmetic, including
    // INT64_MIN, then preserve its bits without a signed overflow.
    u64 magnitude = 0;
    if (negative)
        // RUT_INTEGER_RANGE: existing caller discards the overflow status.
        (void)sub_overflow(u64{0}, number, &magnitude);
    else
        magnitude = number;
    output = __builtin_bit_cast(i64, magnitude);
    return true;
}

// Compile-time selected runtime entry points. The implementation translation
// unit alone receives ISA flags; callers retain the normal deployment baseline.
bool parse_integer32(Str text, i64& output);
bool parse_integer64(Str text, i64& output);
const char* parse_integer_arch();

}  // namespace rut
