#pragma once

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"

namespace rut {
namespace integer_detail {

// Each caller proves that the complete word is inside the supplied view.
[[nodiscard]] inline bool digits8(const char* data, u32* result) {
    u64 word;
    __builtin_memcpy(&word, data, sizeof(word));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    word = __builtin_bswap64(word);
#endif
    constexpr u64 kAsciiZero = 0x3030303030303030ULL;
    if ((wrapping_add(word, u64{0x4646464646464646ULL}) | wrapping_sub(word, kAsciiZero)) &
        0x8080808080808080ULL)
        return false;
    // The packed arithmetic intentionally keeps the low bits of each word.
    word = wrapping_sub(word, kAsciiZero);
    word = wrapping_add(wrapping_mul(word, u64{10}), word >> 8);
    constexpr u64 kPairMask = 0x000000ff000000ffULL;
    const u64 packed =
        wrapping_add(wrapping_mul(word & kPairMask, u64{0x000f424000000064ULL}),
                     wrapping_mul((word >> 16) & kPairMask, u64{0x0000271000000001ULL}));
    *result = bounded_quotient<(u64{1} << 32)>(packed).to<u32>();
    return true;
}

[[nodiscard]] inline bool digits4(const char* data, u32* result) {
    u32 word;
    __builtin_memcpy(&word, data, sizeof(word));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    word = __builtin_bswap32(word);
#endif
    constexpr u32 kAsciiZero = 0x30303030u;
    if ((wrapping_add(word, u32{0x46464646}) | wrapping_sub(word, kAsciiZero)) & 0x80808080u)
        return false;
    word = wrapping_sub(word, kAsciiZero);
    word = wrapping_add(wrapping_mul(word, u32{10}), word >> 8);
    *result = wrapping_mul(word & u32{0x00ff00ff}, u32{0x00640001}) >> 16;
    return true;
}

struct PortableDigits {
    static constexpr bool kBlock16 = false;
    [[nodiscard]] static bool read8(const char* data, u32* result) { return digits8(data, result); }
};

}  // namespace integer_detail

// Strict decimal conversion of the entire non-owning span. No allocation,
// terminator, padding, alignment, locale or CPU feature requirements. On failure
// the output is unchanged. Wide selects the signed 64-bit rather than 32-bit range.
template <bool Wide, class Digits = integer_detail::PortableDigits>
[[nodiscard]] inline bool parse_integer(Str text, i64* output) {
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
                length = (range_int(length) - range_int<8, 9>{}).max(range_int<0, 1>{}).to<u32>();
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
                if (!Digits::read16(data, &block)) return false;
                number = block;
                data += 16;
                length = (range_int(length) - range_int<16, 17>{}).max(range_int<0, 1>{}).to<u32>();
            }
        }
        while (length >= 8) {
            u32 block;
            if (!Digits::read8(data, &block)) return false;
            number = wrapping_add(number * 100000000, u64{block});
            data += 8;
            length = (range_int(length) - range_int<8, 9>{}).max(range_int<0, 1>{}).to<u32>();
        }
        if (length >= 4) {
            u32 block;
            if (!integer_detail::digits4(data, &block)) return false;
            number = wrapping_add(number * 10000, u64{block});
            data += 4;
            length = (range_int(length) - range_int<4, 5>{}).max(range_int<0, 1>{}).to<u32>();
        }
    }
    while (length--) {
        const u8 byte = byte_value(*data++);
        if (byte < '0' || byte > '9') return false;
        // In ASCII the low nibble of a validated digit is its decimal value.
        static_assert('0' == 0x30 && '9' == 0x39);
        number = wrapping_add(number * 10, bounded_remainder<16>(byte).to_u64());
    }
    constexpr u64 kPositiveLimit = Wide ? INT64_MAX : INT32_MAX;
    const u64 limit = wrapping_add(kPositiveLimit, u64{negative});
    if (number > limit) return false;
    *output = signed_wrapping_value(negative ? wrapping_sub(u64{0}, number) : number);
    return true;
}

// Compile-time selected runtime entry points. The implementation translation
// unit alone receives ISA flags; callers retain the normal deployment baseline.
bool parse_integer32(Str text, i64& output);
bool parse_integer64(Str text, i64& output);
const char* parse_integer_arch();

}  // namespace rut
