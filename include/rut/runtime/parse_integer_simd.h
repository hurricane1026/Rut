#pragma once

#include "rut/runtime/parse_integer.h"

#if defined(RUT_INTEGER_ARCH_SSE2) || defined(RUT_INTEGER_ARCH_AVX2) || \
    defined(RUT_INTEGER_ARCH_AVX512)
#include <immintrin.h>
#elif defined(RUT_INTEGER_ARCH_NEON)
#include <arm_neon.h>
#endif

namespace rut::integer_detail {

#if defined(RUT_INTEGER_ARCH_SSE2) || defined(RUT_INTEGER_ARCH_AVX2) || \
    defined(RUT_INTEGER_ARCH_AVX512)
inline u32 low_group(__m128i groups) {
    return static_cast<u32>(_mm_cvtsi128_si32(groups));
}
inline u64 combine16(__m128i groups) {
    const u64 high =
        static_cast<u64>(low_group(groups)) * 10000 + low_group(_mm_srli_si128(groups, 4));
    const u64 low = static_cast<u64>(low_group(_mm_srli_si128(groups, 8))) * 10000 +
                    low_group(_mm_srli_si128(groups, 12));
    return high * 100000000 + low;
}

#if defined(RUT_INTEGER_ARCH_SSE2) || defined(RUT_INTEGER_ARCH_AVX2)
inline bool valid_digits(__m128i digits, u32 mask) {
    const auto excess = _mm_subs_epu8(digits, _mm_set1_epi8(9));
    return (static_cast<u32>(_mm_movemask_epi8(_mm_cmpeq_epi8(excess, _mm_setzero_si128()))) &
            mask) == mask;
}
inline __m128i four_digit_groups(__m128i digits) {
#if defined(RUT_INTEGER_ARCH_AVX2)
    // VEX-encoded 128-bit multiply-add is enough for one <=19-digit integer.
    const auto pairs = _mm_maddubs_epi16(digits, _mm_set1_epi16(0x010a));
#else
    // SSE2 baseline has no byte multiply-add: widen first, then pack the
    // two-digit values (0...99) losslessly into signed 16-bit lanes.
    const auto weights = _mm_set1_epi32(0x0001000a);
    const auto low = _mm_madd_epi16(_mm_unpacklo_epi8(digits, _mm_setzero_si128()), weights);
    const auto high = _mm_madd_epi16(_mm_unpackhi_epi8(digits, _mm_setzero_si128()), weights);
    const auto pairs = _mm_packs_epi32(low, high);
#endif
    return _mm_madd_epi16(pairs, _mm_set1_epi32(0x00010064));
}
struct X86Digits {
    static constexpr bool kBlock16 = true;
    static bool read8(const char* data, u32& result) {
        u64 word;
        __builtin_memcpy(&word, data, sizeof(word));
        const auto digits =
            _mm_sub_epi8(_mm_cvtsi64_si128(static_cast<i64>(word)), _mm_set1_epi8('0'));
        if (!valid_digits(digits, 0xff)) return false;
        const auto groups = four_digit_groups(digits);
        result = low_group(groups) * 10000 + low_group(_mm_srli_si128(groups, 4));
        return true;
    }
    static bool read16(const char* data, u64& result) {
        const auto digits = _mm_sub_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data)),
                                         _mm_set1_epi8('0'));
        if (!valid_digits(digits, 0xffff)) return false;
        result = combine16(four_digit_groups(digits));
        return true;
    }
};
using SelectedDigits = X86Digits;
#elif defined(RUT_INTEGER_ARCH_AVX512)
struct Avx512Digits {
    static constexpr bool kBlock16 = true;
    static bool groups(const char* data, __mmask64 mask, __m128i& result) {
        // Byte-granularity fault-suppressing loads need F+BW, but neither VL,
        // DQ, IFMA nor VBMI. Only the 8/16 input bytes are accessed.
        const auto input = _mm512_maskz_loadu_epi8(mask, data);
        const auto digits = _mm512_maskz_sub_epi8(mask, input, _mm512_set1_epi8('0'));
        if (_mm512_cmpgt_epu8_mask(digits, _mm512_set1_epi8(9))) return false;
        const auto pairs = _mm512_maddubs_epi16(digits, _mm512_set1_epi16(0x010a));
        result = _mm512_castsi512_si128(_mm512_madd_epi16(pairs, _mm512_set1_epi32(0x00010064)));
        return true;
    }
    static bool read8(const char* data, u32& result) {
        __m128i blocks;
        if (!groups(data, 0xff, blocks)) return false;
        result = low_group(blocks) * 10000 + low_group(_mm_srli_si128(blocks, 4));
        return true;
    }
    static bool read16(const char* data, u64& result) {
        __m128i blocks;
        if (!groups(data, 0xffff, blocks)) return false;
        result = combine16(blocks);
        return true;
    }
};
using SelectedDigits = Avx512Digits;
#endif
#elif defined(RUT_INTEGER_ARCH_NEON)
struct NeonDigits {
    static constexpr bool kBlock16 = true;
    static u32 reduce8(uint8x8_t digits) {
        const u8 byte_weights[] = {10, 1, 10, 1, 10, 1, 10, 1};
        const u32 pair_weights[] = {100, 1, 100, 1};
        const auto pairs = vpaddlq_u16(vmull_u8(digits, vld1_u8(byte_weights)));
        const auto groups = vpaddlq_u32(vmulq_u32(pairs, vld1q_u32(pair_weights)));
        return static_cast<u32>(vgetq_lane_u64(groups, 0) * 10000 + vgetq_lane_u64(groups, 1));
    }
    static bool read8(const char* data, u32& result) {
        const auto digits = vsub_u8(vld1_u8(reinterpret_cast<const u8*>(data)), vdup_n_u8('0'));
        if (vmaxv_u8(digits) > 9) return false;
        result = reduce8(digits);
        return true;
    }
    static bool read16(const char* data, u64& result) {
        const auto digits = vsubq_u8(vld1q_u8(reinterpret_cast<const u8*>(data)), vdupq_n_u8('0'));
        if (vmaxvq_u8(digits) > 9) return false;
        result = static_cast<u64>(reduce8(vget_low_u8(digits))) * 100000000 +
                 reduce8(vget_high_u8(digits));
        return true;
    }
};
using SelectedDigits = NeonDigits;
#else
using SelectedDigits = PortableDigits;
#endif

}  // namespace rut::integer_detail
