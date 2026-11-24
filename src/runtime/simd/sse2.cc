#include "char_tables.h"
#include "simd.h"

#include <emmintrin.h>  // SSE2

namespace rut::simd {

u32 find_header_end(const u8* buf, u32 len, u32 from) {
    i64 start = from > 3 ? static_cast<i64>(from) - 3 : 0;
    i64 pos = start;
    const __m128i vcr = _mm_set1_epi8('\r');

    while (pos + 16 <= static_cast<i64>(len)) {
        __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf + pos));
        int mask = _mm_movemask_epi8(_mm_cmpeq_epi8(chunk, vcr));
        while (mask) {
            u32 bit = static_cast<u32>(__builtin_ctz(static_cast<u32>(mask)));
            i64 idx = pos + static_cast<i64>(bit);
            if (idx + 3 < static_cast<i64>(len) && buf[idx + 1] == '\n' && buf[idx + 2] == '\r' &&
                buf[idx + 3] == '\n') {
                return static_cast<u32>(idx + 4);
            }
            mask &= static_cast<int>(static_cast<i64>(mask) - 1);
        }
        pos += 16;
    }
    for (; pos + 3 < static_cast<i64>(len); pos++) {
        if (buf[pos] == '\r' && buf[pos + 1] == '\n' && buf[pos + 2] == '\r' &&
            buf[pos + 3] == '\n')
            return static_cast<u32>(static_cast<i64>(static_cast<u32>(pos)) + 4);
    }
    return 0;
}

u32 scan_header_value(const u8* buf, u32 pos_in, u32 end) {
    i64 pos = pos_in;
    const __m128i vcr = _mm_set1_epi8('\r');
    const __m128i vht = _mm_set1_epi8(0x09);
    const __m128i vdel = _mm_set1_epi8(0x7F);
    // Unsigned comparison via xor-0x80 trick: (x ^ 0x80) <s (0x20 ^ 0x80)
    // This correctly handles obs-text bytes 0x80-0xFF as valid.
    const __m128i v80 = _mm_set1_epi8(static_cast<char>(0x80));
    const __m128i v20_biased = _mm_set1_epi8(static_cast<char>(0x20 ^ 0x80));

    while (pos + 16 <= static_cast<i64>(end)) {
        __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf + pos));
        int cr_mask = _mm_movemask_epi8(_mm_cmpeq_epi8(chunk, vcr));
        __m128i biased = _mm_xor_si128(chunk, v80);
        __m128i bad = _mm_or_si128(
            _mm_andnot_si128(_mm_cmpeq_epi8(chunk, vht), _mm_cmplt_epi8(biased, v20_biased)),
            _mm_cmpeq_epi8(chunk, vdel));
        int bad_mask = _mm_movemask_epi8(bad);

        if (cr_mask | bad_mask) {
            if (cr_mask) {
                u32 cr_pos = static_cast<u32>(__builtin_ctz(static_cast<u32>(cr_mask)));
                int real_bad = (bad_mask & (static_cast<int>((i64{1} << cr_pos) - 1))) & ~cr_mask;
                if (real_bad) return static_cast<u32>(-1);
                return static_cast<u32>(pos + static_cast<i64>(cr_pos));
            }
            if (bad_mask & ~cr_mask) return static_cast<u32>(-1);
        }
        pos += 16;
    }
    while (pos < static_cast<i64>(end)) {
        if (buf[pos] == '\r') return pos;
        if (!kHeaderValueTable[buf[pos]]) return static_cast<u32>(-1);
        pos++;
    }
    return end;
}

u32 scan_uri(const u8* buf, u32 pos_in, u32 end, u32* canon_end_out) {
    i64 pos = pos_in;
    const __m128i vsp = _mm_set1_epi8(' ');
    const __m128i v21 = _mm_set1_epi8(0x21);
    const __m128i v7f = _mm_set1_epi8(0x7F);
    const __m128i vq = _mm_set1_epi8('?');
    const __m128i vh = _mm_set1_epi8('#');

    u32 canon_end = end;  // sentinel: '?'/'#' not yet found

    while (pos + 16 <= static_cast<i64>(end)) {
        __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf + pos));
        int sp_mask = _mm_movemask_epi8(_mm_cmpeq_epi8(chunk, vsp));
        int bad_mask =
            _mm_movemask_epi8(_mm_or_si128(_mm_cmplt_epi8(chunk, v21), _mm_cmpeq_epi8(chunk, v7f)));
        int qf_mask =
            _mm_movemask_epi8(_mm_or_si128(_mm_cmpeq_epi8(chunk, vq), _mm_cmpeq_epi8(chunk, vh)));

        if (sp_mask) {
            u32 sp_pos = static_cast<u32>(__builtin_ctz(static_cast<u32>(sp_mask)));
            int pre_sp = static_cast<int>((i64{1} << sp_pos) - 1);
            int real_bad = (bad_mask & pre_sp) & ~sp_mask;
            if (real_bad) return static_cast<u32>(-1);
            if (canon_end == end) {
                int qf_before_sp = qf_mask & pre_sp;
                canon_end =
                    qf_before_sp
                        ? static_cast<u32>(
                              pos + static_cast<i64>(__builtin_ctz(static_cast<u32>(qf_before_sp))))
                        : static_cast<u32>(pos + static_cast<i64>(sp_pos));
            }
            *canon_end_out = canon_end;
            return static_cast<u32>(pos + static_cast<i64>(sp_pos));
        }
        if (bad_mask) return static_cast<u32>(-1);
        if (qf_mask && canon_end == end) {
            canon_end =
                static_cast<u32>(pos + static_cast<i64>(__builtin_ctz(static_cast<u32>(qf_mask))));
        }
        pos += 16;
    }
    while (pos < static_cast<i64>(end)) {
        u8 b = buf[pos];
        if (b == ' ') {
            *canon_end_out = (canon_end != end) ? canon_end : pos;
            return static_cast<u32>(pos);
        }
        if (!kUriTable[b]) return static_cast<u32>(-1);
        if ((b == '?' || b == '#') && canon_end == end) canon_end = static_cast<u32>(pos);
        pos++;
    }
    *canon_end_out = canon_end;
    return end;
}

u32 scan_header_name(const u8* buf, u32 pos_in, u32 end) {
    i64 pos = pos_in;
    const __m128i vcolon = _mm_set1_epi8(':');

    while (pos + 16 <= static_cast<i64>(end)) {
        __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf + pos));
        int mask = _mm_movemask_epi8(_mm_cmpeq_epi8(chunk, vcolon));
        if (mask) {
            u32 colon_pos = static_cast<u32>(__builtin_ctz(static_cast<u32>(mask)));
            for (i64 j = pos; j < pos + static_cast<i64>(colon_pos); j++) {
                if (!kTokenTable[buf[j]]) return static_cast<u32>(-1);
            }
            return static_cast<u32>(pos + static_cast<i64>(colon_pos));
        }
        for (i64 j = pos; j < pos + 16; j++) {
            if (!kTokenTable[buf[j]]) return static_cast<u32>(-1);
        }
        pos += 16;
    }
    while (pos < static_cast<i64>(end)) {
        if (buf[pos] == ':') return static_cast<u32>(pos);
        if (!kTokenTable[buf[pos]]) return static_cast<u32>(-1);
        pos++;
    }
    return static_cast<u32>(-1);
}

}  // namespace rut::simd
