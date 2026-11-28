#include "char_tables.h"
#include "simd.h"

#include <immintrin.h>  // AVX-512

namespace rut::simd {

u32 find_header_end(const u8* buf, u32 len, u32 from) {
    i64 start = from > 3 ? static_cast<i64>(from) - 3 : 0;
    i64 pos = start;
    const __m512i vcr = _mm512_set1_epi8('\r');

    while (pos + 64 <= static_cast<i64>(len)) {
        __m512i chunk = _mm512_loadu_si512(buf + pos);
        u64 mask = _mm512_cmpeq_epi8_mask(chunk, vcr);
        while (mask) {
            u32 bit = static_cast<u32>(__builtin_ctzll(mask));
            i64 idx = pos + static_cast<i64>(bit);
            if (idx + 3 < static_cast<i64>(len) && buf[idx + 1] == '\n' && buf[idx + 2] == '\r' &&
                buf[idx + 3] == '\n') {
                return static_cast<u32>(idx + 4);
            }
            mask ^= u64{1} << bit;
        }
        pos += 64;
    }
    for (; pos + 3 < static_cast<i64>(len); pos++) {
        if (buf[pos] == '\r' && buf[pos + 1] == '\n' && buf[pos + 2] == '\r' &&
            buf[pos + 3] == '\n')
            return static_cast<u32>(pos + 4);
    }
    return 0;
}

u32 scan_header_value(const u8* buf, u32 pos_in, u32 end) {
    i64 pos = pos_in;
    const __m512i vcr = _mm512_set1_epi8('\r');
    const __m512i v20 = _mm512_set1_epi8(0x20);
    const __m512i vht = _mm512_set1_epi8(0x09);
    const __m512i vdel = _mm512_set1_epi8(0x7F);

    while (pos + 64 <= static_cast<i64>(end)) {
        __m512i chunk = _mm512_loadu_si512(buf + pos);

        // AVX-512BW has unsigned compare — much cleaner
        u64 cr_mask = _mm512_cmpeq_epi8_mask(chunk, vcr);
        u64 lt20 = _mm512_cmplt_epu8_mask(chunk, v20);  // unsigned < 0x20
        u64 is_ht = _mm512_cmpeq_epi8_mask(chunk, vht);
        u64 is_del = _mm512_cmpeq_epi8_mask(chunk, vdel);
        u64 bad_mask = (lt20 & ~is_ht) | is_del;

        if (cr_mask | bad_mask) {
            if (cr_mask) {
                u32 cr_pos = static_cast<u32>(__builtin_ctzll(cr_mask));
                u64 pre_cr = cr_pos < 64 ? ~(~0ULL << cr_pos) : ~0ULL;
                u64 real_bad = (bad_mask & pre_cr) & ~cr_mask;
                if (real_bad) return UINT32_MAX;
                return static_cast<u32>(pos + static_cast<i64>(cr_pos));
            }
            if (bad_mask & ~cr_mask) return UINT32_MAX;
        }
        pos += 64;
    }
    while (pos < static_cast<i64>(end)) {
        if (buf[pos] == '\r') return pos;
        if (!kHeaderValueTable[buf[pos]]) return UINT32_MAX;
        pos++;
    }
    return end;
}

u32 scan_uri(const u8* buf, u32 pos_in, u32 end, u32* canon_end_out) {
    i64 pos = pos_in;
    const __m512i vsp = _mm512_set1_epi8(' ');
    const __m512i v21 = _mm512_set1_epi8(0x21);
    const __m512i v7f = _mm512_set1_epi8(0x7F);
    const __m512i vq = _mm512_set1_epi8('?');
    const __m512i vh = _mm512_set1_epi8('#');

    u32 canon_end = end;  // sentinel: '?'/'#' not yet found

    while (pos + 64 <= static_cast<i64>(end)) {
        __m512i chunk = _mm512_loadu_si512(buf + pos);
        u64 sp_mask = _mm512_cmpeq_epi8_mask(chunk, vsp);
        // Reject bytes < 0x21, == 0x7F, or >= 0x80 (high bit set)
        u64 high_mask = _mm512_movepi8_mask(chunk);  // extract sign bit = high bit
        u64 bad_mask =
            _mm512_cmplt_epu8_mask(chunk, v21) | _mm512_cmpeq_epi8_mask(chunk, v7f) | high_mask;
        u64 qf_mask = _mm512_cmpeq_epi8_mask(chunk, vq) | _mm512_cmpeq_epi8_mask(chunk, vh);

        if (sp_mask) {
            u32 sp_pos = static_cast<u32>(__builtin_ctzll(sp_mask));
            u64 pre_sp = sp_pos < 64 ? ~(~0ULL << sp_pos) : ~0ULL;
            u64 real_bad = (bad_mask & pre_sp) & ~sp_mask;
            if (real_bad) return UINT32_MAX;
            if (canon_end == end) {
                u64 qf_before_sp = qf_mask & pre_sp;
                canon_end =
                    qf_before_sp
                        ? static_cast<u32>(pos + static_cast<i64>(__builtin_ctzll(qf_before_sp)))
                        : static_cast<u32>(pos + static_cast<i64>(sp_pos));
            }
            *canon_end_out = canon_end;
            return static_cast<u32>(pos + static_cast<i64>(sp_pos));
        }
        if (bad_mask) return UINT32_MAX;
        if (qf_mask && canon_end == end) {
            canon_end = static_cast<u32>(pos + static_cast<i64>(__builtin_ctzll(qf_mask)));
        }
        pos += 64;
    }
    while (pos < static_cast<i64>(end)) {
        u8 b = buf[pos];
        if (b == ' ') {
            *canon_end_out = (canon_end != end) ? canon_end : pos;
            return static_cast<u32>(pos);
        }
        if (!kUriTable[b]) return UINT32_MAX;
        if ((b == '?' || b == '#') && canon_end == end) canon_end = static_cast<u32>(pos);
        pos++;
    }
    *canon_end_out = canon_end;
    return end;
}

u32 scan_header_name(const u8* buf, u32 pos_in, u32 end) {
    i64 pos = pos_in;
    const __m512i vcolon = _mm512_set1_epi8(':');

    while (pos + 64 <= static_cast<i64>(end)) {
        __m512i chunk = _mm512_loadu_si512(buf + pos);
        u64 mask = _mm512_cmpeq_epi8_mask(chunk, vcolon);
        if (mask) {
            u32 colon_pos = static_cast<u32>(__builtin_ctzll(mask));
            for (i64 j = pos; j < pos + static_cast<i64>(colon_pos); j++) {
                if (!kTokenTable[buf[j]]) return UINT32_MAX;
            }
            return static_cast<u32>(pos + static_cast<i64>(colon_pos));
        }
        for (i64 j = pos; j < pos + 64; j++) {
            if (!kTokenTable[buf[j]]) return UINT32_MAX;
        }
        pos += 64;
    }
    while (pos < static_cast<i64>(end)) {
        if (buf[pos] == ':') return static_cast<u32>(pos);
        if (!kTokenTable[buf[pos]]) return UINT32_MAX;
        pos++;
    }
    return UINT32_MAX;
}

}  // namespace rut::simd
