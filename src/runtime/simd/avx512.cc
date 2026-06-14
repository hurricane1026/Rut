/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#include "char_tables.h"
#include "simd.h"

#include <immintrin.h>  // AVX-512

namespace rut::simd {

u32 find_header_end(const u8* buf, u32 len, u32 from) {
    u32 start = from > 3 ? from - 3 : 0;
    u32 pos = start;
    const __m512i vcr = _mm512_set1_epi8('\r');

    while (pos + 64 <= len) {
        __m512i chunk = _mm512_loadu_si512(buf + pos);
        u64 mask = _mm512_cmpeq_epi8_mask(chunk, vcr);
        while (mask) {
            u32 bit = static_cast<u32>(__builtin_ctzll(mask));
            u32 idx = pos + bit;
            if (idx + 3 < len && buf[idx + 1] == '\n' && buf[idx + 2] == '\r' &&
                buf[idx + 3] == '\n') {
                return idx + 4;
            }
            mask &= mask - 1;
        }
        pos += 64;
    }
    for (; pos + 3 < len; pos++) {
        if (buf[pos] == '\r' && buf[pos + 1] == '\n' && buf[pos + 2] == '\r' &&
            buf[pos + 3] == '\n')
            return pos + 4;
    }
    return 0;
}

u32 scan_header_value(const u8* buf, u32 pos, u32 end) {
    const __m512i vcr = _mm512_set1_epi8('\r');
    const __m512i v20 = _mm512_set1_epi8(0x20);
    const __m512i vht = _mm512_set1_epi8(0x09);
    const __m512i vdel = _mm512_set1_epi8(0x7F);

    while (pos + 64 <= end) {
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
                u64 pre_cr = cr_pos < 64 ? ((1ULL << cr_pos) - 1) : ~0ULL;
                u64 real_bad = (bad_mask & pre_cr) & ~cr_mask;
                if (real_bad) return static_cast<u32>(-1);
                return pos + cr_pos;
            }
            if (bad_mask & ~cr_mask) return static_cast<u32>(-1);
        }
        pos += 64;
    }
    while (pos < end) {
        if (buf[pos] == '\r') return pos;
        if (!kHeaderValueTable[buf[pos]]) return static_cast<u32>(-1);
        pos++;
    }
    return end;
}

u32 scan_uri(const u8* buf, u32 pos, u32 end, u32* canon_end_out) {
    const __m512i vsp = _mm512_set1_epi8(' ');
    const __m512i v21 = _mm512_set1_epi8(0x21);
    const __m512i v7f = _mm512_set1_epi8(0x7F);
    const __m512i vq = _mm512_set1_epi8('?');
    const __m512i vh = _mm512_set1_epi8('#');

    u32 canon_end = end;  // sentinel: '?'/'#' not yet found

    while (pos + 64 <= end) {
        __m512i chunk = _mm512_loadu_si512(buf + pos);
        u64 sp_mask = _mm512_cmpeq_epi8_mask(chunk, vsp);
        // Reject bytes < 0x21, == 0x7F, or >= 0x80 (high bit set)
        u64 high_mask = _mm512_movepi8_mask(chunk);  // extract sign bit = high bit
        u64 bad_mask =
            _mm512_cmplt_epu8_mask(chunk, v21) | _mm512_cmpeq_epi8_mask(chunk, v7f) | high_mask;
        u64 qf_mask = _mm512_cmpeq_epi8_mask(chunk, vq) | _mm512_cmpeq_epi8_mask(chunk, vh);

        if (sp_mask) {
            u32 sp_pos = static_cast<u32>(__builtin_ctzll(sp_mask));
            u64 pre_sp = sp_pos < 64 ? ((1ULL << sp_pos) - 1) : ~0ULL;
            u64 real_bad = (bad_mask & pre_sp) & ~sp_mask;
            if (real_bad) return static_cast<u32>(-1);
            if (canon_end == end) {
                u64 qf_before_sp = qf_mask & pre_sp;
                canon_end = qf_before_sp ? (pos + static_cast<u32>(__builtin_ctzll(qf_before_sp)))
                                         : (pos + sp_pos);
            }
            *canon_end_out = canon_end;
            return pos + sp_pos;
        }
        if (bad_mask) return static_cast<u32>(-1);
        if (qf_mask && canon_end == end) {
            canon_end = pos + static_cast<u32>(__builtin_ctzll(qf_mask));
        }
        pos += 64;
    }
    while (pos < end) {
        u8 b = buf[pos];
        if (b == ' ') {
            *canon_end_out = (canon_end != end) ? canon_end : pos;
            return pos;
        }
        if (!kUriTable[b]) return static_cast<u32>(-1);
        if ((b == '?' || b == '#') && canon_end == end) canon_end = pos;
        pos++;
    }
    *canon_end_out = canon_end;
    return end;
}

u32 scan_header_name(const u8* buf, u32 pos, u32 end) {
    const __m512i vcolon = _mm512_set1_epi8(':');

    while (pos + 64 <= end) {
        __m512i chunk = _mm512_loadu_si512(buf + pos);
        u64 mask = _mm512_cmpeq_epi8_mask(chunk, vcolon);
        if (mask) {
            u32 colon_pos = static_cast<u32>(__builtin_ctzll(mask));
            for (u32 j = pos; j < pos + colon_pos; j++) {
                if (!kTokenTable[buf[j]]) return static_cast<u32>(-1);
            }
            return pos + colon_pos;
        }
        for (u32 j = pos; j < pos + 64; j++) {
            if (!kTokenTable[buf[j]]) return static_cast<u32>(-1);
        }
        pos += 64;
    }
    while (pos < end) {
        if (buf[pos] == ':') return pos;
        if (!kTokenTable[buf[pos]]) return static_cast<u32>(-1);
        pos++;
    }
    return static_cast<u32>(-1);
}

}  // namespace rut::simd
