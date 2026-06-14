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

#include <immintrin.h>  // AVX2

namespace rut::simd {

u32 find_header_end(const u8* buf, u32 len, u32 from) {
    u32 start = from > 3 ? from - 3 : 0;
    u32 pos = start;
    const __m256i vcr = _mm256_set1_epi8('\r');

    while (pos + 32 <= len) {
        __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buf + pos));
        u32 mask = static_cast<u32>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, vcr)));
        while (mask) {
            u32 bit = static_cast<u32>(__builtin_ctz(mask));
            u32 idx = pos + bit;
            if (idx + 3 < len && buf[idx + 1] == '\n' && buf[idx + 2] == '\r' &&
                buf[idx + 3] == '\n') {
                return idx + 4;
            }
            mask &= mask - 1;
        }
        pos += 32;
    }
    // SSE2-width tail (16 bytes)
    const __m128i vcr128 = _mm_set1_epi8('\r');
    while (pos + 16 <= len) {
        __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf + pos));
        int mask128 = _mm_movemask_epi8(_mm_cmpeq_epi8(chunk, vcr128));
        while (mask128) {
            u32 bit = static_cast<u32>(__builtin_ctz(static_cast<u32>(mask128)));
            u32 idx = pos + bit;
            if (idx + 3 < len && buf[idx + 1] == '\n' && buf[idx + 2] == '\r' &&
                buf[idx + 3] == '\n')
                return idx + 4;
            mask128 &= mask128 - 1;
        }
        pos += 16;
    }
    for (; pos + 3 < len; pos++) {
        if (buf[pos] == '\r' && buf[pos + 1] == '\n' && buf[pos + 2] == '\r' &&
            buf[pos + 3] == '\n')
            return pos + 4;
    }
    return 0;
}

u32 scan_header_value(const u8* buf, u32 pos, u32 end) {
    const __m256i vcr = _mm256_set1_epi8('\r');
    const __m256i vht = _mm256_set1_epi8(0x09);
    const __m256i vdel = _mm256_set1_epi8(0x7F);
    // Unsigned comparison via xor-0x80 trick: (x ^ 0x80) <s (0x20 ^ 0x80)
    // This correctly handles obs-text bytes 0x80-0xFF as valid.
    const __m256i v80 = _mm256_set1_epi8(static_cast<char>(0x80));
    const __m256i v20_biased = _mm256_set1_epi8(static_cast<char>(0x20 ^ 0x80));

    while (pos + 32 <= end) {
        __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buf + pos));
        u32 cr_mask = static_cast<u32>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, vcr)));
        // bad: (< 0x20 unsigned && != HT) || == DEL
        __m256i biased = _mm256_xor_si256(chunk, v80);
        __m256i lt20 = _mm256_cmpgt_epi8(v20_biased, biased);  // unsigned chunk < 0x20
        __m256i bad = _mm256_or_si256(_mm256_andnot_si256(_mm256_cmpeq_epi8(chunk, vht), lt20),
                                      _mm256_cmpeq_epi8(chunk, vdel));
        u32 bad_mask = static_cast<u32>(_mm256_movemask_epi8(bad));

        if (cr_mask | bad_mask) {
            if (cr_mask) {
                u32 cr_pos = static_cast<u32>(__builtin_ctz(cr_mask));
                u32 real_bad = (bad_mask & ((1u << cr_pos) - 1)) & ~cr_mask;
                if (real_bad) return static_cast<u32>(-1);
                return pos + cr_pos;
            }
            if (bad_mask & ~cr_mask) return static_cast<u32>(-1);
        }
        pos += 32;
    }
    // Scalar tail
    while (pos < end) {
        if (buf[pos] == '\r') return pos;
        if (!kHeaderValueTable[buf[pos]]) return static_cast<u32>(-1);
        pos++;
    }
    return end;
}

u32 scan_uri(const u8* buf, u32 pos, u32 end, u32* canon_end_out) {
    const __m256i vsp = _mm256_set1_epi8(' ');
    const __m256i v21 = _mm256_set1_epi8(0x21);
    const __m256i v7f = _mm256_set1_epi8(0x7F);
    const __m256i vq = _mm256_set1_epi8('?');
    const __m256i vh = _mm256_set1_epi8('#');

    u32 canon_end = end;  // sentinel: '?'/'#' not yet found

    while (pos + 32 <= end) {
        __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buf + pos));
        u32 sp_mask = static_cast<u32>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, vsp)));
        u32 bad_mask = static_cast<u32>(_mm256_movemask_epi8(
            _mm256_or_si256(_mm256_cmpgt_epi8(v21, chunk), _mm256_cmpeq_epi8(chunk, v7f))));
        u32 qf_mask = static_cast<u32>(_mm256_movemask_epi8(
            _mm256_or_si256(_mm256_cmpeq_epi8(chunk, vq), _mm256_cmpeq_epi8(chunk, vh))));

        if (sp_mask) {
            u32 sp_pos = static_cast<u32>(__builtin_ctz(sp_mask));
            u32 pre_sp = (1u << sp_pos) - 1;
            u32 real_bad = (bad_mask & pre_sp) & ~sp_mask;
            if (real_bad) return static_cast<u32>(-1);
            if (canon_end == end) {
                u32 qf_before_sp = qf_mask & pre_sp;
                canon_end = qf_before_sp ? (pos + static_cast<u32>(__builtin_ctz(qf_before_sp)))
                                         : (pos + sp_pos);
            }
            *canon_end_out = canon_end;
            return pos + sp_pos;
        }
        if (bad_mask) return static_cast<u32>(-1);
        if (qf_mask && canon_end == end) {
            canon_end = pos + static_cast<u32>(__builtin_ctz(qf_mask));
        }
        pos += 32;
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
    const __m256i vcolon = _mm256_set1_epi8(':');

    while (pos + 32 <= end) {
        __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buf + pos));
        u32 mask = static_cast<u32>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, vcolon)));
        if (mask) {
            u32 colon_pos = static_cast<u32>(__builtin_ctz(mask));
            for (u32 j = pos; j < pos + colon_pos; j++) {
                if (!kTokenTable[buf[j]]) return static_cast<u32>(-1);
            }
            return pos + colon_pos;
        }
        for (u32 j = pos; j < pos + 32; j++) {
            if (!kTokenTable[buf[j]]) return static_cast<u32>(-1);
        }
        pos += 32;
    }
    while (pos < end) {
        if (buf[pos] == ':') return pos;
        if (!kTokenTable[buf[pos]]) return static_cast<u32>(-1);
        pos++;
    }
    return static_cast<u32>(-1);
}

}  // namespace rut::simd
