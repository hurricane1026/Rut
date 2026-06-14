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

#include <arm_neon.h>

namespace rut::simd {

static inline bool neon_any(uint8x16_t v) {
    return vmaxvq_u8(v) != 0;
}

// Compress a 16-byte comparison-result vector (0xFF per match lane,
// 0x00 per no-match) into a 64-bit bitmask with 4 bits per source byte.
// Source byte i contributes nibble [4i..4i+3] of the result: 0xF if
// the byte matched, 0x0 otherwise.
//
// Trick: reinterpret the 16 u8 lanes as 8 u16 lanes (each pair of
// adjacent bytes packed into one 16-bit lane). vshrn_n_u16(_, 4)
// shifts each 16-bit lane right by 4 and narrows to 8 bits, which
// for our 0xFF/0x00 input produces 0xFF/0x0F/0xF0/0x00 patterns —
// exactly the 4-bits-per-source-byte layout we want, packed into 8
// output bytes (= 64 bits). vget_lane_u64 reads the result as a
// scalar.
//
// To find the first matching source byte position: __builtin_ctzll
// the resulting mask, then divide by 4. (Same idea as
// _mm_movemask_epi8 + tzcnt on x86, but ARM doesn't have a direct
// movemask; this shrn-trick is the canonical replacement, used by
// simdjson and others.)
static inline u64 neon_movemask(uint8x16_t v) {
    uint16x8_t v16 = vreinterpretq_u16_u8(v);
    uint8x8_t narrowed = vshrn_n_u16(v16, 4);
    return vget_lane_u64(vreinterpret_u64_u8(narrowed), 0);
}

u32 find_header_end(const u8* buf, u32 len, u32 from) {
    u32 start = from > 3 ? from - 3 : 0;
    u32 pos = start;
    const uint8x16_t vcr = vdupq_n_u8('\r');

    while (pos + 16 <= len) {
        uint8x16_t chunk = vld1q_u8(buf + pos);
        uint8x16_t cmp = vceqq_u8(chunk, vcr);
        if (neon_any(cmp)) {
            // Found at least one \r — check each position
            for (u32 i = 0; i < 16 && pos + i + 3 < len; i++) {
                if (buf[pos + i] == '\r' && buf[pos + i + 1] == '\n' && buf[pos + i + 2] == '\r' &&
                    buf[pos + i + 3] == '\n') {
                    return pos + i + 4;
                }
            }
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
    const uint8x16_t vcr = vdupq_n_u8('\r');
    const uint8x16_t v20 = vdupq_n_u8(0x20);
    const uint8x16_t vht = vdupq_n_u8(0x09);
    const uint8x16_t vdel = vdupq_n_u8(0x7F);

    while (pos + 16 <= end) {
        uint8x16_t chunk = vld1q_u8(buf + pos);
        uint8x16_t cr_match = vceqq_u8(chunk, vcr);
        // vcltq_u8 is unsigned < (NEON advantage over SSE2)
        uint8x16_t lt20 = vcltq_u8(chunk, v20);
        uint8x16_t is_ht = vceqq_u8(chunk, vht);
        uint8x16_t bad_ctl = vbicq_u8(lt20, is_ht);  // lt20 AND NOT is_ht
        uint8x16_t is_del = vceqq_u8(chunk, vdel);
        uint8x16_t bad = vorrq_u8(bad_ctl, is_del);

        const u64 cr_mask = neon_movemask(cr_match);
        const u64 bad_mask = neon_movemask(bad);

        if (cr_mask) {
            const u32 cr_byte = static_cast<u32>(__builtin_ctzll(cr_mask)) >> 2;
            const u64 pre_cr_nibbles = cr_byte == 0 ? 0 : ((1ULL << (cr_byte * 4)) - 1);
            const u64 real_bad = bad_mask & pre_cr_nibbles & ~cr_mask;
            if (real_bad) return static_cast<u32>(-1);
            return pos + cr_byte;
        }
        if (bad_mask) return static_cast<u32>(-1);
        pos += 16;
    }
    while (pos < end) {
        if (buf[pos] == '\r') return pos;
        if (!kHeaderValueTable[buf[pos]]) return static_cast<u32>(-1);
        pos++;
    }
    return end;
}

u32 scan_uri(const u8* buf, u32 pos, u32 end, u32* canon_end_out) {
    const uint8x16_t vsp = vdupq_n_u8(' ');
    const uint8x16_t v21 = vdupq_n_u8(0x21);
    const uint8x16_t v7f = vdupq_n_u8(0x7F);
    const uint8x16_t v80 = vdupq_n_u8(0x80);
    const uint8x16_t vq = vdupq_n_u8('?');
    const uint8x16_t vh = vdupq_n_u8('#');

    u32 canon_end = end;  // sentinel: '?'/'#' not yet found

    while (pos + 16 <= end) {
        uint8x16_t chunk = vld1q_u8(buf + pos);
        uint8x16_t sp_match = vceqq_u8(chunk, vsp);
        uint8x16_t high = vcgeq_u8(chunk, v80);
        uint8x16_t bad = vorrq_u8(vorrq_u8(vcltq_u8(chunk, v21), vceqq_u8(chunk, v7f)), high);
        uint8x16_t qf_match = vorrq_u8(vceqq_u8(chunk, vq), vceqq_u8(chunk, vh));

        const u64 sp_mask = neon_movemask(sp_match);
        const u64 bad_mask = neon_movemask(bad);
        const u64 qf_mask = neon_movemask(qf_match);

        // Bitmask layout: bits [4i..4i+3] correspond to source byte i,
        // all set if matched. To compare positions we use the
        // first-set-bit (ctzll) and divide by 4 to get the byte index.
        if (sp_mask) {
            const u32 sp_byte = static_cast<u32>(__builtin_ctzll(sp_mask)) >> 2;
            const u64 pre_sp_nibbles = sp_byte == 0 ? 0 : ((1ULL << (sp_byte * 4)) - 1);
            const u64 real_bad = bad_mask & pre_sp_nibbles & ~sp_mask;
            if (real_bad) return static_cast<u32>(-1);
            if (canon_end == end) {
                const u64 qf_before_sp = qf_mask & pre_sp_nibbles;
                canon_end = qf_before_sp
                                ? (pos + (static_cast<u32>(__builtin_ctzll(qf_before_sp)) >> 2))
                                : (pos + sp_byte);
            }
            *canon_end_out = canon_end;
            return pos + sp_byte;
        }
        if (bad_mask) return static_cast<u32>(-1);
        if (qf_mask && canon_end == end) {
            canon_end = pos + (static_cast<u32>(__builtin_ctzll(qf_mask)) >> 2);
        }
        pos += 16;
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
    const uint8x16_t vcolon = vdupq_n_u8(':');

    while (pos + 16 <= end) {
        uint8x16_t chunk = vld1q_u8(buf + pos);
        uint8x16_t cmp = vceqq_u8(chunk, vcolon);
        if (neon_any(cmp)) {
            for (u32 i = 0; i < 16 && pos + i < end; i++) {
                if (buf[pos + i] == ':') return pos + i;
                if (!kTokenTable[buf[pos + i]]) return static_cast<u32>(-1);
            }
        }
        for (u32 j = pos; j < pos + 16; j++) {
            if (!kTokenTable[buf[j]]) return static_cast<u32>(-1);
        }
        pos += 16;
    }
    while (pos < end) {
        if (buf[pos] == ':') return pos;
        if (!kTokenTable[buf[pos]]) return static_cast<u32>(-1);
        pos++;
    }
    return static_cast<u32>(-1);
}

}  // namespace rut::simd
