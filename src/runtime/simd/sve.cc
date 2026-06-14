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

#include <arm_sve.h>

namespace rut::simd {

// SVE intrinsics intentionally use the overloaded ACLE form
// (svcmpeq, svcmplt, ...) without explicit type suffixes. clang-18
// and onward enforce the spec'd overload set strictly: the suffixed
// _u8 / _n_u8 variants exist but the type-deducing overloaded names
// are the recommended portable form across compilers and ACLE
// revisions. The compiler picks the right unsigned-byte overload
// from the svuint8_t + scalar argument types.

u32 find_header_end(const u8* buf, u32 len, u32 from) {
    u32 start = from > 3 ? from - 3 : 0;
    u32 pos = start;
    u32 vl = static_cast<u32>(svcntb());  // vector length in bytes

    while (pos < len) {
        svbool_t pred = svwhilelt_b8(pos, len);
        svuint8_t chunk = svld1_u8(pred, buf + pos);
        svbool_t cr_match = svcmpeq(pred, chunk, static_cast<u8>('\r'));

        if (svptest_any(pred, cr_match)) {
            // Found \r — check each match position
            u32 remaining = len - pos;
            u32 check_len = remaining < vl ? remaining : vl;
            for (u32 i = 0; i < check_len; i++) {
                u32 idx = pos + i;
                if (idx + 3 < len && buf[idx] == '\r' && buf[idx + 1] == '\n' &&
                    buf[idx + 2] == '\r' && buf[idx + 3] == '\n') {
                    return idx + 4;
                }
            }
        }
        pos += vl;
    }
    return 0;
}

u32 scan_header_value(const u8* buf, u32 pos, u32 end) {
    u32 vl = static_cast<u32>(svcntb());

    while (pos < end) {
        u32 remaining = end - pos;
        svbool_t pred = svwhilelt_b8(static_cast<u32>(0), remaining);
        svuint8_t chunk = svld1_u8(pred, buf + pos);

        svbool_t cr_match = svcmpeq(pred, chunk, static_cast<u8>('\r'));
        svbool_t lt20 = svcmplt(pred, chunk, static_cast<u8>(0x20));  // unsigned compare
        svbool_t is_ht = svcmpeq(pred, chunk, static_cast<u8>(0x09));
        svbool_t bad_ctl = svbic_z(pred, lt20, is_ht);  // lt20 AND NOT is_ht
        svbool_t is_del = svcmpeq(pred, chunk, static_cast<u8>(0x7F));
        svbool_t bad = svorr_z(pred, bad_ctl, is_del);

        if (svptest_any(pred, svorr_z(pred, cr_match, bad))) {
            // Scalar fallback for this vector window
            u32 scan_end = pos + (remaining < vl ? remaining : vl);
            for (u32 i = pos; i < scan_end; i++) {
                if (buf[i] == '\r') return i;
                if (!kHeaderValueTable[buf[i]]) return static_cast<u32>(-1);
            }
        }
        pos += vl;
    }
    return end;
}

u32 scan_uri(const u8* buf, u32 pos, u32 end, u32* canon_end_out) {
    u32 vl = static_cast<u32>(svcntb());
    u32 canon_end = end;  // sentinel: '?'/'#' not yet found

    while (pos < end) {
        u32 remaining = end - pos;
        svbool_t pred = svwhilelt_b8(static_cast<u32>(0), remaining);
        svuint8_t chunk = svld1_u8(pred, buf + pos);

        svbool_t sp_match = svcmpeq(pred, chunk, static_cast<u8>(' '));
        svbool_t lt21 = svcmplt(pred, chunk, static_cast<u8>(0x21));
        svbool_t is_del = svcmpeq(pred, chunk, static_cast<u8>(0x7F));
        svbool_t ge80 = svcmpge(pred, chunk, static_cast<u8>(0x80));
        svbool_t bad = svorr_z(pred, svorr_z(pred, lt21, is_del), ge80);
        svbool_t qf_match = svorr_z(pred,
                                    svcmpeq(pred, chunk, static_cast<u8>('?')),
                                    svcmpeq(pred, chunk, static_cast<u8>('#')));

        if (svptest_any(pred, svorr_z(pred, svorr_z(pred, sp_match, bad), qf_match))) {
            u32 scan_end = pos + (remaining < vl ? remaining : vl);
            for (u32 i = pos; i < scan_end; i++) {
                u8 b = buf[i];
                if (b == ' ') {
                    *canon_end_out = (canon_end != end) ? canon_end : i;
                    return i;
                }
                if (!kUriTable[b]) return static_cast<u32>(-1);
                if ((b == '?' || b == '#') && canon_end == end) canon_end = i;
            }
        }
        pos += vl;
    }
    *canon_end_out = canon_end;
    return end;
}

u32 scan_header_name(const u8* buf, u32 pos, u32 end) {
    u32 vl = static_cast<u32>(svcntb());

    while (pos < end) {
        u32 remaining = end - pos;
        svbool_t pred = svwhilelt_b8(static_cast<u32>(0), remaining);
        svuint8_t chunk = svld1_u8(pred, buf + pos);

        svbool_t colon_match = svcmpeq(pred, chunk, static_cast<u8>(':'));

        if (svptest_any(pred, colon_match)) {
            u32 scan_end = pos + (remaining < vl ? remaining : vl);
            for (u32 i = pos; i < scan_end; i++) {
                if (buf[i] == ':') return i;
                if (!kTokenTable[buf[i]]) return static_cast<u32>(-1);
            }
        }
        // No colon — validate all bytes
        u32 scan_end = pos + (remaining < vl ? remaining : vl);
        for (u32 j = pos; j < scan_end; j++) {
            if (!kTokenTable[buf[j]]) return static_cast<u32>(-1);
        }
        pos += vl;
    }
    return static_cast<u32>(-1);
}

}  // namespace rut::simd
