#pragma once

#include "rut/common/types.h"

namespace rut {

// RFC 6455 §8.1: a Text message's payload MUST be valid UTF-8. Validate the whole
// reassembled message (rejecting overlong forms, surrogates, and out-of-range code
// points), so a terminating gateway fails the connection instead of forwarding or
// handing malformed text to a DSL filter.
inline bool utf8_valid(const u8* s, u64 n) {
    if (!s && n != 0) return false;
    for (u64 i = 0; i < n;) {
        const u8 c = s[i];
        u64 extra;
        u32 cp;
        u32 min_cp;
        if (c < 0x80) {
            i++;
            continue;
        } else if ((c & 0xE0) == 0xC0) {
            extra = 1;
            cp = c & 0x1F;
            min_cp = 0x80;
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
            cp = c & 0x0F;
            min_cp = 0x800;
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
            cp = c & 0x07;
            min_cp = 0x10000;
        } else {
            return false;  // 0x80-0xBF lead, or 0xF8+ (5/6-byte forms)
        }
        if (i + extra >= n) return false;  // truncated multibyte sequence
        for (u64 k = 1; k <= extra; k++) {
            const u8 cc = s[i + k];
            if ((cc & 0xC0) != 0x80) return false;  // not a continuation byte
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (cp < min_cp) return false;                   // overlong encoding
        if (cp > 0x10FFFF) return false;                 // beyond Unicode
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;  // UTF-16 surrogate half
        i += extra + 1;
    }
    return true;
}

}  // namespace rut
