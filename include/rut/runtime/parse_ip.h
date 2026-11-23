#pragma once

#include "rut/common/types.h"

namespace rut {
// Strict, complete IPv4 dotted-decimal text -> the network-order IP carrier
// used by req.remoteAddr. No allocation, terminator or input padding needed.
// Reject leading-zero octets and leave output unchanged on failure.
inline bool parse_ipv4_address(Str text, u32& output) {
    if (!text.ptr || text.len < 7 || text.len > 15) return false;
    u8 octets[4];
    u32 pos = 0;
    for (u32 part = 0; part < 4; ++part) {
        const u32 kStart = pos;
        u32 value = 0;
        while (pos < text.len && text.ptr[pos] >= '0' && text.ptr[pos] <= '9') {
            if (pos - kStart == 3) return false;
            value = value * 10 + static_cast<u32>(text.ptr[pos++] - '0');
            if (value > 255) return false;
        }
        if (pos == kStart || (pos - kStart > 1 && text.ptr[kStart] == '0')) return false;
        octets[part] = static_cast<u8>(value);
        if (part != 3) {
            if (pos == text.len || text.ptr[pos] != '.') return false;
            ++pos;
        } else if (pos != text.len) {
            return false;
        }
    }
    u32 result;
    __builtin_memcpy(&result, octets, sizeof(result));
    output = result;
    return true;
}
}  // namespace rut
