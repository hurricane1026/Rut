#pragma once

#include "rut/common/types.h"

namespace rut {

// Strict dotted IPv4 in the same host-order representation as req.remoteAddr.
inline bool parse_ipv4_canonical(Str text, u32& output) {
    output = 0;
    if (!text.ptr || text.len < 7 || text.len > 15) return false;
    u32 value = 0;
    u32 pos = 0;
    for (u32 octet = 0; octet < 4; ++octet) {
        const u32 start = pos;
        u32 part = 0;
        while (pos < text.len && text.ptr[pos] >= '0' && text.ptr[pos] <= '9') {
            if (pos - start == 3 || (pos > start && text.ptr[start] == '0')) return false;
            part = part * 10 + static_cast<u32>(text.ptr[pos++] - '0');
            if (part > 255) return false;
        }
        if (pos == start) return false;
        value = (value << 8) | part;
        if (octet < 3) {
            if (pos == text.len || text.ptr[pos++] != '.') return false;
        }
    }
    if (pos != text.len) return false;
    output = value;
    return true;
}

}  // namespace rut
