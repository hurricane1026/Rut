#pragma once

#include "rut/common/types.h"

namespace rut {
// A literal raw query key must fit within one request-target component.
// Percent spelling, plus signs, non-ASCII bytes and case are not normalized.
inline bool http_query_name_valid(Str name) {
    if (!name.ptr || !name.len) return false;
    for (u32 i = 0; i < name.len; ++i) {
        const auto kByte = static_cast<u8>(name.ptr[i]);
        if (kByte <= 0x20 || kByte == 0x7f || kByte == '&' || kByte == '=' || kByte == '#')
            return false;
    }
    return true;
}
}  // namespace rut
