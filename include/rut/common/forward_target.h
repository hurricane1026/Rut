#pragma once

#include "rut/common/types.h"

namespace rut {
// Origin-form only. This preserves URI spelling; normalization is separate.
// Validation is shared by recording and dispatch, including direct-RIR callers.
inline bool forward_target_valid(Str target) {
    if (target.ptr == nullptr || target.len == 0 || target.len > 8192 || target.ptr[0] != '/')
        return false;
    auto hex = [](u8 value) {
        return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
               (value >= 'A' && value <= 'F');
    };
    for (u32 i = 0; i < target.len; i++) {
        const u8 kValue = static_cast<u8>(target.ptr[i]);
        if (kValue <= 0x20 || kValue == 0x7f || kValue == '#') return false;
        if (kValue == '%') {
            if (i64{target.len} - i64{i} < 3 || !hex(target.ptr[i64{i} + 1]) ||
                !hex(target.ptr[i64{i} + 2]))
                return false;
            i = static_cast<u32>(static_cast<i64>(i) + 2);
        }
    }
    return true;
}
}  // namespace rut
