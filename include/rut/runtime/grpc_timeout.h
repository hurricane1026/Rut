#pragma once

#include "rut/common/types.h"

namespace rut {

inline bool grpc_timeout(Str value, u64* micros) {
    if (!micros || value.len < 2 || value.len > 9) return false;
    u64 n = 0;
    for (u32 i = 0; i + 1 < value.len; i++) {
        if (value.ptr[i] < '0' || value.ptr[i] > '9') return false;
        n = n * 10 + static_cast<u32>(value.ptr[i] - '0');
    }
    switch (value.ptr[value.len - 1]) {
        case 'H':
            n *= 3600000000ull;
            break;
        case 'M':
            n *= 60000000ull;
            break;
        case 'S':
            n *= 1000000ull;
            break;
        case 'm':
            n *= 1000;
            break;
        case 'u':
            break;
        case 'n':
            n = (n + 999) / 1000;
            break;
        default:
            return false;
    }
    *micros = n;
    return true;
}

}  // namespace rut
