#pragma once

#include "rut/common/types.h"

namespace rut {
inline constexpr u32 kUuidTextLength = 36;
inline constexpr u32 kUuidRequestBudget = 256 * 1024;

// The OS reader must return exactly 16 bytes. A short read or failure never
// publishes a partial UUID. Reader injection keeps failure/vector tests local.
template <typename ReadEntropy>
bool generate_uuid(char (&out)[kUuidTextLength], ReadEntropy read_entropy) {
    u8 bytes[16]{};
    if (read_entropy(bytes, sizeof(bytes)) != static_cast<i32>(sizeof(bytes))) return false;
    // RFC 9562 UUID v4: 122 random bits, version 4, RFC variant 10xx.
    bytes[6] = static_cast<u8>((bytes[6] & 0x0f) | 0x40);
    bytes[8] = static_cast<u8>((bytes[8] & 0x3f) | 0x80);
    constexpr char kHex[] = "0123456789abcdef";
    u32 offset = 0;
    for (u32 i = 0; i < sizeof(bytes); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[offset++] = '-';
        out[offset++] = kHex[bytes[i] >> 4];
        out[offset++] = kHex[bytes[i] & 0x0f];
    }
    return true;
}
}  // namespace rut
