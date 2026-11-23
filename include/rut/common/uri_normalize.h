#pragma once

#include "rut/common/forward_target.h"
#include "rut/common/types.h"

namespace rut {
// RFC 3986 path normalization for an explicitly selected policy. Query bytes
// remain opaque. Output may equal input; other overlapping views are unsupported.
// The caller reserves at least input.len bytes and owns the output lifetime.
inline bool normalize_forward_target(Str input, char* output, u32 capacity, u32* length) {
    if (length == nullptr) return false;
    *length = 0;
    if (!forward_target_valid(input) || output == nullptr || capacity < input.len) return false;
    auto hex = [](u8 value) -> u8 {
        if (value >= '0' && value <= '9') return static_cast<u8>(static_cast<i64>(value) - '0');
        if (value >= 'a' && value <= 'f')
            return static_cast<u8>(static_cast<i64>(value) - 'a' + 10);
        return static_cast<u8>(static_cast<i64>(value) - 'A' + 10);
    };
    auto unreserved = [](u8 value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
               (value >= '0' && value <= '9') || value == '-' || value == '.' || value == '_' ||
               value == '~';
    };
    static constexpr char kHex[] = "0123456789ABCDEF";
    i64 path_end = 0;
    while (path_end < static_cast<i64>(input.len) && input.ptr[path_end] != '?') ++path_end;
    i64 decoded = 0;
    for (i64 i = 0; i < path_end; ++i) {
        if (input.ptr[i] != '%') {
            output[decoded++] = input.ptr[i];
            continue;
        }
        const u8 kValue = static_cast<u8>((hex(input.ptr[i + 1]) << 4) | hex(input.ptr[i + 2]));
        if (unreserved(kValue))
            output[decoded++] = static_cast<char>(kValue);
        else {
            output[decoded++] = '%';
            output[decoded++] = kHex[kValue >> 4];
            output[decoded++] = kHex[kValue & 15];
        }
        i += 2;
    }
    bool trailing_slash = decoded > 1 && output[decoded - 1] == '/';
    i64 write = 1;
    i64 read = 1;
    while (read < decoded) {
        while (read < decoded && output[read] == '/') read++;
        const i64 kBegin = read;
        while (read < decoded && output[read] != '/') read++;
        const i64 kSize = read - kBegin;
        if (kSize == 0) break;
        const bool kDot = kSize == 1 && output[kBegin] == '.';
        const bool kParent = kSize == 2 && output[kBegin] == '.' && output[kBegin + 1] == '.';
        if (kDot || kParent) {
            if (read == decoded) trailing_slash = true;
            if (kParent && write > 1) {
                while (write > 1 && output[write - 1] != '/') --write;
                if (write > 1) write--;
            }
            continue;
        }
        if (write > 1) output[write++] = '/';
        __builtin_memmove(output + write, output + kBegin, static_cast<u32>(kSize));
        write += kSize;
    }
    if (trailing_slash && write > 1) output[write++] = '/';
    const i64 kQueryLength = static_cast<i64>(input.len) - path_end;
    if (kQueryLength != 0)
        __builtin_memmove(output + write, input.ptr + path_end, static_cast<u32>(kQueryLength));
    *length = static_cast<u32>(write + kQueryLength);
    return true;
}
}  // namespace rut
