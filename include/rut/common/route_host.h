#pragma once

#include "rut/common/types.h"

namespace rut {
inline char route_host_lower(char byte) {
    return byte >= 'A' && byte <= 'Z' ? static_cast<char>(byte + 'a' - 'A') : byte;
}
inline bool route_host_equal(Str lhs, Str rhs) {
    if (lhs.len != rhs.len) return false;
    for (u32 i = 0; i < lhs.len; i++)
        if (route_host_lower(lhs.ptr[i]) != route_host_lower(rhs.ptr[i])) return false;
    return true;
}
inline bool route_host_pattern_valid(Str host) {
    if (!host.ptr || host.len == 0 || host.len > 253) return false;
    u32 begin = 0;
    u32 end = host.len;
    if (host.len > 2 && host.ptr[0] == '*' && host.ptr[1] == '.')
        begin = 2;
    else if (host.len > 2 && host.ptr[end - 1] == '*' && host.ptr[end - 2] == '.')
        end -= 2;
    u32 label = 0;
    for (u32 i = begin; i < end; i++) {
        const char kByte = route_host_lower(host.ptr[i]);
        if (kByte == '.') {
            if (label == 0 || host.ptr[i - 1] == '-') return false;
            label = 0;
        } else {
            if (!((kByte >= 'a' && kByte <= 'z') || (kByte >= '0' && kByte <= '9') ||
                  kByte == '-') ||
                (label == 0 && kByte == '-') || ++label > 63)
                return false;
        }
    }
    return label != 0 && host.ptr[end - 1] != '-';
}
// Exact names outrank wildcards; longer wildcard fixed parts outrank shorter ones.
inline u32 route_host_match_score(Str pattern, Str host) {
    if (pattern.len == 0 || host.len == 0) return 0;
    if (pattern.ptr[0] == '*') {
        Str suffix{pattern.ptr + 1, pattern.len - 1};
        if (host.len > suffix.len &&
            route_host_equal({host.ptr + host.len - suffix.len, suffix.len}, suffix))
            return suffix.len;
        return 0;
    }
    if (pattern.ptr[pattern.len - 1] == '*') {
        Str prefix{pattern.ptr, pattern.len - 1};
        return host.len > prefix.len && route_host_equal({host.ptr, prefix.len}, prefix)
                   ? prefix.len
                   : 0;
    }
    return route_host_equal(pattern, host) ? 512 : 0;
}
// HTTP authority -> lower-case routing name. Port is independently exposed by
// transport metadata. Reject ambiguous authority spellings before policy lookup.
inline bool route_host_from_authority(Str authority, char output[254], u16* length) {
    *length = 0;
    if (!authority.ptr || authority.len == 0 || authority.len > 260) return false;
    u32 end = authority.len;
    for (u32 i = 0; i < authority.len; i++) {
        if (authority.ptr[i] != ':') continue;
        end = i;
        u32 port = 0;
        if (i + 1 == authority.len) return false;
        for (u32 j = i + 1; j < authority.len; j++) {
            const char kByte = authority.ptr[j];
            if (kByte < '0' || kByte > '9' || port > 6553) return false;
            port = port * 10 + static_cast<u32>(kByte - '0');
        }
        if (port == 0 || port > 65535) return false;
        break;
    }
    if (end && authority.ptr[end - 1] == '.') end--;
    if (end == 0 || end > 253) return false;
    for (u32 i = 0; i < end; i++) output[i] = route_host_lower(authority.ptr[i]);
    output[end] = '\0';
    if (!route_host_pattern_valid({output, end})) return false;
    for (u32 i = 0; i < end; i++)
        if (output[i] == '*') return false;
    *length = static_cast<u16>(end);
    return true;
}
}  // namespace rut
