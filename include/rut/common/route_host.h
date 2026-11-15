#pragma once

#include "rut/common/types.h"

#include <arpa/inet.h>

namespace rut {
inline char route_host_lower(char byte) {
    return byte >= 'A' && byte <= 'Z' ? static_cast<char>(byte + 'a' - 'A') : byte;
}
inline bool route_host_ipv6(Str host, in6_addr* address) {
    if (!host.ptr || host.len < 4 || host.len > 47 || host.ptr[0] != '[' ||
        host.ptr[host.len - 1] != ']')
        return false;
    char text[46];
    __builtin_memcpy(text, host.ptr + 1, host.len - 2);
    text[host.len - 2] = '\0';
    return inet_pton(AF_INET6, text, address) == 1;
}
inline bool route_host_equal(Str lhs, Str rhs) {
    if (lhs.len && rhs.len && lhs.ptr[0] == '[' && rhs.ptr[0] == '[') {
        in6_addr left{}, right{};
        return route_host_ipv6(lhs, &left) && route_host_ipv6(rhs, &right) &&
               __builtin_memcmp(&left, &right, sizeof(left)) == 0;
    }
    if (lhs.len != rhs.len) return false;
    for (u32 i = 0; i < lhs.len; i++)
        if (route_host_lower(lhs.ptr[i]) != route_host_lower(rhs.ptr[i])) return false;
    return true;
}
inline bool route_host_pattern_valid(Str host) {
    if (!host.ptr || host.len == 0 || host.len > 253) return false;
    if (host.ptr[0] == '[') {
        in6_addr address{};
        return route_host_ipv6(host, &address);
    }
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
    if (authority.ptr[0] == '[') {
        u32 close = 0;
        while (close < authority.len && authority.ptr[close] != ']') close++;
        in6_addr address{};
        if (close == authority.len || !route_host_ipv6({authority.ptr, close + 1}, &address))
            return false;
        if (close + 1 < authority.len) {
            if (authority.ptr[close + 1] != ':' || close + 2 == authority.len) return false;
            u32 port = 0;
            for (u32 i = close + 2; i < authority.len; i++) {
                const char kByte = authority.ptr[i];
                if (kByte < '0' || kByte > '9' || port > 6553) return false;
                port = port * 10 + static_cast<u32>(kByte - '0');
            }
            if (port > 65535) return false;
        }
        output[0] = '[';
        if (!inet_ntop(AF_INET6, &address, output + 1, 252)) return false;
        u32 size = 1;
        while (output[size]) size++;
        output[size++] = ']';
        output[size] = '\0';
        *length = static_cast<u16>(size);
        return true;
    }
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
        if (port > 65535) return false;
        break;
    }
    if (end && authority.ptr[end - 1] == '.') end--;
    if (end == 0 || end > 253) return false;
    for (u32 i = 0; i < end; i++) output[i] = route_host_lower(authority.ptr[i]);
    output[end] = '\0';
    if (!route_host_pattern_valid({output, end})) {
        // A valid URI reg-name can be outside the DNS scope grammar. Retain
        // global-route eligibility; it must never be mistaken for a DNS scope.
        for (u32 i = 0; i < end; i++) {
            const char kByte = output[i];
            if ((kByte >= 'a' && kByte <= 'z') || (kByte >= '0' && kByte <= '9') || kByte == '-' ||
                kByte == '.' || kByte == '_' || kByte == '~' || kByte == '!' || kByte == '$' ||
                kByte == '&' || kByte == '\'' || kByte == '(' || kByte == ')' || kByte == '+' ||
                kByte == ',' || kByte == ';' || kByte == '=')
                continue;
            if (kByte == '%' && i + 2 < end) {
                const auto hex = [](char byte) {
                    return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
                };
                if (hex(output[i + 1]) && hex(output[i + 2])) {
                    i += 2;
                    continue;
                }
            }
            return false;
        }
    }
    for (u32 i = 0; i < end; i++)
        if (output[i] == '*') return false;
    *length = static_cast<u16>(end);
    return true;
}
}  // namespace rut
