#pragma once

#include "rut/common/types.h"

#include <arpa/inet.h>
#include <string.h>

namespace rut {

struct IpAddress {
    enum class Family : u8 {
        None,
        V4,
        V6,
    };

    Family family = Family::None;
    u8 bytes[16]{};

    static IpAddress v4(u32 host_order) {
        IpAddress out{};
        out.family = Family::V4;
        out.bytes[0] = static_cast<u8>(host_order >> 24);
        out.bytes[1] = static_cast<u8>(host_order >> 16);
        out.bytes[2] = static_cast<u8>(host_order >> 8);
        out.bytes[3] = static_cast<u8>(host_order);
        return out;
    }

    [[nodiscard]] u32 v4_host_order() const {
        if (family != Family::V4) return 0;
        return (static_cast<u32>(bytes[0]) << 24) | (static_cast<u32>(bytes[1]) << 16) |
               (static_cast<u32>(bytes[2]) << 8) | static_cast<u32>(bytes[3]);
    }

    [[nodiscard]] u32 byte_count() const {
        if (family == Family::V4) return 4;
        if (family == Family::V6) return 16;
        return 0;
    }
};

inline bool parse_ip_address(Str text, IpAddress* out) {
    if (out == nullptr || text.ptr == nullptr || text.len == 0 || text.len >= INET6_ADDRSTRLEN)
        return false;
    char buffer[INET6_ADDRSTRLEN];
    for (u32 i = 0; i < text.len; i++) buffer[i] = text.ptr[i];
    buffer[text.len] = '\0';

    in_addr v4{};
    if (inet_pton(AF_INET, buffer, &v4) == 1) {
        out->family = IpAddress::Family::V4;
        memcpy(out->bytes, &v4, sizeof(v4));
        return true;
    }
    in6_addr v6{};
    if (inet_pton(AF_INET6, buffer, &v6) == 1) {
        out->family = IpAddress::Family::V6;
        memcpy(out->bytes, &v6, sizeof(v6));
        return true;
    }
    return false;
}

}  // namespace rut
