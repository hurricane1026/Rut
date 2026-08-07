#include "rut/runtime/dns_resolver.h"

#include <netdb.h>
#include <string.h>

namespace rut {

namespace {

bool same_ip(const IpAddress& lhs, const IpAddress& rhs) {
    const u32 byte_count = lhs.byte_count();
    return lhs.family == rhs.family && byte_count != 0 &&
           memcmp(lhs.bytes, rhs.bytes, byte_count) == 0;
}

}  // namespace

bool resolve_upstream_hostname(Str hostname, ResolvedUpstreamAddresses* out) {
    if (out == nullptr) return false;
    *out = {};
    if (hostname.ptr == nullptr || hostname.len == 0 || hostname.len > 253) return false;

    char name[254];
    memcpy(name, hostname.ptr, hostname.len);
    name[hostname.len] = '\0';

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* results = nullptr;
    if (getaddrinfo(name, nullptr, &hints, &results) != 0) return false;

    for (const addrinfo* entry = results; entry != nullptr; entry = entry->ai_next) {
        IpAddress address{};
        if (entry->ai_addr == nullptr) continue;
        if (entry->ai_family == AF_INET && entry->ai_addrlen >= sizeof(sockaddr_in)) {
            const auto* value = reinterpret_cast<const sockaddr_in*>(entry->ai_addr);
            address = IpAddress::v4(ntohl(value->sin_addr.s_addr));
        } else if (entry->ai_family == AF_INET6 && entry->ai_addrlen >= sizeof(sockaddr_in6)) {
            const auto* value = reinterpret_cast<const sockaddr_in6*>(entry->ai_addr);
            address.family = IpAddress::Family::V6;
            memcpy(address.bytes, &value->sin6_addr, sizeof(value->sin6_addr));
        } else {
            continue;
        }

        bool duplicate = false;
        for (u32 i = 0; i < out->count; ++i) duplicate |= same_ip(out->addresses[i], address);
        if (duplicate) continue;
        if (out->count == ResolvedUpstreamAddresses::kMaxAddresses) break;
        out->addresses[out->count++] = address;
    }
    freeaddrinfo(results);
    return out->count != 0;
}

}  // namespace rut
