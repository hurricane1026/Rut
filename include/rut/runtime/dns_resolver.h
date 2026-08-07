#pragma once

#include "rut/common/ip_address.h"

namespace rut {

struct ResolvedUpstreamAddresses {
    static constexpr u32 kMaxAddresses = 8;

    IpAddress addresses[kMaxAddresses]{};
    u32 count = 0;
    bool overflow = false;
};

using UpstreamHostnameResolver = bool (*)(Str hostname, ResolvedUpstreamAddresses* out);

// Resolve A and AAAA records before a RouteConfig is published. This runs on
// the program-loading path, never on an event-loop shard.
bool resolve_upstream_hostname(Str hostname, ResolvedUpstreamAddresses* out);

}  // namespace rut
