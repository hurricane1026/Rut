#include "rut/runtime/remote_jwks.h"

namespace rut {
bool RemoteJwks::load(json::Document& document, u32 node) {
    *this = {};
    if (!document.valid || node >= document.count) return false;
    RemoteJwks next;
    if (document.nodes[node].kind != json::Kind::Object) return false;
    u32 fields = 0;
    for (u32 entry = document.nodes[node].child; entry != json::kNone;
         entry = document.nodes[entry].next) {
        json::Writer name{document.scratch};
        if (!document.string(document.nodes[entry].key, name)) return false;
        const Str kKey{document.scratch, name.len};
        char* target = nullptr;
        u32 capacity = 0;
        if (kKey.eq(lit_str("address"))) {
            target = next.endpoint.address;
            capacity = sizeof(next.endpoint.address);
            fields |= 1;
        } else if (kKey.eq(lit_str("serverName"))) {
            target = next.endpoint.tls.server_name;
            capacity = sizeof(next.endpoint.tls.server_name);
            fields |= 2;
        } else if (kKey.eq(lit_str("ca"))) {
            target = next.endpoint.tls.ca;
            capacity = sizeof(next.endpoint.tls.ca);
            fields |= 4;
        } else if (kKey.eq(lit_str("path"))) {
            target = next.endpoint.path;
            capacity = sizeof(next.endpoint.path);
            fields |= 8;
        }
        if (target) {
            json::Writer value{target, capacity - 1};
            if (!document.string(entry, value) || !value.ok || !value.len) return false;
            for (u32 i = 0; i < value.len; ++i)
                if (!target[i]) return false;
            target[value.len] = 0;
            continue;
        }
        i64 value = 0;
        if (document.nodes[entry].kind != json::Kind::Number ||
            !json::integer(document.raw(entry), value) || value <= 0)
            return false;
        if (kKey.eq(lit_str("port"))) {
            if (value > 65535) return false;
            next.endpoint.port = static_cast<u16>(value);
            fields |= 16;
        } else if (kKey.eq(lit_str("refreshSeconds"))) {
            if (value > 3600) return false;
            next.refresh_seconds = static_cast<u32>(value);
            fields |= 32;
        } else if (kKey.eq(lit_str("maxAgeSeconds"))) {
            if (value > 86400) return false;
            next.max_age_seconds = static_cast<u32>(value);
            fields |= 64;
        } else if (kKey.eq(lit_str("timeoutSeconds"))) {
            if (value > 60) return false;
            next.timeout_seconds = static_cast<u32>(value);
            fields |= 128;
        } else
            return false;
    }
    next.endpoint.tls.enabled = true;
    if (fields != 255 || !next.endpoint.valid() || next.max_age_seconds <= next.refresh_seconds)
        return false;
    *this = next;
    return true;
}
}  // namespace rut
