#pragma once

#include "rut/native_build_id.h"
#include "rut/native_program.h"

namespace rut::native {
// Private, same-build ABI. Artifacts contain executable code and are trusted
// like the source compiler; they are not a portable configuration format.
constexpr u64 kMagic = 0x5255544e41544956ull;
constexpr u32 kVersion = 1;
struct StreamHeader {
    u64 magic;
    u32 version;
    char build_id[sizeof(kBuildId)];
    u64 artifact_size;
};
struct Header {
    u64 magic;
    u32 version;
    u32 config_size;
    u64 size;
    u32 metadata_size;
    u32 route_count;
    u32 relocation_count;
    u32 symbol_count;
    u32 regex_count;
    RouteConfig::DispatchKind dispatch;
    bool has_listener;
    ListenerSpec listener;
    AccessLogSinkSpec access_log;
};
struct Relocation {
    u32 field;  // byte offset in RouteConfig
    u32 config_offset;
    u64 blob_offset;  // zero selects config_offset
};
struct alignas(8) Symbol {
    u32 field;
    char name[256];
};
struct Regex {
    char symbol[96];
    u64 database_offset;
    u32 database_size;
};
inline u32 metadata_offset(const RouteConfig& c) {
    return static_cast<u32>(reinterpret_cast<const u8*>(&c.upstreams) -
                            reinterpret_cast<const u8*>(&c));
}
inline u32 metadata_size(const RouteConfig& c) {
    return static_cast<u32>(reinterpret_cast<const u8*>(&c.strict_local_response_bytes_used + 1) -
                            reinterpret_cast<const u8*>(&c.upstreams));
}
// Explicitly enumerate every configuration byte view. Dispatch views are rebuilt
// from owned routes; function pointers use a separate symbol table.
template <typename F>
bool visit_views(RouteConfig& c, F f) {
    for (u32 i = 0; i < c.response_body_count; i++)
        if (!f(c.response_bodies[i].data, c.response_bodies[i].len)) return false;
    for (u32 i = 0; i < c.header_pool_used; i++) {
        if (!f(c.header_keys[i].data, c.header_keys[i].len) ||
            !f(c.header_values[i].data, c.header_values[i].len))
            return false;
    }
    auto str = [&](Str& s) { return f(s.ptr, s.len); };
    for (u32 i = 0; i < c.response_policy_count; i++) {
        auto& p = c.response_policies[i];
        if (!str(p.server)) return false;
        for (u32 j = 0; j < p.hide_header_count; j++)
            if (!str(p.hide_headers[j])) return false;
    }
    for (u32 i = 0; i < c.failure_policy_count; i++) {
        auto& p = c.failure_policies[i];
        if (!str(p.reason) || !str(p.content_type) || !str(p.server) || !str(p.body)) return false;
    }
    for (u32 i = 0; i < c.target_transform_count; i++) {
        auto& p = c.target_transforms[i];
        if (!str(p.strip_prefix) || !str(p.replace_prefix)) return false;
    }
    for (u32 i = 0; i < c.redirect_policy_count; i++) {
        auto& p = c.redirect_policies[i];
        if (!str(p.reason) || !str(p.server) || !str(p.content_type) || !str(p.static_authority) ||
            !str(p.target_path) || !str(p.body))
            return false;
    }
    for (u32 i = 0; i < c.strict_local_response_policy_count; i++) {
        auto& p = c.strict_local_response_policies[i];
        if (!str(p.reason) || !str(p.content_type) || !str(p.server) || !str(p.body)) return false;
    }
    return true;
}
}  // namespace rut::native
