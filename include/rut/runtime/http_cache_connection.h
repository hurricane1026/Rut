#pragma once

#include "rut/runtime/access_log.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/route_table.h"

namespace rut {

inline void http_cache_prepare(Connection& conn,
                               const RouteConfig* config,
                               u32 route,
                               u32 ttl,
                               const u8* request,
                               u32 length) {
    if (conn.http_cache_token.generation) local_http_cache().cancel(conn.http_cache_token);
    conn.http_cache_token = {};
    conn.http_cache_ttl = ttl;
    conn.http_cache_route = route;
    conn.http_cache_config = config ? config->http_cache_identity : 0;
    conn.http_cache_mutation_host = 0;
    if (!config || !config->http_cache_route_count) return;
    if (length >= 4 && __builtin_memcmp(request, "GET ", 4) == 0) return;
    HttpCache::Key key;
    if (HttpCache::make_key(
            request, length, conn.http_cache_config, route, conn.tls_active, conn.peer_addr, key) &&
        key.unsafe) {
        conn.http_cache_mutation_host = key.host;
        local_http_cache().invalidate_host(key.config, key.host);
    }
}
inline void http_cache_observe_status(Connection& conn, u16 status) {
    if (conn.http_cache_mutation_host && status >= 200 && status < 400) {
        local_http_cache().invalidate_host(conn.http_cache_config, conn.http_cache_mutation_host);
        conn.http_cache_mutation_host = 0;
    }
}
inline void http_cache_complete(Connection& conn, const u8* wire, u32 length) {
    if (conn.http_cache_token.generation) {
        local_http_cache().commit(
            conn.http_cache_token, wire, length, monotonic_us(), http_cache_wall_us());
        conn.http_cache_token = {};
    }
}
inline HttpCache::Result http_cache_lookup(Connection& conn,
                                           const u8* request,
                                           u32 length,
                                           bool keep_alive,
                                           u8* output,
                                           u32 capacity,
                                           u32& written) {
    written = 0;
    if (!conn.http_cache_ttl || conn.req_header_override_count || conn.req_path_overridden ||
        conn.target_transform_recorded || conn.resp_header_mutation_count ||
        conn.resp_header_mutation_pending_count || conn.resp_header_mutation_overflow ||
        conn.resp_header_mutation_pending_overflow)
        return HttpCache::Result::Bypass;
    HttpCache::Key key;
    if (!HttpCache::make_key(request,
                             length,
                             conn.http_cache_config,
                             conn.http_cache_route,
                             conn.tls_active,
                             conn.peer_addr,
                             key))
        return HttpCache::Result::Bypass;
    return local_http_cache().begin(key,
                                    conn.http_cache_ttl,
                                    monotonic_us(),
                                    keep_alive,
                                    output,
                                    capacity,
                                    written,
                                    conn.http_cache_token);
}

}  // namespace rut
