#pragma once

#include "rut/common/rate_limit_key_spec.h"
#include "rut/common/types.h"
#include "rut/runtime/route_params.h"

// Composable rate-limit key — runtime value extraction. The key *spec* (the
// component list: IP / header / query / cookie / param) lives in
// common/rate_limit_key_spec.h so the compiler can carry it too; this header
// turns a spec + a request into the u64 metering key the RateLimiter uses.
//
// Values are hashed (FNV-1a/64) into one u64; composite keys just chain more
// values into the same hash, so the limiter meters one counter per unique
// tuple. All extraction is zero-copy over the request bytes — no allocation.

namespace rut {

// Request fields needed to extract component values. Passed explicitly so this
// header need not depend on the full Connection definition.
struct RateLimitKeyInput {
    u32 peer_addr = 0;
    const u8* req_buf = nullptr;  // raw request bytes (recv_buf base)
    u32 req_header_end = 0;       // offset past the final CRLFCRLF
    const char* path = nullptr;   // raw request path (may contain ?query)
    u32 path_len = 0;
    const RouteParam* params = nullptr;
    u32 param_count = 0;
};

namespace rl_detail {

inline u8 lower(u8 c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<u8>(c + 32) : c;
}

inline bool ci_eq(const char* a, u32 an, const char* b, u32 bn) {
    if (an != bn) return false;
    for (u32 i = 0; i < an; i++) {
        if (lower(static_cast<u8>(a[i])) != lower(static_cast<u8>(b[i]))) return false;
    }
    return true;
}

// FNV-1a/64 step over a byte range, folded into the running hash `h`.
inline u64 mix(u64 h, const void* p, u32 n) {
    const auto* b = static_cast<const u8*>(p);
    for (u32 i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

// Find a request header by (case-insensitive) name; returns its value
// {ptr,len}, trimmed of leading spaces, or {nullptr,0} if absent. Scans the
// header block in req_buf[0..header_end), skipping the request line.
inline Str header_value(const RateLimitKeyInput& in, const char* name, u32 name_len) {
    if (!in.req_buf || in.req_header_end == 0) return {nullptr, 0};
    const char* p = reinterpret_cast<const char*>(in.req_buf);
    u32 end = in.req_header_end;
    u32 i = 0;
    // Skip the request line (up to and past the first CRLF).
    while (i + 1 < end && (p[i] != '\r' || p[i + 1] != '\n')) i++;
    i += 2;
    while (i < end) {
        if (i + 1 < end && p[i] == '\r' && p[i + 1] == '\n') break;  // end of headers
        u32 line_start = i;
        u32 colon = line_start;
        while (colon < end && p[colon] != ':' && p[colon] != '\r') colon++;
        // Advance to end of this line.
        u32 line_end = colon;
        while (line_end + 1 < end && (p[line_end] != '\r' || p[line_end + 1] != '\n')) line_end++;
        if (colon < end && p[colon] == ':') {
            u32 nlen = colon - line_start;
            if (ci_eq(p + line_start, nlen, name, name_len)) {
                u32 vs = colon + 1;
                while (vs < line_end && (p[vs] == ' ' || p[vs] == '\t')) vs++;
                return {p + vs, line_end - vs};
            }
        }
        i = line_end + 2;
    }
    return {nullptr, 0};
}

// Find a query-string parameter value in the raw path ("...?k=v&k2=v2#frag").
inline Str query_value(const RateLimitKeyInput& in, const char* name, u32 name_len) {
    if (!in.path) return {nullptr, 0};
    const char* p = in.path;
    u32 i = 0;
    while (i < in.path_len && p[i] != '?') i++;
    if (i >= in.path_len) return {nullptr, 0};
    i++;  // past '?'
    while (i < in.path_len && p[i] != '#') {
        u32 ks = i;
        while (i < in.path_len && p[i] != '=' && p[i] != '&' && p[i] != '#') i++;
        u32 klen = i - ks;
        const char* vp = nullptr;
        u32 vlen = 0;
        if (i < in.path_len && p[i] == '=') {
            i++;
            u32 vs = i;
            while (i < in.path_len && p[i] != '&' && p[i] != '#') i++;
            vp = p + vs;
            vlen = i - vs;
        }
        if (ci_eq(p + ks, klen, name, name_len)) return {vp ? vp : p + ks, vp ? vlen : 0};
        if (i < in.path_len && p[i] == '&') i++;
    }
    return {nullptr, 0};
}

// Find a cookie value: the Cookie header is "n1=v1; n2=v2".
inline Str cookie_value(const RateLimitKeyInput& in, const char* name, u32 name_len) {
    Str ck = header_value(in, "Cookie", 6);
    if (ck.empty()) return {nullptr, 0};
    const char* p = ck.ptr;
    u32 i = 0;
    while (i < ck.len) {
        while (i < ck.len && (p[i] == ' ' || p[i] == ';')) i++;
        u32 ks = i;
        while (i < ck.len && p[i] != '=' && p[i] != ';') i++;
        u32 klen = i - ks;
        const char* vp = nullptr;
        u32 vlen = 0;
        if (i < ck.len && p[i] == '=') {
            i++;
            u32 vs = i;
            while (i < ck.len && p[i] != ';') i++;
            vp = p + vs;
            vlen = i - vs;
        }
        if (ci_eq(p + ks, klen, name, name_len)) return {vp ? vp : p + ks, vp ? vlen : 0};
    }
    return {nullptr, 0};
}

// Find a route parameter value by name.
inline Str param_value(const RateLimitKeyInput& in, const char* name, u32 name_len) {
    for (u32 i = 0; i < in.param_count; i++) {
        const RouteParam& rp = in.params[i];
        if (ci_eq(rp.name, rp.name_len, name, name_len)) return {rp.value, rp.value_len};
    }
    return {nullptr, 0};
}

}  // namespace rl_detail

// Compute the u64 metering key for a request: route_idx folded with each
// component's extracted value. With no components, keys by client IP (the
// historical default). A 1-byte separator per component keeps ("ab","c") and
// ("a","bc") distinct. Never returns 0 (the RateLimiter's empty-slot sentinel).
inline u64 rate_limit_key(u32 route_idx,
                          const RateLimitKeyComponent* comps,
                          u32 comp_count,
                          const RateLimitKeyInput& in) {
    using namespace rl_detail;
    u64 h = 14695981039346656037ull;  // FNV-1a/64 offset basis
    h = mix(h, &route_idx, sizeof route_idx);
    if (comp_count == 0) {
        h = mix(h, &in.peer_addr, sizeof in.peer_addr);
    } else {
        for (u32 c = 0; c < comp_count; c++) {
            const RateLimitKeyComponent& k = comps[c];
            u8 sep = static_cast<u8>(k.kind);
            h = mix(h, &sep, 1);
            Str v{nullptr, 0};
            switch (k.kind) {
                case RateLimitKeyKind::Ip:
                    h = mix(h, &in.peer_addr, sizeof in.peer_addr);
                    continue;
                case RateLimitKeyKind::Header:
                    v = header_value(in, k.name, k.name_len);
                    break;
                case RateLimitKeyKind::Query:
                    v = query_value(in, k.name, k.name_len);
                    break;
                case RateLimitKeyKind::Cookie:
                    v = cookie_value(in, k.name, k.name_len);
                    break;
                case RateLimitKeyKind::Param:
                    v = param_value(in, k.name, k.name_len);
                    break;
            }
            // A missing value hashes as an empty field — all requests lacking it
            // share one bucket, which is the sensible "unattributed" group.
            h = mix(h, v.ptr, v.len);
        }
    }
    return h == 0 ? 1 : h;
}

}  // namespace rut
