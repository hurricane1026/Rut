#pragma once

#include "rut/runtime/grpc_web.h"
#include "rut/runtime/http_parser.h"

namespace rut {
inline bool grpc_header_name(Str name, Str expected) {
    if (name.len != expected.len) return false;
    for (u32 i = 0; i < name.len; i++) {
        char c = name.ptr[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != expected.ptr[i]) return false;
    }
    return true;
}
inline bool grpc_content_type(Str value) {
    constexpr Str prefix{"application/grpc", 16};
    if (value.len < prefix.len) return false;
    for (u32 i = 0; i < prefix.len; i++) {
        char c = value.ptr[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != prefix.ptr[i]) return false;
    }
    return value.len == prefix.len || value.ptr[prefix.len] == '+' || value.ptr[prefix.len] == ';';
}
inline GrpcWebContentType grpc_request_mode(const ParsedRequest& req,
                                            bool* ambiguous_web = nullptr) {
    u32 count = 0;
    Str first{};
    bool web_candidate = false;
    for (u32 i = 0; i < req.header_count; i++) {
        if (!grpc_header_name(req.headers[i].name, {"content-type", 12})) continue;
        if (count == 0) first = req.headers[i].value;
        count++;
        if (grpc_web_content_type_candidate(req.headers[i].value)) web_candidate = true;
    }
    if (ambiguous_web) *ambiguous_web = false;
    if (web_candidate) {
        if (count != 1) {
            if (ambiguous_web) *ambiguous_web = true;
            return GrpcWebContentType::Other;
        }
        const GrpcWebContentType mode = grpc_web_content_type(first);
        if (mode != GrpcWebContentType::Binary && mode != GrpcWebContentType::Text) {
            if (ambiguous_web) *ambiguous_web = true;
            return GrpcWebContentType::Other;
        }
        return mode;
    }
    // Preserve the existing native gRPC behavior, including how duplicate
    // native Content-Type fields are interpreted.
    return count ? grpc_web_content_type(first) : GrpcWebContentType::Other;
}
inline bool grpc_request(const ParsedRequest& req) {
    bool ambiguous_web = false;
    const GrpcWebContentType mode = grpc_request_mode(req, &ambiguous_web);
    if (ambiguous_web) return true;
    return mode != GrpcWebContentType::Other;
}
}  // namespace rut
