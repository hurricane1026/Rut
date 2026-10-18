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
inline bool grpc_request(const ParsedRequest& req) {
    for (u32 i = 0; i < req.header_count; i++)
        if (grpc_header_name(req.headers[i].name, {"content-type", 12}))
            return grpc_content_type(req.headers[i].value);
    return false;
}
inline GrpcWebContentType grpc_request_mode(const ParsedRequest& req) {
    for (u32 i = 0; i < req.header_count; i++)
        if (grpc_header_name(req.headers[i].name, {"content-type", 12}))
            return grpc_web_content_type(req.headers[i].value);
    return GrpcWebContentType::Other;
}
}  // namespace rut
