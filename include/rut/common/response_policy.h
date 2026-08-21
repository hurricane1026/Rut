#pragma once

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"

namespace rut {

// Response-policy source objects are deliberately bounded. They describe
// semantics for the response serializer; unsupported future modes are
// rejected by the runtime rather than silently ignored.
static constexpr u32 kMaxResponsePolicies = 16;
static constexpr u32 kMaxResponsePolicyHideHeaders = 8;
static constexpr u32 kMaxResponsePolicyHeaderNameLen = 64;
static constexpr u32 kMaxResponsePolicyServerLen = 64;

enum class ResponsePolicyVersion : u8 {
    Invalid = 0,
    Http11 = 1,
};

enum class ResponsePolicyFraming : u8 {
    Invalid = 0,
    ContentLength = 1,
};

enum class ResponsePolicyConnection : u8 {
    Invalid = 0,
    KeepAlive = 1,
    Request = 2,
};

enum class ResponsePolicyDate : u8 {
    Invalid = 0,
    Current = 1,
};

// Reject is the legacy/source default. SuppressBody is runtime-supported only
// for the bounded cleartext HTTP/1.1 explicit-close HEAD domain; all other
// domains fail closed.
enum class ResponsePolicyHeadMode : u8 {
    Invalid = 0,
    Reject = 1,
    SuppressBody = 2,
};

struct ForwardResponsePolicySpec {
    ResponsePolicyVersion version = ResponsePolicyVersion::Invalid;
    ResponsePolicyFraming framing = ResponsePolicyFraming::Invalid;
    ResponsePolicyConnection connection = ResponsePolicyConnection::Invalid;
    ResponsePolicyDate date = ResponsePolicyDate::Invalid;
    ResponsePolicyHeadMode head_mode = ResponsePolicyHeadMode::Reject;
    Str server{};
    u32 hide_header_count = 0;
    Str hide_headers[kMaxResponsePolicyHideHeaders]{};
};

inline bool response_policy_safe_server(Str value) {
    if (value.ptr == nullptr || value.len == 0 || value.len > kMaxResponsePolicyServerLen)
        return false;
    for (u32 i = 0; i < value.len; i++) {
        const u8 c = static_cast<u8>(value.ptr[i]);
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

inline bool response_policy_safe_header_name(Str value) {
    if (value.ptr == nullptr || value.len == 0 || value.len > kMaxResponsePolicyHeaderNameLen)
        return false;
    for (u32 i = 0; i < value.len; i++) {
        if (!is_http_tchar(static_cast<u8>(value.ptr[i]))) return false;
    }
    return true;
}

inline bool response_policy_spec_valid(const ForwardResponsePolicySpec& policy) {
    if (policy.version != ResponsePolicyVersion::Http11 ||
        policy.framing != ResponsePolicyFraming::ContentLength ||
        (policy.connection != ResponsePolicyConnection::KeepAlive &&
         policy.connection != ResponsePolicyConnection::Request) ||
        policy.date != ResponsePolicyDate::Current ||
        (policy.head_mode != ResponsePolicyHeadMode::Reject &&
         policy.head_mode != ResponsePolicyHeadMode::SuppressBody) ||
        !response_policy_safe_server(policy.server) ||
        policy.hide_header_count > kMaxResponsePolicyHideHeaders)
        return false;
    for (u32 i = 0; i < policy.hide_header_count; i++) {
        if (!response_policy_safe_header_name(policy.hide_headers[i])) return false;
        for (u32 j = 0; j < i; j++) {
            if (http_header_name_eq_ci(policy.hide_headers[i].ptr,
                                       policy.hide_headers[i].len,
                                       policy.hide_headers[j].ptr,
                                       policy.hide_headers[j].len))
                return false;
        }
    }
    return true;
}

inline bool response_policy_spec_equal(const ForwardResponsePolicySpec& a,
                                       const ForwardResponsePolicySpec& b) {
    if (a.version != b.version || a.framing != b.framing || a.connection != b.connection ||
        a.date != b.date || a.head_mode != b.head_mode || !a.server.eq(b.server) ||
        a.hide_header_count != b.hide_header_count)
        return false;
    for (u32 i = 0; i < a.hide_header_count; i++) {
        if (!a.hide_headers[i].eq(b.hide_headers[i])) return false;
    }
    return true;
}

}  // namespace rut
