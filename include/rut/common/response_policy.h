#pragma once

#include "rut/common/forward_policy_head_mode.h"
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
static constexpr u32 kMaxForwardResponseContentTypeLen = 128;

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
    // Envoy H1 profile: keep an upstream `date` in place, or append `date:
    // <now>` when the upstream response sent none. Admitted only alongside
    // `header_order: "upstream"`.
    PreserveOrCurrent = 2,
};

// Envoy H1 profile fields (only meaningful together with `header_order ==
// Upstream`, see `response_policy_spec_scalar_valid` below). The nginx-style
// fixed-order profile (`Synthesized`) requires every one of these at its
// default and is otherwise unaffected.
enum class ResponsePolicyHeaderOrder : u8 {
    Synthesized = 0,
    Upstream = 1,
};

enum class ResponsePolicyHeaderNames : u8 {
    Preserve = 0,
    Lowercase = 1,
};

enum class ResponsePolicyConnectionHeader : u8 {
    Always = 0,
    CloseOnly = 1,
};

enum class ResponsePolicyStatusReason : u8 {
    Upstream = 0,
    Canonical = 1,
};

struct ForwardResponsePolicySpec {
    ResponsePolicyVersion version = ResponsePolicyVersion::Invalid;
    ResponsePolicyFraming framing = ResponsePolicyFraming::Invalid;
    ResponsePolicyConnection connection = ResponsePolicyConnection::Invalid;
    ResponsePolicyDate date = ResponsePolicyDate::Invalid;
    ResponsePolicyHeadMode head_mode = ResponsePolicyHeadMode::Reject;
    ResponsePolicyHeaderOrder header_order = ResponsePolicyHeaderOrder::Synthesized;
    ResponsePolicyHeaderNames header_names = ResponsePolicyHeaderNames::Preserve;
    ResponsePolicyConnectionHeader connection_header = ResponsePolicyConnectionHeader::Always;
    ResponsePolicyStatusReason status_reason = ResponsePolicyStatusReason::Upstream;
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

inline bool response_policy_safe_content_type(Str value) {
    static constexpr char kName[] = "Content-Type";
    return value.ptr != nullptr && value.len != 0 &&
           value.len <= kMaxForwardResponseContentTypeLen &&
           validate_response_header(kName, sizeof(kName) - 1u, value.ptr, value.len) ==
               HttpHeaderValidation::Ok;
}

inline bool response_policy_hides_header(const ForwardResponsePolicySpec& policy, Str name) {
    for (u32 i = 0; i < policy.hide_header_count; i++) {
        const Str hidden = policy.hide_headers[i];
        if (http_header_name_eq_ci(hidden.ptr, hidden.len, name.ptr, name.len)) return true;
    }
    return false;
}

// Policies admitted into an immutable RouteConfig were fully validated when
// they were registered. Runtime re-checks of an admitted policy keep the cheap
// scalar and role checks; the byte-level re-scan of its strings runs only in
// debug/test builds, where it catches a corrupted or mis-built config.
#ifdef NDEBUG
inline constexpr bool kRescanAdmittedPolicies = false;
#else
inline constexpr bool kRescanAdmittedPolicies = true;
#endif

inline bool response_policy_spec_scalar_valid(const ForwardResponsePolicySpec& policy) {
    if (policy.version != ResponsePolicyVersion::Http11 ||
        policy.framing != ResponsePolicyFraming::ContentLength ||
        (policy.connection != ResponsePolicyConnection::KeepAlive &&
         policy.connection != ResponsePolicyConnection::Request) ||
        (policy.head_mode != ResponsePolicyHeadMode::Reject &&
         policy.head_mode != ResponsePolicyHeadMode::SuppressBody) ||
        policy.hide_header_count > kMaxResponsePolicyHideHeaders)
        return false;
    // `header_order: "upstream"` is the closed Envoy H1 combination: every
    // other new field is required at its one supported value. The
    // nginx-compatible fixed-order profile (`Synthesized`) keeps today's
    // contract and rejects any of these fields being set to anything else.
    if (policy.header_order == ResponsePolicyHeaderOrder::Upstream) {
        return policy.header_names == ResponsePolicyHeaderNames::Lowercase &&
               policy.connection_header == ResponsePolicyConnectionHeader::CloseOnly &&
               policy.status_reason == ResponsePolicyStatusReason::Canonical &&
               policy.date == ResponsePolicyDate::PreserveOrCurrent;
    }
    return policy.header_order == ResponsePolicyHeaderOrder::Synthesized &&
           policy.header_names == ResponsePolicyHeaderNames::Preserve &&
           policy.connection_header == ResponsePolicyConnectionHeader::Always &&
           policy.status_reason == ResponsePolicyStatusReason::Upstream &&
           policy.date == ResponsePolicyDate::Current;
}

inline bool response_policy_spec_valid(const ForwardResponsePolicySpec& policy) {
    if (!response_policy_spec_scalar_valid(policy) || !response_policy_safe_server(policy.server))
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

// Re-check of a policy owned by an immutable RouteConfig (see above).
inline bool admitted_response_policy_valid(const ForwardResponsePolicySpec& policy) {
    return kRescanAdmittedPolicies ? response_policy_spec_valid(policy)
                                   : response_policy_spec_scalar_valid(policy);
}

inline bool response_policy_spec_equal(const ForwardResponsePolicySpec& a,
                                       const ForwardResponsePolicySpec& b) {
    if (a.version != b.version || a.framing != b.framing || a.connection != b.connection ||
        a.date != b.date || a.head_mode != b.head_mode || a.header_order != b.header_order ||
        a.header_names != b.header_names || a.connection_header != b.connection_header ||
        a.status_reason != b.status_reason || !a.server.eq(b.server) ||
        a.hide_header_count != b.hide_header_count)
        return false;
    for (u32 i = 0; i < a.hide_header_count; i++) {
        if (!a.hide_headers[i].eq(b.hide_headers[i])) return false;
    }
    return true;
}

}  // namespace rut
