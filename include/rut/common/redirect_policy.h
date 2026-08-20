#pragma once

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"

namespace rut {

// Redirect policies are bounded, caller-supplied metadata for the generic
// Redirect action. They are intentionally not tied to nginx; source and
// converter callers provide the concrete text/body values.
static constexpr u32 kMaxRedirectPolicies = 16;
static constexpr u32 kMaxRedirectReasonLen = 64;
static constexpr u32 kMaxRedirectServerLen = 64;
static constexpr u32 kMaxRedirectContentTypeLen = 128;
static constexpr u32 kMaxRedirectTargetPathLen = 256;
static constexpr u32 kMaxRedirectBodyLen = 4096;
static constexpr u32 kRedirectPolicyBytes = 16 * 1024;

enum class RedirectPolicyScheme : u8 {
    Invalid = 0,
    Http = 1,
};

enum class RedirectPolicyAuthority : u8 {
    Invalid = 0,
    RequestHost = 1,
};

enum class RedirectPolicyPort : u8 {
    Invalid = 0,
    ActualListener = 1,
};

enum class RedirectPolicyPath : u8 {
    Invalid = 0,
    Static = 1,
};

enum class RedirectPolicyQuery : u8 {
    Invalid = 0,
    PreserveRaw = 1,
};

enum class RedirectPolicyDate : u8 {
    Invalid = 0,
    Current = 1,
};

enum class RedirectPolicyConnection : u8 {
    Invalid = 0,
    Close = 1,
};

struct RedirectPolicySpec {
    RedirectPolicyScheme scheme = RedirectPolicyScheme::Invalid;
    RedirectPolicyAuthority authority = RedirectPolicyAuthority::Invalid;
    RedirectPolicyPort port = RedirectPolicyPort::Invalid;
    RedirectPolicyPath path = RedirectPolicyPath::Invalid;
    RedirectPolicyQuery query = RedirectPolicyQuery::Invalid;
    RedirectPolicyDate date = RedirectPolicyDate::Invalid;
    RedirectPolicyConnection connection = RedirectPolicyConnection::Invalid;
    u16 status_code = 0;
    Str reason{};
    Str server{};
    Str content_type{};
    Str target_path{};
    Str body{};
};

inline bool redirect_policy_safe_text(Str value, u32 cap) {
    if (value.ptr == nullptr || value.len == 0 || value.len > cap) return false;
    for (u32 i = 0; i < value.len; i++) {
        const u8 c = static_cast<u8>(value.ptr[i]);
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

inline bool redirect_policy_safe_target_path(Str value) {
    if (value.ptr == nullptr || value.len == 0 || value.len > kMaxRedirectTargetPathLen ||
        value.ptr[0] != '/')
        return false;
    for (u32 i = 0; i < value.len; i++) {
        const u8 c = static_cast<u8>(value.ptr[i]);
        // Query and fragment are separate policy dimensions.  Keeping them
        // out of this field makes raw-query preservation unambiguous.
        if (c < 0x21 || c == 0x7f || c == '?' || c == '#') return false;
    }
    return true;
}

inline bool redirect_policy_safe_body(Str value) {
    return (value.ptr != nullptr || value.len == 0) && value.len <= kMaxRedirectBodyLen;
}

inline bool redirect_policy_spec_valid(const RedirectPolicySpec& policy) {
    if (policy.scheme != RedirectPolicyScheme::Http ||
        policy.authority != RedirectPolicyAuthority::RequestHost ||
        policy.port != RedirectPolicyPort::ActualListener ||
        policy.path != RedirectPolicyPath::Static ||
        policy.query != RedirectPolicyQuery::PreserveRaw ||
        policy.date != RedirectPolicyDate::Current ||
        policy.connection != RedirectPolicyConnection::Close || policy.status_code < 300 ||
        policy.status_code > 399 || !redirect_policy_safe_text(policy.reason, kMaxRedirectReasonLen) ||
        !redirect_policy_safe_text(policy.server, kMaxRedirectServerLen) ||
        !redirect_policy_safe_text(policy.content_type, kMaxRedirectContentTypeLen) ||
        !redirect_policy_safe_target_path(policy.target_path) ||
        !redirect_policy_safe_body(policy.body))
        return false;
    return validate_response_header("Content-Type",
                                   12,
                                   policy.content_type.ptr,
                                   policy.content_type.len) == HttpHeaderValidation::Ok;
}

inline bool redirect_policy_spec_equal(const RedirectPolicySpec& a,
                                       const RedirectPolicySpec& b) {
    return a.scheme == b.scheme && a.authority == b.authority && a.port == b.port &&
           a.path == b.path && a.query == b.query && a.date == b.date &&
           a.connection == b.connection && a.status_code == b.status_code &&
           a.reason.eq(b.reason) && a.server.eq(b.server) && a.content_type.eq(b.content_type) &&
           a.target_path.eq(b.target_path) && a.body.eq(b.body);
}

inline bool redirect_policy_table_valid(const RedirectPolicySpec* specs, u32 count) {
    if (count > kMaxRedirectPolicies || (count != 0 && specs == nullptr)) return false;
    u32 total = 0;
    for (u32 i = 0; i < count; i++) {
        if (!redirect_policy_spec_valid(specs[i])) return false;
        const Str fields[] = {specs[i].reason,
                              specs[i].server,
                              specs[i].content_type,
                              specs[i].target_path,
                              specs[i].body};
        for (const Str field : fields) {
            if (field.len > kRedirectPolicyBytes - total) return false;
            total += field.len;
        }
        for (u32 j = 0; j < i; j++) {
            if (redirect_policy_spec_equal(specs[i], specs[j])) return false;
        }
    }
    return true;
}

}  // namespace rut
