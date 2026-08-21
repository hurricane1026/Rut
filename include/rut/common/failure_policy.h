#pragma once

#include "rut/common/forward_policy_head_mode.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"

namespace rut {

static constexpr u32 kMaxForwardFailurePolicies = 16;
static constexpr u32 kMaxFailurePolicyReasonLen = 64;
static constexpr u32 kMaxFailurePolicyContentTypeLen = 128;
static constexpr u32 kMaxFailurePolicyServerLen = 64;
static constexpr u32 kMaxFailurePolicyBodyLen = 4096;

enum class ForwardFailurePolicyVersion : u8 { Invalid = 0, Http11 = 1 };
enum class ForwardFailurePolicyDate : u8 { Invalid = 0, Current = 1 };
enum class ForwardFailurePolicyConnection : u8 { Invalid = 0, Request = 1 };

struct ForwardFailurePolicySpec {
    ForwardFailurePolicyVersion version = ForwardFailurePolicyVersion::Invalid;
    u16 status_code = 0;
    ForwardFailurePolicyDate date = ForwardFailurePolicyDate::Invalid;
    ForwardFailurePolicyConnection connection = ForwardFailurePolicyConnection::Invalid;
    FailurePolicyHeadMode head_mode = FailurePolicyHeadMode::Reject;
    Str reason{};
    Str content_type{};
    Str server{};
    Str body{};
};

struct ForwardPolicyBundle {
    u16 response_policy_id = 0;
    u16 failure_policy_id = 0;
    // Optional cause-specific timeout policy. Zero preserves the original
    // response/default-failure bundle shape and behavior.
    u16 timeout_failure_policy_id = 0;
};

inline bool failure_policy_safe_text(Str value, u32 cap, bool allow_empty = false) {
    if ((value.ptr == nullptr && !(allow_empty && value.len == 0)) || value.len > cap ||
        (!allow_empty && value.len == 0))
        return false;
    for (u32 i = 0; i < value.len; i++) {
        const u8 c = static_cast<u8>(value.ptr[i]);
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

// Failure bodies are byte payloads, not header/text fields.  In particular,
// NUL and LF are valid here; the serializer will frame them by Content-Length.
inline bool failure_policy_safe_body(Str value) {
    return (value.ptr != nullptr || value.len == 0) && value.len <= kMaxFailurePolicyBodyLen;
}

inline bool forward_failure_policy_spec_shape_valid(const ForwardFailurePolicySpec& policy) {
    if (policy.version != ForwardFailurePolicyVersion::Http11 || policy.status_code < 400 ||
        policy.status_code > 599 ||
        policy.date != ForwardFailurePolicyDate::Current ||
        policy.connection != ForwardFailurePolicyConnection::Request ||
        (policy.head_mode != FailurePolicyHeadMode::Reject &&
         policy.head_mode != FailurePolicyHeadMode::SuppressBody) ||
        !failure_policy_safe_text(policy.reason, kMaxFailurePolicyReasonLen) ||
        !failure_policy_safe_text(policy.content_type, kMaxFailurePolicyContentTypeLen) ||
        !failure_policy_safe_text(policy.server, kMaxFailurePolicyServerLen) ||
        !failure_policy_safe_body(policy.body))
        return false;
    return validate_response_header("Content-Type",
                                   12,
                                   policy.content_type.ptr,
                                   policy.content_type.len) == HttpHeaderValidation::Ok;
}

// The existing default failure-policy contract remains the exact 502 shape.
inline bool forward_failure_policy_spec_valid(const ForwardFailurePolicySpec& policy) {
    return policy.status_code == 502 && forward_failure_policy_spec_shape_valid(policy);
}

// A timeout policy is a complete immutable error response. Its status is
// intentionally bounded to HTTP error statuses, without inheriting from the
// default 502 policy.
inline bool forward_timeout_failure_policy_spec_valid(const ForwardFailurePolicySpec& policy) {
    return forward_failure_policy_spec_shape_valid(policy);
}

// Shared policy tables contain both roles; bundle validation applies the
// stricter role-specific predicate to every referenced ID.
inline bool forward_failure_policy_table_spec_valid(const ForwardFailurePolicySpec& policy) {
    return forward_timeout_failure_policy_spec_valid(policy);
}

inline bool forward_failure_policy_spec_equal(const ForwardFailurePolicySpec& a,
                                              const ForwardFailurePolicySpec& b) {
    return a.version == b.version && a.status_code == b.status_code && a.date == b.date &&
           a.connection == b.connection && a.head_mode == b.head_mode && a.reason.eq(b.reason) &&
           a.content_type.eq(b.content_type) && a.server.eq(b.server) && a.body.eq(b.body);
}

}  // namespace rut
