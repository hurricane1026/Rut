#pragma once

#include "rut/common/forward_policy_head_mode.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/response_policy.h"
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

// Envoy H1 profile (docs/envoy-converter.md; envoy-pr-plan.md PR5):
// lowercase header names, `connection: close` only when closing, and the
// `content-length, content-type, date, server` wire order. `Synthesized` is
// today's nginx-compatible 502 shape and is the only value the 502 role ever
// admits; `LengthTypeDateServer` is admitted only for status 503 with a
// non-empty body.
enum class FailurePolicyHeaderOrder : u8 { Synthesized = 0, LengthTypeDateServer = 1 };

enum class ForwardResponseBufferingMode : u8 {
    None = 0,
    CompleteContentLength = 1,
};

inline bool forward_response_buffering_mode_valid(ForwardResponseBufferingMode mode) {
    return mode == ForwardResponseBufferingMode::None ||
           mode == ForwardResponseBufferingMode::CompleteContentLength;
}

struct ForwardFailurePolicySpec {
    ForwardFailurePolicyVersion version = ForwardFailurePolicyVersion::Invalid;
    u16 status_code = 0;
    ForwardFailurePolicyDate date = ForwardFailurePolicyDate::Invalid;
    ForwardFailurePolicyConnection connection = ForwardFailurePolicyConnection::Invalid;
    FailurePolicyHeadMode head_mode = FailurePolicyHeadMode::Reject;
    FailurePolicyHeaderOrder header_order = FailurePolicyHeaderOrder::Synthesized;
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
    // Optional per-forward upstream response-read inactivity interval. Zero is
    // internal absence; the current TimerWheel representation is exact 1..63s.
    u8 response_read_timeout_seconds = 0;
    // Optional entire-response commit barrier. The packed handler ABI carries
    // only this bundle's id; zero preserves the existing streaming behavior.
    ForwardResponseBufferingMode response_buffering = ForwardResponseBufferingMode::None;
};

static_assert(sizeof(ForwardPolicyBundle) == 8,
              "ForwardPolicyBundle metadata must remain one compact 8-byte value");

inline bool response_read_timeout_seconds_valid(u8 seconds) {
    return seconds >= 1 && seconds <= 63;
}

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

inline bool forward_failure_policy_spec_scalar_valid(const ForwardFailurePolicySpec& policy) {
    return policy.version == ForwardFailurePolicyVersion::Http11 && policy.status_code >= 400 &&
           policy.status_code <= 599 && policy.date == ForwardFailurePolicyDate::Current &&
           policy.connection == ForwardFailurePolicyConnection::Request &&
           (policy.head_mode == FailurePolicyHeadMode::Reject ||
            policy.head_mode == FailurePolicyHeadMode::SuppressBody);
}

inline bool forward_failure_policy_spec_shape_valid(const ForwardFailurePolicySpec& policy) {
    if (!forward_failure_policy_spec_scalar_valid(policy) ||
        !failure_policy_safe_text(policy.reason, kMaxFailurePolicyReasonLen) ||
        !failure_policy_safe_text(policy.content_type, kMaxFailurePolicyContentTypeLen) ||
        !failure_policy_safe_text(policy.server, kMaxFailurePolicyServerLen) ||
        !failure_policy_safe_body(policy.body))
        return false;
    // The fixed Content-Type name is a valid, non-reserved token. The text
    // check above already rejects every forbidden value byte (and also HTAB,
    // which generic response headers allow), so no second scan is needed.
    return true;
}

// The existing default failure-policy contract remains the exact 502 shape.
// Status 503 is admitted only paired with the Envoy `LengthTypeDateServer`
// layout and a non-empty body (the connect-failure representation); 502
// stays closed to `Synthesized`, so nginx's contract is untouched.
inline bool forward_failure_policy_spec_valid(const ForwardFailurePolicySpec& policy) {
    if (!forward_failure_policy_spec_shape_valid(policy)) return false;
    if (policy.header_order == FailurePolicyHeaderOrder::LengthTypeDateServer)
        return policy.status_code == 503 && policy.body.len != 0;
    return policy.status_code == 502 &&
           policy.header_order == FailurePolicyHeaderOrder::Synthesized;
}

// A timeout policy is a complete immutable error response. Its status is
// intentionally bounded to HTTP error statuses, without inheriting from the
// default 502 policy. Kept `Synthesized`-only: no timeout shape has an Envoy
// oracle yet.
inline bool forward_timeout_failure_policy_spec_valid(const ForwardFailurePolicySpec& policy) {
    return policy.header_order == FailurePolicyHeaderOrder::Synthesized &&
           forward_failure_policy_spec_shape_valid(policy);
}

// Re-checks of policies owned by an immutable RouteConfig: the role checks
// always run, the byte-level re-scan only when kRescanAdmittedPolicies.
inline bool admitted_forward_failure_policy_valid(const ForwardFailurePolicySpec& policy) {
    if (kRescanAdmittedPolicies) return forward_failure_policy_spec_valid(policy);
    if (policy.header_order == FailurePolicyHeaderOrder::LengthTypeDateServer)
        return policy.status_code == 503 && forward_failure_policy_spec_scalar_valid(policy);
    return policy.status_code == 502 &&
           policy.header_order == FailurePolicyHeaderOrder::Synthesized &&
           forward_failure_policy_spec_scalar_valid(policy);
}

inline bool admitted_forward_timeout_failure_policy_valid(const ForwardFailurePolicySpec& policy) {
    return kRescanAdmittedPolicies ? forward_timeout_failure_policy_spec_valid(policy)
                                   : policy.header_order == FailurePolicyHeaderOrder::Synthesized &&
                                         forward_failure_policy_spec_scalar_valid(policy);
}

inline bool complete_content_length_buffering_policy_roles_valid(
    const ForwardResponsePolicySpec& response,
    const ForwardFailurePolicySpec& failure,
    const ForwardFailurePolicySpec& timeout) {
    return response.version == ResponsePolicyVersion::Http11 &&
           response.framing == ResponsePolicyFraming::ContentLength &&
           response.connection == ResponsePolicyConnection::Request &&
           response.head_mode == ResponsePolicyHeadMode::Reject &&
           failure.head_mode == FailurePolicyHeadMode::Reject &&
           timeout.head_mode == FailurePolicyHeadMode::Reject;
}

inline bool admitted_complete_content_length_buffering_policies_valid(
    const ForwardResponsePolicySpec& response,
    const ForwardFailurePolicySpec& failure,
    const ForwardFailurePolicySpec& timeout) {
    return admitted_response_policy_valid(response) &&
           admitted_forward_failure_policy_valid(failure) &&
           admitted_forward_timeout_failure_policy_valid(timeout) &&
           complete_content_length_buffering_policy_roles_valid(response, failure, timeout);
}

inline bool complete_content_length_buffering_policies_valid(
    const ForwardResponsePolicySpec& response,
    const ForwardFailurePolicySpec& failure,
    const ForwardFailurePolicySpec& timeout) {
    return response_policy_spec_valid(response) &&
           response.version == ResponsePolicyVersion::Http11 &&
           response.framing == ResponsePolicyFraming::ContentLength &&
           response.connection == ResponsePolicyConnection::Request &&
           response.head_mode == ResponsePolicyHeadMode::Reject &&
           forward_failure_policy_spec_valid(failure) &&
           failure.head_mode == FailurePolicyHeadMode::Reject &&
           forward_timeout_failure_policy_spec_valid(timeout) &&
           timeout.head_mode == FailurePolicyHeadMode::Reject;
}

// Complete static policy contract for the positive fixed-upload HEAD deadline
// profile.  This deliberately does not admit any other request or response
// shape; the request-policy and route-method closed sets are checked separately.
inline bool fixed_upload_head_timeout_policies_valid(const ForwardResponsePolicySpec& response,
                                                     const ForwardFailurePolicySpec& failure,
                                                     const ForwardFailurePolicySpec& timeout) {
    return response_policy_spec_valid(response) &&
           response.connection == ResponsePolicyConnection::Request &&
           response.head_mode == ResponsePolicyHeadMode::SuppressBody &&
           forward_failure_policy_spec_valid(failure) &&
           failure.head_mode == FailurePolicyHeadMode::SuppressBody &&
           forward_timeout_failure_policy_spec_valid(timeout) &&
           timeout.head_mode == FailurePolicyHeadMode::SuppressBody;
}

inline bool admitted_fixed_upload_head_timeout_policies_valid(
    const ForwardResponsePolicySpec& response,
    const ForwardFailurePolicySpec& failure,
    const ForwardFailurePolicySpec& timeout) {
    return admitted_response_policy_valid(response) &&
           response.connection == ResponsePolicyConnection::Request &&
           response.head_mode == ResponsePolicyHeadMode::SuppressBody &&
           admitted_forward_failure_policy_valid(failure) &&
           failure.head_mode == FailurePolicyHeadMode::SuppressBody &&
           admitted_forward_timeout_failure_policy_valid(timeout) &&
           timeout.head_mode == FailurePolicyHeadMode::SuppressBody;
}

// Shared policy tables contain both roles; bundle validation applies the
// stricter role-specific predicate to every referenced ID. A table entry is
// admissible if it is valid under either role: the default-failure role (502
// Synthesized, or 503 with the Envoy layout) or the timeout role (400..599,
// Synthesized only).
inline bool forward_failure_policy_table_spec_valid(const ForwardFailurePolicySpec& policy) {
    return forward_failure_policy_spec_valid(policy) ||
           forward_timeout_failure_policy_spec_valid(policy);
}

inline bool forward_failure_policy_spec_equal(const ForwardFailurePolicySpec& a,
                                              const ForwardFailurePolicySpec& b) {
    return a.version == b.version && a.status_code == b.status_code && a.date == b.date &&
           a.connection == b.connection && a.head_mode == b.head_mode &&
           a.header_order == b.header_order && a.reason.eq(b.reason) &&
           a.content_type.eq(b.content_type) && a.server.eq(b.server) && a.body.eq(b.body);
}

}  // namespace rut
