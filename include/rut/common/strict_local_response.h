#pragma once

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"

namespace rut {

static constexpr u32 kMaxStrictLocalResponsePolicies = 16;
static constexpr u32 kStrictLocalResponseMethodSlots = 10;
static constexpr u32 kMaxStrictLocalResponseReasonLen = 64;
static constexpr u32 kMaxStrictLocalResponseContentTypeLen = 128;
static constexpr u32 kMaxStrictLocalResponseServerLen = 64;
static constexpr u32 kMaxStrictLocalResponseBodyLen = 4096;
static constexpr u32 kMaxStrictLocalResponsePolicyBytes = 8192;

enum class StrictLocalResponseVersion : u8 { Invalid = 0, Http11 = 1 };
enum class StrictLocalResponseDate : u8 { Invalid = 0, Current = 1 };
enum class StrictLocalResponseConnection : u8 { Invalid = 0, Request = 1 };
enum class StrictLocalResponseHeadMode : u8 { Reject = 0, SuppressBody = 1, Invalid = 2 };

struct StrictLocalResponsePolicySpec {
    StrictLocalResponseVersion version = StrictLocalResponseVersion::Invalid;
    u16 status_code = 0;
    StrictLocalResponseDate date = StrictLocalResponseDate::Invalid;
    StrictLocalResponseConnection connection = StrictLocalResponseConnection::Invalid;
    StrictLocalResponseHeadMode head_mode = StrictLocalResponseHeadMode::Invalid;
    Str reason{};
    Str content_type{};
    Str server{};
    Str body{};
};

inline bool strict_local_response_safe_text(Str value, u32 cap) {
    if (value.ptr == nullptr || value.len == 0 || value.len > cap) return false;
    for (u32 i = 0; i < value.len; i++) {
        const u8 c = static_cast<u8>(value.ptr[i]);
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

inline bool strict_local_response_body_valid(Str value) {
    return (value.ptr != nullptr || value.len == 0) && value.len <= kMaxStrictLocalResponseBodyLen;
}

inline bool strict_local_response_content_type_valid(Str value) {
    return value.ptr != nullptr && value.len >= 1 &&
           value.len <= kMaxStrictLocalResponseContentTypeLen &&
           validate_response_header("Content-Type", 12, value.ptr, value.len) ==
               HttpHeaderValidation::Ok;
}

inline bool strict_local_response_policy_spec_valid(const StrictLocalResponsePolicySpec& policy) {
    if (policy.version != StrictLocalResponseVersion::Http11 || policy.status_code < 400 ||
        policy.status_code > 599 || policy.date != StrictLocalResponseDate::Current ||
        policy.connection != StrictLocalResponseConnection::Request ||
        (policy.head_mode != StrictLocalResponseHeadMode::Reject &&
         policy.head_mode != StrictLocalResponseHeadMode::SuppressBody) ||
        !strict_local_response_safe_text(policy.reason, kMaxStrictLocalResponseReasonLen) ||
        !strict_local_response_content_type_valid(policy.content_type) ||
        !strict_local_response_safe_text(policy.server, kMaxStrictLocalResponseServerLen) ||
        !strict_local_response_body_valid(policy.body))
        return false;
    return true;
}

inline bool strict_local_response_policy_spec_equal(const StrictLocalResponsePolicySpec& a,
                                                    const StrictLocalResponsePolicySpec& b) {
    return a.version == b.version && a.status_code == b.status_code && a.date == b.date &&
           a.connection == b.connection && a.head_mode == b.head_mode && a.reason.eq(b.reason) &&
           a.content_type.eq(b.content_type) && a.server.eq(b.server) && a.body.eq(b.body);
}

inline bool strict_local_response_policy_table_valid(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* method_policy_ids,
    u32 method_slot_count = kStrictLocalResponseMethodSlots) {
    if (policy_count > kMaxStrictLocalResponsePolicies ||
        method_slot_count != kStrictLocalResponseMethodSlots || policies == nullptr ||
        method_policy_ids == nullptr)
        return false;

    u32 total_bytes = 0;
    for (u32 i = 0; i < policy_count; i++) {
        const auto& policy = policies[i];
        if (!strict_local_response_policy_spec_valid(policy)) return false;
        const Str fields[] = {policy.reason, policy.content_type, policy.server, policy.body};
        for (const Str field : fields) {
            if (field.len > kMaxStrictLocalResponsePolicyBytes - total_bytes) return false;
            total_bytes += field.len;
        }
    }

    bool referenced[kMaxStrictLocalResponsePolicies]{};
    u32 reference_count = 0;
    for (u32 slot = 0; slot < method_slot_count; slot++) {
        const u16 id = method_policy_ids[slot];
        if (id == 0) continue;
        if (id > policy_count || referenced[id - 1]) return false;
        referenced[id - 1] = true;
        reference_count++;
    }
    if (reference_count != policy_count) return false;
    for (u32 i = 0; i < policy_count; i++)
        if (!referenced[i]) return false;
    return true;
}

}  // namespace rut
