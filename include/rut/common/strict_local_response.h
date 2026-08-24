#pragma once

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"

#include <stddef.h>

namespace rut {

static constexpr u32 kMaxStrictLocalResponsePolicies = 16;
static constexpr u32 kStrictLocalResponseMethodSlots = 10;
static constexpr u8 kStrictLocalResponseAnyMethodSlot = 0;
static constexpr u8 kStrictLocalResponseHeadMethodSlot = 6;
static constexpr u32 kMaxStrictLocalResponseReasonLen = 64;
static constexpr u32 kMaxStrictLocalResponseContentTypeLen = 128;
static constexpr u32 kMaxStrictLocalResponseServerLen = 64;
static constexpr u32 kMaxStrictLocalResponseBodyLen = 4096;
static constexpr u32 kMaxStrictLocalResponsePolicyBytes = 8192;
static constexpr u32 kMaxExactStrictLocalResponseBindings = 16;
static constexpr u32 kMaxExactStrictLocalResponsePathLen = 62;

// Compiler/runtime hand-off metadata for the bounded exact selector.  Every
// byte is named and validated so forged padding can never hide activation.
// Runtime ownership and selection are deliberately later increments.
struct ExactStrictLocalResponseBinding {
    char path[kMaxExactStrictLocalResponsePathLen + 1]{};
    u8 path_len = 0;
    u8 method = 0;
    u8 reserved0 = 0;
    u16 policy_id = 0;
    u32 reserved1 = 0;
};

static_assert(sizeof(ExactStrictLocalResponseBinding) == 72);
static_assert(offsetof(ExactStrictLocalResponseBinding, path) == 0);
static_assert(offsetof(ExactStrictLocalResponseBinding, path_len) == 63);
static_assert(offsetof(ExactStrictLocalResponseBinding, method) == 64);
static_assert(offsetof(ExactStrictLocalResponseBinding, reserved0) == 65);
static_assert(offsetof(ExactStrictLocalResponseBinding, policy_id) == 66);
static_assert(offsetof(ExactStrictLocalResponseBinding, reserved1) == 68);

inline bool exact_strict_local_response_binding_is_neutral(
    const ExactStrictLocalResponseBinding& binding) {
    for (u32 i = 0; i < sizeof(binding.path); i++)
        if (binding.path[i] != 0) return false;
    return binding.path_len == 0 && binding.method == 0 && binding.reserved0 == 0 &&
           binding.policy_id == 0 && binding.reserved1 == 0;
}

inline bool exact_strict_local_response_path_byte_valid(char value) {
    const u8 byte = static_cast<u8>(value);
    return byte >= 0x21 && byte != 0x7f && value != '?' && value != '#' && value != ':' &&
           value != '*' && value != '$' && value != '{' && value != '}' && value != '\\';
}

inline bool exact_strict_local_response_binding_shape_valid(
    const ExactStrictLocalResponseBinding& binding) {
    if (binding.path_len == 0 || binding.path_len > kMaxExactStrictLocalResponsePathLen ||
        binding.path[0] != '/' || binding.method >= kStrictLocalResponseMethodSlots ||
        binding.reserved0 != 0 || binding.policy_id == 0 || binding.reserved1 != 0)
        return false;
    for (u32 i = 0; i < binding.path_len; i++)
        if (!exact_strict_local_response_path_byte_valid(binding.path[i])) return false;
    for (u32 i = binding.path_len; i < sizeof(binding.path); i++)
        if (binding.path[i] != 0) return false;
    return true;
}

inline bool exact_strict_local_response_inventory_present(
    const ExactStrictLocalResponseBinding* bindings,
    u32 binding_count,
    u32 binding_capacity = kMaxExactStrictLocalResponseBindings) {
    if (binding_count != 0) return true;
    if (bindings == nullptr) return false;
    for (u32 i = 0; i < binding_capacity; i++)
        if (!exact_strict_local_response_binding_is_neutral(bindings[i])) return true;
    return false;
}

enum class StrictLocalResponseVersion : u8 { Invalid = 0, Http11 = 1 };
enum class StrictLocalResponseDate : u8 { Invalid = 0, Current = 1 };
enum class StrictLocalResponseConnection : u8 { Invalid = 0, Request = 1 };
enum class StrictLocalResponseHeadMode : u8 { Reject = 0, SuppressBody = 1, Invalid = 2 };
enum class StrictLocalResponseProfile : u8 {
    Invalid = 0,
    Representation200 = 1,
    LegacyError = 2,
};

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

constexpr StrictLocalResponseProfile strict_local_response_profile(u16 status_code) {
    if (status_code == 200) return StrictLocalResponseProfile::Representation200;
    if (status_code >= 400 && status_code <= 599) return StrictLocalResponseProfile::LegacyError;
    return StrictLocalResponseProfile::Invalid;
}

constexpr bool strict_local_response_status_supported(u16 status_code) {
    return strict_local_response_profile(status_code) != StrictLocalResponseProfile::Invalid;
}

inline bool strict_local_response_policy_spec_valid(const StrictLocalResponsePolicySpec& policy) {
    const auto profile = strict_local_response_profile(policy.status_code);
    if (profile == StrictLocalResponseProfile::Invalid ||
        policy.version != StrictLocalResponseVersion::Http11 ||
        policy.date != StrictLocalResponseDate::Current ||
        policy.connection != StrictLocalResponseConnection::Request ||
        (policy.head_mode != StrictLocalResponseHeadMode::Reject &&
         policy.head_mode != StrictLocalResponseHeadMode::SuppressBody) ||
        !strict_local_response_safe_text(policy.reason, kMaxStrictLocalResponseReasonLen) ||
        !strict_local_response_content_type_valid(policy.content_type) ||
        !strict_local_response_safe_text(policy.server, kMaxStrictLocalResponseServerLen) ||
        !strict_local_response_body_valid(policy.body))
        return false;
    if (profile == StrictLocalResponseProfile::Representation200 &&
        (!policy.reason.eq(lit_str("OK")) || !policy.content_type.eq(lit_str("text/plain")) ||
         policy.head_mode != StrictLocalResponseHeadMode::SuppressBody || policy.body.len == 0))
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

// Compiler-source ownership validator for the combined unmatched + exact
// metadata contract.  Source IDs are intentionally single-use; a later
// RouteConfig installer may semantically deduplicate equal policy specs while
// remapping those independent source IDs.
inline bool strict_local_response_source_table_valid(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* unmatched_policy_ids,
    const ExactStrictLocalResponseBinding* exact_bindings,
    u32 exact_binding_count,
    u32 exact_binding_capacity = kMaxExactStrictLocalResponseBindings) {
    if (policy_count > kMaxStrictLocalResponsePolicies || policies == nullptr ||
        unmatched_policy_ids == nullptr || exact_bindings == nullptr ||
        exact_binding_capacity != kMaxExactStrictLocalResponseBindings ||
        exact_binding_count > exact_binding_capacity)
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
    auto add_reference = [&](u16 id) {
        if (id == 0 || id > policy_count || referenced[id - 1]) return false;
        referenced[id - 1] = true;
        reference_count++;
        return true;
    };
    for (u32 slot = 0; slot < kStrictLocalResponseMethodSlots; slot++) {
        const u16 id = unmatched_policy_ids[slot];
        if (id == 0) continue;
        if (!add_reference(id)) return false;
        if ((slot == kStrictLocalResponseAnyMethodSlot ||
             slot == kStrictLocalResponseHeadMethodSlot) &&
            policies[id - 1].head_mode != StrictLocalResponseHeadMode::SuppressBody)
            return false;
    }
    for (u32 i = 0; i < exact_binding_capacity; i++) {
        const auto& binding = exact_bindings[i];
        if (i >= exact_binding_count) {
            if (!exact_strict_local_response_binding_is_neutral(binding)) return false;
            continue;
        }
        if (!exact_strict_local_response_binding_shape_valid(binding) ||
            !add_reference(binding.policy_id))
            return false;
        if ((binding.method == kStrictLocalResponseAnyMethodSlot ||
             binding.method == kStrictLocalResponseHeadMethodSlot) &&
            policies[binding.policy_id - 1].head_mode != StrictLocalResponseHeadMode::SuppressBody)
            return false;
        for (u32 prior = 0; prior < i; prior++) {
            const auto& earlier = exact_bindings[prior];
            if (earlier.method != binding.method || earlier.path_len != binding.path_len) continue;
            bool equal = true;
            for (u32 byte = 0; byte < binding.path_len; byte++)
                equal &= earlier.path[byte] == binding.path[byte];
            if (equal) return false;
        }
    }
    return reference_count == policy_count;
}

}  // namespace rut
