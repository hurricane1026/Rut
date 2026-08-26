#pragma once

#include "rut/common/exact_path_view.h"
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
static constexpr u32 kMaxExactStrictLocalResponsePathLen = kMaxExactPathViewLen;

// Compiler/runtime hand-off metadata for the bounded exact selector.  Every
// byte is named and validated so forged padding can never hide activation.
// Runtime ownership and selection are deliberately later increments.
struct ExactStrictLocalResponseBinding {
    char path[kMaxExactStrictLocalResponsePathLen + 1]{};
    u8 path_len = 0;
    u8 method = 0;
    ExactPathView path_view = ExactPathView::Raw;
    u16 policy_id = 0;
    u32 reserved1 = 0;
};

static_assert(sizeof(ExactStrictLocalResponseBinding) == 72);
static_assert(offsetof(ExactStrictLocalResponseBinding, path) == 0);
static_assert(offsetof(ExactStrictLocalResponseBinding, path_len) == 63);
static_assert(offsetof(ExactStrictLocalResponseBinding, method) == 64);
static_assert(offsetof(ExactStrictLocalResponseBinding, path_view) == 65);
static_assert(offsetof(ExactStrictLocalResponseBinding, policy_id) == 66);
static_assert(offsetof(ExactStrictLocalResponseBinding, reserved1) == 68);

inline bool exact_strict_local_response_binding_is_neutral(
    const ExactStrictLocalResponseBinding& binding) {
    for (u32 i = 0; i < sizeof(binding.path); i++)
        if (binding.path[i] != 0) return false;
    return binding.path_len == 0 && binding.method == 0 &&
           binding.path_view == ExactPathView::Raw &&
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
        (binding.path_view != ExactPathView::Raw &&
         binding.path_view != ExactPathView::SlashNormalized) ||
        binding.policy_id == 0 || binding.reserved1 != 0)
        return false;
    for (u32 i = 0; i < binding.path_len; i++)
        if (!exact_strict_local_response_path_byte_valid(binding.path[i])) return false;
    for (u32 i = binding.path_len; i < sizeof(binding.path); i++)
        if (binding.path[i] != 0) return false;
    if (binding.path_view == ExactPathView::SlashNormalized) {
        if (binding.path_len == 1) return false;
        char normalized[kMaxExactPathViewLen]{};
        u32 normalized_len = 0;
        if (normalize_exact_path_slashes({binding.path, binding.path_len},
                                         normalized,
                                         sizeof(normalized),
                                         &normalized_len) !=
                ExactPathNormalizationResult::Success ||
            normalized_len != binding.path_len)
            return false;
        for (u32 i = 0; i < normalized_len; i++)
            if (normalized[i] != binding.path[i]) return false;
    }
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
    NoContent204 = 3,
};

struct StrictLocalResponsePolicySpec {
    StrictLocalResponseVersion version = StrictLocalResponseVersion::Invalid;
    u8 reserved0 = 0;
    u16 status_code = 0;
    StrictLocalResponseDate date = StrictLocalResponseDate::Invalid;
    StrictLocalResponseConnection connection = StrictLocalResponseConnection::Invalid;
    StrictLocalResponseHeadMode head_mode = StrictLocalResponseHeadMode::Invalid;
    u8 reserved1 = 0;
    Str reason{};
    Str content_type{};
    Str server{};
    Str body{};
};

static_assert(sizeof(StrictLocalResponsePolicySpec) == 72);
static_assert(offsetof(StrictLocalResponsePolicySpec, version) == 0);
static_assert(offsetof(StrictLocalResponsePolicySpec, reserved0) == 1);
static_assert(offsetof(StrictLocalResponsePolicySpec, status_code) == 2);
static_assert(offsetof(StrictLocalResponsePolicySpec, date) == 4);
static_assert(offsetof(StrictLocalResponsePolicySpec, connection) == 5);
static_assert(offsetof(StrictLocalResponsePolicySpec, head_mode) == 6);
static_assert(offsetof(StrictLocalResponsePolicySpec, reserved1) == 7);
static_assert(offsetof(StrictLocalResponsePolicySpec, reason) == 8);
static_assert(offsetof(StrictLocalResponsePolicySpec, content_type) == 24);
static_assert(offsetof(StrictLocalResponsePolicySpec, server) == 40);
static_assert(offsetof(StrictLocalResponsePolicySpec, body) == 56);

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
    return status_code == 204 ||
           strict_local_response_profile(status_code) != StrictLocalResponseProfile::Invalid;
}

// Closed vocabulary derived from the complete semantic tuple. Status 204 is
// never sufficient by itself: every public trust boundary validates the full
// tuple below before admitting the derived no-content profile.
inline StrictLocalResponseProfile strict_local_response_policy_profile(
    const StrictLocalResponsePolicySpec& policy) {
    const auto profile = strict_local_response_profile(policy.status_code);
    if (policy.reserved0 != 0 || policy.reserved1 != 0 ||
        policy.version != StrictLocalResponseVersion::Http11 ||
        policy.date != StrictLocalResponseDate::Current ||
        policy.connection != StrictLocalResponseConnection::Request ||
        (policy.head_mode != StrictLocalResponseHeadMode::Reject &&
         policy.head_mode != StrictLocalResponseHeadMode::SuppressBody) ||
        !strict_local_response_safe_text(policy.reason, kMaxStrictLocalResponseReasonLen) ||
        !strict_local_response_safe_text(policy.server, kMaxStrictLocalResponseServerLen))
        return StrictLocalResponseProfile::Invalid;
    if (policy.status_code == 204) {
        if (!policy.reason.eq(lit_str("No Content")) ||
            policy.head_mode != StrictLocalResponseHeadMode::SuppressBody ||
            policy.content_type.len != 0 || policy.body.len != 0)
            return StrictLocalResponseProfile::Invalid;
        return StrictLocalResponseProfile::NoContent204;
    }
    if (profile == StrictLocalResponseProfile::Invalid ||
        !strict_local_response_content_type_valid(policy.content_type) ||
        !strict_local_response_body_valid(policy.body))
        return StrictLocalResponseProfile::Invalid;
    if (profile == StrictLocalResponseProfile::Representation200 &&
        (!policy.reason.eq(lit_str("OK")) || !policy.content_type.eq(lit_str("text/plain")) ||
         policy.head_mode != StrictLocalResponseHeadMode::SuppressBody || policy.body.len == 0))
        return StrictLocalResponseProfile::Invalid;
    return profile;
}

inline bool strict_local_response_policy_spec_valid(const StrictLocalResponsePolicySpec& policy) {
    const auto profile = strict_local_response_policy_profile(policy);
    return profile == StrictLocalResponseProfile::Representation200 ||
           profile == StrictLocalResponseProfile::LegacyError ||
           profile == StrictLocalResponseProfile::NoContent204;
}

// Retained explicit entry point for the staged compiler/config propagation
// contract. Public validation now accepts the same closed vocabulary, while
// this name remains source-compatible with the reviewed internal pipeline.
inline bool strict_local_response_policy_spec_valid_for_internal_propagation(
    const StrictLocalResponsePolicySpec& policy) {
    return strict_local_response_policy_profile(policy) != StrictLocalResponseProfile::Invalid;
}

inline bool strict_local_response_policy_spec_equal(const StrictLocalResponsePolicySpec& a,
                                                    const StrictLocalResponsePolicySpec& b) {
    if (a.reserved0 != 0 || a.reserved1 != 0 || b.reserved0 != 0 || b.reserved1 != 0) return false;
    return a.version == b.version && a.status_code == b.status_code && a.date == b.date &&
           a.connection == b.connection && a.head_mode == b.head_mode && a.reason.eq(b.reason) &&
           a.content_type.eq(b.content_type) && a.server.eq(b.server) && a.body.eq(b.body);
}

namespace detail {

inline bool strict_local_response_policy_table_valid_impl(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* method_policy_ids,
    u32 method_slot_count,
    bool internal_propagation) {
    if (policy_count > kMaxStrictLocalResponsePolicies ||
        method_slot_count != kStrictLocalResponseMethodSlots || policies == nullptr ||
        method_policy_ids == nullptr)
        return false;

    u32 total_bytes = 0;
    for (u32 i = 0; i < policy_count; i++) {
        const auto& policy = policies[i];
        if (internal_propagation
                ? !strict_local_response_policy_spec_valid_for_internal_propagation(policy)
                : !strict_local_response_policy_spec_valid(policy))
            return false;
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

}  // namespace detail

inline bool strict_local_response_policy_table_valid(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* method_policy_ids,
    u32 method_slot_count = kStrictLocalResponseMethodSlots) {
    return detail::strict_local_response_policy_table_valid_impl(
        policies, policy_count, method_policy_ids, method_slot_count, false);
}

inline bool strict_local_response_policy_table_valid_for_internal_propagation(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* method_policy_ids,
    u32 method_slot_count = kStrictLocalResponseMethodSlots) {
    return detail::strict_local_response_policy_table_valid_impl(
        policies, policy_count, method_policy_ids, method_slot_count, true);
}

// Compiler-source ownership validator for the combined pre-route + unmatched + exact
// metadata contract.  Source IDs are intentionally single-use; a later
// RouteConfig installer may semantically deduplicate equal policy specs while
// remapping those independent source IDs.
namespace detail {

inline bool strict_local_response_source_table_valid_impl(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* pre_route_policy_ids,
    const u16* unmatched_policy_ids,
    const ExactStrictLocalResponseBinding* exact_bindings,
    u32 exact_binding_count,
    u32 exact_binding_capacity,
    bool internal_propagation) {
    if (policy_count > kMaxStrictLocalResponsePolicies || policies == nullptr ||
        pre_route_policy_ids == nullptr || unmatched_policy_ids == nullptr ||
        exact_bindings == nullptr ||
        exact_binding_capacity != kMaxExactStrictLocalResponseBindings ||
        exact_binding_count > exact_binding_capacity)
        return false;

    u32 total_bytes = 0;
    for (u32 i = 0; i < policy_count; i++) {
        const auto& policy = policies[i];
        if (internal_propagation
                ? !strict_local_response_policy_spec_valid_for_internal_propagation(policy)
                : !strict_local_response_policy_spec_valid(policy))
            return false;
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
    if (pre_route_policy_ids[kStrictLocalResponseAnyMethodSlot] != 0) return false;
    for (u32 slot = 1; slot < kStrictLocalResponseMethodSlots; slot++) {
        const u16 id = pre_route_policy_ids[slot];
        if (id == 0) continue;
        if (!add_reference(id)) return false;
        if (slot == kStrictLocalResponseHeadMethodSlot &&
            policies[id - 1].head_mode != StrictLocalResponseHeadMode::SuppressBody)
            return false;
    }
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
            if (earlier.method != binding.method || earlier.path_view != binding.path_view ||
                earlier.path_len != binding.path_len)
                continue;
            bool equal = true;
            for (u32 byte = 0; byte < binding.path_len; byte++)
                equal &= earlier.path[byte] == binding.path[byte];
            if (equal) return false;
        }
    }
    return reference_count == policy_count;
}

}  // namespace detail

inline bool strict_local_response_source_table_valid(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* pre_route_policy_ids,
    const u16* unmatched_policy_ids,
    const ExactStrictLocalResponseBinding* exact_bindings,
    u32 exact_binding_count,
    u32 exact_binding_capacity = kMaxExactStrictLocalResponseBindings) {
    return detail::strict_local_response_source_table_valid_impl(policies,
                                                                 policy_count,
                                                                 pre_route_policy_ids,
                                                                 unmatched_policy_ids,
                                                                 exact_bindings,
                                                                 exact_binding_count,
                                                                 exact_binding_capacity,
                                                                 false);
}

inline bool strict_local_response_source_table_valid_for_internal_propagation(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* pre_route_policy_ids,
    const u16* unmatched_policy_ids,
    const ExactStrictLocalResponseBinding* exact_bindings,
    u32 exact_binding_count,
    u32 exact_binding_capacity = kMaxExactStrictLocalResponseBindings) {
    return detail::strict_local_response_source_table_valid_impl(policies,
                                                                 policy_count,
                                                                 pre_route_policy_ids,
                                                                 unmatched_policy_ids,
                                                                 exact_bindings,
                                                                 exact_binding_count,
                                                                 exact_binding_capacity,
                                                                 true);
}

inline bool strict_local_response_source_table_valid_for_internal_propagation(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* unmatched_policy_ids,
    const ExactStrictLocalResponseBinding* exact_bindings,
    u32 exact_binding_count,
    u32 exact_binding_capacity = kMaxExactStrictLocalResponseBindings) {
    const u16 empty_pre_route[kStrictLocalResponseMethodSlots]{};
    return strict_local_response_source_table_valid_for_internal_propagation(
        policies,
        policy_count,
        empty_pre_route,
        unmatched_policy_ids,
        exact_bindings,
        exact_binding_count,
        exact_binding_capacity);
}

// Compatibility overload for compiler/runtime callers that intentionally have
// no pre-route source metadata. New source pipelines use the complete overload
// above so policy references are validated across all three selector classes.
inline bool strict_local_response_source_table_valid(
    const StrictLocalResponsePolicySpec* policies,
    u32 policy_count,
    const u16* unmatched_policy_ids,
    const ExactStrictLocalResponseBinding* exact_bindings,
    u32 exact_binding_count,
    u32 exact_binding_capacity = kMaxExactStrictLocalResponseBindings) {
    const u16 empty_pre_route[kStrictLocalResponseMethodSlots]{};
    return strict_local_response_source_table_valid(policies,
                                                    policy_count,
                                                    empty_pre_route,
                                                    unmatched_policy_ids,
                                                    exact_bindings,
                                                    exact_binding_count,
                                                    exact_binding_capacity);
}

}  // namespace rut
