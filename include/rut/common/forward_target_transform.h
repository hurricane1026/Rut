#pragma once

#include "rut/common/types.h"

namespace rut {

// Metadata for bounded forward target transforms.
// IDs are 1-based; zero means no transform. Strings are borrowed by this
// descriptor and must be copied by the owning RIR/config container.
static constexpr u32 kMaxForwardTargetTransforms = 16;
static constexpr u32 kMaxForwardTargetTransformPrefixLen = 128;
static constexpr u32 kForwardTargetTransformBytes = 2048;
static constexpr u16 kInvalidForwardTargetTransformId = 0xffffu;

struct ForwardTargetTransformSpec {
    Str strip_prefix{};
    Str replace_prefix{};
};

inline bool forward_target_transform_clean_prefix(Str value) {
    if (value.ptr == nullptr || value.len == 0 || value.len > kMaxForwardTargetTransformPrefixLen ||
        value.ptr[0] != '/')
        return false;
    if (value.len > 1 && value.ptr[value.len - 1] != '/') return false;
    for (u32 i = 0; i < value.len; i++) {
        const u8 c = static_cast<u8>(value.ptr[i]);
        if (c < 0x21 || c == 0x7f || c == '%' || c == '?' || c == '#') return false;
        if (i > 0 && value.ptr[i] == '/' && value.ptr[i - 1] == '/') return false;
    }
    u32 segment_start = 1;
    for (u32 i = 1; i <= value.len; i++) {
        if (i != value.len && value.ptr[i] != '/') continue;
        const u32 segment_len = i - segment_start;
        if (segment_len == 1 && value.ptr[segment_start] == '.') return false;
        if (segment_len == 2 && value.ptr[segment_start] == '.' &&
            value.ptr[segment_start + 1] == '.')
            return false;
        segment_start = i + 1;
    }
    return true;
}

inline bool forward_target_transform_replacement_prefix(Str value) {
    if (forward_target_transform_clean_prefix(value)) return true;
    if (value.ptr == nullptr || value.len < 3 || value.len > kMaxForwardTargetTransformPrefixLen)
        return false;

    u32 query_delimiter = value.len;
    for (u32 i = 0; i < value.len; i++) {
        if (value.ptr[i] != '?') continue;
        if (query_delimiter != value.len) return false;
        query_delimiter = i;
    }
    if (query_delimiter == value.len || query_delimiter + 1 == value.len ||
        !forward_target_transform_clean_prefix({value.ptr, query_delimiter}))
        return false;

    for (u32 i = query_delimiter + 1; i < value.len; i++) {
        const u8 c = static_cast<u8>(value.ptr[i]);
        const bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        const bool digit = c >= '0' && c <= '9';
        if (!alpha && !digit && c != '.' && c != '_' && c != '~' && c != '-' && c != '=' &&
            c != '&')
            return false;
    }
    return true;
}

inline bool forward_target_transform_spec_valid(const ForwardTargetTransformSpec& spec) {
    return forward_target_transform_clean_prefix(spec.strip_prefix) &&
           forward_target_transform_replacement_prefix(spec.replace_prefix);
}

inline bool forward_target_transform_id_is_valid(u16 id, u32 count) {
    return id != 0 && id != kInvalidForwardTargetTransformId &&
           count <= kMaxForwardTargetTransforms && id <= count;
}

inline bool forward_target_transform_spec_equal(const ForwardTargetTransformSpec& a,
                                                const ForwardTargetTransformSpec& b) {
    return a.strip_prefix.eq(b.strip_prefix) && a.replace_prefix.eq(b.replace_prefix);
}

// Validate a complete borrowed table before any owning container copies it.
// The duplicate check is intentional: RIR IDs are positional, so silently
// deduplicating an entry would change every later 1-based ID.
inline bool forward_target_transform_table_valid(const ForwardTargetTransformSpec* specs,
                                                 u32 count) {
    if (count > kMaxForwardTargetTransforms || (count != 0 && specs == nullptr)) return false;
    u32 total = 0;
    for (u32 i = 0; i < count; i++) {
        if (!forward_target_transform_spec_valid(specs[i])) return false;
        if (specs[i].strip_prefix.len > kForwardTargetTransformBytes - total) return false;
        total += specs[i].strip_prefix.len;
        if (specs[i].replace_prefix.len > kForwardTargetTransformBytes - total) return false;
        total += specs[i].replace_prefix.len;
        for (u32 j = 0; j < i; j++) {
            if (forward_target_transform_spec_equal(specs[i], specs[j])) return false;
        }
    }
    return true;
}

}  // namespace rut
