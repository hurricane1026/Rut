#pragma once

#include "rut/common/types.h"

namespace rut {

// Selection view for bounded exact paths. Raw is zero so existing zero-filled
// metadata remains byte-compatible when a later increment carries this field.
enum class ExactPathView : u8 { Raw = 0, SlashNormalized = 1 };

static_assert(sizeof(ExactPathView) == sizeof(u8));
static_assert(static_cast<u8>(ExactPathView::Raw) == 0);
static_assert(static_cast<u8>(ExactPathView::SlashNormalized) == 1);

// Shared bound for exact path selectors. The existing strict-local-response
// bound aliases this value; normalized output is never truncated to fit it.
static constexpr u32 kMaxExactPathViewLen = 62;

enum class ExactPathNormalizationResult : u8 {
    Success = 0,
    InvalidInput = 1,
    OutputOverflow = 2,
};

// Produce a slash-normalized exact-selection key from a raw origin-form target.
//
// This helper is intentionally not a general URI validator. Its caller must
// first establish that the complete request target passed strict HTTP parsing.
// Within the path bytes (before the first '?') it nevertheless fails closed on
// fragments and ASCII controls, requires exactly one leading '/', and treats
// percent escapes and dot-segment spellings as opaque bytes. Query bytes are
// neither copied nor inspected. Embedded/trailing slash runs collapse to one;
// consequently a meaningful trailing slash is retained.
//
// The function does not allocate or mutate input. It first validates and counts
// the complete result, then writes, so output and output_len remain unchanged on
// InvalidInput or OutputOverflow. output_capacity may be smaller than the shared
// bound, but no successful output may exceed kMaxExactPathViewLen. Integer-range
// coherence checks prevent address arithmetic from wrapping; they cannot prove
// that arbitrary addresses refer to mapped storage, so callers still own valid
// storage provenance for every supplied range.
inline ExactPathNormalizationResult normalize_exact_path_slashes(Str raw,
                                                                 char* output,
                                                                 u32 output_capacity,
                                                                 u32* output_len) {
    if (raw.ptr == nullptr || raw.len == 0 || output == nullptr || output_len == nullptr)
        return ExactPathNormalizationResult::InvalidInput;

    const uintptr_t raw_begin = reinterpret_cast<uintptr_t>(raw.ptr);
    if (raw.len > UINTPTR_MAX - raw_begin)
        return ExactPathNormalizationResult::InvalidInput;
    const uintptr_t raw_end = raw_begin + raw.len;

    if (raw.ptr[0] != '/') return ExactPathNormalizationResult::InvalidInput;

    u32 path_end = 0;
    while (path_end < raw.len && raw.ptr[path_end] != '?') {
        const u8 byte = static_cast<u8>(raw.ptr[path_end]);
        if (raw.ptr[path_end] == '#' || byte < 0x20 || byte == 0x7f)
            return ExactPathNormalizationResult::InvalidInput;
        path_end++;
    }
    if (path_end > 1 && raw.ptr[1] == '/')
        return ExactPathNormalizationResult::InvalidInput;

    u32 normalized_len = 0;
    bool previous_slash = false;
    for (u32 i = 0; i < path_end; i++) {
        const bool slash = raw.ptr[i] == '/';
        if (!slash || !previous_slash) normalized_len++;
        previous_slash = slash;
    }
    if (normalized_len > kMaxExactPathViewLen || normalized_len > output_capacity)
        return ExactPathNormalizationResult::OutputOverflow;

    // Refuse aliased storage so the transactional input/output guarantees are
    // preserved even when a caller accidentally supplies an in-place range.
    const uintptr_t output_begin = reinterpret_cast<uintptr_t>(output);
    const uintptr_t output_len_begin = reinterpret_cast<uintptr_t>(output_len);
    if (normalized_len > UINTPTR_MAX - output_begin ||
        sizeof(*output_len) > UINTPTR_MAX - output_len_begin)
        return ExactPathNormalizationResult::InvalidInput;
    const uintptr_t output_end = output_begin + normalized_len;
    const uintptr_t output_len_end = output_len_begin + sizeof(*output_len);
    const auto ranges_overlap = [](uintptr_t first_begin,
                                   uintptr_t first_end,
                                   uintptr_t second_begin,
                                   uintptr_t second_end) {
        return first_begin < second_end && second_begin < first_end;
    };
    if (ranges_overlap(raw_begin, raw_end, output_begin, output_end) ||
        ranges_overlap(raw_begin, raw_end, output_len_begin, output_len_end) ||
        ranges_overlap(output_begin, output_end, output_len_begin, output_len_end))
        return ExactPathNormalizationResult::InvalidInput;

    u32 written = 0;
    previous_slash = false;
    for (u32 i = 0; i < path_end; i++) {
        const bool slash = raw.ptr[i] == '/';
        if (!slash || !previous_slash) output[written++] = raw.ptr[i];
        previous_slash = slash;
    }
    *output_len = written;
    return ExactPathNormalizationResult::Success;
}

}  // namespace rut
