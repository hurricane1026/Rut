#pragma once

#include "rut/common/types.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/collected_values.h"

namespace rut {

// Byte-exact, non-overlapping delimiter splitting. Validate the entire result
// before allocating; never expose a truncated collection. Published fields own
// their bytes until the invocation arena is reset.
inline CollectedValues* split_string(SliceArena* arena, Str input, Str separator) {
    constexpr u32 kMaxInput = 8192;
    constexpr u32 kMaxSeparator = 256;
    if ((!input.ptr && input.len) || input.len > kMaxInput || !separator.ptr || !separator.len ||
        separator.len > kMaxSeparator)
        return nullptr;
    const char* data = input.ptr ? input.ptr : "";
    // KMP keeps repetitive subjects and delimiters linear in their byte lengths.
    u16 prefixes[kMaxSeparator]{};
    for (u32 i = 1, matched = 0; i < separator.len; ++i) {
        while (matched && separator.ptr[i] != separator.ptr[matched])
            matched = prefixes[matched - 1];
        if (separator.ptr[i] == separator.ptr[matched]) ++matched;
        prefixes[i] = static_cast<u16>(matched);
    }
    FixedVec<Str, CollectedValues::kMaxItems> fields;
    u32 start = 0;
    u32 matched = 0;
    for (u32 i = 0; i < input.len; ++i) {
        while (matched && data[i] != separator.ptr[matched]) matched = prefixes[matched - 1];
        if (data[i] == separator.ptr[matched]) ++matched;
        if (matched != separator.len) continue;
        const u32 kEnd = i + 1 - separator.len;
        if (!fields.push({data + start, kEnd - start})) return nullptr;
        start = i + 1;
        matched = 0;
    }
    if (!fields.push({data + start, input.len - start})) return nullptr;
    constexpr u32 kOffset = 0;
    auto* result = CollectedValues::create(arena, sizeof(Str), fields.len, &kOffset, 1);
    if (!result) return nullptr;
    for (u32 i = 0; i < fields.len; ++i)
        if (!result->append(&fields[i], sizeof(Str))) return nullptr;
    return result;
}

}  // namespace rut
