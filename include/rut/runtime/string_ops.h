#pragma once

#include "rut/runtime/arena.h"

namespace rut {
inline constexpr u32 kStringInputLimit = 8192;
inline constexpr u32 kStringOutputLimit = 16384;
inline constexpr u32 kStringNeedleLimit = 256;
inline constexpr u32 kStringArenaBudget = 262144;

// ASCII only; all other bytes, including NUL, are preserved.
inline Str trim_ascii_string(Str text) {
    if (!text.ptr) return {};
    const auto space = [](u8 c) { return c == 32 || (c >= 9 && c <= 13); };
    u32 begin = 0;
    u32 end = text.len;
    while (begin < end && space(static_cast<u8>(text.ptr[begin]))) ++begin;
    while (end > begin && space(static_cast<u8>(text.ptr[end - 1]))) --end;
    return {text.ptr + begin, end - begin};
}

// Modes 0/1: ASCII upper/lower. Mode 2: all nonoverlapping literal matches.
// Failure publishes no partial output. Empty needles are rejected.
inline bool transform_string(
    SliceArena* arena, Str text, Str needle, Str replacement, u32 mode, Str* output) {
    *output = {};
    if (!arena || !arena->backend.pool || mode > 2 || text.len > kStringInputLimit ||
        (text.len && !text.ptr) || replacement.len > kStringInputLimit ||
        (replacement.len && !replacement.ptr) ||
        (mode == 2 && (!needle.ptr || !needle.len || needle.len > kStringNeedleLimit)))
        return false;
    u16 prefix[kStringNeedleLimit]{};
    if (mode == 2) {
        for (u32 i = 1, j = 0; i < needle.len; ++i) {
            while (j && needle.ptr[i] != needle.ptr[j]) j = prefix[j - 1];
            if (needle.ptr[i] == needle.ptr[j]) ++j;
            prefix[i] = static_cast<u16>(j);
        }
    }
    // Both passes use KMP: linear work even for adversarial repetitive input.
    const auto scan = [&](auto&& match) {
        for (u32 i = 0, j = 0; i < text.len; ++i) {
            while (j && text.ptr[i] != needle.ptr[j]) j = prefix[j - 1];
            if (text.ptr[i] == needle.ptr[j]) ++j;
            if (j == needle.len) {
                match(i + 1 - needle.len);
                j = 0;
            }
        }
    };
    u32 count = 0;
    if (mode == 2) scan([&](u32) { ++count; });
    const u64 size = static_cast<u64>(text.len) - static_cast<u64>(count) * needle.len +
                     static_cast<u64>(count) * replacement.len;
    if (size > kStringOutputLimit || arena->space_used() > kStringArenaBudget - (size ? size : 1) ||
        (!arena->current && !arena->init(arena->backend.pool)))
        return false;
    auto* data = static_cast<char*>(arena->alloc(size ? size : 1));
    if (!data) return false;
    u32 written = 0;
    if (mode < 2) {
        for (u32 i = 0; i < text.len; ++i) {
            const u8 c = static_cast<u8>(text.ptr[i]);
            data[i] = static_cast<char>(mode == 0 && c >= 'a' && c <= 'z'   ? c - 32
                                        : mode == 1 && c >= 'A' && c <= 'Z' ? c + 32
                                                                            : c);
        }
    } else {
        u32 copied = 0;
        scan([&](u32 start) {
            const u32 length = start - copied;
            if (length) __builtin_memcpy(data + written, text.ptr + copied, length);
            written += length;
            if (replacement.len) __builtin_memcpy(data + written, replacement.ptr, replacement.len);
            written += replacement.len;
            copied = start + needle.len;
        });
        if (text.len > copied)
            __builtin_memcpy(data + written, text.ptr + copied, text.len - copied);
    }
    *output = {data, static_cast<u32>(size)};
    return true;
}
}  // namespace rut
