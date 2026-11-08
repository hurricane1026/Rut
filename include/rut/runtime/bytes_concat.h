#pragma once
#include "rut/runtime/arena.h"
#include "rut/runtime/slice_pool.h"

namespace rut {
// Immutable owned append for bounded protocol buffers. No text conversion,
// source mutation or retained source pointer; failures publish no result.
inline const char* concat_bytes(SliceArena* arena, Str left, Str right, i32 limit) {
    if (limit < 1 || limit > 8192 || left.len > static_cast<u32>(limit) ||
        right.len > static_cast<u32>(limit) - left.len || (!left.ptr && left.len) ||
        (!right.ptr && right.len))
        return nullptr;
    const u32 length = left.len + right.len;
    const u32 allocation = length ? length : 1;
    if (!arena || !arena->backend.pool || arena->space_used() > 262144 - allocation ||
        (!arena->current && !arena->init(arena->backend.pool)))
        return nullptr;
    auto* result = static_cast<char*>(arena->alloc(allocation));
    if (!result) return nullptr;
    if (left.len) __builtin_memcpy(result, left.ptr, left.len);
    if (right.len) __builtin_memcpy(result + left.len, right.ptr, right.len);
    return result;
}
}  // namespace rut
