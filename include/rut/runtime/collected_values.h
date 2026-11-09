#pragma once

#include "rut/runtime/arena.h"
#include "rut/runtime/slice_pool.h"

namespace rut {

// An invocation-owned, write-once collection. Only the compiler's bounded
// collector may append; published language values expose checked reads only.
struct CollectedValues {
    static constexpr u32 kMaxItems = 64;
    static constexpr u32 kMaxStrings = 16;
    static constexpr u32 kMaxElementBytes = 512;
    static constexpr u32 kArenaBudget = 262144;
    SliceArena* arena = nullptr;
    u32 count = 0;
    u32 capacity = 0;
    u32 width = 0;
    u32 string_count = 0;
    u32 string_offsets[kMaxStrings]{};

    static CollectedValues* create(
        SliceArena* arena, u32 width, u32 capacity, const u32* offsets, u32 strings) {
        if (!arena || !arena->backend.pool || !width || width > kMaxElementBytes || !capacity ||
            capacity > kMaxItems || strings > kMaxStrings || (strings && !offsets))
            return nullptr;
        for (u32 i = 0; i < strings; ++i) {
            if (offsets[i] > width || sizeof(Str) > width - offsets[i] || offsets[i] % alignof(Str))
                return nullptr;
            for (u32 j = 0; j < i; ++j)
                if (offsets[i] < offsets[j] + sizeof(Str) && offsets[j] < offsets[i] + sizeof(Str))
                    return nullptr;
        }
        const u32 kBytes = static_cast<u32>(sizeof(CollectedValues)) + width * capacity;
        if (arena->space_used() > kArenaBudget - kBytes ||
            (!arena->current && !arena->init(arena->backend.pool)))
            return nullptr;
        auto* storage = arena->alloc(kBytes);
        if (!storage) return nullptr;
        auto* result = ::new (storage) CollectedValues{};
        result->arena = arena;
        result->width = width;
        result->capacity = capacity;
        result->string_count = strings;
        for (u32 i = 0; i < strings; ++i) result->string_offsets[i] = offsets[i];
        return result;
    }

    bool append(const void* item, u32 size) {
        if (!item || !arena || size != width || count >= capacity) return false;
        auto* destination = reinterpret_cast<u8*>(this + 1) + static_cast<u64>(count) * width;
        __builtin_memcpy(destination, item, width);
        // A returned record must not retain an input/scratch view. Copy string
        // leaves before publishing count; failure never publishes half a record.
        for (u32 i = 0; i < string_count; ++i) {
            Str text{};
            __builtin_memcpy(&text, destination + string_offsets[i], sizeof(text));
            if ((!text.ptr && text.len) || text.len > kArenaBudget ||
                arena->space_used() > kArenaBudget - text.len)
                return false;
            if (text.len) {
                auto* owned = static_cast<char*>(arena->alloc(text.len));
                if (!owned) return false;
                __builtin_memcpy(owned, text.ptr, text.len);
                text.ptr = owned;
            } else {
                text.ptr = "";
            }
            __builtin_memcpy(destination + string_offsets[i], &text, sizeof(text));
        }
        ++count;
        return true;
    }

    const void* get(i32 index, u32 size) const {
        if (index < 0 || static_cast<u32>(index) >= count || size != width) return nullptr;
        return reinterpret_cast<const u8*>(this + 1) + static_cast<u64>(index) * width;
    }
};

}  // namespace rut
