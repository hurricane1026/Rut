/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

// Placement new — declaration only; definition lives in src/placement_new.cc.
#ifndef RUE_PLACEMENT_NEW_DECLARED
#define RUE_PLACEMENT_NEW_DECLARED
void* operator new(decltype(sizeof(0)), void* p) noexcept;
#endif

namespace rut {

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;
using f32 = float;
using f64 = double;

// Non-owning string view (no stdlib dependency)
struct Str {
    const char* ptr;
    u32 len;

    [[nodiscard]] bool eq(Str other) const {
        if (len != other.len) return false;
        for (u32 i = 0; i < len; i++) {
            if (ptr[i] != other.ptr[i]) return false;
        }
        return true;
    }

    [[nodiscard]] bool empty() const { return len == 0; }

    [[nodiscard]] Str slice(u32 start, u32 end) const { return {ptr + start, end - start}; }
};

template <size_t N>
constexpr Str lit_str(const char (&s)[N]) {
    return {s, static_cast<u32>(N - 1)};
}

// Fixed-capacity vector, no heap allocation
template <typename T, u32 Cap>
struct FixedVec {
    T data[Cap];
    u32 len = 0;

    bool push(const T& val) {
        if (len >= Cap) return false;
        data[len++] = val;
        return true;
    }
    T& operator[](u32 i) { return data[i]; }
    const T& operator[](u32 i) const { return data[i]; }
    T* begin() { return data; }
    T* end() { return data + len; }
    [[nodiscard]] bool full() const { return len >= Cap; }
    [[nodiscard]] bool empty() const { return len == 0; }
};

// Intrusive linked list node
struct ListNode {
    ListNode* prev;
    ListNode* next;

    void init() {
        prev = this;
        next = this;
    }

    void remove() {
        prev->next = next;
        next->prev = prev;
    }

    void insert_after(ListNode* node) {
        node->prev = this;
        node->next = next;
        next->prev = node;
        next = node;
    }

    [[nodiscard]] bool empty() const { return next == this; }
};

}  // namespace rut
