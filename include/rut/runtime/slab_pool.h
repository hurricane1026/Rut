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

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"

#include <sys/mman.h>

namespace rut {

// SlabPool<T, Cap> — fixed-size object pool, O(1) alloc/free.
// Double-free detected via per-slot in_use tracking.

template <typename T, u32 Cap>
struct SlabPool {
    // T must be trivially constructible (mmap zeroes) and destructible (no dtors called).
    // GCC uses __has_trivial_constructor/__has_trivial_destructor;
    // Clang uses __is_trivially_constructible/__is_trivially_destructible.
#if defined(__clang__)
    static_assert(__is_trivially_constructible(T),
                  "SlabPool<T>: T must be trivially constructible");
    static_assert(__is_trivially_destructible(T), "SlabPool<T>: T must be trivially destructible");
#elif defined(__GNUC__)
    static_assert(__has_trivial_constructor(T), "SlabPool<T>: T must be trivially constructible");
    static_assert(__has_trivial_destructor(T), "SlabPool<T>: T must be trivially destructible");
#endif

    T* objects = nullptr;
    u32* free_stack = nullptr;
    u8* in_use_map = nullptr;  // 1 byte per slot: 0=free, 1=allocated
    u32 free_top = 0;
    u64 objects_size = 0;
    u64 stack_size = 0;
    u64 map_size = 0;

    core::Expected<void, Error> init() {
        free_top = Cap;

        objects_size = static_cast<u64>(Cap) * sizeof(T);
        void* obj_mem =
            mmap(nullptr, objects_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (obj_mem == MAP_FAILED) {
            free_top = 0;
            return core::make_unexpected(Error::from_errno(Error::Source::SlabPool));
        }
        objects = static_cast<T*>(obj_mem);

        stack_size = static_cast<u64>(Cap) * sizeof(u32);
        void* stk_mem =
            mmap(nullptr, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stk_mem == MAP_FAILED) {
            munmap(objects, objects_size);
            objects = nullptr;
            free_top = 0;
            return core::make_unexpected(Error::from_errno(Error::Source::SlabPool));
        }
        free_stack = static_cast<u32*>(stk_mem);

        map_size = static_cast<u64>(Cap);
        void* map_mem =
            mmap(nullptr, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map_mem == MAP_FAILED) {
            auto err = Error::from_errno(Error::Source::SlabPool);
            munmap(free_stack, stack_size);
            free_stack = nullptr;
            munmap(objects, objects_size);
            objects = nullptr;
            free_top = 0;
            return core::make_unexpected(err);
        }
        in_use_map = static_cast<u8*>(map_mem);  // mmap zeroes = all free

        for (u32 i = 0; i < Cap; i++) free_stack[i] = i;
        return {};
    }

    T* alloc() {
        if (free_top == 0) return nullptr;
        u32 idx = free_stack[--free_top];
        if (in_use_map) in_use_map[idx] = 1;
        return &objects[idx];
    }

    T* alloc_with_id(u32& out_idx) {
        if (free_top == 0) {
            out_idx = 0;
            return nullptr;
        }
        out_idx = free_stack[--free_top];
        if (in_use_map) in_use_map[out_idx] = 1;
        return &objects[out_idx];
    }

    void free(u32 idx) {
        if (idx >= Cap || free_top >= Cap || !free_stack) return;
        if (in_use_map && !in_use_map[idx]) return;  // double-free
        if (in_use_map) in_use_map[idx] = 0;
        free_stack[free_top++] = idx;
    }

    void free(T* obj) {
        if (!obj || !objects || obj < objects || obj >= objects + Cap) return;
        u32 idx = static_cast<u32>(obj - objects);
        if (free_top >= Cap) return;
        if (in_use_map && !in_use_map[idx]) return;  // double-free
        if (in_use_map) in_use_map[idx] = 0;
        free_stack[free_top++] = idx;
    }

    T& operator[](u32 idx) { return objects[idx]; }
    const T& operator[](u32 idx) const { return objects[idx]; }
    u32 index_of(const T* obj) const { return static_cast<u32>(obj - objects); }

    u32 capacity() const { return Cap; }
    u32 available() const { return free_top; }
    u32 in_use() const { return Cap - free_top; }

    void destroy() {
        if (in_use_map) {
            munmap(in_use_map, map_size);
            in_use_map = nullptr;
        }
        if (free_stack) {
            munmap(free_stack, stack_size);
            free_stack = nullptr;
        }
        if (objects) {
            munmap(objects, objects_size);
            objects = nullptr;
        }
        free_top = 0;
    }
};

}  // namespace rut
