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

// SlicePool — fixed-size (16KB) memory slice allocator with lazy commit.
//
// Per-shard pool of 16KB slices for network I/O buffers. Connections borrow
// slices on demand (recv/send), return them when done. Idle connections hold
// 0 slices → zero memory overhead at C100K.
//
// Memory strategy: reserve full VA range upfront (PROT_NONE — no physical
// pages), then mprotect slices to PROT_READ|PROT_WRITE on first use. This
// gives O(1) alloc, stable base pointer (no mremap), and physical memory
// proportional to active connections rather than max capacity.
//
// On Linux, PROT_NONE pages consume virtual address space but zero RSS and
// don't count against overcommit. VA is abundant on 64-bit (256TB).
//
// Usage:
//   SlicePool pool;
//   auto rc = pool.init(32768);  // max 32768 slices, ~0 RSS until used
//   u8* buf = pool.alloc();      // commits pages on first use
//   pool.free(buf);
//   pool.destroy();

struct SlicePool {
    static constexpr u32 kSliceSize = 16384;  // 16KB per slice

    u8* base = nullptr;         // mmap'd region: max_count * kSliceSize bytes
    u32* free_stack = nullptr;  // mmap'd: free slice indices
    u8* in_use_map = nullptr;   // mmap'd: 1 byte per slice (0=free, 1=in-use)
    u32 free_top = 0;
    u32 count = 0;       // currently committed slices
    u32 max_count = 0;   // maximum slices (VA reserved at init)
    u64 base_size = 0;   // size of mmap'd base region
    u64 stack_size = 0;  // size of mmap'd free_stack region
    u64 map_size = 0;    // size of mmap'd in_use_map

    // Number of slices to commit per growth step.
    // 256 slices × 16KB = 4MB per step — small enough to avoid waste,
    // large enough to amortize mprotect syscall overhead.
    static constexpr u32 kGrowStep = 256;

    // Initialize pool with max capacity `n`. Reserves VA but only commits
    // `prealloc` slices upfront (0 = fully lazy). Free-stack and in-use
    // map (small: n * 4 + n bytes) are committed immediately.
    core::Expected<void, Error> init(u32 n, u32 prealloc = 0) {
        max_count = n;
        count = 0;
        free_top = 0;

        // Reserve VA for slice data — PROT_NONE, no physical pages
        base_size = static_cast<u64>(n) * kSliceSize;
        void* data_mem = mmap(nullptr, base_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (data_mem == MAP_FAILED) {
            return core::make_unexpected(Error::from_errno(Error::Source::SlicePool));
        }
        base = static_cast<u8*>(data_mem);

        // Commit free stack (small: n * 4 bytes ≈ 128KB for 32K slices)
        stack_size = static_cast<u64>(n) * sizeof(u32);
        void* stack_mem =
            mmap(nullptr, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack_mem == MAP_FAILED) {
            munmap(base, base_size);
            base = nullptr;
            return core::make_unexpected(Error::from_errno(Error::Source::SlicePool));
        }
        free_stack = static_cast<u32*>(stack_mem);

        // Commit in-use tracking map (n bytes ≈ 32KB for 32K slices)
        map_size = static_cast<u64>(n);
        void* map_mem =
            mmap(nullptr, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map_mem == MAP_FAILED) {
            auto err = Error::from_errno(Error::Source::SlicePool);
            munmap(free_stack, stack_size);
            free_stack = nullptr;
            munmap(base, base_size);
            base = nullptr;
            return core::make_unexpected(err);
        }
        in_use_map = static_cast<u8*>(map_mem);

        // Pre-commit requested slices (0 = fully lazy).
        if (prealloc > 0) {
            if (prealloc > n) prealloc = n;
            // Round up to kGrowStep for mprotect alignment.
            u32 steps = (prealloc + kGrowStep - 1) / kGrowStep;
            for (u32 s = 0; s < steps && count < max_count; s++) {
                if (!grow()) {
                    destroy();
                    return core::make_unexpected(Error::from_errno(Error::Source::SlicePool));
                }
            }
        }

        return {};
    }

    // Allocate one 16KB slice. Grows committed region if empty.
    // Returns pointer to slice, or nullptr if at max capacity.
    u8* alloc() {
        if (free_top == 0 && !grow()) return nullptr;
        u32 idx = free_stack[--free_top];
        if (in_use_map) in_use_map[idx] = 1;
        return base + static_cast<u64>(idx) * kSliceSize;
    }

    // Free a slice back to the pool. ptr must have been returned by alloc().
    // Uses MADV_DONTNEED to release physical pages — RSS drops after traffic
    // spikes. Pages are faulted back (zero-filled) on next alloc.
    void free(u8* ptr) {
        if (!ptr || !base || !free_stack || count == 0) return;
        if (ptr < base || ptr >= base + static_cast<u64>(count) * kSliceSize) return;
        u64 offset = static_cast<u64>(ptr - base);
        if (offset % kSliceSize != 0) return;  // not slice-aligned
        if (free_top >= max_count) return;     // overflow guard
        u32 idx = static_cast<u32>(offset / kSliceSize);
        if (in_use_map && !in_use_map[idx]) return;  // double-free detection
        if (in_use_map) in_use_map[idx] = 0;
        madvise(ptr, kSliceSize, MADV_DONTNEED);
        free_stack[free_top++] = idx;
    }

    // Number of available (free) slices.
    u32 available() const { return free_top; }

    // Number of in-use slices.
    u32 in_use() const { return count - free_top; }

    // Release all mmap'd memory.
    void destroy() {
        if (in_use_map) {
            munmap(in_use_map, map_size);
            in_use_map = nullptr;
        }
        if (free_stack) {
            munmap(free_stack, stack_size);
            free_stack = nullptr;
        }
        if (base) {
            munmap(base, base_size);
            base = nullptr;
        }
        free_top = 0;
        count = 0;
        max_count = 0;
    }

private:
    // Commit the next batch of slices (mprotect PROT_NONE → PROT_READ|PROT_WRITE).
    // Base pointer is stable — no mremap, no pointer fixup needed.
    bool grow() {
        if (count >= max_count) return false;

        u32 step = kGrowStep;
        if (count + step > max_count) step = max_count - count;

        // mprotect the next chunk of the reserved VA region
        u8* chunk = base + static_cast<u64>(count) * kSliceSize;
        u64 chunk_size = static_cast<u64>(step) * kSliceSize;
        if (mprotect(chunk, chunk_size, PROT_READ | PROT_WRITE) != 0) return false;

        // Add new slices to free stack
        for (u32 i = count; i < count + step; i++) {
            free_stack[free_top++] = i;
        }
        count += step;
        return true;
    }
};

}  // namespace rut
