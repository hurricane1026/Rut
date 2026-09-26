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
// 0 slices; the pool retains only a bounded idle working set.
//
// Memory strategy: reserve full VA range upfront (PROT_NONE — no physical
// pages), then mprotect slices to PROT_READ|PROT_WRITE on first use. This
// gives O(1) alloc, stable base pointer (no mremap), and physical memory
// proportional to active connections plus a bounded cache of returned slices.
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
    static constexpr u32 kSliceSize = 16384;      // 16KB per slice
    static constexpr u32 kMaxCachedSlices = 256;  // At most 4 MiB idle retention per pool.
    // A buffered response keeps its header/prefix slice separately and stores
    // the remaining bounded body in whole SlicePool nodes. Keep this reserve
    // with the pool sizing contract so every backend accounts for it equally.
    static constexpr u32 kMaxBufferedResponseBody = 1u << 20;
    static constexpr u32 kResponseBodyPayload = kSliceSize - sizeof(void*) - 2 * sizeof(u32);
    static constexpr u32 kMaxBufferedResponseSlices =
        (kMaxBufferedResponseBody + kResponseBodyPayload - 1) / kResponseBodyPayload;
    static constexpr u32 kOrdinarySlicesPerConnection = 6;
    static constexpr u32 kSlicesPerConnection =
        kOrdinarySlicesPerConnection + kMaxBufferedResponseSlices;

    // Bulk relay buffers: a small fixed set of large buffers a connection
    // borrows only while it relays a large proxied body, so the body moves in
    // 256 KiB steps. Separate VA region, faulted in on first use; free()
    // routes a bulk pointer here by address, so release sites need not know
    // which kind they hold. Exhaustion is not an error: callers keep slices.
    static constexpr u32 kBulkSliceSize = 256 * 1024;
    static constexpr u32 kBulkSlices = 64;  // 16 MiB VA per pool
    static_assert(kBulkSlices <= 64, "bulk in-use tracking is one u64 bitmap");

    static constexpr u32 capacity_for_connections(u32 connections) {
        constexpr u32 kMaxU32 = 0xFFFFFFFFu;
        if (connections > kMaxU32 / kSlicesPerConnection) return 0;
        return connections * kSlicesPerConnection;
    }

    u8* base = nullptr;         // mmap'd region: max_count * kSliceSize bytes
    u32* free_stack = nullptr;  // mmap'd: free slice indices
    u8* in_use_map = nullptr;   // mmap'd: 1 byte per slice (0=free, 1=in-use)
    u32 free_top = 0;
    // Cached indices occupy the top cached_count entries of free_stack.
    // Untouched/discarded indices remain below them, so reuse prefers hot pages.
    u32 cached_count = 0;
    u32 cache_limit = 0;
    u32 count = 0;       // currently committed slices
    u32 max_count = 0;   // maximum slices (VA reserved at init)
    u64 base_size = 0;   // size of mmap'd base region
    u64 stack_size = 0;  // size of mmap'd free_stack region
    u64 map_size = 0;    // size of mmap'd in_use_map

    // Mapped on the first alloc_bulk(): pools that never relay a large body
    // (and init's allocation sequence) are unaffected. A failed map is sticky.
    u8* bulk_base = nullptr;  // kBulkSlices * kBulkSliceSize bytes, or null
    u32 bulk_free[kBulkSlices] = {};
    u32 bulk_free_top = 0;
    u64 bulk_in_use = 0;  // bit i set while bulk slice i is borrowed
    bool bulk_map_failed = false;

    // Number of slices to commit per growth step.
    // 256 slices × 16KB = 4MB per step — small enough to avoid waste,
    // large enough to amortize mprotect syscall overhead.
    static constexpr u32 kGrowStep = 256;

    // Initialize pool with max capacity `n`. Reserves VA but only commits
    // `prealloc` slices upfront (0 = fully lazy). Free-stack and in-use
    // map (small: n * 4 + n bytes) are committed immediately.
    // cache_slices may lower/disable the cache; the hard bound is unchanged.
    core::Expected<void, Error> init(u32 n, u32 prealloc = 0, u32 cache_slices = kMaxCachedSlices) {
        cache_limit = cache_slices < kMaxCachedSlices ? cache_slices : kMaxCachedSlices;
        if (cache_limit > n) cache_limit = n;
        cached_count = 0;
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
        u8* ptr = base + static_cast<u64>(idx) * kSliceSize;
        if (cached_count != 0) --cached_count;
        if (in_use_map) in_use_map[idx] = 1;
        return ptr;
    }

    // Borrow one bulk relay buffer, or null when none is available.
    u8* alloc_bulk() {
        if (bulk_base == nullptr && !map_bulk()) return nullptr;
        if (bulk_free_top == 0) return nullptr;
        const u32 idx = bulk_free[--bulk_free_top];
        bulk_in_use |= u64{1} << idx;
        return bulk_base + static_cast<u64>(idx) * kBulkSliceSize;
    }

    [[nodiscard]] bool is_bulk(const u8* ptr) const {
        return bulk_base != nullptr && ptr >= bulk_base &&
               ptr < bulk_base + static_cast<u64>(kBulkSlices) * kBulkSliceSize;
    }

    // Byte capacity of a buffer handed out by alloc() or alloc_bulk().
    [[nodiscard]] u32 capacity_of(const u8* ptr) const {
        return is_bulk(ptr) ? kBulkSliceSize : kSliceSize;
    }

    u32 bulk_available() const {
        if (bulk_base != nullptr) return bulk_free_top;
        return bulk_map_failed ? 0 : kBulkSlices;
    }

    // Free a slice back to the pool. ptr must have been returned by alloc()
    // or alloc_bulk(). Retain a bounded working set; discard excess pages after
    // traffic spikes. Only call once all asynchronous users have retired.
    void free(u8* ptr) {
        if (is_bulk(ptr)) {
            free_bulk(ptr, kBulkSliceSize);
            return;
        }
        if (!ptr || !base || !free_stack || count == 0) return;
        if (ptr < base || ptr >= base + static_cast<u64>(count) * kSliceSize) return;
        u64 offset = static_cast<u64>(ptr - base);
        if (offset % kSliceSize != 0) return;  // not slice-aligned
        if (free_top >= max_count) return;     // overflow guard
        u32 idx = static_cast<u32>(offset / kSliceSize);
        if (in_use_map && !in_use_map[idx]) return;  // double-free detection
        if (in_use_map) in_use_map[idx] = 0;
        if (cached_count < cache_limit) {
            // Preserve zero-filled reuse and clear the previous owner's bytes
            // even while the slice is idle, including bytes beyond buffer length.
            __builtin_memset(ptr, 0, kSliceSize);
            free_stack[free_top++] = idx;
            ++cached_count;
            return;
        }
        // A discarded slice must not expose the previous owner's bytes either.
#ifdef __linux__
        // Private anonymous pages read back zero-filled after MADV_DONTNEED.
        if (madvise(ptr, kSliceSize, MADV_DONTNEED) != 0) __builtin_memset(ptr, 0, kSliceSize);
#else
        // Elsewhere (macOS) MADV_DONTNEED may keep the page contents.
        __builtin_memset(ptr, 0, kSliceSize);
#endif
        // Insert below the cached suffix in O(1). Pushing discarded slices on
        // top would strand the cache after a burst and keep faulting cold pages.
        const u32 boundary = free_top - cached_count;
        if (cached_count != 0) free_stack[free_top] = free_stack[boundary];
        free_stack[boundary] = idx;
        ++free_top;
    }

    // free() for a caller that knows nothing past the first `written` bytes
    // was ever written since the buffer was handed out. A bulk buffer then
    // re-zeroes only that prefix (the rest is still zero), which keeps a
    // mostly-empty 256 KiB node from costing a full-buffer memset. Slices
    // keep free()'s behavior.
    void free_written(u8* ptr, u32 written) {
        if (is_bulk(ptr)) {
            free_bulk(ptr, written < kBulkSliceSize ? written : kBulkSliceSize);
            return;
        }
        free(ptr);
    }

    // Number of available (free) slices.
    u32 available() const { return free_top; }

    // Number of in-use slices.
    u32 in_use() const { return count - free_top; }

    // Release all mmap'd memory.
    void destroy() {
        if (bulk_base) {
            munmap(bulk_base, static_cast<u64>(kBulkSlices) * kBulkSliceSize);
            bulk_base = nullptr;
        }
        bulk_free_top = 0;
        bulk_in_use = 0;
        bulk_map_failed = false;
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
        cached_count = 0;
        cache_limit = 0;
        count = 0;
        max_count = 0;
    }

private:
    bool map_bulk() {
        if (bulk_map_failed || base == nullptr) return false;
        void* mem = mmap(nullptr,
                         static_cast<u64>(kBulkSlices) * kBulkSliceSize,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1,
                         0);
        if (mem == MAP_FAILED) {
            bulk_map_failed = true;
            return false;
        }
        bulk_base = static_cast<u8*>(mem);
        bulk_in_use = 0;
        bulk_free_top = 0;
        for (u32 i = kBulkSlices; i > 0; --i) bulk_free[bulk_free_top++] = i - 1;
        return true;
    }

    void free_bulk(u8* ptr, u32 dirty) {
        const u64 offset = static_cast<u64>(ptr - bulk_base);
        if (offset % kBulkSliceSize != 0) return;  // not buffer-aligned
        const u32 idx = static_cast<u32>(offset / kBulkSliceSize);
        const u64 bit = u64{1} << idx;
        if ((bulk_in_use & bit) == 0) return;  // double-free detection
        bulk_in_use &= ~bit;
        // Like slices, a returned buffer must not expose its owner's bytes.
        // Zero in place: the set is small and hot, and MADV_DONTNEED would make
        // every reuse fault its pages back in. Bytes past `dirty` are still
        // zero from the previous return (or the fresh mapping).
        __builtin_memset(ptr, 0, dirty);
        bulk_free[bulk_free_top++] = idx;
    }

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
