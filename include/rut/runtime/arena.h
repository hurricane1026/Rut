#pragma once

#include "core/expected.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"

#include <errno.h>
#include <sys/mman.h>  // mmap, munmap

namespace rut {

// Forward declaration — only needed by SlicePoolBackend.
struct SlicePool;

// ── Block Backends ─────────────────────────────────────────────────
// Arena is parameterized on a backend that controls where blocks come
// from. Two backends:
//   MmapBackend      — mmap/munmap, variable-size blocks. For compiler.
//   SlicePoolBackend — borrows 16KB slices from SlicePool. For runtime hot path.

struct MmapBackend {
    u64 default_block_size = 4096;

    core::Expected<void, Error> init(u64 block_size) {
        default_block_size = block_size < 256 ? 256 : block_size;
        return {};
    }

    // Acquire a block of at least `needed` bytes. Returns raw ptr + actual size.
    // The caller embeds a Block header at the start.
    [[nodiscard]] u8* acquire(u64 needed, u64* out_size) {
        u64 size = default_block_size > needed ? default_block_size : needed;
        // Page-align
        if (size > static_cast<u64>(-1) - 4095) return nullptr;
        u64 aligned = 0;
        if (__builtin_add_overflow(size, static_cast<u64>(4095), &aligned)) return nullptr;
        size = aligned & ~static_cast<u64>(4095);
        void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return nullptr;
        *out_size = size;
        return static_cast<u8*>(p);
    }

    void release(u8* ptr, u64 size) { munmap(ptr, size); }
};

struct SlicePoolBackend {
    SlicePool* pool = nullptr;

    core::Expected<void, Error> init(SlicePool* p) {
        pool = p;
        return {};
    }

    // Acquire a 16KB slice from the pool. `needed` must fit in one slice.
    u8* acquire(u64 needed, u64* out_size);
    void release(u8* ptr, u64 size);
};

// ── Arena<Backend> ─────────────────────────────────────────────────
// Bump allocator with block chaining. Zero stdlib, no malloc, no new.
//
// Pure bump allocation. No destructors, no cleanup, no ownership tracking.
// Objects allocated from Arena must be trivially destructible, or the caller
// is responsible for calling destructors manually before reset/destroy.
//
// Block memory comes from the Backend (mmap or SlicePool).
//
// Usage (runtime):
//   Arena<SlicePoolBackend> arena;
//   arena.init(&shard_pool);
//   auto* hdr = arena.alloc_t<Header>();
//   arena.reset();  // returns extra slices to pool
//
// Usage (compiler):
//   Arena<MmapBackend> arena;
//   arena.init(4096);
//   auto* node = arena.alloc_t<AstNode>();
//   arena.destroy();  // munmap all blocks

template <typename Backend>
struct Arena {
    struct Block {
        Block* prev;
        // Published blocks satisfy kHeaderSize <= size and 0 <= used <= size - kHeaderSize.
        i64 size;  // total block size (including this header)
        i64 used;  // payload bytes reserved so far, also the next allocation offset

        static constexpr i64 kHeaderSize = [] {
            constexpr i64 kBlockSize = sizeof(Block);
            static_assert(kBlockSize <= UINT32_MAX);
            return (kBlockSize + 15) / 16 * 16;
        }();
        u8* data() { return reinterpret_cast<u8*>(this) + kHeaderSize; }
        i64 capacity() const { return size - kHeaderSize; }
        i64 remaining() const { return capacity() - used; }
    };

    Block* current = nullptr;
    Backend backend{};
    u64 total_allocated = 0;

    // Initialize with backend-specific args (forwarded to Backend::init).
    template <typename... Args>
    core::Expected<void, Error> init(Args&&... args) {
        total_allocated = 0;
        current = nullptr;
        auto r = backend.init(static_cast<Args&&>(args)...);
        if (!r) return r;
        current = alloc_block(Block::kHeaderSize, nullptr);
        if (!current) return core::make_unexpected(Error::from_errno(Error::Source::Arena));
        return {};
    }

    // Bump allocate, 8-byte aligned.
    [[nodiscard]] void* alloc(u64 requested_size) {
        if (!current) return nullptr;
        constexpr i64 kAlignment = 8;
        constexpr auto kAlignmentPadding =
            range_int<kAlignment - 1, kAlignment>::constant<kAlignment - 1>();
        range_int<0, kI64ExclusiveEnd - (kAlignment - 1)> request;
        if (!decltype(request)::try_from_u64(requested_size, &request)) return nullptr;
        const auto padded = request + kAlignmentPadding;
        const i64 aligned_size = padded.value() / kAlignment * kAlignment;
        if (aligned_size <= current->remaining()) {
            void* p = current->data() + current->used;
            current->used += aligned_size;
            return p;
        }
        i64 needed;
        if (__builtin_add_overflow(Block::kHeaderSize, aligned_size, &needed)) return nullptr;
        // alloc_block releases undersized blocks before returning, so any returned block
        // has at least aligned_size bytes of payload.
        Block* b = alloc_block(needed, current);
        if (!b) return nullptr;
        b->used = aligned_size;
        current = b;
        return b->data();
    }

    // Typed bump alloc + placement new.
    template <typename T, typename... Args>
    [[nodiscard]] T* alloc_t(Args&&... args) {
        void* p = alloc(sizeof(T));
        if (!p) return nullptr;
        return ::new (p) T(static_cast<Args&&>(args)...);
    }

    // Array bump alloc, value-initialized via placement new.
    template <typename T>
    [[nodiscard]] T* alloc_array(u32 count) {
        T* a = nullptr;
        // NOLINTNEXTLINE(bugprone-sizeof-expression)
        if (count > 0 && sizeof(a[0]) > static_cast<u64>(-1) / count) return nullptr;
        // NOLINTNEXTLINE(bugprone-sizeof-expression)
        void* p = alloc(static_cast<u64>(sizeof(a[0])) * count);
        if (!p) return nullptr;
        a = static_cast<T*>(p);
        for (u32 i = 0; i < count; i++) {
            // NOLINTNEXTLINE(bugprone-multi-level-implicit-pointer-conversion)
            void* slot = static_cast<void*>(a + static_cast<i64>(i));
            ::new (slot) T{};
        }
        return a;
    }

    // Free all blocks except first, reset pointer. O(blocks).
    void reset() {
        if (!current) return;
        while (current->prev) {
            Block* prev = current->prev;
            backend.release(reinterpret_cast<u8*>(current), static_cast<u64>(current->size));
            current = prev;
        }
        current->used = 0;
        // Only the original block remains. Its validated size is the total.
        total_allocated = static_cast<u64>(current->size);
    }

    // Free everything.
    void destroy() {
        while (current) {
            Block* prev = current->prev;
            backend.release(reinterpret_cast<u8*>(current), static_cast<u64>(current->size));
            current = prev;
        }
        current = nullptr;
        total_allocated = 0;
    }

    u64 space_used() const {
        // Each block has 0 <= used <= size. Every partial sum is bounded by
        // total_allocated, which alloc_block updates with checked addition.
        __int128_t used = 0;
        for (const Block* b = current; b; b = b->prev) used += b->used;
        return static_cast<u64>(used);
    }

    u64 space_allocated() const { return total_allocated; }

private:
    [[nodiscard]] Block* alloc_block(i64 needed, Block* prev) {
        u64 actual_size = 0;
        u8* mem = backend.acquire(static_cast<u64>(needed), &actual_size);
        if (!mem) return nullptr;
        // Every block embeds its header before the payload. A backend that
        // reports a short block or a size outside the signed offset range
        // cannot be used.
        range_int<0> block_size;
        if (!decltype(block_size)::try_from_u64(actual_size, &block_size) ||
            block_size.value() < needed) {
            backend.release(mem, actual_size);
            return nullptr;
        }
        auto* b = reinterpret_cast<Block*>(mem);
        b->prev = prev;
        b->size = block_size.value();
        b->used = 0;
        u64 next_total = 0;
        if (__builtin_add_overflow(total_allocated, actual_size, &next_total)) {
            backend.release(mem, actual_size);
            return nullptr;
        }
        total_allocated = next_total;
        return b;
    }
};

// ── Type Aliases ───────────────────────────────────────────────────
// MmapArena  — compiler/offline use (mmap-backed, variable-size blocks)
// SliceArena — runtime hot path (SlicePool-backed, 16KB fixed blocks)

using MmapArena = Arena<MmapBackend>;
using SliceArena = Arena<SlicePoolBackend>;

}  // namespace rut
