#pragma once

#include "core/expected.h"
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
    u8* acquire(u64 needed, u64* out_size) {
        u64 size = default_block_size > needed ? default_block_size : needed;
        // Page-align
        if (size > static_cast<u64>(-1) - 4095) return nullptr;
        size = (size + 4095) & ~static_cast<u64>(4095);
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
        u64 size;  // total block size (including this header)
        u64 used;  // bytes allocated after header

        static constexpr u64 kHeaderSize = (sizeof(Block) + 15) & ~u64(15);
        u8* data() { return reinterpret_cast<u8*>(this) + kHeaderSize; }
        const u8* data() const { return reinterpret_cast<const u8*>(this) + kHeaderSize; }
        u64 capacity() const { return size - kHeaderSize; }
        u64 remaining() const { return capacity() - used; }
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
    void* alloc(u64 size) {
        if (!current) return nullptr;
        if (size > static_cast<u64>(-1) - 7) return nullptr;
        size = (size + 7) & ~static_cast<u64>(7);
        if (current->remaining() >= size) {
            void* p = current->data() + current->used;
            current->used += size;
            return p;
        }
        if (size > static_cast<u64>(-1) - Block::kHeaderSize) return nullptr;
        Block* b = alloc_block(Block::kHeaderSize + size, current);
        if (!b || b->capacity() < size) {
            if (b) backend.release(reinterpret_cast<u8*>(b), b->size);
            return nullptr;
        }
        current = b;
        void* p = current->data() + current->used;
        current->used += size;
        return p;
    }

    // Typed bump alloc + placement new.
    template <typename T, typename... Args>
    T* alloc_t(Args&&... args) {
        void* p = alloc(sizeof(T));
        if (!p) return nullptr;
        return ::new (p) T(static_cast<Args&&>(args)...);
    }

    // Array bump alloc, value-initialized via placement new.
    template <typename T>
    T* alloc_array(u32 count) {
        T* a = nullptr;
        // NOLINTNEXTLINE(bugprone-sizeof-expression)
        if (count > 0 && sizeof(a[0]) > static_cast<u64>(-1) / count) return nullptr;
        // NOLINTNEXTLINE(bugprone-sizeof-expression)
        void* p = alloc(static_cast<u64>(sizeof(a[0])) * count);
        if (!p) return nullptr;
        a = static_cast<T*>(p);
        for (u32 i = 0; i < count; i++) {
            // NOLINTNEXTLINE(bugprone-multi-level-implicit-pointer-conversion)
            void* slot = static_cast<void*>(a + i);
            ::new (slot) T{};
        }
        return a;
    }

    // Free all blocks except first, reset pointer. O(blocks).
    void reset() {
        if (!current) return;
        while (current->prev) {
            Block* prev = current->prev;
            u64 sz = current->size;
            backend.release(reinterpret_cast<u8*>(current), sz);
            total_allocated -= sz;
            current = prev;
        }
        current->used = 0;
    }

    // Free everything.
    void destroy() {
        while (current) {
            Block* prev = current->prev;
            backend.release(reinterpret_cast<u8*>(current), current->size);
            current = prev;
        }
        current = nullptr;
        total_allocated = 0;
    }

    u64 space_used() const {
        u64 t = 0;
        for (Block* b = current; b; b = b->prev) t += b->used;
        return t;
    }

    u64 space_allocated() const { return total_allocated; }

    bool contains_range(const void* ptr, u64 size) const {
        if (ptr == nullptr) return size == 0;
        const auto begin = reinterpret_cast<uintptr_t>(ptr);
        if (size > static_cast<u64>(UINTPTR_MAX) - begin) return false;
        const auto end = begin + static_cast<uintptr_t>(size);
        for (const Block* block = current; block; block = block->prev) {
            const auto block_begin = reinterpret_cast<uintptr_t>(block->data());
            const auto block_end = block_begin + static_cast<uintptr_t>(block->used);
            if (begin >= block_begin && end <= block_end) return true;
        }
        return false;
    }

private:
    Block* alloc_block(u64 needed, Block* prev) {
        u64 actual_size = 0;
        u8* mem = backend.acquire(needed, &actual_size);
        if (!mem) return nullptr;
        auto* b = reinterpret_cast<Block*>(mem);
        b->prev = prev;
        b->size = actual_size;
        b->used = 0;
        total_allocated += actual_size;
        return b;
    }
};

// ── Type Aliases ───────────────────────────────────────────────────
// MmapArena  — compiler/offline use (mmap-backed, variable-size blocks)
// SliceArena — runtime hot path (SlicePool-backed, 16KB fixed blocks)

using MmapArena = Arena<MmapBackend>;
using SliceArena = Arena<SlicePoolBackend>;

}  // namespace rut
