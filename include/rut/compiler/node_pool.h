#pragma once

#include "rut/runtime/arena.h"

namespace rut {

// Compiler-owned, append-only storage. Arena chunks keep node addresses stable
// as the directory grows; no request-path allocations or C++ library containers.
// Copies own their nodes; the IR owner rebases internal pointers via index_of().
// A failed copy is explicitly invalid and must be rejected before lowering.
template <typename T>
class NodePool {
#if defined(__clang__)
    static_assert(__is_trivially_destructible(T));
#else
    static_assert(__has_trivial_destructor(T));
#endif
    static constexpr u32 kChunkSize = 16;
    MmapArena arena_{};
    T** chunks_ = nullptr;
    u32 chunk_count_ = 0;
    u32 directory_capacity_ = 0;
    bool failed_ = false;

    void copy_from(const NodePool& other) {
        for (u32 i = 0; i < other.len; ++i) {
            if (!push(other[i])) break;
        }
        failed_ |= !other.ok();
    }

public:
    u32 len = 0;

    NodePool() = default;
    NodePool(const NodePool& other) { copy_from(other); }
    NodePool& operator=(const NodePool& other) {
        if (this == &other) return *this;
        arena_.destroy();
        chunks_ = nullptr;
        chunk_count_ = 0;
        directory_capacity_ = 0;
        failed_ = false;
        len = 0;
        copy_from(other);
        return *this;
    }
    ~NodePool() { arena_.destroy(); }

    [[nodiscard]] bool ok() const { return !failed_; }
    [[nodiscard]] bool empty() const { return len == 0; }

    bool push(const T& value) {
        if (failed_) return false;
        if (len == 0xffffffffu) {
            failed_ = true;
            return false;
        }
        if (len / kChunkSize == chunk_count_) {
            if (!arena_.current && !arena_.init(4096)) {
                failed_ = true;
                return false;
            }
            if (chunk_count_ == directory_capacity_) {
                const u32 next = directory_capacity_ == 0 ? 8 : directory_capacity_ * 2;
                auto** directory = arena_.template alloc_array<T*>(next);
                if (!directory) {
                    failed_ = true;
                    return false;
                }
                for (u32 i = 0; i < chunk_count_; ++i) directory[i] = chunks_[i];
                chunks_ = directory;
                directory_capacity_ = next;
            }
            auto* chunk = arena_.template alloc_array<T>(kChunkSize);
            if (!chunk) {
                failed_ = true;
                return false;
            }
            chunks_[chunk_count_++] = chunk;
        }
        (*this)[len++] = value;
        return true;
    }

    T& operator[](u32 i) { return chunks_[i / kChunkSize][i % kChunkSize]; }
    const T& operator[](u32 i) const { return chunks_[i / kChunkSize][i % kChunkSize]; }

    // Integer address comparisons also handle pointers belonging to another pool
    // without undefined ordering/subtraction between unrelated C++ arrays.
    [[nodiscard]] u32 index_of(const T* ptr) const {
        const auto address = reinterpret_cast<uintptr_t>(ptr);
        for (u32 i = 0; i < chunk_count_; ++i) {
            const auto begin = reinterpret_cast<uintptr_t>(chunks_[i]);
            const u32 remaining = len - i * kChunkSize;
            const u32 count = remaining < kChunkSize ? remaining : kChunkSize;
            if (address >= begin && address - begin < sizeof(T) * count &&
                (address - begin) % sizeof(T) == 0)
                return i * kChunkSize + static_cast<u32>((address - begin) / sizeof(T));
            if (count < kChunkSize) break;
        }
        return 0xffffffffu;
    }
};

}  // namespace rut
