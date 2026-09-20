#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"
#include <new>

#include <sys/mman.h>

namespace rut {

// Stable-address, mmap-backed storage for fixed-capacity runtime tables.
// Constructing a default instance allocates nothing. init() is idempotent only
// for the same size; changing size requires destroy() first.
template <typename T>
class MappedArray {
public:
    MappedArray() = default;
    MappedArray(const MappedArray&) = delete;
    MappedArray& operator=(const MappedArray&) = delete;
    MappedArray(MappedArray&&) = delete;
    MappedArray& operator=(MappedArray&&) = delete;

    ~MappedArray() { destroy(); }

    core::Expected<void, Error> init(u32 count) {
        if (count == 0 || static_cast<u64>(count) > static_cast<u64>(SIZE_MAX) / sizeof(T))
            return core::make_unexpected(Error::make(EINVAL, Error::Source::Mmap));
        if (ptr_) {
            if (count == count_) return {};
            return core::make_unexpected(Error::make(EINVAL, Error::Source::Mmap));
        }

        const size_t bytes = static_cast<size_t>(count) * sizeof(T);
        void* region =
            mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (region == MAP_FAILED)
            return core::make_unexpected(Error::from_errno(Error::Source::Mmap));

        ptr_ = static_cast<T*>(region);
        count_ = count;
        // Value-initialize elements so default member initializers and object
        // lifetimes are honored; zero-filled mmap memory alone is insufficient.
        for (; constructed_ < count_; ++constructed_) new (&ptr_[constructed_]) T{};
        return {};
    }

    void destroy() {
        if (!ptr_) return;
        while (constructed_ != 0) ptr_[--constructed_].~T();
        munmap(ptr_, static_cast<size_t>(count_) * sizeof(T));
        ptr_ = nullptr;
        count_ = 0;
    }

    T* data() { return ptr_; }
    const T* data() const { return ptr_; }
    u32 size() const { return count_; }
    bool initialized() const { return ptr_ != nullptr; }
    T& operator[](u32 i) { return ptr_[i]; }
    const T& operator[](u32 i) const { return ptr_[i]; }
    operator T*() { return ptr_; }
    operator const T*() const { return ptr_; }
    T* begin() { return ptr_; }
    T* end() { return ptr_ ? ptr_ + count_ : nullptr; }
    const T* begin() const { return ptr_; }
    const T* end() const { return ptr_ ? ptr_ + count_ : nullptr; }

private:
    T* ptr_ = nullptr;
    u32 count_ = 0;
    u32 constructed_ = 0;
};

}  // namespace rut
