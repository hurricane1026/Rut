#pragma once

#include "rut/common/range_int.h"
#include "rut/common/types.h"

#include <inttypes.h>
#include <stdio.h>

namespace rut {

template <typename Size>
using BufferLength = range_int<0, __is_same(Size, i64) ? kI64ExclusiveEnd : i64{UINT32_MAX} + 1>;

template <typename Size>
struct BasicBuffer;

// View — read-only, move-only. Created by Buffer::release().
// On destruction, restores Buffer's write permission and resets Buffer's len to 0
// (data is considered consumed; Buffer starts fresh for the next write cycle).
template <typename Size>
struct BasicView {
    BasicView() noexcept : ptr_(nullptr), len_{}, owner_(nullptr) {}

    // No copy
    BasicView(const BasicView&) = delete;
    void operator=(const BasicView&) = delete;

    // Move: source invalidated
    BasicView(BasicView&& o) noexcept : ptr_(o.ptr_), len_(o.len_), owner_(o.owner_) {
        o.ptr_ = nullptr;
        o.len_ = {};
        o.owner_ = nullptr;
    }

    void operator=(BasicView&& o) noexcept {
        if (this != &o) {
            restore_owner();
            ptr_ = o.ptr_;
            len_ = o.len_;
            owner_ = o.owner_;
            o.ptr_ = nullptr;
            o.len_ = {};
            o.owner_ = nullptr;
        }
    }

    ~BasicView() { restore_owner(); }

    // Read: copy data out of the view.
    [[nodiscard]] Size read(u8* dst, i64 max) const noexcept {
        range_int<0> limit;
        if (!ptr_ || !range_int<0>::try_from_i64(max, &limit)) return 0;
        const auto kRead = len_.min(limit);
        if (kRead.value()) __builtin_memmove(dst, ptr_, kRead.to_u64());
        return kRead.template to<Size>();
    }

    [[nodiscard]] const u8* data() const noexcept { return ptr_; }
    [[nodiscard]] Size len() const noexcept { return len_.template to<Size>(); }
    bool valid() const noexcept { return ptr_ != nullptr; }

private:
    const u8* ptr_;
    BufferLength<Size> len_;
    BasicBuffer<Size>* owner_;

    friend struct BasicBuffer<Size>;
    BasicView(const u8* ptr, BufferLength<Size> len, BasicBuffer<Size>* owner) noexcept
        : ptr_(ptr), len_(len), owner_(owner) {}

    inline void restore_owner() noexcept;
};

// Buffer — read + write, move-only (exclusive owner).
// Cannot be moved while released (View alive) — traps.
template <typename Size>
struct BasicBuffer {
    static_assert(__is_same(Size, u32) || __is_same(Size, i64));

private:
    using Length = BufferLength<Size>;

public:
    BasicBuffer() noexcept = default;
    BasicBuffer(u8* ptr, i64 cap) noexcept { bind(ptr, cap); }

    // Destructor: traps if BasicView<Size> still alive (the view would dangle)
    ~BasicBuffer() {
        if (released_) __builtin_trap();
    }

    // No copy
    BasicBuffer(const BasicBuffer&) = delete;
    void operator=(const BasicBuffer&) = delete;

    // Move: traps if released (BasicView<Size> holds pointer to us — moving would dangle)
    BasicBuffer(BasicBuffer&& o) noexcept
        : ptr_(o.ptr_), cap_(o.cap_), len_(o.len_), released_(o.released_) {
        if (released_) __builtin_trap();  // move while a view is alive = dangling owner_
        o.ptr_ = nullptr;
        o.len_ = {};
        o.cap_ = {};
        o.released_ = false;
    }

    void operator=(BasicBuffer&& o) noexcept {
        if (o.released_) __builtin_trap();  // source has a view is alive = dangling owner_
        if (released_)
            __builtin_trap();  // dest has a view is alive = the view would corrupt new
                               // state
        if (this != &o) {
            ptr_ = o.ptr_;
            len_ = o.len_;
            cap_ = o.cap_;
            released_ = o.released_;
            o.ptr_ = nullptr;
            o.len_ = {};
            o.cap_ = {};
            o.released_ = false;
        }
    }

    // Write up to n bytes into this buffer, returning the number copied.
    [[nodiscard]] Size write(const u8* src, i64 n) noexcept {
        Length written;
        copy_prefix(src, n, &written);
        return written.template to<Size>();
    }

    // Append the prefix that fits. Call write() when the caller needs its length.
    void append_prefix(const u8* src, i64 n) noexcept { copy_prefix(src, n, nullptr); }

    [[nodiscard]] Size read(u8* dst, i64 max) const noexcept {
        range_int<0> limit;
        if (!ptr_ || !range_int<0>::try_from_i64(max, &limit)) return 0;
        const auto kRead = len_.min(limit);
        if (kRead.value()) __builtin_memmove(dst, ptr_, kRead.to_u64());
        return kRead.template to<Size>();
    }

    // Release: create BasicView<Size>, lock writes. BasicView<Size> destructor auto-unlocks.
    // Traps if already released (double release = two Views = bug).
    // Returns empty BasicView<Size> if buffer is invalid (ptr_==nullptr).
    [[nodiscard]] BasicView<Size> release() noexcept {
        if (released_) __builtin_trap();      // double release = bug
        if (!ptr_) return BasicView<Size>();  // invalid buffer → empty BasicView<Size>, no lock
        released_ = true;
        return BasicView<Size>(ptr_, len_, this);
    }

    void reset() noexcept {
        if (released_) __builtin_trap();
        len_ = {};
    }

    // --- I/O boundary: direct access for kernel syscalls ---
    // These bypass the copy-based read()/write() interface.
    // Use only at system boundaries (recv/send), not in application logic.

    // Writable region for direct I/O (e.g. recv() target).
    // Returns pointer past current data; write_avail() bytes available.
    [[nodiscard]] u8* write_ptr() noexcept {
        if (released_) __builtin_trap();
        return ptr_ ? ptr_ + len_.index() : nullptr;
    }

    [[nodiscard]] Size write_avail() const noexcept {
        if (released_) __builtin_trap();
        return ptr_ ? available().template to<Size>() : 0;
    }

    // Commit bytes already written into the reserved storage.
    void commit(i64 n) noexcept {
        if (released_) commit_failed("buffer has a live view", n);
        if (!ptr_) commit_failed("buffer has no storage", n);
        const auto kAvailable = available();
        range_int<0> written;
        if (!range_int<0>::try_from_i64(n, &written) || n > kAvailable.value())
            commit_failed("write exceeds capacity", n);
        advance(kAvailable, written.min(kAvailable));
    }

    // Set the absolute length after an in-place edit.
    void set_len(i64 n) noexcept {
        if (released_ || !ptr_ || n > cap_.value() || !Length::try_from_i64(n, &len_))
            __builtin_trap();
    }

    // Drop the first n already-consumed bytes, shifting the remainder to the front.
    void consume(i64 n) noexcept {
        if (released_) __builtin_trap();
        range_int<0> consumed;
        if (!range_int<0>::try_from_i64(n, &consumed) || n == 0) return;
        if (n >= len_.value()) {
            len_ = {};
            return;
        }
        const auto kRemaining = (len_ - consumed.min(len_)).max(range_int<0, 1>{});
        __builtin_memmove(ptr_, ptr_ + consumed.index(), kRemaining.to_u64());
        len_ = kRemaining;
    }

    // Read-only data pointer for kernel send() / zero-copy forwarding.
    // Traps if released — use BasicView<Size>::data() for the released case.
    const u8* data() const noexcept {
        if (released_) __builtin_trap();
        return ptr_;
    }

    // Forceful reinit — only for connection reset (all Views must be dead).
    // Caller guarantees no live Views reference this BasicBuffer.
    void bind(u8* ptr, i64 cap) noexcept {
        if (!Length::try_from_i64(cap, &cap_)) {
            ::fprintf(stderr, "rut: Buffer::bind: invalid capacity (%" PRId64 ")\n", cap);
            __builtin_trap();
        }
        ptr_ = ptr;
        len_ = {};
        released_ = false;
    }

    [[nodiscard]] Size len() const noexcept { return len_.template to<Size>(); }
    [[nodiscard]] i64 capacity() const noexcept { return cap_.value(); }

    [[nodiscard]] u32 capacity_u32() const noexcept
        requires(__is_same(Size, u32))
    {
        return cap_.template to<u32>();
    }
    bool valid() const noexcept { return ptr_ != nullptr; }
    bool is_released() const noexcept { return released_; }

private:
    [[nodiscard]] Length available() const noexcept { return (cap_ - len_).max(range_int<0, 1>{}); }

    void advance(Length available, Length written) noexcept {
        // Subtract the unwritten tail from capacity so no sum of two unbounded
        // i64 quantities is ever formed. The caller bounds written by available.
        len_ = (cap_ - (available - written).max(range_int<0, 1>{})).max(range_int<0, 1>{});
    }

    void copy_prefix(const u8* src, i64 n, Length* copied) noexcept {
        if (released_) __builtin_trap();
        if (!ptr_) return;
        range_int<0> requested;
        if (!range_int<0>::try_from_i64(n, &requested)) return;
        const auto kAvailable = available();
        const auto kWritten = kAvailable.min(requested);
        if (kWritten.value()) {
            __builtin_memmove(ptr_ + len_.index(), src, kWritten.to_u64());
            advance(kAvailable, kWritten);
        }
        if (copied) *copied = kWritten;
    }

    [[noreturn, gnu::cold, gnu::noinline]] void commit_failed(const char* reason,
                                                              i64 n) const noexcept {
        ::fprintf(stderr,
                  "rut: Buffer::commit: %s (length=%" PRId64 ", capacity=%" PRId64
                  ", bytes=%" PRId64 ")\n",
                  reason,
                  len_.value(),
                  cap_.value(),
                  n);
        __builtin_trap();
    }

    friend struct BasicView<Size>;
    u8* ptr_ = nullptr;
    Length cap_;
    Length len_;
    bool released_ = false;
};

template <typename Size>
inline void BasicView<Size>::restore_owner() noexcept {
    if (owner_) {
        owner_->released_ = false;
        owner_->len_ = {};
        owner_ = nullptr;
    }
}

// General buffers use signed pointer-sized offsets. Slice buffers are bounded
// at binding, so their I/O-facing lengths can use u32 without narrowing.
using Buffer = BasicBuffer<i64>;
using View = BasicView<i64>;
using SliceBuffer = BasicBuffer<u32>;

}  // namespace rut
