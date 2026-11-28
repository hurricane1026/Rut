#pragma once

#include "rut/common/range_int.h"
#include "rut/common/trap.h"
#include "rut/common/types.h"
#include <type_traits>

#include <inttypes.h>

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
        BufferLength<Size> count;
        if (!ptr_ || !len_.try_nonempty_prefix(max, &count)) return 0;
        __builtin_memmove(dst, ptr_, count.to_u64());
        return count.template to<Size>();
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
        if (released_) RUT_TRAP("Buffer destruction while a view is alive");
    }

    // No copy
    BasicBuffer(const BasicBuffer&) = delete;
    void operator=(const BasicBuffer&) = delete;

    // Move: traps if released (BasicView<Size> holds pointer to us — moving would dangle)
    BasicBuffer(BasicBuffer&& o) noexcept
        : ptr_(o.ptr_), cap_(o.cap_), len_(o.len_), released_(o.released_) {
        if (released_) RUT_TRAP("Buffer move construction while a view is alive");
        o.ptr_ = nullptr;
        o.len_ = {};
        o.cap_ = {};
        o.released_ = false;
    }

    void operator=(BasicBuffer&& o) noexcept {
        if (o.released_) RUT_TRAP("Buffer move assignment from a buffer with a live view");
        if (released_) RUT_TRAP("Buffer move assignment to a buffer with a live view");
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
        BufferLength<Size> count;
        const Length current{len_};
        if (!ptr_ || !current.try_nonempty_prefix(max, &count)) return 0;
        __builtin_memmove(dst, ptr_, count.to_u64());
        return count.template to<Size>();
    }

    // Release: create BasicView<Size>, lock writes. BasicView<Size> destructor auto-unlocks.
    // Traps if already released (double release = two Views = bug).
    // Returns empty BasicView<Size> if buffer is invalid (ptr_==nullptr).
    [[nodiscard]] BasicView<Size> release() noexcept {
        if (released_) RUT_TRAP("Buffer::release called twice");
        if (!ptr_) return BasicView<Size>();  // invalid buffer → empty BasicView<Size>, no lock
        released_ = true;
        return BasicView<Size>(ptr_, Length{len_}, this);
    }

    void reset() noexcept {
        if (released_) RUT_TRAP("Buffer::reset: buffer has a live view");
        len_ = {};
    }

    // --- I/O boundary: direct access for kernel syscalls ---
    // These bypass the copy-based read()/write() interface.
    // Use only at system boundaries (recv/send), not in application logic.

    // Writable region for direct I/O (e.g. recv() target).
    // Returns pointer past current data; write_avail() bytes available.
    [[nodiscard]] u8* write_ptr() noexcept {
        if (released_) RUT_TRAP("Buffer::write_ptr: buffer has a live view");
        return ptr_ ? ptr_ + Length{len_}.index() : nullptr;
    }

    [[nodiscard]] Size write_avail() const noexcept {
        if (released_) RUT_TRAP("Buffer::write_avail: buffer has a live view");
        return ptr_ ? available().template to<Size>() : 0;
    }

    // Commit bytes already written into the reserved storage.
    void commit(i64 n) noexcept {
        if (released_) commit_failed("buffer has a live view", n);
        if (!ptr_) commit_failed("buffer has no storage", n);
        const auto kAvailable = available();
        Length written;
        if (!kAvailable.try_count(n, &written)) commit_failed("write exceeds capacity", n);
        advance(kAvailable, written);
    }

    // Set the absolute length after an in-place edit.
    void set_len(i64 n) noexcept {
        if (released_) RUT_TRAP("Buffer::set_len: buffer has a live view");
        if (!ptr_) RUT_TRAP("Buffer::set_len: buffer has no storage");
        Length next;
        if (!Length{cap_}.try_count(n, &next))
            RUT_TRAP("Buffer::set_len: invalid length (%" PRId64 ", capacity=%" PRId64 ")",
                     n,
                     Length{cap_}.value());
        len_ = store_length(next);
    }

    // Drop the first n already-consumed bytes, shifting the remainder to the front.
    void consume(i64 n) noexcept {
        if (released_) RUT_TRAP("Buffer::consume: buffer has a live view");
        Length consumed;
        const Length current{len_};
        if (!current.try_nonempty_prefix(n, &consumed)) return;
        const auto kRemaining = (current - consumed).max(range_int<0, 1>{});
        if (kRemaining.value())
            __builtin_memmove(ptr_, ptr_ + consumed.index(), kRemaining.to_u64());
        len_ = store_length(kRemaining);
    }

    // Read-only data pointer for kernel send() / zero-copy forwarding.
    // Traps if released — use BasicView<Size>::data() for the released case.
    const u8* data() const noexcept {
        if (released_) RUT_TRAP("Buffer::data: buffer has a live view");
        return ptr_;
    }

    // Forceful reinit — only for connection reset (all Views must be dead).
    // Caller guarantees no live Views reference this BasicBuffer.
    void bind(u8* ptr, i64 cap) noexcept {
        Length checked_cap;
        if (!Length::try_from_i64(cap, &checked_cap))
            RUT_TRAP("Buffer::bind: invalid capacity (%" PRId64 ")", cap);
        ptr_ = ptr;
        cap_ = store_length(checked_cap);
        len_ = {};
        released_ = false;
    }

    [[nodiscard]] Size len() const noexcept { return Length{len_}.template to<Size>(); }
    [[nodiscard]] i64 capacity() const noexcept { return Length{cap_}.value(); }

    [[nodiscard]] u32 capacity_u32() const noexcept
        requires(__is_same(Size, u32))
    {
        return Length{cap_}.template to<u32>();
    }
    bool valid() const noexcept { return ptr_ != nullptr; }
    bool is_released() const noexcept { return released_; }

private:
    [[nodiscard]] Length available() const noexcept {
        return (Length{cap_} - Length{len_}).max(range_int<0, 1>{});
    }

    void advance(Length available, Length written) noexcept {
        // Subtract the unwritten tail from capacity so no sum of two unbounded
        // i64 quantities is ever formed. The caller bounds written by available.
        len_ = store_length(
            (Length{cap_} - (available - written).max(range_int<0, 1>{})).max(range_int<0, 1>{}));
    }

    void copy_prefix(const u8* src, i64 n, Length* copied) noexcept {
        if (released_) RUT_TRAP("Buffer::copy_prefix: buffer has a live view");
        if (!ptr_) return;
        const auto kAvailable = available();
        Length written;
        if (!kAvailable.try_nonempty_prefix(n, &written)) return;
        __builtin_memmove(ptr_ + Length{len_}.index(), src, written.to_u64());
        advance(kAvailable, written);
        if (copied) *copied = written;
    }

    [[noreturn, gnu::cold, gnu::noinline]] void commit_failed(const char* reason,
                                                              i64 n) const noexcept {
        RUT_TRAP("Buffer::commit: %s (length=%" PRId64 ", capacity=%" PRId64 ", bytes=%" PRId64 ")",
                 reason,
                 Length{len_}.value(),
                 Length{cap_}.value(),
                 n);
    }

    friend struct BasicView<Size>;
    using StoredLength = std::conditional_t<__is_same(Size, u32), u32, Length>;

    [[nodiscard]] static StoredLength store_length(Length value) noexcept {
        if constexpr (__is_same(Size, u32))
            return value.template to<u32>();
        else
            return value;
    }

    u8* ptr_ = nullptr;
    StoredLength cap_{};
    StoredLength len_{};
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
