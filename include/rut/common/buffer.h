#pragma once

#include "rut/common/types.h"

namespace rut {

struct Buffer;

// View — read-only, move-only. Created by Buffer::release().
// On destruction, restores Buffer's write permission and resets Buffer's len to 0
// (data is considered consumed; Buffer starts fresh for the next write cycle).
struct View {
    View() noexcept : ptr_(nullptr), len_(0), owner_(nullptr) {}

    // No copy
    View(const View&) = delete;
    View& operator=(const View&) = delete;

    // Move: source invalidated
    View(View&& o) noexcept : ptr_(o.ptr_), len_(o.len_), owner_(o.owner_) {
        o.ptr_ = nullptr;
        o.len_ = 0;
        o.owner_ = nullptr;
    }

    View& operator=(View&& o) noexcept {
        if (this != &o) {
            restore_owner();
            ptr_ = o.ptr_;
            len_ = o.len_;
            owner_ = o.owner_;
            o.ptr_ = nullptr;
            o.len_ = 0;
            o.owner_ = nullptr;
        }
        return *this;
    }

    ~View() { restore_owner(); }

    // Read: copy data out of the View. const.
    u32 read(u8* dst, u32 max) const noexcept {
        if (!ptr_ || max == 0) return 0;
        u32 n = len_ < max ? len_ : max;
        if (n > 0) __builtin_memmove(dst, ptr_, n);
        return n;
    }

    // Read-only data pointer — for kernel send() on a View.
    const u8* data() const noexcept { return ptr_; }

    u32 len() const noexcept { return len_; }
    bool valid() const noexcept { return ptr_ != nullptr; }

private:
    const u8* ptr_;
    u32 len_;
    Buffer* owner_;

    friend struct Buffer;
    View(const u8* ptr, u32 len, Buffer* owner) noexcept : ptr_(ptr), len_(len), owner_(owner) {}

    inline void restore_owner() noexcept;
};

// Buffer — read + write, move-only (exclusive owner).
// Cannot be moved while released (View alive) — traps.
struct Buffer {
    Buffer() noexcept : ptr_(nullptr), len_(0), cap_(0), released_(false) {}
    Buffer(u8* ptr, u32 cap) noexcept : ptr_(ptr), len_(0), cap_(cap), released_(false) {}

    // Destructor: traps if View still alive (View would dangle)
    ~Buffer() {
        if (released_) __builtin_trap();
    }

    // No copy
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    // Move: traps if released (View holds pointer to us — moving would dangle)
    Buffer(Buffer&& o) noexcept : ptr_(o.ptr_), len_(o.len_), cap_(o.cap_), released_(o.released_) {
        if (released_) __builtin_trap();  // move while View alive = dangling owner_
        o.ptr_ = nullptr;
        o.len_ = 0;
        o.cap_ = 0;
        o.released_ = false;
    }

    Buffer& operator=(Buffer&& o) noexcept {
        if (o.released_) __builtin_trap();  // source has View alive = dangling owner_
        if (released_) __builtin_trap();    // dest has View alive = View would corrupt new state
        if (this != &o) {
            ptr_ = o.ptr_;
            len_ = o.len_;
            cap_ = o.cap_;
            released_ = o.released_;
            o.ptr_ = nullptr;
            o.len_ = 0;
            o.cap_ = 0;
            o.released_ = false;
        }
        return *this;
    }

    // Write: traps if released (View still alive = bug)
    u32 write(const u8* src, u32 n) noexcept {
        if (released_) __builtin_trap();
        if (!ptr_) return 0;
        u32 avail = cap_ - len_;
        u32 to_write = n < avail ? n : avail;
        if (to_write > 0) {
            __builtin_memmove(ptr_ + len_, src, to_write);
            len_ += to_write;
        }
        return to_write;
    }

    // Read: const — Buffer owner can also read
    u32 read(u8* dst, u32 max) const noexcept {
        if (!ptr_ || max == 0) return 0;
        u32 n = len_ < max ? len_ : max;
        if (n > 0) __builtin_memmove(dst, ptr_, n);
        return n;
    }

    // Release: create View, lock writes. View destructor auto-unlocks.
    // Traps if already released (double release = two Views = bug).
    // Returns empty View if buffer is invalid (ptr_==nullptr).
    [[nodiscard]] View release() noexcept {
        if (released_) __builtin_trap();  // double release = bug
        if (!ptr_) return View();         // invalid buffer → empty View, no lock
        released_ = true;
        return View(ptr_, len_, this);
    }

    void reset() noexcept {
        if (released_) __builtin_trap();
        len_ = 0;
    }

    // --- I/O boundary: direct access for kernel syscalls ---
    // These bypass the copy-based read()/write() interface.
    // Use only at system boundaries (recv/send), not in application logic.

    // Writable region for direct I/O (e.g. recv() target).
    // Returns pointer past current data; write_avail() bytes available.
    u8* write_ptr() noexcept {
        if (released_) __builtin_trap();
        return ptr_ ? ptr_ + len_ : nullptr;
    }

    u32 write_avail() const noexcept {
        if (released_) __builtin_trap();
        return ptr_ ? cap_ - len_ : 0;
    }

    // Commit n bytes written directly via write_ptr().
    // Call after recv() returns — advances len_ without copying.
    void commit(u32 n) noexcept {
        if (released_) __builtin_trap();
        if (!ptr_ || len_ + n > cap_) __builtin_trap();
        len_ += n;
    }

    // Set the absolute length after an in-place edit (e.g. rewriting the
    // request line for forward(set_path:)). Traps if released or out of range.
    void set_len(u32 n) noexcept {
        if (released_ || !ptr_ || n > cap_) __builtin_trap();
        len_ = n;
    }

    // Read-only data pointer for kernel send() / zero-copy forwarding.
    // Traps if released — use View::data() for the released case.
    const u8* data() const noexcept {
        if (released_) __builtin_trap();
        return ptr_;
    }

    // Forceful reinit — only for connection reset (all Views must be dead).
    // Caller guarantees no live Views reference this Buffer.
    void bind(u8* ptr, u32 cap) noexcept {
        ptr_ = ptr;
        len_ = 0;
        cap_ = cap;
        released_ = false;
    }

    u32 len() const noexcept { return len_; }
    u32 capacity() const noexcept { return cap_; }
    bool valid() const noexcept { return ptr_ != nullptr; }
    bool is_released() const noexcept { return released_; }

private:
    friend struct View;
    u8* ptr_;
    u32 len_;
    u32 cap_;
    bool released_;
};

inline void View::restore_owner() noexcept {
    if (owner_) {
        owner_->released_ = false;
        owner_->len_ = 0;
        owner_ = nullptr;
    }
}

}  // namespace rut
