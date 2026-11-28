#pragma once

#include "rut/common/range_int.h"

// Compile-time feature switches. WebSocket/Upgrade passthrough is ON by default;
// build with -DRUT_ENABLE_WEBSOCKET=0 (e.g. a minimal k8s mesh sidecar that never
// proxies WebSocket) to compile out the 101 tunnel path entirely — no 101 check
// on the proxy response path, no tunnel callbacks, no idle-timeout exemption.
#ifndef RUT_ENABLE_EBPF
#define RUT_ENABLE_EBPF 0
#endif

#ifndef RUT_ENABLE_WEBSOCKET
#define RUT_ENABLE_WEBSOCKET 1
#endif

// Placement new — declaration only; definition lives in src/placement_new.cc.
#include "core/placement_new.h"

namespace rut {

using f32 = float;
using f64 = double;

// Interpret a char from a byte stream as an unsigned octet on either char ABI.
[[nodiscard]] constexpr u8 byte_value(char value) {
    return bounded_remainder<256>(value).to<u8>();
}

// Non-owning string view (no stdlib dependency)
struct Str {
    const char* ptr;
    u32 len;

    [[nodiscard]] bool eq(Str other) const {
        if (len != other.len) return false;
        for (u32 i = 0; i < len; i++) {
            if (ptr[i] != other.ptr[i]) return false;
        }
        return true;
    }

    [[nodiscard]] bool empty() const { return len == 0; }

    [[nodiscard]] Str slice(u32 start, u32 end) const {
        // Invalid ranges are an empty view; validate before forming the pointer
        // so a malformed parser span cannot create an out-of-bounds address.
        if (ptr == nullptr || start > end || end > len) return {nullptr, 0};
        return {ptr + range_int{start}.index(), range_int{end - start}.to<u32>()};
    }
};

template <size_t N>
    requires(N > 0 && N - 1 <= UINT32_MAX)
[[nodiscard]] constexpr Str lit_str(const char (&s)[N]) {
    return {s, range_int<N - 1, N>{}.template to<u32>()};
}

// Fixed-capacity vector, no heap allocation
template <typename T, u32 Cap>
struct FixedVec {
    T data[Cap];
    u32 len = 0;

    bool push(const T& val) {
        if (len >= Cap) return false;
        data[len++] = val;
        return true;
    }
    T& operator[](u32 i) { return data[i]; }
    const T& operator[](u32 i) const { return data[i]; }
    T* begin() { return data; }
    [[nodiscard]] T* end() { return data + range_int{len}.index(); }
    [[nodiscard]] bool full() const { return len >= Cap; }
    [[nodiscard]] bool empty() const { return len == 0; }
};

// Intrusive linked list node
struct ListNode {
    ListNode* prev;
    ListNode* next;

    constexpr void init() {
        prev = this;
        next = this;
    }

    constexpr void remove() {
        prev->next = next;
        next->prev = prev;
    }

    constexpr void insert_after(ListNode* node) {
        node->prev = this;
        node->next = next;
        next->prev = node;
        next = node;
    }

    constexpr void detach() {
        remove();
        init();
    }

    constexpr void move_to_tail(ListNode& head) {
        remove();
        head.prev->insert_after(this);
    }

    [[nodiscard]] constexpr bool empty() const { return next == this; }
};

}  // namespace rut
