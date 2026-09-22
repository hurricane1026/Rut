#pragma once

#include "rut/runtime/slice_pool.h"

namespace rut {

// Overflow storage for complete-buffered responses. The ordinary receive slice
// remains the header/prefix owner; only bytes beyond it allocate these slices.
// Nodes are sent in place and reclaimed after their send completion.
struct ResponseBodyChain {
    static constexpr u32 kMaxBody = 1u << 20;
    struct Node {
        Node* next;
        u32 len;
        u32 offset;
        u8 bytes[SlicePool::kSliceSize - sizeof(Node*) - 2 * sizeof(u32)];
    };
    static_assert(sizeof(Node) == SlicePool::kSliceSize);
    static constexpr u32 kPayload = sizeof(Node::bytes);

    Node* head = nullptr;
    Node* tail = nullptr;
    SlicePool* owner = nullptr;
    u32 size = 0;

    const u8* data() const { return head ? head->bytes + head->offset : nullptr; }
    u32 front_size() const { return head ? head->len - head->offset : 0; }

    // Reserve before publishing: allocation failure leaves the existing bytes
    // and length unchanged, as required by the receive copy witness.
    bool append(SlicePool& pool, const u8* src, u32 len) {
        if (len > kMaxBody - size || (owner && owner != &pool)) return false;
        if (len == 0) return true;
        const u32 spare = tail ? kPayload - tail->len : 0;
        u32 missing = len > spare ? len - spare : 0;
        Node* first = nullptr;
        Node* last = nullptr;
        while (missing != 0) {
            auto* node = reinterpret_cast<Node*>(pool.alloc());
            if (!node) {
                while (first) {
                    Node* next = first->next;
                    pool.free(reinterpret_cast<u8*>(first));
                    first = next;
                }
                return false;
            }
            node->next = nullptr;
            node->len = node->offset = 0;
            if (last)
                last->next = node;
            else
                first = node;
            last = node;
            missing = missing > kPayload ? missing - kPayload : 0;
        }
        Node* write = tail ? tail : first;
        if (tail)
            tail->next = first;
        else
            head = first;
        if (last) tail = last;
        owner = &pool;
        size += len;
        while (len != 0) {
            const u32 room = kPayload - write->len;
            const u32 n = len < room ? len : room;
            __builtin_memcpy(write->bytes + write->len, src, n);
            write->len += n;
            src += n;
            len -= n;
            write = write->next;
        }
        return true;
    }

    // The caller has completed all asynchronous users of the consumed bytes.
    void consume(u32 len) {
        while (len != 0) {
            const u32 n = len < front_size() ? len : front_size();
            head->offset += n;
            size -= n;
            len -= n;
            if (head->offset == head->len) {
                Node* old = head;
                head = head->next;
                owner->free(reinterpret_cast<u8*>(old));
            }
        }
        if (!head) {
            tail = nullptr;
            owner = nullptr;
        }
    }

    void release() {
        while (head) {
            Node* next = head->next;
            owner->free(reinterpret_cast<u8*>(head));
            head = next;
        }
        tail = nullptr;
        owner = nullptr;
        size = 0;
    }
};

}  // namespace rut
