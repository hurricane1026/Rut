#pragma once

#include "rut/runtime/slice_pool.h"

namespace rut {

// Overflow storage for complete-buffered responses. The ordinary receive slice
// remains the header/prefix owner; only bytes beyond it allocate these slices.
// Nodes are sent in place and reclaimed after their send completion, one node
// per send. A node is an ordinary slice or, once the body has proven larger
// than one slice and the pool has one, a bulk relay buffer: a large body then
// leaves in 256 KiB sends instead of 16 KiB ones.
struct ResponseBodyChain {
    static constexpr u32 kMaxBody = SlicePool::kMaxBufferedResponseBody;
    struct Node {
        Node* next;
        u32 len;
        u32 offset;
        u8 bytes[SlicePool::kSliceSize - sizeof(Node*) - 2 * sizeof(u32)];
    };
    static_assert(sizeof(Node) == SlicePool::kSliceSize);
    static constexpr u32 kPayload = sizeof(Node::bytes);
    static_assert(kPayload == SlicePool::kResponseBodyPayload);
    static constexpr u32 kHeader = SlicePool::kSliceSize - kPayload;

    // Payload of a node, which may extend past Node::bytes for a bulk node.
    static u8* payload(Node* node) { return reinterpret_cast<u8*>(node) + kHeader; }
    static const u8* payload(const Node* node) {
        return reinterpret_cast<const u8*>(node) + kHeader;
    }
    static u32 payload_capacity(const SlicePool& pool, const Node* node) {
        return pool.capacity_of(reinterpret_cast<const u8*>(node)) - kHeader;
    }

    Node* head = nullptr;
    Node* tail = nullptr;
    SlicePool* owner = nullptr;
    u32 size = 0;

    const u8* data() const { return head ? payload(head) + head->offset : nullptr; }
    u32 front_size() const { return head ? head->len - head->offset : 0; }

    // Stored bytes after which new nodes prefer bulk buffers. Plaintext
    // switches as soon as the body outgrew one slice. TLS waits until four:
    // the per-send win is smaller there (each record is encrypted anyway)
    // and a ~48 KiB bulk node for a 64 KiB TLS body measured slower than
    // slices at high concurrency.
    static constexpr u32 kBulkAfterPlaintext = kPayload;
    static constexpr u32 kBulkAfterTls = 4 * kPayload;

    // Reserve before publishing: allocation failure leaves the existing bytes
    // and length unchanged, as required by the receive copy witness.
    bool append(SlicePool& pool, const u8* src, u32 len, u32 bulk_after = kBulkAfterPlaintext) {
        if (len > kMaxBody - size || (owner && owner != &pool)) return false;
        if (len == 0) return true;
        const u32 spare = tail ? payload_capacity(pool, tail) - tail->len : 0;
        u32 missing = len > spare ? len - spare : 0;
        Node* first = nullptr;
        Node* last = nullptr;
        while (missing != 0) {
            // Appends arrive one receive at a time, so judge by what the body
            // has proven: once it outgrew `bulk_after` (or this append alone
            // needs more than one slice), prefer one bulk node over slices.
            u8* raw = (missing > kPayload || size >= bulk_after) ? pool.alloc_bulk() : nullptr;
            if (!raw) raw = pool.alloc();
            auto* node = reinterpret_cast<Node*>(raw);
            if (!node) {
                while (first) {
                    Node* next = first->next;
                    pool.free_written(reinterpret_cast<u8*>(first), kHeader);
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
            const u32 cap = payload_capacity(pool, node);
            missing = missing > cap ? missing - cap : 0;
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
            const u32 room = payload_capacity(pool, write) - write->len;
            const u32 n = len < room ? len : room;
            __builtin_memcpy(payload(write) + write->len, src, n);
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
                release_node(old);
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
            release_node(head);
            head = next;
        }
        tail = nullptr;
        owner = nullptr;
        size = 0;
    }

private:
    // Payload bytes are only ever written at [0, len), so that is all a
    // bulk node has to re-zero on return.
    void release_node(Node* node) {
        owner->free_written(reinterpret_cast<u8*>(node), kHeader + node->len);
    }
};

}  // namespace rut
