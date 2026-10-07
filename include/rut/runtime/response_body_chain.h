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
        // Physical high-water mark survives private reuse within one response.
        u32 dirty_end;
        u8 bytes[SlicePool::kSliceSize - sizeof(Node*) - 3 * sizeof(u32)];
    };
    static_assert(sizeof(Node) == SlicePool::kSliceSize);
    static constexpr u32 kPayload = sizeof(Node::bytes);
    static_assert(kPayload == SlicePool::kResponseBodyPayload);
    static constexpr u32 kHeader = SlicePool::kSliceSize - kPayload;
    static constexpr u32 header_size() { return kHeader; }

    // Payload of a node, which may extend past Node::bytes for a bulk node.
    static u8* payload(Node* node) { return reinterpret_cast<u8*>(node) + header_size(); }
    static const u8* payload(const Node* node) {
        return reinterpret_cast<const u8*>(node) + header_size();
    }
    static u32 payload_capacity(const SlicePool& pool, const Node* node) {
        return pool.capacity_of(reinterpret_cast<const u8*>(node)) - header_size();
    }

    Node* head = nullptr;
    Node* tail = nullptr;
    // One consumed bulk node may remain response-owned for another direct recv.
    // It is not returned to the zero-filled pool until release_recycled().
    Node* recycled = nullptr;
    SlicePool* owner = nullptr;
    u32 size = 0;
    // Bytes a direct recv has physically written into the current tail beyond
    // its committed logical length. Kept separately so a late/stale CQE can be
    // zeroed on release without publishing those bytes to the response.
    u32 tail_dirty_end = 0;

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
            u32 previous_dirty = 0;
            u8* raw = (missing > kPayload || size >= bulk_after)
                          ? pool.alloc_response_body_bulk(previous_dirty)
                          : nullptr;
            if (!raw) raw = pool.alloc();
            auto* node = reinterpret_cast<Node*>(raw);
            if (!node) {
                while (first) {
                    Node* next = first->next;
                    pool.free_response_body_written(reinterpret_cast<u8*>(first),
                                                    header_size() + first->dirty_end);
                    first = next;
                }
                return false;
            }
            node->next = nullptr;
            node->len = node->offset = 0;
            node->dirty_end = previous_dirty > header_size() ? previous_dirty - header_size() : 0;
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
        if (last) {
            tail = last;
            tail_dirty_end = 0;
        }
        owner = &pool;
        size += len;
        while (len != 0) {
            const u32 room = payload_capacity(pool, write) - write->len;
            const u32 n = len < room ? len : room;
            __builtin_memcpy(payload(write) + write->len, src, n);
            write->len += n;
            if (write->dirty_end < write->len) write->dirty_end = write->len;
            src += n;
            len -= n;
            write = write->next;
        }
        return true;
    }

    // Completed sends may consume the committed prefix while a direct recv
    // still owns the tail's reserved capacity. Retain that node until the
    // receive target settles; consume(0) then removes any empty retained head.
    void consume(u32 len, bool tail_pinned = false, bool recycle_bulk = false) {
        while (head && (len != 0 || head->offset == head->len)) {
            const u32 n = len < front_size() ? len : front_size();
            head->offset += n;
            size -= n;
            len -= n;
            if (head->offset == head->len) {
                if (head == tail && tail_pinned) break;
                Node* old = head;
                head = head->next;
                if (recycle_bulk && recycled == nullptr &&
                    owner->is_bulk(reinterpret_cast<const u8*>(old))) {
                    if (old == tail && old->dirty_end < tail_dirty_end)
                        old->dirty_end = tail_dirty_end;
                    old->next = nullptr;
                    recycled = old;
                } else {
                    release_node(old);
                }
            }
        }
        if (!head) {
            tail = nullptr;
            if (!recycled) owner = nullptr;
            tail_dirty_end = 0;
        }
    }

    void release_recycled() {
        if (recycled) {
            release_node(recycled);
            recycled = nullptr;
        }
        if (!head) owner = nullptr;
    }

    void release() {
        while (head) {
            Node* next = head->next;
            release_node(head);
            head = next;
        }
        tail = nullptr;
        release_recycled();
        owner = nullptr;
        size = 0;
        tail_dirty_end = 0;
    }

    // --- Direct-recv tail API ---
    // A direct (buffer-select-free) recv must know its destination and exact
    // length before arming, unlike append() which learns `len` only once the
    // kernel copy has already happened. reserve_tail() guarantees the tail
    // has room for at least one byte — allocating a new node (bulk once the
    // body has proven larger than `bulk_after`, else a slice) if the current
    // tail is full or absent — after which write_ptr()/write_avail() name the
    // destination and commit() records what the kernel wrote there directly.
    // The reserved node is otherwise ordinary: sent and reclaimed exactly
    // like one built by append().
    bool reserve_tail(SlicePool& pool, u32 bulk_after = kBulkAfterPlaintext) {
        if (tail && payload_capacity(pool, tail) > tail->len) return true;
        if (owner && owner != &pool) return false;
        const bool reuse = size >= bulk_after && recycled != nullptr;
        u32 previous_dirty = 0;
        u8* raw = reuse                ? reinterpret_cast<u8*>(recycled)
                  : size >= bulk_after ? pool.alloc_response_body_bulk(previous_dirty)
                                       : nullptr;
        if (!raw) raw = pool.alloc();
        auto* node = reinterpret_cast<Node*>(raw);
        if (!node) return false;
        if (reuse)
            recycled = nullptr;
        else
            node->dirty_end = previous_dirty > header_size() ? previous_dirty - header_size() : 0;
        node->next = nullptr;
        node->len = node->offset = 0;
        if (tail)
            tail->next = node;
        else
            head = node;
        tail = node;
        tail_dirty_end = 0;
        owner = &pool;
        return true;
    }

    // Valid only after a successful reserve_tail() with no intervening
    // append()/reserve_tail() failure or consume() of the tail.
    u8* write_ptr(const SlicePool& pool) const {
        (void)pool;
        return tail ? payload(tail) + tail->len : nullptr;
    }
    u32 write_avail(const SlicePool& pool) const {
        return tail ? payload_capacity(pool, tail) - tail->len : 0;
    }

    // Record bytes a direct recv wrote straight into write_ptr()'s
    // destination (n <= the write_avail() observed when it was armed).
    void commit(u32 n) {
        tail->len += n;
        if (tail->dirty_end < tail->len) tail->dirty_end = tail->len;
        size += n;
    }

    // Record physical writes before deciding whether their CQE still owns a
    // logical response. Only the current tail can have a direct recv in flight:
    // complete-buffered responses do not consume or send body nodes while the
    // origin recv is active, and close defers chain release until its CQE drains.
    bool record_direct_write(Node* node, const u8* ptr, u32 n, const SlicePool& pool) {
        if (node == nullptr || node != tail || ptr == nullptr) return false;
        const u64 begin = reinterpret_cast<u64>(payload(node));
        const u64 address = reinterpret_cast<u64>(ptr);
        const u32 capacity = payload_capacity(pool, node);
        if (address < begin || address - begin > capacity ||
            n > capacity - static_cast<u32>(address - begin))
            return false;
        const u32 end = static_cast<u32>(address - begin) + n;
        if (end > tail_dirty_end) tail_dirty_end = end;
        if (end > node->dirty_end) node->dirty_end = end;
        return true;
    }

private:
    // Ordinary writes publish [0, len); a direct recv can dirty a longer
    // prefix before its CQE is accepted, tracked by tail_dirty_end.
    void release_node(Node* node) {
        u32 dirty = node->dirty_end > node->len ? node->dirty_end : node->len;
        if (node == tail && tail_dirty_end > dirty) dirty = tail_dirty_end;
        owner->free_response_body_written(reinterpret_cast<u8*>(node), header_size() + dirty);
        if (node == tail) tail_dirty_end = 0;
    }
};

}  // namespace rut
