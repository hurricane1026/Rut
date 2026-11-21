#include "rut/runtime/response_body_chain.h"

#include "rut/common/types.h"

#include <stdint.h>

namespace rut {
namespace {

// Advance through one node and transfer it to the caller only when reclaimable.
// Keep tail intact until reclamation so its physical dirty extent remains available.
constexpr ResponseBodyChain::Node* consume_head(ResponseBodyChain& chain,
                                                u32& pending,
                                                bool tail_pinned) {
    auto* node = chain.head;
    if (!node) return nullptr;
    const u32 kAvailable = chain.front_size();
    const u32 kUsed = pending < kAvailable ? pending : kAvailable;
    node->offset += kUsed;
    chain.size -= kUsed;
    pending -= kUsed;
    if (node->offset != node->len || (node == chain.tail && tail_pinned)) return nullptr;
    chain.head = node->next;
    return node;
}

// Compare the real detach sequence with positions in a flat five-byte suffix.
// The head already has a consumed prefix; the last node may still belong to recv.
consteval bool consume_contract(u32 requested, bool pinned) {
    ResponseBodyChain::Node nodes[3]{};
    nodes[0].offset = 1;
    nodes[0].len = 3;
    nodes[1].len = 1;
    nodes[2].len = 2;
    nodes[0].next = &nodes[1];
    nodes[1].next = &nodes[2];
    ResponseBodyChain chain{};
    chain.head = nodes;
    chain.tail = &nodes[2];
    chain.size = 5;
    u32 pending = requested;
    const u32 kUsed = requested < 5 ? requested : 5;
    // Nodes end at positions 2, 3 and 5 in the unsent suffix.
    const u32 kRetired = static_cast<u32>(kUsed >= 2) + static_cast<u32>(kUsed >= 3) +
                         static_cast<u32>(kUsed == 5 && !pinned);
    for (u32 i = 0; i < kRetired; ++i) {
        if (consume_head(chain, pending, pinned) != &nodes[i]) return false;
    }
    if (consume_head(chain, pending, pinned) != nullptr || chain.size != 5 - kUsed ||
        pending != requested - kUsed || chain.tail != &nodes[2])
        return false;
    if (chain.head != (kRetired == 3 ? nullptr : &nodes[kRetired])) return false;
    if (nodes[0].offset != 1 + (kUsed < 2 ? kUsed : 2) ||
        nodes[1].offset != (kUsed >= 3 ? 1u : 0u) || nodes[2].offset != (kUsed > 3 ? kUsed - 3 : 0))
        return false;
    if (pinned && kUsed == 5) {
        u32 zero = 0;
        return !consume_head(chain, zero, true) && consume_head(chain, zero, false) == &nodes[2] &&
               !consume_head(chain, zero, false) && chain.size == 0;
    }
    return true;
}

static_assert(
    [] {
        for (u32 request = 0; request <= 6; ++request)
            if (!consume_contract(request, true) || !consume_contract(request, false)) return false;
        return true;
    }(),
    "Response body consumption violates prefix or tail ownership");

// A send covers only the bytes visible when it was armed. Receiving into its
// pinned tail before or after that send completes must leave the same suffix.
consteval bool pinned_commit_contract(bool receive_first, u32 sent, u32 received, u32 dirty) {
    ResponseBodyChain::Node prefix{};
    ResponseBodyChain::Node tail{};
    prefix.next = &tail;
    prefix.len = prefix.dirty_end = 3;
    prefix.offset = 1;
    tail.len = 2;
    tail.dirty_end = dirty;
    ResponseBodyChain chain{};
    chain.head = &prefix;
    chain.tail = &tail;
    chain.size = 4;

    if (receive_first) chain.commit(received);
    u32 pending = sent;
    if (sent >= 2 && consume_head(chain, pending, true) != &prefix) return false;
    if (consume_head(chain, pending, true) || pending != 0) return false;
    if (!receive_first) chain.commit(received);

    const u32 kExpectedLen = 2 + received;
    return chain.head == (sent < 2 ? &prefix : &tail) && chain.tail == &tail &&
           (sent >= 2 || prefix.next == &tail) && prefix.len == 3 &&
           prefix.offset == 1 + (sent < 2 ? sent : 2) && tail.next == nullptr &&
           tail.len == kExpectedLen && tail.offset == (sent > 2 ? sent - 2 : 0) &&
           chain.size == 4 - sent + received &&
           tail.dirty_end == (dirty > kExpectedLen ? dirty : kExpectedLen);
}

static_assert(
    [] {
        for (u32 sent = 0; sent <= 4; ++sent)
            for (u32 received = 0; received <= 2; ++received)
                for (u32 dirty = 2; dirty <= 5; ++dirty)
                    if (!pinned_commit_contract(false, sent, received, dirty) ||
                        !pinned_commit_contract(true, sent, received, dirty))
                        return false;
        return true;
    }(),
    "Pinned receive commit violates buffered response suffix contract");

consteval bool direct_write_extent_contract() {
    constexpr u64 kBegin = 32;
    constexpr u32 kCapacity = 8;
    // Compare to an end-position oracle in a wider integer domain. Include
    // offsets that alias a valid position if narrowed before validation.
    const u64 kAddresses[] = {kBegin - 1,
                              kBegin,
                              kBegin + 3,
                              kBegin + 7,
                              kBegin + 8,
                              kBegin + 9,
                              kBegin + (1ULL << 32),
                              UINT64_MAX};
    const u32 kCounts[] = {0, 1, 5, 6, 8, 9, UINT32_MAX};
    for (const u64 kAddress : kAddresses) {
        for (const u32 kCount : kCounts) {
            u32 tail_dirty = 2;
            u32 node_dirty = 6;
            const bool kValid = kAddress >= kBegin && kAddress <= kBegin + kCapacity &&
                                kAddress + kCount <= kBegin + kCapacity;
            if (detail::record_direct_write_extent(
                    kBegin, kAddress, kCapacity, kCount, tail_dirty, node_dirty) != kValid)
                return false;
            const u64 kEnd = kValid ? kAddress + kCount - kBegin : 0;
            if (tail_dirty != (kEnd > 2 ? kEnd : 2) || node_dirty != (kEnd > 6 ? kEnd : 6))
                return false;
        }
    }
    return true;
}

static_assert(direct_write_extent_contract(),
              "Direct receive violates physical write extent contract");
}  // namespace

void ResponseBodyChain::consume(u32 len, bool tail_pinned, bool recycle_bulk) {
    while (Node* old = consume_head(*this, len, tail_pinned)) {
        if (recycle_bulk && recycled == nullptr &&
            owner->is_bulk(reinterpret_cast<const u8*>(old))) {
            if (old == tail && old->dirty_end < tail_dirty_end) old->dirty_end = tail_dirty_end;
            old->next = nullptr;
            recycled = old;
        } else {
            release_node(old);
        }
    }
    if (!head) {
        tail = nullptr;
        if (!recycled) owner = nullptr;
        tail_dirty_end = 0;
    }
}
}  // namespace rut
