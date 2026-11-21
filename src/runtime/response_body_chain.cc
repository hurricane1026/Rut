#include "rut/runtime/response_body_chain.h"

#include "rut/common/types.h"

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
