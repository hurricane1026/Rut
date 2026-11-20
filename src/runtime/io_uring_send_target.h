#pragma once

#include "rut/runtime/io_event.h"

#include <linux/io_uring.h>

namespace rut {

// Only the owner's single-shot SEND completion may advance its byte counters.
// Generation zero is the untagged legacy owner and still requires an exact match.
constexpr bool matches_downstream_send_target(u32 owner, u32 incoming, u32 flags) {
    return owner == incoming && (incoming & kNonUpstreamSendCancelBit) == 0 &&
           (flags & IORING_CQE_F_MORE) == 0;
}

consteval bool downstream_send_target_contract() {
    constexpr u32 kOwners[] = {0, 1, 0x12345678, kNonUpstreamSendGenerationMask};
    for (u32 owner : kOwners) {
        if (!matches_downstream_send_target(owner, owner, 0) ||
            matches_downstream_send_target(owner, owner, IORING_CQE_F_MORE) ||
            matches_downstream_send_target(owner, owner, IORING_CQE_F_MORE | IORING_CQE_F_BUFFER))
            return false;
        // A difference in any wire bit, including the cancel marker, makes
        // this a different operation even when the low generation bits match.
        for (u32 bit = 0; bit < 32; ++bit) {
            const u32 kOther = owner ^ (1u << bit);
            if (matches_downstream_send_target(owner, kOther, 0) ||
                matches_downstream_send_target(kOther, owner, 0))
                return false;
        }
        // Even equality cannot turn a cancel-tagged pair into a SEND target.
        const u32 kCancel = owner | kNonUpstreamSendCancelBit;
        if (matches_downstream_send_target(kCancel, kCancel, 0)) return false;
    }
    return true;
}

static_assert(downstream_send_target_contract(),
              "Downstream send completion violates target identity");

}  // namespace rut
