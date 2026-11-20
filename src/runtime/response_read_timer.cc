#include "rut/runtime/response_read_timer.h"

namespace rut {
namespace {

// Model outstanding kernel operations as a two-bit set. Checking every edge
// (including rejection self-loops) also covers repeated and reordered CQEs.
consteval bool timer_ownership_conserved() {
    using enum ResponseReadTimerPhase;
    constexpr ResponseReadTimerPhase phases[] = {None, Armed, CancelPending};
    constexpr u32 generations[] = {0, 1, 2, kResponseReadTimerGenerationMask};
    constexpr unsigned target = 1, cancel = 2;
    for (const auto phase : phases) {
        for (unsigned owners = 0; owners <= (target | cancel); ++owners) {
            for (const auto owner_generation : generations) {
                for (const auto generation : generations) {
                    for (unsigned arriving = target; arriving <= cancel; ++arriving) {
                        const bool live =
                            phase == CancelPending || (phase == Armed && owners == target);
                        const bool accepts = live && generation != 0 &&
                                             generation == owner_generation &&
                                             (owners & arriving) != 0;
                        const unsigned remaining = accepts ? owners & ~arriving : owners;
                        const auto expected = !accepts    ? TimerCompletion::Rejected
                                              : remaining ? TimerCompletion::Pending
                                                          : TimerCompletion::Drained;
                        bool target_owned = owners & target;
                        bool cancel_owned = owners & cancel;
                        const u32 tag =
                            generation | (arriving == cancel ? kResponseReadTimerCancelBit : 0);
                        const auto result = consume_response_read_timer_owner(
                            phase, owner_generation, tag, target_owned, cancel_owned);
                        if (result != expected || target_owned != bool(remaining & target) ||
                            cancel_owned != bool(remaining & cancel))
                            return false;
                    }
                }
            }
        }
    }
    return true;
}

static_assert(timer_ownership_conserved(),
              "Response-read timer completion violates ownership contract");

}  // namespace
}  // namespace rut
