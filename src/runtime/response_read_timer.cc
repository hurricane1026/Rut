#include "rut/runtime/response_read_timer.h"

#include "rut/common/types.h"
#include "rut/runtime/io_event.h"

#include <errno.h>
#include <stdint.h>

namespace rut {
namespace {

consteval bool timer_rearm_contract() {
    constexpr u64 kMs = 1'000'000;
    constexpr u64 kMaxDelay = u64{UINT32_MAX} * kMs;
    // Hold the deadline at UINT64_MAX and move now across rounding, expiry,
    // and saturation boundaries. Check the interval represented by the
    // result independently of the division used in production.
    constexpr u64 kIntervals[] = {0,
                                  1,
                                  kMs - 1,
                                  kMs,
                                  kMs + 1,
                                  kMaxDelay - kMs,
                                  kMaxDelay - 1,
                                  kMaxDelay,
                                  kMaxDelay + 1,
                                  UINT64_MAX - 1};
    for (const u64 kRemaining : kIntervals) {
        const u32 kDelay =
            response_read_timer_remaining_ms(1, UINT64_MAX - 1, UINT64_MAX - kRemaining);
        if (kRemaining == 0) {
            if (kDelay != 0) return false;
        } else if (kRemaining > kMaxDelay) {
            if (kDelay != UINT32_MAX) return false;
        } else if (kDelay == 0 || u64{kDelay} * kMs < kRemaining ||
                   u64{kDelay - 1} * kMs >= kRemaining) {
            return false;
        }
    }
    return response_read_timer_remaining_ms(0, kMs, 1) == 0 &&
           response_read_timer_remaining_ms(UINT64_MAX - 1, 2, UINT64_MAX - 1) == 0 &&
           response_read_timer_remaining_ms(10, 1, 12) == 0;
}

static_assert(timer_rearm_contract(), "Response timer violates rearm interval contract");

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

// Check every transition of the two-bit observation set, including the
// second completion in either order and a replay after both have arrived.
consteval bool timer_batch_observation_contract() {
    constexpr u32 kGeneration = 7;
    constexpr u32 kIncoming[] = {0, kGeneration, kGeneration + (1u << 16)};
    for (unsigned prior = 0; prior < 4; ++prior) {
        for (unsigned kind = 1; kind <= 2; ++kind) {
            for (const u32 kId : kIncoming) {
                for (unsigned flags = 0; flags < 4; ++flags) {
                    const bool kOwnerValid = (flags & 1u) != 0;
                    const bool kCleanPayload = (flags & 2u) == 0;
                    IoEvent event{};
                    event.type = IoEventType::ResponseReadTimer;
                    event.non_upstream_generation =
                        kId | (kind == 2 ? kResponseReadTimerCancelBit : 0);
                    event.result = kind == 2 ? 0 : -ETIME;
                    event.more = !kCleanPayload;
                    ResponseReadTimerBatch batch{bool(prior & 1u), bool(prior & 2u)};
                    const bool kExpected =
                        (prior & kind) == 0 && kOwnerValid && kId == kGeneration && kCleanPayload;
                    if (batch.observe(event, kOwnerValid, kGeneration) != kExpected) return false;
                    const unsigned kAfter = prior | kind;
                    if (batch.target_seen != bool(kAfter & 1u) ||
                        batch.cancel_seen != bool(kAfter & 2u))
                        return false;
                }
            }
        }
    }
    return true;
}

static_assert(timer_batch_observation_contract(),
              "Response timer violates batch observation contract");

}  // namespace
}  // namespace rut
