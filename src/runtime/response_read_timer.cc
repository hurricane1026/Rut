#include "rut/runtime/response_read_timer.h"

#include "rut/common/types.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/io_timespec.h"

#include <errno.h>
#include <stdint.h>

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

// Cover each millisecond remainder at the bottom and top of
// the input range, including the first carry into a whole second.
consteval bool timer_timespec_contract() {
    constexpr u32 kBases[] = {0, 1000, UINT32_MAX - 999};
    for (const u32 kBase : kBases) {
        for (u32 fraction = 0; fraction < 1000; ++fraction) {
            const u32 kMs = kBase + fraction;
            const auto kTime = io_timespec_from_ms(kMs);
            if (kTime.tv_sec < 0 || kTime.tv_nsec < 0 || kTime.tv_nsec >= 1'000'000'000 ||
                static_cast<u64>(kTime.tv_sec) * 1'000'000'000 + kTime.tv_nsec !=
                    static_cast<u64>(kMs) * 1'000'000 ||
                valid_positive_io_timespec(kTime) != (kMs != 0))
                return false;
        }
    }
    // Owner validation also handles timespecs not produced by this converter.
    return valid_positive_io_timespec({0, 1}) && valid_positive_io_timespec({0, 999'999'999}) &&
           !valid_positive_io_timespec({-1, 1}) && !valid_positive_io_timespec({1, -1}) &&
           !valid_positive_io_timespec({1, 1'000'000'000});
}

static_assert(timer_timespec_contract(), "Timer timespec violates duration contract");

}  // namespace
}  // namespace rut
