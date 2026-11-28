#pragma once

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
#include "rut/runtime/io_event.h"

#include <stdint.h>

namespace rut {

// An early completion rearms for the remaining interval, rounded up to a
// millisecond. Missing, unrepresentable or elapsed deadlines cannot rearm.
[[nodiscard]] constexpr u32 response_read_timer_remaining_ms(u64 last_progress_ns,
                                                             u64 timeout_ns,
                                                             u64 now_ns) {
    u64 deadline = 0;
    // RUT_INTEGER_RANGE: both timestamps can use the full u64 range.
    if (last_progress_ns == 0 || add_overflow(last_progress_ns, timeout_ns, &deadline) ||
        now_ns >= deadline)
        return 0;
    // The guard establishes now_ns < deadline, so both differences fit u64.
    const u64 kRounded = wrapping_sub(wrapping_sub(deadline, now_ns), u64{1});
    const auto kMillis = bounded_quotient<1'000'000>(kRounded) + range_int<1, 2>{};
    return kMillis.min(range_int<UINT32_MAX, i64{UINT32_MAX} + 1>{}).to<u32>();
}

// Batch evidence records which completions arrived, including rejected ones.
// Kernel ownership is consumed separately during settlement.
struct ResponseReadTimerBatch {
    bool target_seen = false;
    bool cancel_seen = false;

    [[nodiscard]] constexpr bool observe(const IoEvent& event, bool owner_valid, u32 generation) {
        const u32 kTag = event.non_upstream_generation;
        bool& seen = (kTag & kResponseReadTimerCancelBit) ? cancel_seen : target_seen;
        const bool kFirst = !seen;
        seen = true;
        return kFirst && owner_valid && (kTag & kResponseReadTimerGenerationMask) == generation &&
               valid_response_read_timer_transport_event(event);
    }
};

// Kernel ownership for the generic precise response-read timer. CancelPending
// retains the immutable identity until both the timeout target and the cancel
// SQE completions have been harvested, in either order.
enum class ResponseReadTimerPhase : u8 {
    None,
    Armed,
    CancelPending,
};

enum class TimerCompletion : u8 { Rejected, Pending, Drained };

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch-enum"
#pragma GCC diagnostic error "-Wswitch"
[[nodiscard]] constexpr TimerCompletion consume_response_read_timer_owner(
    ResponseReadTimerPhase phase,
    u32 owner_generation,
    u32 tagged_generation,
    bool* target_owned,
    bool* cancel_owned) {
    const u32 generation = tagged_generation & kResponseReadTimerGenerationMask;
    if (generation == 0 || generation != owner_generation) return TimerCompletion::Rejected;
    const bool cancel = (tagged_generation & kResponseReadTimerCancelBit) != 0;
    switch (phase) {
        case ResponseReadTimerPhase::None:
            return TimerCompletion::Rejected;
        case ResponseReadTimerPhase::Armed:
            if (cancel || *cancel_owned) return TimerCompletion::Rejected;
            break;
        case ResponseReadTimerPhase::CancelPending:
            break;
        default:
            return TimerCompletion::Rejected;
    }
    bool* owned = cancel ? cancel_owned : target_owned;
    if (!*owned) return TimerCompletion::Rejected;
    *owned = false;
    return *target_owned || *cancel_owned ? TimerCompletion::Pending : TimerCompletion::Drained;
}
#pragma GCC diagnostic pop

}  // namespace rut
