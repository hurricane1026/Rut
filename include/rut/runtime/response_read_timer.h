#pragma once

#include "rut/runtime/io_event.h"

namespace rut {

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
constexpr TimerCompletion consume_response_read_timer_owner(ResponseReadTimerPhase phase,
                                                            u32 owner_generation,
                                                            u32 tagged_generation,
                                                            bool& target_owned,
                                                            bool& cancel_owned) {
    const u32 generation = tagged_generation & kResponseReadTimerGenerationMask;
    if (generation == 0 || generation != owner_generation) return TimerCompletion::Rejected;
    const bool cancel = (tagged_generation & kResponseReadTimerCancelBit) != 0;
    switch (phase) {
        case ResponseReadTimerPhase::None:
            return TimerCompletion::Rejected;
        case ResponseReadTimerPhase::Armed:
            if (cancel || cancel_owned) return TimerCompletion::Rejected;
            break;
        case ResponseReadTimerPhase::CancelPending:
            break;
        default:
            return TimerCompletion::Rejected;
    }
    bool& owned = cancel ? cancel_owned : target_owned;
    if (!owned) return TimerCompletion::Rejected;
    owned = false;
    return target_owned || cancel_owned ? TimerCompletion::Pending : TimerCompletion::Drained;
}
#pragma GCC diagnostic pop

}  // namespace rut
