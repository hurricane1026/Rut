#include "rut/runtime/jit_dispatch.h"

namespace rut {
namespace {

// Check both directions: every accepted event reports a declared arm, and
// every arm of an event wait can be delivered. A nonzero payload exposes the
// optional timer to the eligibility check; the loop checks whether it is armed.
consteval bool completion_contract_matches() {
    using jit::YieldArm;
    using jit::YieldKind;
    for (unsigned raw = 0; raw <= 255; ++raw) {
        const auto wait = static_cast<YieldKind>(raw);
        const auto arms = jit::yield_contract(wait, 1);
        const bool event_wait = arms.primary != YieldArm::None && arms.primary != YieldArm::Timer;
        bool saw_primary = false;
        bool saw_secondary = false;
        for (unsigned i = 0; i <= static_cast<unsigned>(IoEventType::Count); ++i) {
            const auto event = static_cast<IoEventType>(i);
            const auto tag = yield_kind_from_event(event);
            const auto completion = jit::yield_contract(tag, 1);
            if (tag == YieldKind::Any || completion.secondary != YieldArm::None) return false;
            const bool primary =
                completion.primary != YieldArm::None && completion.primary == arms.primary;
            const bool secondary =
                completion.primary != YieldArm::None && completion.primary == arms.secondary;
            if (yield_kind_matches_event(wait, event) != (event_wait && (primary || secondary)))
                return false;
            saw_primary |= primary;
            saw_secondary |= secondary;
        }
        if (event_wait && (!saw_primary || (arms.secondary != YieldArm::None && !saw_secondary)))
            return false;
    }
    return yield_kind_from_event(IoEventType::Timeout) == YieldKind::Timer &&
           yield_kind_from_event(IoEventType::HandlerTimer) == YieldKind::Timer;
}

static_assert(completion_contract_matches(),
              "Event eligibility disagrees with handler completion contract");

}  // namespace
}  // namespace rut
