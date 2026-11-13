#include "rut/common/types.h"
#include "rut/compiler/concurrency_verifier.h"

namespace rut::verify {

bool build_wait_protocol_model(u8 first_arms, u8 second_arms, WaitProtocolModel& out) {
    out.model = {};
    out.operation_count = 0;
    out.reclaim_action = kNoIndex;
    for (u32 i = 0; i < 4; ++i) {
        out.win_actions[i] = kNoIndex;
        out.drain_actions[i] = kNoIndex;
        out.cancel_ack_actions[i] = kNoIndex;
    }
    if (!first_arms || !second_arms || ((first_arms | second_arms) & ~u8{63})) return false;
    u32 counts[2]{};
    for (u32 bit = 0; bit < 6; ++bit) {
        if (first_arms & (1u << bit)) ++counts[0];
        if (second_arms & (1u << bit)) ++counts[1];
    }
    if (counts[0] > 2 || counts[1] > 2) return false;

    constexpr u64 kClosed = u64{1} << 12;
    constexpr u64 kFinished = u64{1} << 13;
    const u32 kOperationCount = counts[0] + counts[1];
    const u64 kPending = (u64{1} << kOperationCount) - 1;
    const u64 kSlots = kPending << 4;
    const u64 kCancels = kPending << 20;
    const u64 kWaiting = (u64{1} << 8) | (u64{1} << 9);
    const u64 kResumed = (u64{1} << 10) | (u64{1} << 11);
    const u16 kDraining = static_cast<u16>(kOperationCount + 4);
    Model& model = out.model;
    model.actor_count = static_cast<u8>(kOperationCount + 1);
    model.actors[0] = {static_cast<u16>(kDraining + 2), 0, static_cast<u16>(kDraining + 1)};
    model.actions = out.actions;
    model.invariants = out.invariants;
    model.terminal_clear = kPending | kSlots | kWaiting | kCancels;
    model.weak_fairness = kPending;
    out.operation_count = static_cast<u8>(kOperationCount);

    const auto kAdd = [&](Action action) -> u32 {
        const u32 kIndex = model.action_count++;
        out.actions[kIndex] = action;
        return kIndex;
    };
    for (u32 generation = 0; generation < 2; ++generation) {
        const u32 kArmCount = counts[generation];
        const u32 kOperationBase = generation == 0 ? 0 : counts[0];
        const u16 kBase = generation == 0 ? 0 : static_cast<u16>(counts[0] + 2);
        const u64 kWaitingBit = u64{1} << (8 + generation);
        const u64 kResumedBit = u64{1} << (10 + generation);
        const u64 kSeenBit = u64{1} << (14 + generation);
        const u64 kGenerationSlots = ((u64{1} << kArmCount) - 1) << (4 + kOperationBase);
        for (u32 arm = 0; arm < kArmCount; ++arm) {
            const u32 kOperation = kOperationBase + arm;
            const u64 kPendingBit = u64{1} << kOperation;
            const u64 kSlotBit = kPendingBit << 4;
            const u64 kStartedBit = kPendingBit << 16;
            const u64 kCancelBit = kPendingBit << 20;
            const u64 kCancelIssuedBit = kPendingBit << 24;
            const u8 kActor = static_cast<u8>(kOperation + 1);
            model.actors[kActor] = {2, 0, 1};
            out.invariants[model.invariant_count++] = {kSlotBit, 0, kPendingBit, 0};

            Action submit{};
            submit.from = static_cast<u16>(kBase + arm);
            submit.to = static_cast<u16>(submit.from + 1);
            submit.set = kPendingBit | kSlotBit | kStartedBit;
            submit.assert_clear = kPendingBit | kSlotBit | kWaiting | kClosed;
            (void)kAdd(submit);

            Action win{};
            win.actor = kActor;
            win.fairness = static_cast<u8>(kOperation);
            win.to = 0;
            win.guard_set = kPendingBit | kSlotBit | kWaitingBit;
            win.assert_set = kWaitingBit | kSlotBit;
            win.assert_clear = kSeenBit | kClosed;
            win.clear = kPendingBit | kGenerationSlots | kWaitingBit;
            win.set = kResumedBit | kSeenBit;
            out.win_actions[kOperation] = kAdd(win);

            // This is also the target CQE after cancellation. No callback
            // ownership remains, so it may release IO but cannot resume.
            Action drain{};
            drain.actor = kActor;
            drain.fairness = static_cast<u8>(kOperation);
            drain.to = 0;
            drain.guard_set = kPendingBit;
            drain.guard_clear = kSlotBit;
            drain.clear = kPendingBit;
            drain.assert_clear = kSlotBit;
            out.drain_actions[kOperation] = kAdd(drain);

            // A cancel owns a separate completion. Its acknowledgement can
            // arrive before or after the target final completion; neither one
            // permits reclaim while the other is outstanding. If the target
            // already finished, no cancellation needs to be submitted.
            Action cancel{};
            cancel.actor = kActor;
            cancel.guard_set = kPendingBit;
            cancel.guard_clear = kSlotBit | kCancelIssuedBit;
            cancel.set = kCancelBit | kCancelIssuedBit;
            (void)kAdd(cancel);

            Action acknowledge{};
            acknowledge.actor = kActor;
            acknowledge.fairness = static_cast<u8>(kOperation);
            acknowledge.guard_set = kCancelBit;
            acknowledge.clear = kCancelBit;
            out.cancel_ack_actions[kOperation] = kAdd(acknowledge);

            Action retire{};
            retire.actor = kActor;
            retire.to = 1;
            retire.guard_set = kStartedBit;
            retire.guard_clear = kPendingBit | kCancelBit;
            (void)kAdd(retire);

            // Close/submit failure may occur before this operation is armed.
            for (u32 choice = 0; choice < 2; ++choice) {
                Action unused{};
                unused.actor = kActor;
                unused.to = 1;
                unused.guard_set = choice == 0 ? kClosed : kFinished;
                unused.guard_clear = kStartedBit;
                (void)kAdd(unused);
            }
        }
        Action publish{};
        publish.from = static_cast<u16>(kBase + kArmCount);
        publish.to = static_cast<u16>(publish.from + 1);
        publish.set = kWaitingBit;
        publish.assert_clear = kWaiting | kResumed | kClosed;
        (void)kAdd(publish);

        Action resume{};
        resume.from = publish.to;
        resume.to = static_cast<u16>(resume.from + 1);
        resume.guard_set = kResumedBit;
        resume.assert_clear = kGenerationSlots | kWaitingBit;
        resume.clear = kResumedBit;
        if (generation == 1) resume.set = kFinished;
        (void)kAdd(resume);
    }
    // Close, operation failure and submit failure are all fail-closed exits;
    // they can happen before arming, after partial arming, or while waiting.
    for (u16 location = 0; location < kDraining; ++location) {
        Action close{};
        close.from = location;
        close.to = kDraining;
        close.set = kClosed | kFinished;
        close.clear = kSlots | kWaiting | kResumed;
        (void)kAdd(close);
    }
    Action reclaim{};
    reclaim.from = kDraining;
    reclaim.to = static_cast<u16>(kDraining + 1);
    reclaim.guard_clear = kPending | kCancels;
    reclaim.assert_clear = kPending | kSlots | kWaiting | kCancels;
    out.reclaim_action = kAdd(reclaim);
    out.invariants[model.invariant_count++] = {kClosed, 0, 0, kSlots | kWaiting};
    return true;
}

bool build_wait_protocol_model(u8 arms, WaitProtocolModel& out) {
    return build_wait_protocol_model(arms, arms, out);
}

}  // namespace rut::verify
