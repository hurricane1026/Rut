#include "rut/harness/deterministic_environment.h"

namespace rut::harness {

void DeterministicEnvironment::reset(const DeterministicCompletion* scheduled, u32 count) {
    completions = scheduled;
    completion_count = count;
    cursor = 0;
    now_us = 0;
    schedule_valid = count == 0 || scheduled != nullptr;
    if (!schedule_valid) return;

    for (u32 i = 1; i < count; i++) {
        const auto& previous = scheduled[i - 1];
        const auto& current = scheduled[i];
        if (current.at_us < previous.at_us || current.order <= previous.order) {
            schedule_valid = false;
            return;
        }
    }
}

CompletionStatus DeterministicEnvironment::next(jit::YieldKind yielded,
                                                u32 yielded_target,
                                                u64 earliest_at_us,
                                                u64 max_virtual_time_us,
                                                DeterministicCompletion& completion) {
    if (!schedule_valid) return CompletionStatus::InvalidSchedule;
    if (cursor >= completion_count) return CompletionStatus::Empty;

    const DeterministicCompletion candidate = completions[cursor];
    if (yielded != jit::YieldKind::Any && yielded != candidate.kind)
        return CompletionStatus::KindMismatch;
    if (candidate.target_id != DeterministicCompletion::kAnyTarget &&
        candidate.target_id != yielded_target)
        return CompletionStatus::TargetMismatch;
    if (candidate.at_us < earliest_at_us) return CompletionStatus::TooEarly;
    if (candidate.at_us < now_us || candidate.at_us > max_virtual_time_us)
        return CompletionStatus::TimeLimit;

    completion = candidate;
    now_us = candidate.at_us;
    cursor++;
    return CompletionStatus::Ready;
}

CompletionStatus DeterministicEnvironment::complete_timer(u32 delay_ms,
                                                          u64 max_virtual_time_us,
                                                          DeterministicCompletion& completion) {
    const u64 delta_us = static_cast<u64>(delay_ms) * 1000u;
    if (delta_us > max_virtual_time_us - now_us) return CompletionStatus::TimeLimit;

    now_us += delta_us;
    completion = {};
    completion.kind = jit::YieldKind::Timer;
    completion.at_us = now_us;
    return CompletionStatus::Ready;
}

CompletionStatus DeterministicEnvironment::complete_now(jit::YieldKind kind,
                                                        i32 result,
                                                        DeterministicCompletion& completion) {
    if (!schedule_valid) return CompletionStatus::InvalidSchedule;
    completion = {};
    completion.kind = kind;
    completion.result = result;
    completion.at_us = now_us;
    return CompletionStatus::Ready;
}

}  // namespace rut::harness
