#pragma once

#include "rut/common/types.h"
#include "rut/jit/handler_abi.h"

namespace rut::harness {

// One explicitly ordered synthetic completion. Schedules are immutable input;
// reset() makes the environment reusable without retaining run state.
struct DeterministicCompletion {
    static constexpr u32 kAnyTarget = ~u32{0};

    jit::YieldKind kind = jit::YieldKind::Timer;
    i32 result = 0;
    u64 at_us = 0;
    u32 order = 0;
    u32 target_id = kAnyTarget;
    const u8* data = nullptr;
    u32 data_len = 0;
    bool logical_fault_point = false;
    bool injected_fault = false;
};

enum class CompletionStatus : u8 {
    Ready = 0,
    Empty,
    KindMismatch,
    TargetMismatch,
    TooEarly,
    InvalidSchedule,
    TimeLimit,
};

struct DeterministicEnvironment {
    const DeterministicCompletion* completions = nullptr;
    u32 completion_count = 0;
    u32 cursor = 0;
    u64 now_us = 0;
    bool schedule_valid = true;

    void reset(const DeterministicCompletion* scheduled = nullptr, u32 count = 0);

    CompletionStatus next(jit::YieldKind yielded,
                          u32 yielded_target,
                          u64 earliest_timer_at_us,
                          u64 max_virtual_time_us,
                          DeterministicCompletion& completion);

    CompletionStatus complete_timer(u32 delay_ms,
                                    u64 max_virtual_time_us,
                                    DeterministicCompletion& completion);

    CompletionStatus complete_now(jit::YieldKind kind,
                                  i32 result,
                                  DeterministicCompletion& completion);
};

}  // namespace rut::harness
