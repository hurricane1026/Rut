#pragma once

#include "rut/common/types.h"
#include "rut/runtime/rate_limit.h"

namespace rut::harness {

enum class StateIsolation : u8 {
    Run = 0,
    Group,
    Process,
    External,
};

// State explicitly owned by a sequential scenario driver. Cache tables remain
// per-thread/per-shard in the runtime; this object controls their reset boundary
// and directly owns the scenario's per-shard/global rate-limit buckets.
struct ScenarioState {
    RateLimiter rate_limiter{};
    GlobalRateLimiter global_rate_limiter{};
    bool initialized = false;
    u64 active_group = 0;
    const void* active_target = nullptr;

    void reset();
    bool prepare(StateIsolation isolation, u64 group, const void* target_identity);
    void finish(StateIsolation isolation);
};

const char* state_isolation_name(StateIsolation isolation);

}  // namespace rut::harness
