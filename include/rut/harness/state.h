#pragma once

#include "rut/common/shard_limits.h"
#include "rut/common/types.h"
#include "rut/runtime/rate_limit.h"
#include <memory>

namespace rut {
struct CacheLocalState;
}

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
    std::unique_ptr<RateLimiter> rate_limiters[kMaxShards]{};
    GlobalRateLimiter global_rate_limiter{};
    bool initialized = false;
    u64 active_group = 0;
    const void* active_target = nullptr;
    u64 active_target_generation = 0;
    CacheLocalState* cache_state = nullptr;

    ScenarioState() = default;
    ~ScenarioState();
    ScenarioState(const ScenarioState&) = delete;
    ScenarioState& operator=(const ScenarioState&) = delete;

    void reset();
    bool ensure_cache_state();
    RateLimiter* rate_limiter_for_shard(u32 shard_id);
    bool prepare(StateIsolation isolation,
                 u64 group,
                 const void* target_identity,
                 u64 target_generation);
    void finish(StateIsolation isolation);
};

const char* state_isolation_name(StateIsolation isolation);

}  // namespace rut::harness
