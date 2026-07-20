#include "rut/harness/state.h"

#include "rut/jit/runtime_helpers.h"

namespace rut::harness {

ScenarioState::~ScenarioState() {
    rut_helper_cache_destroy_local_state(cache_state);
}

bool ScenarioState::ensure_cache_state() {
    if (cache_state == nullptr) cache_state = rut_helper_cache_create_local_state();
    return cache_state != nullptr;
}

void ScenarioState::reset() {
    for (auto& rate_limiter : rate_limiters) {
        if (rate_limiter) rate_limiter->reset();
    }
    global_rate_limiter.reset();
    rut_helper_cache_reset_state(cache_state);
    initialized = false;
    active_group = 0;
    active_target = nullptr;
    active_target_generation = 0;
}

RateLimiter* ScenarioState::rate_limiter_for_shard(u32 shard_id) {
    if (shard_id >= kMaxShards) return nullptr;
    auto& limiter = rate_limiters[shard_id];
    if (!limiter) limiter = std::make_unique<RateLimiter>();
    return limiter.get();
}

bool ScenarioState::prepare(StateIsolation isolation,
                            u64 group,
                            const void* target_identity,
                            u64 target_generation) {
    bool should_reset = false;
    switch (isolation) {
        case StateIsolation::Run:
            should_reset = true;
            break;
        case StateIsolation::Group:
            should_reset = !initialized || active_group != group ||
                           active_target != target_identity ||
                           active_target_generation != target_generation;
            break;
        case StateIsolation::Process:
            should_reset = !initialized || active_target != target_identity ||
                           active_target_generation != target_generation;
            break;
        case StateIsolation::External:
            should_reset = false;
            break;
    }
    if (should_reset) reset();
    initialized = true;
    active_group = group;
    active_target = target_identity;
    active_target_generation = target_generation;
    return should_reset;
}

void ScenarioState::finish(StateIsolation isolation) {
    if (isolation != StateIsolation::Run) return;
    reset();
}

const char* state_isolation_name(StateIsolation isolation) {
    switch (isolation) {
        case StateIsolation::Run:
            return "run";
        case StateIsolation::Group:
            return "group";
        case StateIsolation::Process:
            return "process";
        case StateIsolation::External:
            return "external";
    }
    return "unknown";
}

}  // namespace rut::harness
