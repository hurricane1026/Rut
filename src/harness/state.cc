#include "rut/harness/state.h"

#include "rut/jit/runtime_helpers.h"

namespace rut::harness {

void ScenarioState::reset() {
    rate_limiter.reset();
    global_rate_limiter.reset();
    rut_helper_cache_reset_local_state();
    initialized = false;
    active_group = 0;
    active_target = nullptr;
}

bool ScenarioState::prepare(StateIsolation isolation, u64 group, const void* target_identity) {
    bool should_reset = false;
    switch (isolation) {
        case StateIsolation::Run:
            should_reset = true;
            break;
        case StateIsolation::Group:
            should_reset =
                !initialized || active_group != group || active_target != target_identity;
            break;
        case StateIsolation::Process:
            should_reset = !initialized || active_target != target_identity;
            break;
        case StateIsolation::External:
            should_reset = false;
            break;
    }
    if (should_reset) reset();
    initialized = true;
    active_group = group;
    active_target = target_identity;
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
