#pragma once

#include "rut/harness/connection_execution.h"
#include "rut/harness/handler_execution.h"
#include "rut/harness/scripted_environment.h"
#include "rut/harness/source_target.h"
#include "rut/harness/state.h"
#include "rut/runtime/control_plane_mutation.h"

namespace rut::harness {

struct ScenarioExpectation {
    bool enabled = false;
    jit::HandlerAction action = jit::HandlerAction::ReturnStatus;
    u16 value = 0;  // status code or upstream id, selected by action
};

struct ScenarioSpec {
    SourceTarget* target = nullptr;
    Str path{};
    u8 method = 0;
    const u8* request_data = nullptr;
    u32 request_len = 0;
    u32 peer_addr = 0;
    u16 peer_port = 0;
    u32 shard_id = 0;
    u64 now_us = 0;
    StateIsolation state_isolation = StateIsolation::Run;
    u64 state_group = 0;
    ScenarioState* state = nullptr;
    ScriptedEnvironment* environment = nullptr;
    // Explicit value-only fixture for stats()/metrics(). The scenario must
    // declare ControlPlaneSnapshot; the copied value is stable across resumes.
    const jit::ControlPlaneSnapshot* control_plane_snapshot = nullptr;
    // Deterministic mutation state. Declaration and fixture must match; the
    // pointer remains stable across resumes and follows state_isolation reset
    // boundaries while preserving its configured generation and authority.
    ControlPlaneMutationPort* control_plane_mutation = nullptr;
    bool auto_complete_timers = true;
    ScenarioExpectation expected{};
};

struct ScenarioResult {
    HarnessResult harness{};
    jit::HandlerResult terminal{};
    bool has_terminal = false;
    u32 route_index = 0;
    bool route_selected = false;
    u64 connection_invariant_violations = 0;
};

ScenarioResult drive_scenario(const ScenarioSpec& scenario, const HarnessSpec& harness);

}  // namespace rut::harness
