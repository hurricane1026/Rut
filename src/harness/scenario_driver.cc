#include "rut/harness/scenario_driver.h"

#include "rut/runtime/http_parser.h"
#include "rut/runtime/rate_limit_enforce.h"
#include "rut/runtime/route_canon.h"

namespace rut::harness {
namespace {

void copy_detail(HarnessResult& result, const char* detail) {
    u32 i = 0;
    while (detail[i] != '\0' && i + 1 < sizeof(result.detail)) {
        result.detail[i] = detail[i];
        i++;
    }
    result.detail[i] = '\0';
}

bool declared(CapabilitySet declared_set, Capability capability) {
    return declared_set.has(capability);
}

bool str_equal(Str lhs, Str rhs) {
    if (lhs.len != rhs.len) return false;
    for (u32 i = 0; i < lhs.len; i++) {
        if (lhs.ptr[i] != rhs.ptr[i]) return false;
    }
    return true;
}

bool expectation_matches(const ScenarioExpectation& expected, const jit::HandlerResult& terminal) {
    if (!expected.enabled) return true;
    if (terminal.action != expected.action) return false;
    if (terminal.action == jit::HandlerAction::ReturnStatus)
        return terminal.status_code == expected.value;
    if (terminal.action == jit::HandlerAction::Forward)
        return terminal.upstream_id == expected.value;
    return false;
}

u32 request_header_end(const u8* data, u32 len) {
    if (data == nullptr) return 0;
    for (u32 i = 0; i + 3 < len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n')
            return i + 4;
    }
    return len;
}

bool publish_terminal(const HarnessSpec& spec,
                      HarnessResult& result,
                      const jit::HandlerResult& terminal,
                      u64 timestamp_us) {
    if (result.semantic_events >= spec.limits.max_semantic_events) {
        result.outcome = Outcome::Failed;
        result.has_reached_limit = true;
        result.reached_limit = LimitKind::SemanticEvents;
        copy_detail(result, "semantic-events limit reached");
        return false;
    }

    Observation event{};
    event.kind = terminal.action == jit::HandlerAction::ReturnStatus
                     ? ObservationKind::ResponseProduced
                     : ObservationKind::UpstreamSelected;
    event.phase = Phase::Observe;
    event.sequence = result.semantic_events;
    event.timestamp_us = timestamp_us;
    event.value0 = terminal.action == jit::HandlerAction::ReturnStatus ? terminal.status_code
                                                                       : terminal.upstream_id;
    result.semantic_events++;
    if (spec.observations.publish(event)) return true;

    result.outcome = Outcome::Mismatched;
    copy_detail(result, "observation rejected by oracle");
    return false;
}

bool publish_route_selected(const HarnessSpec& spec,
                            HarnessResult& result,
                            u32 route_index,
                            const RouteEntry& route,
                            u64 timestamp_us) {
    if (result.semantic_events >= spec.limits.max_semantic_events) {
        result.outcome = Outcome::Failed;
        result.has_reached_limit = true;
        result.reached_limit = LimitKind::SemanticEvents;
        copy_detail(result, "semantic-events limit reached");
        return false;
    }

    Observation event{};
    event.kind = ObservationKind::RouteSelected;
    event.phase = Phase::Start;
    event.sequence = result.semantic_events;
    event.timestamp_us = timestamp_us;
    event.value0 = route_index;
    event.label = {route.path, route.path_len};
    result.semantic_events++;
    if (spec.observations.publish(event)) return true;

    result.outcome = Outcome::Mismatched;
    result.phase = Phase::Observe;
    copy_detail(result, "observation rejected by oracle");
    return false;
}

}  // namespace

ScenarioResult drive_scenario(const ScenarioSpec& scenario, const HarnessSpec& harness) {
    ScenarioResult out{};
    out.harness = validate_spec(harness);
    if (out.harness.outcome != Outcome::Passed) return out;
    out.harness.phase = Phase::Prepare;
    out.harness.cleanup = CleanupOutcome::NotRun;

    if (harness.layer != ExecutionLayer::Connection) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "typed scenario requires connection layer");
        return out;
    }
    if (!declared(harness.required_capabilities, Capability::SyntheticIo) ||
        !declared(harness.required_capabilities, Capability::VirtualTime)) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "scenario must declare synthetic-io and virtual-time");
        return out;
    }
    if (scenario.environment != nullptr && scenario.environment->has_upstream_steps() &&
        !declared(harness.required_capabilities, Capability::ScriptedUpstream)) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "scripted upstream capability was not declared");
        return out;
    }
    if (scenario.environment != nullptr && scenario.environment->has_faults() &&
        !declared(harness.required_capabilities, Capability::ScriptedFaults)) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "scripted faults capability was not declared");
        return out;
    }
    if (scenario.target == nullptr || !scenario.target->prepared) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "scenario source target is not prepared");
        return out;
    }
    if (scenario.state_isolation != StateIsolation::Run && scenario.state == nullptr) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "shared state isolation requires an explicit ScenarioState");
        return out;
    }
    if (scenario.shard_id >= kMaxShards) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "scenario shard id is out of range");
        return out;
    }
    if (scenario.path.ptr == nullptr || scenario.path.len == 0 ||
        scenario.path.len >= Connection::kMaxReqPathLen) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "scenario path is invalid or too long");
        return out;
    }
    if (scenario.request_len > harness.limits.max_input_bytes ||
        (scenario.request_len != 0 && scenario.request_data == nullptr)) {
        out.harness.outcome = scenario.request_data == nullptr ? Outcome::Invalid : Outcome::Failed;
        out.harness.cleanup = CleanupOutcome::Clean;
        if (out.harness.outcome == Outcome::Failed) {
            out.harness.has_reached_limit = true;
            out.harness.reached_limit = LimitKind::InputBytes;
        }
        copy_detail(out.harness,
                    out.harness.outcome == Outcome::Failed ? "input-bytes limit reached"
                                                           : "scenario request data is null");
        return out;
    }
    out.harness.input_bytes = scenario.request_len;

    Str routing_path = scenario.path;
    u8 routing_method = scenario.method;
    ParsedRequest parsed_request{};
    if (scenario.request_len != 0) {
        HttpParser parser{};
        parser.reset();
        parsed_request.reset();
        if (parser.parse(scenario.request_data, scenario.request_len, &parsed_request) !=
            ParseStatus::Complete) {
            out.harness.outcome = Outcome::Invalid;
            out.harness.cleanup = CleanupOutcome::Clean;
            copy_detail(out.harness, "scenario request is not a complete HTTP request");
            return out;
        }
        if (parsed_request.method == HttpMethod::Unknown ||
            !str_equal(scenario.path, parsed_request.path) ||
            scenario.method != static_cast<u8>(parsed_request.method) + kRouteMethodGet) {
            out.harness.outcome = Outcome::Invalid;
            out.harness.cleanup = CleanupOutcome::Clean;
            copy_detail(out.harness, "scenario routing fields do not match request line");
            return out;
        }
        routing_path = parsed_request.path;
        routing_method = static_cast<u8>(parsed_request.method) + kRouteMethodGet;
    }

    ConnectionExecution connection{};
    connection.reset(scenario.peer_addr, scenario.peer_port, scenario.shard_id);
    for (u32 i = 0; i < routing_path.len; i++)
        connection.connection.req_path[i] = routing_path.ptr[i];
    connection.connection.req_path[routing_path.len] = '\0';
    connection.connection.req_path_canon =
        canonicalize_request({connection.connection.req_path, routing_path.len});
    connection.connection.req_method =
        routing_method >= kRouteMethodGet && routing_method <= kRouteMethodTrace
            ? routing_method - 1
            : static_cast<u8>(LogHttpMethod::Other);
    connection.connection.req_size = scenario.request_len;
    connection.connection.request_config = &scenario.target->program.config;

    RouteParam route_params[kMaxRouteParams]{};
    u32 route_param_count = 0;
    const RouteEntry* route =
        scenario.target->program.config.match_canonical(connection.connection.req_path_canon,
                                                        routing_method,
                                                        route_params,
                                                        &route_param_count,
                                                        kMaxRouteParams);
    if (route == nullptr) {
        out.harness.outcome = Outcome::Failed;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "scenario route did not match");
        connection.destroy();
        return out;
    }
    out.route_selected = true;
    out.route_index = static_cast<u32>(route - scenario.target->program.config.routes);
    if (!publish_route_selected(harness, out.harness, out.route_index, *route, scenario.now_us)) {
        connection.destroy();
        out.harness.cleanup = CleanupOutcome::Clean;
        return out;
    }

    activate_rut_program(scenario.target->program);
    ScenarioState local_state{};
    ScenarioState* state = scenario.state != nullptr ? scenario.state : &local_state;
    if (state->prepare(scenario.state_isolation,
                       scenario.state_group,
                       scenario.target,
                       scenario.target->generation))
        out.harness.state_resets++;
    struct StateFinish {
        ScenarioState* state;
        StateIsolation isolation;
        ~StateFinish() { state->finish(isolation); }
    } state_finish{state, scenario.state_isolation};

    bool rate_limited = false;
    if (route->rate_limit.count != 0) {
        RateLimiter* rate_limiter = state->rate_limiter_for_shard(scenario.shard_id);
        if (rate_limiter == nullptr) {
            out.harness.outcome = Outcome::Invalid;
            out.harness.cleanup = CleanupOutcome::Clean;
            copy_detail(out.harness, "scenario shard id is out of range");
            connection.destroy();
            return out;
        }
        RateLimitKeyInput key_input{};
        key_input.peer_addr = scenario.peer_addr;
        key_input.req_buf = scenario.request_data;
        key_input.req_header_end = request_header_end(scenario.request_data, scenario.request_len);
        key_input.path = connection.connection.req_path;
        key_input.path_len = routing_path.len;
        key_input.params = route_params;
        key_input.param_count = route_param_count;
        rate_limited = rate_limit_exceeded_with_limiters(*rate_limiter,
                                                         &state->global_rate_limiter,
                                                         route->rate_limit,
                                                         out.route_index,
                                                         key_input,
                                                         scenario.now_us);
    }

    bool needs_terminal_observation = false;
    if (rate_limited) {
        out.terminal = jit::HandlerResult::make_status(429);
        out.has_terminal = true;
        needs_terminal_observation = true;
        out.harness.outcome = Outcome::Passed;
        out.harness.phase = Phase::Observe;
        out.harness.cleanup = CleanupOutcome::Clean;
    } else if (route->action == RouteAction::Static) {
        out.terminal = jit::HandlerResult::make_status(route->status_code);
        out.has_terminal = true;
        needs_terminal_observation = true;
        out.harness.outcome = Outcome::Passed;
        out.harness.phase = Phase::Observe;
        out.harness.cleanup = CleanupOutcome::Clean;
    } else if (route->action == RouteAction::Proxy) {
        out.terminal = jit::HandlerResult::make_forward(route->upstream_id);
        out.has_terminal = true;
        needs_terminal_observation = true;
        out.harness.outcome = Outcome::Passed;
        out.harness.phase = Phase::Observe;
        out.harness.cleanup = CleanupOutcome::Clean;
    } else if (route->fn == nullptr) {
        out.harness.outcome = Outcome::Failed;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "matched JIT route has no handler");
    } else {
        DeterministicEnvironment empty_environment{};
        DeterministicEnvironment* runtime_environment = &empty_environment;
        if (scenario.environment != nullptr) {
            if (!scenario.environment->prepare_run()) {
                out.harness.outcome = Outcome::Invalid;
                out.harness.cleanup = CleanupOutcome::Clean;
                copy_detail(out.harness, "scripted environment is invalid");
                connection.destroy();
                return out;
            }
            runtime_environment = &scenario.environment->runtime;
        }

        HandlerExecution execution{};
        execution.init(
            route->fn, &connection.connection, scenario.request_data, scenario.request_len);
        execution.frame.context.route_param_count = route_param_count;
        for (u32 i = 0; i < route_param_count; i++)
            execution.frame.context.route_params[i] = route_params[i];
        DeterministicHandlerSpec driver{};
        driver.execution = execution;
        driver.environment = runtime_environment;
        driver.initial_semantic_events = out.harness.semantic_events;
        driver.auto_complete_timers = scenario.auto_complete_timers;
        HarnessSpec handler_harness = harness;
        handler_harness.layer = ExecutionLayer::Handler;
        const HandlerExecutionResult driven =
            drive_handler_deterministically(driver, handler_harness);
        const u32 state_resets = out.harness.state_resets;
        out.harness = driven.harness;
        out.harness.state_resets += state_resets;
        out.terminal = driven.terminal;
        out.has_terminal = driven.has_terminal;
    }

    if (needs_terminal_observation)
        (void)publish_terminal(harness, out.harness, out.terminal, scenario.now_us);

    if (out.harness.outcome == Outcome::Passed && out.has_terminal &&
        !expectation_matches(scenario.expected, out.terminal)) {
        out.harness.outcome = Outcome::Mismatched;
        out.harness.phase = Phase::Observe;
        copy_detail(out.harness, "scenario terminal result did not match expectation");
    }

    out.connection_invariant_violations = connection.invariant_violations();
    if (out.connection_invariant_violations != 0) {
        out.harness.outcome = Outcome::Failed;
        out.harness.phase = Phase::Quiesce;
        copy_detail(out.harness, "connection cleanup invariant violated");
        Observation event{};
        event.kind = ObservationKind::InvariantViolation;
        event.phase = Phase::Quiesce;
        event.sequence = out.harness.semantic_events;
        event.value0 = out.connection_invariant_violations;
        if (out.harness.semantic_events < harness.limits.max_semantic_events) {
            out.harness.semantic_events++;
            (void)harness.observations.publish(event);
        }
    }
    connection.destroy();
    out.harness.cleanup = CleanupOutcome::Clean;
    return out;
}

}  // namespace rut::harness
