#include "rut/harness/scenario_driver.h"

#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/callbacks_impl.h"
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
    if (terminal.action == jit::HandlerAction::Forward ||
        terminal.action == jit::HandlerAction::ForwardBuffered)
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

bool publish_response_body(const HarnessSpec& spec,
                           HarnessResult& result,
                           const Connection& connection,
                           u64 timestamp_us) {
    if (result.semantic_events >= spec.limits.max_semantic_events) {
        result.outcome = Outcome::Failed;
        result.has_reached_limit = true;
        result.reached_limit = LimitKind::SemanticEvents;
        copy_detail(result, "semantic-events limit reached");
        return false;
    }

    const u8* response = connection.send_buf.data();
    const u32 response_len = connection.send_buf.len();
    u32 body_offset = response_len;
    for (u32 i = 0; i + 3 < response_len; i++) {
        if (response[i] == '\r' && response[i + 1] == '\n' && response[i + 2] == '\r' &&
            response[i + 3] == '\n') {
            body_offset = i + 4;
            break;
        }
    }

    constexpr u32 kMaxObservedBodyLen = 4096;
    const u32 body_len = response_len - body_offset;
    const u32 observed_len = body_len < kMaxObservedBodyLen ? body_len : kMaxObservedBodyLen;
    Observation event{};
    event.kind = ObservationKind::ResponseBodyProduced;
    event.phase = Phase::Observe;
    event.sequence = result.semantic_events;
    event.timestamp_us = timestamp_us;
    event.value0 = body_len;
    event.value1 = observed_len != body_len ? 1 : 0;
    event.label = {reinterpret_cast<const char*>(response + body_offset), observed_len};
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

bool account_terminal_output(const HarnessSpec& spec,
                             HarnessResult& result,
                             Connection& connection,
                             jit::HandlerResult& terminal,
                             const char* dynamic_body = nullptr,
                             u32 dynamic_body_len = 0,
                             bool dynamic_body_valid = false,
                             const jit::HandlerCtx* response_ctx = nullptr) {
    if (terminal.action != jit::HandlerAction::ReturnStatus) return true;

    connection.resp_status = terminal.status_code;
    const bool wants_dynamic_body =
        terminal.upstream_id == jit::HandlerResult::kDynamicResponseBody;
    if (wants_dynamic_body && (!dynamic_body_valid || dynamic_body == nullptr)) {
        terminal = jit::HandlerResult::make_status(500);
        connection.resp_status = 500;
        format_static_response(connection, 500, false);
        result.output_bytes = connection.send_buf.len();
        if (result.output_bytes <= spec.limits.max_output_bytes) return true;
        result.outcome = Outcome::Failed;
        result.has_reached_limit = true;
        result.reached_limit = LimitKind::OutputBytes;
        copy_detail(result, "output-bytes limit reached");
        return false;
    }
    const RouteConfig* config = connection.request_config;
    const bool has_body = !wants_dynamic_body && terminal.upstream_id != 0 && config != nullptr &&
                          terminal.upstream_id <= config->response_body_count;
    constexpr u32 kMaxHeaders = RouteConfig::kMaxHeadersPerSet + jit::kMaxResponseHeaderMutations;
    ResponseHeaderKV headers[kMaxHeaders];
    u32 header_count = 0;
    if (!collect_effective_response_headers(
            response_ctx, config, terminal.next_state, headers, kMaxHeaders, &header_count)) {
        connection.resp_status = 500;
        format_static_response(connection, 500, false);
    } else if (header_count != 0) {
        const char* body_data = nullptr;
        u32 body_len = 0;
        bool fallback_body = false;
        if (wants_dynamic_body) {
            body_data = dynamic_body;
            body_len = dynamic_body_len;
        } else if (has_body) {
            const auto& body = config->response_bodies[terminal.upstream_id - 1];
            body_data = body.data;
            body_len = body.len;
        } else if (terminal.upstream_id != 0) {
            body_data = status_reason(terminal.status_code);
            while (body_data[body_len] != '\0') body_len++;
            fallback_body = true;
        }
        format_response_with_body_and_headers(connection,
                                              terminal.status_code,
                                              body_data,
                                              body_len,
                                              headers,
                                              header_count,
                                              connection.keep_alive,
                                              fallback_body);
    } else if (wants_dynamic_body) {
        format_response_with_body(connection,
                                  terminal.status_code,
                                  dynamic_body,
                                  dynamic_body_len,
                                  connection.keep_alive);
    } else if (has_body) {
        const auto& body = config->response_bodies[terminal.upstream_id - 1];
        format_response_with_body(
            connection, terminal.status_code, body.data, body.len, connection.keep_alive);
    } else {
        format_static_response(connection, terminal.status_code, connection.keep_alive);
    }

    result.output_bytes = connection.send_buf.len();
    if (connection.resp_status != terminal.status_code)
        terminal = jit::HandlerResult::make_status(connection.resp_status);
    if (result.output_bytes <= spec.limits.max_output_bytes) return true;
    result.outcome = Outcome::Failed;
    result.has_reached_limit = true;
    result.reached_limit = LimitKind::OutputBytes;
    copy_detail(result, "output-bytes limit reached");
    return false;
}

}  // namespace

ScenarioResult drive_scenario(const ScenarioSpec& scenario, const HarnessSpec& harness) {
    ScenarioResult out{};
    const char* dynamic_response_body = nullptr;
    u32 dynamic_response_body_len = 0;
    bool dynamic_response_body_valid = false;
    jit::HandlerCtx response_ctx{};
    HandlerExecutionResult driven_storage{};
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
    out.harness.virtual_time_us = scenario.now_us;

    Str routing_path = scenario.path;
    u8 routing_method = scenario.method;
    ParsedRequest parsed_request{};
    u32 parsed_header_end = 0;
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
        parsed_header_end = parser.header_end;
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
    connection.connection.keep_alive = scenario.request_len == 0 || parsed_request.keep_alive;
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
    if (route->action == RouteAction::JitHandler && route->needs_req_body) {
        if (parsed_request.chunked) {
            out.harness.outcome = Outcome::Unsupported;
            out.harness.cleanup = CleanupOutcome::Clean;
            copy_detail(out.harness, "chunked JIT request bodies are unsupported");
            connection.destroy();
            return out;
        }
        const u64 available_body = scenario.request_len - parsed_header_end;
        if (parsed_request.has_content_length && available_body < parsed_request.content_length) {
            out.harness.outcome = Outcome::Stalled;
            out.harness.cleanup = CleanupOutcome::Clean;
            copy_detail(out.harness, "scenario request body is incomplete");
            connection.destroy();
            return out;
        }
    }

    activate_rut_program(scenario.target->program);
    ScenarioState local_state{};
    ScenarioState* state = scenario.state != nullptr ? scenario.state : &local_state;
    if (!state->ensure_cache_state()) {
        out.harness.outcome = Outcome::Failed;
        out.harness.cleanup = CleanupOutcome::Clean;
        copy_detail(out.harness, "scenario cache state allocation failed");
        connection.destroy();
        return out;
    }
    if (state->prepare(scenario.state_isolation,
                       scenario.state_group,
                       scenario.target,
                       scenario.target->generation))
        out.harness.state_resets++;
    CacheLocalState* previous_cache_state = rut_helper_cache_select_local_state(state->cache_state);
    const u32 previous_cache_shard = rut_helper_cache_select_local_shard(scenario.shard_id);
    struct CacheStateRestore {
        CacheLocalState* previous_state;
        u32 previous_shard;
        ~CacheStateRestore() {
            (void)rut_helper_cache_select_local_shard(previous_shard);
            (void)rut_helper_cache_select_local_state(previous_state);
        }
    } cache_state_restore{previous_cache_state, previous_cache_shard};
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

    if (rate_limited) {
        out.terminal = jit::HandlerResult::make_status(429);
        out.has_terminal = true;
        out.harness.outcome = Outcome::Passed;
        out.harness.phase = Phase::Observe;
        out.harness.cleanup = CleanupOutcome::Clean;
    } else if (route->action == RouteAction::Static) {
        out.terminal = jit::HandlerResult::make_status(route->status_code);
        out.has_terminal = true;
        out.harness.outcome = Outcome::Passed;
        out.harness.phase = Phase::Observe;
        out.harness.cleanup = CleanupOutcome::Clean;
    } else if (route->action == RouteAction::Proxy) {
        out.terminal = jit::HandlerResult::make_forward(route->upstream_id);
        out.has_terminal = true;
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
        driver.initial_virtual_time_us = scenario.now_us;
        driver.auto_complete_timers = scenario.auto_complete_timers;
        HarnessSpec handler_harness = harness;
        handler_harness.layer = ExecutionLayer::Handler;
        driven_storage = drive_handler_deterministically(driver, handler_harness);
        const HandlerExecutionResult& driven = driven_storage;
        const u32 state_resets = out.harness.state_resets;
        out.harness = driven.harness;
        out.harness.state_resets += state_resets;
        out.terminal = driven.terminal;
        out.has_terminal = driven.has_terminal;
        dynamic_response_body = driven.dynamic_response_body;
        dynamic_response_body_len = driven.dynamic_response_body_len;
        dynamic_response_body_valid = driven.dynamic_response_body_valid;
        response_ctx.response_header_count = driven.response_header_count;
        response_ctx.response_header_overflow = driven.response_header_overflow;
        for (u32 i = 0; i < driven.response_header_count; i++)
            response_ctx.response_header_mutations[i] = driven.response_header_mutations[i];
    }

    if (out.harness.outcome == Outcome::Passed && out.has_terminal)
        (void)account_terminal_output(harness,
                                      out.harness,
                                      connection.connection,
                                      out.terminal,
                                      dynamic_response_body,
                                      dynamic_response_body_len,
                                      dynamic_response_body_valid,
                                      &response_ctx);

    if (out.has_terminal && out.harness.outcome == Outcome::Passed)
        (void)publish_terminal(harness, out.harness, out.terminal, scenario.now_us);

    if (out.has_terminal && out.terminal.action == jit::HandlerAction::ReturnStatus &&
        out.harness.outcome == Outcome::Passed)
        (void)publish_response_body(
            harness, out.harness, connection.connection, out.harness.virtual_time_us);

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
