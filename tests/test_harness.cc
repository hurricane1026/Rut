#include "rut/harness/core.h"
#include "test.h"
#if RUT_ENABLE_JIT_TESTS
#include "fault_injection.h"
#include "rut/harness/connection_execution.h"
#include "rut/harness/handler_execution.h"
#include "rut/harness/scenario_driver.h"
#include "rut/harness/scripted_environment.h"
#include "rut/harness/source_target.h"
#include "rut/runtime/cache_table.h"
#endif

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <type_traits>

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

using namespace rut;

TEST(harness_core, validates_capabilities_and_limits) {
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;
    spec.required_capabilities =
        harness::Capability::VirtualTime | harness::Capability::SyntheticIo;
    spec.environment_capabilities = spec.required_capabilities;

    const auto result = harness::validate_spec(spec);
    CHECK_EQ(result.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.phase, harness::Phase::Complete);
    CHECK_EQ(result.cleanup, harness::CleanupOutcome::Clean);
}

TEST(harness_core, reports_missing_capabilities_as_unsupported) {
    harness::HarnessSpec spec{};
    spec.required_capabilities = harness::CapabilitySet::one(harness::Capability::IoUring);
    spec.environment_capabilities = harness::CapabilitySet::one(harness::Capability::SyntheticIo);

    const auto result = harness::validate_spec(spec);
    CHECK_EQ(result.outcome, harness::Outcome::Unsupported);
    CHECK_EQ(result.phase, harness::Phase::Prepare);
    CHECK(result.missing_capabilities.has(harness::Capability::IoUring));
    CHECK(std::strcmp(result.detail, "environment capability missing") == 0);
}

TEST(harness_core, rejects_zero_limits) {
    harness::HarnessSpec spec{};
    spec.limits.max_handler_resumes = 0;

    const auto result = harness::validate_spec(spec);
    CHECK_EQ(result.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.phase, harness::Phase::Prepare);
    CHECK(std::strcmp(result.detail, "run limits must be non-zero") == 0);
}

TEST(harness_core, stable_names_cover_public_enums) {
    CHECK(std::strcmp(harness::layer_name(harness::ExecutionLayer::Connection), "connection") == 0);
    CHECK(std::strcmp(harness::phase_name(harness::Phase::Quiesce), "quiesce") == 0);
    CHECK(std::strcmp(harness::outcome_name(harness::Outcome::Stalled), "stalled") == 0);
    CHECK(std::strcmp(harness::capability_name(harness::Capability::ScriptedFaults),
                      "scripted-faults") == 0);
    CHECK(std::strcmp(harness::limit_name(harness::LimitKind::HandlerResumes), "handler-resumes") ==
          0);
}

#if RUT_ENABLE_JIT_TESTS
namespace {

u64 immediate_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return jit::HandlerResult::make_status(204).pack();
}

u64 timer_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Timer, 25).pack();
    if (ctx->state == 1 && ctx->resume_event_kind == static_cast<u32>(jit::YieldKind::Timer) &&
        ctx->resume_event_result == 0)
        return jit::HandlerResult::make_status(205).pack();
    return jit::HandlerResult::make_status(500).pack();
}

u64 recv_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0) return jit::HandlerResult::make_yield(1, jit::YieldKind::Recv).pack();
    return jit::HandlerResult::make_status(206).pack();
}

u64 endless_timer_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Timer, 1).pack();
}

u64 targeted_upstream_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::UpstreamConnect, 1).pack();
    return jit::HandlerResult::make_status(204).pack();
}

u64 any_timer_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Any, 25).pack();
    if (ctx->resume_event_kind == static_cast<u32>(jit::YieldKind::Timer))
        return jit::HandlerResult::make_status(208).pack();
    return jit::HandlerResult::make_status(500).pack();
}

u64 any_recv_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Any, 25).pack();
    if (ctx->resume_event_kind == static_cast<u32>(jit::YieldKind::Recv) &&
        ctx->resume_event_result == 17)
        return jit::HandlerResult::make_status(209).pack();
    return jit::HandlerResult::make_status(500).pack();
}

u64 any_without_timeout_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Any, 0).pack();
    return jit::HandlerResult::make_status(500).pack();
}

u16 oversized_body_index = 0;
u16 oversized_headers_index = 0;

u64 oversized_response_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    jit::HandlerResult result = jit::HandlerResult::make_status(200);
    result.upstream_id = oversized_body_index;
    result.next_state = oversized_headers_index;
    return result.pack();
}

bool reject_yield(void*, const harness::Observation& event) {
    return event.kind != harness::ObservationKind::HandlerYielded;
}

bool reject_terminal_observations(void*, const harness::Observation& event) {
    return event.kind != harness::ObservationKind::ResponseProduced &&
           event.kind != harness::ObservationKind::UpstreamSelected;
}

bool reject_route_selection(void*, const harness::Observation& event) {
    return event.kind != harness::ObservationKind::RouteSelected;
}

struct ResponseObservation {
    bool seen = false;
    u64 status = 0;
};

bool capture_response_observation(void* context, const harness::Observation& event) {
    if (event.kind != harness::ObservationKind::ResponseProduced) return true;
    auto* captured = static_cast<ResponseObservation*>(context);
    captured->seen = true;
    captured->status = event.value0;
    return true;
}

struct TempSource {
    char path[64] = "/tmp/rut_harness_XXXXXX";

    bool write(const char* source) {
        const int fd = ::mkstemp(path);
        if (fd < 0) return false;
        u32 len = 0;
        while (source[len]) len++;
        u32 pos = 0;
        while (pos < len) {
            const ssize_t n = ::write(fd, source + pos, len - pos);
            if (n <= 0) {
                ::close(fd);
                return false;
            }
            pos += static_cast<u32>(n);
        }
        return ::close(fd) == 0;
    }

    ~TempSource() {
        if (path[0]) (void)::unlink(path);
    }
};

}  // namespace

TEST(harness_handler, completes_immediate_handler) {
    harness::HandlerExecution execution{};
    execution.init(&immediate_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically({execution}, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.action, jit::HandlerAction::ReturnStatus);
    CHECK_EQ(result.terminal.status_code, 204);
    CHECK_EQ(result.harness.handler_resumes, 0u);
}

TEST(harness_handler, advances_virtual_time_for_timer_yield) {
    harness::HandlerExecution execution{};
    execution.init(&timer_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically({execution}, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 205);
    CHECK_EQ(result.harness.handler_resumes, 1u);
    CHECK_EQ(result.harness.virtual_time_us, 25000u);
}

TEST(harness_handler, rejects_wrong_execution_layer) {
    harness::HandlerExecution execution{};
    execution.init(&immediate_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};

    const auto result = harness::drive_handler_deterministically({execution}, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK(!result.has_terminal);
}

TEST(harness_handler, rejects_timer_completion_before_requested_delay) {
    harness::HandlerExecution execution{};
    execution.init(&timer_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::Timer, 0, 100, 1},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.harness.virtual_time_us, 0u);
    CHECK_EQ(result.consumed_events, 0u);
}

TEST(harness_handler, timer_completion_ignores_explicit_target_id) {
    harness::HandlerExecution execution{};
    execution.init(&timer_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::Timer, 0, 25000, 1, 1},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 205);
    CHECK_EQ(result.harness.virtual_time_us, 25000u);
    CHECK_EQ(result.consumed_events, 1u);
}

TEST(harness_handler, direct_timer_deadline_wins_over_late_scripted_timer) {
    harness::HandlerExecution execution{};
    execution.init(&timer_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::Timer, 0, 50000, 1},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 205);
    CHECK_EQ(result.harness.virtual_time_us, 25000u);
    CHECK_EQ(result.consumed_events, 0u);
}

TEST(harness_handler, rejects_wait_any_timer_before_timeout) {
    harness::HandlerExecution execution{};
    execution.init(&any_timer_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::Timer, 0, 100, 1},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.harness.virtual_time_us, 0u);
    CHECK_EQ(result.consumed_events, 0u);
}

TEST(harness_handler, wait_any_timeout_wins_over_later_completion) {
    harness::HandlerExecution execution{};
    execution.init(&any_timer_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::Recv, 17, 50000, 1, 3},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 208);
    CHECK_EQ(result.harness.virtual_time_us, 25000u);
    CHECK_EQ(result.consumed_events, 0u);
}

TEST(harness_handler, wait_any_timeout_completes_without_scripted_events) {
    harness::HandlerExecution execution{};
    execution.init(&any_timer_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically({execution}, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 208);
    CHECK_EQ(result.harness.virtual_time_us, 25000u);
    CHECK_EQ(result.consumed_events, 0u);
}

TEST(harness_handler, wait_any_accepts_targeted_completion_before_timeout) {
    harness::HandlerExecution execution{};
    execution.init(&any_recv_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::Recv, 17, 10000, 1, 3},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 209);
    CHECK_EQ(result.harness.virtual_time_us, 10000u);
    CHECK_EQ(result.consumed_events, 1u);
}

TEST(harness_handler, wait_any_ignores_upstream_completion_until_timeout) {
    harness::HandlerExecution execution{};
    execution.init(&any_timer_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::UpstreamRecv, 17, 10000, 1, 3},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 208);
    CHECK_EQ(result.harness.virtual_time_us, 25000u);
    CHECK_EQ(result.consumed_events, 0u);
}

TEST(harness_handler, wait_any_without_timeout_rejects_timer_completion) {
    harness::HandlerExecution execution{};
    execution.init(&any_without_timeout_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::Timer, 0, 100, 1},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Stalled);
    CHECK(!result.has_terminal);
    CHECK_EQ(result.consumed_events, 0u);
    CHECK_EQ(result.harness.virtual_time_us, 0u);
}

TEST(harness_handler, wait_any_without_timeout_rejects_upstream_completion) {
    harness::HandlerExecution execution{};
    execution.init(&any_without_timeout_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::UpstreamConnect, 0, 100, 1, 2},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Stalled);
    CHECK(!result.has_terminal);
    CHECK_EQ(result.harness.virtual_time_us, 0u);
    CHECK_EQ(result.consumed_events, 0u);
}

TEST(harness_handler, stalls_when_yield_has_no_declared_event) {
    harness::HandlerExecution execution{};
    execution.init(&recv_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically({execution}, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Stalled);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK(!result.has_terminal);
}

TEST(harness_handler, enforces_resume_limit) {
    harness::HandlerExecution execution{};
    execution.init(&endless_timer_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;
    spec.limits.max_handler_resumes = 2;

    const auto result = harness::drive_handler_deterministically({execution}, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Failed);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK(result.harness.has_reached_limit);
    CHECK_EQ(result.harness.reached_limit, harness::LimitKind::HandlerResumes);
    CHECK_EQ(result.harness.handler_resumes, 2u);
}

TEST(harness_handler, stops_when_observation_oracle_rejects_event) {
    harness::HandlerExecution execution{};
    execution.init(&timer_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;
    spec.observations.observe = &reject_yield;

    const auto result = harness::drive_handler_deterministically({execution}, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Mismatched);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK(!result.has_terminal);
    CHECK_EQ(result.harness.handler_resumes, 0u);
}

TEST(harness_handler, consumes_declared_completion_from_deterministic_environment) {
    harness::HandlerExecution execution{};
    execution.init(&recv_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::Recv, 17, 100, 1},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 206);
    CHECK_EQ(result.consumed_events, 1u);
    CHECK_EQ(result.harness.virtual_time_us, 100u);
    // A run consumes an isolated copy, not the caller's reusable environment.
    CHECK_EQ(environment.cursor, 0u);
    CHECK_EQ(environment.now_us, 0u);
}

TEST(harness_handler, rejects_ambiguous_or_non_monotonic_completion_schedule) {
    harness::HandlerExecution execution{};
    execution.init(&recv_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::Recv, 0, 100, 1},
        {jit::YieldKind::Recv, 0, 100, 1},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 2);
    CHECK(!environment.schedule_valid);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
}

TEST(harness_handler, stalls_when_script_targets_a_different_upstream) {
    harness::HandlerExecution execution{};
    execution.init(&targeted_upstream_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {
        {jit::YieldKind::UpstreamConnect, 0, 1, 1, 2},
    };
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Stalled);
    CHECK_EQ(result.consumed_events, 0u);
    CHECK_EQ(result.harness.virtual_time_us, 0u);
}

TEST(harness_connection, reports_and_resets_cleanup_invariants) {
    harness::ConnectionExecution execution{};
    CHECK_EQ(execution.connection.fd, -1);
    CHECK_EQ(execution.connection.upstream_fd, -1);
    CHECK_EQ(execution.connection.idle_return_fd, -1);
    execution.reset(0x7f000001u, 8080, 3);
    CHECK_EQ(execution.invariant_violations(), 0u);
    execution.connection.pending_ops = 1;
    execution.connection.yield_armed = true;
    const u64 violations = execution.invariant_violations();
    CHECK((violations &
           harness::invariant_bit(harness::ConnectionInvariant::NoPendingOperations)) != 0);
    CHECK((violations & harness::invariant_bit(harness::ConnectionInvariant::NoArmedYield)) != 0);
    execution.destroy();
    CHECK_EQ(execution.invariant_violations(), 0u);
}

TEST(harness_connection, destroy_closes_owned_upstream_descriptor) {
    int descriptors[2] = {-1, -1};
    REQUIRE_EQ(::pipe(descriptors), 0);
    harness::ConnectionExecution execution{};
    execution.connection.upstream_fd = descriptors[0];

    execution.destroy();

    errno = 0;
    CHECK_EQ(::fcntl(descriptors[0], F_GETFD), -1);
    CHECK_EQ(errno, EBADF);
    CHECK_EQ(::close(descriptors[1]), 0);
}

static_assert(!std::is_copy_constructible_v<harness::ConnectionExecution>);
static_assert(!std::is_copy_assignable_v<harness::ConnectionExecution>);
static_assert(!std::is_move_constructible_v<harness::ConnectionExecution>);
static_assert(!std::is_move_assignable_v<harness::ConnectionExecution>);

static harness::HarnessSpec scripted_scenario_harness(bool faults = false) {
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities = harness::Capability::SyntheticIo |
                                 harness::Capability::VirtualTime |
                                 harness::Capability::ScriptedUpstream;
    if (faults) spec.required_capabilities.add(harness::Capability::ScriptedFaults);
    spec.environment_capabilities = spec.required_capabilities;
    return spec;
}

TEST(harness_scenario, drives_real_source_with_scripted_upstream_completion) {
    TempSource source;
    REQUIRE(
        source.write("upstream api at \"127.0.0.1:9000\"\n"
                     "route GET \"/x\" { wait(5) let ev = wait(upstream(api).connect()) if ev.ok { "
                     "return 204 } else { return 502 } }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    harness::ScriptedEnvironment environment{};
    REQUIRE(environment.add_upstream(jit::YieldKind::UpstreamConnect, 1, 0, 10000));
    const char request[] = "GET /x HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.now_us = 999;
    scenario.environment = &environment;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 204};

    const auto result = harness::drive_scenario(scenario, scripted_scenario_harness());
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 204);
    CHECK_EQ(result.harness.virtual_time_us, 10000u);
    CHECK_EQ(result.harness.handler_resumes, 2u);
    CHECK_EQ(result.harness.fault_points_reached, 1u);
    CHECK_EQ(result.harness.faults_injected, 0u);
    CHECK_EQ(result.connection_invariant_violations, 0u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, dynamic_json_body_is_accounted_as_runtime_output) {
    TempSource source;
    REQUIRE(source.write("route GET \"/x\" { return 200, json({ path: req.path }) }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    const char request[] = "GET /x HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 200};

    auto spec = scripted_scenario_harness();
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.terminal.status_code, 200);
    // Includes the 13-byte {"path":"/x"} body, not the two-byte "OK"
    // fallback that an unrecognized body marker would have produced.
    CHECK_EQ(result.harness.output_bytes, 117u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, dynamic_json_failure_preserves_committed_response_headers) {
    TempSource source;
    REQUIRE(source.write(R"rut(
func add_stage(_ resp: Response) -> i32 {
    resp.set("X-Stage", "after")
    0
}
chain observed { after add_stage(resp) }
route GET "/with" use chain observed {
    return 200, json({ value: req.header("X-Value").or("") })
}
route GET "/without" {
    return 200, json({ value: req.header("X-Value").or("") })
}
)rut"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    auto run = [&](const char* path, u32 path_len, const char* request, u32 request_len) {
        harness::ScenarioSpec scenario{};
        scenario.target = &target;
        scenario.path = {path, path_len};
        scenario.method = kRouteMethodGet;
        scenario.request_data = reinterpret_cast<const u8*>(request);
        scenario.request_len = request_len;
        scenario.expected = {true, jit::HandlerAction::ReturnStatus, 500};
        auto spec = scripted_scenario_harness();
        spec.required_capabilities =
            harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
        spec.environment_capabilities = spec.required_capabilities;
        return harness::drive_scenario(scenario, spec);
    };

    static const char kWith[] =
        "GET /with HTTP/1.1\r\nHost: test\r\nX-Value: \xc0\x80\r\n\r\n";
    static const char kWithout[] =
        "GET /without HTTP/1.1\r\nHost: test\r\nX-Value: \xc0\x80\r\n\r\n";
    const auto with_header = run("/with", 5, kWith, sizeof(kWith) - 1);
    const auto without_header = run("/without", 8, kWithout, sizeof(kWithout) - 1);

    REQUIRE_EQ(with_header.harness.outcome, harness::Outcome::Passed);
    REQUIRE_EQ(without_header.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(with_header.terminal.status_code, 500u);
    CHECK_EQ(without_header.terminal.status_code, 500u);
    // The committed-header path is header-only after the failed dynamic body;
    // the baseline static 500 contains "Internal Server Error" and grows its
    // Content-Length field from one digit to two.
    CHECK_EQ(with_header.harness.output_bytes,
             without_header.harness.output_bytes + sizeof("X-Stage: after\r\n") - 1 -
                 (sizeof("Internal Server Error") - 1) - 1);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, static_terminal_is_published_to_observation_oracle) {
    harness::SourceTarget target{};
    REQUIRE(target.program.config.add_static("/static", kRouteMethodGet, 204));
    target.prepared = true;
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/static", 7};
    scenario.method = kRouteMethodGet;
    const char request[] = "GET /static HTTP/1.1\r\nHost: test\r\n\r\n";
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.now_us = 777;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    spec.observations.observe = &reject_terminal_observations;

    const auto result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Mismatched);
    CHECK_EQ(result.harness.semantic_events, 2u);
    CHECK_EQ(result.harness.input_bytes, scenario.request_len);
    CHECK_EQ(result.harness.virtual_time_us, scenario.now_us);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 204);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, rejects_routing_fields_that_disagree_with_request_line) {
    harness::SourceTarget target{};
    REQUIRE(target.program.config.add_static("/expected", kRouteMethodGet, 204));
    target.prepared = true;
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/expected", 9};
    scenario.method = kRouteMethodGet;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;

    const char wrong_path[] = "GET /different HTTP/1.1\r\nHost: test\r\n\r\n";
    scenario.request_data = reinterpret_cast<const u8*>(wrong_path);
    scenario.request_len = sizeof(wrong_path) - 1;
    const auto path_result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(path_result.harness.outcome, harness::Outcome::Invalid);
    CHECK(!path_result.route_selected);

    const char wrong_method[] = "POST /expected HTTP/1.1\r\nHost: test\r\n\r\n";
    scenario.request_data = reinterpret_cast<const u8*>(wrong_method);
    scenario.request_len = sizeof(wrong_method) - 1;
    const auto method_result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(method_result.harness.outcome, harness::Outcome::Invalid);
    CHECK(!method_result.route_selected);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, route_selection_is_published_before_terminal_handling) {
    harness::SourceTarget target{};
    REQUIRE(target.program.config.add_static("/selected", kRouteMethodGet, 204));
    target.prepared = true;
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/selected", 9};
    scenario.method = kRouteMethodGet;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    spec.observations.observe = &reject_route_selection;

    const auto result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Mismatched);
    CHECK_EQ(result.harness.semantic_events, 1u);
    CHECK(result.route_selected);
    CHECK_EQ(result.route_index, 0u);
    CHECK(!result.has_terminal);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, jit_handler_shares_route_observation_budget) {
    harness::SourceTarget target{};
    REQUIRE(target.program.config.add_jit_handler("/jit", kRouteMethodGet, &immediate_handler));
    target.prepared = true;
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/jit", 4};
    scenario.method = kRouteMethodGet;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    spec.limits.max_semantic_events = 1;

    const auto result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Failed);
    CHECK(result.harness.has_reached_limit);
    CHECK_EQ(result.harness.reached_limit, harness::LimitKind::SemanticEvents);
    CHECK_EQ(result.harness.semantic_events, 1u);
    CHECK(!result.has_terminal);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, terminal_observation_limit_precedes_expectation_mismatch) {
    harness::SourceTarget target{};
    REQUIRE(target.program.config.add_static("/limited-events", kRouteMethodGet, 204));
    target.prepared = true;
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/limited-events", 15};
    scenario.method = kRouteMethodGet;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 500};
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    spec.limits.max_semantic_events = 1;

    const auto result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Failed);
    CHECK(result.harness.has_reached_limit);
    CHECK_EQ(result.harness.reached_limit, harness::LimitKind::SemanticEvents);
    CHECK_EQ(result.harness.semantic_events, 1u);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 204);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, terminal_response_enforces_output_budget) {
    harness::SourceTarget target{};
    REQUIRE(target.program.config.add_static("/output", kRouteMethodGet, 204));
    target.prepared = true;
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/output", 7};
    scenario.method = kRouteMethodGet;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    spec.limits.max_output_bytes = 1;

    const auto result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Failed);
    CHECK(result.harness.has_reached_limit);
    CHECK_EQ(result.harness.reached_limit, harness::LimitKind::OutputBytes);
    CHECK(result.harness.output_bytes > spec.limits.max_output_bytes);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, formatter_fallback_updates_terminal_status) {
    harness::SourceTarget target{};
    char body[RouteConfig::kResponseBodyPoolBytes];
    char header_value[RouteConfig::kResponseHeaderBytesPoolBytes - 12];
    std::memset(body, 'b', sizeof(body));
    std::memset(header_value, 'v', sizeof(header_value));
    oversized_body_index = target.program.config.add_response_body(body, sizeof(body));
    const char* keys[] = {"X"};
    const u32 key_lens[] = {1};
    const char* values[] = {header_value};
    const u32 value_lens[] = {sizeof(header_value)};
    oversized_headers_index =
        target.program.config.add_response_header_set(keys, key_lens, values, value_lens, 1);
    REQUIRE(oversized_body_index != 0);
    REQUIRE(oversized_headers_index != 0);
    REQUIRE(target.program.config.add_jit_handler(
        "/oversized", kRouteMethodGet, &oversized_response_handler));
    target.prepared = true;
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/oversized", 10};
    scenario.method = kRouteMethodGet;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 500};
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    ResponseObservation observed{};
    spec.observations.context = &observed;
    spec.observations.observe = &capture_response_observation;

    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 500);
    CHECK(result.harness.output_bytes > 0);
    CHECK(observed.seen);
    CHECK_EQ(observed.status, 500u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, scripted_upstream_recv_accounts_owned_data_and_limits) {
    TempSource source;
    REQUIRE(source.write(
        "upstream api at \"127.0.0.1:9000\"\n"
        "route GET \"/stream\" { let ev = wait(upstream(api).recv()) if ev.result == 4 { "
        "return 204 } else { return 502 } }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    harness::ScriptedEnvironment environment{};
    const u8 response[] = {'p', 'o', 'n', 'g'};
    REQUIRE(environment.add_upstream_recv(1, response, sizeof(response), 100));
    const char request[] = "GET /stream HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/stream", 7};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.environment = &environment;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 204};
    auto spec = scripted_scenario_harness();

    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 204);
    CHECK_EQ(result.harness.input_bytes, scenario.request_len + sizeof(response));
    CHECK_EQ(result.harness.backend_completions, 1u);
    CHECK_EQ(result.harness.virtual_time_us, 100u);

    spec.limits.max_input_bytes = scenario.request_len + sizeof(response) - 1;
    const auto limited = harness::drive_scenario(scenario, spec);
    CHECK_EQ(limited.harness.outcome, harness::Outcome::Failed);
    CHECK(limited.harness.has_reached_limit);
    CHECK_EQ(limited.harness.reached_limit, harness::LimitKind::InputBytes);

    REQUIRE(environment.inject_fault(jit::YieldKind::UpstreamRecv, 1, -1, 1));
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 502};
    const auto faulted = harness::drive_scenario(scenario, scripted_scenario_harness(true));
    REQUIRE_EQ(faulted.harness.outcome, harness::Outcome::Passed);
    REQUIRE(faulted.has_terminal);
    CHECK_EQ(faulted.terminal.status_code, 502);
    CHECK_EQ(faulted.harness.input_bytes, scenario.request_len);
    CHECK_EQ(faulted.harness.faults_injected, 1u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, logical_fault_is_reproducible_after_state_reset) {
    TempSource source;
    REQUIRE(source.write(
        "upstream api at \"127.0.0.1:9000\"\n"
        "route GET \"/x\" { let ev = wait(upstream(api).connect()) if ev.ok { return 204 } "
        "else { return 502 } }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    harness::ScriptedEnvironment environment{};
    REQUIRE(environment.add_upstream(jit::YieldKind::UpstreamConnect, 1, 0, 10));
    REQUIRE(environment.inject_fault(jit::YieldKind::UpstreamConnect, 1, -111, 1));
    const char request[] = "GET /x HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.environment = &environment;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 502};
    const auto spec = scripted_scenario_harness(true);

    const auto first = harness::drive_scenario(scenario, spec);
    const auto second = harness::drive_scenario(scenario, spec);
    for (const auto* result : {&first, &second}) {
        REQUIRE_EQ(result->harness.outcome, harness::Outcome::Passed);
        REQUIRE(result->has_terminal);
        CHECK_EQ(result->terminal.status_code, 502);
        CHECK_EQ(result->harness.fault_points_reached, 1u);
        CHECK_EQ(result->harness.faults_injected, 1u);
        CHECK_EQ(result->harness.virtual_time_us, 10u);
    }
    // The reusable builder retains its definition, while mutable cursor/time
    // state is rebuilt for each run.
    CHECK_EQ(environment.runtime.cursor, 0u);
    CHECK_EQ(environment.runtime.now_us, 0u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, rejects_undeclared_scripted_upstream_capability) {
    TempSource source;
    REQUIRE(source.write("route GET \"/x\" { return 204 }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodGet;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;

    const auto result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, real_source_timer_obeys_virtual_duration_limit) {
    TempSource source;
    REQUIRE(source.write("route GET \"/slow\" { wait(25) return 204 }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    const char request[] = "GET /slow HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/slow", 5};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    spec.limits.max_virtual_time_us = 10000;

    const auto result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Failed);
    CHECK(result.harness.has_reached_limit);
    CHECK_EQ(result.harness.reached_limit, harness::LimitKind::VirtualDuration);
    CHECK_EQ(result.connection_invariant_violations, 0u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, handler_clock_and_timer_deadline_start_at_scenario_time) {
    TempSource source;
    REQUIRE(source.write(
        "route GET \"/clock\" { if time.nowMicros() == 123456 { return 204 } else { return 500 "
        "} }\n"
        "route GET \"/timer\" { wait(5) return 205 }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    const char request[] = "GET /clock HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/clock", 6};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.now_us = 123456;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    spec.limits.max_virtual_time_us = 5000;

    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 204);
    CHECK_EQ(result.harness.virtual_time_us, 123456u);

    const char timer_request[] = "GET /timer HTTP/1.1\r\nHost: test\r\n\r\n";
    scenario.path = {"/timer", 6};
    scenario.request_data = reinterpret_cast<const u8*>(timer_request);
    scenario.request_len = sizeof(timer_request) - 1;
    const auto timer_result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(timer_result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(timer_result.has_terminal);
    CHECK_EQ(timer_result.terminal.status_code, 205);
    CHECK_EQ(timer_result.harness.virtual_time_us, 128456u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, gates_jit_routes_on_complete_supported_request_bodies) {
    TempSource source;
    REQUIRE(source.write(
        "route POST \"/body\" { if req.body == \"ping\" { return 204 } else { return 400 } }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/body", 5};
    scenario.method = kRouteMethodPost;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;

    const char incomplete[] = "POST /body HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\n";
    scenario.request_data = reinterpret_cast<const u8*>(incomplete);
    scenario.request_len = sizeof(incomplete) - 1;
    const auto incomplete_result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(incomplete_result.harness.outcome, harness::Outcome::Stalled);
    CHECK(!incomplete_result.has_terminal);

    const char chunked[] =
        "POST /body HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n"
        "4\r\nping\r\n0\r\n\r\n";
    scenario.request_data = reinterpret_cast<const u8*>(chunked);
    scenario.request_len = sizeof(chunked) - 1;
    const auto chunked_result = harness::drive_scenario(scenario, spec);
    CHECK_EQ(chunked_result.harness.outcome, harness::Outcome::Unsupported);
    CHECK(!chunked_result.has_terminal);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, cache_state_shares_within_group_and_resets_between_groups) {
    TempSource source;
    REQUIRE(source.write(
        "let seen = Cache<IP, i64>(capacity: 64)\n"
        "route GET \"/cache\" { let prev = seen.get(req.remoteAddr).or(0) if prev == 0 { "
        "seen.set(req.remoteAddr, 1) return 201 } else { return 200 } }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    const char request[] = "GET /cache HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioState state{};
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/cache", 6};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.peer_addr = 0x0a00002au;
    scenario.state_isolation = harness::StateIsolation::Group;
    scenario.state_group = 7;
    scenario.state = &state;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;

    const auto first = harness::drive_scenario(scenario, spec);
    const auto second = harness::drive_scenario(scenario, spec);
    REQUIRE(first.has_terminal);
    REQUIRE(second.has_terminal);
    CHECK_EQ(first.terminal.status_code, 201);
    CHECK_EQ(second.terminal.status_code, 200);
    CHECK_EQ(first.harness.state_resets, 1u);
    CHECK_EQ(second.harness.state_resets, 0u);

    scenario.shard_id = 1;
    const auto other_shard = harness::drive_scenario(scenario, spec);
    REQUIRE(other_shard.has_terminal);
    CHECK_EQ(other_shard.terminal.status_code, 201);
    CHECK_EQ(other_shard.harness.state_resets, 0u);

    scenario.shard_id = 0;
    const auto original_shard = harness::drive_scenario(scenario, spec);
    REQUIRE(original_shard.has_terminal);
    CHECK_EQ(original_shard.terminal.status_code, 200);

    scenario.state_group = 8;
    const auto other_group = harness::drive_scenario(scenario, spec);
    REQUIRE(other_group.has_terminal);
    CHECK_EQ(other_group.terminal.status_code, 201);
    CHECK_EQ(other_group.harness.state_resets, 1u);
    state.reset();
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
    CHECK_EQ(cache_registry().count.load(std::memory_order_acquire), 0u);
}

TEST(harness_scenario, run_isolation_resets_cache_for_every_item) {
    TempSource source;
    REQUIRE(source.write(
        "let seen = Cache<IP, i64>(capacity: 64)\n"
        "route GET \"/cache\" { let prev = seen.get(req.remoteAddr).or(0) if prev == 0 { "
        "seen.set(req.remoteAddr, 1) return 201 } else { return 200 } }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    const char request[] = "GET /cache HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/cache", 6};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.peer_addr = 0x0a00002au;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;

    const auto first = harness::drive_scenario(scenario, spec);
    const auto second = harness::drive_scenario(scenario, spec);
    REQUIRE(first.has_terminal);
    REQUIRE(second.has_terminal);
    CHECK_EQ(first.terminal.status_code, 201);
    CHECK_EQ(second.terminal.status_code, 201);
    CHECK_EQ(first.harness.state_resets, 1u);
    CHECK_EQ(second.harness.state_resets, 1u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, run_cache_isolation_preserves_process_state) {
    TempSource source;
    REQUIRE(source.write(
        "let seen = Cache<IP, i64>(capacity: 64)\n"
        "route GET \"/cache\" { let prev = seen.get(req.remoteAddr).or(0) if prev == 0 { "
        "seen.set(req.remoteAddr, 1) return 201 } else { return 200 } }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    harness::ScenarioState process_state{};
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/cache", 6};
    scenario.method = kRouteMethodGet;
    scenario.peer_addr = 0x0a00002au;
    scenario.state_isolation = harness::StateIsolation::Process;
    scenario.state = &process_state;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;

    const auto process_first = harness::drive_scenario(scenario, spec);
    scenario.state_isolation = harness::StateIsolation::Run;
    scenario.state = nullptr;
    scenario.peer_addr++;
    const auto unrelated_run = harness::drive_scenario(scenario, spec);
    scenario.state_isolation = harness::StateIsolation::Process;
    scenario.state = &process_state;
    scenario.peer_addr--;
    const auto process_second = harness::drive_scenario(scenario, spec);

    REQUIRE(process_first.has_terminal);
    REQUIRE(unrelated_run.has_terminal);
    REQUIRE(process_second.has_terminal);
    CHECK_EQ(process_first.terminal.status_code, 201);
    CHECK_EQ(unrelated_run.terminal.status_code, 201);
    CHECK_EQ(process_second.terminal.status_code, 200);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, rate_limit_state_obeys_group_and_run_isolation) {
    TempSource source;
    REQUIRE(
        source.write("@rateLimit(limit: 2, window: 1m)\nroute GET \"/limited\" { return 204 }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    const char request[] = "GET /limited HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioState state{};
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/limited", 8};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.peer_addr = 0x0a00002au;
    scenario.now_us = 100;
    scenario.state_isolation = harness::StateIsolation::Group;
    scenario.state_group = 1;
    scenario.state = &state;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;

    const auto first = harness::drive_scenario(scenario, spec);
    const auto second = harness::drive_scenario(scenario, spec);
    scenario.shard_id = 1;
    const auto other_shard = harness::drive_scenario(scenario, spec);
    scenario.shard_id = 0;
    const auto third = harness::drive_scenario(scenario, spec);
    REQUIRE(first.has_terminal);
    REQUIRE(second.has_terminal);
    REQUIRE(third.has_terminal);
    REQUIRE(other_shard.has_terminal);
    CHECK_EQ(first.terminal.status_code, 204);
    CHECK_EQ(second.terminal.status_code, 204);
    CHECK_EQ(other_shard.terminal.status_code, 204);
    CHECK_EQ(third.terminal.status_code, 429);

    scenario.state_isolation = harness::StateIsolation::Run;
    scenario.state = nullptr;
    const auto isolated_a = harness::drive_scenario(scenario, spec);
    const auto isolated_b = harness::drive_scenario(scenario, spec);
    CHECK_EQ(isolated_a.terminal.status_code, 204);
    CHECK_EQ(isolated_b.terminal.status_code, 204);
    state.reset();
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, reprepare_changes_shared_state_generation) {
    TempSource source;
    REQUIRE(
        source.write("@rateLimit(limit: 1, window: 1m)\nroute GET \"/limited\" { return 204 }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    const u64 first_generation = target.generation;
    harness::ScenarioState state{};
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/limited", 8};
    scenario.method = kRouteMethodGet;
    scenario.peer_addr = 0x0a00002au;
    scenario.now_us = 100;
    scenario.state_isolation = harness::StateIsolation::Process;
    scenario.state = &state;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Connection;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;

    const auto first = harness::drive_scenario(scenario, spec);
    const auto limited = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);
    CHECK(target.generation != first_generation);
    const auto reloaded = harness::drive_scenario(scenario, spec);

    REQUIRE(first.has_terminal);
    REQUIRE(limited.has_terminal);
    REQUIRE(reloaded.has_terminal);
    CHECK_EQ(first.terminal.status_code, 204);
    CHECK_EQ(limited.terminal.status_code, 429);
    CHECK_EQ(reloaded.terminal.status_code, 204);
    CHECK_EQ(reloaded.harness.state_resets, 1u);
    state.reset();
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_source_target, prepares_production_loaded_program_and_cleans_up) {
    TempSource source;
    REQUIRE(source.write("route GET \"/health\" { return 204 }\n"));

    harness::SourceTarget target{};
    harness::HarnessSpec harness_spec{};
    harness_spec.layer = harness::ExecutionLayer::Handler;
    const harness::SourceTargetSpec target_spec{source.path, jit::OptLevel::O0};

    const auto result = target.prepare(target_spec, harness_spec);
    REQUIRE_EQ(result.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.phase, harness::Phase::Start);
    CHECK(target.prepared);
    CHECK(target.program.jit_inited);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
    CHECK(!target.prepared);
    CHECK(!target.program.jit_inited);
}

static_assert(!std::is_copy_constructible_v<harness::SourceTarget>);
static_assert(!std::is_copy_assignable_v<harness::SourceTarget>);
static_assert(!std::is_move_constructible_v<harness::SourceTarget>);
static_assert(!std::is_move_assignable_v<harness::SourceTarget>);

TEST(harness_source_target, can_prepare_again_after_successful_load) {
    TempSource source;
    REQUIRE(source.write("route GET \"/health\" { return 204 }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto first = target.prepare({source.path, jit::OptLevel::O0}, spec);
    REQUIRE_EQ(first.outcome, harness::Outcome::Passed);
    CHECK_EQ(target.program.config.route_count, 1u);
    const auto second = target.prepare({source.path, jit::OptLevel::O0}, spec);
    REQUIRE_EQ(second.outcome, harness::Outcome::Passed);
    CHECK_EQ(target.program.config.route_count, 1u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
    CHECK_EQ(target.program.config.route_count, 0u);
}

TEST(harness_source_target, preserves_compile_failure_and_remains_destroyable) {
    TempSource source;
    REQUIRE(source.write("route GET \"/broken\" { return }\n"));

    harness::SourceTarget target{};
    harness::HarnessSpec harness_spec{};
    const auto result = target.prepare({source.path, jit::OptLevel::O0}, harness_spec);
    CHECK_EQ(result.outcome, harness::Outcome::Failed);
    CHECK_EQ(result.phase, harness::Phase::Prepare);
    CHECK_EQ(result.cleanup, harness::CleanupOutcome::Clean);
    CHECK(!target.prepared);
    CHECK(!target.program.jit_inited);
    CHECK(result.detail[0] != '\0');
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_source_target, enforces_source_limit_before_loading) {
    TempSource source;
    REQUIRE(source.write("route GET \"/health\" { return 204 }\n"));

    harness::SourceTarget target{};
    harness::HarnessSpec harness_spec{};
    harness_spec.limits.max_source_bytes = 1;
    const auto result = target.prepare({source.path, jit::OptLevel::O0}, harness_spec);
    CHECK_EQ(result.outcome, harness::Outcome::Failed);
    CHECK(result.has_reached_limit);
    CHECK_EQ(result.reached_limit, harness::LimitKind::SourceBytes);
    CHECK_EQ(result.cleanup, harness::CleanupOutcome::Clean);
    CHECK(!target.prepared);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_source_target, enforces_source_limit_across_imported_modules) {
    TempSource imported;
    REQUIRE(imported.write("fn helper() -> i64 { return 1 }\n"));
    TempSource root;
    char source[256]{};
    const int source_len = std::snprintf(source,
                                         sizeof(source),
                                         "import \"%s\"\nroute GET \"/health\" { return 204 }\n",
                                         imported.path);
    REQUIRE(source_len > 0);
    REQUIRE(static_cast<size_t>(source_len) < sizeof(source));
    REQUIRE(root.write(source));

    harness::SourceTarget target{};
    harness::HarnessSpec harness_spec{};
    harness_spec.limits.max_source_bytes = static_cast<u64>(source_len);
    const auto result = target.prepare({root.path, jit::OptLevel::O0}, harness_spec);
    CHECK_EQ(result.outcome, harness::Outcome::Failed);
    CHECK(result.has_reached_limit);
    CHECK_EQ(result.reached_limit, harness::LimitKind::SourceBytes);
    CHECK_EQ(result.cleanup, harness::CleanupOutcome::Clean);
    CHECK(!target.prepared);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_source_target, jit_memory_failure_is_reported_and_cleaned) {
    TempSource source;
    REQUIRE(source.write("route GET \"/health\" { return 204 }\n"));

    harness::SourceTarget target{};
    harness::HarnessSpec harness_spec{};
    {
        test_fault::ScopedMemoryFault fault(0, true);
        const auto result = target.prepare({source.path, jit::OptLevel::O0}, harness_spec);
        CHECK_EQ(result.outcome, harness::Outcome::Failed);
        // ORC may materialize lazily at register-time symbol lookup.
        CHECK(target.load_error.stage == LoadStage::JitCompile ||
              target.load_error.stage == LoadStage::Codegen ||
              target.load_error.stage == LoadStage::Register);
        CHECK_EQ(result.cleanup, harness::CleanupOutcome::Clean);
        CHECK(!target.program.jit_inited);
    }
    CHECK(!target.prepared);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
    CHECK(!target.program.jit_inited);
}
#endif

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
