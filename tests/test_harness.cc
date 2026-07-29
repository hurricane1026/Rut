#include "rut/harness/core.h"
#include "test.h"
#if RUT_ENABLE_JIT_TESTS
#include "fault_injection.h"
#include "rut/harness/connection_execution.h"
#include "rut/harness/handler_execution.h"
#include "rut/harness/scenario_driver.h"
#include "rut/harness/scripted_environment.h"
#include "rut/harness/source_target.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/cache_table.h"
#endif

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
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
    CHECK(std::strcmp(harness::capability_name(harness::Capability::ControlPlaneMutation),
                      "control-plane-mutation") == 0);
    CHECK(std::strcmp(harness::limit_name(harness::LimitKind::HandlerResumes), "handler-resumes") ==
          0);
}

#if RUT_ENABLE_JIT_TESTS
namespace {

u64 immediate_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return jit::HandlerResult::make_status(204).pack();
}

u64 reload_admission_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->control_plane_mutation == nullptr) return jit::HandlerResult::make_status(500).pack();
    const bool accepted = ctx->control_plane_mutation->request_reload(ReloadRequestSource::Route);
    return jit::HandlerResult::make_status(accepted ? 202 : 503).pack();
}

u64 mutable_body_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    char source[] = "stable-body";
    rut_helper_resp_set_body(ctx, source, sizeof(source) - 1);
    __builtin_memset(source, 'x', sizeof(source) - 1);
    rut_helper_resp_commit_headers(ctx);
    return jit::HandlerResult::make_status(200).pack();
}

u64 snapshotted_header_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    static constexpr char kBody[] = "saved-body";
    static constexpr char kName[] = "X-Saved";
    rut_helper_resp_set_body(ctx, kBody, sizeof(kBody) - 1);
    const char* snapshot = nullptr;
    u32 snapshot_len = 0;
    rut_helper_resp_body(ctx, nullptr, 0, &snapshot, &snapshot_len);
    rut_helper_resp_set_header(ctx, kName, sizeof(kName) - 1, snapshot, snapshot_len);
    rut_helper_resp_commit_headers(ctx);
    return jit::HandlerResult::make_status(200).pack();
}

u64 long_header_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    static char value[5000];
    __builtin_memset(value, 'v', sizeof(value));
    static constexpr char kName[] = "X-Long";
    rut_helper_resp_set_header(ctx, kName, sizeof(kName) - 1, value, sizeof(value));
    rut_helper_resp_commit_headers(ctx);
    return jit::HandlerResult::make_status(200).pack();
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

u64 captured_forward_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Forward, 7).pack();
    if (ctx->resume_event_kind != static_cast<u32>(jit::YieldKind::Forward) ||
        ctx->resume_event_result != 206 || !ctx->captured_response_valid ||
        ctx->captured_response_status != 206 || ctx->captured_response_body_len != 4 ||
        ctx->captured_response_header_count != 1 ||
        !ctx->captured_response_headers[0].value.eq({"fixture", 7}))
        return jit::HandlerResult::make_status(500).pack();
    return jit::HandlerResult::make_status(0).pack();
}

u64 captured_empty_forward_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Forward, 7).pack();
    if (!ctx->captured_response_valid || ctx->captured_response_body_len != 0)
        return jit::HandlerResult::make_status(500).pack();
    return jit::HandlerResult::make_status(0).pack();
}

u64 captured_passthrough_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Forward, 7).pack();
    if (!ctx->captured_response_valid) return jit::HandlerResult::make_status(500).pack();
    return jit::HandlerResult::make_status(0).pack();
}

u64 captured_body_mutation_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx->state == 0)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Forward, 7).pack();
    if (!ctx->captured_response_valid) return jit::HandlerResult::make_status(500).pack();
    static constexpr char kReplacement[] = "replacement";
    rut_helper_resp_set_body(ctx, kReplacement, sizeof(kReplacement) - 1);
    rut_helper_resp_commit_headers(ctx);
    return jit::HandlerResult::make_status(0).pack();
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

struct ResponseBodyObservation {
    bool seen = false;
    bool truncated = false;
    u64 timestamp_us = 0;
    u32 full_len = 0;
    u32 copied_len = 0;
    char bytes[4096]{};
};

bool capture_response_body_observation(void* context, const harness::Observation& event) {
    if (event.kind != harness::ObservationKind::ResponseBodyProduced) return true;
    auto* captured = static_cast<ResponseBodyObservation*>(context);
    captured->seen = true;
    captured->truncated = event.value1 != 0;
    captured->timestamp_us = event.timestamp_us;
    captured->full_len = static_cast<u32>(event.value0);
    captured->copied_len = event.label.len;
    if (event.label.len != 0) __builtin_memcpy(captured->bytes, event.label.ptr, event.label.len);
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

TEST(harness_handler, owns_mutated_response_body_after_driver_returns) {
    harness::HandlerExecution execution{};
    execution.init(&mutable_body_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically({execution}, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    REQUIRE(result.dynamic_response_body_valid);
    REQUIRE_EQ(result.dynamic_response_body_len, 11u);
    CHECK(std::memcmp(result.dynamic_response_body, "stable-body", 11) == 0);
}

TEST(harness_handler, owns_snapshotted_response_header_values_after_driver_returns) {
    harness::HandlerExecution execution{};
    execution.init(&snapshotted_header_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically({execution}, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE_EQ(result.response_header_count, 1u);
    CHECK(result.response_header_mutations[0].name.eq({"X-Saved", 7}));
    CHECK(result.response_header_mutations[0].value.eq({"saved-body", 10}));
}

TEST(harness_handler, owns_long_response_headers_across_result_copies) {
    harness::HandlerExecution execution{};
    execution.init(&long_header_handler, nullptr, nullptr, 0);
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    auto result = harness::drive_handler_deterministically({execution}, spec);
    REQUIRE_FALSE(result.response_header_overflow);
    REQUIRE_EQ(result.response_header_count, 1u);
    REQUIRE_EQ(result.response_header_mutations[0].value.len, 5000u);
    CHECK(result.response_header_mutations[0].value.ptr == result.response_header_values[0].data());

    auto copied = result;
    CHECK(copied.response_header_mutations[0].value.ptr == copied.response_header_values[0].data());
    CHECK(copied.response_header_mutations[0].value.ptr !=
          result.response_header_mutations[0].value.ptr);
    CHECK_EQ(copied.response_header_mutations[0].value.ptr[4999], 'v');

    auto moved = static_cast<harness::HandlerExecutionResult&&>(copied);
    CHECK(moved.response_header_mutations[0].value.ptr == moved.response_header_values[0].data());
    CHECK_EQ(moved.response_header_mutations[0].value.ptr[4999], 'v');
}

TEST(harness_handler, copying_session_clones_mutated_response_body_storage) {
    harness::HandlerExecution original{};
    original.init(&immediate_handler, nullptr, nullptr, 0);
    static const char kBody[] = "fork-safe";
    rut_helper_resp_set_body(&original.frame.context, kBody, sizeof(kBody) - 1);
    REQUIRE(original.frame.context.response_body_mutation_storage != nullptr);
    const char* snapshot = nullptr;
    u32 snapshot_len = 0;
    rut_helper_resp_body(&original.frame.context, nullptr, 0, &snapshot, &snapshot_len);
    REQUIRE(snapshot != nullptr);
    REQUIRE_EQ(snapshot_len, sizeof(kBody) - 1);

    harness::HandlerExecution fork = original;
    REQUIRE(fork.frame.context.response_body_mutation_storage != nullptr);
    CHECK(fork.frame.context.response_body_snapshot_storage ==
          original.frame.context.response_body_snapshot_storage);
    CHECK(fork.frame.context.response_body_mutation_storage !=
          original.frame.context.response_body_mutation_storage);
    __builtin_memset(original.frame.context.response_body_mutation_storage, 'x', sizeof(kBody) - 1);
    CHECK(std::memcmp(
              fork.frame.context.response_body_mutation_storage, kBody, sizeof(kBody) - 1) == 0);
    CHECK(std::memcmp(snapshot, kBody, sizeof(kBody) - 1) == 0);
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
    CHECK_EQ(result.terminal.upstream_id, 0u);
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

TEST(harness_handler, replays_owned_buffered_forward_response_fields) {
    harness::HandlerExecution execution{};
    execution.init(&captured_forward_handler, nullptr, nullptr, 0);
    static constexpr u8 kBody[] = {'b', 'o', 'd', 'y'};
    static constexpr char kName[] = "X-Origin";
    static constexpr char kValue[] = "fixture";
    const jit::CapturedResponseHeader headers[] = {
        {{kName, sizeof(kName) - 1}, {kValue, sizeof(kValue) - 1}},
    };
    const harness::DeterministicCompletion completions[] = {{
        jit::YieldKind::Forward,
        0,
        100,
        1,
        7,
        kBody,
        sizeof(kBody),
        false,
        false,
        206,
        headers,
        1,
    }};
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
    REQUIRE(result.uses_captured_response);
    CHECK_EQ(result.captured_response_body_len, sizeof(kBody));
    CHECK(std::memcmp(result.captured_response_body, kBody, sizeof(kBody)) == 0);
}

TEST(harness_handler, accepts_empty_captured_response_body) {
    harness::HandlerExecution execution{};
    execution.init(&captured_empty_forward_handler, nullptr, nullptr, 0);
    const harness::DeterministicCompletion completions[] = {{
        jit::YieldKind::Forward,
        0,
        100,
        1,
        7,
        nullptr,
        0,
        false,
        false,
        204,
        nullptr,
        0,
    }};
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
    CHECK_EQ(result.terminal.status_code, 204);
    CHECK(result.uses_captured_response);
    CHECK_EQ(result.captured_response_body_len, 0u);
}

TEST(harness_handler, routes_captured_body_mutations_through_captured_storage) {
    harness::HandlerExecution execution{};
    execution.init(&captured_body_mutation_handler, nullptr, nullptr, 0);
    static constexpr u8 kOriginal[] = {'o', 'l', 'd'};
    const harness::DeterministicCompletion completions[] = {{
        jit::YieldKind::Forward,
        0,
        100,
        1,
        7,
        kOriginal,
        sizeof(kOriginal),
        false,
        false,
        200,
        nullptr,
        0,
    }};
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    static constexpr char kExpected[] = "replacement";
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.uses_captured_response);
    CHECK(result.captured_response_body_mutated);
    REQUIRE_EQ(result.captured_response_body_len, sizeof(kExpected) - 1);
    CHECK(std::memcmp(result.captured_response_body, kExpected, sizeof(kExpected) - 1) == 0);
}

TEST(harness_handler, preserves_captured_body_beyond_dynamic_json_limit) {
    harness::HandlerExecution execution{};
    execution.init(&captured_passthrough_handler, nullptr, nullptr, 0);
    static u8 body[12000];
    for (u32 i = 0; i < sizeof(body); i++) body[i] = static_cast<u8>('a' + i % 26);
    const harness::DeterministicCompletion completions[] = {{
        jit::YieldKind::Forward,
        0,
        100,
        1,
        7,
        body,
        sizeof(body),
        false,
        false,
        200,
        nullptr,
        0,
    }};
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.uses_captured_response);
    CHECK_FALSE(result.captured_response_body_mutated);
    CHECK_EQ(result.captured_response_body_len, sizeof(body));
    CHECK(std::memcmp(result.captured_response_body, body, sizeof(body)) == 0);
}

TEST(harness_handler, owns_captured_headers_across_result_copies) {
    harness::HandlerExecution execution{};
    execution.init(&captured_passthrough_handler, nullptr, nullptr, 0);
    const jit::CapturedResponseHeader headers[] = {
        {{"X-Origin", 8}, {"fixture", 7}},
    };
    const harness::DeterministicCompletion completions[] = {{
        jit::YieldKind::Forward,
        0,
        100,
        1,
        7,
        nullptr,
        0,
        false,
        false,
        204,
        headers,
        1,
    }};
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    const harness::HandlerExecutionResult copied = result;
    REQUIRE(copied.uses_captured_response);
    CHECK_EQ(copied.captured_response_body_mutated, result.captured_response_body_mutated);
    REQUIRE_EQ(copied.captured_response_header_count, 1u);
    CHECK(copied.captured_response_headers[0].name.eq({"X-Origin", 8}));
    CHECK(copied.captured_response_headers[0].value.eq({"fixture", 7}));
}

TEST(harness_handler, normalizes_captured_content_length_for_request_method) {
    const auto run = [](const u8* request, u32 request_len) {
        static const u8 body[123]{};
        const bool head = request_len >= 4 && request[0] == 'H';
        harness::HandlerExecution execution{};
        execution.init(&captured_passthrough_handler, nullptr, request, request_len);
        const jit::CapturedResponseHeader headers[] = {
            {{"Content-Length", 14}, {"123", 3}},
            {{"X-Origin", 8}, {"fixture", 7}},
        };
        const harness::DeterministicCompletion completion = {
            jit::YieldKind::Forward,
            0,
            100,
            1,
            7,
            head ? nullptr : body,
            head ? 0u : static_cast<u32>(sizeof(body)),
            false,
            false,
            200,
            headers,
            2,
        };
        harness::DeterministicEnvironment environment{};
        environment.reset(&completion, 1);
        harness::DeterministicHandlerSpec driver{};
        driver.execution = execution;
        driver.environment = &environment;
        harness::HarnessSpec spec{};
        spec.layer = harness::ExecutionLayer::Handler;
        return harness::drive_handler_deterministically(driver, spec);
    };

    static constexpr u8 kGet[] = "GET /x HTTP/1.1\r\nHost: test\r\n\r\n";
    const auto get = run(kGet, sizeof(kGet) - 1);
    REQUIRE_EQ(get.harness.outcome, harness::Outcome::Passed);
    REQUIRE_EQ(get.captured_response_header_count, 1u);
    CHECK(get.captured_response_headers[0].name.eq({"X-Origin", 8}));

    static constexpr u8 kHead[] = "HEAD /x HTTP/1.1\r\nHost: test\r\n\r\n";
    const auto head = run(kHead, sizeof(kHead) - 1);
    REQUIRE_EQ(head.harness.outcome, harness::Outcome::Passed);
    REQUIRE_EQ(head.captured_response_header_count, 2u);
    CHECK(head.captured_response_headers[0].name.eq({"Content-Length", 14}));
}

TEST(harness_handler, rejects_null_captured_response_header_views) {
    harness::HandlerExecution execution{};
    execution.init(&captured_forward_handler, nullptr, nullptr, 0);
    const jit::CapturedResponseHeader headers[] = {
        {{nullptr, 1}, {"fixture", 7}},
    };
    const harness::DeterministicCompletion completions[] = {{
        jit::YieldKind::Forward,
        0,
        100,
        1,
        7,
        nullptr,
        0,
        false,
        false,
        206,
        headers,
        1,
    }};
    harness::DeterministicEnvironment environment{};
    environment.reset(completions, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
}

TEST(harness_handler, rejects_informational_captured_response_fixtures) {
    for (const u16 status : {100u, 103u, 199u}) {
        harness::HandlerExecution execution{};
        execution.init(&captured_passthrough_handler, nullptr, nullptr, 0);
        const harness::DeterministicCompletion completion = {
            jit::YieldKind::Forward, 0, 100, 1, 7, nullptr, 0, false, false, status, nullptr, 0};
        harness::DeterministicEnvironment environment{};
        environment.reset(&completion, 1);
        harness::DeterministicHandlerSpec driver{};
        driver.execution = execution;
        driver.environment = &environment;
        harness::HarnessSpec spec{};
        spec.layer = harness::ExecutionLayer::Handler;

        const auto result = harness::drive_handler_deterministically(driver, spec);
        CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    }
}

TEST(harness_handler, rejects_invalid_captured_response_header_syntax) {
    const jit::CapturedResponseHeader invalid_headers[] = {
        {{"", 0}, {"value", 5}},
        {{"Bad Name", 8}, {"value", 5}},
        {{"X-Test", 6}, {"bad\rvalue", 9}},
    };
    for (const auto& header : invalid_headers) {
        harness::HandlerExecution execution{};
        execution.init(&captured_passthrough_handler, nullptr, nullptr, 0);
        const harness::DeterministicCompletion completion = {
            jit::YieldKind::Forward, 0, 100, 1, 7, nullptr, 0, false, false, 206, &header, 1};
        harness::DeterministicEnvironment environment{};
        environment.reset(&completion, 1);
        harness::DeterministicHandlerSpec driver{};
        driver.execution = execution;
        driver.environment = &environment;
        harness::HarnessSpec spec{};
        spec.layer = harness::ExecutionLayer::Handler;

        const auto result = harness::drive_handler_deterministically(driver, spec);
        CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    }
}

TEST(harness_handler, rejects_bodies_for_bodyless_forward_fixtures) {
    static const u8 body[] = {'x'};
    for (const u16 status : {204u, 205u, 304u}) {
        harness::HandlerExecution execution{};
        execution.init(&captured_passthrough_handler, nullptr, nullptr, 0);
        const harness::DeterministicCompletion completion = {
            jit::YieldKind::Forward, 0, 100, 1, 7, body, 1, false, false, status, nullptr, 0};
        harness::DeterministicEnvironment environment{};
        environment.reset(&completion, 1);
        harness::DeterministicHandlerSpec driver{};
        driver.execution = execution;
        driver.environment = &environment;
        harness::HarnessSpec spec{};
        spec.layer = harness::ExecutionLayer::Handler;
        CHECK_EQ(harness::drive_handler_deterministically(driver, spec).harness.outcome,
                 harness::Outcome::Invalid);
    }
}

TEST(harness_handler, rejects_captured_content_length_body_mismatch) {
    static constexpr u8 request[] = "GET /x HTTP/1.1\r\nHost: test\r\n\r\n";
    static constexpr u8 body[] = {'x'};
    const jit::CapturedResponseHeader headers[] = {
        {{"Content-Length", 14}, {"10", 2}},
    };
    harness::HandlerExecution execution{};
    execution.init(&captured_passthrough_handler, nullptr, request, sizeof(request) - 1);
    const harness::DeterministicCompletion completion = {
        jit::YieldKind::Forward, 0, 100, 1, 7, body, 1, false, false, 200, headers, 1};
    harness::DeterministicEnvironment environment{};
    environment.reset(&completion, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    const auto result = harness::drive_handler_deterministically(driver, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(result.harness.cleanup, harness::CleanupOutcome::Clean);
}

TEST(harness_handler, rejects_hop_by_hop_forward_fixture_headers) {
    const jit::CapturedResponseHeader headers[] = {
        {{"Connection", 10}, {"X-Private", 9}},
        {{"Transfer-Encoding", 17}, {"chunked", 7}},
        {{"Keep-Alive", 10}, {"timeout=5", 9}},
    };
    for (const auto& header : headers) {
        harness::HandlerExecution execution{};
        execution.init(&captured_passthrough_handler, nullptr, nullptr, 0);
        const harness::DeterministicCompletion completion = {
            jit::YieldKind::Forward, 0, 100, 1, 7, nullptr, 0, false, false, 200, &header, 1};
        harness::DeterministicEnvironment environment{};
        environment.reset(&completion, 1);
        harness::DeterministicHandlerSpec driver{};
        driver.execution = execution;
        driver.environment = &environment;
        harness::HarnessSpec spec{};
        spec.layer = harness::ExecutionLayer::Handler;
        CHECK_EQ(harness::drive_handler_deterministically(driver, spec).harness.outcome,
                 harness::Outcome::Invalid);
    }
}

TEST(harness_handler, captured_response_headers_count_toward_input_limit) {
    harness::HandlerExecution execution{};
    execution.init(&captured_passthrough_handler, nullptr, nullptr, 0);
    const jit::CapturedResponseHeader header = {{"X-Origin", 8}, {"fixture", 7}};
    const harness::DeterministicCompletion completion = {
        jit::YieldKind::Forward, 0, 100, 1, 7, nullptr, 0, false, false, 206, &header, 1};
    harness::DeterministicEnvironment environment{};
    environment.reset(&completion, 1);
    harness::DeterministicHandlerSpec driver{};
    driver.execution = execution;
    driver.environment = &environment;
    harness::HarnessSpec spec{};
    spec.layer = harness::ExecutionLayer::Handler;

    auto result = harness::drive_handler_deterministically(driver, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.harness.input_bytes, 15u);

    environment.reset(&completion, 1);
    spec.limits.max_input_bytes = 14;
    result = harness::drive_handler_deterministically(driver, spec);
    CHECK_EQ(result.harness.outcome, harness::Outcome::Failed);
    CHECK_EQ(result.harness.reached_limit, harness::LimitKind::InputBytes);
}

TEST(harness_handler, failed_captured_forward_terminates_without_resuming) {
    for (const bool injected_fault : {false, true}) {
        harness::HandlerExecution execution{};
        execution.init(&captured_passthrough_handler, nullptr, nullptr, 0);
        const harness::DeterministicCompletion completion = {
            jit::YieldKind::Forward,
            injected_fault ? 0 : -ECONNRESET,
            100,
            1,
            7,
            nullptr,
            0,
            true,
            injected_fault,
            0,
            nullptr,
            0,
        };
        harness::DeterministicEnvironment environment{};
        environment.reset(&completion, 1);
        harness::DeterministicHandlerSpec driver{};
        driver.execution = execution;
        driver.environment = &environment;
        harness::HarnessSpec spec{};
        spec.layer = harness::ExecutionLayer::Handler;

        const auto result = harness::drive_handler_deterministically(driver, spec);
        REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
        REQUIRE(result.has_terminal);
        CHECK_EQ(result.terminal.action, jit::HandlerAction::ReturnStatus);
        CHECK_EQ(result.terminal.status_code, 502);
        CHECK_EQ(result.harness.handler_resumes, 0u);
        CHECK_FALSE(result.uses_captured_response);
    }
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

TEST(harness_scenario, empty_capture_and_headers_survive_connection_formatting) {
    TempSource source;
    REQUIRE(source.write(R"rut(
upstream api at "127.0.0.1:9000"
route GET "/x" {
    let resp = forward(api, buffered: true)
    return resp
}
)rut"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    static constexpr char kName[] = "X-Origin";
    static constexpr char kValue[] = "fixture";
    const jit::CapturedResponseHeader headers[] = {
        {{kName, sizeof(kName) - 1}, {kValue, sizeof(kValue) - 1}},
    };
    const auto run = [&](bool with_header) {
        harness::ScriptedEnvironment environment{};
        auto& completion = environment.base_completions[0];
        completion.kind = jit::YieldKind::Forward;
        completion.result = 204;
        completion.at_us = 1;
        completion.order = 1;
        completion.target_id = 0;
        completion.logical_fault_point = true;
        completion.response_status = 204;
        completion.response_headers = with_header ? headers : nullptr;
        completion.response_header_count = with_header ? 1 : 0;
        environment.completion_count = 1;
        environment.next_order = 2;

        static const char kRequest[] = "GET /x HTTP/1.1\r\nHost: test\r\n\r\n";
        harness::ScenarioSpec scenario{};
        scenario.target = &target;
        scenario.path = {"/x", 2};
        scenario.method = kRouteMethodGet;
        scenario.request_data = reinterpret_cast<const u8*>(kRequest);
        scenario.request_len = sizeof(kRequest) - 1;
        scenario.environment = &environment;
        scenario.expected = {true, jit::HandlerAction::ReturnStatus, 204};
        return harness::drive_scenario(scenario, scripted_scenario_harness());
    };

    const auto without_header = run(false);
    const auto with_header = run(true);
    REQUIRE_EQ(without_header.harness.outcome, harness::Outcome::Passed);
    REQUIRE_EQ(with_header.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(with_header.terminal.status_code, 204u);
    // Headerless captured responses still take the captured formatter path, so
    // a 204 does not gain a synthetic Content-Length field.
    CHECK_EQ(with_header.harness.output_bytes, without_header.harness.output_bytes + 19);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, captured_head_preserves_representation_content_length) {
    TempSource source;
    REQUIRE(source.write(R"rut(
upstream api at "127.0.0.1:9000"
route HEAD "/x" {
    let resp = forward(api, buffered: true)
    return resp
}
)rut"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    const auto run = [&](const jit::CapturedResponseHeader* headers, u32 header_count) {
        harness::ScriptedEnvironment environment{};
        auto& completion = environment.base_completions[0];
        completion.kind = jit::YieldKind::Forward;
        completion.result = 200;
        completion.at_us = 1;
        completion.order = 1;
        completion.target_id = 0;
        completion.logical_fault_point = true;
        completion.response_status = 200;
        completion.response_headers = headers;
        completion.response_header_count = header_count;
        environment.completion_count = 1;
        environment.next_order = 2;

        static const char kRequest[] = "HEAD /x HTTP/1.1\r\nHost: test\r\n\r\n";
        harness::ScenarioSpec scenario{};
        scenario.target = &target;
        scenario.path = {"/x", 2};
        scenario.method = kRouteMethodHead;
        scenario.request_data = reinterpret_cast<const u8*>(kRequest);
        scenario.request_len = sizeof(kRequest) - 1;
        scenario.environment = &environment;
        scenario.expected = {true, jit::HandlerAction::ReturnStatus, 200};
        return harness::drive_scenario(scenario, scripted_scenario_harness());
    };

    const jit::CapturedResponseHeader short_headers[] = {
        {{"Content-Length", 14}, {"0", 1}},
    };
    const jit::CapturedResponseHeader representation_headers[] = {
        {{"Content-Length", 14}, {"123", 3}},
    };
    const jit::CapturedResponseHeader matching_duplicate_headers[] = {
        {{"Content-Length", 14}, {"123", 3}},
        {{"content-length", 14}, {"123", 3}},
    };
    const jit::CapturedResponseHeader invalid_headers[] = {
        {{"Content-Length", 14}, {"nope", 4}},
    };
    const jit::CapturedResponseHeader conflicting_headers[] = {
        {{"Content-Length", 14}, {"1", 1}},
        {{"content-length", 14}, {"2", 1}},
    };
    const auto short_length = run(short_headers, 1);
    const auto representation_length = run(representation_headers, 1);
    const auto matching_duplicates = run(matching_duplicate_headers, 2);
    const auto invalid = run(invalid_headers, 1);
    const auto conflicting = run(conflicting_headers, 2);
    REQUIRE_EQ(short_length.harness.outcome, harness::Outcome::Passed);
    REQUIRE_EQ(representation_length.harness.outcome, harness::Outcome::Passed);
    REQUIRE_EQ(matching_duplicates.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(invalid.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(conflicting.harness.outcome, harness::Outcome::Invalid);
    CHECK_EQ(representation_length.harness.output_bytes, short_length.harness.output_bytes + 2);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, large_capture_reaches_truncated_body_observation) {
    TempSource source;
    REQUIRE(source.write(R"rut(
upstream api at "127.0.0.1:9000"
route GET "/x" {
    let resp = forward(api, buffered: true)
    return resp
}
)rut"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    static u8 body[12000];
    for (u32 i = 0; i < sizeof(body); i++) body[i] = static_cast<u8>('a' + i % 26);
    harness::ScriptedEnvironment environment{};
    auto& completion = environment.base_completions[0];
    completion.kind = jit::YieldKind::Forward;
    completion.result = 200;
    completion.at_us = 1;
    completion.order = 1;
    completion.target_id = 0;
    completion.logical_fault_point = true;
    completion.data = body;
    completion.data_len = sizeof(body);
    completion.response_status = 200;
    environment.completion_count = 1;
    environment.next_order = 2;

    static const char kRequest[] = "GET /x HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(kRequest);
    scenario.request_len = sizeof(kRequest) - 1;
    scenario.environment = &environment;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 200};

    ResponseBodyObservation observed{};
    auto spec = scripted_scenario_harness();
    spec.observations = {&observed, &capture_response_body_observation};
    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.terminal.status_code, 200u);
    REQUIRE(observed.seen);
    CHECK(observed.truncated);
    CHECK_EQ(observed.full_len, sizeof(body));
    CHECK_EQ(observed.copied_len, sizeof(observed.bytes));
    CHECK(std::memcmp(observed.bytes, body, sizeof(observed.bytes)) == 0);
    CHECK_GT(result.harness.output_bytes, sizeof(body));
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
    ResponseBodyObservation observed{};
    spec.observations = {&observed, &capture_response_body_observation};
    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.terminal.status_code, 200);
    REQUIRE(observed.seen);
    CHECK(!observed.truncated);
    CHECK_EQ(observed.full_len, 13u);
    CHECK_EQ(observed.copied_len, 13u);
    CHECK(__builtin_memcmp(observed.bytes, "{\"path\":\"/x\"}", 13) == 0);
    CHECK_EQ(result.harness.output_bytes, 117u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, control_plane_snapshot_fixture_replays_exact_json) {
    TempSource source;
    REQUIRE(source.write("route GET \"/stats\" { wait(1) return 200, json(stats()) }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    jit::ControlPlaneSnapshot fixture{};
    fixture.valid = true;
    fixture.shard_id = 2;
    fixture.shard_count = 4;
    fixture.stats.requests_total = 9;
    fixture.stats.requests_active = 1;
    fixture.stats.connections_total = 8;
    fixture.stats.connections_active = 2;
    fixture.stats.connections_closed = 6;
    fixture.stats.request_latency_buckets[0] = 3;
    fixture.stats.request_latency_sum_us = 30;
    fixture.stats.request_latency_count = 3;
    fixture.stats.memory_arena_used = 10;
    fixture.stats.memory_slices_used = 11;
    fixture.stats.memory_slices_free = 12;
    fixture.stats.memory_connections_used = 13;
    static constexpr char kExpectedBytes[] =
        "{\"scope\":\"shard\",\"shard_id\":2,\"shard_count\":4,\"requests\":{"
        "\"total\":9,\"active\":1,\"latency_us\":{\"buckets\":[3,0,0,0,0,0,0,0,0,0,"
        "0],\"sum\":30,\"count\":3}},\"connections\":{\"total\":8,\"active\":2,"
        "\"closed\":6},\"memory\":{\"arena_used\":10,\"slices_used\":11,"
        "\"slices_free\":12,\"connections_used\":13}}";
    const Str kExpected{kExpectedBytes, sizeof(kExpectedBytes) - 1};

    const char request[] = "GET /stats HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/stats", 6};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.control_plane_snapshot = &fixture;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 200};

    auto spec = scripted_scenario_harness();
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.required_capabilities.add(harness::Capability::ControlPlaneSnapshot);
    spec.environment_capabilities = spec.required_capabilities;
    ResponseBodyObservation first_body{};
    spec.observations = {&first_body, &capture_response_body_observation};
    const auto first = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(first.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(first.harness.handler_resumes, 1u);
    REQUIRE(first_body.seen);
    CHECK(!first_body.truncated);
    CHECK_EQ(first_body.full_len, kExpected.len);
    CHECK_EQ(first_body.copied_len, kExpected.len);
    CHECK(__builtin_memcmp(first_body.bytes, kExpected.ptr, kExpected.len) == 0);
    CHECK(first.harness.output_bytes > kExpected.len);

    ResponseBodyObservation replay_body{};
    spec.observations = {&replay_body, &capture_response_body_observation};
    const auto replay = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(replay.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(replay.harness.output_bytes, first.harness.output_bytes);
    CHECK_EQ(replay_body.copied_len, first_body.copied_len);
    CHECK(__builtin_memcmp(replay_body.bytes, first_body.bytes, first_body.copied_len) == 0);

    scenario.control_plane_snapshot = nullptr;
    const auto missing = harness::drive_scenario(scenario, spec);
    CHECK_EQ(missing.harness.outcome, harness::Outcome::Invalid);
    CHECK(std::strcmp(missing.harness.detail, "control-plane snapshot fixture is missing") == 0);

    jit::ControlPlaneSnapshot invalid_fixture{};
    scenario.control_plane_snapshot = &invalid_fixture;
    const auto invalid = harness::drive_scenario(scenario, spec);
    CHECK_EQ(invalid.harness.outcome, harness::Outcome::Invalid);
    CHECK(std::strcmp(invalid.harness.detail, "control-plane snapshot fixture is invalid") == 0);

    invalid_fixture.valid = true;
    invalid_fixture.shard_count = 0;
    const auto empty_topology = harness::drive_scenario(scenario, spec);
    CHECK_EQ(empty_topology.harness.outcome, harness::Outcome::Invalid);
    CHECK(std::strcmp(empty_topology.harness.detail, "control-plane snapshot fixture is invalid") ==
          0);

    invalid_fixture.shard_count = 2;
    invalid_fixture.shard_id = 2;
    const auto out_of_range_shard = harness::drive_scenario(scenario, spec);
    CHECK_EQ(out_of_range_shard.harness.outcome, harness::Outcome::Invalid);
    CHECK(std::strcmp(out_of_range_shard.harness.detail,
                      "control-plane snapshot fixture is invalid") == 0);

    scenario.control_plane_snapshot = nullptr;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    const auto undeclared = harness::drive_scenario(scenario, spec);
    CHECK_EQ(undeclared.harness.outcome, harness::Outcome::Invalid);
    CHECK(std::strcmp(undeclared.harness.detail,
                      "selected route requires a control-plane snapshot fixture") == 0);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, dynamic_json_overflow_has_deterministic_500_observation) {
    std::string source = "route GET \"/x\" { return 200, json({ path: req.path, value: \"";
    source.append(jit::kMaxDynamicResponseBodyBytes - 22, 'x');
    source += "\" }) }\n";
    TempSource file;
    REQUIRE(file.write(source.c_str()));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({file.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    const char request[] = "GET /x HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 500};

    ResponseBodyObservation observed{};
    auto spec = scripted_scenario_harness();
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    spec.observations = {&observed, &capture_response_body_observation};
    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.terminal.status_code, 500);
    REQUIRE(observed.seen);
    CHECK(!observed.truncated);
    CHECK_EQ(observed.full_len, 21u);
    CHECK_EQ(observed.copied_len, 21u);
    CHECK(__builtin_memcmp(observed.bytes, "Internal Server Error", 21) == 0);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, dynamic_json_failure_preserves_committed_body_mutation) {
    std::string source =
        "func rewrite(_ resp: Response) -> i32 { resp.body = \"fallback\" 0 }\n"
        "chain rewrite_chain { after rewrite(resp) }\n"
        "route GET \"/x\" use chain rewrite_chain { return 200, json({ path: req.path, value: \"";
    source.append(jit::kMaxDynamicResponseBodyBytes - 22, 'x');
    source += "\" }) }\n";
    TempSource file;
    REQUIRE(file.write(source.c_str()));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({file.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    const char request[] = "GET /x HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 500};

    ResponseBodyObservation observed{};
    auto spec = scripted_scenario_harness();
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    spec.observations = {&observed, &capture_response_body_observation};
    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.terminal.status_code, 500);
    REQUIRE(observed.seen);
    CHECK_EQ(observed.full_len, 8u);
    CHECK_EQ(observed.copied_len, 8u);
    CHECK(__builtin_memcmp(observed.bytes, "fallback", 8) == 0);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, reusable_json_body_mutation_survives_resume) {
    TempSource source;
    REQUIRE(source.write(
        "route GET \"/x\" { let body = json({ path: req.path }) let resp = response(200) "
        "resp.body = body wait(1) return resp }\n"));
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
    scenario.now_us = 700;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 200};

    auto spec = scripted_scenario_harness();
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    ResponseBodyObservation observed{};
    spec.observations = {&observed, &capture_response_body_observation};
    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.terminal.status_code, 200);
    CHECK_EQ(result.harness.handler_resumes, 1u);
    REQUIRE(observed.seen);
    CHECK_EQ(observed.timestamp_us, result.harness.virtual_time_us);
    CHECK_GT(observed.timestamp_us, scenario.now_us);
    CHECK_EQ(result.harness.output_bytes, 117u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, declared_struct_json_body_is_accounted_as_runtime_output) {
    TempSource source;
    REQUIRE(
        source.write("struct Payload { path: str, code: i32 }\n"
                     "route GET \"/x\" { let p = Payload(path: req.path, code: 40 + 2) return 200, "
                     "json(p) }\n"));
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
    CHECK_EQ(result.harness.output_bytes, 127u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, dynamic_json_head_accounts_representation_without_payload) {
    TempSource source;
    REQUIRE(source.write("route HEAD \"/x\" { return 200, json({ path: req.path }) }\n"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    const char request[] = "HEAD /x HTTP/1.1\r\nHost: test\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodHead;
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
    CHECK_EQ(result.harness.output_bytes, 104u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, bodyless_dynamic_json_failure_preserves_status) {
    TempSource source;
    REQUIRE(source.write(R"rut(
route GET "/x" {
    return 204, json({ value: req.header("X-Value").or("") })
}
)rut"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    static const char kRequest[] = "GET /x HTTP/1.1\r\nHost: test\r\nX-Value: \xc0\x80\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(kRequest);
    scenario.request_len = sizeof(kRequest) - 1;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 204};

    auto spec = scripted_scenario_harness();
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.terminal.status_code, 204u);
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

    static const char kWith[] = "GET /with HTTP/1.1\r\nHost: test\r\nX-Value: \xc0\x80\r\n\r\n";
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

TEST(harness_scenario, dynamic_json_failure_overrides_committed_status) {
    TempSource source;
    REQUIRE(source.write(R"rut(
func set_status(_ resp: Response) -> i32 {
    resp.status = 202
    0
}
chain observed { after set_status(resp) }
route GET "/x" use chain observed {
    return 200, json({ value: req.header("X-Value").or("") })
}
)rut"));
    harness::SourceTarget target{};
    harness::HarnessSpec load_spec{};
    REQUIRE_EQ(target.prepare({source.path, jit::OptLevel::O0}, load_spec).outcome,
               harness::Outcome::Passed);

    static const char kRequest[] = "GET /x HTTP/1.1\r\nHost: test\r\nX-Value: \xc0\x80\r\n\r\n";
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/x", 2};
    scenario.method = kRouteMethodGet;
    scenario.request_data = reinterpret_cast<const u8*>(kRequest);
    scenario.request_len = sizeof(kRequest) - 1;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 500};

    auto spec = scripted_scenario_harness();
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    REQUIRE(result.has_terminal);
    CHECK_EQ(result.terminal.status_code, 500u);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, committed_response_status_and_body_are_observed_after_wait) {
    TempSource source;
    REQUIRE(source.write(
        "func rewrite(_ resp: Response) -> i32 { resp.status = 201 resp.body = \"after-wait\" 0 }\n"
        "chain access { after rewrite(resp) }\n"
        "route GET \"/x\" use chain access { wait(1) return 200, \"before\" }\n"));
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
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 201};

    auto spec = scripted_scenario_harness();
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    const auto result = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.terminal.status_code, 201);
    CHECK_EQ(result.harness.handler_resumes, 1u);
    CHECK(result.harness.output_bytes > sizeof("after-wait") - 1);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, response_field_reads_drive_committed_status_and_body) {
    TempSource source;
    REQUIRE(
        source.write("route GET \"/x\" { let resp = response(200) let initial = resp.status "
                     "resp.status = initial + 1 resp.body = req.path resp.status = resp.status + 1 "
                     "resp.body = resp.body return resp }\n"));
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
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 202};

    const auto result = harness::drive_scenario(scenario, scripted_scenario_harness());
    REQUIRE_EQ(result.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(result.terminal.status_code, 202);
    CHECK(result.harness.output_bytes > sizeof("/x") - 1);
    CHECK_EQ(target.destroy(), harness::CleanupOutcome::Clean);
}

TEST(harness_scenario, control_plane_mutation_fixture_follows_state_isolation) {
    harness::SourceTarget target{};
    REQUIRE(target.program.config.add_jit_handler(
        "/reload", kRouteMethodPost, &reload_admission_handler));
    REQUIRE(target.program.config.add_upstream("test", 0x7f000001u, 8000));
    target.prepared = true;
    ControlPlaneMutationPort mutation;
    mutation.reset(1, true, &target.program.config);
    harness::ScenarioSpec scenario{};
    scenario.target = &target;
    scenario.path = {"/reload", 7};
    scenario.method = kRouteMethodPost;
    const char request[] = "POST /reload HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n";
    scenario.request_data = reinterpret_cast<const u8*>(request);
    scenario.request_len = sizeof(request) - 1;
    scenario.control_plane_mutation = &mutation;
    scenario.expected = {true, jit::HandlerAction::ReturnStatus, 202};
    auto spec = scripted_scenario_harness();
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.required_capabilities.add(harness::Capability::ControlPlaneMutation);
    spec.environment_capabilities = spec.required_capabilities;

    const auto accepted = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(accepted.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(accepted.terminal.status_code, 202);
    REQUIRE(mutation.mark({1, 0, 0}, false));
    const auto fresh_run = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(fresh_run.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(fresh_run.terminal.status_code, 202);

    harness::ScenarioState group_state{};
    scenario.state_isolation = harness::StateIsolation::Group;
    scenario.state_group = 7;
    scenario.state = &group_state;
    const auto group_accepted = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(group_accepted.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(group_accepted.terminal.status_code, 202);
    scenario.expected.value = 503;
    const auto group_full = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(group_full.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(group_full.terminal.status_code, 503);

    ControlPlaneMutationPort other_mutation;
    other_mutation.reset(1, true, &target.program.config);
    REQUIRE(other_mutation.request_reload(ReloadRequestSource::Signal));
    scenario.control_plane_mutation = &other_mutation;
    scenario.expected.value = 202;
    const auto switched_fixture = harness::drive_scenario(scenario, spec);
    REQUIRE_EQ(switched_fixture.harness.outcome, harness::Outcome::Passed);
    CHECK_EQ(switched_fixture.terminal.status_code, 202);
    scenario.control_plane_mutation = &mutation;
    scenario.expected.value = 503;

    scenario.control_plane_mutation = nullptr;
    const auto missing = harness::drive_scenario(scenario, spec);
    CHECK_EQ(missing.harness.outcome, harness::Outcome::Invalid);
    CHECK(std::strcmp(missing.harness.detail, "control-plane mutation fixture is missing") == 0);
    scenario.control_plane_mutation = &mutation;
    spec.required_capabilities =
        harness::Capability::SyntheticIo | harness::Capability::VirtualTime;
    spec.environment_capabilities = spec.required_capabilities;
    const auto undeclared = harness::drive_scenario(scenario, spec);
    CHECK_EQ(undeclared.harness.outcome, harness::Outcome::Invalid);
    CHECK(std::strcmp(undeclared.harness.detail,
                      "control-plane mutation capability was not declared") == 0);
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
