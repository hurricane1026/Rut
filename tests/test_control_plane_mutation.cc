#include "rut/runtime/control_plane_mutation.h"
#include "test.h"
#include <atomic>
#include <thread>

using namespace rut;

TEST(control_plane_mutation, route_reload_is_capability_gated_and_single_slot) {
    ControlPlaneMutationPort port;
    port.reset(7, false);
    u64 id = 99;
    CHECK(!port.request_reload(ReloadRequestSource::Route, &id));
    CHECK_EQ(id, 99u);
    REQUIRE(port.set_route_reload_enabled(true));
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    CHECK_EQ(id, 1u);  // the rejected, capability-gated attempt reserves no request id
    CHECK_EQ(port.state(), ReloadAdmissionState::Pending);
    CHECK(!port.request_reload(ReloadRequestSource::Route));

    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    CHECK_EQ(request.id, id);
    CHECK_EQ(request.source, ReloadRequestSource::Route);
    CHECK_EQ(port.state(), ReloadAdmissionState::InFlight);
    CHECK(!port.take_reload(&request));
}

TEST(control_plane_mutation, signal_reload_bypasses_route_authority_and_failure_is_not_applied) {
    ControlPlaneMutationPort port;
    port.reset(11, false);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(port.complete_reload(request.id, request.source, ReloadTerminalOutcome::CompileFailed));
    CHECK_EQ(port.state(), ReloadAdmissionState::Idle);
    CHECK_EQ(port.active_generation(), 11u);
    const auto record = port.last_record();
    REQUIRE(record.valid);
    CHECK_EQ(record.request_id, id);
    CHECK_EQ(record.source, ReloadRequestSource::Signal);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::CompileFailed);
    CHECK_EQ(record.old_generation, 11u);
    CHECK_EQ(record.new_generation, 0u);
}

TEST(control_plane_mutation, activation_advances_generation_and_clears_manual_health) {
    ControlPlaneMutationPort port;
    port.reset(3, true);
    const ServerIdentity old_server{3, 4, 2};
    REQUIRE(port.mark(old_server, false));
    CHECK_EQ(port.manual_health(old_server), ManualHealthOverride::Unhealthy);

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    CHECK(!port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 3));
    CHECK_EQ(port.state(), ReloadAdmissionState::InFlight);
    REQUIRE(port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4));
    CHECK_EQ(port.active_generation(), 4u);
    CHECK_EQ(port.state(), ReloadAdmissionState::Idle);
    CHECK_EQ(port.manual_health(old_server), ManualHealthOverride::None);
    CHECK(!port.mark(old_server, true));

    const ServerIdentity new_server{4, 4, 2};
    CHECK_EQ(port.manual_health(new_server), ManualHealthOverride::None);
    REQUIRE(port.mark(new_server, true));
    CHECK_EQ(port.manual_health(new_server), ManualHealthOverride::Healthy);
    const auto record = port.last_record();
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Activated);
    CHECK_EQ(record.old_generation, 3u);
    CHECK_EQ(record.new_generation, 4u);
}

TEST(control_plane_mutation, manual_health_rejects_foreign_slots_and_preserves_neighbors) {
    ControlPlaneMutationPort port;
    port.reset(9, false);
    const ServerIdentity first{9, 1, 0};
    const ServerIdentity second{9, 1, 1};
    REQUIRE(port.mark(first, false));
    REQUIRE(port.mark(second, true));
    CHECK_EQ(port.manual_health(first), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.manual_health(second), ManualHealthOverride::Healthy);
    CHECK(!port.mark({9, RouteConfig::kMaxUpstreams, 0}, true));
    CHECK(!port.mark({9, 0, UpstreamTarget::kMaxBackends}, true));
    CHECK(!port.mark({8, 1, 0}, true));
}

TEST(control_plane_mutation, stop_terminalizes_an_accepted_request_once) {
    ControlPlaneMutationPort port;
    port.reset(5, true);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    port.stop();
    CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
    CHECK(!port.request_reload(ReloadRequestSource::Signal));
    CHECK(!port.mark({5, 0, 0}, true));
    const auto record = port.last_record();
    REQUIRE(record.valid);
    CHECK_EQ(record.request_id, id);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Stopped);
    port.stop();
    CHECK_EQ(port.last_record().request_id, id);
}

TEST(control_plane_mutation, concurrent_reload_admission_has_exactly_one_winner) {
    ControlPlaneMutationPort port;
    port.reset(1, true);
    std::atomic<u32> ready{0};
    std::atomic<bool> start{false};
    std::atomic<u32> accepted{0};
    std::thread workers[8];
    for (auto& worker : workers) {
        worker = std::thread([&] {
            ready.fetch_add(1, std::memory_order_release);
            while (!start.load(std::memory_order_acquire)) {
            }
            if (port.request_reload(ReloadRequestSource::Route))
                accepted.fetch_add(1, std::memory_order_relaxed);
        });
    }
    while (ready.load(std::memory_order_acquire) != 8) {
    }
    start.store(true, std::memory_order_release);
    for (auto& worker : workers) worker.join();
    CHECK_EQ(accepted.load(std::memory_order_relaxed), 1u);
    CHECK_EQ(port.state(), ReloadAdmissionState::Pending);
}

TEST(control_plane_mutation, handler_context_latches_only_the_explicit_loop_capability) {
    struct Loop {
        ControlPlaneMutationPort* control_plane_mutation = nullptr;
    } loop;
    ControlPlaneMutationPort port;
    jit::HandlerCtx ctx{};
    loop.control_plane_mutation = &port;
    latch_control_plane_mutation(&loop, &ctx);
    CHECK(ctx.control_plane_mutation == &port);
    latch_control_plane_mutation<Loop>(nullptr, &ctx);
    CHECK(ctx.control_plane_mutation == nullptr);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
