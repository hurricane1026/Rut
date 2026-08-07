#include "rut/reload_coordinator.h"
#include "test.h"
#include <filesystem>
#include <fstream>

using namespace rut;

namespace {

struct FakeLoader {
    bool succeed = true;
    bool add_cache = false;
    u32 cache_capacity = 64;
    i32 timer_shard = -1;
    bool change_firewall = false;
    u32 calls = 0;
    char last_source[ReloadRequest::kMaxSourceVersion]{};
};

bool cancellation_requested(void* context) {
    return *static_cast<bool*>(context);
}

u64 timer_noop(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return 0;
}

bool load_fake(
    void* context, const char* source, LoadedProgram& output, LoadError& error, jit::OptLevel) {
    auto& fake = *static_cast<FakeLoader*>(context);
    fake.calls++;
    const u32 source_len = static_cast<u32>(__builtin_strlen(source));
    if (source_len >= ReloadRequest::kMaxSourceVersion) return false;
    __builtin_memcpy(fake.last_source, source, source_len + 1);
    if (!fake.succeed) {
        error.stage = LoadStage::Analyze;
        return false;
    }
    output.pins.reset();
    output.config.program_pins = &output.pins;
    if (fake.add_cache && !output.config.add_cache_instance("sessions", 8, fake.cache_capacity))
        return false;
    if (fake.timer_shard >= 0 &&
        !output.config.add_timer("tick", 4, 1000, &timer_noop, fake.timer_shard))
        return false;
    if (fake.change_firewall && !output.config.add_firewall_deny_ip("10.0.0.1")) return false;
    return true;
}

struct MutableSourceVersion {
    const char* current = nullptr;
};

bool capture_mutable_source_version(void* context, char* out, u32 capacity, u32* out_len) {
    const char* current = static_cast<MutableSourceVersion*>(context)->current;
    const u32 len = static_cast<u32>(__builtin_strlen(current));
    if (len >= capacity) return false;
    __builtin_memcpy(out, current, len + 1);
    *out_len = len;
    return true;
}

struct Fixture {
    ControlPlaneMutationPort mutation;
    LoadedProgram active;
    LoadedProgram spare;
    ShardControlBlock controls[2]{};
    ReloadShardEndpoint shards[2]{};
    ProcessReloadCoordinator coordinator;
    FakeLoader loader;

    bool setup(bool with_cache = false) {
        active.config.config_generation = 1;
        active.config.program_pins = &active.pins;
        if (with_cache && !active.config.add_cache_instance("sessions", 8, 64)) return false;
        mutation.reset(1, true);
        for (u32 i = 0; i < 2; i++) {
            controls[i].acknowledged_generation.store(1, std::memory_order_relaxed);
            shards[i].control = &controls[i];
        }
        return coordinator.init(&mutation,
                                "/fake/app.rut",
                                jit::OptLevel::O2,
                                &active,
                                &spare,
                                shards,
                                2,
                                &load_fake,
                                &loader);
    }

    bool acknowledge_pending() {
        for (auto& control : controls) {
            const RouteConfig* cfg =
                control.pending_config.exchange(nullptr, std::memory_order_acq_rel);
            if (cfg == nullptr) return false;
            control.acknowledged_generation.store(cfg->config_generation,
                                                  std::memory_order_release);
        }
        return true;
    }

    void cleanup() {
        active.destroy();
        spare.destroy();
    }
};

}  // namespace

TEST(reload_coordinator, compatible_rate_limit_policy_migrates_stable_allocation) {
    RouteConfig active;
    RouteConfig candidate;
    REQUIRE(active.add_static("/api", 0, 200));
    REQUIRE(candidate.add_static("/api", 0, 200));
    REQUIRE(active.add_route_rate_limit_rule(0, 100, 60, RateLimitScope::Shard, 1));
    REQUIRE(candidate.add_route_rate_limit_rule(0, 1, 60, RateLimitScope::Shard, 1));
    active.routes[0].rate_limit.rules[0].identity = 0xabc;
    candidate.routes[0].rate_limit.rules[0].identity = 0xdef;

    REQUIRE(ProcessReloadCoordinator::compatible(active, candidate, 1));
    CHECK_EQ(candidate.routes[0].rate_limit.rules[0].identity, 0xabcu);
    CHECK_NE(candidate.routes[0].rate_limit.rules[0].migration_time_us, 0u);
}

TEST(reload_coordinator, compatible_rate_limit_insertion_preserves_existing_rule) {
    RouteConfig active;
    RouteConfig candidate;
    REQUIRE(active.add_static("/api", 0, 200));
    REQUIRE(candidate.add_static("/api", 0, 200));
    REQUIRE(active.add_route_rate_limit_rule(0, 10, 60, RateLimitScope::Shard, 10));
    REQUIRE(candidate.add_route_rate_limit_rule(0, 20, 60, RateLimitScope::Shard, 20));
    REQUIRE(candidate.add_route_rate_limit_rule(0, 10, 60, RateLimitScope::Shard, 10));
    active.routes[0].rate_limit.rules[0].identity = 0x111;
    candidate.routes[0].rate_limit.rules[0].identity = 0x222;
    candidate.routes[0].rate_limit.rules[1].identity = 0x333;

    REQUIRE(ProcessReloadCoordinator::compatible(active, candidate, 1));
    CHECK_EQ(candidate.routes[0].rate_limit.rules[1].identity, 0x111u);
    CHECK_NE(candidate.routes[0].rate_limit.rules[0].identity, 0x222u);
}

TEST(reload_coordinator, incompatible_rate_limit_key_or_scope_change_is_rejected) {
    RouteConfig active;
    RouteConfig candidate;
    REQUIRE(active.add_static("/api", 0, 200));
    REQUIRE(candidate.add_static("/api", 0, 200));
    REQUIRE(active.add_route_rate_limit_rule(0, 10, 60, RateLimitScope::Shard, 10));
    REQUIRE(candidate.add_route_rate_limit_rule(0, 10, 60, RateLimitScope::Global, 10));
    active.routes[0].rate_limit.rules[0].identity = 0x111;
    candidate.routes[0].rate_limit.rules[0].identity = 0x222;
    CHECK_FALSE(ProcessReloadCoordinator::compatible(active, candidate, 1));
}

TEST(reload_coordinator, identical_sibling_count_change_is_rejected) {
    RouteConfig active;
    RouteConfig candidate;
    REQUIRE(active.add_static("/api", 0, 200));
    REQUIRE(candidate.add_static("/api", 0, 200));
    REQUIRE(active.add_route_rate_limit_rule(0, 10, 60, RateLimitScope::Shard, 10));
    REQUIRE(active.add_route_rate_limit_rule(0, 10, 60, RateLimitScope::Shard, 10));
    REQUIRE(candidate.add_route_rate_limit_rule(0, 10, 60, RateLimitScope::Shard, 10));
    CHECK_FALSE(ProcessReloadCoordinator::compatible(active, candidate, 1));
}

TEST(reload_coordinator, reintroduced_rule_receives_fresh_identity) {
    RouteConfig active;
    RouteConfig candidate;
    REQUIRE(candidate.add_static("/api", 0, 200));
    REQUIRE(candidate.add_route_rate_limit_rule(0, 10, 60, RateLimitScope::Shard, 10));
    const u64 provisional = candidate.routes[0].rate_limit.rules[0].identity;
    REQUIRE(ProcessReloadCoordinator::compatible(active, candidate, 1));
    CHECK_NE(candidate.routes[0].rate_limit.rules[0].identity, provisional);
}

TEST(reload_coordinator, changed_health_policy_requires_warming_support) {
    RouteConfig active;
    RouteConfig candidate;
    REQUIRE(active.add_upstream("api", 0x7f000001u, 8000));
    REQUIRE(candidate.add_upstream("api", 0x7f000001u, 8000));
    active.upstreams[0].hc_enabled = true;
    active.upstreams[0].hc_path_len = 7;
    __builtin_memcpy(active.upstreams[0].hc_path, "/health", 7);
    active.upstreams[0].hc_interval_ms = 1000;
    active.upstreams[0].hc_expected_status = 200;
    candidate.upstreams[0] = active.upstreams[0];
    candidate.upstreams[0].hc_expected_status = 204;
    CHECK_FALSE(ProcessReloadCoordinator::compatible(active, candidate, 1));
}

TEST(reload_coordinator, changed_health_endpoint_requires_warming_support) {
    RouteConfig active;
    RouteConfig candidate;
    REQUIRE(active.add_upstream("api", 0x7f000001u, 8000));
    REQUIRE(candidate.add_upstream("api", 0x7f000001u, 8001));
    active.upstreams[0].hc_enabled = true;
    active.upstreams[0].hc_path_len = 7;
    __builtin_memcpy(active.upstreams[0].hc_path, "/health", 7);
    active.upstreams[0].hc_interval_ms = 1000;
    candidate.upstreams[0] = active.upstreams[0];
    candidate.upstreams[0].set_addr(0x7f000001u, 8001);
    CHECK_FALSE(ProcessReloadCoordinator::compatible(active, candidate, 1));
}

TEST(reload_coordinator, rejects_health_check_reload_when_backend_cannot_probe) {
    RouteConfig active;
    RouteConfig candidate;
    REQUIRE(candidate.add_upstream("api", 0x7f000001u, 8000));
    candidate.upstreams[0].hc_enabled = true;
    candidate.upstreams[0].hc_path_len = 7;
    __builtin_memcpy(candidate.upstreams[0].hc_path, "/health", 7);
    candidate.upstreams[0].hc_interval_ms = 1000;
    candidate.upstreams[0].hc_expected_status = 200;

    CHECK_FALSE(ProcessReloadCoordinator::compatible(active, candidate, 1, false));
    CHECK(ProcessReloadCoordinator::compatible(active, candidate, 1, true));
}

TEST(reload_coordinator, publication_waits_for_all_shards_and_retired_program_pins) {
    Fixture f;
    REQUIRE(f.setup());
    f.active.pins.http1_requests.store(1, std::memory_order_relaxed);

    u64 request_id = 0;
    REQUIRE(f.mutation.request_reload(ReloadRequestSource::Route, &request_id));
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::Published);
    CHECK_EQ(f.loader.calls, 1u);
    CHECK_EQ(f.mutation.state(), ReloadAdmissionState::Completing);
    CHECK_EQ(f.mutation.active_generation(), 2u);
    REQUIRE(f.coordinator.active_program() != nullptr);
    CHECK_EQ(f.coordinator.active_program()->config.config_generation, 2u);

    REQUIRE(f.acknowledge_pending());
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::Waiting);
    CHECK(!f.mutation.last_record().valid);
    f.active.pins.http1_requests.store(0, std::memory_order_release);
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::Activated);
    CHECK_EQ(f.mutation.state(), ReloadAdmissionState::Idle);
    const auto record = f.mutation.last_record();
    REQUIRE(record.valid);
    CHECK_EQ(record.request_id, request_id);
    CHECK_EQ(record.old_generation, 1u);
    CHECK_EQ(record.new_generation, 2u);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Activated);
    CHECK(f.active.config.program_pins == nullptr);

    REQUIRE(f.coordinator.request_signal());
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::Published);
    CHECK_EQ(f.coordinator.active_program()->config.config_generation, 3u);
    REQUIRE(f.acknowledge_pending());
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::Activated);
    CHECK_EQ(f.mutation.active_generation(), 3u);
    CHECK_EQ(f.loader.calls, 2u);
    f.cleanup();
}

TEST(reload_coordinator, shutdown_finalizes_published_activation_after_shards_join) {
    Fixture f;
    REQUIRE(f.setup());

    u64 request_id = 0;
    REQUIRE(f.mutation.request_reload(ReloadRequestSource::Route, &request_id));
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::Published);
    REQUIRE(f.coordinator.waiting_for_activation());
    CHECK(f.coordinator.finish_activation_for_shutdown());
    CHECK_FALSE(f.coordinator.waiting_for_activation());
    CHECK_EQ(f.mutation.state(), ReloadAdmissionState::Idle);
    const auto record = f.mutation.last_record();
    REQUIRE(record.valid);
    CHECK_EQ(record.request_id, request_id);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Activated);

    f.cleanup();
}

TEST(reload_coordinator, compile_failure_is_definitely_not_applied) {
    Fixture f;
    f.loader.succeed = false;
    REQUIRE(f.setup());
    REQUIRE(f.coordinator.request_signal());
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::CompileFailed);
    CHECK_EQ(f.mutation.active_generation(), 1u);
    CHECK_EQ(f.coordinator.active_program(), &f.active);
    const auto record = f.mutation.last_record();
    REQUIRE(record.valid);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::CompileFailed);
    CHECK_EQ(record.new_generation, 0u);
    for (const auto& control : f.controls) CHECK(control.pending_config == nullptr);
    f.cleanup();
}

TEST(reload_coordinator, shutdown_after_compile_cancels_before_publication) {
    ControlPlaneMutationPort mutation;
    mutation.reset(1, true);
    LoadedProgram active;
    LoadedProgram spare;
    active.config.config_generation = 1;
    active.config.program_pins = &active.pins;
    ShardControlBlock control{};
    control.acknowledged_generation.store(1, std::memory_order_relaxed);
    ReloadShardEndpoint shard{&control};
    FakeLoader loader;
    bool cancel = true;
    ProcessReloadCoordinator coordinator;
    REQUIRE(coordinator.init(&mutation,
                             "/fake/app.rut",
                             jit::OptLevel::O2,
                             &active,
                             &spare,
                             &shard,
                             1,
                             &load_fake,
                             &loader,
                             &cancellation_requested,
                             &cancel));
    REQUIRE(coordinator.request_signal());
    CHECK_EQ(coordinator.poll(), ReloadCoordinatorPoll::Stopped);
    CHECK_EQ(loader.calls, 1u);
    CHECK_EQ(mutation.active_generation(), 1u);
    CHECK(control.pending_config.load(std::memory_order_relaxed) == nullptr);
    CHECK_EQ(mutation.last_record().outcome, ReloadTerminalOutcome::Stopped);
    active.destroy();
    spare.destroy();
}

TEST(reload_coordinator, request_keeps_its_admission_time_source_version) {
    Fixture f;
    REQUIRE(f.setup());
    MutableSourceVersion source{"/versions/v1/app.rut"};
    f.mutation.set_reload_source_version_capture(&capture_mutable_source_version, &source);
    REQUIRE(f.mutation.request_reload(ReloadRequestSource::Route));
    source.current = "/versions/v2/app.rut";
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::Published);
    CHECK_EQ(__builtin_strcmp(f.loader.last_source, "/versions/v1/app.rut"), 0);
    f.cleanup();
}

TEST(reload_coordinator, default_source_snapshot_is_captured_by_the_winning_request) {
    namespace fs = std::filesystem;
    const fs::path root = "/tmp/rut_reload_coordinator_source_capture";
    fs::remove_all(root);
    fs::create_directories(root / "v1");
    fs::create_directories(root / "v2");
    std::ofstream(root / "v1" / "app.rut") << "route GET \"/\" { return 201 }\n";
    std::ofstream(root / "v2" / "app.rut") << "route GET \"/\" { return 202 }\n";
    fs::create_symlink(root / "v1" / "app.rut", root / "current.rut");
    const std::string source_path = (root / "current.rut").string();

    ControlPlaneMutationPort mutation;
    mutation.reset(1, true);
    LoadedProgram active;
    LoadedProgram spare;
    active.config.config_generation = 1;
    active.config.program_pins = &active.pins;
    ShardControlBlock control{};
    control.acknowledged_generation.store(1, std::memory_order_relaxed);
    ReloadShardEndpoint shard{&control};
    std::string first_snapshot_root;
    std::string second_snapshot_root;
    {
        ProcessReloadCoordinator coordinator;
        // Initialization must remain valid even for ordinary regular paths;
        // immutable provider resolution is deferred until a reload attempt.
        REQUIRE(coordinator.init(
            &mutation, source_path.c_str(), jit::OptLevel::O2, &active, &spare, &shard, 1));

        fs::remove(root / "current.rut");
        fs::create_symlink(root / "v2" / "app.rut", root / "current.rut");
        CHECK_EQ(coordinator.poll(), ReloadCoordinatorPoll::Idle);
        REQUIRE(mutation.request_reload(ReloadRequestSource::Route));
        ReloadRequest request{};
        REQUIRE(mutation.take_reload(&request));
        std::ifstream captured(request.source_version);
        std::string contents((std::istreambuf_iterator<char>(captured)), {});
        CHECK(contents.find("return 202") != std::string::npos);
        first_snapshot_root = fs::path(request.source_version).parent_path();
        REQUIRE(mutation.complete_reload(
            request.id, request.source, ReloadTerminalOutcome::CompileFailed));

        fs::remove(root / "current.rut");
        fs::create_symlink(root / "v1" / "app.rut", root / "current.rut");
        CHECK_EQ(coordinator.poll(), ReloadCoordinatorPoll::Idle);
        REQUIRE(mutation.request_reload(ReloadRequestSource::Route));
        REQUIRE(mutation.take_reload(&request));
        second_snapshot_root = fs::path(request.source_version).parent_path();
        CHECK_FALSE(fs::exists(first_snapshot_root));
        CHECK(fs::exists(second_snapshot_root));
        REQUIRE(mutation.complete_reload(
            request.id, request.source, ReloadTerminalOutcome::CompileFailed));
    }
    CHECK_FALSE(fs::exists(second_snapshot_root));

    // The destroyed coordinator detached its callback; the surviving port does
    // not call through freed coordinator state.
    REQUIRE(mutation.request_reload(ReloadRequestSource::Route));
    mutation.stop();
    active.destroy();
    spare.destroy();
    fs::remove_all(root);
}

TEST(reload_coordinator, regular_source_path_does_not_fail_initialization) {
    namespace fs = std::filesystem;
    const fs::path root = "/tmp/rut_reload_coordinator_regular_source";
    fs::remove_all(root);
    fs::create_directories(root);
    std::ofstream(root / "app.rut") << "route GET \"/\" { return 200 }\n";
    const std::string source_path = (root / "app.rut").string();

    ControlPlaneMutationPort mutation;
    mutation.reset(1, false);
    LoadedProgram active;
    LoadedProgram spare;
    active.config.config_generation = 1;
    active.config.program_pins = &active.pins;
    ShardControlBlock control{};
    control.acknowledged_generation.store(1, std::memory_order_relaxed);
    ReloadShardEndpoint shard{&control};
    ProcessReloadCoordinator coordinator;
    CHECK(coordinator.init(
        &mutation, source_path.c_str(), jit::OptLevel::O2, &active, &spare, &shard, 1));
    active.destroy();
    spare.destroy();
    fs::remove_all(root);
}

TEST(reload_coordinator, incompatible_cache_or_timer_is_rejected_before_publication) {
    {
        Fixture f;
        f.loader.add_cache = true;
        f.loader.cache_capacity = 128;
        REQUIRE(f.setup(true));
        REQUIRE(f.coordinator.request_signal());
        CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::ValidationFailed);
        CHECK_EQ(f.mutation.active_generation(), 1u);
        CHECK_EQ(f.mutation.last_record().outcome, ReloadTerminalOutcome::ValidationFailed);
        f.cleanup();
    }
    {
        Fixture f;
        f.loader.timer_shard = 2;
        REQUIRE(f.setup());
        REQUIRE(f.coordinator.request_signal());
        CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::ValidationFailed);
        CHECK_EQ(f.mutation.active_generation(), 1u);
        f.cleanup();
    }
}

TEST(reload_coordinator, firewall_policy_change_is_rejected_before_publication) {
    Fixture f;
    f.loader.change_firewall = true;
    REQUIRE(f.setup());
    REQUIRE(f.coordinator.request_signal());
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::ValidationFailed);
    CHECK_EQ(f.mutation.active_generation(), 1u);
    f.cleanup();
}

TEST(reload_coordinator, signal_uses_same_single_slot_and_bypasses_route_authority) {
    ControlPlaneMutationPort mutation;
    mutation.reset(1, false);
    LoadedProgram active;
    LoadedProgram spare;
    active.config.config_generation = 1;
    active.config.program_pins = &active.pins;
    ShardControlBlock control{};
    control.acknowledged_generation.store(1, std::memory_order_relaxed);
    ReloadShardEndpoint shard{&control};
    FakeLoader loader;
    ProcessReloadCoordinator coordinator;
    REQUIRE(coordinator.init(&mutation,
                             "/fake/app.rut",
                             jit::OptLevel::O2,
                             &active,
                             &spare,
                             &shard,
                             1,
                             &load_fake,
                             &loader));
    CHECK(!mutation.request_reload(ReloadRequestSource::Route));
    REQUIRE(coordinator.request_signal());
    CHECK(!coordinator.request_signal());
    CHECK_EQ(coordinator.poll(), ReloadCoordinatorPoll::Published);
    const RouteConfig* cfg = control.pending_config.exchange(nullptr, std::memory_order_acq_rel);
    REQUIRE(cfg != nullptr);
    control.acknowledged_generation.store(cfg->config_generation, std::memory_order_release);
    CHECK_EQ(coordinator.poll(), ReloadCoordinatorPoll::Activated);
    CHECK_EQ(mutation.last_record().source, ReloadRequestSource::Signal);
    active.destroy();
    spare.destroy();
}

TEST(reload_coordinator, refuses_to_overwrite_unconsumed_shard_config) {
    Fixture f;
    REQUIRE(f.setup());
    RouteConfig stale;
    f.controls[1].pending_config.store(&stale, std::memory_order_relaxed);
    REQUIRE(f.coordinator.request_signal());
    CHECK_EQ(f.coordinator.poll(), ReloadCoordinatorPoll::ValidationFailed);
    CHECK(f.controls[1].pending_config.load(std::memory_order_relaxed) == &stale);
    CHECK_EQ(f.mutation.active_generation(), 1u);
    f.controls[1].pending_config.store(nullptr, std::memory_order_relaxed);
    f.cleanup();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
