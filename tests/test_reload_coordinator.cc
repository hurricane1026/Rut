#include "rut/reload_coordinator.h"
#include "test.h"

using namespace rut;

namespace {

struct FakeLoader {
    bool succeed = true;
    bool add_cache = false;
    u32 cache_capacity = 64;
    i32 timer_shard = -1;
    bool change_firewall = false;
    u32 calls = 0;
};

u64 timer_noop(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return 0;
}

bool load_fake(void* context, const char*, LoadedProgram& output, LoadError& error, jit::OptLevel) {
    auto& fake = *static_cast<FakeLoader*>(context);
    fake.calls++;
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
