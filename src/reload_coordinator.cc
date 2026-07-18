#include "rut/reload_coordinator.h"

namespace rut {

bool ProcessReloadCoordinator::default_loader(
    void*, const char* source_path, LoadedProgram& output, LoadError& error, jit::OptLevel opt) {
    return load_rut_program(source_path, output, error, opt);
}

bool ProcessReloadCoordinator::init(ControlPlaneMutationPort* mutation,
                                    const char* source_path,
                                    jit::OptLevel opt,
                                    LoadedProgram* active,
                                    LoadedProgram* spare,
                                    const ReloadShardEndpoint* shards,
                                    u32 shard_count,
                                    ReloadProgramLoader loader,
                                    void* loader_context) {
    if (mutation == nullptr || source_path == nullptr || active == nullptr || spare == nullptr ||
        active == spare || shards == nullptr || shard_count == 0 || shard_count > kMaxShards ||
        active->config.config_generation == 0 ||
        mutation->active_generation() != active->config.config_generation)
        return false;
    for (u32 i = 0; i < shard_count; i++) {
        if (shards[i].control == nullptr) return false;
        shards_[i] = shards[i];
    }
    mutation_ = mutation;
    source_path_ = source_path;
    opt_ = opt;
    active_ = active;
    spare_ = spare;
    retired_ = nullptr;
    shard_count_ = shard_count;
    loader_ = loader != nullptr ? loader : &default_loader;
    loader_context_ = loader_context;
    request_ = {};
    old_generation_ = 0;
    last_load_error_ = {};
    return true;
}

bool ProcessReloadCoordinator::request_signal(u64* request_id) {
    return mutation_ != nullptr &&
           mutation_->request_reload(ReloadRequestSource::Signal, request_id);
}

bool ProcessReloadCoordinator::compatible(const RouteConfig& active,
                                          const RouteConfig& candidate,
                                          u32 shard_count) {
    if (shard_count == 0 || candidate.first_out_of_range_timer_shard(shard_count) >= 0)
        return false;
    if (active.cache_instance_count != candidate.cache_instance_count) return false;
    for (u32 i = 0; i < active.cache_instance_count; i++) {
        const auto& lhs = active.cache_instances[i];
        const auto& rhs = candidate.cache_instances[i];
        if (lhs.name_len != rhs.name_len || lhs.capacity != rhs.capacity) return false;
        for (u32 c = 0; c < lhs.name_len; c++)
            if (lhs.name[c] != rhs.name[c]) return false;
    }
    return true;
}

bool ProcessReloadCoordinator::all_shards_acknowledged(u64 generation) const {
    for (u32 i = 0; i < shard_count_; i++) {
        if (shards_[i].control->acknowledged_generation.load(std::memory_order_acquire) !=
            generation)
            return false;
    }
    return true;
}

ReloadCoordinatorPoll ProcessReloadCoordinator::poll() {
    if (mutation_ == nullptr) return ReloadCoordinatorPoll::Idle;
    if (retired_ != nullptr) {
        const u64 generation = active_->config.config_generation;
        if (!all_shards_acknowledged(generation) || !retired_->pins.empty())
            return ReloadCoordinatorPoll::Waiting;
        retired_->destroy();
        spare_ = retired_;
        if (!mutation_->complete_published_reload(request_.id, request_.source, old_generation_))
            return ReloadCoordinatorPoll::Waiting;
        retired_ = nullptr;
        return ReloadCoordinatorPoll::Activated;
    }

    ReloadRequest request{};
    if (!mutation_->take_reload(&request)) return ReloadCoordinatorPoll::Idle;
    request_ = request;
    old_generation_ = active_->config.config_generation;
    spare_->destroy();
    last_load_error_ = {};
    if (!loader_(loader_context_, source_path_, *spare_, last_load_error_, opt_)) {
        spare_->destroy();
        (void)mutation_->complete_reload(
            request.id, request.source, ReloadTerminalOutcome::CompileFailed);
        return ReloadCoordinatorPoll::CompileFailed;
    }
    if (!compatible(active_->config, spare_->config, shard_count_) ||
        old_generation_ >= ControlPlaneMutationPort::kMaxGeneration) {
        spare_->destroy();
        (void)mutation_->complete_reload(
            request.id, request.source, ReloadTerminalOutcome::ValidationFailed);
        return ReloadCoordinatorPoll::ValidationFailed;
    }
    // The coordinator is the sole publisher. Never overwrite a config that a
    // shard has not consumed yet, even if an integration accidentally leaves a
    // stale writer attached to the same control block.
    for (u32 i = 0; i < shard_count_; i++) {
        if (shards_[i].control->pending_config.load(std::memory_order_acquire) != nullptr) {
            spare_->destroy();
            (void)mutation_->complete_reload(
                request.id, request.source, ReloadTerminalOutcome::ValidationFailed);
            return ReloadCoordinatorPoll::ValidationFailed;
        }
    }

    const u64 new_generation = old_generation_ + 1;
    spare_->config.config_generation = new_generation;
    if (!mutation_->publish_reload_generation(request.id, request.source, new_generation)) {
        spare_->destroy();
        (void)mutation_->complete_reload(
            request.id, request.source, ReloadTerminalOutcome::ValidationFailed);
        return ReloadCoordinatorPoll::ValidationFailed;
    }
    // No fallible operation follows the generation publication boundary.
    activate_rut_program(*spare_);

    LoadedProgram* previous = active_;
    active_ = spare_;
    retired_ = previous;
    spare_ = nullptr;
    for (u32 i = 0; i < shard_count_; i++)
        shards_[i].control->pending_config.store(&active_->config, std::memory_order_release);
    return ReloadCoordinatorPoll::Published;
}

}  // namespace rut
