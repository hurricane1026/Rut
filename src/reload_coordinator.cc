#include "rut/reload_coordinator.h"

#include "rut/runtime/access_log.h"
#include <filesystem>

namespace rut {

namespace {

std::atomic<u64> next_rate_limit_incarnation{1};

u64 fresh_rate_limit_identity(u64 provisional) {
    const u64 incarnation = next_rate_limit_incarnation.fetch_add(1, std::memory_order_relaxed);
    u64 identity = provisional ^ (incarnation * 0x9E3779B97F4A7C15ull);
    identity ^= identity >> 29;
    return identity != 0 ? identity : incarnation;
}

bool same_rate_limit_key_shape(const RateLimitRule& lhs, const RateLimitRule& rhs) {
    if (lhs.scope != rhs.scope || lhs.key.count != rhs.key.count) return false;
    for (u32 component = 0; component < lhs.key.count; component++) {
        const auto& a = lhs.key.comps[component];
        const auto& b = rhs.key.comps[component];
        if (a.kind != b.kind || a.name_len != b.name_len) return false;
        for (u32 byte = 0; byte < a.name_len; byte++)
            if (a.name[byte] != b.name[byte]) return false;
    }
    return true;
}

bool same_rate_limit_policy(const RateLimitRule& lhs, const RateLimitRule& rhs) {
    return same_rate_limit_key_shape(lhs, rhs) && lhs.max == rhs.max &&
           lhs.window_sec == rhs.window_sec && lhs.burst == rhs.burst;
}

bool same_route_declaration(const RouteEntry& lhs, const RouteEntry& rhs) {
    if (lhs.method != rhs.method || lhs.path_len != rhs.path_len) return false;
    for (u32 byte = 0; byte < lhs.path_len; byte++)
        if (lhs.path[byte] != rhs.path[byte]) return false;
    return true;
}

bool same_health_policy(const UpstreamTarget& lhs, const UpstreamTarget& rhs) {
    if (lhs.hc_enabled != rhs.hc_enabled || lhs.hc_path_len != rhs.hc_path_len ||
        lhs.hc_interval_ms != rhs.hc_interval_ms ||
        lhs.hc_expected_status != rhs.hc_expected_status)
        return false;
    for (u32 byte = 0; byte < lhs.hc_path_len; byte++)
        if (lhs.hc_path[byte] != rhs.hc_path[byte]) return false;
    return true;
}

bool same_upstream_endpoints(const UpstreamTarget& lhs, const UpstreamTarget& rhs) {
    if (lhs.addr_count != rhs.addr_count) return false;
    for (u32 i = 0; i < lhs.addr_count; i++) {
        if (!lhs.addrs[i].same_address(rhs.addrs[i])) return false;
    }
    return true;
}

}  // namespace

bool ProcessReloadCoordinator::default_loader(
    void*, const char* source_path, LoadedProgram& output, LoadError& error, jit::OptLevel opt) {
    return load_rut_program(source_path, output, error, opt);
}

ProcessReloadCoordinator::~ProcessReloadCoordinator() {
    if (mutation_ != nullptr)
        mutation_->clear_reload_source_version_capture(&capture_source_version, this);
    clear_source_snapshots();
}

void ProcessReloadCoordinator::clear_source_snapshots() {
    std::vector<std::string> roots;
    const bool can_reclaim =
        mutation_ == nullptr ||
        (mutation_->state() == ReloadAdmissionState::Idle && !mutation_->admission_in_progress());
    {
        std::lock_guard lock(source_snapshot_mutex_);
        if (!source_snapshot_root_.empty())
            retired_snapshot_roots_.push_back(std::move(source_snapshot_root_));
        cached_snapshot_source_.clear();
        cached_provider_version_.clear();
        source_snapshot_epoch_.store(0, std::memory_order_release);
        route_snapshot_armed_.store(false, std::memory_order_release);
        if (can_reclaim) roots.swap(retired_snapshot_roots_);
    }
    for (const auto& root : roots) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }
}

void ProcessReloadCoordinator::reclaim_retired_snapshots() {
    if (mutation_ == nullptr || mutation_->state() != ReloadAdmissionState::Idle ||
        mutation_->admission_in_progress())
        return;
    std::vector<std::string> roots;
    {
        std::lock_guard lock(source_snapshot_mutex_);
        roots.swap(retired_snapshot_roots_);
    }
    for (const auto& root : roots) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }
}

bool ProcessReloadCoordinator::refresh_source_snapshot() {
    if (!default_loader_selected_) return true;
    char version[ReloadRequest::kMaxSourceVersion]{};
    u32 version_len = 0;
    if (!resolve_rut_program_source_version(source_path_, version, sizeof(version), &version_len)) {
        std::lock_guard lock(source_snapshot_mutex_);
        cached_snapshot_source_.clear();
        cached_provider_version_.clear();
        source_snapshot_epoch_.store(0, std::memory_order_release);
        route_snapshot_armed_.store(false, std::memory_order_release);
        return false;
    }
    bool cache_hit = false;
    {
        std::lock_guard lock(source_snapshot_mutex_);
        cache_hit = cached_provider_version_.size() == version_len &&
                    __builtin_memcmp(cached_provider_version_.data(), version, version_len) == 0;
    }
    if (cache_hit) {
        route_snapshot_armed_.store(true, std::memory_order_release);
        reclaim_retired_snapshots();
        return true;
    }
    // A provider version change invalidates the old admission boundary. Drop
    // the cached path before materializing the replacement so no route can
    // observe the previous snapshot after the control thread refreshes.
    clear_source_snapshots();
    char snapshot_source[ReloadRequest::kMaxSourceVersion]{};
    char snapshot_root[ReloadRequest::kMaxSourceVersion]{};
    u32 source_len = 0;
    u32 root_len = 0;
    if (!materialize_rut_program_source_snapshot(version,
                                                 snapshot_source,
                                                 sizeof(snapshot_source),
                                                 &source_len,
                                                 snapshot_root,
                                                 sizeof(snapshot_root),
                                                 &root_len)) {
        std::lock_guard lock(source_snapshot_mutex_);
        cached_snapshot_source_.clear();
        cached_provider_version_.clear();
        source_snapshot_epoch_.store(0, std::memory_order_release);
        route_snapshot_armed_.store(false, std::memory_order_release);
        if (!source_snapshot_root_.empty())
            retired_snapshot_roots_.push_back(std::move(source_snapshot_root_));
        return false;
    }
    std::string previous_root;
    {
        std::lock_guard lock(source_snapshot_mutex_);
        previous_root = std::move(source_snapshot_root_);
        source_snapshot_root_.assign(snapshot_root, root_len);
        cached_provider_version_.assign(version, version_len);
        cached_snapshot_source_.assign(snapshot_source, source_len);
        source_snapshot_epoch_.fetch_add(1, std::memory_order_release);
    }
    if (!previous_root.empty()) {
        std::lock_guard lock(source_snapshot_mutex_);
        retired_snapshot_roots_.push_back(std::move(previous_root));
    }
    route_snapshot_armed_.store(true, std::memory_order_release);
    reclaim_retired_snapshots();
    return true;
}

bool ProcessReloadCoordinator::capture_source_version(
    void* context, ReloadRequestSource source, char* out, u32 capacity, u32* out_len) {
    auto* coordinator = static_cast<ProcessReloadCoordinator*>(context);
    if (coordinator == nullptr) return false;
    if (coordinator->default_loader_selected_) {
        // This callback can run on a route worker. It uses only the immutable
        // snapshot epoch published by the control thread; filesystem/provider
        // resolution and snapshot materialization stay off the shard thread.
        const u64 epoch = coordinator->source_snapshot_epoch_.load(std::memory_order_acquire);
        if (epoch == 0) return false;
        if (source == ReloadRequestSource::Route &&
            !coordinator->route_snapshot_armed_.load(std::memory_order_acquire))
            return false;
        std::unique_lock lock(coordinator->source_snapshot_mutex_, std::try_to_lock);
        if (!lock.owns_lock()) return false;
        if (epoch != coordinator->source_snapshot_epoch_.load(std::memory_order_acquire))
            return false;
        const u32 len = static_cast<u32>(coordinator->cached_snapshot_source_.size());
        if (len == 0 || len >= capacity) return false;
        __builtin_memcpy(out, coordinator->cached_snapshot_source_.data(), len);
        out[len] = '\0';
        *out_len = len;
        return true;
    }
    const u32 len = static_cast<u32>(__builtin_strlen(coordinator->source_path_));
    if (len >= capacity) return false;
    __builtin_memcpy(out, coordinator->source_path_, len + 1);
    *out_len = len;
    return true;
}

bool ProcessReloadCoordinator::init(ControlPlaneMutationPort* mutation,
                                    const char* source_path,
                                    jit::OptLevel opt,
                                    LoadedProgram* active,
                                    LoadedProgram* spare,
                                    const ReloadShardEndpoint* shards,
                                    u32 shard_count,
                                    ReloadProgramLoader loader,
                                    void* loader_context,
                                    ReloadCancellationCheck cancellation_check,
                                    void* cancellation_context,
                                    bool supports_active_health_probes) {
    if (mutation == nullptr || source_path == nullptr || active == nullptr || spare == nullptr ||
        active == spare || shards == nullptr || shard_count == 0 || shard_count > kMaxShards ||
        active->config.config_generation == 0 ||
        mutation->active_generation() != active->config.config_generation)
        return false;
    for (u32 i = 0; i < shard_count; i++) {
        if (shards[i].control == nullptr) return false;
        shards_[i] = shards[i];
    }
    if (mutation_ != nullptr && mutation_ != mutation)
        mutation_->clear_reload_source_version_capture(&capture_source_version, this);
    mutation_ = mutation;
    source_path_ = source_path;
    opt_ = opt;
    active_ = active;
    spare_ = spare;
    retired_ = nullptr;
    shard_count_ = shard_count;
    default_loader_selected_ = loader == nullptr;
    loader_ = loader != nullptr ? loader : &default_loader;
    loader_context_ = loader_context;
    cancellation_check_ = cancellation_check;
    cancellation_context_ = cancellation_context;
    supports_active_health_probes_ = supports_active_health_probes;
    clear_source_snapshots();
    if (default_loader_selected_) (void)refresh_source_snapshot();
    // Startup preparation establishes the source snapshot but does not arm
    // route-triggered reload until the control loop has observed that boundary.
    route_snapshot_armed_.store(false, std::memory_order_release);
    mutation_->set_reload_source_version_capture(&capture_source_version, this);
    request_ = {};
    old_generation_ = 0;
    last_load_error_ = {};
    return true;
}

bool ProcessReloadCoordinator::request_signal(u64* request_id) {
    if (mutation_ == nullptr) return false;
    if (mutation_->state() != ReloadAdmissionState::Idle)
        return mutation_->request_reload(ReloadRequestSource::Signal, request_id);
    // Signals are processed by the control thread, so they may synchronously
    // materialize the current immutable source version before admission. A
    // refresh failure still enters the mutation port so SIGHUP receives its
    // required SnapshotUnavailable terminal record.
    if (default_loader_selected_) (void)refresh_source_snapshot();
    return mutation_->request_reload(ReloadRequestSource::Signal, request_id);
}

bool ProcessReloadCoordinator::finish_activation_for_shutdown() {
    if (retired_ == nullptr) return true;
    if (!mutation_->finish_activation(request_.id)) return false;
    retired_->destroy();
    spare_ = retired_;
    retired_ = nullptr;
    return true;
}

bool ProcessReloadCoordinator::compatible(const RouteConfig& active,
                                          RouteConfig& candidate,
                                          u32 shard_count,
                                          bool supports_active_health_probes) {
    if (shard_count == 0 || candidate.first_out_of_range_timer_shard(shard_count) >= 0)
        return false;
    if (!supports_active_health_probes && candidate.requires_active_health_probes()) return false;
    if (!active.same_firewall_policy(candidate)) return false;
    if (active.cache_instance_count != candidate.cache_instance_count) return false;
    for (u32 i = 0; i < active.cache_instance_count; i++) {
        const auto& lhs = active.cache_instances[i];
        const auto& rhs = candidate.cache_instances[i];
        if (lhs.name_len != rhs.name_len || lhs.capacity != rhs.capacity) return false;
        for (u32 c = 0; c < lhs.name_len; c++)
            if (lhs.name[c] != rhs.name[c]) return false;
    }

    // A changed active-health contract cannot inherit a predecessor verdict:
    // without a candidate-policy warm-up probe it could keep selecting a now
    // invalid endpoint for a full new interval. Reject until warming exists.
    for (u32 old_upstream = 0; old_upstream < active.upstream_count; old_upstream++) {
        const auto& old_target = active.upstreams[old_upstream];
        for (u32 new_upstream = 0; new_upstream < candidate.upstream_count; new_upstream++) {
            const auto& new_target = candidate.upstreams[new_upstream];
            if (old_target.name_identity != 0 &&
                old_target.name_identity == new_target.name_identity &&
                (!same_health_policy(old_target, new_target) ||
                 !same_upstream_endpoints(old_target, new_target)))
                return false;
        }
    }

    const u64 migration_time = monotonic_us();
    for (u32 new_route = 0; new_route < candidate.route_count; new_route++) {
        auto& next = candidate.routes[new_route];
        const RouteEntry* previous = nullptr;
        for (u32 old_route = 0; old_route < active.route_count; old_route++) {
            if (same_route_declaration(active.routes[old_route], next)) {
                previous = &active.routes[old_route];
                break;
            }
        }
        if (previous == nullptr) {
            for (u32 ni = 0; ni < next.rate_limit.count; ni++)
                next.rate_limit.rules[ni].identity =
                    fresh_rate_limit_identity(next.rate_limit.rules[ni].identity);
            continue;
        }

        // Without a persistent declaration id, changing the cardinality of a
        // group of identical siblings cannot identify which bucket survived.
        // Reject the ambiguous transition instead of remapping by position.
        for (u32 oi = 0; oi < previous->rate_limit.count; oi++) {
            u32 old_copies = 0;
            u32 new_copies = 0;
            for (u32 other = 0; other < previous->rate_limit.count; other++)
                old_copies += same_rate_limit_policy(previous->rate_limit.rules[oi],
                                                     previous->rate_limit.rules[other]);
            for (u32 ni = 0; ni < next.rate_limit.count; ni++)
                new_copies += same_rate_limit_policy(previous->rate_limit.rules[oi],
                                                     next.rate_limit.rules[ni]);
            if (old_copies != new_copies && (old_copies > 1 || new_copies > 1)) return false;
        }

        bool old_used[kMaxRateLimitRules]{};
        bool new_used[kMaxRateLimitRules]{};
        // First preserve exact declarations independent of sibling order.
        for (u32 ni = 0; ni < next.rate_limit.count; ni++) {
            for (u32 oi = 0; oi < previous->rate_limit.count; oi++) {
                if (!old_used[oi] && same_rate_limit_policy(previous->rate_limit.rules[oi],
                                                            next.rate_limit.rules[ni])) {
                    next.rate_limit.rules[ni].identity = previous->rate_limit.rules[oi].identity;
                    old_used[oi] = true;
                    new_used[ni] = true;
                    break;
                }
            }
        }
        // A one-to-one remaining key/scope match is a policy edit. Reuse the
        // allocation and migrate its timestamp at this activation boundary.
        for (u32 ni = 0; ni < next.rate_limit.count; ni++) {
            if (new_used[ni]) continue;
            i32 matched_old = -1;
            u32 matches = 0;
            for (u32 oi = 0; oi < previous->rate_limit.count; oi++) {
                if (!old_used[oi] && same_rate_limit_key_shape(previous->rate_limit.rules[oi],
                                                               next.rate_limit.rules[ni])) {
                    matched_old = static_cast<i32>(oi);
                    matches++;
                }
            }
            if (matches != 1) continue;
            u32 reverse_matches = 0;
            for (u32 candidate_rule = 0; candidate_rule < next.rate_limit.count; candidate_rule++)
                if (!new_used[candidate_rule] &&
                    same_rate_limit_key_shape(previous->rate_limit.rules[matched_old],
                                              next.rate_limit.rules[candidate_rule]))
                    reverse_matches++;
            if (reverse_matches != 1) continue;
            auto& rule = next.rate_limit.rules[ni];
            rule.identity = previous->rate_limit.rules[matched_old].identity;
            rule.migration_time_us = migration_time;
            old_used[matched_old] = true;
            new_used[ni] = true;
        }

        bool old_unmatched = false;
        bool new_unmatched = false;
        for (u32 oi = 0; oi < previous->rate_limit.count; oi++) old_unmatched |= !old_used[oi];
        for (u32 ni = 0; ni < next.rate_limit.count; ni++) new_unmatched |= !new_used[ni];
        // Pure insertion or removal is unambiguous. Unmatched rules on both
        // sides are a key/scope replacement (or ambiguous sibling rewrite),
        // which cannot safely receive a fresh bucket while predecessor history
        // is live.
        if (old_unmatched && new_unmatched) return false;
        for (u32 ni = 0; ni < next.rate_limit.count; ni++)
            if (!new_used[ni])
                next.rate_limit.rules[ni].identity =
                    fresh_rate_limit_identity(next.rate_limit.rules[ni].identity);
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
        if (!mutation_->finish_activation(request_.id)) return ReloadCoordinatorPoll::Waiting;
        retired_->destroy();
        spare_ = retired_;
        retired_ = nullptr;
        return ReloadCoordinatorPoll::Activated;
    }

    ReloadRequest request{};
    if (!mutation_->take_reload(&request)) {
        // Do not delay an admitted request by materializing a newer provider
        // tree. Refresh only when the control port has no pending request.
        (void)refresh_source_snapshot();
        return ReloadCoordinatorPoll::Idle;
    }
    request_ = request;
    old_generation_ = active_->config.config_generation;
    spare_->destroy();
    last_load_error_ = {};
    const char* source_path = request.source_version;
    // The admission callback captured this immutable source-version handle.
    // Never refresh the provider cache here: doing so could compile a newer
    // version than the one associated with the admitted request.
    auto reclaim_retired_snapshots = [&] {
        std::vector<std::string> roots;
        {
            std::lock_guard lock(source_snapshot_mutex_);
            roots.swap(retired_snapshot_roots_);
        }
        for (const auto& root : roots) {
            std::error_code ignored;
            std::filesystem::remove_all(root, ignored);
        }
    };
    if (source_path == nullptr || source_path[0] == '\0' ||
        !loader_(loader_context_, source_path, *spare_, last_load_error_, opt_)) {
        spare_->destroy();
        reclaim_retired_snapshots();
        (void)mutation_->complete_reload(
            request.id, request.source, ReloadTerminalOutcome::CompileFailed);
        return ReloadCoordinatorPoll::CompileFailed;
    }
    // The admitted request has finished reading its source. Older snapshot
    // roots retained across a cache swap can now be reclaimed safely.
    reclaim_retired_snapshots();
    if (cancellation_check_ != nullptr && cancellation_check_(cancellation_context_)) {
        spare_->destroy();
        mutation_->stop();
        return ReloadCoordinatorPoll::Stopped;
    }
    if (!compatible(
            active_->config, spare_->config, shard_count_, supports_active_health_probes_) ||
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
    if (!mutation_->complete_reload(request.id,
                                    request.source,
                                    ReloadTerminalOutcome::Activated,
                                    new_generation,
                                    &spare_->config)) {
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
