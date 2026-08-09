#pragma once

#include "rut/runtime/control_plane_mutation.h"
#include "rut/runtime/shard_control.h"
#include "rut/serve_loader.h"
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace rut {

struct ReloadShardEndpoint {
    ShardControlBlock* control = nullptr;
};

enum class ReloadCoordinatorPoll : u8 {
    Idle = 0,
    CompileFailed,
    ValidationFailed,
    Published,
    Waiting,
    Activated,
    Stopped,
};

using ReloadProgramLoader = bool (*)(void* context,
                                     const char* source_path,
                                     LoadedProgram& output,
                                     LoadError& error,
                                     jit::OptLevel opt);
using ReloadCancellationCheck = bool (*)(void* context);

// Single process owner for source compilation, generation publication, shard
// acknowledgements, and LoadedProgram lifetime. poll() is called only by the
// process control thread; request admission itself remains lock-free through
// ControlPlaneMutationPort.
class ProcessReloadCoordinator {
public:
    static constexpr u32 kMaxShards = 256;
    ~ProcessReloadCoordinator();

    [[nodiscard]] bool init(ControlPlaneMutationPort* mutation,
                            const char* source_path,
                            jit::OptLevel opt,
                            LoadedProgram* active,
                            LoadedProgram* spare,
                            const ReloadShardEndpoint* shards,
                            u32 shard_count,
                            ReloadProgramLoader loader = nullptr,
                            void* loader_context = nullptr,
                            ReloadCancellationCheck cancellation_check = nullptr,
                            void* cancellation_context = nullptr,
                            bool supports_active_health_probes = true);

    [[nodiscard]] bool request_signal(u64* request_id = nullptr);
    ReloadCoordinatorPoll poll();

    [[nodiscard]] const LoadedProgram* active_program() const { return active_; }
    [[nodiscard]] const LoadError& last_load_error() const { return last_load_error_; }
    [[nodiscard]] bool waiting_for_activation() const { return retired_ != nullptr; }

    // Shutdown-only completion after all shard threads have joined. At that
    // point no acknowledgement or generation pin can arrive, so a published
    // activation must be finalized before the mutation port is stopped.
    bool finish_activation_for_shutdown();

    static bool compatible(const RouteConfig& active,
                           RouteConfig& candidate,
                           u32 shard_count,
                           bool supports_active_health_probes = true);

private:
    static bool default_loader(void* context,
                               const char* source_path,
                               LoadedProgram& output,
                               LoadError& error,
                               jit::OptLevel opt);
    static bool capture_source_version(void* context,
                                       ReloadRequestSource source,
                                       char* out,
                                       u32 capacity,
                                       u32* out_len);
    bool refresh_source_snapshot();
    void clear_source_snapshots();
    void reclaim_retired_snapshots();
    bool all_shards_acknowledged(u64 generation) const;

    ControlPlaneMutationPort* mutation_ = nullptr;
    const char* source_path_ = nullptr;
    jit::OptLevel opt_ = jit::OptLevel::O2;
    LoadedProgram* active_ = nullptr;
    LoadedProgram* spare_ = nullptr;
    LoadedProgram* retired_ = nullptr;
    ReloadShardEndpoint shards_[kMaxShards]{};
    u32 shard_count_ = 0;
    ReloadProgramLoader loader_ = nullptr;
    void* loader_context_ = nullptr;
    ReloadCancellationCheck cancellation_check_ = nullptr;
    void* cancellation_context_ = nullptr;
    bool default_loader_selected_ = false;
    bool supports_active_health_probes_ = true;
    std::string cached_provider_version_;
    std::string cached_snapshot_source_;
    std::string source_snapshot_root_;
    std::vector<std::string> retired_snapshot_roots_;
    // Published by the control thread after a complete immutable snapshot is
    // installed. Route workers use it to copy a stable prepared path without
    // resolving the source provider or touching the filesystem.
    std::atomic<u64> source_snapshot_epoch_{0};
    std::atomic<bool> route_snapshot_armed_{false};
    mutable std::mutex source_snapshot_mutex_;
    ReloadRequest request_{};
    u64 old_generation_ = 0;
    LoadError last_load_error_{};
};

}  // namespace rut
