#pragma once

#include "rut/common/types.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/route_table.h"
#include <atomic>

namespace rut {

enum class ReloadRequestSource : u8 {
    Route = 0,
    Signal,
};

enum class ReloadAdmissionState : u8 {
    Idle = 0,
    Pending,
    InFlight,
    Completing,
    Stopping,
};

enum class ReloadTerminalOutcome : u8 {
    None = 0,
    Activated,
    CompileFailed,
    ValidationFailed,
    Stopped,
};

enum class ManualHealthOverride : u8 {
    None = 0,
    Healthy,
    Unhealthy,
};

struct ServerIdentity {
    u64 config_generation = 0;
    u16 upstream_id = 0;
    u16 backend_id = 0;
};

struct ReloadRequest {
    u64 id = 0;
    ReloadRequestSource source = ReloadRequestSource::Route;
};

struct ReloadTerminalRecord {
    bool valid = false;
    u64 request_id = 0;
    u64 old_generation = 0;
    u64 new_generation = 0;
    ReloadRequestSource source = ReloadRequestSource::Route;
    ReloadTerminalOutcome outcome = ReloadTerminalOutcome::None;
};

// Process-shared, allocation-free mutation boundary used by production and the
// deterministic harness. Reload admission is a single packed CAS word: route
// handlers can claim at most one request without blocking, while the process
// coordinator owns Pending -> InFlight -> Completing. Manual health overrides
// are generation-tagged atomics, so a stale Server can never mutate a target
// that reused the same numeric slot after reload.
class ControlPlaneMutationPort {
public:
    static_assert(std::atomic<u64>::is_always_lock_free);
    static_assert(std::atomic<u8>::is_always_lock_free);
    static constexpr u64 kMaxGeneration = (u64{1} << 62) - 1;
    static constexpr u64 kMaxRequestId = (u64{1} << 60) - 1;

    ControlPlaneMutationPort() { reset(1, false); }

    // Startup/harness setup only: callers must ensure no concurrent users.
    void reset(u64 generation, bool allow_route_reload) {
        if (generation == 0 || generation > kMaxGeneration) generation = 1;
        active_generation_.store(generation, std::memory_order_relaxed);
        route_reload_enabled_.store(allow_route_reload ? 1 : 0, std::memory_order_relaxed);
        reload_word_.store(pack_reload(ReloadAdmissionState::Idle, 0, ReloadRequestSource::Route),
                           std::memory_order_relaxed);
        next_request_id_.store(1, std::memory_order_relaxed);
        clear_overrides();
        record_seq_.store(0, std::memory_order_relaxed);
        record_request_id_.store(0, std::memory_order_relaxed);
        record_old_generation_.store(0, std::memory_order_relaxed);
        record_new_generation_.store(0, std::memory_order_relaxed);
        record_source_.store(static_cast<u8>(ReloadRequestSource::Route),
                             std::memory_order_relaxed);
        record_outcome_.store(static_cast<u8>(ReloadTerminalOutcome::None),
                              std::memory_order_relaxed);
    }

    bool set_route_reload_enabled(bool enabled) {
        if (state() == ReloadAdmissionState::Stopping) return false;
        route_reload_enabled_.store(enabled ? 1 : 0, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool route_reload_enabled() const {
        return route_reload_enabled_.load(std::memory_order_acquire) != 0;
    }

    [[nodiscard]] ReloadAdmissionState state() const {
        return unpack_state(reload_word_.load(std::memory_order_acquire));
    }

    [[nodiscard]] u64 active_generation() const {
        return active_generation_.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool request_reload(ReloadRequestSource source, u64* request_id = nullptr) {
        if (source == ReloadRequestSource::Route && !route_reload_enabled()) return false;
        const u64 id = next_request_id_.fetch_add(1, std::memory_order_relaxed);
        if (id == 0 || id > kMaxRequestId) return false;
        u64 expected = pack_reload(ReloadAdmissionState::Idle, 0, ReloadRequestSource::Route);
        const u64 desired = pack_reload(ReloadAdmissionState::Pending, id, source);
        if (!reload_word_.compare_exchange_strong(
                expected, desired, std::memory_order_release, std::memory_order_relaxed))
            return false;
        if (request_id != nullptr) *request_id = id;
        return true;
    }

    // Process coordinator only. Exactly one coordinator may consume requests.
    [[nodiscard]] bool take_reload(ReloadRequest* out) {
        if (out == nullptr) return false;
        u64 expected = reload_word_.load(std::memory_order_acquire);
        if (unpack_state(expected) != ReloadAdmissionState::Pending) return false;
        const u64 desired = with_state(expected, ReloadAdmissionState::InFlight);
        if (!reload_word_.compare_exchange_strong(
                expected, desired, std::memory_order_acq_rel, std::memory_order_acquire))
            return false;
        out->id = unpack_request_id(desired);
        out->source = unpack_source(desired);
        return true;
    }

    // Process coordinator only. Activated outcomes must advance the generation;
    // failures leave the active generation and override table untouched.
    [[nodiscard]] bool complete_reload(u64 request_id,
                                       ReloadRequestSource source,
                                       ReloadTerminalOutcome outcome,
                                       u64 new_generation = 0) {
        if (outcome == ReloadTerminalOutcome::None || outcome == ReloadTerminalOutcome::Stopped)
            return false;
        const u64 old_generation = active_generation();
        if (outcome == ReloadTerminalOutcome::Activated) {
            if (new_generation == 0 || new_generation <= old_generation ||
                new_generation > kMaxGeneration)
                return false;
        } else if (new_generation != 0) {
            return false;
        }
        u64 expected = pack_reload(ReloadAdmissionState::InFlight, request_id, source);
        const u64 completing = with_state(expected, ReloadAdmissionState::Completing);
        if (!reload_word_.compare_exchange_strong(
                expected, completing, std::memory_order_acq_rel, std::memory_order_acquire))
            return false;

        if (outcome == ReloadTerminalOutcome::Activated) {
            // Generation zero is an intentionally unavailable publication
            // window: old-generation writers fail their post-store recheck and
            // new-generation writers cannot start until clearing is complete.
            active_generation_.store(0, std::memory_order_release);
            clear_overrides();
            active_generation_.store(new_generation, std::memory_order_release);
        }

        publish_record({true, request_id, old_generation, new_generation, source, outcome});
        u64 completing_expected = completing;
        (void)reload_word_.compare_exchange_strong(
            completing_expected,
            pack_reload(ReloadAdmissionState::Idle, 0, ReloadRequestSource::Route),
            std::memory_order_release,
            std::memory_order_relaxed);
        return true;
    }

    // Prevent new admission. An accepted request that has not entered the
    // non-interruptible Completing phase receives exactly one Stopped record.
    void stop() {
        const u64 stopped =
            pack_reload(ReloadAdmissionState::Stopping, 0, ReloadRequestSource::Route);
        const u64 previous = reload_word_.exchange(stopped, std::memory_order_acq_rel);
        const auto previous_state = unpack_state(previous);
        if (previous_state == ReloadAdmissionState::Pending ||
            previous_state == ReloadAdmissionState::InFlight) {
            const u64 generation = active_generation();
            publish_record({true,
                            unpack_request_id(previous),
                            generation,
                            0,
                            unpack_source(previous),
                            ReloadTerminalOutcome::Stopped});
        }
    }

    [[nodiscard]] bool mark(ServerIdentity server, bool healthy) {
        if (state() == ReloadAdmissionState::Stopping) return false;
        if (server.config_generation == 0 || server.upstream_id >= RouteConfig::kMaxUpstreams ||
            server.backend_id >= UpstreamTarget::kMaxBackends)
            return false;
        const u64 generation = active_generation();
        if (generation == 0 || server.config_generation != generation) return false;
        const auto value =
            healthy ? ManualHealthOverride::Healthy : ManualHealthOverride::Unhealthy;
        overrides_[server.upstream_id][server.backend_id].store(pack_override(generation, value),
                                                                std::memory_order_release);
        return active_generation() == generation;
    }

    [[nodiscard]] ManualHealthOverride manual_health(ServerIdentity server) const {
        const u64 generation = active_generation();
        if (generation == 0 || server.config_generation != generation ||
            server.upstream_id >= RouteConfig::kMaxUpstreams ||
            server.backend_id >= UpstreamTarget::kMaxBackends)
            return ManualHealthOverride::None;
        const u64 packed =
            overrides_[server.upstream_id][server.backend_id].load(std::memory_order_acquire);
        if (unpack_override_generation(packed) != generation || active_generation() != generation)
            return ManualHealthOverride::None;
        return unpack_override(packed);
    }

    [[nodiscard]] ReloadTerminalRecord last_record() const {
        for (;;) {
            const u64 before = record_seq_.load(std::memory_order_acquire);
            if ((before & 1u) != 0) continue;
            ReloadTerminalRecord record{};
            record.request_id = record_request_id_.load(std::memory_order_relaxed);
            record.old_generation = record_old_generation_.load(std::memory_order_relaxed);
            record.new_generation = record_new_generation_.load(std::memory_order_relaxed);
            record.source =
                static_cast<ReloadRequestSource>(record_source_.load(std::memory_order_relaxed));
            record.outcome =
                static_cast<ReloadTerminalOutcome>(record_outcome_.load(std::memory_order_relaxed));
            const u64 after = record_seq_.load(std::memory_order_acquire);
            if (before == after) {
                record.valid = record.outcome != ReloadTerminalOutcome::None;
                return record;
            }
        }
    }

private:
    static constexpr u64 kStateMask = 0x7u;
    static constexpr u64 kSourceBit = 0x8u;
    static constexpr u32 kRequestShift = 4;
    static constexpr u64 kOverrideMask = 0x3u;
    static constexpr u32 kOverrideGenerationShift = 2;

    static constexpr u64 pack_reload(ReloadAdmissionState state,
                                     u64 request_id,
                                     ReloadRequestSource source) {
        return (request_id << kRequestShift) |
               (source == ReloadRequestSource::Signal ? kSourceBit : 0) | static_cast<u8>(state);
    }
    static constexpr ReloadAdmissionState unpack_state(u64 value) {
        return static_cast<ReloadAdmissionState>(value & kStateMask);
    }
    static constexpr ReloadRequestSource unpack_source(u64 value) {
        return (value & kSourceBit) != 0 ? ReloadRequestSource::Signal : ReloadRequestSource::Route;
    }
    static constexpr u64 unpack_request_id(u64 value) { return value >> kRequestShift; }
    static constexpr u64 with_state(u64 value, ReloadAdmissionState state) {
        return (value & ~kStateMask) | static_cast<u8>(state);
    }
    static constexpr u64 pack_override(u64 generation, ManualHealthOverride value) {
        return (generation << kOverrideGenerationShift) | static_cast<u8>(value);
    }
    static constexpr u64 unpack_override_generation(u64 value) {
        return value >> kOverrideGenerationShift;
    }
    static constexpr ManualHealthOverride unpack_override(u64 value) {
        return static_cast<ManualHealthOverride>(value & kOverrideMask);
    }

    void clear_overrides() {
        for (auto& upstream : overrides_)
            for (auto& backend : upstream) backend.store(0, std::memory_order_relaxed);
    }

    void publish_record(const ReloadTerminalRecord& record) {
        record_seq_.fetch_add(1, std::memory_order_acq_rel);
        record_request_id_.store(record.request_id, std::memory_order_relaxed);
        record_old_generation_.store(record.old_generation, std::memory_order_relaxed);
        record_new_generation_.store(record.new_generation, std::memory_order_relaxed);
        record_source_.store(static_cast<u8>(record.source), std::memory_order_relaxed);
        record_outcome_.store(static_cast<u8>(record.outcome), std::memory_order_relaxed);
        record_seq_.fetch_add(1, std::memory_order_release);
    }

    std::atomic<u64> reload_word_{0};
    std::atomic<u64> next_request_id_{1};
    std::atomic<u8> route_reload_enabled_{0};
    std::atomic<u64> active_generation_{1};
    std::atomic<u64> overrides_[RouteConfig::kMaxUpstreams][UpstreamTarget::kMaxBackends]{};

    std::atomic<u64> record_seq_{0};
    std::atomic<u64> record_request_id_{0};
    std::atomic<u64> record_old_generation_{0};
    std::atomic<u64> record_new_generation_{0};
    std::atomic<u8> record_source_{0};
    std::atomic<u8> record_outcome_{0};
};

template <typename Loop>
inline void latch_control_plane_mutation(Loop* loop, jit::HandlerCtx* ctx) {
    if (ctx == nullptr) return;
    ctx->control_plane_mutation = nullptr;
    if (loop == nullptr) return;
    if constexpr (requires { loop->control_plane_mutation; })
        ctx->control_plane_mutation = loop->control_plane_mutation;
}

}  // namespace rut
