#pragma once

#include "rut/common/types.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/control_plane_replay.h"
#include "rut/runtime/route_table.h"
#include <atomic>
#include <mutex>

namespace rut {

// Replay executes captured requests outside live traffic admission. Keep this
// thread-local so replay cannot latch a real mutation port into its handler
// context even when the loop does not expose a capture ring.
inline thread_local bool control_plane_replay_mode = false;
inline thread_local const void* control_plane_mark_replay_callback_owner = nullptr;
inline thread_local u32 control_plane_mark_replay_callback_depth = 0;

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
    Busy,
    Stopped,
    AdmissionContended,
    CounterExhausted,
    SnapshotUnavailable,
};

constexpr const char* reload_terminal_outcome_name(ReloadTerminalOutcome outcome) {
    switch (outcome) {
        case ReloadTerminalOutcome::None:
            return "none";
        case ReloadTerminalOutcome::Activated:
            return "activated";
        case ReloadTerminalOutcome::CompileFailed:
            return "compile_failed";
        case ReloadTerminalOutcome::ValidationFailed:
            return "validation_failed";
        case ReloadTerminalOutcome::Busy:
            return "busy";
        case ReloadTerminalOutcome::Stopped:
            return "stopped";
        case ReloadTerminalOutcome::AdmissionContended:
            return "admission_contended";
        case ReloadTerminalOutcome::CounterExhausted:
            return "counter_exhausted";
        case ReloadTerminalOutcome::SnapshotUnavailable:
            return "snapshot_unavailable";
    }
    return "none";
}

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
    static constexpr u32 kMaxSourceVersion = 1024;

    u64 id = 0;
    ReloadRequestSource source = ReloadRequestSource::Route;
    u32 source_version_len = 0;
    char source_version[kMaxSourceVersion]{};
};

using ReloadSourceVersionCapture = bool (*)(void* context, char* out, u32 capacity, u32* out_len);

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
    struct ClaimedRecordSlot {
        u64 ticket = 0;
        u64 sequence = 0;
        u32 slot = 0;
        bool valid = false;
    };

public:
    static_assert(std::atomic<u64>::is_always_lock_free);
    static_assert(std::atomic<u8>::is_always_lock_free);
    static constexpr u64 kMaxGeneration = (u64{1} << 62) - 1;
    static constexpr u64 kMaxRequestId = (u64{1} << 32) - 1;
    static constexpr u64 kCounterExhaustedRequestId = kMaxRequestId + 1;
    static constexpr u32 kMaxMarkAttempts = 8;
    static constexpr u32 kMaxSnapshotAttempts = 8;
    static constexpr u32 kMaxAdmissionAttempts = 8;
    static constexpr u32 kMaxCounterAllocationAttempts = 128;
    static constexpr u16 kInvalidAllocation = 0xffff;
    static constexpr u16 kMaxUpstreamAllocations = RouteConfig::kMaxUpstreams * 2;
    static constexpr u16 kMaxEndpointAllocations =
        kMaxUpstreamAllocations * UpstreamTarget::kMaxBackends;
    static constexpr u32 kPublisherClosed = u32{1} << 31;
    static constexpr u32 kPublisherCountMask = kPublisherClosed - 1;

    ControlPlaneMutationPort() { reset(1, false); }

    // Startup/harness setup only: callers must ensure no concurrent users.
    void reset(u64 generation, bool allow_route_reload, RouteConfig* config = nullptr) {
        if (generation == 0 || generation > kMaxGeneration) generation = 1;
        if (config != nullptr) config->config_generation = generation;
        active_bank_.store(0, std::memory_order_relaxed);
        for (u32 bank = 0; bank < 2; bank++) {
            clear_bank(bank);
            bank_generation_[bank].store(0, std::memory_order_relaxed);
            bank_config_[bank].store(nullptr, std::memory_order_relaxed);
        }
        configure_membership(0, config);
        initialize_allocations(0);
        bank_config_[0].store(config, std::memory_order_relaxed);
        bank_generation_[0].store(generation, std::memory_order_relaxed);
        active_generation_.store(generation, std::memory_order_relaxed);
        stopping_.store(0, std::memory_order_relaxed);
        cutover_.store(0, std::memory_order_relaxed);
        admission_identity_claim_.store(kAdmissionOpen, std::memory_order_relaxed);
        terminal_publication_claim_.store(0, std::memory_order_relaxed);
        unclaimed_busy_publishers_.store(0, std::memory_order_relaxed);
        stopping_terminal_publishers_.store(0, std::memory_order_relaxed);
        stopped_signal_publishers_.store(0, std::memory_order_relaxed);
        override_writer_claim_.store(0, std::memory_order_relaxed);
        activation_publication_.store(kPublicationOpen, std::memory_order_relaxed);
        activation_terminal_slot_ = {};
        event_counters_.store(0, std::memory_order_relaxed);
        counter_exhaustion_generation_.store(0, std::memory_order_relaxed);
        counter_exhaustion_frontier_.store(0, std::memory_order_relaxed);
        counter_exhaustion_state_.store(0, std::memory_order_relaxed);
        reload_word_.store(
            pack_reload(
                ReloadAdmissionState::Idle, 0, ReloadRequestSource::Route, allow_route_reload),
            std::memory_order_relaxed);
        published_record_.store(0, std::memory_order_relaxed);
        for (u32 slot = 0; slot < kRecordSlotCount; slot++) {
            record_seq_[slot].store(0, std::memory_order_relaxed);
            record_claim_ticket_[slot].store(0, std::memory_order_relaxed);
            record_slot_ticket_[slot].store(0, std::memory_order_relaxed);
            record_observable_ticket_[slot].store(0, std::memory_order_relaxed);
            record_request_id_[slot].store(0, std::memory_order_relaxed);
            record_old_generation_[slot].store(0, std::memory_order_relaxed);
            record_new_generation_[slot].store(0, std::memory_order_relaxed);
            record_source_[slot].store(static_cast<u8>(ReloadRequestSource::Route),
                                       std::memory_order_relaxed);
            record_outcome_[slot].store(static_cast<u8>(ReloadTerminalOutcome::None),
                                        std::memory_order_relaxed);
        }
    }

    // Deterministic scenario isolation clears mutable control-plane state but
    // must retain the active config's bounded server membership.
    void reset_preserving_membership(u64 generation, bool allow_route_reload) {
        const u32 bank = active_bank_.load(std::memory_order_relaxed);
        reset(generation, allow_route_reload, bank_config_[bank].load(std::memory_order_relaxed));
    }

    bool set_route_reload_enabled(bool enabled) {
        if (stopping_.load(std::memory_order_acquire) != 0) return false;
        if (!try_lock_terminal_publication()) return false;
        u32 identity_open = kAdmissionOpen;
        if (!admission_identity_claim_.compare_exchange_strong(identity_open,
                                                               kAdmissionAuthorityClaimed,
                                                               std::memory_order_acq_rel,
                                                               std::memory_order_acquire)) {
            unlock_terminal_publication();
            return false;
        }

        u64 observed = reload_word_.load(std::memory_order_acquire);
        if (stopping_.load(std::memory_order_acquire) != 0 ||
            unpack_state(observed) != ReloadAdmissionState::Idle) {
            admission_identity_claim_.store(kAdmissionOpen, std::memory_order_release);
            unlock_terminal_publication();
            return false;
        }
        // The identity claim makes the authority bit and request-counter
        // reservation one admission protocol. An Idle requester either
        // publishes Pending with its reserved ID first, or observes this
        // update before reserving an ID; neither side can strand a hole.
        const u64 desired = with_route_enabled(observed, enabled);
        const bool updated =
            desired == observed ||
            reload_word_.compare_exchange_strong(
                observed, desired, std::memory_order_acq_rel, std::memory_order_acquire);
        admission_identity_claim_.store(kAdmissionOpen, std::memory_order_release);
        unlock_terminal_publication();
        return updated && stopping_.load(std::memory_order_acquire) == 0;
    }

    // Permanently close route authority at a process shutdown boundary without
    // cancelling an activation that has already crossed publication. Unlike the
    // general capability setter, this must also work while the slot is
    // Completing; finish_activation() preserves the cleared bit when it exposes
    // Idle, so draining handlers cannot claim a new request in between
    // activation completion and stop(). Signal admission remains available to
    // the coordinator until stop() closes the entire mutation boundary.
    void close_route_reload_admission() {
        lock_terminal_publication();
        u32 identity_open = kAdmissionOpen;
        while (!admission_identity_claim_.compare_exchange_weak(identity_open,
                                                                kAdmissionAuthorityClaimed,
                                                                std::memory_order_acq_rel,
                                                                std::memory_order_acquire)) {
            identity_open = kAdmissionOpen;
        }
        u64 observed = reload_word_.load(std::memory_order_acquire);
        for (;;) {
            const u64 closed = with_route_enabled(observed, false);
            if (closed == observed ||
                reload_word_.compare_exchange_weak(
                    observed, closed, std::memory_order_acq_rel, std::memory_order_acquire))
                break;
        }
        admission_identity_claim_.store(kAdmissionOpen, std::memory_order_release);
        unlock_terminal_publication();
    }

    [[nodiscard]] bool route_reload_enabled() const {
        return unpack_route_enabled(reload_word_.load(std::memory_order_acquire));
    }

    [[nodiscard]] ReloadAdmissionState state() const {
        const auto current = unpack_state(reload_word_.load(std::memory_order_acquire));
        if (current != ReloadAdmissionState::Completing &&
            stopping_.load(std::memory_order_acquire) != 0)
            return ReloadAdmissionState::Stopping;
        return current;
    }

    [[nodiscard]] bool admission_in_progress() const {
        return admission_identity_claim_.load(std::memory_order_acquire) != kAdmissionOpen;
    }

    [[nodiscard]] u64 active_generation() const {
        return active_generation_.load(std::memory_order_acquire);
    }

    void set_reload_source_version_capture(ReloadSourceVersionCapture capture, void* context) {
        source_version_capture_ = capture;
        source_version_capture_context_ = context;
    }

    void clear_reload_source_version_capture(ReloadSourceVersionCapture capture, void* context) {
        if (source_version_capture_ == capture && source_version_capture_context_ == context) {
            source_version_capture_ = nullptr;
            source_version_capture_context_ = nullptr;
        }
    }

    void set_upstream_mark_replay_sink(UpstreamMarkReplaySink sink, void* context) {
        if (control_plane_mark_replay_callback_owner == this &&
            control_plane_mark_replay_callback_depth != 0) {
            std::lock_guard lock(mark_replay_mutex_);
            const u64 epoch = mark_replay_sink_epoch_.load(std::memory_order_relaxed);
            const bool opened_epoch = (epoch & 1u) == 0;
            if (opened_epoch) mark_replay_sink_epoch_.fetch_add(1, std::memory_order_acq_rel);
            mark_replay_sink_.store(sink, std::memory_order_relaxed);
            mark_replay_sink_context_.store(context, std::memory_order_relaxed);
            mark_replay_sequence_.store(0, std::memory_order_release);
            if (opened_epoch) mark_replay_sink_epoch_.fetch_add(1, std::memory_order_release);
            return;
        }
        for (;;) {
            {
                std::lock_guard lock(mark_replay_mutex_);
                if ((mark_replay_sink_epoch_.load(std::memory_order_relaxed) & 1u) == 0)
                    mark_replay_sink_epoch_.fetch_add(1, std::memory_order_acq_rel);
            }
            while (mark_replay_callbacks_.load(std::memory_order_acquire) != 0) {
            }
            std::lock_guard lock(mark_replay_mutex_);
            if (mark_replay_callbacks_.load(std::memory_order_acquire) != 0) continue;
            u64 epoch = mark_replay_sink_epoch_.load(std::memory_order_relaxed);
            if ((epoch & 1u) == 0) {
                mark_replay_sink_epoch_.fetch_add(1, std::memory_order_acq_rel);
                epoch++;
            }
            mark_replay_sink_.store(sink, std::memory_order_relaxed);
            mark_replay_sink_context_.store(context, std::memory_order_relaxed);
            mark_replay_sequence_.store(0, std::memory_order_release);
            mark_replay_sink_epoch_.store(epoch + 1, std::memory_order_release);
            return;
        }
    }

    [[nodiscard]] bool request_reload(ReloadRequestSource source, u64* request_id = nullptr) {
        for (u32 round = 0; round < kMaxAdmissionAttempts; round++) {
            if (stopping_.load(std::memory_order_acquire) != 0) {
                if (source == ReloadRequestSource::Signal) (void)publish_stopped_signal(request_id);
                return false;
            }
            u64 observed = reload_word_.load(std::memory_order_acquire);
            if (source == ReloadRequestSource::Signal &&
                unpack_state(observed) == ReloadAdmissionState::Idle &&
                admission_identity_claim_.load(std::memory_order_acquire) ==
                    kAdmissionAuthorityClaimed &&
                publish_authority_contended_signal(request_id))
                return false;
            for (u32 attempt = 0; attempt < kMaxAdmissionAttempts; attempt++) {
                if (unpack_state(observed) != ReloadAdmissionState::Idle) break;
                if (source == ReloadRequestSource::Route && !unpack_route_enabled(observed))
                    return false;
                if (source == ReloadRequestSource::Route &&
                    active_generation_.load(std::memory_order_acquire) >= kMaxGeneration)
                    return false;
                // Serialize the request claim through identity reservation
                // with Busy terminal publication and stop(). No observer can
                // allocate a later request identity from a claim whose
                // occupant has not reserved its own yet.
                if (!try_lock_terminal_publication()) {
                    if (source == ReloadRequestSource::Signal) {
                        const u8 owner =
                            terminal_publication_claim_.load(std::memory_order_acquire);
                        if (owner == kTerminalPublicationStopClaimed)
                            return admit_contended_idle_signal(request_id);
                        if (owner == kTerminalPublicationRequestClaimed) {
                            if (publish_unclaimed_contended_busy(request_id)) return false;
                            // The request owner may have advanced to Pending
                            // between the owner observation and the helper's
                            // revalidation. Retry from the current admission
                            // word so this signal follows the ordinary Busy
                            // path instead of disappearing.
                            observed = reload_word_.load(std::memory_order_acquire);
                            continue;
                        }
                        const u32 identity_claim =
                            admission_identity_claim_.load(std::memory_order_acquire);
                        if ((is_admission_request_claim(identity_claim) ||
                             is_admission_busy_claim(identity_claim)) &&
                            publish_contended_busy(request_id))
                            return false;
                        // A generic terminal publisher may already have
                        // reopened admission after a failed completion but not
                        // yet published its record. Retry within the bounded
                        // admission budget; if it remains occupied, the final
                        // fallback below records this signal as Busy. The Open
                        // observation covers release between the failed lock
                        // attempt and the owner load.
                        if (owner == kTerminalPublicationClaimed ||
                            owner == kTerminalPublicationOpen) {
                            observed = reload_word_.load(std::memory_order_acquire);
                            continue;
                        }
                    }
                    if (request_id != nullptr) *request_id = 0;
                    return false;
                }
                observed = reload_word_.load(std::memory_order_acquire);
                if (unpack_state(observed) != ReloadAdmissionState::Idle ||
                    stopping_.load(std::memory_order_acquire) != 0) {
                    unlock_terminal_publication();
                    continue;
                }
                if (source == ReloadRequestSource::Route && !unpack_route_enabled(observed)) {
                    unlock_terminal_publication();
                    return false;
                }
                const u32 visible_identity_claim =
                    admission_identity_claim_.load(std::memory_order_acquire);
                if (visible_identity_claim != kAdmissionOpen) {
                    unlock_terminal_publication();
                    if (source == ReloadRequestSource::Signal &&
                        (is_admission_request_claim(visible_identity_claim) ||
                         is_admission_busy_claim(visible_identity_claim))) {
                        if (publish_contended_busy(request_id)) return false;
                        // The visible request may have advanced and released
                        // its identity while a transient authority claim made
                        // Busy publication lose revalidation. Retry from the
                        // current admission word instead of dropping the
                        // signal without an identity or terminal record.
                        observed = reload_word_.load(std::memory_order_acquire);
                        continue;
                    }
                    return false;
                }
                // The admission word may have changed while an earlier
                // request released its identity claim. Reload it after
                // observing the open claim so a stale Idle snapshot cannot
                // reserve an identity behind an already admitted request.
                observed = reload_word_.load(std::memory_order_acquire);
                if (unpack_state(observed) != ReloadAdmissionState::Idle ||
                    stopping_.load(std::memory_order_acquire) != 0) {
                    unlock_terminal_publication();
                    continue;
                }
                if (source == ReloadRequestSource::Route && !unpack_route_enabled(observed)) {
                    unlock_terminal_publication();
                    return false;
                }
                u32 identity_open = kAdmissionOpen;
                if (!admission_identity_claim_.compare_exchange_strong(identity_open,
                                                                       kAdmissionRequestClaimed,
                                                                       std::memory_order_acq_rel,
                                                                       std::memory_order_acquire)) {
                    unlock_terminal_publication();
                    observed = reload_word_.load(std::memory_order_acquire);
                    continue;
                }
                // Capture only after this caller owns the single admission
                // slot. This lets a provider bind an immutable source snapshot
                // to the winning request without doing work for Busy callers.
                char source_version[ReloadRequest::kMaxSourceVersion]{};
                u32 source_version_len = 0;
                bool snapshot_recorded = false;
                bool snapshot_capture_failed = false;
                if (source_version_capture_ != nullptr) {
                    snapshot_capture_failed =
                        !source_version_capture_(source_version_capture_context_,
                                                 source_version,
                                                 ReloadRequest::kMaxSourceVersion,
                                                 &source_version_len);
                    snapshot_capture_failed |=
                        source_version_len >= ReloadRequest::kMaxSourceVersion;
                }
                if (snapshot_capture_failed) {
                    if (source == ReloadRequestSource::Signal) {
                        ClaimedRecordSlot snapshot_slot{};
                        const u64 snapshot_id = reserve_request_identity(&snapshot_slot);
                        if (snapshot_id != 0) {
                            const bool published =
                                publish_claimed_record({true,
                                                        snapshot_id,
                                                        active_generation(),
                                                        0,
                                                        ReloadRequestSource::Signal,
                                                        ReloadTerminalOutcome::SnapshotUnavailable},
                                                       snapshot_slot);
                            if (published) {
                                snapshot_recorded = true;
                                if (request_id != nullptr) *request_id = snapshot_id;
                            }
                        }
                    }
                    release_request_identity_claim();
                    unlock_terminal_publication();
                    if (request_id != nullptr && !snapshot_recorded) *request_id = 0;
                    return false;
                }
                ClaimedRecordSlot identity_slot{};
                const u64 id = reserve_request_identity(&identity_slot);
                if (id == 0) {
                    release_request_identity_claim();
                    unlock_terminal_publication();
                    if (source == ReloadRequestSource::Signal)
                        (void)terminalize_counter_exhaustion(request_id);
                    return false;
                }
                // Expose the request-specific terminal owner only after its
                // identity is reserved. A signal that observes this value can
                // therefore allocate only a later Busy identity.
                terminal_publication_claim_.store(kTerminalPublicationRequestClaimed,
                                                  std::memory_order_release);
                // Release the terminal lock before the Pending CAS so a
                // bounded signal may publish Busy without overtaking it.
                unlock_terminal_publication();
                const u64 desired = pack_reload(
                    ReloadAdmissionState::Pending, id, source, unpack_route_enabled(observed));
                source_version_len_ = source_version_len;
                for (u32 i = 0; i < source_version_len; i++) source_version_[i] = source_version[i];
                const bool admitted = reload_word_.compare_exchange_strong(
                    observed, desired, std::memory_order_acq_rel, std::memory_order_acquire);
                if (admitted) {
                    // The accepted request keeps its identity but does not
                    // consume a terminal-history ticket until completion.
                    finish_request_identity_reservation(identity_slot, id);
                } else {
                    const auto outcome =
                        stopping_.load(std::memory_order_acquire) != 0 ||
                                unpack_state(observed) == ReloadAdmissionState::Stopping
                            ? ReloadTerminalOutcome::Stopped
                            : ReloadTerminalOutcome::Busy;
                    if (source == ReloadRequestSource::Signal) {
                        const bool published = publish_claimed_record({true,
                                                                       id,
                                                                       active_generation(),
                                                                       0,
                                                                       ReloadRequestSource::Signal,
                                                                       outcome},
                                                                      identity_slot);
                        if (published && request_id != nullptr) *request_id = id;
                    } else {
                        u64 counters = pack_event_counters(identity_slot.ticket, id);
                        const u64 rollback = pack_event_counters(identity_slot.ticket - 1, id - 1);
                        if (event_counters_.compare_exchange_strong(counters,
                                                                    rollback,
                                                                    std::memory_order_acq_rel,
                                                                    std::memory_order_acquire))
                            release_record_slot(identity_slot);
                        else
                            cancel_claimed_record(identity_slot);
                    }
                }
                release_request_identity_claim();
                if (admitted) {
                    if (request_id != nullptr) *request_id = id;
                    return true;
                }
            }

            if (source != ReloadRequestSource::Signal) return false;
            if (unpack_state(observed) == ReloadAdmissionState::Stopping ||
                stopping_.load(std::memory_order_acquire) != 0) {
                // Shutdown may win after this round's entry check while the
                // signal is retrying Idle admission. Preserve the same
                // explicit terminal outcome as a signal that observes
                // stopping at entry instead of returning its caller's stale
                // request ID without a corresponding record.
                (void)publish_stopped_signal(request_id);
                return false;
            }
            if (unpack_state(observed) == ReloadAdmissionState::Idle) {
                // A signal must not disappear while another Idle contender
                // owns the identity protocol. Preserve it for the bounded
                // outer retry budget, then publish Busy below if the claim is
                // still the linearized occupant.
                continue;
            }

            if (publish_busy_for_observed(observed, request_id)) return false;
        }
        if (source == ReloadRequestSource::Signal) {
            const u64 observed = reload_word_.load(std::memory_order_acquire);
            if (stopping_.load(std::memory_order_acquire) != 0 ||
                unpack_state(observed) == ReloadAdmissionState::Stopping) {
                (void)publish_stopped_signal(request_id);
            } else if (!publish_busy_for_observed(observed, request_id) &&
                       unpack_state(reload_word_.load(std::memory_order_acquire)) ==
                           ReloadAdmissionState::Idle) {
                (void)admit_contended_idle_signal(request_id);
            }
        }
        return false;
    }

    // Process coordinator only. Exactly one coordinator may consume requests.
    [[nodiscard]] bool take_reload(ReloadRequest* out) {
        if (out == nullptr || stopping_.load(std::memory_order_acquire) != 0) return false;
        u64 expected = reload_word_.load(std::memory_order_acquire);
        if (unpack_state(expected) != ReloadAdmissionState::Pending) return false;
        const u64 desired = with_state(expected, ReloadAdmissionState::InFlight);
        if (!reload_word_.compare_exchange_strong(
                expected, desired, std::memory_order_acq_rel, std::memory_order_acquire))
            return false;
        if (stopping_.load(std::memory_order_acquire) != 0) {
            // stop() owns the terminal-publication lock before setting
            // stopping_, and its reload-word loop observes this InFlight state
            // and publishes the required Stopped record before returning. Do
            // not reserve a competing earlier ticket here: if this thread is
            // descheduled before staging its tombstone, it could block the
            // ordered record frontier past the shutdown boundary.
            return false;
        }
        out->id = unpack_request_id(desired);
        out->source = unpack_source(desired);
        out->source_version_len = source_version_len_;
        for (u32 i = 0; i < source_version_len_; i++) out->source_version[i] = source_version_[i];
        if (source_version_len_ < ReloadRequest::kMaxSourceVersion)
            out->source_version[source_version_len_] = '\0';
        return true;
    }

    // Process coordinator only. Activated outcomes publish the generation but
    // deliberately remain Completing. finish_activation() is called only after
    // every shard acknowledged it and the retained generation has no pins.
    // Failures leave the active generation and override tables untouched.
    [[nodiscard]] bool complete_reload(u64 request_id,
                                       ReloadRequestSource source,
                                       ReloadTerminalOutcome outcome,
                                       u64 new_generation = 0,
                                       RouteConfig* new_config = nullptr) {
        if (outcome == ReloadTerminalOutcome::None || outcome == ReloadTerminalOutcome::Busy ||
            outcome == ReloadTerminalOutcome::Stopped ||
            outcome == ReloadTerminalOutcome::AdmissionContended ||
            outcome == ReloadTerminalOutcome::CounterExhausted)
            return false;
        const u64 old_generation = active_generation();
        if (outcome == ReloadTerminalOutcome::Activated) {
            if (old_generation >= kMaxGeneration || new_generation != old_generation + 1 ||
                new_generation > kMaxGeneration || new_config == nullptr)
                return false;
        } else if (new_generation != 0 &&
                   (new_generation <= old_generation || new_generation > kMaxGeneration)) {
            return false;
        }
        if (stopping_.load(std::memory_order_acquire) != 0) return false;
        u64 expected = reload_word_.load(std::memory_order_acquire);
        if (unpack_state(expected) != ReloadAdmissionState::InFlight ||
            unpack_request_id(expected) != request_id || unpack_source(expected) != source)
            return false;
        const u64 completing = with_state(expected, ReloadAdmissionState::Completing);
        if (!reload_word_.compare_exchange_strong(
                expected, completing, std::memory_order_acq_rel, std::memory_order_acquire))
            return false;

        // Closing mutation admission linearizes before publication when stop()
        // wins either side of the InFlight -> Completing CAS. The second check
        // covers the window after stop stored stopping_ but before it could
        // replace reload_word_; no candidate state has changed yet.
        if (stopping_.load(std::memory_order_acquire) != 0) {
            (void)terminalize_stopping(
                {true, request_id, old_generation, 0, source, ReloadTerminalOutcome::Stopped},
                completing);
            return false;
        }

        if (outcome == ReloadTerminalOutcome::Activated) {
            // Keep the last published generation visible to capture/Busy
            // observers while cutover independently closes mark admission.
            cutover_.store(1, std::memory_order_release);
            const u32 old_bank = active_bank_.load(std::memory_order_relaxed);
            auto& old_sequence = override_seq_[old_bank];
            u64 stable_seq = old_sequence.load(std::memory_order_acquire);
            bool claimed = false;
            for (u32 attempt = 0; attempt < kMaxMarkAttempts; attempt++) {
                if ((stable_seq & 1u) != 0) {
                    stable_seq = old_sequence.load(std::memory_order_acquire);
                    continue;
                }
                if (old_sequence.compare_exchange_weak(stable_seq,
                                                       stable_seq + 1,
                                                       std::memory_order_acq_rel,
                                                       std::memory_order_acquire)) {
                    claimed = true;
                    break;
                }
            }
            if (!claimed) {
                u64 rollback = completing;
                if (stopping_.load(std::memory_order_acquire) != 0) {
                    (void)terminalize_stopping({true,
                                                request_id,
                                                old_generation,
                                                0,
                                                source,
                                                ReloadTerminalOutcome::Stopped},
                                               completing);
                } else if (reload_word_.compare_exchange_strong(rollback,
                                                                expected,
                                                                std::memory_order_acq_rel,
                                                                std::memory_order_acquire) &&
                           stopping_.load(std::memory_order_acquire) != 0) {
                    (void)terminalize_stopping({true,
                                                request_id,
                                                old_generation,
                                                0,
                                                source,
                                                ReloadTerminalOutcome::Stopped},
                                               expected);
                }
                cutover_.store(0, std::memory_order_release);
                return false;
            }
            // cutover_ excludes new writers and the successful odd claim proves
            // every earlier writer has drained. Restore a stable sequence now
            // so retained-generation readers remain lock-free during new-bank
            // initialization and publication.
            old_sequence.store(stable_seq, std::memory_order_release);
            const u32 new_bank = old_bank ^ 1u;
            clear_bank(new_bank);
            configure_membership(new_bank, new_config);
            bank_config_[new_bank].store(new_config, std::memory_order_relaxed);
            carry_compatible_overrides(old_bank, new_bank, old_generation, new_generation);
            // Claim physical record capacity before crossing the non-fallible
            // generation-publication boundary. Its ticket is assigned only at
            // finish_activation(), so Busy records do not wait behind an
            // acknowledgement-dependent frontier gap.
            auto terminal_slot = reserve_activation_record_slot();
            if (!terminal_slot.valid) {
                clear_bank(new_bank);
                u64 rollback = completing;
                if (stopping_.load(std::memory_order_acquire) != 0) {
                    (void)terminalize_stopping({true,
                                                request_id,
                                                old_generation,
                                                0,
                                                source,
                                                ReloadTerminalOutcome::Stopped},
                                               completing);
                } else {
                    (void)reload_word_.compare_exchange_strong(
                        rollback, expected, std::memory_order_acq_rel, std::memory_order_acquire);
                }
                cutover_.store(0, std::memory_order_release);
                return false;
            }
            activation_terminal_slot_ = terminal_slot;
            u8 publication = kPublicationOpen;
            if (!activation_publication_.compare_exchange_strong(publication,
                                                                 kPublicationClaimed,
                                                                 std::memory_order_acq_rel,
                                                                 std::memory_order_acquire)) {
                release_record_slot(activation_terminal_slot_);
                activation_terminal_slot_ = {};
                clear_bank(new_bank);
                (void)terminalize_stopping(
                    {true, request_id, old_generation, 0, source, ReloadTerminalOutcome::Stopped},
                    completing);
                cutover_.store(0, std::memory_order_release);
                return false;
            }
            new_config->config_generation = new_generation;
            bank_generation_[new_bank].store(new_generation, std::memory_order_release);
            active_bank_.store(static_cast<u8>(new_bank), std::memory_order_release);
            active_generation_.store(new_generation, std::memory_order_release);
            // No old-bank mark can cross the generation publication: writers
            // that began earlier observed cutover and rolled back before this
            // claim succeeded; later writers cannot start until cutover opens.
            cutover_.store(0, std::memory_order_release);
            return true;
        }

        const ReloadTerminalRecord terminal{
            true, request_id, old_generation, new_generation, source, outcome};
        lock_terminal_publication();
        if (stopping_.load(std::memory_order_acquire) != 0) {
            if (reload_word_.load(std::memory_order_acquire) == completing)
                (void)terminalize_stopping(
                    {true, request_id, old_generation, 0, source, ReloadTerminalOutcome::Stopped},
                    completing);
            unlock_terminal_publication();
            return false;
        }
        auto terminal_slot = reserve_record_slot();
        if (!terminal_slot.valid) {
            u64 rollback = completing;
            (void)reload_word_.compare_exchange_strong(
                rollback, expected, std::memory_order_acq_rel, std::memory_order_acquire);
            unlock_terminal_publication();
            return false;
        }
        // Publish the terminal record before exposing Idle. A route requester
        // that sees Idle can therefore never be rejected merely because this
        // publisher still owns the terminal lock.
        const bool published = publish_claimed_record(terminal, terminal_slot);
        reload_word_.store(with_state(completing, ReloadAdmissionState::Idle),
                           std::memory_order_release);
        unlock_terminal_publication();
        return published;
    }

    // Process coordinator only. This is the activation terminal boundary: the
    // caller has observed every shard acknowledgement and verified that no
    // invocation/session pin still retains the predecessor generation.
    [[nodiscard]] bool finish_activation(u64 request_id) {
        u64 expected = reload_word_.load(std::memory_order_acquire);
        if (unpack_state(expected) != ReloadAdmissionState::Completing ||
            unpack_request_id(expected) != request_id)
            return false;
        const u32 current_bank = active_bank_.load(std::memory_order_acquire);
        const u32 retained_bank = current_bank ^ 1u;
        const u64 old_generation = bank_generation_[retained_bank].load(std::memory_order_acquire);
        const u64 new_generation = active_generation();
        if (old_generation == 0 || new_generation == 0) return false;

        const ReloadTerminalRecord terminal{true,
                                            request_id,
                                            old_generation,
                                            new_generation,
                                            unpack_source(expected),
                                            ReloadTerminalOutcome::Activated};
        if (activation_publication_.load(std::memory_order_acquire) != kPublicationClaimed ||
            !activation_terminal_slot_.valid)
            return false;
        auto terminal_slot = activation_terminal_slot_;
        terminal_slot.ticket = reserve_activation_record_ticket();
        cutover_.store(1, std::memory_order_release);
        u8 writer_open = 0;
        while (!override_writer_claim_.compare_exchange_weak(
            writer_open, 1, std::memory_order_acq_rel, std::memory_order_acquire))
            writer_open = 0;
        bank_generation_[retained_bank].store(0, std::memory_order_release);
        clear_bank(retained_bank);
        override_writer_claim_.store(0, std::memory_order_release);
        cutover_.store(0, std::memory_order_release);
        const auto terminal_state = stopping_.load(std::memory_order_acquire) != 0
                                        ? ReloadAdmissionState::Stopping
                                        : ReloadAdmissionState::Idle;
        const u64 idle = with_state(expected, terminal_state);
        if (!reload_word_.compare_exchange_strong(
                expected, idle, std::memory_order_release, std::memory_order_relaxed)) {
            cancel_claimed_record(terminal_slot);
            activation_terminal_slot_ = {};
            activation_publication_.store(kPublicationOpen, std::memory_order_release);
            return false;
        }
        const bool published = publish_claimed_record(terminal, terminal_slot);
        activation_terminal_slot_ = {};
        activation_publication_.store(kPublicationOpen, std::memory_order_release);
        return published;
    }

    // Prevent new admission. An accepted request receives exactly one Stopped
    // record unless activation already claimed its non-interruptible publication.
    void stop() {
        lock_terminal_publication(kTerminalPublicationStopClaimed);
        if (stopping_.load(std::memory_order_acquire) != 0) {
            unlock_terminal_publication();
            while (stopping_.load(std::memory_order_acquire) != 2) {
            }
            return;
        }

        // Close admission before publishing stopping_. A signal that reserved
        // an identity and claims the open word first is admitted and then
        // terminalized below; a signal that loses this CAS observes authority
        // closure and cannot manufacture Busy for an unoccupied Idle slot.
        u32 identity_open = kAdmissionOpen;
        while (!admission_identity_claim_.compare_exchange_weak(identity_open,
                                                                kAdmissionAuthorityClaimed,
                                                                std::memory_order_acq_rel,
                                                                std::memory_order_acquire)) {
            identity_open = kAdmissionOpen;
        }
        u8 open = 0;
        if (!stopping_.compare_exchange_strong(
                open, 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
            unlock_terminal_publication();
            while (stopping_.load(std::memory_order_acquire) != 2) {
            }
            return;
        }
        u8 publication = kPublicationOpen;
        (void)activation_publication_.compare_exchange_strong(
            publication, kPublicationStopped, std::memory_order_acq_rel, std::memory_order_acquire);
        u64 previous = reload_word_.load(std::memory_order_acquire);
        for (;;) {
            const auto previous_state = unpack_state(previous);
            if (previous_state == ReloadAdmissionState::Stopping) break;
            if (previous_state == ReloadAdmissionState::Completing &&
                activation_publication_.load(std::memory_order_acquire) == kPublicationClaimed) {
                // The activation owner has crossed the non-interruptible
                // publication boundary. It still owns generation publication
                // and the Activated terminal record; shutdown is complete only
                // after finish_activation() releases that claim.
                while (activation_publication_.load(std::memory_order_acquire) ==
                       kPublicationClaimed) {
                }
                previous = reload_word_.load(std::memory_order_acquire);
                continue;
            }
            const u64 stopped = with_state(previous, ReloadAdmissionState::Stopping);
            if (previous_state == ReloadAdmissionState::Pending ||
                previous_state == ReloadAdmissionState::InFlight ||
                previous_state == ReloadAdmissionState::Completing) {
                const u64 generation = active_generation();
                if (!terminalize_stopping({true,
                                           unpack_request_id(previous),
                                           generation,
                                           0,
                                           unpack_source(previous),
                                           ReloadTerminalOutcome::Stopped},
                                          previous)) {
                    previous = reload_word_.load(std::memory_order_acquire);
                    continue;
                }
            } else if (!reload_word_.compare_exchange_weak(previous,
                                                           stopped,
                                                           std::memory_order_acq_rel,
                                                           std::memory_order_acquire)) {
                continue;
            }
            break;
        }

        // stopping_ prevents a new writer from passing its post-claim check.
        // Claiming the active sequence after that store waits for any writer
        // that already passed its final shutdown check to publish or roll back,
        // so no successful mark can commit after stop() returns. Leave the
        // sequence odd as a permanent shutdown barrier; reset() reinitializes it.
        for (u32 bank = 0; bank < 2; bank++) {
            if (bank_generation_[bank].load(std::memory_order_acquire) == 0) continue;
            auto& sequence = override_seq_[bank];
            u64 stable = sequence.load(std::memory_order_acquire);
            for (;;) {
                if ((stable & 1u) != 0) {
                    stable = sequence.load(std::memory_order_acquire);
                    continue;
                }
                if (sequence.compare_exchange_weak(
                        stable, stable + 1, std::memory_order_acq_rel, std::memory_order_acquire))
                    break;
            }
        }
        // Busy publishers behind a request owner do not occupy the admission
        // claim, so wait for any publisher that crossed its terminal-owner
        // validation before declaring shutdown complete.
        stopped_signal_publishers_.fetch_or(kPublisherClosed, std::memory_order_acq_rel);
        while (unclaimed_busy_publishers_.load(std::memory_order_acquire) != 0 ||
               stopping_terminal_publishers_.load(std::memory_order_acquire) != 0 ||
               (stopped_signal_publishers_.load(std::memory_order_acquire) & kPublisherCountMask) !=
                   0) {
        }
        stopping_.store(2, std::memory_order_release);
        unlock_terminal_publication();
    }

    [[nodiscard]] bool mark(ServerIdentity server, bool healthy) {
        UpstreamMarkReplaySink event_sink = nullptr;
        void* event_context = nullptr;
        bool event_callback_claimed = false;
        const auto make_event =
            [&](bool accepted,
                UpstreamMarkReplayReason reason,
                u64 published_version = 0,
                u64 peer_config_generation = 0,
                u64 peer_published_version = 0) {
                event_sink = nullptr;
                event_context = nullptr;
                event_callback_claimed = false;
                for (u32 attempt = 0; attempt < kMaxMarkAttempts; attempt++) {
                    const u64 epoch = mark_replay_sink_epoch_.load(std::memory_order_acquire);
                    if ((epoch & 1u) != 0) continue;
                    mark_replay_callbacks_.fetch_add(1, std::memory_order_acq_rel);
                    if (epoch != mark_replay_sink_epoch_.load(std::memory_order_acquire)) {
                        mark_replay_callbacks_.fetch_sub(1, std::memory_order_release);
                        continue;
                    }
                    event_sink = mark_replay_sink_.load(std::memory_order_relaxed);
                    event_context = mark_replay_sink_context_.load(std::memory_order_relaxed);
                    if (epoch != mark_replay_sink_epoch_.load(std::memory_order_acquire)) {
                        mark_replay_callbacks_.fetch_sub(1, std::memory_order_release);
                        event_sink = nullptr;
                        event_context = nullptr;
                        continue;
                    }
                    event_callback_claimed = event_sink != nullptr;
                    if (!event_callback_claimed)
                        mark_replay_callbacks_.fetch_sub(1, std::memory_order_release);
                    break;
                }
                UpstreamMarkReplayEvent event{};
                event.event_sequence =
                    mark_replay_sequence_.fetch_add(1, std::memory_order_acq_rel) + 1;
                event.config_generation = server.config_generation;
                event.upstream_id = server.upstream_id;
                event.backend_id = server.backend_id;
                event.healthy = healthy;
                event.accepted = accepted;
                event.reason = reason;
                event.published_version = published_version;
                event.peer_config_generation = peer_config_generation;
                event.peer_published_version = peer_published_version;
                return event;
            };
        const auto publish_event = [&](const UpstreamMarkReplayEvent& event) {
            if (!event_callback_claimed || event_sink == nullptr) return;
            const void* previous_callback_owner = control_plane_mark_replay_callback_owner;
            const u32 previous_callback_depth = control_plane_mark_replay_callback_depth;
            control_plane_mark_replay_callback_owner = this;
            control_plane_mark_replay_callback_depth++;
            event_sink(event_context, event);
            control_plane_mark_replay_callback_owner = previous_callback_owner;
            control_plane_mark_replay_callback_depth = previous_callback_depth;
            mark_replay_callbacks_.fetch_sub(1, std::memory_order_release);
            event_callback_claimed = false;
        };
        if (stopping_.load(std::memory_order_acquire) != 0 ||
            cutover_.load(std::memory_order_acquire) != 0) {
            publish_event(make_event(false, UpstreamMarkReplayReason::Unavailable));
            return false;
        }
        if (server.config_generation == 0 || server.upstream_id >= RouteConfig::kMaxUpstreams ||
            server.backend_id >= UpstreamTarget::kMaxBackends) {
            publish_event(make_event(false, UpstreamMarkReplayReason::StaleOrForeign));
            return false;
        }
        const u64 generation = server.config_generation;
        u32 bank = 2;
        for (u32 candidate = 0; candidate < 2; candidate++)
            if (bank_generation_[candidate].load(std::memory_order_acquire) == generation &&
                is_member(candidate, server)) {
                bank = candidate;
                break;
            }
        if (bank == 2) {
            publish_event(make_event(false, UpstreamMarkReplayReason::StaleOrForeign));
            return false;
        }
        u8 writer_open = 0;
        bool writer_claimed = false;
        for (u32 attempt = 0; attempt < kMaxMarkAttempts; attempt++) {
            if (override_writer_claim_.compare_exchange_weak(
                    writer_open, 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
                writer_claimed = true;
                break;
            }
            writer_open = 0;
        }
        if (!writer_claimed) {
            publish_event(make_event(false, UpstreamMarkReplayReason::Contended));
            return false;
        }

        const auto value =
            healthy ? ManualHealthOverride::Healthy : ManualHealthOverride::Unhealthy;
        const u64 desired = pack_override(generation, value);
        const auto claim_sequence = [](std::atomic<u64>& sequence, u64* stable) {
            *stable = sequence.load(std::memory_order_acquire);
            for (u32 attempt = 0; attempt < kMaxMarkAttempts; attempt++) {
                if ((*stable & 1u) != 0) {
                    *stable = sequence.load(std::memory_order_acquire);
                    continue;
                }
                if (sequence.compare_exchange_weak(
                        *stable, *stable + 1, std::memory_order_acq_rel, std::memory_order_acquire))
                    return true;
            }
            return false;
        };

        auto& sequence = override_seq_[bank];
        u64 stable_seq = 0;
        if (!claim_sequence(sequence, &stable_seq)) {
            override_writer_claim_.store(0, std::memory_order_release);
            const auto reason = stopping_.load(std::memory_order_acquire) != 0 ||
                                        cutover_.load(std::memory_order_acquire) != 0
                                    ? UpstreamMarkReplayReason::Unavailable
                                    : UpstreamMarkReplayReason::Contended;
            publish_event(make_event(false, reason));
            return false;
        }

        u32 peer_upstream = 0;
        u32 peer_backend = 0;
        const bool has_peer = compatible_override_peer(
            bank, server.upstream_id, server.backend_id, &peer_upstream, &peer_backend);
        const u32 peer_bank = bank ^ 1u;
        const u64 peer_generation =
            has_peer ? bank_generation_[peer_bank].load(std::memory_order_acquire) : 0;
        u64 peer_stable_seq = 0;
        if (has_peer && !claim_sequence(override_seq_[peer_bank], &peer_stable_seq)) {
            sequence.store(stable_seq + 2, std::memory_order_release);
            override_writer_claim_.store(0, std::memory_order_release);
            const auto reason = stopping_.load(std::memory_order_acquire) != 0 ||
                                        cutover_.load(std::memory_order_acquire) != 0
                                    ? UpstreamMarkReplayReason::Unavailable
                                    : UpstreamMarkReplayReason::Contended;
            publish_event(make_event(false, reason, stable_seq + 2));
            return false;
        }

        auto& slot = overrides_[bank][server.upstream_id][server.backend_id];
        const u64 prior = slot.load(std::memory_order_relaxed);
        auto* peer_slot = has_peer ? &overrides_[peer_bank][peer_upstream][peer_backend] : nullptr;
        const u64 peer_prior =
            peer_slot == nullptr ? 0 : peer_slot->load(std::memory_order_relaxed);
        if (stopping_.load(std::memory_order_acquire) != 0 ||
            cutover_.load(std::memory_order_acquire) != 0 ||
            unpack_override_generation(prior) > generation ||
            bank_generation_[bank].load(std::memory_order_acquire) != generation ||
            (has_peer &&
             bank_generation_[peer_bank].load(std::memory_order_acquire) != peer_generation)) {
            if (has_peer)
                override_seq_[peer_bank].store(peer_stable_seq + 2, std::memory_order_release);
            sequence.store(stable_seq + 2, std::memory_order_release);
            override_writer_claim_.store(0, std::memory_order_release);
            publish_event(make_event(false,
                                     UpstreamMarkReplayReason::Unavailable,
                                     stable_seq + 2,
                                     has_peer ? peer_generation : 0,
                                     has_peer ? peer_stable_seq + 2 : 0));
            return false;
        }
        slot.store(desired, std::memory_order_relaxed);
        if (peer_slot != nullptr)
            peer_slot->store(pack_override(peer_generation, value), std::memory_order_relaxed);
        if (stopping_.load(std::memory_order_acquire) == 0 &&
            cutover_.load(std::memory_order_acquire) == 0 &&
            bank_generation_[bank].load(std::memory_order_acquire) == generation &&
            (!has_peer ||
             bank_generation_[peer_bank].load(std::memory_order_acquire) == peer_generation)) {
            const u64 prior_version = override_version_[bank].load(std::memory_order_relaxed);
            const u64 peer_prior_version =
                has_peer ? override_version_[peer_bank].load(std::memory_order_relaxed) : 0;
            if (prior_version >= kMaxOverrideVersion ||
                (has_peer && peer_prior_version >= kMaxOverrideVersion)) {
                slot.store(prior, std::memory_order_relaxed);
                if (peer_slot != nullptr) peer_slot->store(peer_prior, std::memory_order_relaxed);
                if (has_peer)
                    override_seq_[peer_bank].store(peer_stable_seq + 2, std::memory_order_release);
                sequence.store(stable_seq + 2, std::memory_order_release);
                override_writer_claim_.store(0, std::memory_order_release);
                publish_event(make_event(false,
                                         UpstreamMarkReplayReason::VersionExhausted,
                                         stable_seq + 2,
                                         has_peer ? peer_generation : 0,
                                         has_peer ? peer_stable_seq + 2 : 0));
                return false;
            }
            const u64 version = prior_version + 1;
            publish_committed_override(
                bank, server.upstream_id, server.backend_id, desired, version);
            override_version_[bank].store(version, std::memory_order_release);
            if (has_peer) {
                const u64 peer_version = peer_prior_version + 1;
                publish_committed_override(peer_bank,
                                           peer_upstream,
                                           peer_backend,
                                           pack_override(peer_generation, value),
                                           peer_version);
                override_version_[peer_bank].store(peer_version, std::memory_order_release);
                override_seq_[peer_bank].store(peer_stable_seq + 2, std::memory_order_release);
            }
            sequence.store(stable_seq + 2, std::memory_order_release);
            const auto success_event =
                make_event(true,
                           UpstreamMarkReplayReason::Published,
                           stable_seq + 2,
                           has_peer ? peer_generation : 0,
                           has_peer ? peer_stable_seq + 2 : 0);
            override_writer_claim_.store(0, std::memory_order_release);
            publish_event(success_event);
            return true;
        }
        // Readers ignore odd sequences while the prior value is restored. Use a
        // new stable sequence after the rollback: reusing stable_seq would let a
        // reader that straddled the writer validate the transient desired value.
        slot.store(prior, std::memory_order_relaxed);
        if (peer_slot != nullptr) {
            peer_slot->store(peer_prior, std::memory_order_relaxed);
            override_seq_[peer_bank].store(peer_stable_seq + 2, std::memory_order_release);
        }
        sequence.store(stable_seq + 2, std::memory_order_release);
        override_writer_claim_.store(0, std::memory_order_release);
        publish_event(make_event(false,
                                 UpstreamMarkReplayReason::Unavailable,
                                 stable_seq + 2,
                                 has_peer ? peer_generation : 0,
                                 has_peer ? peer_stable_seq + 2 : 0));
        return false;
    }

    [[nodiscard]] ManualHealthOverride manual_health(ServerIdentity server,
                                                     u64* override_version = nullptr) const {
        if (server.config_generation == 0 || server.upstream_id >= RouteConfig::kMaxUpstreams ||
            server.backend_id >= UpstreamTarget::kMaxBackends)
            return ManualHealthOverride::None;
        for (u32 bank = 0; bank < 2; bank++) {
            const u64 generation = bank_generation_[bank].load(std::memory_order_acquire);
            if (generation != server.config_generation || !is_member(bank, server)) continue;
            for (u32 attempt = 0; attempt < kMaxSnapshotAttempts; attempt++) {
                const u64 before = override_seq_[bank].load(std::memory_order_acquire);
                if ((before & 1u) != 0) {
                    // A process-wide writer may be updating an unrelated slot.
                    // Keep the last committed verdict readable instead of
                    // degrading a previously Unhealthy backend to None.
                    const u64 bank_version_before =
                        override_version_[bank].load(std::memory_order_acquire);
                    const u64 publication =
                        committed_override_publication_[bank][server.upstream_id][server.backend_id]
                            .load(std::memory_order_acquire);
                    const u64 bank_version_after =
                        override_version_[bank].load(std::memory_order_acquire);
                    const u64 after = override_seq_[bank].load(std::memory_order_acquire);
                    if (before != after || bank_version_before != bank_version_after) continue;
                    const u64 committed_version = unpack_committed_version(publication);
                    const u64 version = bank_version_after > committed_version ? bank_version_after
                                                                               : committed_version;
                    if (bank_generation_[bank].load(std::memory_order_acquire) != generation) break;
                    if (override_version != nullptr) *override_version = version;
                    return unpack_committed_override(publication);
                }
                const u64 packed = overrides_[bank][server.upstream_id][server.backend_id].load(
                    std::memory_order_relaxed);
                const u64 version = override_version_[bank].load(std::memory_order_relaxed);
                std::atomic_thread_fence(std::memory_order_acquire);
                const u64 after = override_seq_[bank].load(std::memory_order_relaxed);
                if (before != after) continue;
                if (bank_generation_[bank].load(std::memory_order_acquire) != generation) break;
                if (override_version != nullptr) *override_version = version;
                if (unpack_override_generation(packed) == generation)
                    return unpack_override(packed);
                return ManualHealthOverride::None;
            }
            // Bank-wide writers can invalidate every bounded seqlock attempt,
            // including when they touch unrelated backends. Verdict and its
            // own commit version share one atomic publication, so exhaustion
            // cannot pair a newer verdict with an older version.
            const u64 bank_version = override_version_[bank].load(std::memory_order_acquire);
            const u64 publication =
                committed_override_publication_[bank][server.upstream_id][server.backend_id].load(
                    std::memory_order_acquire);
            const u64 committed_version = unpack_committed_version(publication);
            if (bank_generation_[bank].load(std::memory_order_acquire) != generation) continue;
            if (override_version != nullptr)
                *override_version =
                    bank_version > committed_version ? bank_version : committed_version;
            return unpack_committed_override(publication);
        }
        return ManualHealthOverride::None;
    }

    [[nodiscard]] u64 generation_for_config(const RouteConfig* config) const {
        if (config == nullptr) return 0;
        for (u32 bank = 0; bank < 2; bank++)
            if (bank_config_[bank].load(std::memory_order_acquire) == config)
                return bank_generation_[bank].load(std::memory_order_acquire);
        return 0;
    }

    [[nodiscard]] u16 upstream_allocation_for_config(const RouteConfig* config,
                                                     u16 upstream_id) const {
        if (config == nullptr || upstream_id >= RouteConfig::kMaxUpstreams)
            return kInvalidAllocation;
        for (u32 bank = 0; bank < 2; bank++)
            if (bank_config_[bank].load(std::memory_order_acquire) == config &&
                upstream_id < upstream_count_[bank].load(std::memory_order_acquire))
                return upstream_allocation_[bank][upstream_id].load(std::memory_order_acquire);
        return kInvalidAllocation;
    }

    [[nodiscard]] u64 upstream_incarnation_for_config(const RouteConfig* config,
                                                      u16 upstream_id) const {
        if (config == nullptr || upstream_id >= RouteConfig::kMaxUpstreams) return 0;
        for (u32 bank = 0; bank < 2; bank++)
            if (bank_config_[bank].load(std::memory_order_acquire) == config &&
                upstream_id < upstream_count_[bank].load(std::memory_order_acquire))
                return upstream_incarnation_[bank][upstream_id].load(std::memory_order_acquire);
        return 0;
    }

    [[nodiscard]] u16 endpoint_allocation_for_config(const RouteConfig* config,
                                                     u16 upstream_id,
                                                     u32 backend_id) const {
        if (config == nullptr || upstream_id >= RouteConfig::kMaxUpstreams ||
            backend_id >= UpstreamTarget::kMaxBackends)
            return kInvalidAllocation;
        for (u32 bank = 0; bank < 2; bank++)
            if (bank_config_[bank].load(std::memory_order_acquire) == config &&
                upstream_id < upstream_count_[bank].load(std::memory_order_acquire) &&
                backend_id < backend_count_[bank][upstream_id].load(std::memory_order_acquire))
                return endpoint_allocation_[bank][upstream_id][backend_id].load(
                    std::memory_order_acquire);
        return kInvalidAllocation;
    }

    [[nodiscard]] u16 endpoint_probe_allocation_for_config(const RouteConfig* config,
                                                           u16 upstream_id,
                                                           u32 backend_id) const {
        if (config == nullptr || upstream_id >= RouteConfig::kMaxUpstreams ||
            backend_id >= UpstreamTarget::kMaxBackends)
            return kInvalidAllocation;
        for (u32 bank = 0; bank < 2; bank++)
            if (bank_config_[bank].load(std::memory_order_acquire) == config &&
                upstream_id < upstream_count_[bank].load(std::memory_order_acquire) &&
                backend_id < backend_count_[bank][upstream_id].load(std::memory_order_acquire))
                return endpoint_probe_allocation_[bank][upstream_id][backend_id].load(
                    std::memory_order_acquire);
        return kInvalidAllocation;
    }

    [[nodiscard]] u64 endpoint_incarnation_for_config(const RouteConfig* config,
                                                      u16 upstream_id,
                                                      u32 backend_id) const {
        if (config == nullptr || upstream_id >= RouteConfig::kMaxUpstreams ||
            backend_id >= UpstreamTarget::kMaxBackends)
            return 0;
        for (u32 bank = 0; bank < 2; bank++)
            if (bank_config_[bank].load(std::memory_order_acquire) == config &&
                upstream_id < upstream_count_[bank].load(std::memory_order_acquire) &&
                backend_id < backend_count_[bank][upstream_id].load(std::memory_order_acquire))
                return endpoint_incarnation_[bank][upstream_id][backend_id].load(
                    std::memory_order_acquire);
        return 0;
    }

    [[nodiscard]] u16 endpoint_health_seed_allocation_for_config(const RouteConfig* config,
                                                                 u16 upstream_id,
                                                                 u32 backend_id) const {
        if (config == nullptr || upstream_id >= RouteConfig::kMaxUpstreams ||
            backend_id >= UpstreamTarget::kMaxBackends)
            return kInvalidAllocation;
        for (u32 bank = 0; bank < 2; bank++)
            if (bank_config_[bank].load(std::memory_order_acquire) == config &&
                upstream_id < upstream_count_[bank].load(std::memory_order_acquire) &&
                backend_id < backend_count_[bank][upstream_id].load(std::memory_order_acquire))
                return endpoint_health_seed_allocation_[bank][upstream_id][backend_id].load(
                    std::memory_order_acquire);
        return kInvalidAllocation;
    }

    [[nodiscard]] u64 endpoint_health_seed_incarnation_for_config(const RouteConfig* config,
                                                                  u16 upstream_id,
                                                                  u32 backend_id) const {
        if (config == nullptr || upstream_id >= RouteConfig::kMaxUpstreams ||
            backend_id >= UpstreamTarget::kMaxBackends)
            return 0;
        for (u32 bank = 0; bank < 2; bank++)
            if (bank_config_[bank].load(std::memory_order_acquire) == config &&
                upstream_id < upstream_count_[bank].load(std::memory_order_acquire) &&
                backend_id < backend_count_[bank][upstream_id].load(std::memory_order_acquire))
                return endpoint_health_seed_incarnation_[bank][upstream_id][backend_id].load(
                    std::memory_order_acquire);
        return 0;
    }

    [[nodiscard]] bool manual_health_snapshot(u64 generation,
                                              u16 upstream_id,
                                              u32 backend_count,
                                              ManualHealthOverride* verdicts,
                                              u64* override_version = nullptr) const {
        if (verdicts == nullptr || upstream_id >= RouteConfig::kMaxUpstreams ||
            backend_count > UpstreamTarget::kMaxBackends)
            return false;
        for (u32 backend = 0; backend < backend_count; backend++)
            verdicts[backend] = ManualHealthOverride::None;
        if (generation == 0) {
            if (override_version != nullptr) *override_version = 0;
            return true;
        }
        for (u32 bank = 0; bank < 2; bank++) {
            if (bank_generation_[bank].load(std::memory_order_acquire) != generation) continue;
            if (upstream_id >= upstream_count_[bank].load(std::memory_order_acquire) ||
                backend_count > backend_count_[bank][upstream_id].load(std::memory_order_acquire))
                return false;
            for (u32 attempt = 0; attempt < kMaxSnapshotAttempts; attempt++) {
                const u64 before = override_seq_[bank].load(std::memory_order_acquire);
                if ((before & 1u) != 0) continue;
                for (u32 backend = 0; backend < backend_count; backend++) {
                    const u64 packed =
                        overrides_[bank][upstream_id][backend].load(std::memory_order_relaxed);
                    verdicts[backend] = unpack_override_generation(packed) == generation
                                            ? unpack_override(packed)
                                            : ManualHealthOverride::None;
                }
                const u64 version = override_version_[bank].load(std::memory_order_relaxed);
                std::atomic_thread_fence(std::memory_order_acquire);
                if (override_seq_[bank].load(std::memory_order_relaxed) != before) continue;
                if (bank_generation_[bank].load(std::memory_order_acquire) != generation)
                    return false;
                if (override_version != nullptr) *override_version = version;
                return true;
            }
            return false;
        }
        return false;
    }

    [[nodiscard]] ReloadTerminalRecord last_record() const {
        if (counter_exhaustion_state_.load(std::memory_order_acquire) == 2 &&
            published_record_.load(std::memory_order_acquire) ==
                counter_exhaustion_frontier_.load(std::memory_order_acquire))
            return {true,
                    kCounterExhaustedRequestId,
                    counter_exhaustion_generation_.load(std::memory_order_acquire),
                    0,
                    ReloadRequestSource::Signal,
                    ReloadTerminalOutcome::CounterExhausted};
        for (u32 attempt = 0; attempt < kMaxSnapshotAttempts; attempt++) {
            const u64 descriptor = published_record_.load(std::memory_order_acquire);
            if (descriptor == 0) return {};
            const u32 slot = static_cast<u32>(descriptor & kRecordSlotMask);
            const u64 ticket = descriptor >> kRecordSlotBits;
            const u64 before = record_seq_[slot].load(std::memory_order_acquire);
            if ((before & 1u) != 0) continue;
            ReloadTerminalRecord record{};
            record.request_id = record_request_id_[slot].load(std::memory_order_relaxed);
            record.old_generation = record_old_generation_[slot].load(std::memory_order_relaxed);
            record.new_generation = record_new_generation_[slot].load(std::memory_order_relaxed);
            record.source = static_cast<ReloadRequestSource>(
                record_source_[slot].load(std::memory_order_relaxed));
            record.outcome = static_cast<ReloadTerminalOutcome>(
                record_outcome_[slot].load(std::memory_order_relaxed));
            // Pair the writer's release publication with the first acquire and
            // keep every relaxed field read before the validating sequence load.
            std::atomic_thread_fence(std::memory_order_acquire);
            const u64 after = record_seq_[slot].load(std::memory_order_relaxed);
            if (before == after &&
                record_slot_ticket_[slot].load(std::memory_order_acquire) == ticket &&
                published_record_.load(std::memory_order_acquire) == descriptor) {
                record.valid = record.outcome != ReloadTerminalOutcome::None;
                if (record.valid) return record;
                break;
            }
        }

        // A continuously advancing descriptor can exhaust the exact snapshot
        // budget even though its previously published slots remain stable.
        // Fall back to the newest stable ticket no newer than the observed
        // publication frontier; unpublished future writers are excluded.
        const u64 published_ticket =
            published_record_.load(std::memory_order_acquire) >> kRecordSlotBits;
        ReloadTerminalRecord newest{};
        u64 newest_ticket = 0;
        for (u32 slot = 0; slot < kRecordSlotCount; slot++) {
            for (u32 attempt = 0; attempt < kMaxSnapshotAttempts; attempt++) {
                const u64 before = record_seq_[slot].load(std::memory_order_acquire);
                if ((before & 1u) != 0) continue;
                const u64 ticket = record_slot_ticket_[slot].load(std::memory_order_relaxed);
                ReloadTerminalRecord candidate{};
                candidate.request_id = record_request_id_[slot].load(std::memory_order_relaxed);
                candidate.old_generation =
                    record_old_generation_[slot].load(std::memory_order_relaxed);
                candidate.new_generation =
                    record_new_generation_[slot].load(std::memory_order_relaxed);
                candidate.source = static_cast<ReloadRequestSource>(
                    record_source_[slot].load(std::memory_order_relaxed));
                candidate.outcome = static_cast<ReloadTerminalOutcome>(
                    record_outcome_[slot].load(std::memory_order_relaxed));
                std::atomic_thread_fence(std::memory_order_acquire);
                if (before != record_seq_[slot].load(std::memory_order_relaxed)) continue;
                if (ticket > newest_ticket && ticket <= published_ticket &&
                    candidate.outcome != ReloadTerminalOutcome::None) {
                    candidate.valid = true;
                    newest = candidate;
                    newest_ticket = ticket;
                }
                break;
            }
        }
        return newest;
    }

    // Bounded history lookup keeps an accepted request's terminal result
    // accessible even when a later unadmitted signal becomes the latest event.
    [[nodiscard]] ReloadTerminalRecord record_for_request(u64 request_id) const {
        if (request_id == kCounterExhaustedRequestId &&
            counter_exhaustion_state_.load(std::memory_order_acquire) == 2)
            return {true,
                    request_id,
                    counter_exhaustion_generation_.load(std::memory_order_acquire),
                    0,
                    ReloadRequestSource::Signal,
                    ReloadTerminalOutcome::CounterExhausted};
        const u64 published_ticket =
            published_record_.load(std::memory_order_acquire) >> kRecordSlotBits;
        for (u32 slot = 0; slot < kRecordSlotCount; slot++) {
            for (u32 attempt = 0; attempt < kMaxSnapshotAttempts; attempt++) {
                const u64 before = record_seq_[slot].load(std::memory_order_acquire);
                if ((before & 1u) != 0) continue;
                const u64 ticket = record_slot_ticket_[slot].load(std::memory_order_relaxed);
                ReloadTerminalRecord record{};
                record.request_id = record_request_id_[slot].load(std::memory_order_relaxed);
                record.old_generation =
                    record_old_generation_[slot].load(std::memory_order_relaxed);
                record.new_generation =
                    record_new_generation_[slot].load(std::memory_order_relaxed);
                record.source = static_cast<ReloadRequestSource>(
                    record_source_[slot].load(std::memory_order_relaxed));
                record.outcome = static_cast<ReloadTerminalOutcome>(
                    record_outcome_[slot].load(std::memory_order_relaxed));
                const u64 observable_ticket =
                    record_observable_ticket_[slot].load(std::memory_order_relaxed);
                std::atomic_thread_fence(std::memory_order_acquire);
                const u64 after = record_seq_[slot].load(std::memory_order_relaxed);
                if (before != after) continue;
                if (ticket != 0 && (ticket <= published_ticket || observable_ticket == ticket) &&
                    record.request_id == request_id &&
                    record.outcome != ReloadTerminalOutcome::None) {
                    record.valid = true;
                    return record;
                }
                break;
            }
        }
        return {};
    }

private:
    friend struct ControlPlaneMutationPortTestAccess;

    static constexpr u32 kAdmissionStateMask = 0x3u;
    static constexpr u32 kAdmissionOpen = 0;
    static constexpr u32 kAdmissionAuthorityClaimed = 1;
    static constexpr u32 kAdmissionRequestClaimed = 2;
    // Busy publishers occupy the high counter bits independently of the low
    // admission-owner state. Joining and leaving are therefore single bounded
    // atomic operations even while the request owner releases its claim.
    static constexpr u32 kAdmissionBusyClaimBase = 4;
    static constexpr u8 kPublicationOpen = 0;
    static constexpr u8 kPublicationClaimed = 1;
    static constexpr u8 kPublicationStopped = 2;
    static constexpr u8 kTerminalPublicationOpen = 0;
    static constexpr u8 kTerminalPublicationClaimed = 1;
    static constexpr u8 kTerminalPublicationRequestClaimed = 2;
    static constexpr u8 kTerminalPublicationStopClaimed = 3;

    static constexpr u64 kStateMask = 0x7u;
    static constexpr u64 kSourceBit = 0x8u;
    static constexpr u64 kRouteEnabledBit = 0x10u;
    static constexpr u32 kRequestShift = 5;
    static constexpr u64 kOverrideMask = 0x3u;
    static constexpr u32 kOverrideGenerationShift = 2;
    static constexpr u64 kMaxOverrideVersion = (u64{1} << 62) - 1;
    // One slot per possible shard writer plus coordinator/stop headroom keeps
    // the bounded publication scan lossless at the supported 64-shard limit.
    static constexpr u32 kRecordSlotCount = 128;
    static constexpr u64 kRecordSlotMask = kRecordSlotCount - 1;
    static constexpr u32 kRecordSlotBits = 7;
    static constexpr u64 kCounterFieldMask = (u64{1} << 32) - 1;
    static constexpr u64 kMaxRecordTicket = kCounterFieldMask;

    static constexpr u64 pack_reload(ReloadAdmissionState state,
                                     u64 request_id,
                                     ReloadRequestSource source,
                                     bool route_enabled) {
        return (request_id << kRequestShift) | (route_enabled ? kRouteEnabledBit : 0) |
               (source == ReloadRequestSource::Signal ? kSourceBit : 0) | static_cast<u8>(state);
    }
    static constexpr ReloadAdmissionState unpack_state(u64 value) {
        return static_cast<ReloadAdmissionState>(value & kStateMask);
    }
    static constexpr ReloadRequestSource unpack_source(u64 value) {
        return (value & kSourceBit) != 0 ? ReloadRequestSource::Signal : ReloadRequestSource::Route;
    }
    static constexpr bool unpack_route_enabled(u64 value) {
        return (value & kRouteEnabledBit) != 0;
    }
    static constexpr u64 unpack_request_id(u64 value) { return value >> kRequestShift; }
    static constexpr u64 with_state(u64 value, ReloadAdmissionState state) {
        return (value & ~kStateMask) | static_cast<u8>(state);
    }
    static constexpr u64 with_route_enabled(u64 value, bool enabled) {
        return enabled ? value | kRouteEnabledBit : value & ~kRouteEnabledBit;
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
    static constexpr u64 pack_committed_publication(u64 version, ManualHealthOverride value) {
        return (version << 2) | static_cast<u8>(value);
    }
    static constexpr u64 unpack_committed_version(u64 publication) { return publication >> 2; }
    static constexpr ManualHealthOverride unpack_committed_override(u64 publication) {
        return static_cast<ManualHealthOverride>(publication & kOverrideMask);
    }
    static constexpr u64 pack_event_counters(u64 record_ticket, u64 request_id) {
        return (record_ticket << 32) | request_id;
    }
    static constexpr u64 unpack_counter_ticket(u64 value) { return value >> 32; }
    static constexpr u64 unpack_counter_request(u64 value) { return value & kCounterFieldMask; }

    void publish_committed_override(u32 bank, u32 upstream, u32 backend, u64 packed, u64 version) {
        auto& descriptor = committed_override_descriptor_[bank][upstream][backend];
        const u64 active = descriptor.load(std::memory_order_relaxed) & 1u;
        const u64 next = active ^ 1u;
        committed_overrides_[bank][upstream][backend][next].store(packed,
                                                                  std::memory_order_relaxed);
        committed_override_versions_[bank][upstream][backend][next].store(
            version, std::memory_order_relaxed);
        descriptor.store((version << 1) | next, std::memory_order_release);
        committed_override_publication_[bank][upstream][backend].store(
            pack_committed_publication(version, unpack_override(packed)),
            std::memory_order_release);
    }

    [[nodiscard]] u64 committed_override(
        u32 bank, u32 upstream, u32 backend, u64* version, u64 maximum_version = ~u64{0}) const {
        const auto& descriptor = committed_override_descriptor_[bank][upstream][backend];
        for (u32 attempt = 0; attempt < kMaxSnapshotAttempts; attempt++) {
            const u64 before = descriptor.load(std::memory_order_acquire);
            u64 slot = before & 1u;
            u64 selected_version = before >> 1;
            if (selected_version > maximum_version) {
                slot ^= 1u;
                selected_version = committed_override_versions_[bank][upstream][backend][slot].load(
                    std::memory_order_relaxed);
                if (selected_version > maximum_version) continue;
            }
            const u64 packed =
                committed_overrides_[bank][upstream][backend][slot].load(std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_acquire);
            if (descriptor.load(std::memory_order_relaxed) != before) continue;
            if (version != nullptr) *version = selected_version;
            return packed;
        }
        if (version != nullptr) *version = 0;
        return 0;
    }

    void clear_bank(u32 bank) {
        bank_config_[bank].store(nullptr, std::memory_order_relaxed);
        override_seq_[bank].store(0, std::memory_order_relaxed);
        override_version_[bank].store(0, std::memory_order_relaxed);
        upstream_count_[bank].store(0, std::memory_order_relaxed);
        for (u32 upstream = 0; upstream < RouteConfig::kMaxUpstreams; upstream++) {
            upstream_allocation_[bank][upstream].store(kInvalidAllocation,
                                                       std::memory_order_relaxed);
            upstream_incarnation_[bank][upstream].store(0, std::memory_order_relaxed);
            membership_[bank][upstream] = {};
            backend_count_[bank][upstream].store(0, std::memory_order_relaxed);
            for (auto& backend : overrides_[bank][upstream])
                backend.store(0, std::memory_order_relaxed);
            for (u32 backend = 0; backend < UpstreamTarget::kMaxBackends; backend++) {
                override_peer_upstream_[bank][upstream][backend] = 0xff;
                override_peer_backend_[bank][upstream][backend] = 0xff;
                endpoint_allocation_[bank][upstream][backend].store(kInvalidAllocation,
                                                                    std::memory_order_relaxed);
                endpoint_probe_allocation_[bank][upstream][backend].store(
                    kInvalidAllocation, std::memory_order_relaxed);
                endpoint_incarnation_[bank][upstream][backend].store(0, std::memory_order_relaxed);
                endpoint_health_seed_allocation_[bank][upstream][backend].store(
                    kInvalidAllocation, std::memory_order_relaxed);
                endpoint_health_seed_incarnation_[bank][upstream][backend].store(
                    0, std::memory_order_relaxed);
                committed_override_descriptor_[bank][upstream][backend].store(
                    0, std::memory_order_relaxed);
                for (auto& snapshot : committed_overrides_[bank][upstream][backend])
                    snapshot.store(0, std::memory_order_relaxed);
                for (auto& version : committed_override_versions_[bank][upstream][backend])
                    version.store(0, std::memory_order_relaxed);
                committed_override_publication_[bank][upstream][backend].store(
                    0, std::memory_order_relaxed);
            }
        }
    }

    void configure_membership(u32 bank, const RouteConfig* config) {
        const u32 count = config == nullptr ? 0
                                            : (config->upstream_count < RouteConfig::kMaxUpstreams
                                                   ? config->upstream_count
                                                   : RouteConfig::kMaxUpstreams);
        for (u32 upstream = 0; upstream < RouteConfig::kMaxUpstreams; upstream++) {
            u32 backends = 0;
            if (upstream < count) {
                membership_[bank][upstream] = config->upstreams[upstream];
                backends = config->upstreams[upstream].addr_count;
                if (backends > UpstreamTarget::kMaxBackends)
                    backends = UpstreamTarget::kMaxBackends;
                membership_[bank][upstream].addr_count = static_cast<u8>(backends);
            }
            backend_count_[bank][upstream].store(static_cast<u8>(backends),
                                                 std::memory_order_relaxed);
        }
        upstream_count_[bank].store(static_cast<u8>(count), std::memory_order_release);
    }

    [[nodiscard]] static u64 allocate_endpoint_incarnation() {
        u64 incarnation = next_endpoint_incarnation_.fetch_add(1, std::memory_order_relaxed);
        if (incarnation == 0)
            incarnation = next_endpoint_incarnation_.fetch_add(1, std::memory_order_relaxed);
        return incarnation;
    }

    [[nodiscard]] static u64 allocate_upstream_incarnation() {
        u64 incarnation = next_upstream_incarnation_.fetch_add(1, std::memory_order_relaxed);
        if (incarnation == 0)
            incarnation = next_upstream_incarnation_.fetch_add(1, std::memory_order_relaxed);
        return incarnation;
    }

    void initialize_allocations(u32 bank) {
        const u32 upstreams = upstream_count_[bank].load(std::memory_order_relaxed);
        for (u32 upstream = 0; upstream < upstreams; upstream++) {
            upstream_allocation_[bank][upstream].store(static_cast<u16>(upstream),
                                                       std::memory_order_relaxed);
            upstream_incarnation_[bank][upstream].store(allocate_upstream_incarnation(),
                                                        std::memory_order_relaxed);
            const u32 backends = backend_count_[bank][upstream].load(std::memory_order_relaxed);
            for (u32 backend = 0; backend < backends; backend++) {
                endpoint_allocation_[bank][upstream][backend].store(
                    static_cast<u16>(upstream * UpstreamTarget::kMaxBackends + backend),
                    std::memory_order_relaxed);
                endpoint_probe_allocation_[bank][upstream][backend].store(
                    static_cast<u16>(upstream * UpstreamTarget::kMaxBackends + backend),
                    std::memory_order_relaxed);
                endpoint_incarnation_[bank][upstream][backend].store(
                    allocate_endpoint_incarnation(), std::memory_order_relaxed);
            }
        }
    }

    [[nodiscard]] static bool compatible_target(const UpstreamTarget& old_target,
                                                const UpstreamTarget& new_target) {
        // Manual overrides belong to the named upstream endpoint, independent
        // of active-probe scheduling and response policy. Probe state performs
        // its own stricter compatibility transition in callbacks.cc.
        return old_target.name_identity != 0 &&
               old_target.name_identity == new_target.name_identity;
    }

    [[nodiscard]] static bool same_endpoint(const sockaddr_in& old_endpoint,
                                            const sockaddr_in& new_endpoint) {
        return old_endpoint.sin_family == new_endpoint.sin_family &&
               old_endpoint.sin_addr.s_addr == new_endpoint.sin_addr.s_addr &&
               old_endpoint.sin_port == new_endpoint.sin_port;
    }

    [[nodiscard]] static bool compatible_health_policy(const UpstreamTarget& old_target,
                                                       const UpstreamTarget& new_target) {
        if (old_target.marking_policy_identity != new_target.marking_policy_identity) return false;
        if (old_target.hc_enabled != new_target.hc_enabled) return false;
        if (!old_target.hc_enabled) return true;
        return old_target.hc_path_len == new_target.hc_path_len &&
               old_target.hc_interval_ms == new_target.hc_interval_ms &&
               old_target.hc_expected_status == new_target.hc_expected_status &&
               __builtin_memcmp(old_target.hc_path, new_target.hc_path, old_target.hc_path_len) ==
                   0;
    }

    [[nodiscard]] bool compatible_override_peer(
        u32 bank, u16 upstream, u16 backend, u32* peer_upstream, u32* peer_backend) const {
        if (peer_upstream == nullptr || peer_backend == nullptr || bank >= 2 ||
            upstream >= RouteConfig::kMaxUpstreams || backend >= UpstreamTarget::kMaxBackends)
            return false;
        const u32 peer_bank = bank ^ 1u;
        if (bank_generation_[peer_bank].load(std::memory_order_acquire) == 0) return false;
        const u8 mapped_upstream = override_peer_upstream_[bank][upstream][backend];
        const u8 mapped_backend = override_peer_backend_[bank][upstream][backend];
        if (mapped_upstream >= RouteConfig::kMaxUpstreams ||
            mapped_backend >= UpstreamTarget::kMaxBackends ||
            mapped_upstream >= upstream_count_[peer_bank].load(std::memory_order_acquire) ||
            mapped_backend >=
                backend_count_[peer_bank][mapped_upstream].load(std::memory_order_acquire))
            return false;
        *peer_upstream = mapped_upstream;
        *peer_backend = mapped_backend;
        return true;
    }

    [[nodiscard]] static u32 matching_endpoint_count(const UpstreamTarget& old_target,
                                                     const UpstreamTarget& new_target) {
        bool matched_old_backend[UpstreamTarget::kMaxBackends]{};
        u32 matches = 0;
        for (u32 backend = 0; backend < new_target.addr_count; backend++) {
            for (u32 candidate = 0; candidate < old_target.addr_count; candidate++) {
                if (matched_old_backend[candidate] ||
                    !same_endpoint(old_target.addrs[candidate], new_target.addrs[backend]))
                    continue;
                matched_old_backend[candidate] = true;
                matches++;
                break;
            }
        }
        return matches;
    }

    static void match_compatible_upstreams(const UpstreamTarget* old_targets,
                                           u32 old_count,
                                           const UpstreamTarget* new_targets,
                                           u32 new_count,
                                           u32* old_for_new) {
        const u32 count = old_count > new_count ? old_count : new_count;
        i32 row_potential[RouteConfig::kMaxUpstreams + 1]{};
        i32 col_potential[RouteConfig::kMaxUpstreams + 1]{};
        u32 assigned_row[RouteConfig::kMaxUpstreams + 1]{};
        u32 predecessor[RouteConfig::kMaxUpstreams + 1]{};
        for (u32 row = 0; row < new_count; row++) old_for_new[row] = old_count;

        // Fixed-capacity Hungarian assignment. Endpoint overlap dominates the
        // compatible-pair tie breaker, yielding a global one-to-one maximum
        // rather than consuming predecessors greedily in target order.
        for (u32 row = 1; row <= count; row++) {
            assigned_row[0] = row;
            i32 minimum[RouteConfig::kMaxUpstreams + 1]{};
            bool used[RouteConfig::kMaxUpstreams + 1]{};
            for (u32 col = 1; col <= count; col++) minimum[col] = 0x3fffffff;
            u32 col = 0;
            do {
                used[col] = true;
                const u32 active_row = assigned_row[col];
                i32 delta = 0x3fffffff;
                u32 next_col = 0;
                for (u32 candidate = 1; candidate <= count; candidate++) {
                    if (used[candidate]) continue;
                    u32 score = 0;
                    if (active_row <= new_count && candidate <= old_count &&
                        compatible_target(old_targets[candidate - 1],
                                          new_targets[active_row - 1])) {
                        score = matching_endpoint_count(old_targets[candidate - 1],
                                                        new_targets[active_row - 1]) *
                                    (RouteConfig::kMaxUpstreams + 1) +
                                1;
                    }
                    const i32 reduced = -static_cast<i32>(score) - row_potential[active_row] -
                                        col_potential[candidate];
                    if (reduced < minimum[candidate]) {
                        minimum[candidate] = reduced;
                        predecessor[candidate] = col;
                    }
                    if (minimum[candidate] < delta) {
                        delta = minimum[candidate];
                        next_col = candidate;
                    }
                }
                for (u32 candidate = 0; candidate <= count; candidate++) {
                    if (used[candidate]) {
                        row_potential[assigned_row[candidate]] += delta;
                        col_potential[candidate] -= delta;
                    } else if (candidate != 0) {
                        minimum[candidate] -= delta;
                    }
                }
                col = next_col;
            } while (assigned_row[col] != 0);
            do {
                const u32 prior = predecessor[col];
                assigned_row[col] = assigned_row[prior];
                col = prior;
            } while (col != 0);
        }

        for (u32 col = 1; col <= old_count; col++) {
            const u32 row = assigned_row[col];
            if (row == 0 || row > new_count ||
                !compatible_target(old_targets[col - 1], new_targets[row - 1]))
                continue;
            old_for_new[row - 1] = col - 1;
        }
    }

    void carry_compatible_overrides(u32 old_bank,
                                    u32 new_bank,
                                    u64 old_generation,
                                    u64 new_generation) {
        const u32 upstreams = upstream_count_[new_bank].load(std::memory_order_relaxed);
        const u32 old_upstreams = upstream_count_[old_bank].load(std::memory_order_relaxed);
        u32 old_for_new[RouteConfig::kMaxUpstreams]{};
        match_compatible_upstreams(
            membership_[old_bank], old_upstreams, membership_[new_bank], upstreams, old_for_new);
        bool used_upstream[kMaxUpstreamAllocations]{};
        bool used_endpoint[kMaxEndpointAllocations]{};
        bool used_probe[kMaxEndpointAllocations]{};
        for (u32 upstream = 0; upstream < old_upstreams; upstream++) {
            const u16 allocation =
                upstream_allocation_[old_bank][upstream].load(std::memory_order_relaxed);
            if (allocation < kMaxUpstreamAllocations) used_upstream[allocation] = true;
            const u32 backends = backend_count_[old_bank][upstream].load(std::memory_order_relaxed);
            for (u32 backend = 0; backend < backends; backend++) {
                const u16 endpoint = endpoint_allocation_[old_bank][upstream][backend].load(
                    std::memory_order_relaxed);
                if (endpoint < kMaxEndpointAllocations) used_endpoint[endpoint] = true;
                const u16 probe = endpoint_probe_allocation_[old_bank][upstream][backend].load(
                    std::memory_order_relaxed);
                if (probe < kMaxEndpointAllocations) used_probe[probe] = true;
            }
        }
        u16 next_upstream = 0;
        u16 next_endpoint = 0;
        u16 next_probe = 0;
        bool carried = false;
        for (u32 upstream = 0; upstream < upstreams; upstream++) {
            const auto& new_target = membership_[new_bank][upstream];
            const u32 old_upstream = old_for_new[upstream];
            if (old_upstream != old_upstreams) {
                upstream_allocation_[new_bank][upstream].store(
                    upstream_allocation_[old_bank][old_upstream].load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
                upstream_incarnation_[new_bank][upstream].store(
                    upstream_incarnation_[old_bank][old_upstream].load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
            } else {
                while (next_upstream < kMaxUpstreamAllocations && used_upstream[next_upstream])
                    next_upstream++;
                upstream_allocation_[new_bank][upstream].store(next_upstream,
                                                               std::memory_order_relaxed);
                upstream_incarnation_[new_bank][upstream].store(allocate_upstream_incarnation(),
                                                                std::memory_order_relaxed);
                if (next_upstream < kMaxUpstreamAllocations) used_upstream[next_upstream++] = true;
            }
            if (old_upstream == old_upstreams) {
                for (u32 backend = 0; backend < new_target.addr_count; backend++) {
                    while (next_endpoint < kMaxEndpointAllocations && used_endpoint[next_endpoint])
                        next_endpoint++;
                    endpoint_allocation_[new_bank][upstream][backend].store(
                        next_endpoint, std::memory_order_relaxed);
                    while (next_probe < kMaxEndpointAllocations && used_probe[next_probe])
                        next_probe++;
                    endpoint_probe_allocation_[new_bank][upstream][backend].store(
                        next_probe, std::memory_order_relaxed);
                    endpoint_incarnation_[new_bank][upstream][backend].store(
                        allocate_endpoint_incarnation(), std::memory_order_relaxed);
                    if (next_endpoint < kMaxEndpointAllocations)
                        used_endpoint[next_endpoint++] = true;
                    if (next_probe < kMaxEndpointAllocations) used_probe[next_probe++] = true;
                }
                continue;
            }
            const auto& old_target = membership_[old_bank][old_upstream];
            bool matched_old_backend[UpstreamTarget::kMaxBackends]{};
            const u32 backends = backend_count_[new_bank][upstream].load(std::memory_order_relaxed);
            for (u32 backend = 0; backend < backends; backend++) {
                u32 old_backend = old_target.addr_count;
                for (u32 candidate = 0; candidate < old_target.addr_count; candidate++) {
                    if (!matched_old_backend[candidate] &&
                        same_endpoint(old_target.addrs[candidate], new_target.addrs[backend])) {
                        old_backend = candidate;
                        break;
                    }
                }
                if (old_backend == old_target.addr_count) {
                    while (next_endpoint < kMaxEndpointAllocations && used_endpoint[next_endpoint])
                        next_endpoint++;
                    endpoint_allocation_[new_bank][upstream][backend].store(
                        next_endpoint, std::memory_order_relaxed);
                    while (next_probe < kMaxEndpointAllocations && used_probe[next_probe])
                        next_probe++;
                    endpoint_probe_allocation_[new_bank][upstream][backend].store(
                        next_probe, std::memory_order_relaxed);
                    endpoint_incarnation_[new_bank][upstream][backend].store(
                        allocate_endpoint_incarnation(), std::memory_order_relaxed);
                    if (next_endpoint < kMaxEndpointAllocations)
                        used_endpoint[next_endpoint++] = true;
                    if (next_probe < kMaxEndpointAllocations) used_probe[next_probe++] = true;
                    continue;
                }
                matched_old_backend[old_backend] = true;
                endpoint_probe_allocation_[new_bank][upstream][backend].store(
                    endpoint_probe_allocation_[old_bank][old_upstream][old_backend].load(
                        std::memory_order_relaxed),
                    std::memory_order_relaxed);
                override_peer_upstream_[new_bank][upstream][backend] =
                    static_cast<u8>(old_upstream);
                override_peer_backend_[new_bank][upstream][backend] = static_cast<u8>(old_backend);
                override_peer_upstream_[old_bank][old_upstream][old_backend] =
                    static_cast<u8>(upstream);
                override_peer_backend_[old_bank][old_upstream][old_backend] =
                    static_cast<u8>(backend);
                if (compatible_health_policy(old_target, new_target)) {
                    endpoint_allocation_[new_bank][upstream][backend].store(
                        endpoint_allocation_[old_bank][old_upstream][old_backend].load(
                            std::memory_order_relaxed),
                        std::memory_order_relaxed);
                    endpoint_incarnation_[new_bank][upstream][backend].store(
                        endpoint_incarnation_[old_bank][old_upstream][old_backend].load(
                            std::memory_order_relaxed),
                        std::memory_order_relaxed);
                } else {
                    endpoint_health_seed_allocation_[new_bank][upstream][backend].store(
                        endpoint_allocation_[old_bank][old_upstream][old_backend].load(
                            std::memory_order_relaxed),
                        std::memory_order_relaxed);
                    endpoint_health_seed_incarnation_[new_bank][upstream][backend].store(
                        endpoint_incarnation_[old_bank][old_upstream][old_backend].load(
                            std::memory_order_relaxed),
                        std::memory_order_relaxed);
                    while (next_endpoint < kMaxEndpointAllocations && used_endpoint[next_endpoint])
                        next_endpoint++;
                    endpoint_allocation_[new_bank][upstream][backend].store(
                        next_endpoint, std::memory_order_relaxed);
                    endpoint_incarnation_[new_bank][upstream][backend].store(
                        allocate_endpoint_incarnation(), std::memory_order_relaxed);
                    if (next_endpoint < kMaxEndpointAllocations)
                        used_endpoint[next_endpoint++] = true;
                }
                const u64 old_value =
                    committed_override(old_bank, old_upstream, old_backend, nullptr);
                if (unpack_override_generation(old_value) != old_generation ||
                    unpack_override(old_value) == ManualHealthOverride::None)
                    continue;
                overrides_[new_bank][upstream][backend].store(
                    pack_override(new_generation, unpack_override(old_value)),
                    std::memory_order_relaxed);
                publish_committed_override(
                    new_bank,
                    upstream,
                    backend,
                    pack_override(new_generation, unpack_override(old_value)),
                    1);
                carried = true;
            }
        }
        if (carried) {
            override_version_[new_bank].store(1, std::memory_order_relaxed);
            override_seq_[new_bank].store(2, std::memory_order_relaxed);
        }
    }

    [[nodiscard]] bool is_member(u32 bank, ServerIdentity server) const {
        if (bank >= 2 || server.upstream_id >= RouteConfig::kMaxUpstreams ||
            server.backend_id >= UpstreamTarget::kMaxBackends)
            return false;
        const u32 upstreams = upstream_count_[bank].load(std::memory_order_acquire);
        return server.upstream_id < upstreams &&
               server.backend_id <
                   backend_count_[bank][server.upstream_id].load(std::memory_order_acquire);
    }

    [[nodiscard]] u64 reserve_request_identity(ClaimedRecordSlot* record_slot) {
        if (record_slot == nullptr) return 0;
        u64 current = event_counters_.load(std::memory_order_acquire);
        for (u32 attempt = 0; attempt < kMaxCounterAllocationAttempts; attempt++) {
            const u64 request_id = unpack_counter_request(current);
            const u64 ticket = unpack_counter_ticket(current);
            if (request_id >= kMaxRequestId || ticket >= kMaxRecordTicket - 1) return 0;
            const ClaimedRecordSlot claimed = claim_record_slot(ticket + 1);
            if (!claimed.valid) {
                // Slot pressure is transient, but admission is non-suspending:
                // each failed probe consumes the bounded allocation budget.
                current = event_counters_.load(std::memory_order_acquire);
                continue;
            }
            const u64 desired = pack_event_counters(ticket + 1, request_id + 1);
            if (event_counters_.compare_exchange_weak(
                    current, desired, std::memory_order_acq_rel, std::memory_order_acquire)) {
                *record_slot = claimed;
                return request_id + 1;
            }
            release_record_slot(claimed);
        }
        return 0;
    }

    [[nodiscard]] bool claim_reserved_request_identity(u64 request_id,
                                                       ReloadRequestSource source,
                                                       u64* returned_request_id,
                                                       const ClaimedRecordSlot& identity_slot) {
        u32 identity_open = kAdmissionOpen;
        if (admission_identity_claim_.compare_exchange_strong(identity_open,
                                                              kAdmissionRequestClaimed,
                                                              std::memory_order_acq_rel,
                                                              std::memory_order_acquire))
            return true;
        ReloadTerminalRecord abandoned{};
        if (source == ReloadRequestSource::Signal) {
            abandoned = {true,
                         request_id,
                         active_generation(),
                         0,
                         ReloadRequestSource::Signal,
                         ReloadTerminalOutcome::Busy};
            if (returned_request_id != nullptr) *returned_request_id = request_id;
        } else {
            u64 expected = pack_event_counters(identity_slot.ticket, request_id);
            const u64 desired = pack_event_counters(identity_slot.ticket - 1, request_id - 1);
            if (event_counters_.compare_exchange_strong(
                    expected, desired, std::memory_order_acq_rel, std::memory_order_acquire)) {
                release_record_slot(identity_slot);
                return false;
            }
        }
        (void)publish_claimed_record(abandoned, identity_slot);
        return false;
    }

    // An authority update owns the Idle admission boundary but does not
    // represent a reload request. Preserve a contending SIGHUP as an explicit
    // terminal outcome instead of exhausting bounded retries with request ID 0.
    [[nodiscard]] bool publish_authority_contended_signal(u64* returned_request_id) {
        if (admission_identity_claim_.load(std::memory_order_acquire) !=
                kAdmissionAuthorityClaimed ||
            stopping_.load(std::memory_order_acquire) != 0 ||
            unpack_state(reload_word_.load(std::memory_order_acquire)) !=
                ReloadAdmissionState::Idle)
            return false;
        const u64 generation = active_generation();
        u64 request_id = 0;
        ClaimedRecordSlot slot{};
        if (!allocate_busy_identity(0, &request_id, &slot)) {
            if (!terminalize_counter_exhaustion(returned_request_id) &&
                returned_request_id != nullptr)
                *returned_request_id = 0;
            return false;
        }
        return publish_authority_contended_signal_record(
            generation, request_id, slot, returned_request_id);
    }

    [[nodiscard]] bool publish_stopped_signal(u64* returned_request_id) {
        u32 publishers = stopped_signal_publishers_.load(std::memory_order_acquire);
        bool tracked = false;
        for (;;) {
            if ((publishers & kPublisherClosed) != 0) {
                // stop() already closed and drained the pre-return publisher
                // set. Publish this later observation only after that boundary.
                while (stopping_.load(std::memory_order_acquire) != 2) {
                }
                break;
            }
            if (stopped_signal_publishers_.compare_exchange_weak(publishers,
                                                                 publishers + 1,
                                                                 std::memory_order_acq_rel,
                                                                 std::memory_order_acquire)) {
                tracked = true;
                break;
            }
        }
        u64 request_id = 0;
        ClaimedRecordSlot slot{};
        if (!allocate_busy_identity(0, &request_id, &slot)) {
            if (!terminalize_counter_exhaustion(returned_request_id) &&
                returned_request_id != nullptr)
                *returned_request_id = 0;
            if (tracked) stopped_signal_publishers_.fetch_sub(1, std::memory_order_acq_rel);
            return false;
        }
        const bool published = publish_claimed_record({true,
                                                       request_id,
                                                       active_generation(),
                                                       0,
                                                       ReloadRequestSource::Signal,
                                                       ReloadTerminalOutcome::Stopped},
                                                      slot);
        if (published && returned_request_id != nullptr) *returned_request_id = request_id;
        if (tracked) stopped_signal_publishers_.fetch_sub(1, std::memory_order_acq_rel);
        return published;
    }

    [[nodiscard]] bool publish_authority_contended_signal_record(u64 generation,
                                                                 u64 request_id,
                                                                 const ClaimedRecordSlot& slot,
                                                                 u64* returned_request_id) {
        // Identity allocation can deschedule after the first authority check.
        // Revalidate at the record's publication point so a completed authority
        // update or newly admitted request cannot be ordered before a stale
        // AdmissionContended result.
        if (admission_identity_claim_.load(std::memory_order_acquire) !=
                kAdmissionAuthorityClaimed ||
            stopping_.load(std::memory_order_acquire) != 0 ||
            unpack_state(reload_word_.load(std::memory_order_acquire)) !=
                ReloadAdmissionState::Idle) {
            const auto outcome = stopping_.load(std::memory_order_acquire) != 0
                                     ? ReloadTerminalOutcome::Stopped
                                     : ReloadTerminalOutcome::AdmissionContended;
            const bool published = publish_claimed_record(
                {true, request_id, generation, 0, ReloadRequestSource::Signal, outcome}, slot);
            if (published && returned_request_id != nullptr) *returned_request_id = request_id;
            return published;
        }
        const bool published = publish_claimed_record({true,
                                                       request_id,
                                                       generation,
                                                       0,
                                                       ReloadRequestSource::Signal,
                                                       ReloadTerminalOutcome::AdmissionContended},
                                                      slot);
        if (published && returned_request_id != nullptr) *returned_request_id = request_id;
        return published;
    }

    // A signal that observes an Idle slot must arbitrate directly with a
    // terminal owner that has not yet closed admission. Reserving the identity
    // first preserves request ordering; the claim CAS then decides whether the
    // signal precedes shutdown/authority closure or follows a real occupant.
    [[nodiscard]] bool admit_contended_idle_signal(u64* returned_request_id) {
        const u64 busy_generation = active_generation();
        ClaimedRecordSlot identity_slot{};
        const u64 request_id = reserve_request_identity(&identity_slot);
        if (request_id == 0) {
            if (!terminalize_counter_exhaustion(returned_request_id) &&
                returned_request_id != nullptr)
                *returned_request_id = 0;
            return false;
        }

        u32 claim = kAdmissionOpen;
        if (!admission_identity_claim_.compare_exchange_strong(claim,
                                                               kAdmissionRequestClaimed,
                                                               std::memory_order_acq_rel,
                                                               std::memory_order_acquire)) {
            if (is_admission_request_claim(claim) || is_admission_busy_claim(claim)) {
                const bool published = publish_claimed_record({true,
                                                               request_id,
                                                               busy_generation,
                                                               0,
                                                               ReloadRequestSource::Signal,
                                                               ReloadTerminalOutcome::Busy},
                                                              identity_slot);
                if (published && returned_request_id != nullptr) *returned_request_id = request_id;
                return false;
            }

            const auto outcome = stopping_.load(std::memory_order_acquire) != 0
                                     ? ReloadTerminalOutcome::Stopped
                                     : ReloadTerminalOutcome::AdmissionContended;
            const bool published = publish_claimed_record(
                {true, request_id, busy_generation, 0, ReloadRequestSource::Signal, outcome},
                identity_slot);
            if (published && returned_request_id != nullptr) *returned_request_id = request_id;
            return false;
        }

        u64 observed = reload_word_.load(std::memory_order_acquire);
        if (stopping_.load(std::memory_order_acquire) != 0 ||
            unpack_state(observed) == ReloadAdmissionState::Stopping) {
            const bool published = publish_claimed_record({true,
                                                           request_id,
                                                           busy_generation,
                                                           0,
                                                           ReloadRequestSource::Signal,
                                                           ReloadTerminalOutcome::Stopped},
                                                          identity_slot);
            release_request_identity_claim();
            if (published && returned_request_id != nullptr) *returned_request_id = request_id;
            return false;
        }
        if (unpack_state(observed) != ReloadAdmissionState::Idle) {
            const bool published = publish_claimed_record({true,
                                                           request_id,
                                                           busy_generation,
                                                           0,
                                                           ReloadRequestSource::Signal,
                                                           ReloadTerminalOutcome::Busy},
                                                          identity_slot);
            release_request_identity_claim();
            if (published && returned_request_id != nullptr) *returned_request_id = request_id;
            return false;
        }

        finish_request_identity_reservation(identity_slot, request_id);
        const u64 desired = pack_reload(ReloadAdmissionState::Pending,
                                        request_id,
                                        ReloadRequestSource::Signal,
                                        unpack_route_enabled(observed));
        const bool admitted = reload_word_.compare_exchange_strong(
            observed, desired, std::memory_order_acq_rel, std::memory_order_acquire);
        release_request_identity_claim();
        if (admitted && returned_request_id != nullptr) *returned_request_id = request_id;
        return admitted;
    }

    void finish_request_identity_reservation(const ClaimedRecordSlot& claimed, u64 request_id) {
        if (!claimed.valid || claimed.ticket == 0) return;
        u64 expected = pack_event_counters(claimed.ticket, request_id);
        const u64 desired = pack_event_counters(claimed.ticket - 1, request_id);
        if (event_counters_.compare_exchange_strong(
                expected, desired, std::memory_order_acq_rel, std::memory_order_acquire)) {
            release_record_slot(claimed);
            return;
        }
        // A joined Busy publisher already reserved a successor. Keep this
        // placeholder so its ticket can advance without waiting for request
        // ownership to be released.
        cancel_claimed_record(claimed);
    }

    [[nodiscard]] bool allocate_busy_identity(u64 minimum,
                                              u64* request_id,
                                              ClaimedRecordSlot* record_slot) {
        if (request_id == nullptr || record_slot == nullptr) return false;
        u64 current = event_counters_.load(std::memory_order_acquire);
        for (u32 attempt = 0; attempt < kMaxCounterAllocationAttempts; attempt++) {
            const u64 current_request = unpack_counter_request(current);
            const u64 current_ticket = unpack_counter_ticket(current);
            const u64 base = current_request < minimum ? minimum : current_request;
            // Keep the final ticket available for the already accepted
            // request's required terminal record.
            if (base >= kMaxRequestId || current_ticket >= kMaxRecordTicket - 1) return false;
            const ClaimedRecordSlot claimed = claim_record_slot(current_ticket + 1);
            if (!claimed.valid) {
                current = event_counters_.load(std::memory_order_acquire);
                continue;
            }
            const u64 desired = pack_event_counters(current_ticket + 1, base + 1);
            if (event_counters_.compare_exchange_weak(
                    current, desired, std::memory_order_acq_rel, std::memory_order_acquire)) {
                *request_id = base + 1;
                *record_slot = claimed;
                return true;
            }
            release_record_slot(claimed);
        }
        return false;
    }

    [[nodiscard]] bool counter_allocation_exhausted() const {
        const u64 counters = event_counters_.load(std::memory_order_acquire);
        return unpack_counter_request(counters) >= kMaxRequestId ||
               unpack_counter_ticket(counters) >= kMaxRecordTicket - 1;
    }

    [[nodiscard]] bool terminalize_counter_exhaustion(u64* request_id) {
        if (!counter_allocation_exhausted()) return false;
        u8 open = 0;
        if (counter_exhaustion_state_.compare_exchange_strong(
                open, 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
            counter_exhaustion_generation_.store(active_generation(), std::memory_order_relaxed);
            counter_exhaustion_frontier_.store(published_record_.load(std::memory_order_acquire),
                                               std::memory_order_relaxed);
            counter_exhaustion_state_.store(2, std::memory_order_release);
        }
        if (request_id != nullptr) *request_id = kCounterExhaustedRequestId;
        return true;
    }

    [[nodiscard]] bool publish_busy_for_observed(u64 expected, u64* request_id) {
        if (!try_lock_terminal_publication()) {
            const u32 identity_claim = admission_identity_claim_.load(std::memory_order_acquire);
            const bool admission_open = unpack_state(expected) == ReloadAdmissionState::Idle &&
                                        !is_admission_request_claim(identity_claim) &&
                                        !is_admission_busy_claim(identity_claim);
            const auto outcome = admission_open ? ReloadTerminalOutcome::AdmissionContended
                                                : ReloadTerminalOutcome::Busy;
            if (publish_contended_busy(request_id, expected, true, outcome)) return true;
            if (request_id != nullptr) *request_id = 0;
            return false;
        }
        const u64 observed = reload_word_.load(std::memory_order_acquire);
        const auto state = unpack_state(observed);
        const bool reserved_idle =
            state == ReloadAdmissionState::Idle &&
            is_admission_request_claim(admission_identity_claim_.load(std::memory_order_acquire));
        if (stopping_.load(std::memory_order_acquire) != 0 ||
            state == ReloadAdmissionState::Stopping ||
            (state == ReloadAdmissionState::Idle && !reserved_idle) ||
            (unpack_state(expected) != ReloadAdmissionState::Idle && observed != expected)) {
            unlock_terminal_publication();
            return false;
        }
        const u64 busy_generation = active_generation();
        u64 busy_id = 0;
        ClaimedRecordSlot busy_slot{};
        const u64 minimum = reserved_idle ? 0 : unpack_request_id(observed);
        if (!allocate_busy_identity(minimum, &busy_id, &busy_slot)) {
            // Explicitly report that bounded counter allocation produced
            // neither an identity nor a terminal publication.
            if (!terminalize_counter_exhaustion(request_id) && request_id != nullptr)
                *request_id = 0;
            unlock_terminal_publication();
            return false;
        }
        const bool published = publish_claimed_record({true,
                                                       busy_id,
                                                       busy_generation,
                                                       0,
                                                       ReloadRequestSource::Signal,
                                                       ReloadTerminalOutcome::Busy},
                                                      busy_slot);
        if (published && request_id != nullptr) *request_id = busy_id;
        unlock_terminal_publication();
        return published;
    }

    [[nodiscard]] bool publish_contended_busy(
        u64* request_id,
        u64 expected = 0,
        bool revalidate_expected = false,
        ReloadTerminalOutcome outcome = ReloadTerminalOutcome::Busy) {
        const u32 claim = admission_identity_claim_.load(std::memory_order_acquire);
        bool joined_request = false;
        if (is_admission_request_claim(claim)) {
            joined_request = claim_request_busy_publisher();
            if (!joined_request && !claim_contended_busy_publisher()) return false;
        } else {
            if (!claim_contended_busy_publisher()) return false;
        }
        // Snapshot the decision generation before reserving the Busy identity.
        // A later generation publication cannot retag this earlier ticket.
        const u64 busy_generation = active_generation();
        const u64 observed = reload_word_.load(std::memory_order_acquire);
        const auto state = unpack_state(observed);
        if (stopping_.load(std::memory_order_acquire) != 0 ||
            state == ReloadAdmissionState::Stopping ||
            (revalidate_expected && observed != expected)) {
            if (joined_request)
                release_request_busy_publisher();
            else
                release_contended_busy_publisher();
            return false;
        }
        u64 busy_id = 0;
        ClaimedRecordSlot busy_slot{};
        const u64 minimum = state == ReloadAdmissionState::Idle ? 0 : unpack_request_id(observed);
        if (!allocate_busy_identity(minimum, &busy_id, &busy_slot)) {
            if (!terminalize_counter_exhaustion(request_id) && request_id != nullptr)
                *request_id = 0;
            if (joined_request)
                release_request_busy_publisher();
            else
                release_contended_busy_publisher();
            return false;
        }
        const bool published = publish_claimed_record(
            {true, busy_id, busy_generation, 0, ReloadRequestSource::Signal, outcome}, busy_slot);
        if (published && request_id != nullptr) *request_id = busy_id;
        if (joined_request)
            release_request_busy_publisher();
        else
            release_contended_busy_publisher();
        return published;
    }

    // The terminal request owner already excludes shutdown and authority
    // mutation, so a contending Signal need not occupy the admission claim.
    // Leaving that claim open lets an identity already reserved by the owner
    // become Pending instead of being abandoned behind this Busy identity.
    [[nodiscard]] bool publish_unclaimed_contended_busy(u64* request_id) {
        unclaimed_busy_publishers_.fetch_add(1, std::memory_order_acq_rel);
        const auto release_publisher = [this] {
            unclaimed_busy_publishers_.fetch_sub(1, std::memory_order_acq_rel);
        };
        const u64 busy_generation = active_generation();
        const u64 observed = reload_word_.load(std::memory_order_acquire);
        if (terminal_publication_claim_.load(std::memory_order_acquire) !=
                kTerminalPublicationRequestClaimed ||
            stopping_.load(std::memory_order_acquire) != 0 ||
            unpack_state(observed) != ReloadAdmissionState::Idle) {
            release_publisher();
            return false;
        }

        u64 busy_id = 0;
        ClaimedRecordSlot busy_slot{};
        if (!allocate_busy_identity(0, &busy_id, &busy_slot)) {
            if (!terminalize_counter_exhaustion(request_id) && request_id != nullptr)
                *request_id = 0;
            release_publisher();
            return false;
        }
        const bool published = publish_claimed_record({true,
                                                       busy_id,
                                                       busy_generation,
                                                       0,
                                                       ReloadRequestSource::Signal,
                                                       ReloadTerminalOutcome::Busy},
                                                      busy_slot);
        if (published && request_id != nullptr) *request_id = busy_id;
        release_publisher();
        return published;
    }

    [[nodiscard]] static bool is_admission_request_claim(u32 claim) {
        return (claim & kAdmissionStateMask) == kAdmissionRequestClaimed;
    }

    [[nodiscard]] static bool is_admission_busy_claim(u32 claim) {
        return claim >= kAdmissionBusyClaimBase;
    }

    [[nodiscard]] bool claim_request_busy_publisher() {
        u32 claim = admission_identity_claim_.load(std::memory_order_acquire);
        for (u32 attempt = 0; attempt < kMaxCounterAllocationAttempts; attempt++) {
            if (!is_admission_request_claim(claim) ||
                claim > static_cast<u32>(~u32{0}) - kAdmissionBusyClaimBase)
                return false;
            if (admission_identity_claim_.compare_exchange_strong(claim,
                                                                  claim + kAdmissionBusyClaimBase,
                                                                  std::memory_order_acq_rel,
                                                                  std::memory_order_acquire))
                return true;
        }
        return false;
    }

    void release_request_busy_publisher() { release_contended_busy_publisher(); }

    void release_request_identity_claim() {
        (void)admission_identity_claim_.fetch_and(~kAdmissionStateMask, std::memory_order_acq_rel);
    }

    [[nodiscard]] bool claim_contended_busy_publisher() {
        u32 claim = admission_identity_claim_.load(std::memory_order_acquire);
        for (u32 attempt = 0; attempt < kMaxCounterAllocationAttempts; attempt++) {
            if ((claim & kAdmissionStateMask) != kAdmissionOpen ||
                claim > static_cast<u32>(~u32{0}) - kAdmissionBusyClaimBase) {
                return false;
            }
            if (admission_identity_claim_.compare_exchange_strong(claim,
                                                                  claim + kAdmissionBusyClaimBase,
                                                                  std::memory_order_acq_rel,
                                                                  std::memory_order_acquire))
                return true;
        }
        return false;
    }

    void release_contended_busy_publisher() {
        const u32 claim = admission_identity_claim_.load(std::memory_order_acquire);
        if (!is_admission_busy_claim(claim)) return;
        (void)admission_identity_claim_.fetch_sub(kAdmissionBusyClaimBase,
                                                  std::memory_order_acq_rel);
    }

    [[nodiscard]] ClaimedRecordSlot reserve_record_slot() {
        u64 current = event_counters_.load(std::memory_order_acquire);
        for (u32 attempt = 0; attempt < kMaxCounterAllocationAttempts; attempt++) {
            const u64 current_ticket = unpack_counter_ticket(current);
            if (current_ticket >= kMaxRecordTicket) return {};
            const ClaimedRecordSlot claimed = claim_record_slot(current_ticket + 1);
            if (!claimed.valid) return {};
            const u64 desired =
                pack_event_counters(current_ticket + 1, unpack_counter_request(current));
            if (event_counters_.compare_exchange_weak(
                    current, desired, std::memory_order_acq_rel, std::memory_order_acquire))
                return claimed;
            release_record_slot(claimed);
        }
        return {};
    }

    [[nodiscard]] ClaimedRecordSlot reserve_activation_record_slot() {
        const u64 current = event_counters_.load(std::memory_order_acquire);
        const u64 next_ticket = unpack_counter_ticket(current) + 1;
        if (next_ticket == 0 || next_ticket > kMaxRecordTicket) return {};
        // Use the ring position of the actual next ticket. The ticket itself is
        // assigned only after activation acknowledgements, avoiding a frontier
        // gap, but reserving its canonical slot evicts the oldest resident in a
        // full sequential history rather than an arbitrary synthetic position.
        auto claimed = claim_record_slot(next_ticket);
        if (claimed.valid) claimed.ticket = 0;
        return claimed;
    }

    [[nodiscard]] u64 reserve_activation_record_ticket() {
        constexpr u64 kTicketIncrement = u64{1} << 32;
        const u64 previous = event_counters_.fetch_add(kTicketIncrement, std::memory_order_acq_rel);
        return unpack_counter_ticket(previous) + 1;
    }

    [[nodiscard]] ClaimedRecordSlot claim_record_slot(u64 ticket) {
        if (ticket == 0) return {};
        // Prefer every genuinely empty slot before bounded history starts
        // replacing older tickets. Concurrent linear probing can otherwise
        // overwrite an earlier record while unused capacity still exists.
        for (u32 attempt = 0; attempt < kRecordSlotCount; attempt++) {
            const u32 slot = static_cast<u32>((ticket + attempt) & kRecordSlotMask);
            const u64 current_published = published_record_.load(std::memory_order_acquire);
            if (current_published != 0 &&
                static_cast<u32>(current_published & kRecordSlotMask) == slot)
                continue;
            if (record_claim_ticket_[slot].load(std::memory_order_acquire) != 0) continue;
            u64 sequence = record_seq_[slot].load(std::memory_order_acquire);
            if ((sequence & 1u) != 0) continue;
            if (record_slot_ticket_[slot].load(std::memory_order_relaxed) != 0) continue;
            if (!record_seq_[slot].compare_exchange_strong(
                    sequence, sequence + 1, std::memory_order_acq_rel, std::memory_order_acquire))
                continue;
            if (record_claim_ticket_[slot].load(std::memory_order_acquire) != 0 ||
                record_slot_ticket_[slot].load(std::memory_order_relaxed) != 0) {
                record_seq_[slot].store(sequence + 2, std::memory_order_release);
                continue;
            }
            const u64 claimed_published = published_record_.load(std::memory_order_acquire);
            if (claimed_published != 0 &&
                static_cast<u32>(claimed_published & kRecordSlotMask) == slot) {
                record_seq_[slot].store(sequence + 2, std::memory_order_release);
                continue;
            }
            return {ticket, sequence, slot, true};
        }

        // Linear probing can displace canonical ticket positions. Once every
        // slot is resident, select the globally oldest evictable ticket rather
        // than the first resident encountered from the incoming position.
        for (u32 retry = 0; retry < kRecordSlotCount; retry++) {
            u32 oldest_slot = kRecordSlotCount;
            u64 oldest_ticket = ~u64{0};
            u64 oldest_sequence = 0;
            for (u32 slot = 0; slot < kRecordSlotCount; slot++) {
                const u64 current_published = published_record_.load(std::memory_order_acquire);
                if (current_published != 0 &&
                    static_cast<u32>(current_published & kRecordSlotMask) == slot)
                    continue;
                if (record_claim_ticket_[slot].load(std::memory_order_acquire) != 0) continue;
                const u64 sequence = record_seq_[slot].load(std::memory_order_acquire);
                if ((sequence & 1u) != 0) continue;
                const u64 resident_ticket =
                    record_slot_ticket_[slot].load(std::memory_order_relaxed);
                std::atomic_thread_fence(std::memory_order_acquire);
                if (record_seq_[slot].load(std::memory_order_relaxed) != sequence ||
                    record_claim_ticket_[slot].load(std::memory_order_relaxed) != 0 ||
                    resident_ticket == 0 || resident_ticket > ticket)
                    continue;
                if (resident_ticket < oldest_ticket) {
                    oldest_slot = slot;
                    oldest_ticket = resident_ticket;
                    oldest_sequence = sequence;
                }
            }
            if (oldest_slot == kRecordSlotCount) return {};
            if (!record_seq_[oldest_slot].compare_exchange_strong(oldest_sequence,
                                                                  oldest_sequence + 1,
                                                                  std::memory_order_acq_rel,
                                                                  std::memory_order_acquire))
                continue;
            const u64 claimed_published = published_record_.load(std::memory_order_acquire);
            if (record_claim_ticket_[oldest_slot].load(std::memory_order_acquire) != 0 ||
                record_slot_ticket_[oldest_slot].load(std::memory_order_relaxed) != oldest_ticket ||
                (claimed_published != 0 &&
                 static_cast<u32>(claimed_published & kRecordSlotMask) == oldest_slot)) {
                record_seq_[oldest_slot].store(oldest_sequence + 2, std::memory_order_release);
                continue;
            }
            return {ticket, oldest_sequence, oldest_slot, true};
        }
        return {};
    }

    void release_record_slot(const ClaimedRecordSlot& claimed) {
        if (!claimed.valid) return;
        record_seq_[claimed.slot].store(claimed.sequence + 2, std::memory_order_release);
    }

    void stage_claimed_record(const ReloadTerminalRecord& record,
                              const ClaimedRecordSlot& claimed) {
        if (!claimed.valid) return;
        const u32 slot = claimed.slot;
        const u64 ticket = claimed.ticket;
        record_request_id_[slot].store(record.request_id, std::memory_order_relaxed);
        record_old_generation_[slot].store(record.old_generation, std::memory_order_relaxed);
        record_new_generation_[slot].store(record.new_generation, std::memory_order_relaxed);
        record_source_[slot].store(static_cast<u8>(record.source), std::memory_order_relaxed);
        record_outcome_[slot].store(static_cast<u8>(record.outcome), std::memory_order_relaxed);
        record_slot_ticket_[slot].store(ticket, std::memory_order_relaxed);
        record_observable_ticket_[slot].store(
            record.outcome == ReloadTerminalOutcome::None ? 0 : ticket, std::memory_order_relaxed);
        // This ready claim keeps the slot immutable until the contiguous
        // descriptor frontier reaches its ticket.
        record_claim_ticket_[slot].store(ticket, std::memory_order_release);
        release_record_slot(claimed);
    }

    [[nodiscard]] bool publish_claimed_record(const ReloadTerminalRecord& record,
                                              const ClaimedRecordSlot& claimed) {
        if (!claimed.valid) return false;
        stage_claimed_record(record, claimed);

        // The slot publication above makes real terminal records independently
        // observable by request ID. Help the ordered last-record frontier for
        // a fixed number of slots, but never wait for a descheduled predecessor.
        for (u32 attempt = 0; attempt < kRecordSlotCount; attempt++) {
            u64 published = published_record_.load(std::memory_order_acquire);
            const u64 next_ticket = (published >> kRecordSlotBits) + 1;
            u32 ready_slot = kRecordSlotCount;
            for (u32 candidate = 0; candidate < kRecordSlotCount; candidate++) {
                if (record_claim_ticket_[candidate].load(std::memory_order_acquire) != next_ticket)
                    continue;
                const u64 before = record_seq_[candidate].load(std::memory_order_acquire);
                if ((before & 1u) != 0) continue;
                const u64 resident = record_slot_ticket_[candidate].load(std::memory_order_relaxed);
                std::atomic_thread_fence(std::memory_order_acquire);
                if (record_seq_[candidate].load(std::memory_order_relaxed) != before ||
                    record_claim_ticket_[candidate].load(std::memory_order_relaxed) !=
                        next_ticket ||
                    resident != next_ticket)
                    continue;
                ready_slot = candidate;
                break;
            }
            if (ready_slot == kRecordSlotCount) return true;
            const u64 descriptor = (next_ticket << kRecordSlotBits) | ready_slot;
            if (!published_record_.compare_exchange_strong(
                    published, descriptor, std::memory_order_release, std::memory_order_acquire))
                continue;
            record_claim_ticket_[ready_slot].store(0, std::memory_order_release);
        }
        return true;
    }

    void cancel_claimed_record(const ClaimedRecordSlot& claimed) {
        if (!claimed.valid) return;
        // Once the counter CAS has assigned a ticket it must still reach the
        // contiguous frontier. A None record is an internal tombstone: it
        // advances publication without becoming observable terminal history.
        (void)publish_claimed_record({}, claimed);
    }

    [[nodiscard]] ClaimedRecordSlot claim_stopping_record_slot() {
        for (;;) {
            auto claimed = reserve_record_slot();
            if (claimed.valid) return claimed;
            if (unpack_counter_ticket(event_counters_.load(std::memory_order_acquire)) >=
                kMaxRecordTicket)
                return {};
        }
    }

    [[nodiscard]] bool terminalize_stopping(const ReloadTerminalRecord& record,
                                            u64 expected_state) {
        stopping_terminal_publishers_.fetch_add(1, std::memory_order_acq_rel);
        auto terminal_slot = claim_stopping_record_slot();
        if (!terminal_slot.valid) {
            stopping_terminal_publishers_.fetch_sub(1, std::memory_order_acq_rel);
            return false;
        }
        u64 observed = expected_state;
        if (!reload_word_.compare_exchange_strong(
                observed,
                with_state(expected_state, ReloadAdmissionState::Stopping),
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            cancel_claimed_record(terminal_slot);
            stopping_terminal_publishers_.fetch_sub(1, std::memory_order_acq_rel);
            return false;
        }
        const bool published = publish_claimed_record(record, terminal_slot);
        stopping_terminal_publishers_.fetch_sub(1, std::memory_order_acq_rel);
        return published;
    }

    [[nodiscard]] bool try_lock_terminal_publication(
        u8 desired_claim = kTerminalPublicationClaimed) {
        u8 open = 0;
        for (u32 attempt = 0; attempt < kMaxAdmissionAttempts; attempt++) {
            if (terminal_publication_claim_.compare_exchange_weak(
                    open, desired_claim, std::memory_order_acq_rel, std::memory_order_acquire))
                return true;
            open = 0;
        }
        return false;
    }

    void lock_terminal_publication(u8 desired_claim = kTerminalPublicationClaimed) {
        while (!try_lock_terminal_publication(desired_claim)) {
        }
    }

    void unlock_terminal_publication() {
        terminal_publication_claim_.store(kTerminalPublicationOpen, std::memory_order_release);
    }

    std::atomic<u64> reload_word_{0};
    std::atomic<UpstreamMarkReplaySink> mark_replay_sink_{nullptr};
    std::atomic<void*> mark_replay_sink_context_{nullptr};
    std::atomic<u64> mark_replay_sink_epoch_{0};
    std::atomic<u64> mark_replay_sequence_{0};
    std::atomic<u32> mark_replay_callbacks_{0};
    std::mutex mark_replay_mutex_;
    ReloadSourceVersionCapture source_version_capture_ = nullptr;
    void* source_version_capture_context_ = nullptr;
    u32 source_version_len_ = 0;
    char source_version_[ReloadRequest::kMaxSourceVersion]{};
    std::atomic<u64> event_counters_{0};
    std::atomic<u64> counter_exhaustion_generation_{0};
    std::atomic<u64> counter_exhaustion_frontier_{0};
    std::atomic<u8> counter_exhaustion_state_{0};
    std::atomic<u32> admission_identity_claim_{0};
    std::atomic<u8> terminal_publication_claim_{0};
    std::atomic<u32> unclaimed_busy_publishers_{0};
    std::atomic<u32> stopping_terminal_publishers_{0};
    std::atomic<u32> stopped_signal_publishers_{0};
    std::atomic<u8> override_writer_claim_{0};
    std::atomic<u8> stopping_{0};
    std::atomic<u8> cutover_{0};
    std::atomic<u8> activation_publication_{kPublicationOpen};
    ClaimedRecordSlot activation_terminal_slot_{};
    std::atomic<u64> active_generation_{1};
    std::atomic<u8> active_bank_{0};
    std::atomic<u64> bank_generation_[2]{};
    std::atomic<RouteConfig*> bank_config_[2]{};
    std::atomic<u8> upstream_count_[2]{};
    std::atomic<u8> backend_count_[2][RouteConfig::kMaxUpstreams]{};
    std::atomic<u16> upstream_allocation_[2][RouteConfig::kMaxUpstreams]{};
    std::atomic<u64> upstream_incarnation_[2][RouteConfig::kMaxUpstreams]{};
    std::atomic<u16> endpoint_allocation_[2][RouteConfig::kMaxUpstreams]
                                         [UpstreamTarget::kMaxBackends]{};
    std::atomic<u16> endpoint_probe_allocation_[2][RouteConfig::kMaxUpstreams]
                                               [UpstreamTarget::kMaxBackends]{};
    std::atomic<u64> endpoint_incarnation_[2][RouteConfig::kMaxUpstreams]
                                          [UpstreamTarget::kMaxBackends]{};
    std::atomic<u16> endpoint_health_seed_allocation_[2][RouteConfig::kMaxUpstreams]
                                                     [UpstreamTarget::kMaxBackends]{};
    std::atomic<u64> endpoint_health_seed_incarnation_[2][RouteConfig::kMaxUpstreams]
                                                      [UpstreamTarget::kMaxBackends]{};
    UpstreamTarget membership_[2][RouteConfig::kMaxUpstreams]{};
    u8 override_peer_upstream_[2][RouteConfig::kMaxUpstreams][UpstreamTarget::kMaxBackends]{};
    u8 override_peer_backend_[2][RouteConfig::kMaxUpstreams][UpstreamTarget::kMaxBackends]{};
    std::atomic<u64> overrides_[2][RouteConfig::kMaxUpstreams][UpstreamTarget::kMaxBackends]{};
    std::atomic<u64> committed_overrides_[2][RouteConfig::kMaxUpstreams]
                                         [UpstreamTarget::kMaxBackends][2]{};
    std::atomic<u64> committed_override_descriptor_[2][RouteConfig::kMaxUpstreams]
                                                   [UpstreamTarget::kMaxBackends]{};
    std::atomic<u64> committed_override_versions_[2][RouteConfig::kMaxUpstreams]
                                                 [UpstreamTarget::kMaxBackends][2]{};
    std::atomic<u64> committed_override_publication_[2][RouteConfig::kMaxUpstreams]
                                                    [UpstreamTarget::kMaxBackends]{};
    std::atomic<u64> override_seq_[2]{};
    std::atomic<u64> override_version_[2]{};
    inline static std::atomic<u64> next_endpoint_incarnation_{1};
    inline static std::atomic<u64> next_upstream_incarnation_{1};

    std::atomic<u64> published_record_{0};
    std::atomic<u64> record_seq_[kRecordSlotCount]{};
    std::atomic<u64> record_claim_ticket_[kRecordSlotCount]{};
    std::atomic<u64> record_slot_ticket_[kRecordSlotCount]{};
    std::atomic<u64> record_observable_ticket_[kRecordSlotCount]{};
    std::atomic<u64> record_request_id_[kRecordSlotCount]{};
    std::atomic<u64> record_old_generation_[kRecordSlotCount]{};
    std::atomic<u64> record_new_generation_[kRecordSlotCount]{};
    std::atomic<u8> record_source_[kRecordSlotCount]{};
    std::atomic<u8> record_outcome_[kRecordSlotCount]{};
};

template <typename Loop>
inline void latch_control_plane_mutation(Loop* loop, jit::HandlerCtx* ctx, u64 config_generation) {
    if (ctx == nullptr) return;
    ctx->control_plane_mutation = nullptr;
    ctx->config_generation = config_generation;
    if (loop == nullptr) return;
    if (control_plane_replay_mode) return;
    // Route reload attempts do not yet have a traffic capture/replay event.
    // Keep the capability unavailable while capture is active so captured
    // executions remain deterministic and fail closed.
    if constexpr (requires { loop->capture_ring; })
        if (loop->capture_ring != nullptr) return;
    if constexpr (requires { loop->control_plane_mutation; })
        ctx->control_plane_mutation = loop->control_plane_mutation;
}

}  // namespace rut
