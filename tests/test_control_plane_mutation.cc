#include "rut/runtime/control_plane_mutation.h"
#include "rut/runtime/upstream_concurrency.h"
#include "test.h"
#include <atomic>
#include <thread>

using namespace rut;

static bool failed_source_capture(void*, char*, u32, u32*) {
    return false;
}
static bool oversized_source_capture(void*, char*, u32 capacity, u32* out_len) {
    *out_len = capacity;
    return true;
}

struct MarkReplayEvents {
    UpstreamMarkReplayEvent events[8]{};
    u32 count = 0;
};

static void collect_mark_replay_event(void* context, const UpstreamMarkReplayEvent& event) {
    auto* events = static_cast<MarkReplayEvents*>(context);
    if (events != nullptr && events->count < 8) events->events[events->count++] = event;
}

struct ReentrantMarkReplaySinkContext {
    ControlPlaneMutationPort* port = nullptr;
    u32 count = 0;
};

static void disable_mark_replay_sink(void* context, const UpstreamMarkReplayEvent&) {
    auto* state = static_cast<ReentrantMarkReplaySinkContext*>(context);
    ++state->count;
    state->port->set_upstream_mark_replay_sink(nullptr, nullptr);
}

namespace rut {
struct ControlPlaneMutationPortTestAccess {
    static u64 begin_serialized_admission_claim(ControlPlaneMutationPort& port) {
        port.lock_terminal_publication();
        ControlPlaneMutationPort::ClaimedRecordSlot identity_slot{};
        const u64 request_id = port.reserve_request_identity(&identity_slot);
        if (request_id == 0) {
            port.unlock_terminal_publication();
            return 0;
        }
        u32 open = ControlPlaneMutationPort::kAdmissionOpen;
        if (port.admission_identity_claim_.compare_exchange_strong(
                open,
                ControlPlaneMutationPort::kAdmissionRequestClaimed,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            port.finish_request_identity_reservation(identity_slot, request_id);
            port.terminal_publication_claim_.store(
                ControlPlaneMutationPort::kTerminalPublicationRequestClaimed,
                std::memory_order_release);
            return request_id;
        }
        port.stage_claimed_record({}, identity_slot);
        port.unlock_terminal_publication();
        return 0;
    }

    static void lock_terminal_publication(ControlPlaneMutationPort& port) {
        port.lock_terminal_publication();
    }

    static void lock_request_terminal_publication(ControlPlaneMutationPort& port) {
        port.lock_terminal_publication(
            ControlPlaneMutationPort::kTerminalPublicationRequestClaimed);
    }

    static void lock_stop_terminal_publication(ControlPlaneMutationPort& port) {
        port.lock_terminal_publication(ControlPlaneMutationPort::kTerminalPublicationStopClaimed);
    }

    static bool exercise_signal_behind_reserved_route_identity(ControlPlaneMutationPort& port,
                                                               u64* route_id,
                                                               u64* signal_id) {
        if (route_id == nullptr || signal_id == nullptr) return false;
        lock_terminal_publication(port);
        ControlPlaneMutationPort::ClaimedRecordSlot identity_slot{};
        *route_id = port.reserve_request_identity(&identity_slot);
        if (*route_id == 0) {
            port.unlock_terminal_publication();
            return false;
        }
        u32 open = ControlPlaneMutationPort::kAdmissionOpen;
        const bool route_claimed = port.admission_identity_claim_.compare_exchange_strong(
            open,
            ControlPlaneMutationPort::kAdmissionRequestClaimed,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
        if (route_claimed) {
            port.finish_request_identity_reservation(identity_slot, *route_id);
            port.terminal_publication_claim_.store(
                ControlPlaneMutationPort::kTerminalPublicationRequestClaimed,
                std::memory_order_release);
        }
        const bool signal_admitted = port.request_reload(ReloadRequestSource::Signal, signal_id);
        port.unlock_terminal_publication();
        if (!route_claimed) {
            port.cancel_claimed_record(identity_slot);
            return false;
        }
        const bool route_published =
            publish_admission_identity(port, *route_id, ReloadRequestSource::Route);
        return !signal_admitted && route_published;
    }

    static void unlock_terminal_publication(ControlPlaneMutationPort& port) {
        port.unlock_terminal_publication();
    }

    static void stage_stopped(ControlPlaneMutationPort& port) {
        port.stopping_.store(2, std::memory_order_release);
        const u64 current = port.reload_word_.load(std::memory_order_acquire);
        port.reload_word_.store(port.with_state(current, ReloadAdmissionState::Stopping),
                                std::memory_order_release);
        port.unlock_terminal_publication();
    }

    static u64 reserve_admission_identity(ControlPlaneMutationPort& port) {
        ControlPlaneMutationPort::ClaimedRecordSlot identity_slot{};
        const u64 request_id = port.reserve_request_identity(&identity_slot);
        if (request_id == 0) return 0;
        u32 open = ControlPlaneMutationPort::kAdmissionOpen;
        if (!port.admission_identity_claim_.compare_exchange_strong(
                open,
                ControlPlaneMutationPort::kAdmissionRequestClaimed,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            port.stage_claimed_record({}, identity_slot);
            return 0;
        }
        port.finish_request_identity_reservation(identity_slot, request_id);
        return request_id;
    }

    static bool claim_authority_update(ControlPlaneMutationPort& port) {
        u32 open = ControlPlaneMutationPort::kAdmissionOpen;
        return port.admission_identity_claim_.compare_exchange_strong(
            open,
            ControlPlaneMutationPort::kAdmissionAuthorityClaimed,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
    }

    static void release_authority_update(ControlPlaneMutationPort& port) {
        port.admission_identity_claim_.store(ControlPlaneMutationPort::kAdmissionOpen,
                                             std::memory_order_release);
    }

    static bool publish_after_authority_release(ControlPlaneMutationPort& port, u64* request_id) {
        if (!claim_authority_update(port)) return false;
        const u64 generation = port.active_generation();
        u64 reserved_id = 0;
        ControlPlaneMutationPort::ClaimedRecordSlot slot{};
        if (!port.allocate_busy_identity(0, &reserved_id, &slot)) {
            release_authority_update(port);
            return false;
        }
        release_authority_update(port);
        return port.publish_authority_contended_signal_record(
            generation, reserved_id, slot, request_id);
    }

    static void exhaust_event_counters(ControlPlaneMutationPort& port) {
        port.event_counters_.store(
            port.pack_event_counters(ControlPlaneMutationPort::kMaxRecordTicket - 1,
                                     ControlPlaneMutationPort::kMaxRequestId),
            std::memory_order_release);
    }

    static bool claim_contended_busy_publisher(ControlPlaneMutationPort& port) {
        return port.claim_contended_busy_publisher();
    }

    static void release_contended_busy_publisher(ControlPlaneMutationPort& port) {
        port.release_contended_busy_publisher();
    }

    static void begin_unclaimed_busy_publication(ControlPlaneMutationPort& port) {
        port.unclaimed_busy_publishers_.fetch_add(1, std::memory_order_acq_rel);
    }

    static void finish_unclaimed_busy_publication(ControlPlaneMutationPort& port) {
        port.unclaimed_busy_publishers_.fetch_sub(1, std::memory_order_acq_rel);
    }

    static bool claim_request_busy_publisher(ControlPlaneMutationPort& port) {
        return port.claim_request_busy_publisher();
    }

    static void release_request_busy_publisher(ControlPlaneMutationPort& port) {
        port.release_request_busy_publisher();
    }

    static u32 admission_identity_claim(const ControlPlaneMutationPort& port) {
        return port.admission_identity_claim_.load(std::memory_order_acquire);
    }

    static u64 reload_word(const ControlPlaneMutationPort& port) {
        return port.reload_word_.load(std::memory_order_acquire);
    }

    static void reopen_reload_slot(ControlPlaneMutationPort& port) {
        const u64 observed = port.reload_word_.load(std::memory_order_acquire);
        port.reload_word_.store(port.with_state(observed, ReloadAdmissionState::Idle),
                                std::memory_order_release);
    }

    static bool publish_busy_for_observed(ControlPlaneMutationPort& port,
                                          u64 expected,
                                          u64* request_id) {
        return port.publish_busy_for_observed(expected, request_id);
    }

    static u64 reserve_behind_standalone_busy(ControlPlaneMutationPort& port,
                                              ReloadRequestSource source,
                                              u64* returned_request_id = nullptr) {
        port.lock_terminal_publication();
        ControlPlaneMutationPort::ClaimedRecordSlot identity_slot{};
        const u64 request_id = port.reserve_request_identity(&identity_slot);
        if (request_id == 0) {
            port.unlock_terminal_publication();
            return 0;
        }
        const bool claimed = port.claim_reserved_request_identity(
            request_id, source, returned_request_id, identity_slot);
        port.unlock_terminal_publication();
        return claimed ? 0 : request_id;
    }

    static bool publish_admission_identity(ControlPlaneMutationPort& port,
                                           u64 request_id,
                                           ReloadRequestSource source) {
        u64 observed = port.reload_word_.load(std::memory_order_acquire);
        const u64 desired = port.pack_reload(
            ReloadAdmissionState::Pending, request_id, source, port.unpack_route_enabled(observed));
        const bool published = port.reload_word_.compare_exchange_strong(
            observed, desired, std::memory_order_acq_rel, std::memory_order_acquire);
        port.release_request_identity_claim();
        return published;
    }

    static void set_record_ticket(ControlPlaneMutationPort& port, u64 ticket) {
        const u64 counters = port.event_counters_.load(std::memory_order_relaxed);
        port.event_counters_.store(
            port.pack_event_counters(ticket, port.unpack_counter_request(counters)),
            std::memory_order_relaxed);
    }

    static void set_record_frontier(ControlPlaneMutationPort& port, u64 ticket) {
        set_record_ticket(port, ticket);
        port.record_slot_ticket_[0].store(ticket, std::memory_order_relaxed);
        port.record_outcome_[0].store(static_cast<u8>(ReloadTerminalOutcome::None),
                                      std::memory_order_relaxed);
        port.published_record_.store(ticket << ControlPlaneMutationPort::kRecordSlotBits,
                                     std::memory_order_release);
    }

    static constexpr u64 max_record_ticket() { return ControlPlaneMutationPort::kMaxRecordTicket; }

    static constexpr u32 record_slot_count() { return ControlPlaneMutationPort::kRecordSlotCount; }

    static bool activation_terminal_slot_reserved(const ControlPlaneMutationPort& port) {
        return port.activation_terminal_slot_.valid;
    }

    static u32 activation_terminal_slot(const ControlPlaneMutationPort& port) {
        return port.activation_terminal_slot_.slot;
    }

    static void seed_full_sequential_history(ControlPlaneMutationPort& port) {
        for (u64 ticket = 1; ticket <= ControlPlaneMutationPort::kRecordSlotCount; ticket++) {
            const u32 slot = static_cast<u32>(ticket & ControlPlaneMutationPort::kRecordSlotMask);
            port.record_request_id_[slot].store(ticket, std::memory_order_relaxed);
            port.record_old_generation_[slot].store(port.active_generation(),
                                                    std::memory_order_relaxed);
            port.record_source_[slot].store(static_cast<u8>(ReloadRequestSource::Signal),
                                            std::memory_order_relaxed);
            port.record_outcome_[slot].store(static_cast<u8>(ReloadTerminalOutcome::Busy),
                                             std::memory_order_relaxed);
            port.record_slot_ticket_[slot].store(ticket, std::memory_order_relaxed);
            port.record_observable_ticket_[slot].store(ticket, std::memory_order_relaxed);
            port.record_claim_ticket_[slot].store(0, std::memory_order_relaxed);
            port.record_seq_[slot].store(0, std::memory_order_relaxed);
        }
        set_record_ticket(port, ControlPlaneMutationPort::kRecordSlotCount);
        port.published_record_.store(
            ControlPlaneMutationPort::kRecordSlotCount << ControlPlaneMutationPort::kRecordSlotBits,
            std::memory_order_release);
    }

    static void seed_displaced_full_history(ControlPlaneMutationPort& port) {
        seed_full_sequential_history(port);
        // Model two raced claims that probed past ticket 1's canonical slot.
        // Tickets 129 and 130 displaced tickets 2 and 3 instead, so ticket 1
        // remains the globally oldest resident even though ticket 131 probes
        // from slot 3.
        constexpr u32 slot129 = 2;
        constexpr u32 slot130 = 3;
        port.record_request_id_[slot129].store(129, std::memory_order_relaxed);
        port.record_slot_ticket_[slot129].store(129, std::memory_order_relaxed);
        port.record_observable_ticket_[slot129].store(129, std::memory_order_relaxed);
        port.record_request_id_[slot130].store(130, std::memory_order_relaxed);
        port.record_slot_ticket_[slot130].store(130, std::memory_order_relaxed);
        port.record_observable_ticket_[slot130].store(130, std::memory_order_relaxed);
        port.event_counters_.store(port.pack_event_counters(130, 130), std::memory_order_relaxed);
        port.published_record_.store(
            (u64{130} << ControlPlaneMutationPort::kRecordSlotBits) | slot130,
            std::memory_order_release);
    }

    struct BusyReservation {
        u64 request_id = 0;
        u64 generation = 0;
        ControlPlaneMutationPort::ClaimedRecordSlot slot{};
        bool valid = false;
    };

    static BusyReservation reserve_busy(ControlPlaneMutationPort& port, u64 minimum) {
        BusyReservation reservation{};
        reservation.generation = port.active_generation();
        reservation.valid =
            port.allocate_busy_identity(minimum, &reservation.request_id, &reservation.slot);
        return reservation;
    }

    static bool publish_busy(ControlPlaneMutationPort& port, const BusyReservation& reservation) {
        return reservation.valid && port.publish_claimed_record({true,
                                                                 reservation.request_id,
                                                                 reservation.generation,
                                                                 0,
                                                                 ReloadRequestSource::Signal,
                                                                 ReloadTerminalOutcome::Busy},
                                                                reservation.slot);
    }

    static void stage_busy(ControlPlaneMutationPort& port, const BusyReservation& reservation) {
        const u32 slot = reservation.slot.slot;
        port.record_request_id_[slot].store(reservation.request_id, std::memory_order_relaxed);
        port.record_old_generation_[slot].store(port.active_generation(),
                                                std::memory_order_relaxed);
        port.record_new_generation_[slot].store(0, std::memory_order_relaxed);
        port.record_source_[slot].store(static_cast<u8>(ReloadRequestSource::Signal),
                                        std::memory_order_relaxed);
        port.record_outcome_[slot].store(static_cast<u8>(ReloadTerminalOutcome::Busy),
                                         std::memory_order_relaxed);
        port.record_slot_ticket_[slot].store(reservation.slot.ticket, std::memory_order_relaxed);
        port.record_observable_ticket_[slot].store(0, std::memory_order_relaxed);
        port.record_claim_ticket_[slot].store(reservation.slot.ticket, std::memory_order_release);
        port.release_record_slot(reservation.slot);
    }

    static void release_busy(ControlPlaneMutationPort& port, const BusyReservation& reservation) {
        if (reservation.valid) port.cancel_claimed_record(reservation.slot);
    }

    static ReloadAdmissionState reload_state(const ControlPlaneMutationPort& port) {
        return port.unpack_state(port.reload_word_.load(std::memory_order_acquire));
    }

    static bool begin_completion(ControlPlaneMutationPort& port) {
        u64 expected = port.reload_word_.load(std::memory_order_acquire);
        if (port.unpack_state(expected) != ReloadAdmissionState::InFlight) return false;
        return port.reload_word_.compare_exchange_strong(
            expected,
            port.with_state(expected, ReloadAdmissionState::Completing),
            std::memory_order_acq_rel,
            std::memory_order_acquire);
    }

    static void fill_record_slots_with_newer_tickets(ControlPlaneMutationPort& port,
                                                     u64 first_ticket) {
        for (u32 slot = 0; slot < ControlPlaneMutationPort::kRecordSlotCount; slot++) {
            port.record_slot_ticket_[slot].store(first_ticket + slot, std::memory_order_relaxed);
            port.record_seq_[slot].store(0, std::memory_order_relaxed);
        }
    }

    static void set_override_sequence(ControlPlaneMutationPort& port, u32 bank, u64 sequence) {
        port.override_seq_[bank].store(sequence, std::memory_order_release);
    }

    static void set_override_version(ControlPlaneMutationPort& port, u32 bank, u64 version) {
        port.override_version_[bank].store(version, std::memory_order_release);
    }

    static u64 override_version(const ControlPlaneMutationPort& port, u32 bank) {
        return port.override_version_[bank].load(std::memory_order_acquire);
    }

    static void set_active_generation(ControlPlaneMutationPort& port, u64 generation) {
        port.active_generation_.store(generation, std::memory_order_release);
    }

    static void publish_committed_override(ControlPlaneMutationPort& port,
                                           u32 bank,
                                           ServerIdentity server,
                                           bool healthy,
                                           u64 version) {
        port.publish_committed_override(
            bank,
            server.upstream_id,
            server.backend_id,
            ControlPlaneMutationPort::pack_override(
                server.config_generation,
                healthy ? ManualHealthOverride::Healthy : ManualHealthOverride::Unhealthy),
            version);
    }

    static void stage_committed_override(ControlPlaneMutationPort& port,
                                         u32 bank,
                                         ServerIdentity server,
                                         bool healthy,
                                         u64 version) {
        const u64 descriptor =
            port.committed_override_descriptor_[bank][server.upstream_id][server.backend_id].load(
                std::memory_order_relaxed);
        const u64 slot = (descriptor & 1u) ^ 1u;
        port.committed_overrides_[bank][server.upstream_id][server.backend_id][slot].store(
            ControlPlaneMutationPort::pack_override(
                server.config_generation,
                healthy ? ManualHealthOverride::Healthy : ManualHealthOverride::Unhealthy),
            std::memory_order_relaxed);
        port.committed_override_versions_[bank][server.upstream_id][server.backend_id][slot].store(
            version, std::memory_order_relaxed);
    }

    static u8 stopping(const ControlPlaneMutationPort& port) {
        return port.stopping_.load(std::memory_order_acquire);
    }
};
}  // namespace rut

namespace {
bool add_upstreams(RouteConfig* config, u32 count) {
    for (u32 i = 0; i < count; i++)
        if (!config->add_upstream("test", 0x7f000001u, 8000)) return false;
    return true;
}
}  // namespace

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

TEST(control_plane_mutation, admission_reserves_identity_before_pending_publication) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    const u64 first_id = ControlPlaneMutationPortTestAccess::reserve_admission_identity(port);
    REQUIRE_EQ(first_id, 1u);
    CHECK_EQ(port.state(), ReloadAdmissionState::Idle);
    REQUIRE(ControlPlaneMutationPortTestAccess::publish_admission_identity(
        port, first_id, ReloadRequestSource::Route));

    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(
        port.complete_reload(request.id, request.source, ReloadTerminalOutcome::ValidationFailed));
    u64 next_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &next_id));
    CHECK_EQ(next_id, 2u);
}

TEST(control_plane_mutation, authority_update_cannot_invalidate_reserved_admission_identity) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    const u64 first_id = ControlPlaneMutationPortTestAccess::reserve_admission_identity(port);
    REQUIRE_EQ(first_id, 1u);

    CHECK_FALSE(port.set_route_reload_enabled(false));
    CHECK(port.route_reload_enabled());
    REQUIRE(ControlPlaneMutationPortTestAccess::publish_admission_identity(
        port, first_id, ReloadRequestSource::Route));

    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(port.complete_reload(
        request.id, request.source, ReloadTerminalOutcome::ValidationFailed, 12));
    u64 second_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &second_id));
    CHECK_EQ(second_id, 2u);
}

TEST(control_plane_mutation, signal_bounds_retry_for_in_progress_admission_identity) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    const u64 admitted_id = ControlPlaneMutationPortTestAccess::reserve_admission_identity(port);
    REQUIRE_EQ(admitted_id, 1u);

    std::atomic<bool> started{false};
    std::atomic<bool> returned{false};
    u64 signal_id = 99;
    bool signal_admitted = true;
    std::thread signal([&] {
        started.store(true, std::memory_order_release);
        signal_admitted = port.request_reload(ReloadRequestSource::Signal, &signal_id);
        returned.store(true, std::memory_order_release);
    });
    while (!started.load(std::memory_order_acquire)) {
    }
    signal.join();
    CHECK(returned.load(std::memory_order_acquire));
    CHECK_FALSE(signal_admitted);
    CHECK_EQ(signal_id, 2u);
    const auto busy = port.record_for_request(signal_id);
    REQUIRE(busy.valid);
    CHECK_EQ(busy.outcome, ReloadTerminalOutcome::Busy);

    REQUIRE(ControlPlaneMutationPortTestAccess::publish_admission_identity(
        port, admitted_id, ReloadRequestSource::Route));
}

TEST(control_plane_mutation, signal_records_busy_behind_reserved_request_claim) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    const u64 admitted_id =
        ControlPlaneMutationPortTestAccess::begin_serialized_admission_claim(port);
    REQUIRE_EQ(admitted_id, 1u);

    std::atomic<bool> started{false};
    std::atomic<bool> returned{false};
    u64 signal_id = 99;
    std::thread signal([&] {
        started.store(true, std::memory_order_release);
        (void)port.request_reload(ReloadRequestSource::Signal, &signal_id);
        returned.store(true, std::memory_order_release);
    });
    while (!started.load(std::memory_order_acquire)) {
    }
    signal.join();
    CHECK(returned.load(std::memory_order_acquire));
    CHECK_EQ(signal_id, 2u);
    const auto busy = port.record_for_request(signal_id);
    REQUIRE(busy.valid);
    CHECK_EQ(busy.outcome, ReloadTerminalOutcome::Busy);

    ControlPlaneMutationPortTestAccess::unlock_terminal_publication(port);
    REQUIRE(ControlPlaneMutationPortTestAccess::publish_admission_identity(
        port, admitted_id, ReloadRequestSource::Route));
}

TEST(control_plane_mutation, signal_admits_when_terminal_owner_has_not_closed_admission) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    ControlPlaneMutationPortTestAccess::lock_stop_terminal_publication(port);

    u64 signal_id = 99;
    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &signal_id));
    CHECK_EQ(signal_id, 1u);
    CHECK_EQ(port.state(), ReloadAdmissionState::Pending);
    CHECK_FALSE(port.record_for_request(signal_id).valid);

    ControlPlaneMutationPortTestAccess::unlock_terminal_publication(port);
}

TEST(control_plane_mutation, signal_does_not_displace_reserved_route_identity) {
    ControlPlaneMutationPort port;
    port.reset(11, true);

    u64 route_id = 0;
    u64 signal_id = 0;
    REQUIRE(ControlPlaneMutationPortTestAccess::exercise_signal_behind_reserved_route_identity(
        port, &route_id, &signal_id));
    CHECK_EQ(route_id, 1u);
    CHECK_EQ(signal_id, 2u);
    const auto busy = port.record_for_request(signal_id);
    REQUIRE(busy.valid);
    CHECK_EQ(busy.outcome, ReloadTerminalOutcome::Busy);
    CHECK_EQ(port.state(), ReloadAdmissionState::Pending);
}

TEST(control_plane_mutation, signal_records_authority_contention_while_terminal_is_claimed) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    ControlPlaneMutationPortTestAccess::lock_terminal_publication(port);
    REQUIRE(ControlPlaneMutationPortTestAccess::claim_authority_update(port));

    u64 signal_id = 99;
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &signal_id));
    CHECK_EQ(signal_id, 1u);
    const auto contended = port.record_for_request(signal_id);
    REQUIRE(contended.valid);
    CHECK_EQ(contended.outcome, ReloadTerminalOutcome::AdmissionContended);

    ControlPlaneMutationPortTestAccess::release_authority_update(port);
    ControlPlaneMutationPortTestAccess::unlock_terminal_publication(port);
    u64 admitted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &admitted_id));
    CHECK_EQ(admitted_id, 2u);
}

TEST(control_plane_mutation, signal_reports_admission_contention_after_reload_reopens) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    ControlPlaneMutationPortTestAccess::lock_terminal_publication(port);

    u64 signal_id = 99;
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &signal_id));
    CHECK_EQ(signal_id, 1u);
    const auto terminal = port.record_for_request(signal_id);
    REQUIRE(terminal.valid);
    CHECK_EQ(terminal.outcome, ReloadTerminalOutcome::AdmissionContended);

    ControlPlaneMutationPortTestAccess::unlock_terminal_publication(port);
}

TEST(control_plane_mutation, every_signal_joins_a_contended_busy_publication) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    ControlPlaneMutationPortTestAccess::lock_terminal_publication(port);
    REQUIRE(ControlPlaneMutationPortTestAccess::claim_contended_busy_publisher(port));

    constexpr u32 kSignals = 16;
    u64 signal_ids[kSignals]{};
    bool signal_admitted[kSignals]{};
    std::thread signals[kSignals];
    for (u32 i = 0; i < kSignals; i++) {
        signals[i] = std::thread([&, i] {
            signal_admitted[i] = port.request_reload(ReloadRequestSource::Signal, &signal_ids[i]);
        });
    }
    for (auto& signal : signals) signal.join();

    bool seen[kSignals + 1]{};
    for (u32 i = 0; i < kSignals; i++) {
        CHECK_FALSE(signal_admitted[i]);
        const u64 signal_id = signal_ids[i];
        REQUIRE(signal_id >= 1 && signal_id <= kSignals);
        CHECK_FALSE(seen[signal_id]);
        seen[signal_id] = true;
        const auto busy = port.record_for_request(signal_id);
        REQUIRE(busy.valid);
        CHECK_EQ(busy.outcome, ReloadTerminalOutcome::Busy);
    }
    ControlPlaneMutationPortTestAccess::release_contended_busy_publisher(port);
    ControlPlaneMutationPortTestAccess::unlock_terminal_publication(port);
}

TEST(control_plane_mutation, requester_does_not_wait_for_standalone_busy_publisher) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    REQUIRE(ControlPlaneMutationPortTestAccess::claim_contended_busy_publisher(port));

    const u64 abandoned_id = ControlPlaneMutationPortTestAccess::reserve_behind_standalone_busy(
        port, ReloadRequestSource::Route);
    CHECK_EQ(abandoned_id, 1u);

    ControlPlaneMutationPortTestAccess::release_contended_busy_publisher(port);
    u64 request_id = 99;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &request_id));
    CHECK_EQ(request_id, 1u);
}

TEST(control_plane_mutation, signal_publishes_busy_behind_standalone_publisher) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    REQUIRE(ControlPlaneMutationPortTestAccess::claim_contended_busy_publisher(port));

    u64 signal_id = 99;
    const u64 abandoned_id = ControlPlaneMutationPortTestAccess::reserve_behind_standalone_busy(
        port, ReloadRequestSource::Signal, &signal_id);
    CHECK_EQ(abandoned_id, 1u);
    CHECK_EQ(signal_id, 1u);
    const auto busy = port.record_for_request(signal_id);
    REQUIRE(busy.valid);
    CHECK_EQ(busy.outcome, ReloadTerminalOutcome::Busy);

    ControlPlaneMutationPortTestAccess::release_contended_busy_publisher(port);
}

TEST(control_plane_mutation, admitted_request_detaches_joined_busy_publisher) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    const u64 request_id = ControlPlaneMutationPortTestAccess::reserve_admission_identity(port);
    REQUIRE_EQ(request_id, 1u);
    REQUIRE(ControlPlaneMutationPortTestAccess::claim_request_busy_publisher(port));

    REQUIRE(ControlPlaneMutationPortTestAccess::publish_admission_identity(
        port, request_id, ReloadRequestSource::Route));
    CHECK(ControlPlaneMutationPortTestAccess::admission_identity_claim(port) >= 4u);

    ControlPlaneMutationPortTestAccess::release_request_busy_publisher(port);
    CHECK_EQ(ControlPlaneMutationPortTestAccess::admission_identity_claim(port), 0u);
}

TEST(control_plane_mutation, busy_revalidates_shutdown_under_terminal_boundary) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    u64 admitted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &admitted_id));
    REQUIRE_EQ(admitted_id, 1u);
    ControlPlaneMutationPortTestAccess::lock_terminal_publication(port);

    std::atomic<bool> started{false};
    u64 signal_id = 99;
    bool signal_admitted = true;
    std::thread signal([&] {
        started.store(true, std::memory_order_release);
        signal_admitted = port.request_reload(ReloadRequestSource::Signal, &signal_id);
    });
    while (!started.load(std::memory_order_acquire)) {
    }
    signal.join();
    CHECK_FALSE(signal_admitted);
    CHECK_EQ(signal_id, 2u);
    const auto busy = port.record_for_request(signal_id);
    REQUIRE(busy.valid);
    CHECK_EQ(busy.outcome, ReloadTerminalOutcome::Busy);
    ControlPlaneMutationPortTestAccess::stage_stopped(port);

    CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
    CHECK(port.record_for_request(2).valid);
}

TEST(control_plane_mutation, contended_busy_rejects_a_reopened_reload_slot) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    u64 admitted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &admitted_id));
    const u64 occupied = ControlPlaneMutationPortTestAccess::reload_word(port);
    ControlPlaneMutationPortTestAccess::lock_terminal_publication(port);
    ControlPlaneMutationPortTestAccess::reopen_reload_slot(port);

    u64 signal_id = 99;
    CHECK_FALSE(
        ControlPlaneMutationPortTestAccess::publish_busy_for_observed(port, occupied, &signal_id));
    CHECK_EQ(signal_id, 0u);
    CHECK_FALSE(port.last_record().valid);

    ControlPlaneMutationPortTestAccess::unlock_terminal_publication(port);
    u64 next_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &next_id));
    CHECK_EQ(next_id, 2u);
}

TEST(control_plane_mutation, signal_records_authority_update_contention) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    REQUIRE(ControlPlaneMutationPortTestAccess::claim_authority_update(port));

    u64 signal_id = 99;
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &signal_id));
    CHECK_EQ(signal_id, 1u);
    const auto contended = port.record_for_request(signal_id);
    REQUIRE(contended.valid);
    CHECK_EQ(contended.outcome, ReloadTerminalOutcome::AdmissionContended);

    ControlPlaneMutationPortTestAccess::release_authority_update(port);
    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &signal_id));
    CHECK_EQ(signal_id, 2u);
}

TEST(control_plane_mutation, authority_contention_revalidates_before_publication) {
    ControlPlaneMutationPort port;
    port.reset(11, true);

    u64 signal_id = 99;
    REQUIRE(ControlPlaneMutationPortTestAccess::publish_after_authority_release(port, &signal_id));
    CHECK_EQ(signal_id, 1u);
    REQUIRE(port.last_record().valid);
    CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::AdmissionContended);

    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &signal_id));
    CHECK_EQ(signal_id, 2u);
}

TEST(control_plane_mutation, exhausted_signal_counters_publish_terminal_state) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    ControlPlaneMutationPortTestAccess::exhaust_event_counters(port);

    u64 signal_id = 99;
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &signal_id));
    CHECK_EQ(signal_id, ControlPlaneMutationPort::kCounterExhaustedRequestId);
    const auto exhausted = port.record_for_request(signal_id);
    REQUIRE(exhausted.valid);
    CHECK_EQ(exhausted.request_id, signal_id);
    CHECK_EQ(exhausted.old_generation, 11u);
    CHECK_EQ(exhausted.outcome, ReloadTerminalOutcome::CounterExhausted);
    CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::CounterExhausted);

    u64 repeated_id = 99;
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &repeated_id));
    CHECK_EQ(repeated_id, signal_id);
    CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::CounterExhausted);
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

    u64 next_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &next_id));
    CHECK_EQ(next_id, id + 1);
}

TEST(control_plane_mutation, busy_signal_attempt_receives_terminal_identity) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    u64 accepted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &accepted_id));
    u64 busy_id = 0;
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &busy_id));
    CHECK_EQ(busy_id, accepted_id + 1);
    const auto record = port.last_record();
    REQUIRE(record.valid);
    CHECK_EQ(record.request_id, busy_id);
    CHECK_EQ(record.source, ReloadRequestSource::Signal);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Busy);
    CHECK_EQ(port.state(), ReloadAdmissionState::Pending);
}

TEST(control_plane_mutation, concurrent_signals_keep_terminal_or_explicit_failure) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    u64 accepted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &accepted_id));

    std::atomic<bool> start{false};
    u64 ids[64]{};
    bool results[64]{};
    std::thread workers[64];
    for (u32 i = 0; i < 64; i++) {
        workers[i] = std::thread([&, i] {
            while (!start.load(std::memory_order_acquire)) {
            }
            results[i] = port.request_reload(ReloadRequestSource::Signal, &ids[i]);
        });
    }
    start.store(true, std::memory_order_release);
    for (auto& worker : workers) worker.join();
    u32 terminal_count = 0;
    for (u32 i = 0; i < 64; i++) {
        CHECK_FALSE(results[i]);
        REQUIRE_NE(ids[i], 0u);
        terminal_count++;
        CHECK(ids[i] > accepted_id);
        for (u32 j = 0; j < i; j++) CHECK_NE(ids[i], ids[j]);
        const auto record = port.record_for_request(ids[i]);
        REQUIRE(record.valid);
        CHECK_EQ(record.outcome, ReloadTerminalOutcome::Busy);
    }
    CHECK_EQ(terminal_count, 64u);
    u64 highest_id = 0;
    for (const u64 id : ids)
        if (id > highest_id) highest_id = id;
    REQUIRE(port.last_record().valid);
    CHECK_EQ(port.last_record().request_id, highest_id);
}

TEST(control_plane_mutation, busy_publication_does_not_wait_for_earlier_claimed_ticket) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    u64 accepted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &accepted_id));

    const auto paused = ControlPlaneMutationPortTestAccess::reserve_busy(port, accepted_id);
    REQUIRE(paused.valid);
    CHECK_EQ(paused.request_id, accepted_id + 1);

    std::atomic<bool> started{false};
    std::atomic<bool> returned{false};
    u64 later_id = 0;
    bool later_admitted = true;
    std::thread later([&] {
        started.store(true, std::memory_order_release);
        later_admitted = port.request_reload(ReloadRequestSource::Signal, &later_id);
        returned.store(true, std::memory_order_release);
    });
    while (!started.load(std::memory_order_acquire)) {
    }
    for (u32 attempt = 0; attempt < 10000 && !returned.load(std::memory_order_acquire); attempt++)
        std::this_thread::yield();
    CHECK(returned.load(std::memory_order_acquire));
    CHECK(port.record_for_request(later_id).valid);
    CHECK_FALSE(port.last_record().valid);

    REQUIRE(ControlPlaneMutationPortTestAccess::publish_busy(port, paused));
    later.join();
    CHECK_FALSE(later_admitted);
    CHECK_EQ(later_id, paused.request_id + 1);
    const auto record = port.record_for_request(paused.request_id);
    REQUIRE(record.valid);
    CHECK_EQ(record.request_id, paused.request_id);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Busy);
    CHECK(port.record_for_request(later_id).valid);
}

TEST(control_plane_mutation, busy_record_keeps_decision_generation) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    u64 accepted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &accepted_id));
    const auto busy = ControlPlaneMutationPortTestAccess::reserve_busy(port, accepted_id);
    REQUIRE(busy.valid);
    CHECK_EQ(busy.generation, 11u);

    ControlPlaneMutationPortTestAccess::set_active_generation(port, 12);
    REQUIRE(ControlPlaneMutationPortTestAccess::publish_busy(port, busy));
    const auto record = port.record_for_request(busy.request_id);
    REQUIRE(record.valid);
    CHECK_EQ(record.old_generation, 11u);
}

TEST(control_plane_mutation, request_lookup_hides_unpublished_terminal_slot) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    u64 accepted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &accepted_id));
    const auto published = ControlPlaneMutationPortTestAccess::reserve_busy(port, accepted_id);
    REQUIRE(published.valid);
    REQUIRE(ControlPlaneMutationPortTestAccess::publish_busy(port, published));
    const auto staged =
        ControlPlaneMutationPortTestAccess::reserve_busy(port, published.request_id);
    REQUIRE(staged.valid);

    ControlPlaneMutationPortTestAccess::stage_busy(port, staged);
    CHECK(port.record_for_request(published.request_id).valid);
    CHECK_FALSE(port.record_for_request(staged.request_id).valid);
    REQUIRE(ControlPlaneMutationPortTestAccess::publish_busy(port, staged));
    CHECK(port.record_for_request(staged.request_id).valid);
}

TEST(control_plane_mutation, record_publication_frontier_does_not_block_ready_successors) {
    ControlPlaneMutationPort port;
    port.reset(11, true);
    u64 accepted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &accepted_id));
    const auto first = ControlPlaneMutationPortTestAccess::reserve_busy(port, accepted_id);
    REQUIRE(first.valid);
    const auto second = ControlPlaneMutationPortTestAccess::reserve_busy(port, first.request_id);
    REQUIRE(second.valid);

    std::atomic<bool> second_started{false};
    std::atomic<bool> second_returned{false};
    bool second_published = false;
    std::thread second_publisher([&] {
        second_started.store(true, std::memory_order_release);
        second_published = ControlPlaneMutationPortTestAccess::publish_busy(port, second);
        second_returned.store(true, std::memory_order_release);
    });
    while (!second_started.load(std::memory_order_acquire)) {
    }
    for (u32 attempt = 0; attempt < 10000 && !second_returned.load(std::memory_order_acquire);
         attempt++)
        std::this_thread::yield();
    CHECK(second_returned.load(std::memory_order_acquire));
    REQUIRE(second_published);
    CHECK_FALSE(port.last_record().valid);
    CHECK(port.record_for_request(second.request_id).valid);

    REQUIRE(ControlPlaneMutationPortTestAccess::publish_busy(port, first));
    second_publisher.join();
    CHECK(port.record_for_request(first.request_id).valid);
    CHECK(port.record_for_request(second.request_id).valid);
    REQUIRE(port.last_record().valid);
    CHECK_EQ(port.last_record().request_id, second.request_id);
}

TEST(control_plane_mutation, failed_reload_records_assigned_candidate_generation) {
    ControlPlaneMutationPort port;
    port.reset(11, false);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    CHECK_FALSE(port.complete_reload(request.id, request.source, ReloadTerminalOutcome::Busy));
    CHECK_EQ(port.state(), ReloadAdmissionState::InFlight);
    REQUIRE(port.complete_reload(
        request.id, request.source, ReloadTerminalOutcome::ValidationFailed, 12));
    CHECK_EQ(port.active_generation(), 11u);
    CHECK_EQ(port.state(), ReloadAdmissionState::Idle);
    CHECK_EQ(port.last_record().new_generation, 12u);
}

TEST(control_plane_mutation, failed_reload_ticket_exhaustion_rolls_back_for_retry) {
    ControlPlaneMutationPort port;
    port.reset(11, false);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));

    ControlPlaneMutationPortTestAccess::set_record_ticket(
        port, ControlPlaneMutationPortTestAccess::max_record_ticket());
    CHECK_FALSE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::ValidationFailed, 12));
    CHECK_EQ(port.state(), ReloadAdmissionState::InFlight);
    CHECK_EQ(port.active_generation(), 11u);

    ControlPlaneMutationPortTestAccess::set_record_ticket(port, 0);
    REQUIRE(port.complete_reload(id, request.source, ReloadTerminalOutcome::ValidationFailed, 12));
    CHECK_EQ(port.state(), ReloadAdmissionState::Idle);
    CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::ValidationFailed);
}

TEST(control_plane_mutation, activation_retains_old_health_until_terminal_ack_boundary) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(add_upstreams(&old_config, 5));
    REQUIRE(old_config.add_upstream_backend(4, 0x7f000001u, 8100));
    REQUIRE(old_config.add_upstream_backend(4, 0x7f000001u, 8101));
    port.reset(3, true, &old_config);
    CHECK_EQ(old_config.config_generation, 3u);
    const ServerIdentity old_server{3, 4, 2};
    REQUIRE(port.mark(old_server, false));
    CHECK_EQ(port.manual_health(old_server), ManualHealthOverride::Unhealthy);

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    CHECK(!port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 3));
    CHECK_EQ(port.state(), ReloadAdmissionState::InFlight);
    RouteConfig new_config;
    REQUIRE(add_upstreams(&new_config, 5));
    REQUIRE(new_config.add_upstream_backend(4, 0x7f000001u, 8200));
    REQUIRE(new_config.add_upstream_backend(4, 0x7f000001u, 8201));
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));
    CHECK_EQ(new_config.config_generation, 4u);
    CHECK_EQ(port.active_generation(), 4u);
    CHECK_EQ(port.state(), ReloadAdmissionState::Completing);
    CHECK(!port.request_reload(ReloadRequestSource::Route));
    CHECK_EQ(port.manual_health(old_server), ManualHealthOverride::Unhealthy);
    REQUIRE(port.mark(old_server, true));
    CHECK_EQ(port.manual_health(old_server), ManualHealthOverride::Healthy);

    const ServerIdentity new_server{4, 4, 2};
    CHECK_EQ(port.manual_health(new_server), ManualHealthOverride::None);
    REQUIRE(port.mark(new_server, true));
    CHECK_EQ(port.manual_health(new_server), ManualHealthOverride::Healthy);
    REQUIRE(port.mark(old_server, false));
    CHECK_EQ(port.manual_health(old_server), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.manual_health(new_server), ManualHealthOverride::Healthy);
    CHECK(!port.last_record().valid);
    REQUIRE(port.finish_activation(id));
    CHECK_EQ(port.state(), ReloadAdmissionState::Idle);
    CHECK_EQ(port.manual_health(old_server), ManualHealthOverride::None);
    const auto record = port.last_record();
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Activated);
    CHECK_EQ(record.old_generation, 3u);
    CHECK_EQ(record.new_generation, 4u);
}

TEST(control_plane_mutation, shutdown_authority_stays_closed_after_activation_finishes) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    RouteConfig new_config;
    port.reset(3, true, &old_config);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));
    REQUIRE_EQ(port.state(), ReloadAdmissionState::Completing);

    port.close_route_reload_admission();
    CHECK_FALSE(port.route_reload_enabled());
    REQUIRE(port.finish_activation(id));
    CHECK_EQ(port.state(), ReloadAdmissionState::Idle);
    CHECK_FALSE(port.route_reload_enabled());
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Route));
}

TEST(control_plane_mutation, activation_carries_overrides_across_probe_policy_changes) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(add_upstreams(&old_config, 2));
    old_config.upstreams[1].hc_enabled = true;
    old_config.upstreams[1].hc_interval_ms = 1000;
    old_config.upstreams[1].hc_expected_status = 204;
    port.reset(3, true, &old_config);
    MarkReplayEvents replay_events;
    port.set_upstream_mark_replay_sink(&collect_mark_replay_event, &replay_events);
    const u16 old_allocation = port.endpoint_allocation_for_config(&old_config, 1, 0);
    const u64 old_incarnation = port.endpoint_incarnation_for_config(&old_config, 1, 0);
    REQUIRE(port.mark({3, 0, 0}, false));
    REQUIRE(port.mark({3, 1, 0}, true));
    REQUIRE(replay_events.count == 2);
    CHECK_EQ(replay_events.events[0].event_sequence, 1u);
    CHECK(replay_events.events[0].accepted);
    CHECK_EQ(replay_events.events[0].reason, UpstreamMarkReplayReason::Published);
    CHECK_EQ(replay_events.events[0].published_version, 2u);

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    REQUIRE(add_upstreams(&new_config, 2));
    REQUIRE(new_config.add_upstream_backend(0, 0x7f000001u, 8100));
    new_config.upstreams[1].hc_enabled = true;
    new_config.upstreams[1].hc_interval_ms = 2000;
    new_config.upstreams[1].hc_expected_status = 204;
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.manual_health({4, 0, 1}), ManualHealthOverride::None);
    CHECK_EQ(port.manual_health({4, 1, 0}), ManualHealthOverride::Healthy);
    CHECK_NE(port.endpoint_allocation_for_config(&new_config, 1, 0), old_allocation);
    CHECK_EQ(port.endpoint_probe_allocation_for_config(&new_config, 1, 0), old_allocation);
    CHECK_NE(port.endpoint_incarnation_for_config(&new_config, 1, 0), old_incarnation);
    CHECK_EQ(port.endpoint_health_seed_allocation_for_config(&new_config, 1, 0), old_allocation);
    CHECK_EQ(port.endpoint_health_seed_incarnation_for_config(&new_config, 1, 0), old_incarnation);
    CHECK_EQ(port.endpoint_health_seed_allocation_for_config(nullptr, 1, 0),
             ControlPlaneMutationPort::kInvalidAllocation);
    CHECK_EQ(port.endpoint_health_seed_incarnation_for_config(nullptr, 1, 0), 0u);
    CHECK_EQ(
        port.endpoint_health_seed_allocation_for_config(&new_config, RouteConfig::kMaxUpstreams, 0),
        ControlPlaneMutationPort::kInvalidAllocation);
    CHECK_EQ(port.endpoint_health_seed_incarnation_for_config(
                 &new_config, 1, UpstreamTarget::kMaxBackends),
             0u);
    u64 version = 0;
    CHECK_EQ(port.manual_health({4, 0, 0}, &version), ManualHealthOverride::Unhealthy);
    CHECK_EQ(version, 1u);
}

TEST(control_plane_mutation, mark_replay_sink_handles_reentrant_disable_and_failures) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(config.add_upstream("users", 0x7f000001u, 8000).has_value());
    port.reset(3, true, &config);

    ReentrantMarkReplaySinkContext reentrant{&port};
    port.set_upstream_mark_replay_sink(&disable_mark_replay_sink, &reentrant);
    REQUIRE(port.mark({3, 0, 0}, true));
    CHECK_EQ(reentrant.count, 1u);

    MarkReplayEvents events;
    port.set_upstream_mark_replay_sink(&collect_mark_replay_event, &events);
    CHECK_FALSE(port.mark({3, RouteConfig::kMaxUpstreams, 0}, false));
    REQUIRE_EQ(events.count, 1u);
    CHECK_FALSE(events.events[0].accepted);
    CHECK_EQ(events.events[0].reason, UpstreamMarkReplayReason::StaleOrForeign);

    port.stop();
    CHECK_FALSE(port.mark({3, 0, 0}, false));
    REQUIRE_EQ(events.count, 2u);
    CHECK_EQ(events.events[1].reason, UpstreamMarkReplayReason::Unavailable);
}

TEST(control_plane_mutation, compatible_retained_generations_share_override_updates) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    port.reset(3, true, &old_config);
    MarkReplayEvents replay_events;
    port.set_upstream_mark_replay_sink(&collect_mark_replay_event, &replay_events);
    REQUIRE(port.mark({3, 0, 0}, false));

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));
    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Unhealthy);

    REQUIRE(port.mark({3, 0, 0}, true));
    REQUIRE_EQ(replay_events.count, 2u);
    CHECK_EQ(replay_events.events[1].peer_config_generation, 4u);
    CHECK(replay_events.events[1].peer_published_version > 0u);
    CHECK_EQ(port.manual_health({3, 0, 0}), ManualHealthOverride::Healthy);
    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Healthy);

    REQUIRE(port.mark({4, 0, 0}, false));
    CHECK_EQ(port.manual_health({3, 0, 0}), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Unhealthy);
}

TEST(control_plane_mutation, activation_carries_overrides_across_backend_reordering) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(old_config.add_upstream_backend(0, 0x7f000001u, 8100));
    port.reset(3, true, &old_config);
    REQUIRE(port.mark({3, 0, 0}, false));
    REQUIRE(port.mark({3, 0, 1}, true));

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8100).has_value());
    REQUIRE(new_config.add_upstream_backend(0, 0x7f000001u, 8000));
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Healthy);
    CHECK_EQ(port.manual_health({4, 0, 1}), ManualHealthOverride::Unhealthy);
}

TEST(control_plane_mutation, activation_clamps_oversized_endpoint_counts_before_matching) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    old_config.upstreams[0].addr_count = UpstreamTarget::kMaxBackends + 3;
    port.reset(3, true, &old_config);
    REQUIRE(port.mark({3, 0, 0}, false));
    CHECK_FALSE(port.mark({3, 0, UpstreamTarget::kMaxBackends}, false));

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    new_config.upstreams[0].addr_count = UpstreamTarget::kMaxBackends + 2;
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));
    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.manual_health({4, 0, UpstreamTarget::kMaxBackends}), ManualHealthOverride::None);
}

TEST(control_plane_mutation, activation_matches_duplicate_endpoints_one_to_one) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(old_config.add_upstream_backend(0, 0x7f000001u, 8000));
    port.reset(3, true, &old_config);
    REQUIRE(port.mark({3, 0, 0}, false));
    REQUIRE(port.mark({3, 0, 1}, true));

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(new_config.add_upstream_backend(0, 0x7f000001u, 8000));
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.manual_health({4, 0, 1}), ManualHealthOverride::Healthy);
    REQUIRE(port.mark({3, 0, 0}, true));
    REQUIRE(port.mark({3, 0, 1}, false));
    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Healthy);
    CHECK_EQ(port.manual_health({4, 0, 1}), ManualHealthOverride::Unhealthy);
}

TEST(control_plane_mutation, activation_matches_duplicate_upstreams_one_to_one) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8100).has_value());
    port.reset(3, true, &old_config);
    REQUIRE(port.mark({3, 0, 0}, false));
    REQUIRE(port.mark({3, 1, 0}, true));

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8100).has_value());
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Healthy);
    CHECK_EQ(port.manual_health({4, 1, 0}), ManualHealthOverride::Unhealthy);
    REQUIRE(port.mark({3, 0, 0}, true));
    REQUIRE(port.mark({3, 1, 0}, false));
    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.manual_health({4, 1, 0}), ManualHealthOverride::Healthy);
}

TEST(control_plane_mutation, activation_globally_matches_overlapping_duplicate_upstreams) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(old_config.add_upstream_backend(0, 0x7f000001u, 8100));
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    port.reset(3, true, &old_config);
    REQUIRE(port.mark({3, 0, 0}, false));
    REQUIRE(port.mark({3, 0, 1}, true));
    REQUIRE(port.mark({3, 1, 0}, true));

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(new_config.add_upstream_backend(1, 0x7f000001u, 8100));
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Healthy);
    CHECK_EQ(port.manual_health({4, 1, 0}), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.manual_health({4, 1, 1}), ManualHealthOverride::Healthy);
}

TEST(control_plane_mutation, activation_compares_full_upstream_name_identity) {
    constexpr char kOldName[] = "abcdefghijklmnopqrstuvwxyz12345-old";
    constexpr char kNewName[] = "abcdefghijklmnopqrstuvwxyz12345-new";
    static_assert(sizeof(kOldName) > UpstreamTarget::kMaxUpstreamNameLen);
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(old_config.add_upstream(kOldName, 0x7f000001u, 8000).has_value());
    port.reset(3, true, &old_config);
    REQUIRE(port.mark({3, 0, 0}, false));

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    REQUIRE(new_config.add_upstream(kNewName, 0x7f000001u, 8000).has_value());
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    CHECK_EQ(old_config.upstreams[0].name_len, new_config.upstreams[0].name_len);
    CHECK_EQ(memcmp(old_config.upstreams[0].name,
                    new_config.upstreams[0].name,
                    old_config.upstreams[0].name_len),
             0);
    CHECK_NE(old_config.upstreams[0].name_identity, new_config.upstreams[0].name_identity);
    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::None);
}

TEST(control_plane_mutation, activation_keys_runtime_tokens_by_stable_identity) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(old_config.add_upstream("orders", 0x7f000001u, 9000).has_value());
    port.reset(3, true, &old_config);

    const u16 old_users = port.upstream_allocation_for_config(&old_config, 0);
    const u16 old_users_endpoint = port.endpoint_allocation_for_config(&old_config, 0, 0);
    REQUIRE_NE(old_users, ControlPlaneMutationPort::kInvalidAllocation);
    REQUIRE_NE(old_users_endpoint, ControlPlaneMutationPort::kInvalidAllocation);

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    // Reuse the old numeric slot and address for a different upstream while
    // moving the compatible upstream to another index.
    REQUIRE(new_config.add_upstream("replacement", 0x7f000001u, 8000).has_value());
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    const u16 replacement = port.upstream_allocation_for_config(&new_config, 0);
    const u16 moved_users = port.upstream_allocation_for_config(&new_config, 1);
    CHECK_EQ(moved_users, old_users);
    CHECK_NE(replacement, old_users);
    CHECK_EQ(port.endpoint_allocation_for_config(&new_config, 1, 0), old_users_endpoint);
    CHECK_NE(port.endpoint_allocation_for_config(&new_config, 0, 0), old_users_endpoint);

    UpstreamConcurrency concurrency;
    concurrency.reset();
    // Even the unlimited predecessor is accounted against the shared token, so
    // lowering the compatible successor to one observes the request already in flight.
    REQUIRE(concurrency.try_acquire(old_users, ~u32{0}));
    CHECK_FALSE(concurrency.try_acquire(moved_users, 1));
    CHECK(concurrency.try_acquire(replacement, 1));
    concurrency.release(replacement);
    concurrency.release(old_users);
    CHECK(concurrency.try_acquire(moved_users, 1));
    concurrency.release(moved_users);
}

TEST(control_plane_mutation, activation_carries_overrides_across_marking_policy_changes) {
    for (u64 candidate_policy : {u64{0}, u64{22}}) {
        ControlPlaneMutationPort port;
        RouteConfig old_config;
        REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
        old_config.upstreams[0].marking_policy_identity = 11;
        port.reset(3, true, &old_config);
        REQUIRE(port.mark({3, 0, 0}, false));
        const u16 old_allocation = port.endpoint_allocation_for_config(&old_config, 0, 0);
        const u64 old_incarnation = port.endpoint_incarnation_for_config(&old_config, 0, 0);

        u64 id = 0;
        REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
        ReloadRequest request{};
        REQUIRE(port.take_reload(&request));
        RouteConfig new_config;
        REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8000).has_value());
        new_config.upstreams[0].marking_policy_identity = candidate_policy;
        REQUIRE(port.complete_reload(
            id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

        CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Unhealthy);
        CHECK_NE(port.endpoint_allocation_for_config(&new_config, 0, 0), old_allocation);
        CHECK_NE(port.endpoint_incarnation_for_config(&new_config, 0, 0), old_incarnation);
        CHECK_EQ(port.endpoint_health_seed_incarnation_for_config(&new_config, 0, 0),
                 old_incarnation);
    }
}

TEST(control_plane_mutation, activation_carries_overrides_for_same_marking_policy) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(old_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    old_config.upstreams[0].marking_policy_identity = 11;
    port.reset(3, true, &old_config);
    REQUIRE(port.mark({3, 0, 0}, false));
    const u16 old_allocation = port.endpoint_allocation_for_config(&old_config, 0, 0);
    const u64 old_incarnation = port.endpoint_incarnation_for_config(&old_config, 0, 0);

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    RouteConfig new_config;
    REQUIRE(new_config.add_upstream("users", 0x7f000001u, 8000).has_value());
    new_config.upstreams[0].marking_policy_identity = 11;
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    CHECK_EQ(port.manual_health({4, 0, 0}), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.endpoint_allocation_for_config(&new_config, 0, 0), old_allocation);
    CHECK_EQ(port.endpoint_incarnation_for_config(&new_config, 0, 0), old_incarnation);
}

TEST(control_plane_mutation, activation_rejects_skipped_generation) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    RouteConfig new_config;
    REQUIRE(add_upstreams(&old_config, 1));
    REQUIRE(add_upstreams(&new_config, 1));
    port.reset(3, true, &old_config);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    CHECK_FALSE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 5, &new_config));
    CHECK_EQ(port.active_generation(), 3u);
    CHECK_EQ(port.state(), ReloadAdmissionState::InFlight);
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));
}

TEST(control_plane_mutation, activation_terminal_remains_addressable_after_reopening) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    RouteConfig new_config;
    REQUIRE(add_upstreams(&old_config, 1));
    REQUIRE(add_upstreams(&new_config, 1));
    port.reset(3, true, &old_config);
    u64 activation_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &activation_id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(port.complete_reload(
        activation_id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));
    REQUIRE(port.finish_activation(activation_id));

    u64 next_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Signal, &next_id));
    u64 busy_id = 0;
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &busy_id));
    CHECK_EQ(port.last_record().request_id, busy_id);
    const auto activation = port.record_for_request(activation_id);
    REQUIRE(activation.valid);
    CHECK_EQ(activation.outcome, ReloadTerminalOutcome::Activated);
    CHECK_EQ(activation.old_generation, 3u);
    CHECK_EQ(activation.new_generation, 4u);
}

TEST(control_plane_mutation, manual_health_rejects_foreign_slots_and_preserves_neighbors) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(add_upstreams(&config, 2));
    REQUIRE(config.add_upstream_backend(1, 0x7f000001u, 8100));
    port.reset(9, false, &config);
    const ServerIdentity first{9, 1, 0};
    const ServerIdentity second{9, 1, 1};
    REQUIRE(port.mark(first, false));
    REQUIRE(port.mark(second, true));
    CHECK_EQ(port.manual_health(first), ManualHealthOverride::Unhealthy);
    CHECK_EQ(port.manual_health(second), ManualHealthOverride::Healthy);
    CHECK(!port.mark({9, RouteConfig::kMaxUpstreams, 0}, true));
    CHECK(!port.mark({9, 0, UpstreamTarget::kMaxBackends}, true));
    CHECK(!port.mark({9, 0, 1}, true));
    CHECK(!port.mark({9, 2, 0}, true));
    CHECK(!port.mark({8, 1, 0}, true));
}

TEST(control_plane_mutation, every_successful_mark_advances_generation_scoped_version) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(add_upstreams(&config, 1));
    port.reset(9, false, &config);
    const ServerIdentity server{9, 0, 0};
    u64 version = 99;
    CHECK_EQ(port.manual_health(server, &version), ManualHealthOverride::None);
    CHECK_EQ(version, 0u);
    REQUIRE(port.mark(server, true));
    CHECK_EQ(port.manual_health(server, &version), ManualHealthOverride::Healthy);
    CHECK_EQ(version, 1u);
    REQUIRE(port.mark(server, true));
    CHECK_EQ(port.manual_health(server, &version), ManualHealthOverride::Healthy);
    CHECK_EQ(version, 2u);
    REQUIRE(port.mark(server, false));
    CHECK_EQ(port.manual_health(server, &version), ManualHealthOverride::Unhealthy);
    CHECK_EQ(version, 3u);
}

TEST(control_plane_mutation, backend_override_snapshot_uses_one_table_version) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(add_upstreams(&config, 1));
    REQUIRE(config.add_upstream_backend(0, 0x7f000001u, 8100));
    port.reset(9, false, &config);
    REQUIRE(port.mark({9, 0, 0}, false));
    REQUIRE(port.mark({9, 0, 1}, true));

    ManualHealthOverride snapshot[UpstreamTarget::kMaxBackends]{};
    u64 version = 0;
    REQUIRE(port.manual_health_snapshot(9, 0, 2, snapshot, &version));
    CHECK_EQ(version, 2u);
    CHECK_EQ(snapshot[0], ManualHealthOverride::Unhealthy);
    CHECK_EQ(snapshot[1], ManualHealthOverride::Healthy);
    CHECK_FALSE(port.manual_health_snapshot(8, 0, 2, snapshot));
}

TEST(control_plane_mutation, manual_health_committed_fallback_preserves_bank_version) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(add_upstreams(&config, 1));
    port.reset(9, false, &config);
    const ServerIdentity server{9, 0, 0};
    REQUIRE(port.mark(server, false));

    ControlPlaneMutationPortTestAccess::set_override_sequence(port, 0, 3);
    // Stage a later write in the inactive slot without publishing its descriptor.
    // The committed reader must continue using the descriptor-selected slot.
    ControlPlaneMutationPortTestAccess::stage_committed_override(port, 0, server, true, 5);
    // Simulate an unrelated backend having advanced the bank version while
    // this backend's committed descriptor still names its last change.
    ControlPlaneMutationPortTestAccess::set_override_version(port, 0, 2);
    u64 version = 0;
    CHECK_EQ(port.manual_health(server, &version), ManualHealthOverride::Unhealthy);
    CHECK_EQ(version, 2u);
    ControlPlaneMutationPortTestAccess::set_override_sequence(port, 0, 4);
}

TEST(control_plane_mutation, committed_fallback_never_pairs_future_version_with_old_verdict) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(add_upstreams(&config, 1));
    port.reset(9, false, &config);
    const ServerIdentity server{9, 0, 0};
    REQUIRE(port.mark(server, false));

    ControlPlaneMutationPortTestAccess::set_override_sequence(port, 0, 3);
    ControlPlaneMutationPortTestAccess::publish_committed_override(port, 0, server, true, 2);
    u64 version = 0;
    CHECK_EQ(port.manual_health(server, &version), ManualHealthOverride::Healthy);
    CHECK_EQ(version, 2u);

    ControlPlaneMutationPortTestAccess::set_override_version(port, 0, 2);
    CHECK_EQ(port.manual_health(server, &version), ManualHealthOverride::Healthy);
    CHECK_EQ(version, 2u);
    ControlPlaneMutationPortTestAccess::set_override_sequence(port, 0, 4);
}

TEST(control_plane_mutation, snapshot_exhaustion_preserves_committed_unhealthy_verdict) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(add_upstreams(&config, 1));
    REQUIRE(config.add_upstream_backend(0, 0x7f000001u, 8100));
    port.reset(9, false, &config);
    const ServerIdentity protected_server{9, 0, 0};
    const ServerIdentity noisy_server{9, 0, 1};
    REQUIRE(port.mark(protected_server, false));

    std::atomic<bool> start{false};
    std::atomic<bool> running{true};
    std::thread writer([&] {
        while (!start.load(std::memory_order_acquire)) {
        }
        bool healthy = false;
        while (running.load(std::memory_order_acquire)) {
            (void)port.mark(noisy_server, healthy);
            healthy = !healthy;
        }
    });
    start.store(true, std::memory_order_release);
    for (u32 attempt = 0; attempt < 10000; attempt++)
        CHECK_EQ(port.manual_health(protected_server), ManualHealthOverride::Unhealthy);
    running.store(false, std::memory_order_release);
    writer.join();
    u64 version = 0;
    CHECK_EQ(port.manual_health(protected_server, &version), ManualHealthOverride::Unhealthy);
    CHECK_EQ(version, ControlPlaneMutationPortTestAccess::override_version(port, 0));
}

TEST(control_plane_mutation, activation_reserves_terminal_capacity_before_publication) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    RouteConfig new_config;
    REQUIRE(add_upstreams(&old_config, 1));
    REQUIRE(add_upstreams(&new_config, 1));
    port.reset(3, true, &old_config);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));
    REQUIRE(ControlPlaneMutationPortTestAccess::activation_terminal_slot_reserved(port));

    constexpr u32 kReservations = ControlPlaneMutationPortTestAccess::record_slot_count() - 1;
    ControlPlaneMutationPortTestAccess::BusyReservation reservations[kReservations]{};
    for (u32 i = 0; i < kReservations; i++) {
        reservations[i] = ControlPlaneMutationPortTestAccess::reserve_busy(port, id + i);
        REQUIRE(reservations[i].valid);
    }

    std::atomic<bool> returned{false};
    bool finished = false;
    std::thread finisher([&] {
        finished = port.finish_activation(id);
        returned.store(true, std::memory_order_release);
    });
    for (u32 attempt = 0; attempt < 10000 && !returned.load(std::memory_order_acquire); attempt++)
        std::this_thread::yield();
    const bool returned_without_predecessors = returned.load(std::memory_order_acquire);
    if (!returned_without_predecessors)
        for (const auto& reservation : reservations)
            ControlPlaneMutationPortTestAccess::release_busy(port, reservation);
    finisher.join();
    CHECK(returned_without_predecessors);
    REQUIRE(finished);
    const auto activated = port.record_for_request(id);
    REQUIRE(activated.valid);
    CHECK_EQ(activated.outcome, ReloadTerminalOutcome::Activated);
    if (returned_without_predecessors)
        for (const auto& reservation : reservations)
            ControlPlaneMutationPortTestAccess::release_busy(port, reservation);
    CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::Activated);
}

TEST(control_plane_mutation, activation_reserves_the_actual_next_history_slot) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    RouteConfig new_config;
    REQUIRE(add_upstreams(&old_config, 1));
    REQUIRE(add_upstreams(&new_config, 1));
    port.reset(3, true, &old_config);
    ControlPlaneMutationPortTestAccess::seed_full_sequential_history(port);

    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    CHECK_EQ(ControlPlaneMutationPortTestAccess::activation_terminal_slot(port), 1u);
    CHECK_FALSE(port.record_for_request(1).valid);
    CHECK(port.record_for_request(127).valid);
}

TEST(control_plane_mutation, displaced_ticket_claims_evict_the_globally_oldest_record) {
    ControlPlaneMutationPort port;
    port.reset(3, true);
    ControlPlaneMutationPortTestAccess::seed_displaced_full_history(port);

    const auto reservation = ControlPlaneMutationPortTestAccess::reserve_busy(port, 130);
    REQUIRE(reservation.valid);
    CHECK_EQ(reservation.request_id, 131u);
    REQUIRE(ControlPlaneMutationPortTestAccess::publish_busy(port, reservation));

    CHECK_FALSE(port.record_for_request(1).valid);
    CHECK(port.record_for_request(4).valid);
    CHECK(port.record_for_request(131).valid);
}

TEST(control_plane_mutation, stop_claims_terminal_slot_before_stopping_transition) {
    ControlPlaneMutationPort port;
    port.reset(9, true);
    u64 accepted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &accepted_id));

    ControlPlaneMutationPortTestAccess::BusyReservation reservations[128]{};
    for (u32 i = 0; i < 128; i++) {
        reservations[i] = ControlPlaneMutationPortTestAccess::reserve_busy(port, accepted_id + i);
        REQUIRE(reservations[i].valid);
    }

    std::thread stopper([&] { port.stop(); });
    while (ControlPlaneMutationPortTestAccess::stopping(port) == 0) {
    }
    CHECK_EQ(ControlPlaneMutationPortTestAccess::reload_state(port), ReloadAdmissionState::Pending);
    for (const auto& reservation : reservations)
        ControlPlaneMutationPortTestAccess::release_busy(port, reservation);
    stopper.join();

    const auto stopped = port.record_for_request(accepted_id);
    REQUIRE(stopped.valid);
    CHECK_EQ(stopped.outcome, ReloadTerminalOutcome::Stopped);
    CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::Stopped);
}

TEST(control_plane_mutation, signal_waits_for_transient_record_slot_pressure) {
    ControlPlaneMutationPort port;
    port.reset(9, true);
    u64 accepted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &accepted_id));
    ControlPlaneMutationPortTestAccess::BusyReservation reservations[128]{};
    for (u32 i = 0; i < 128; i++) {
        reservations[i] = ControlPlaneMutationPortTestAccess::reserve_busy(port, accepted_id + i);
        REQUIRE(reservations[i].valid);
    }
    std::atomic<bool> returned{false};
    u64 signal_id = 0;
    bool admitted = false;
    std::thread signal([&] {
        admitted = port.request_reload(ReloadRequestSource::Signal, &signal_id);
        returned.store(true, std::memory_order_release);
    });
    CHECK_FALSE(returned.load(std::memory_order_acquire));
    for (const auto& reservation : reservations)
        ControlPlaneMutationPortTestAccess::release_busy(port, reservation);
    signal.join();
    CHECK(returned.load(std::memory_order_acquire));
    CHECK_FALSE(admitted);
    CHECK_GT(signal_id, accepted_id);
    CHECK_EQ(port.record_for_request(signal_id).outcome, ReloadTerminalOutcome::Busy);
}

TEST(control_plane_mutation, busy_history_reserves_final_ticket_for_accepted_terminal) {
    ControlPlaneMutationPort port;
    port.reset(9, true);
    u64 accepted_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &accepted_id));
    ControlPlaneMutationPortTestAccess::set_record_frontier(
        port, ControlPlaneMutationPortTestAccess::max_record_ticket() - 1);

    u64 busy_id = 99;
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &busy_id));
    CHECK_EQ(busy_id, ControlPlaneMutationPort::kCounterExhaustedRequestId);
    CHECK_EQ(port.record_for_request(busy_id).outcome, ReloadTerminalOutcome::CounterExhausted);
    port.stop();

    const auto stopped = port.record_for_request(accepted_id);
    REQUIRE(stopped.valid);
    CHECK_EQ(stopped.outcome, ReloadTerminalOutcome::Stopped);
    CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::Stopped);
}

TEST(control_plane_mutation, stop_waits_for_the_active_override_writer) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(add_upstreams(&config, 1));
    port.reset(9, false, &config);
    ControlPlaneMutationPortTestAccess::set_override_sequence(port, 0, 1);

    std::atomic<bool> returned{false};
    std::thread stopper([&] {
        port.stop();
        returned.store(true, std::memory_order_release);
    });
    while (ControlPlaneMutationPortTestAccess::stopping(port) == 0) {
    }
    CHECK_FALSE(returned.load(std::memory_order_acquire));
    ControlPlaneMutationPortTestAccess::set_override_sequence(port, 0, 2);
    stopper.join();

    CHECK(returned.load(std::memory_order_acquire));
    CHECK_EQ(ControlPlaneMutationPortTestAccess::stopping(port), 2u);
    CHECK_FALSE(port.mark({9, 0, 0}, true));
}

TEST(control_plane_mutation, stop_waits_for_unclaimed_request_busy_publication) {
    ControlPlaneMutationPort port;
    port.reset(5, true);
    ControlPlaneMutationPortTestAccess::begin_unclaimed_busy_publication(port);

    std::atomic<bool> returned{false};
    std::thread stopper([&] {
        port.stop();
        returned.store(true, std::memory_order_release);
    });
    while (port.state() != ReloadAdmissionState::Stopping) {
    }
    CHECK_FALSE(returned.load(std::memory_order_acquire));

    ControlPlaneMutationPortTestAccess::finish_unclaimed_busy_publication(port);
    stopper.join();
    CHECK(returned.load(std::memory_order_acquire));
    CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
}

TEST(control_plane_mutation, isolation_reset_preserves_active_server_membership) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(add_upstreams(&config, 2));
    REQUIRE(config.add_upstream_backend(1, 0x7f000001u, 8100));
    port.reset(9, true, &config);
    const ServerIdentity server{9, 1, 1};
    REQUIRE(port.mark(server, false));

    port.reset_preserving_membership(9, true);
    CHECK_EQ(port.manual_health(server), ManualHealthOverride::None);
    REQUIRE(port.mark(server, true));
    CHECK_EQ(port.manual_health(server), ManualHealthOverride::Healthy);
}

TEST(control_plane_mutation, stop_terminalizes_an_accepted_request_once) {
    ControlPlaneMutationPort port;
    RouteConfig config;
    REQUIRE(add_upstreams(&config, 1));
    port.reset(5, true, &config);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    port.stop();
    CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
    u64 stopped_signal_id = 0;
    CHECK(!port.request_reload(ReloadRequestSource::Signal, &stopped_signal_id));
    CHECK_GT(stopped_signal_id, id);
    CHECK_EQ(port.last_record().request_id, stopped_signal_id);
    CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::Stopped);
    CHECK(!port.mark({5, 0, 0}, true));
    const auto record = port.last_record();
    REQUIRE(record.valid);
    CHECK_EQ(record.request_id, stopped_signal_id);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Stopped);
    port.stop();
    CHECK_EQ(port.last_record().request_id, stopped_signal_id);
}

TEST(control_plane_mutation, stop_terminalizes_a_failure_waiting_to_publish) {
    ControlPlaneMutationPort port;
    port.reset(5, true);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(ControlPlaneMutationPortTestAccess::begin_completion(port));

    port.stop();
    CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
    const auto stopped = port.last_record();
    REQUIRE(stopped.valid);
    CHECK_EQ(stopped.request_id, id);
    CHECK_EQ(stopped.outcome, ReloadTerminalOutcome::Stopped);

    CHECK_FALSE(port.complete_reload(id, request.source, ReloadTerminalOutcome::CompileFailed));
    const auto after_completion = port.last_record();
    CHECK_EQ(after_completion.request_id, id);
    CHECK_EQ(after_completion.outcome, ReloadTerminalOutcome::Stopped);
}

TEST(control_plane_mutation, stop_prevents_inflight_completion_from_publishing) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    REQUIRE(add_upstreams(&old_config, 1));
    port.reset(5, true, &old_config);
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));

    port.stop();
    RouteConfig new_config;
    REQUIRE(add_upstreams(&new_config, 1));
    CHECK_FALSE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 6, &new_config));
    CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
    CHECK_EQ(port.active_generation(), 5u);
    const auto record = port.last_record();
    REQUIRE(record.valid);
    CHECK_EQ(record.request_id, id);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Stopped);
    CHECK_EQ(record.new_generation, 0u);
}

TEST(control_plane_mutation, stop_racing_admission_never_leaves_pending_work) {
    for (u32 iteration = 0; iteration < 256; iteration++) {
        ControlPlaneMutationPort port;
        port.reset(5, true);
        std::atomic<bool> start{false};
        std::thread requester([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            (void)port.request_reload(ReloadRequestSource::Route);
        });
        std::thread stopper([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            port.stop();
        });
        start.store(true, std::memory_order_release);
        requester.join();
        stopper.join();
        CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
        ReloadRequest request{};
        CHECK_FALSE(port.take_reload(&request));
    }
}

TEST(control_plane_mutation, stop_racing_take_publishes_terminal_before_return) {
    for (u32 iteration = 0; iteration < 512; iteration++) {
        ControlPlaneMutationPort port;
        port.reset(5, true);
        u64 id = 0;
        REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
        std::atomic<bool> start{false};
        ReloadRequest request{};
        std::thread taker([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            (void)port.take_reload(&request);
        });
        std::thread stopper([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            port.stop();
        });
        start.store(true, std::memory_order_release);
        stopper.join();
        const auto stopped = port.last_record();
        REQUIRE(stopped.valid);
        CHECK_EQ(stopped.request_id, id);
        CHECK_EQ(stopped.outcome, ReloadTerminalOutcome::Stopped);
        taker.join();
    }
}

TEST(control_plane_mutation, stop_racing_idle_signal_has_explicit_terminal_outcome) {
    for (u32 iteration = 0; iteration < 256; iteration++) {
        ControlPlaneMutationPort port;
        port.reset(5, true);
        std::atomic<bool> start{false};
        bool admitted = false;
        u64 signal_id = 99;
        std::thread requester([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            admitted = port.request_reload(ReloadRequestSource::Signal, &signal_id);
        });
        std::thread stopper([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            port.stop();
        });
        start.store(true, std::memory_order_release);
        requester.join();
        stopper.join();

        CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
        if (admitted) {
            CHECK_EQ(signal_id, 1u);
            const auto stopped = port.record_for_request(signal_id);
            REQUIRE(stopped.valid);
            CHECK_EQ(stopped.outcome, ReloadTerminalOutcome::Stopped);
        } else {
            CHECK_NE(signal_id, 0u);
            const auto terminal = port.record_for_request(signal_id);
            REQUIRE(terminal.valid);
            CHECK(terminal.outcome == ReloadTerminalOutcome::Stopped ||
                  terminal.outcome == ReloadTerminalOutcome::AdmissionContended);
        }
    }
}

TEST(control_plane_mutation, stop_preserves_activation_completion_boundary) {
    ControlPlaneMutationPort port;
    RouteConfig old_config;
    RouteConfig new_config;
    REQUIRE(add_upstreams(&old_config, 1));
    REQUIRE(add_upstreams(&new_config, 1));
    port.reset(3, true, &old_config);
    REQUIRE(port.mark({3, 0, 0}, false));
    u64 id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(
        port.complete_reload(id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

    std::atomic<bool> stopped{false};
    std::thread stopper([&] {
        port.stop();
        stopped.store(true, std::memory_order_release);
    });
    while (ControlPlaneMutationPortTestAccess::stopping(port) == 0) {
    }
    CHECK_FALSE(stopped.load(std::memory_order_acquire));
    CHECK_EQ(port.state(), ReloadAdmissionState::Completing);
    CHECK_FALSE(port.last_record().valid);
    REQUIRE(port.finish_activation(id));
    stopper.join();
    CHECK(stopped.load(std::memory_order_acquire));
    CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
    CHECK_EQ(port.manual_health({3, 0, 0}), ManualHealthOverride::None);
    const auto record = port.last_record();
    REQUIRE(record.valid);
    CHECK_EQ(record.outcome, ReloadTerminalOutcome::Activated);
    CHECK_EQ(record.old_generation, 3u);
    CHECK_EQ(record.new_generation, 4u);
}

TEST(control_plane_mutation, shutdown_racing_activation_finish_keeps_activated_terminal) {
    for (u32 iteration = 0; iteration < 256; iteration++) {
        ControlPlaneMutationPort port;
        RouteConfig old_config;
        RouteConfig new_config;
        REQUIRE(add_upstreams(&old_config, 1));
        REQUIRE(add_upstreams(&new_config, 1));
        port.reset(3, true, &old_config);
        u64 id = 0;
        REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
        ReloadRequest request{};
        REQUIRE(port.take_reload(&request));
        REQUIRE(port.complete_reload(
            id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config));

        std::atomic<bool> start{false};
        bool finished = false;
        std::thread finisher([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            finished = port.finish_activation(id);
        });
        std::thread stopper([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            port.stop();
        });
        start.store(true, std::memory_order_release);
        finisher.join();
        stopper.join();

        REQUIRE(finished);
        CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
        CHECK_EQ(port.active_generation(), 4u);
        const auto record = port.last_record();
        REQUIRE(record.valid);
        CHECK_EQ(record.request_id, id);
        CHECK_EQ(record.outcome, ReloadTerminalOutcome::Activated);
    }
}

TEST(control_plane_mutation, shutdown_and_activation_publication_have_one_winner) {
    for (u32 iteration = 0; iteration < 256; iteration++) {
        ControlPlaneMutationPort port;
        RouteConfig old_config;
        RouteConfig new_config;
        REQUIRE(add_upstreams(&old_config, 1));
        REQUIRE(add_upstreams(&new_config, 1));
        port.reset(3, true, &old_config);
        u64 id = 0;
        REQUIRE(port.request_reload(ReloadRequestSource::Route, &id));
        ReloadRequest request{};
        REQUIRE(port.take_reload(&request));

        std::atomic<bool> start{false};
        bool activated = false;
        std::thread publisher([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            activated = port.complete_reload(
                id, request.source, ReloadTerminalOutcome::Activated, 4, &new_config);
        });
        std::thread stopper([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            port.stop();
        });
        start.store(true, std::memory_order_release);
        publisher.join();

        if (activated) {
            CHECK_EQ(port.active_generation(), 4u);
            CHECK_EQ(port.state(), ReloadAdmissionState::Completing);
            REQUIRE(port.finish_activation(id));
            stopper.join();
            CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
            CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::Activated);
        } else {
            stopper.join();
            CHECK_EQ(port.active_generation(), 3u);
            CHECK_EQ(port.state(), ReloadAdmissionState::Stopping);
            CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::Stopped);
        }
    }
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

    ReloadRequest request{};
    REQUIRE(port.take_reload(&request));
    REQUIRE(
        port.complete_reload(request.id, request.source, ReloadTerminalOutcome::ValidationFailed));
    u64 next_id = 0;
    REQUIRE(port.request_reload(ReloadRequestSource::Route, &next_id));
    CHECK_EQ(next_id, 2u);  // rejected route contenders consume no request IDs
}

TEST(control_plane_mutation, failed_completion_claims_a_terminal_slot_before_reopening_admission) {
    ControlPlaneMutationPort failed;
    failed.reset(1, true);
    u64 failed_id = 0;
    REQUIRE(failed.request_reload(ReloadRequestSource::Route, &failed_id));
    ReloadRequest failed_request{};
    REQUIRE(failed.take_reload(&failed_request));
    ControlPlaneMutationPortTestAccess::fill_record_slots_with_newer_tickets(failed, 1000);

    CHECK_FALSE(failed.complete_reload(
        failed_id, failed_request.source, ReloadTerminalOutcome::ValidationFailed));
    CHECK_EQ(failed.state(), ReloadAdmissionState::InFlight);
}

TEST(control_plane_mutation, route_authority_disable_linearizes_with_idle_admission) {
    for (u32 iteration = 0; iteration < 256; iteration++) {
        ControlPlaneMutationPort port;
        port.reset(1, true);
        std::atomic<bool> start{false};
        bool disabled = false;
        bool admitted = false;
        std::thread disabler([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            disabled = port.set_route_reload_enabled(false);
        });
        std::thread requester([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            admitted = port.request_reload(ReloadRequestSource::Route);
        });
        start.store(true, std::memory_order_release);
        disabler.join();
        requester.join();

        CHECK_NE(disabled, admitted);
        if (disabled) {
            CHECK_FALSE(port.route_reload_enabled());
            CHECK_FALSE(port.request_reload(ReloadRequestSource::Route));
            u64 signal_id = 0;
            REQUIRE(port.request_reload(ReloadRequestSource::Signal, &signal_id));
            CHECK_EQ(signal_id, 1u);
        } else {
            CHECK(port.route_reload_enabled());
            CHECK_EQ(port.state(), ReloadAdmissionState::Pending);
        }
    }
}

TEST(control_plane_mutation, published_terminal_record_remains_readable_during_slot_reuse) {
    ControlPlaneMutationPort port;
    port.reset(1, true);
    REQUIRE(port.request_reload(ReloadRequestSource::Route));
    u64 busy_id = 0;
    CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &busy_id));
    REQUIRE(port.last_record().valid);

    std::atomic<bool> running{true};
    std::atomic<u32> invalid_reads{0};
    std::thread reader([&] {
        while (running.load(std::memory_order_acquire)) {
            if (!port.last_record().valid) invalid_reads.fetch_add(1, std::memory_order_relaxed);
        }
    });
    for (u32 attempt = 0; attempt < 512; attempt++) {
        CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &busy_id));
    }
    running.store(false, std::memory_order_release);
    reader.join();
    CHECK_EQ(invalid_reads.load(std::memory_order_relaxed), 0u);
    CHECK(port.last_record().valid);
}

TEST(control_plane_mutation, handler_context_latches_only_the_explicit_loop_capability) {
    struct Loop {
        ControlPlaneMutationPort* control_plane_mutation = nullptr;
        void* capture_ring = nullptr;
    } loop;
    ControlPlaneMutationPort port;
    jit::HandlerCtx ctx{};
    loop.control_plane_mutation = &port;
    latch_control_plane_mutation(&loop, &ctx, 0);
    CHECK(ctx.control_plane_mutation == &port);
    loop.capture_ring = &loop;
    latch_control_plane_mutation(&loop, &ctx, 0);
    CHECK(ctx.control_plane_mutation == nullptr);
    loop.capture_ring = nullptr;
    latch_control_plane_mutation<Loop>(nullptr, &ctx, 0);
    CHECK(ctx.control_plane_mutation == nullptr);
}

TEST(control_plane_mutation, terminal_outcome_names_are_explicit_and_stable) {
    CHECK_EQ(std::string(reload_terminal_outcome_name(ReloadTerminalOutcome::None)), "none");
    CHECK_EQ(std::string(reload_terminal_outcome_name(ReloadTerminalOutcome::Activated)),
             "activated");
    CHECK_EQ(std::string(reload_terminal_outcome_name(ReloadTerminalOutcome::CompileFailed)),
             "compile_failed");
    CHECK_EQ(std::string(reload_terminal_outcome_name(ReloadTerminalOutcome::ValidationFailed)),
             "validation_failed");
    CHECK_EQ(std::string(reload_terminal_outcome_name(ReloadTerminalOutcome::Busy)), "busy");
    CHECK_EQ(std::string(reload_terminal_outcome_name(ReloadTerminalOutcome::Stopped)), "stopped");
    CHECK_EQ(std::string(reload_terminal_outcome_name(ReloadTerminalOutcome::AdmissionContended)),
             "admission_contended");
    CHECK_EQ(std::string(reload_terminal_outcome_name(ReloadTerminalOutcome::CounterExhausted)),
             "counter_exhausted");
    CHECK_EQ(std::string(reload_terminal_outcome_name(ReloadTerminalOutcome::SnapshotUnavailable)),
             "snapshot_unavailable");
}

TEST(control_plane_mutation, signal_snapshot_capture_failures_are_terminalized) {
    for (auto capture : {failed_source_capture, oversized_source_capture}) {
        ControlPlaneMutationPort port;
        port.reset(1, true);
        port.set_reload_source_version_capture(capture, nullptr);
        u64 request_id = 0;
        CHECK_FALSE(port.request_reload(ReloadRequestSource::Signal, &request_id));
        CHECK_NE(request_id, 0u);
        CHECK(port.last_record().valid);
        CHECK_EQ(port.last_record().request_id, request_id);
        CHECK_EQ(port.last_record().outcome, ReloadTerminalOutcome::SnapshotUnavailable);
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
