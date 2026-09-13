#pragma once

#include "fixture_worker_protocol.h"
#include <cstdint>

namespace rut::test::fixture_collision_release_protocol {

namespace worker = fixture_worker_protocol;

inline constexpr worker::u16 kCommandFrameType = 55u;
inline constexpr worker::u16 kPhaseFrameType = 56u;
inline constexpr worker::u16 kDecisionFrameType = 57u;
inline constexpr worker::u16 kSettlementFrameType = 58u;
inline constexpr worker::u64 kProfileVersion = 2u;

enum class Profile : worker::u64 { Canonical = 1u };

enum class Phase : worker::u64 {
    ReservationHeld = 1u,
    CollisionNaturallyRejectedEvidenceOpen = 2u,
    EvidenceClosedReservationHeld = 3u,
    ReservationReleased = 4u,
    RetryLive = 5u,
};

enum class DecisionKind : worker::u64 {
    AuthorizeCollisionExec = 1u,
    AuthorizeEvidenceClose = 2u,
    AuthorizeReservationRelease = 3u,
    AuthorizeRetryExec = 4u,
    AuthorizeRetrySettlement = 5u,
    Finish = 6u,
};

enum class SettlementKind : worker::u64 { AttemptSettled = 1u };

struct CommandV2 {
    worker::u64 version = kProfileVersion;
    worker::u64 transaction_id = 0u;
    Profile profile = Profile::Canonical;
    worker::u64 sequence = 0u;
};

struct PhaseV2 {
    worker::u64 version = kProfileVersion;
    worker::u64 transaction_id = 0u;
    Profile profile = Profile::Canonical;
    Phase phase = Phase::ReservationHeld;
    worker::u64 sequence = 1u;
};

struct DecisionV2 {
    worker::u64 version = kProfileVersion;
    worker::u64 transaction_id = 0u;
    Profile profile = Profile::Canonical;
    DecisionKind decision = DecisionKind::AuthorizeCollisionExec;
    Phase for_phase = Phase::ReservationHeld;
    worker::u64 sequence = 2u;
};

struct SettlementV2 {
    worker::u64 version = kProfileVersion;
    worker::u64 transaction_id = 0u;
    Profile profile = Profile::Canonical;
    SettlementKind settlement = SettlementKind::AttemptSettled;
    Phase terminal_phase = Phase::RetryLive;
    worker::u64 sequence = 11u;
};

worker::Frame encode_command(const worker::Token& token, const CommandV2& command);
worker::Frame encode_phase(const worker::Token& token, const PhaseV2& phase);
worker::Frame encode_decision(const worker::Token& token, const DecisionV2& decision);
worker::Frame encode_settlement(const worker::Token& token, const SettlementV2& settlement);

bool decode_command(const worker::Frame& frame,
                    const worker::Token& expected_token,
                    CommandV2& command);
bool decode_phase(const worker::Frame& frame, const worker::Token& expected_token, PhaseV2& phase);
bool decode_decision(const worker::Frame& frame,
                     const worker::Token& expected_token,
                     DecisionV2& decision);
bool decode_settlement(const worker::Frame& frame,
                       const worker::Token& expected_token,
                       SettlementV2& settlement);

enum class State : std::uint8_t {
    AwaitCommand,
    AwaitReservationHeld,
    AwaitCollisionExecAuthorization,
    AwaitCollisionNaturallyRejectedEvidenceOpen,
    AwaitEvidenceCloseAuthorization,
    AwaitEvidenceClosedReservationHeld,
    AwaitReservationReleaseAuthorization,
    AwaitReservationReleased,
    AwaitRetryExecAuthorization,
    AwaitRetryLive,
    AwaitRetrySettlementAuthorization,
    AwaitAttemptSettlement,
    AwaitFinish,
    Complete,
    Failed,
};

class StateMachine {
public:
    bool begin(const worker::Frame& frame, const worker::Token& expected_token);
    bool observe(const worker::Frame& frame, const worker::Token& expected_token);
    bool decide(const worker::Frame& frame, const worker::Token& expected_token);
    bool settle(const worker::Frame& frame, const worker::Token& expected_token);

    State state() const { return state_; }
    worker::u64 transaction_id() const { return transaction_id_; }

private:
    bool accept_command(const CommandV2& command);
    bool accept_phase(const PhaseV2& phase);
    bool accept_decision(const DecisionV2& decision);
    bool accept_settlement(const SettlementV2& settlement);
    bool bound(worker::u64 version, worker::u64 transaction_id, Profile profile) const;
    bool fail();

    State state_ = State::AwaitCommand;
    worker::u64 transaction_id_ = 0u;
};

}  // namespace rut::test::fixture_collision_release_protocol
