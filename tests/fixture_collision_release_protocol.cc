#include "fixture_collision_release_protocol.h"

#include <array>
#include <cstddef>
#include <vector>

namespace rut::test::fixture_collision_release_protocol {
namespace {

using worker::u64;

void append_u64(std::vector<unsigned char>& payload, u64 value) {
    for (unsigned int shift = 0u; shift != 64u; shift += 8u)
        payload.push_back(static_cast<unsigned char>(value >> shift));
}

u64 read_u64(const unsigned char* bytes) {
    u64 value = 0u;
    for (unsigned int shift = 0u; shift != 64u; shift += 8u)
        value |= static_cast<u64>(bytes[shift / 8u]) << shift;
    return value;
}

template <std::size_t Size>
std::vector<unsigned char> encode_fields(const std::array<u64, Size>& fields) {
    std::vector<unsigned char> payload;
    payload.reserve(Size * sizeof(u64));
    for (const u64 field : fields) append_u64(payload, field);
    return payload;
}

template <std::size_t Size>
bool decode_fields(const std::vector<unsigned char>& payload, std::array<u64, Size>& fields) {
    if (payload.size() != Size * sizeof(u64)) return false;
    for (std::size_t index = 0u; index != Size; ++index)
        fields[index] = read_u64(payload.data() + index * sizeof(u64));
    return true;
}

bool valid_profile_value(u64 value) {
    return value == static_cast<u64>(Profile::Canonical);
}

bool valid_phase_value(u64 value) {
    return value >= static_cast<u64>(Phase::ReservationHeld) &&
           value <= static_cast<u64>(Phase::RetryLive);
}

bool valid_decision_value(u64 value) {
    return value >= static_cast<u64>(DecisionKind::AuthorizeCollisionExec) &&
           value <= static_cast<u64>(DecisionKind::Finish);
}

bool valid_settlement_value(u64 value) {
    return value == static_cast<u64>(SettlementKind::AttemptSettled);
}

u64 phase_sequence(Phase phase) {
    switch (phase) {
        case Phase::ReservationHeld:
            return 1u;
        case Phase::CollisionNaturallyRejectedEvidenceOpen:
            return 3u;
        case Phase::EvidenceClosedReservationHeld:
            return 5u;
        case Phase::ReservationReleased:
            return 7u;
        case Phase::RetryLive:
            return 9u;
    }
    return 0u;
}

Phase decision_phase(DecisionKind decision) {
    switch (decision) {
        case DecisionKind::AuthorizeCollisionExec:
            return Phase::ReservationHeld;
        case DecisionKind::AuthorizeEvidenceClose:
            return Phase::CollisionNaturallyRejectedEvidenceOpen;
        case DecisionKind::AuthorizeReservationRelease:
            return Phase::EvidenceClosedReservationHeld;
        case DecisionKind::AuthorizeRetryExec:
            return Phase::ReservationReleased;
        case DecisionKind::AuthorizeRetrySettlement:
        case DecisionKind::Finish:
            return Phase::RetryLive;
    }
    return static_cast<Phase>(0u);
}

u64 decision_sequence(DecisionKind decision) {
    switch (decision) {
        case DecisionKind::AuthorizeCollisionExec:
            return 2u;
        case DecisionKind::AuthorizeEvidenceClose:
            return 4u;
        case DecisionKind::AuthorizeReservationRelease:
            return 6u;
        case DecisionKind::AuthorizeRetryExec:
            return 8u;
        case DecisionKind::AuthorizeRetrySettlement:
            return 10u;
        case DecisionKind::Finish:
            return 12u;
    }
    return 0u;
}

bool valid_command(const CommandV2& command) {
    return command.version == kProfileVersion && command.transaction_id != 0u &&
           command.profile == Profile::Canonical && command.sequence == 0u;
}

bool valid_phase(const PhaseV2& phase) {
    return phase.version == kProfileVersion && phase.transaction_id != 0u &&
           phase.profile == Profile::Canonical && phase.sequence == phase_sequence(phase.phase) &&
           phase.sequence != 0u;
}

bool valid_decision(const DecisionV2& decision) {
    return decision.version == kProfileVersion && decision.transaction_id != 0u &&
           decision.profile == Profile::Canonical &&
           decision.for_phase == decision_phase(decision.decision) &&
           decision.sequence == decision_sequence(decision.decision) && decision.sequence != 0u;
}

bool valid_settlement(const SettlementV2& settlement) {
    return settlement.version == kProfileVersion && settlement.transaction_id != 0u &&
           settlement.profile == Profile::Canonical &&
           settlement.settlement == SettlementKind::AttemptSettled &&
           settlement.terminal_phase == Phase::RetryLive && settlement.sequence == 11u;
}

bool authentic_frame(const worker::Frame& frame,
                     worker::u16 expected_type,
                     const worker::Token& expected_token) {
    return frame.type == expected_type && worker::token_equal(frame.token, expected_token);
}

}  // namespace

worker::Frame encode_command(const worker::Token& token, const CommandV2& command) {
    return {kCommandFrameType,
            token,
            encode_fields<4u>({command.version,
                               command.transaction_id,
                               static_cast<u64>(command.profile),
                               command.sequence})};
}

worker::Frame encode_phase(const worker::Token& token, const PhaseV2& phase) {
    return {kPhaseFrameType,
            token,
            encode_fields<5u>({phase.version,
                               phase.transaction_id,
                               static_cast<u64>(phase.profile),
                               static_cast<u64>(phase.phase),
                               phase.sequence})};
}

worker::Frame encode_decision(const worker::Token& token, const DecisionV2& decision) {
    return {kDecisionFrameType,
            token,
            encode_fields<6u>({decision.version,
                               decision.transaction_id,
                               static_cast<u64>(decision.profile),
                               static_cast<u64>(decision.decision),
                               static_cast<u64>(decision.for_phase),
                               decision.sequence})};
}

worker::Frame encode_settlement(const worker::Token& token, const SettlementV2& settlement) {
    return {kSettlementFrameType,
            token,
            encode_fields<6u>({settlement.version,
                               settlement.transaction_id,
                               static_cast<u64>(settlement.profile),
                               static_cast<u64>(settlement.settlement),
                               static_cast<u64>(settlement.terminal_phase),
                               settlement.sequence})};
}

bool decode_command(const worker::Frame& frame,
                    const worker::Token& expected_token,
                    CommandV2& command) {
    std::array<u64, 4u> fields{};
    if (!authentic_frame(frame, kCommandFrameType, expected_token) ||
        !decode_fields(frame.payload, fields) || fields[0] != kProfileVersion || fields[1] == 0u ||
        !valid_profile_value(fields[2]) || fields[3] != 0u)
        return false;
    const CommandV2 decoded{fields[0], fields[1], static_cast<Profile>(fields[2]), fields[3]};
    if (!valid_command(decoded)) return false;
    command = decoded;
    return true;
}

bool decode_phase(const worker::Frame& frame, const worker::Token& expected_token, PhaseV2& phase) {
    std::array<u64, 5u> fields{};
    if (!authentic_frame(frame, kPhaseFrameType, expected_token) ||
        !decode_fields(frame.payload, fields) || fields[0] != kProfileVersion || fields[1] == 0u ||
        !valid_profile_value(fields[2]) || !valid_phase_value(fields[3]))
        return false;
    const PhaseV2 decoded{fields[0],
                          fields[1],
                          static_cast<Profile>(fields[2]),
                          static_cast<Phase>(fields[3]),
                          fields[4]};
    if (!valid_phase(decoded)) return false;
    phase = decoded;
    return true;
}

bool decode_decision(const worker::Frame& frame,
                     const worker::Token& expected_token,
                     DecisionV2& decision) {
    std::array<u64, 6u> fields{};
    if (!authentic_frame(frame, kDecisionFrameType, expected_token) ||
        !decode_fields(frame.payload, fields) || fields[0] != kProfileVersion || fields[1] == 0u ||
        !valid_profile_value(fields[2]) || !valid_decision_value(fields[3]) ||
        !valid_phase_value(fields[4]))
        return false;
    const DecisionV2 decoded{fields[0],
                             fields[1],
                             static_cast<Profile>(fields[2]),
                             static_cast<DecisionKind>(fields[3]),
                             static_cast<Phase>(fields[4]),
                             fields[5]};
    if (!valid_decision(decoded)) return false;
    decision = decoded;
    return true;
}

bool decode_settlement(const worker::Frame& frame,
                       const worker::Token& expected_token,
                       SettlementV2& settlement) {
    std::array<u64, 6u> fields{};
    if (!authentic_frame(frame, kSettlementFrameType, expected_token) ||
        !decode_fields(frame.payload, fields) || fields[0] != kProfileVersion || fields[1] == 0u ||
        !valid_profile_value(fields[2]) || !valid_settlement_value(fields[3]) ||
        !valid_phase_value(fields[4]))
        return false;
    const SettlementV2 decoded{fields[0],
                               fields[1],
                               static_cast<Profile>(fields[2]),
                               static_cast<SettlementKind>(fields[3]),
                               static_cast<Phase>(fields[4]),
                               fields[5]};
    if (!valid_settlement(decoded)) return false;
    settlement = decoded;
    return true;
}

bool StateMachine::bound(u64 version, u64 transaction_id, Profile profile) const {
    return version == kProfileVersion && transaction_id == transaction_id_ &&
           transaction_id != 0u && profile == Profile::Canonical;
}

bool StateMachine::fail() {
    state_ = State::Failed;
    return false;
}

bool StateMachine::begin(const worker::Frame& frame, const worker::Token& expected_token) {
    CommandV2 command;
    if (!decode_command(frame, expected_token, command)) return fail();
    return accept_command(command);
}

bool StateMachine::observe(const worker::Frame& frame, const worker::Token& expected_token) {
    PhaseV2 phase;
    if (!decode_phase(frame, expected_token, phase)) return fail();
    return accept_phase(phase);
}

bool StateMachine::decide(const worker::Frame& frame, const worker::Token& expected_token) {
    DecisionV2 decision;
    if (!decode_decision(frame, expected_token, decision)) return fail();
    return accept_decision(decision);
}

bool StateMachine::settle(const worker::Frame& frame, const worker::Token& expected_token) {
    SettlementV2 settlement;
    if (!decode_settlement(frame, expected_token, settlement)) return fail();
    return accept_settlement(settlement);
}

bool StateMachine::accept_command(const CommandV2& command) {
    if (state_ != State::AwaitCommand || !valid_command(command)) return fail();
    transaction_id_ = command.transaction_id;
    state_ = State::AwaitReservationHeld;
    return true;
}

bool StateMachine::accept_phase(const PhaseV2& phase) {
    if (!valid_phase(phase) || !bound(phase.version, phase.transaction_id, phase.profile))
        return fail();
    switch (state_) {
        case State::AwaitReservationHeld:
            if (phase.phase != Phase::ReservationHeld) return fail();
            state_ = State::AwaitCollisionExecAuthorization;
            return true;
        case State::AwaitCollisionNaturallyRejectedEvidenceOpen:
            if (phase.phase != Phase::CollisionNaturallyRejectedEvidenceOpen) return fail();
            state_ = State::AwaitEvidenceCloseAuthorization;
            return true;
        case State::AwaitEvidenceClosedReservationHeld:
            if (phase.phase != Phase::EvidenceClosedReservationHeld) return fail();
            state_ = State::AwaitReservationReleaseAuthorization;
            return true;
        case State::AwaitReservationReleased:
            if (phase.phase != Phase::ReservationReleased) return fail();
            state_ = State::AwaitRetryExecAuthorization;
            return true;
        case State::AwaitRetryLive:
            if (phase.phase != Phase::RetryLive) return fail();
            state_ = State::AwaitRetrySettlementAuthorization;
            return true;
        case State::AwaitCommand:
        case State::AwaitCollisionExecAuthorization:
        case State::AwaitEvidenceCloseAuthorization:
        case State::AwaitReservationReleaseAuthorization:
        case State::AwaitRetryExecAuthorization:
        case State::AwaitRetrySettlementAuthorization:
        case State::AwaitAttemptSettlement:
        case State::AwaitFinish:
        case State::Complete:
        case State::Failed:
            return fail();
    }
    return fail();
}

bool StateMachine::accept_decision(const DecisionV2& decision) {
    if (!valid_decision(decision) ||
        !bound(decision.version, decision.transaction_id, decision.profile))
        return fail();
    switch (state_) {
        case State::AwaitCollisionExecAuthorization:
            if (decision.decision != DecisionKind::AuthorizeCollisionExec) return fail();
            state_ = State::AwaitCollisionNaturallyRejectedEvidenceOpen;
            return true;
        case State::AwaitEvidenceCloseAuthorization:
            if (decision.decision != DecisionKind::AuthorizeEvidenceClose) return fail();
            state_ = State::AwaitEvidenceClosedReservationHeld;
            return true;
        case State::AwaitReservationReleaseAuthorization:
            if (decision.decision != DecisionKind::AuthorizeReservationRelease) return fail();
            state_ = State::AwaitReservationReleased;
            return true;
        case State::AwaitRetryExecAuthorization:
            if (decision.decision != DecisionKind::AuthorizeRetryExec) return fail();
            state_ = State::AwaitRetryLive;
            return true;
        case State::AwaitRetrySettlementAuthorization:
            if (decision.decision != DecisionKind::AuthorizeRetrySettlement) return fail();
            state_ = State::AwaitAttemptSettlement;
            return true;
        case State::AwaitFinish:
            if (decision.decision != DecisionKind::Finish) return fail();
            state_ = State::Complete;
            return true;
        case State::AwaitCommand:
        case State::AwaitReservationHeld:
        case State::AwaitCollisionNaturallyRejectedEvidenceOpen:
        case State::AwaitEvidenceClosedReservationHeld:
        case State::AwaitReservationReleased:
        case State::AwaitRetryLive:
        case State::AwaitAttemptSettlement:
        case State::Complete:
        case State::Failed:
            return fail();
    }
    return fail();
}

bool StateMachine::accept_settlement(const SettlementV2& settlement) {
    if (state_ != State::AwaitAttemptSettlement || !valid_settlement(settlement) ||
        !bound(settlement.version, settlement.transaction_id, settlement.profile))
        return fail();
    state_ = State::AwaitFinish;
    return true;
}

}  // namespace rut::test::fixture_collision_release_protocol
