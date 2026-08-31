#include "fixture_collision_release_protocol.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace protocol = rut::test::fixture_collision_release_protocol;
namespace worker = rut::test::fixture_worker_protocol;

namespace {

using Clock = std::chrono::steady_clock;
using worker::u64;
constexpr u64 kTransaction = 0x37702u;

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s\n", message);
    return condition;
}

worker::Token token(unsigned char seed = 0x80u) {
    worker::Token value;
    for (std::size_t index = 0u; index != value.bytes.size(); ++index)
        value.bytes[index] = static_cast<unsigned char>(seed + index);
    return value;
}

protocol::CommandV2 command(u64 transaction = kTransaction) {
    return {protocol::kProfileVersion, transaction, protocol::Profile::Canonical, 0u};
}

u64 phase_sequence(protocol::Phase phase) {
    switch (phase) {
        case protocol::Phase::ReservationHeld:
            return 1u;
        case protocol::Phase::CollisionNaturallyRejectedEvidenceOpen:
            return 3u;
        case protocol::Phase::EvidenceClosedReservationHeld:
            return 5u;
        case protocol::Phase::ReservationReleased:
            return 7u;
        case protocol::Phase::RetryLive:
            return 9u;
    }
    return 0u;
}

protocol::PhaseV2 phase(protocol::Phase kind, u64 transaction = kTransaction) {
    return {protocol::kProfileVersion,
            transaction,
            protocol::Profile::Canonical,
            kind,
            phase_sequence(kind)};
}

protocol::Phase decision_phase(protocol::DecisionKind decision) {
    switch (decision) {
        case protocol::DecisionKind::AuthorizeCollisionExec:
            return protocol::Phase::ReservationHeld;
        case protocol::DecisionKind::AuthorizeEvidenceClose:
            return protocol::Phase::CollisionNaturallyRejectedEvidenceOpen;
        case protocol::DecisionKind::AuthorizeReservationRelease:
            return protocol::Phase::EvidenceClosedReservationHeld;
        case protocol::DecisionKind::AuthorizeRetryExec:
            return protocol::Phase::ReservationReleased;
        case protocol::DecisionKind::AuthorizeRetrySettlement:
        case protocol::DecisionKind::Finish:
            return protocol::Phase::RetryLive;
    }
    return static_cast<protocol::Phase>(0u);
}

u64 decision_sequence(protocol::DecisionKind decision) {
    return 2u * static_cast<u64>(decision);
}

protocol::DecisionV2 decision(protocol::DecisionKind kind, u64 transaction = kTransaction) {
    return {protocol::kProfileVersion,
            transaction,
            protocol::Profile::Canonical,
            kind,
            decision_phase(kind),
            decision_sequence(kind)};
}

protocol::SettlementV2 settlement(u64 transaction = kTransaction) {
    return {protocol::kProfileVersion,
            transaction,
            protocol::Profile::Canonical,
            protocol::SettlementKind::AttemptSettled,
            protocol::Phase::RetryLive,
            11u};
}

bool same(const protocol::CommandV2& left, const protocol::CommandV2& right) {
    return left.version == right.version && left.transaction_id == right.transaction_id &&
           left.profile == right.profile && left.sequence == right.sequence;
}

bool same(const protocol::PhaseV2& left, const protocol::PhaseV2& right) {
    return left.version == right.version && left.transaction_id == right.transaction_id &&
           left.profile == right.profile && left.phase == right.phase &&
           left.sequence == right.sequence;
}

bool same(const protocol::DecisionV2& left, const protocol::DecisionV2& right) {
    return left.version == right.version && left.transaction_id == right.transaction_id &&
           left.profile == right.profile && left.decision == right.decision &&
           left.for_phase == right.for_phase && left.sequence == right.sequence;
}

bool same(const protocol::SettlementV2& left, const protocol::SettlementV2& right) {
    return left.version == right.version && left.transaction_id == right.transaction_id &&
           left.profile == right.profile && left.settlement == right.settlement &&
           left.terminal_phase == right.terminal_phase && left.sequence == right.sequence;
}

void append_u16(std::vector<unsigned char>& bytes, worker::u16 value) {
    bytes.push_back(static_cast<unsigned char>(value));
    bytes.push_back(static_cast<unsigned char>(value >> 8u));
}

void append_u32(std::vector<unsigned char>& bytes, worker::u32 value) {
    for (unsigned int shift = 0u; shift != 32u; shift += 8u)
        bytes.push_back(static_cast<unsigned char>(value >> shift));
}

void append_u64(std::vector<unsigned char>& bytes, u64 value) {
    for (unsigned int shift = 0u; shift != 64u; shift += 8u)
        bytes.push_back(static_cast<unsigned char>(value >> shift));
}

std::vector<unsigned char> golden_frame(worker::u16 type,
                                        const worker::Token& frame_token,
                                        const std::vector<u64>& fields) {
    std::vector<unsigned char> bytes;
    append_u32(bytes, worker::kMagic);
    append_u16(bytes, worker::kVersion);
    append_u16(bytes, type);
    append_u32(bytes, static_cast<worker::u32>(fields.size() * sizeof(u64)));
    bytes.insert(bytes.end(), frame_token.bytes.begin(), frame_token.bytes.end());
    for (const u64 field : fields) append_u64(bytes, field);
    return bytes;
}

bool golden_frames() {
    static_assert(worker::kVersion == 1u);
    static_assert(protocol::kProfileVersion == 2u);
    static_assert(protocol::kCommandFrameType == 55u);
    static_assert(protocol::kPhaseFrameType == 56u);
    static_assert(protocol::kDecisionFrameType == 57u);
    static_assert(protocol::kSettlementFrameType == 58u);
    const worker::Token expected_token = token();
    const protocol::CommandV2 cmd = command();
    const protocol::PhaseV2 held = phase(protocol::Phase::ReservationHeld);
    const protocol::DecisionV2 authorize = decision(protocol::DecisionKind::AuthorizeCollisionExec);
    const protocol::SettlementV2 settled = settlement();
    if (worker::frame_bytes(protocol::encode_command(expected_token, cmd)) !=
            golden_frame(55u, expected_token, {2u, kTransaction, 1u, 0u}) ||
        worker::frame_bytes(protocol::encode_phase(expected_token, held)) !=
            golden_frame(56u, expected_token, {2u, kTransaction, 1u, 1u, 1u}) ||
        worker::frame_bytes(protocol::encode_decision(expected_token, authorize)) !=
            golden_frame(57u, expected_token, {2u, kTransaction, 1u, 1u, 1u, 2u}) ||
        worker::frame_bytes(protocol::encode_settlement(expected_token, settled)) !=
            golden_frame(58u, expected_token, {2u, kTransaction, 1u, 1u, 5u, 11u}))
        return false;

    // v1's test-local payload profile remains untouched; these are the exact
    // common-frame headers already allocated to it before v2 took 55--58.
    for (worker::u16 type = 51u; type <= 54u; ++type) {
        const worker::Frame existing{type, expected_token, {}};
        if (worker::frame_bytes(existing) != golden_frame(type, expected_token, {})) return false;
    }
    return true;
}

bool round_trips() {
    const worker::Token expected_token = token();
    protocol::CommandV2 decoded_command;
    const protocol::CommandV2 cmd = command();
    if (!protocol::decode_command(
            protocol::encode_command(expected_token, cmd), expected_token, decoded_command) ||
        !same(cmd, decoded_command))
        return false;

    constexpr std::array phases{protocol::Phase::ReservationHeld,
                                protocol::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                protocol::Phase::EvidenceClosedReservationHeld,
                                protocol::Phase::ReservationReleased,
                                protocol::Phase::RetryLive};
    for (const protocol::Phase kind : phases) {
        const protocol::PhaseV2 value = phase(kind);
        protocol::PhaseV2 decoded;
        if (!protocol::decode_phase(
                protocol::encode_phase(expected_token, value), expected_token, decoded) ||
            !same(value, decoded))
            return false;
    }

    constexpr std::array decisions{protocol::DecisionKind::AuthorizeCollisionExec,
                                   protocol::DecisionKind::AuthorizeEvidenceClose,
                                   protocol::DecisionKind::AuthorizeReservationRelease,
                                   protocol::DecisionKind::AuthorizeRetryExec,
                                   protocol::DecisionKind::AuthorizeRetrySettlement,
                                   protocol::DecisionKind::Finish};
    for (const protocol::DecisionKind kind : decisions) {
        const protocol::DecisionV2 value = decision(kind);
        protocol::DecisionV2 decoded;
        if (!protocol::decode_decision(
                protocol::encode_decision(expected_token, value), expected_token, decoded) ||
            !same(value, decoded))
            return false;
    }

    const protocol::SettlementV2 value = settlement();
    protocol::SettlementV2 decoded;
    return protocol::decode_settlement(
               protocol::encode_settlement(expected_token, value), expected_token, decoded) &&
           same(value, decoded);
}

void set_field(worker::Frame& frame, std::size_t index, u64 value) {
    const std::size_t offset = index * sizeof(u64);
    for (unsigned int shift = 0u; shift != 64u; shift += 8u)
        frame.payload[offset + shift / 8u] = static_cast<unsigned char>(value >> shift);
}

template <typename Value, typename Decoder, typename Equal>
bool rejects_atomically(const std::vector<worker::Frame>& invalid,
                        const worker::Token& expected_token,
                        const Value& sentinel,
                        Decoder decoder,
                        Equal equal) {
    return std::all_of(invalid.begin(), invalid.end(), [&](const worker::Frame& frame) {
        Value output = sentinel;
        return !decoder(frame, expected_token, output) && equal(output, sentinel);
    });
}

template <typename Encoder, typename Value>
std::vector<worker::Frame> common_invalid_frames(Encoder encoder,
                                                 const Value& value,
                                                 worker::u16 wrong_type) {
    const worker::Token expected_token = token();
    std::vector<worker::Frame> invalid;
    worker::Frame wrong_token = encoder(expected_token, value);
    wrong_token.token = token(0x20u);
    invalid.push_back(wrong_token);
    worker::Frame type = encoder(expected_token, value);
    type.type = wrong_type;
    invalid.push_back(type);
    worker::Frame truncated = encoder(expected_token, value);
    truncated.payload.pop_back();
    invalid.push_back(truncated);
    worker::Frame trailing = encoder(expected_token, value);
    trailing.payload.push_back(0u);
    invalid.push_back(trailing);
    for (std::size_t field = 0u; field != 4u; ++field) {
        worker::Frame changed = encoder(expected_token, value);
        set_field(changed, field, field == 0u ? 1u : (field == 1u ? 0u : 2u));
        invalid.push_back(changed);
    }
    return invalid;
}

bool atomic_decoder_rejections() {
    const worker::Token expected_token = token();
    const protocol::CommandV2 command_sentinel = command(0x8001u);
    std::vector<worker::Frame> commands =
        common_invalid_frames(protocol::encode_command, command(), protocol::kPhaseFrameType);
    if (!rejects_atomically(commands,
                            expected_token,
                            command_sentinel,
                            protocol::decode_command,
                            [](const auto& left, const auto& right) { return same(left, right); }))
        return false;

    const protocol::PhaseV2 phase_sentinel = phase(protocol::Phase::RetryLive, 0x8002u);
    std::vector<worker::Frame> phases =
        common_invalid_frames(protocol::encode_phase,
                              phase(protocol::Phase::ReservationHeld),
                              protocol::kDecisionFrameType);
    worker::Frame invalid_phase =
        protocol::encode_phase(expected_token, phase(protocol::Phase::ReservationHeld));
    set_field(invalid_phase, 3u, 0u);
    phases.push_back(invalid_phase);
    invalid_phase = protocol::encode_phase(expected_token, phase(protocol::Phase::ReservationHeld));
    set_field(invalid_phase, 4u, 3u);
    phases.push_back(invalid_phase);
    if (!rejects_atomically(phases,
                            expected_token,
                            phase_sentinel,
                            protocol::decode_phase,
                            [](const auto& left, const auto& right) { return same(left, right); }))
        return false;

    const protocol::DecisionV2 decision_sentinel =
        decision(protocol::DecisionKind::Finish, 0x8003u);
    std::vector<worker::Frame> decisions =
        common_invalid_frames(protocol::encode_decision,
                              decision(protocol::DecisionKind::AuthorizeCollisionExec),
                              protocol::kSettlementFrameType);
    worker::Frame invalid_decision = protocol::encode_decision(
        expected_token, decision(protocol::DecisionKind::AuthorizeCollisionExec));
    set_field(invalid_decision, 3u, 0u);
    decisions.push_back(invalid_decision);
    invalid_decision = protocol::encode_decision(
        expected_token, decision(protocol::DecisionKind::AuthorizeCollisionExec));
    set_field(invalid_decision, 4u, 2u);
    decisions.push_back(invalid_decision);
    invalid_decision = protocol::encode_decision(
        expected_token, decision(protocol::DecisionKind::AuthorizeCollisionExec));
    set_field(invalid_decision, 5u, 4u);
    decisions.push_back(invalid_decision);
    if (!rejects_atomically(decisions,
                            expected_token,
                            decision_sentinel,
                            protocol::decode_decision,
                            [](const auto& left, const auto& right) { return same(left, right); }))
        return false;

    const protocol::SettlementV2 settlement_sentinel = settlement(0x8004u);
    std::vector<worker::Frame> settlements = common_invalid_frames(
        protocol::encode_settlement, settlement(), protocol::kCommandFrameType);
    worker::Frame invalid_settlement = protocol::encode_settlement(expected_token, settlement());
    set_field(invalid_settlement, 3u, 2u);
    settlements.push_back(invalid_settlement);
    invalid_settlement = protocol::encode_settlement(expected_token, settlement());
    set_field(invalid_settlement, 4u, 4u);
    settlements.push_back(invalid_settlement);
    invalid_settlement = protocol::encode_settlement(expected_token, settlement());
    set_field(invalid_settlement, 5u, 12u);
    settlements.push_back(invalid_settlement);
    return rejects_atomically(
        settlements,
        expected_token,
        settlement_sentinel,
        protocol::decode_settlement,
        [](const auto& left, const auto& right) { return same(left, right); });
}

worker::Frame event_frame(std::size_t index,
                          const worker::Token& frame_token,
                          u64 transaction = kTransaction) {
    switch (index) {
        case 0u:
            return protocol::encode_command(frame_token, command(transaction));
        case 1u:
            return protocol::encode_phase(frame_token,
                                          phase(protocol::Phase::ReservationHeld, transaction));
        case 2u:
            return protocol::encode_decision(
                frame_token, decision(protocol::DecisionKind::AuthorizeCollisionExec, transaction));
        case 3u:
            return protocol::encode_phase(
                frame_token,
                phase(protocol::Phase::CollisionNaturallyRejectedEvidenceOpen, transaction));
        case 4u:
            return protocol::encode_decision(
                frame_token, decision(protocol::DecisionKind::AuthorizeEvidenceClose, transaction));
        case 5u:
            return protocol::encode_phase(
                frame_token, phase(protocol::Phase::EvidenceClosedReservationHeld, transaction));
        case 6u:
            return protocol::encode_decision(
                frame_token,
                decision(protocol::DecisionKind::AuthorizeReservationRelease, transaction));
        case 7u:
            return protocol::encode_phase(frame_token,
                                          phase(protocol::Phase::ReservationReleased, transaction));
        case 8u:
            return protocol::encode_decision(
                frame_token, decision(protocol::DecisionKind::AuthorizeRetryExec, transaction));
        case 9u:
            return protocol::encode_phase(frame_token,
                                          phase(protocol::Phase::RetryLive, transaction));
        case 10u:
            return protocol::encode_decision(
                frame_token,
                decision(protocol::DecisionKind::AuthorizeRetrySettlement, transaction));
        case 11u:
            return protocol::encode_settlement(frame_token, settlement(transaction));
        case 12u:
            return protocol::encode_decision(frame_token,
                                             decision(protocol::DecisionKind::Finish, transaction));
    }
    return {};
}

bool apply_frame(protocol::StateMachine& machine,
                 std::size_t index,
                 const worker::Frame& frame,
                 const worker::Token& expected_token) {
    switch (index) {
        case 0u:
            return machine.begin(frame, expected_token);
        case 1u:
        case 3u:
        case 5u:
        case 7u:
        case 9u:
            return machine.observe(frame, expected_token);
        case 2u:
        case 4u:
        case 6u:
        case 8u:
        case 10u:
        case 12u:
            return machine.decide(frame, expected_token);
        case 11u:
            return machine.settle(frame, expected_token);
    }
    return false;
}

bool apply_event(protocol::StateMachine& machine,
                 std::size_t index,
                 u64 transaction = kTransaction) {
    const worker::Token expected_token = token();
    return apply_frame(
        machine, index, event_frame(index, expected_token, transaction), expected_token);
}

constexpr std::array<protocol::State, 14u> kPrefixStates{
    protocol::State::AwaitCommand,
    protocol::State::AwaitReservationHeld,
    protocol::State::AwaitCollisionExecAuthorization,
    protocol::State::AwaitCollisionNaturallyRejectedEvidenceOpen,
    protocol::State::AwaitEvidenceCloseAuthorization,
    protocol::State::AwaitEvidenceClosedReservationHeld,
    protocol::State::AwaitReservationReleaseAuthorization,
    protocol::State::AwaitReservationReleased,
    protocol::State::AwaitRetryExecAuthorization,
    protocol::State::AwaitRetryLive,
    protocol::State::AwaitRetrySettlementAuthorization,
    protocol::State::AwaitAttemptSettlement,
    protocol::State::AwaitFinish,
    protocol::State::Complete,
};

bool apply_prefix(protocol::StateMachine& machine, std::size_t count) {
    for (std::size_t index = 0u; index != count; ++index)
        if (!apply_event(machine, index)) return false;
    return machine.state() == kPrefixStates[count];
}

bool rejection_is_terminal(protocol::StateMachine machine,
                           std::size_t invalid_event,
                           std::size_t expected_event,
                           u64 transaction = kTransaction) {
    return !apply_event(machine, invalid_event, transaction) &&
           machine.state() == protocol::State::Failed && !apply_event(machine, expected_event) &&
           machine.state() == protocol::State::Failed;
}

bool frame_rejection_is_terminal(protocol::StateMachine machine,
                                 std::size_t expected_event,
                                 const worker::Frame& invalid) {
    const worker::Token expected_token = token();
    return !apply_frame(machine, expected_event, invalid, expected_token) &&
           machine.state() == protocol::State::Failed && !apply_event(machine, expected_event) &&
           machine.state() == protocol::State::Failed;
}

bool canonical_and_rejection_matrix() {
    constexpr std::size_t event_count = kPrefixStates.size() - 1u;
    protocol::StateMachine canonical;
    if (!apply_prefix(canonical, event_count) || canonical.state() != protocol::State::Complete ||
        canonical.transaction_id() != kTransaction)
        return false;

    for (std::size_t next = 0u; next != event_count; ++next) {
        protocol::StateMachine prefix;
        if (!apply_prefix(prefix, next)) return false;
        protocol::StateMachine correct = prefix;
        if (!apply_event(correct, next) || correct.state() != kPrefixStates[next + 1u])
            return false;

        const worker::Token expected_token = token();
        worker::Frame wrong_token = event_frame(next, token(0x20u));
        if (!frame_rejection_is_terminal(prefix, next, wrong_token)) return false;
        worker::Frame wrong_type = event_frame(next, expected_token);
        wrong_type.type = wrong_type.type == protocol::kSettlementFrameType
                              ? protocol::kCommandFrameType
                              : static_cast<worker::u16>(wrong_type.type + 1u);
        if (!frame_rejection_is_terminal(prefix, next, wrong_type)) return false;
        worker::Frame wrong_version = event_frame(next, expected_token);
        set_field(wrong_version, 0u, 1u);
        if (!frame_rejection_is_terminal(prefix, next, wrong_version)) return false;
        worker::Frame wrong_profile = event_frame(next, expected_token);
        set_field(wrong_profile, 2u, 2u);
        if (!frame_rejection_is_terminal(prefix, next, wrong_profile)) return false;
        worker::Frame wrong_sequence = event_frame(next, expected_token);
        set_field(wrong_sequence,
                  wrong_sequence.payload.size() / sizeof(u64) - 1u,
                  static_cast<u64>(next + 101u));
        if (!frame_rejection_is_terminal(prefix, next, wrong_sequence)) return false;

        if (next > 0u && !rejection_is_terminal(prefix, next, next, kTransaction + 1u))
            return false;
        if (next > 0u && !rejection_is_terminal(prefix, next - 1u, next)) return false;
        if (next + 1u < event_count && !rejection_is_terminal(prefix, next + 1u, next))
            return false;
        const std::size_t reordered = (next + 3u) % event_count;
        if (reordered != next && !rejection_is_terminal(prefix, reordered, next)) return false;
    }

    for (std::size_t replay = 0u; replay != event_count; ++replay) {
        protocol::StateMachine complete;
        if (!apply_prefix(complete, event_count) || apply_event(complete, replay) ||
            complete.state() != protocol::State::Failed || apply_event(complete, replay) ||
            complete.state() != protocol::State::Failed)
            return false;
    }

    protocol::StateMachine malformed;
    protocol::CommandV2 wrong_version = command();
    wrong_version.version = 1u;
    const worker::Token expected_token = token();
    if (malformed.begin(protocol::encode_command(expected_token, wrong_version), expected_token) ||
        malformed.state() != protocol::State::Failed ||
        malformed.begin(protocol::encode_command(expected_token, command()), expected_token) ||
        malformed.state() != protocol::State::Failed)
        return false;
    return true;
}

bool send_fragments(int fd, const std::vector<unsigned char>& bytes) {
    std::size_t offset = 0u;
    while (offset != bytes.size()) {
        const std::size_t count = std::min<std::size_t>((offset % 5u) + 1u, bytes.size() - offset);
        const ssize_t sent = send(fd, bytes.data() + offset, count, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0 || sent > static_cast<ssize_t>(count)) return false;
        offset += static_cast<std::size_t>(sent);
        (void)poll(nullptr, 0, 1);
    }
    return true;
}

bool common_transport_round_trip() {
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
    const worker::Token expected_token = token();
    const protocol::DecisionV2 expected =
        decision(protocol::DecisionKind::AuthorizeReservationRelease);
    const worker::Frame sent = protocol::encode_decision(expected_token, expected);
    worker::Frame received;
    protocol::DecisionV2 decoded;
    const bool transferred =
        worker::send_frame(sockets[0], sent, worker::kHandshakeMs) &&
        worker::receive_frame_until(sockets[1], received, Clock::now() + std::chrono::seconds(1)) &&
        protocol::decode_decision(received, expected_token, decoded) && same(expected, decoded);
    const bool closed = close(sockets[0]) == 0 && close(sockets[1]) == 0;
    return transferred && closed;
}

bool fragmented_same_deadline() {
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
    const worker::Token expected_token = token();
    const std::vector<unsigned char> first =
        worker::frame_bytes(protocol::encode_command(expected_token, command()));
    const std::vector<unsigned char> second = worker::frame_bytes(
        protocol::encode_phase(expected_token, phase(protocol::Phase::ReservationHeld)));
    const pid_t child = fork();
    if (child < 0) {
        close(sockets[0]);
        close(sockets[1]);
        return false;
    }
    if (child == 0) {
        close(sockets[0]);
        const bool sent = send_fragments(sockets[1], first) && send_fragments(sockets[1], second);
        close(sockets[1]);
        _exit(sent ? 0 : 1);
    }
    close(sockets[1]);
    const auto deadline = Clock::now() + std::chrono::seconds(2);
    worker::Frame first_received;
    worker::Frame second_received;
    protocol::CommandV2 decoded_command;
    protocol::PhaseV2 decoded_phase;
    const bool received =
        worker::receive_frame_until(sockets[0], first_received, deadline) &&
        protocol::decode_command(first_received, expected_token, decoded_command) &&
        worker::receive_frame_until(sockets[0], second_received, deadline) &&
        protocol::decode_phase(second_received, expected_token, decoded_phase) &&
        same(decoded_command, command()) &&
        same(decoded_phase, phase(protocol::Phase::ReservationHeld));
    const bool closed = close(sockets[0]) == 0;
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return received && closed && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool missing_payload_is_bounded() {
    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) return false;
    const worker::Token expected_token = token();
    const std::vector<unsigned char> wire = worker::frame_bytes(
        protocol::encode_phase(expected_token, phase(protocol::Phase::ReservationHeld)));
    const bool header_sent =
        worker::write_exact(sockets[0], wire.data(), worker::kHeaderBytes, worker::kHandshakeMs);
    worker::Frame received;
    const auto begin = Clock::now();
    const auto deadline = begin + std::chrono::milliseconds(30);
    const bool rejected = !worker::receive_frame_until(sockets[1], received, deadline);
    const auto elapsed = Clock::now() - begin;
    const bool closed = close(sockets[0]) == 0 && close(sockets[1]) == 0;
    return header_sent && rejected && elapsed < std::chrono::milliseconds(500) && closed;
}

}  // namespace

int main() {
    bool ok = true;
    ok = check(golden_frames(), "exact frame 51--58 golden bytes") && ok;
    ok = check(round_trips(), "v2 closed-domain round trips") && ok;
    ok = check(atomic_decoder_rejections(), "authenticated atomic decoder rejection") && ok;
    for (unsigned int repetition = 0u; repetition != 200u; ++repetition)
        ok = check(canonical_and_rejection_matrix(), "canonical/replay causal matrix") && ok;
    ok = check(common_transport_round_trip(), "common send/receive transport round trip") && ok;
    ok = check(fragmented_same_deadline(), "fragmented frames under one absolute deadline") && ok;
    ok = check(missing_payload_is_bounded(), "missing payload bounded failure") && ok;
    if (!ok) return 1;
    std::puts("PASS: #377 CollisionRelease v2 pure protocol/state machine");
    return 0;
}
