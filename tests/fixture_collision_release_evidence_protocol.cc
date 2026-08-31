#include "fixture_collision_release_evidence_protocol.h"

#include <cerrno>
#include <climits>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

#include <fcntl.h>

namespace rut::test::fixture_collision_release_evidence_protocol {
namespace {

using Bytes = std::vector<unsigned char>;

void put(Bytes& bytes, u64 value) {
    for (unsigned shift = 0u; shift < 64u; shift += 8u)
        bytes.push_back(static_cast<unsigned char>(value >> shift));
}

bool get(const Bytes& bytes, std::size_t& position, u64& value) {
    if (position > bytes.size() || bytes.size() - position < sizeof(u64)) return false;
    value = 0u;
    for (unsigned shift = 0u; shift < 64u; shift += 8u)
        value |= static_cast<u64>(bytes[position++]) << shift;
    return true;
}

void put_bytes(Bytes& bytes, const std::string& value) {
    bytes.insert(bytes.end(), value.begin(), value.end());
}

bool get_bytes(const Bytes& bytes, std::size_t& position, std::size_t length, std::string& value) {
    if (position > bytes.size() || length > bytes.size() - position) return false;
    value.assign(reinterpret_cast<const char*>(bytes.data() + position), length);
    position += length;
    return true;
}

bool at_end(const Bytes& bytes, std::size_t position) {
    return position == bytes.size();
}

bool canonical_bool(u64 value) {
    return value == 0u || value == 1u;
}

void put_proc(Bytes& bytes, const Proc13& value) {
    for (const u64 field : {value.pid,
                            value.ppid,
                            value.sid,
                            value.start,
                            value.pgid,
                            value.uid,
                            value.gid,
                            value.netns,
                            value.exe_dev,
                            value.exe_ino,
                            value.no_new_privs,
                            value.capabilities_clear,
                            value.supplementary_groups})
        put(bytes, field);
}

bool valid_proc(const Proc13& value) {
    return canonical_bool(value.no_new_privs) && canonical_bool(value.capabilities_clear);
}

bool get_proc(const Bytes& bytes, std::size_t& position, Proc13& value) {
    return get(bytes, position, value.pid) && get(bytes, position, value.ppid) &&
           get(bytes, position, value.sid) && get(bytes, position, value.start) &&
           get(bytes, position, value.pgid) && get(bytes, position, value.uid) &&
           get(bytes, position, value.gid) && get(bytes, position, value.netns) &&
           get(bytes, position, value.exe_dev) && get(bytes, position, value.exe_ino) &&
           get(bytes, position, value.no_new_privs) &&
           get(bytes, position, value.capabilities_clear) &&
           get(bytes, position, value.supplementary_groups) && valid_proc(value);
}

void put_pair(Bytes& bytes, const ProcPair& value) {
    put(bytes, value.first_tag);
    put_proc(bytes, value.first);
    put(bytes, value.second_tag);
    put_proc(bytes, value.second);
}

bool get_pair(const Bytes& bytes, std::size_t& position, ProcPair& value) {
    if (!get(bytes, position, value.first_tag) || !get_proc(bytes, position, value.first) ||
        !get(bytes, position, value.second_tag) || !get_proc(bytes, position, value.second))
        return false;
    if ((value.first_tag != 0u && value.first_tag != 1u) ||
        (value.second_tag != 0u && value.second_tag != 1u))
        return false;
    const bool first_absent = value.first == Proc13{};
    const bool second_absent = value.second == Proc13{};
    return (value.first_tag == 0u) == first_absent && (value.second_tag == 0u) == second_absent;
}

void put_settlement(Bytes& bytes, const Settlement9& value) {
    for (const u64 field : {value.child_pid,
                            value.identity_pid,
                            value.identity_ppid,
                            value.identity_start,
                            value.identity_netns,
                            value.terminal,
                            value.reaped,
                            value.wait_status,
                            value.error_number})
        put(bytes, field);
}

bool valid_settlement(const Settlement9& value) {
    return canonical_bool(value.terminal) && canonical_bool(value.reaped);
}

bool get_settlement(const Bytes& bytes, std::size_t& position, Settlement9& value) {
    return get(bytes, position, value.child_pid) && get(bytes, position, value.identity_pid) &&
           get(bytes, position, value.identity_ppid) &&
           get(bytes, position, value.identity_start) &&
           get(bytes, position, value.identity_netns) && get(bytes, position, value.terminal) &&
           get(bytes, position, value.reaped) && get(bytes, position, value.wait_status) &&
           get(bytes, position, value.error_number) && valid_settlement(value);
}

void put_cleanup(Bytes& bytes, const Cleanup14& value) {
    for (const u64 field : {value.destructor_attempted,
                            value.destructor_reportable_success,
                            value.child_attempted,
                            value.child_settled,
                            value.handoff_attempted,
                            value.handoff_closed,
                            value.null_attempted,
                            value.null_closed,
                            value.capture_settle_attempted,
                            value.capture_settled,
                            value.capture_close_attempted,
                            value.capture_closed,
                            value.diagnostic_phase,
                            value.diagnostic_error})
        put(bytes, field);
}

bool valid_cleanup(const Cleanup14& value) {
    return canonical_bool(value.destructor_attempted) &&
           canonical_bool(value.destructor_reportable_success) &&
           canonical_bool(value.child_attempted) && canonical_bool(value.child_settled) &&
           canonical_bool(value.handoff_attempted) && canonical_bool(value.handoff_closed) &&
           canonical_bool(value.null_attempted) && canonical_bool(value.null_closed) &&
           canonical_bool(value.capture_settle_attempted) &&
           canonical_bool(value.capture_settled) && canonical_bool(value.capture_close_attempted) &&
           canonical_bool(value.capture_closed);
}

bool get_cleanup(const Bytes& bytes, std::size_t& position, Cleanup14& value) {
    return get(bytes, position, value.destructor_attempted) &&
           get(bytes, position, value.destructor_reportable_success) &&
           get(bytes, position, value.child_attempted) &&
           get(bytes, position, value.child_settled) &&
           get(bytes, position, value.handoff_attempted) &&
           get(bytes, position, value.handoff_closed) &&
           get(bytes, position, value.null_attempted) && get(bytes, position, value.null_closed) &&
           get(bytes, position, value.capture_settle_attempted) &&
           get(bytes, position, value.capture_settled) &&
           get(bytes, position, value.capture_close_attempted) &&
           get(bytes, position, value.capture_closed) &&
           get(bytes, position, value.diagnostic_phase) &&
           get(bytes, position, value.diagnostic_error) && valid_cleanup(value);
}

void put_release(Bytes& bytes, const Release16& value) {
    for (const u64 field : {value.attempted,
                            value.destructor,
                            value.real_close_attempts,
                            value.real_close_result,
                            value.real_close_error,
                            value.reported_close_error,
                            value.immediate_fgetfd_result,
                            value.immediate_fgetfd_error,
                            value.immediate_ebadf,
                            value.post_inventory_checked,
                            value.baseline_restored,
                            value.socket_inode_absent,
                            value.reportable_success,
                            value.state,
                            value.diagnostic_phase,
                            value.diagnostic_error})
        put(bytes, field);
}

bool valid_release(const Release16& value) {
    return canonical_bool(value.attempted) && canonical_bool(value.destructor) &&
           canonical_bool(value.real_close_result) && canonical_bool(value.immediate_ebadf) &&
           canonical_bool(value.post_inventory_checked) &&
           canonical_bool(value.baseline_restored) && canonical_bool(value.socket_inode_absent) &&
           canonical_bool(value.reportable_success);
}

bool get_release(const Bytes& bytes, std::size_t& position, Release16& value) {
    return get(bytes, position, value.attempted) && get(bytes, position, value.destructor) &&
           get(bytes, position, value.real_close_attempts) &&
           get(bytes, position, value.real_close_result) &&
           get(bytes, position, value.real_close_error) &&
           get(bytes, position, value.reported_close_error) &&
           get(bytes, position, value.immediate_fgetfd_result) &&
           get(bytes, position, value.immediate_fgetfd_error) &&
           get(bytes, position, value.immediate_ebadf) &&
           get(bytes, position, value.post_inventory_checked) &&
           get(bytes, position, value.baseline_restored) &&
           get(bytes, position, value.socket_inode_absent) &&
           get(bytes, position, value.reportable_success) && get(bytes, position, value.state) &&
           get(bytes, position, value.diagnostic_phase) &&
           get(bytes, position, value.diagnostic_error) && valid_release(value);
}

Bytes envelope(const Envelope& value, std::size_t body_length) {
    Bytes bytes;
    bytes.reserve(kEnvelopeBytes);
    for (const u64 field : {value.version,
                            value.transaction,
                            value.domain,
                            static_cast<u64>(value.kind),
                            static_cast<u64>(value.binding),
                            static_cast<u64>(value.phase),
                            value.sequence,
                            value.target.pid,
                            value.target.start,
                            value.target.netns,
                            body_length})
        put(bytes, field);
    return bytes;
}

bool parse(const Bytes& bytes, Envelope& value, std::size_t& position) {
    u64 kind = 0u;
    u64 binding = 0u;
    u64 phase = 0u;
    u64 body_length = 0u;
    if (bytes.size() < kEnvelopeBytes || !get(bytes, position, value.version) ||
        !get(bytes, position, value.transaction) || !get(bytes, position, value.domain) ||
        !get(bytes, position, kind) || !get(bytes, position, binding) ||
        !get(bytes, position, phase) || !get(bytes, position, value.sequence) ||
        !get(bytes, position, value.target.pid) || !get(bytes, position, value.target.start) ||
        !get(bytes, position, value.target.netns) || !get(bytes, position, body_length))
        return false;
    if (body_length != bytes.size() - kEnvelopeBytes || kind < 1u || kind > 9u || binding < 1u ||
        binding > 2u || phase < 1u || phase > 5u)
        return false;
    value.kind = static_cast<ReportKind>(kind);
    value.binding = static_cast<Binding>(binding);
    value.phase = static_cast<Phase>(phase);
    return true;
}

bool start(const worker::Frame& frame,
           const worker::Token& token,
           const Envelope& expected,
           ReportKind kind,
           Envelope& got,
           std::size_t& position) {
    if (frame.type != kEvidenceFrameType || !worker::token_equal(frame.token, token) ||
        frame.payload.size() > worker::kMaxPayload || frame.payload.size() > max_payload(kind) ||
        !parse(frame.payload, got, position))
        return false;
    return got.kind == kind && valid_envelope(got, kind) && got.version == expected.version &&
           got.transaction == expected.transaction && got.domain == expected.domain &&
           got.binding == expected.binding && got.phase == expected.phase &&
           got.sequence == expected.sequence && got.target == expected.target;
}

worker::Frame make(const worker::Token& token,
                   const Envelope& envelope_value,
                   ReportKind kind,
                   const Bytes& body,
                   std::size_t maximum) {
    if (envelope_value.kind != kind || !valid_envelope(envelope_value, kind) ||
        body.size() > maximum - kEnvelopeBytes)
        return {};
    Bytes payload = envelope(envelope_value, body.size());
    payload.insert(payload.end(), body.begin(), body.end());
    return {kEvidenceFrameType, token, std::move(payload)};
}

bool bounded_string(const std::string& value, std::size_t maximum) {
    return value.size() <= maximum && value.find('\0') == std::string::npos;
}

bool capture_body(const Bytes& bytes, std::size_t& position, u64 length, std::string& value) {
    return length <= kMaxCapture && length == bytes.size() - position &&
           get_bytes(bytes, position, static_cast<std::size_t>(length), value) &&
           at_end(bytes, position);
}

bool valid_header(const CollisionHeader7& value) {
    return value.attempt_state >= static_cast<u64>(AttemptState::EarlyDeath) &&
           value.attempt_state <= static_cast<u64>(AttemptState::ExecObservedLive) &&
           value.outcome == static_cast<u64>(CollisionOutcome::NaturallyRejected) &&
           value.child_pid != 0u && value.child_start != 0u &&
           (value.cmdline_provenance == static_cast<u64>(CmdlineProvenance::OwnedExpected) ||
            value.cmdline_provenance == static_cast<u64>(CmdlineProvenance::BracketedProc));
}

bool cleanup_phase(const Cleanup14& value, bool evidence_closed) {
    return valid_cleanup(value) && value.destructor_attempted == 0u &&
           value.destructor_reportable_success == 0u && value.child_attempted == 1u &&
           value.child_settled == 1u && value.handoff_attempted == 1u &&
           value.handoff_closed == 1u && value.null_attempted == 1u && value.null_closed == 1u &&
           value.capture_settle_attempted == 1u && value.capture_settled == 1u &&
           value.capture_close_attempted == static_cast<u64>(evidence_closed) &&
           value.capture_closed == static_cast<u64>(evidence_closed) &&
           value.diagnostic_phase == 0u && value.diagnostic_error == 0u;
}

}  // namespace

bool valid_envelope(const Envelope& value, ReportKind kind) {
    return value.version == kVersion && value.transaction != 0u &&
           value.domain == kClosedEvidenceDomain && value.kind == kind && value.sequence != 0u &&
           value.target.pid != 0u && value.target.start != 0u && value.target.netns != 0u;
}

std::size_t max_payload(ReportKind kind) {
    switch (kind) {
        case ReportKind::ReservationSource:
            return kReservationSourceMax;
        case ReportKind::CollisionAttempt:
            return kCollisionAttemptMax;
        case ReportKind::CollisionCapture:
            return kCollisionCaptureMax;
        case ReportKind::EvidenceClosed:
            return kEvidenceClosedMax;
        case ReportKind::Release:
            return kReleaseMax;
        case ReportKind::RetryLive:
            return kRetryLiveMax;
        case ReportKind::RetryLiveCapture:
            return kRetryLiveCaptureMax;
        case ReportKind::RetrySettlement:
            return kRetrySettlementMax;
        case ReportKind::RetryFinalCapture:
            return kRetryFinalCaptureMax;
    }
    return 0u;
}

bool valid_cmdline(const std::string& value, const std::string& path) {
    if (value.empty() || value.size() > kMaxCmdline || value.back() != '\0') return false;
    std::string arguments[9];
    std::size_t position = 0u;
    for (unsigned index = 0u; index < 9u; ++index) {
        const std::size_t end = value.find('\0', position);
        if (end == std::string::npos || end == position) return false;
        arguments[index] = value.substr(position, end - position);
        position = end + 1u;
    }
    if (position != value.size() || arguments[0].size() > 4095u ||
        arguments[1].size() > kMaxSourcePath || (!path.empty() && arguments[1] != path))
        return false;
    return !arguments[0].empty() && arguments[2] == "--shards" && arguments[3] == "1" &&
           arguments[4] == "--no-pin" && arguments[5] == "--drain" && arguments[6] == "0" &&
           arguments[7] == "--opt" && arguments[8] == "2";
}

worker::Frame encode_reservation_source(const worker::Token& token,
                                        const Envelope& envelope_value,
                                        const ReservationSource& value) {
    if (!bounded_string(value.proc_link, kMaxProcLink) ||
        !bounded_string(value.source_path, kMaxSourcePath) ||
        value.source_bytes.size() > kMaxSourceBytes ||
        value.proc_link_len != value.proc_link.size() ||
        value.path_len != value.source_path.size() || value.bytes_len != value.source_bytes.size())
        return {};
    Bytes body;
    for (const u64 field : {value.reservation_state,
                            value.g_fd,
                            value.g_f_getfd,
                            value.g_f_getfl,
                            value.ipv4,
                            value.port,
                            value.dev,
                            value.ino,
                            value.mode,
                            value.rdev,
                            value.socket_domain,
                            value.socket_type,
                            value.socket_protocol,
                            value.reuseaddr,
                            value.reuseport,
                            value.acceptconn,
                            value.proc_link_len,
                            value.directory_dev,
                            value.directory_ino,
                            value.directory_mode,
                            value.directory_uid,
                            value.directory_gid,
                            value.source_state,
                            value.source_dev,
                            value.source_ino,
                            value.source_mode,
                            value.source_uid,
                            value.source_gid,
                            value.source_size,
                            value.source_nlink,
                            value.path_len,
                            value.bytes_len})
        put(body, field);
    put_bytes(body, value.proc_link);
    put_bytes(body, value.source_path);
    put_bytes(body, value.source_bytes);
    return make(token, envelope_value, ReportKind::ReservationSource, body, kReservationSourceMax);
}

worker::Frame encode_collision_attempt(const worker::Token& token,
                                       const Envelope& envelope_value,
                                       const CollisionAttempt& value) {
    if (value.header.cmdline_len != value.cmdline.size() || !valid_cmdline(value.cmdline))
        return {};
    Bytes body;
    for (const u64 field : {value.cross.g_fd,
                            value.cross.g_inode,
                            value.cross.source_dev,
                            value.cross.source_inode,
                            value.header.attempt_state,
                            value.header.outcome,
                            value.header.error_number,
                            value.header.child_pid,
                            value.header.child_start,
                            value.header.cmdline_provenance,
                            value.header.cmdline_len})
        put(body, field);
    put_pair(body, value.procs);
    put_settlement(body, value.settlement);
    put_cleanup(body, value.cleanup);
    for (const u64 field : {value.classifier.backend,
                            value.classifier.opt,
                            value.classifier.error_number,
                            value.classifier.error_source,
                            value.classifier.capture_len})
        put(body, field);
    put_bytes(body, value.cmdline);
    return make(token, envelope_value, ReportKind::CollisionAttempt, body, kCollisionAttemptMax);
}

worker::Frame encode_collision_capture(const worker::Token& token,
                                       const Envelope& envelope_value,
                                       const CollisionCapture& value) {
    if (value.capture_len != value.capture.size() || value.capture_len > kMaxCapture) return {};
    Bytes body;
    put(body, value.capture_len);
    put_bytes(body, value.capture);
    return make(token, envelope_value, ReportKind::CollisionCapture, body, kCollisionCaptureMax);
}

worker::Frame encode_evidence_closed(const worker::Token& token,
                                     const Envelope& envelope_value,
                                     const EvidenceClosed& value) {
    Bytes body;
    for (const u64 field : {value.g_fd,
                            value.g_inode,
                            value.source_dev,
                            value.source_inode,
                            value.child_pid,
                            value.child_start,
                            value.attempt_state,
                            value.reservation_state,
                            value.source_state,
                            value.capture_len})
        put(body, field);
    put_cleanup(body, value.cleanup);
    return make(token, envelope_value, ReportKind::EvidenceClosed, body, kEvidenceClosedMax);
}

worker::Frame encode_release(const worker::Token& token,
                             const Envelope& envelope_value,
                             const Release& value) {
    Bytes body;
    for (const u64 field : {value.g_fd, value.ipv4, value.port, value.g_inode}) put(body, field);
    put_release(body, value.receipt);
    return make(token, envelope_value, ReportKind::Release, body, kReleaseMax);
}

worker::Frame encode_retry_live(const worker::Token& token,
                                const Envelope& envelope_value,
                                const RetryLive& value) {
    if (value.header.cmdline_len != value.cmdline.size() ||
        value.source_path_len != value.source_path.size() ||
        !bounded_string(value.source_path, kMaxSourcePath) ||
        !valid_cmdline(value.cmdline, value.source_path))
        return {};
    Bytes body;
    for (const u64 field : {value.source_dev,
                            value.source_inode,
                            value.source_size,
                            value.source_path_len,
                            value.g_inode,
                            value.port,
                            value.header.attempt_state,
                            value.header.outcome,
                            value.header.error_number,
                            value.header.child_pid,
                            value.header.child_start,
                            value.header.cmdline_provenance,
                            value.header.cmdline_len})
        put(body, field);
    put_pair(body, value.procs);
    for (const u64 field : {value.pidfd.pidfd_fd,
                            value.pidfd.poll_result,
                            value.pidfd.revents,
                            value.pidfd.fdinfo_pid,
                            value.startup.backend,
                            value.startup.opt,
                            value.startup.port,
                            value.startup.capture_len})
        put(body, field);
    put_bytes(body, value.source_path);
    put_bytes(body, value.cmdline);
    return make(token, envelope_value, ReportKind::RetryLive, body, kRetryLiveMax);
}

worker::Frame encode_retry_live_capture(const worker::Token& token,
                                        const Envelope& envelope_value,
                                        const RetryLiveCapture& value) {
    if (value.capture_len != value.capture.size() || value.capture_len > kMaxCapture) return {};
    Bytes body;
    put(body, value.capture_len);
    put_bytes(body, value.capture);
    return make(token, envelope_value, ReportKind::RetryLiveCapture, body, kRetryLiveCaptureMax);
}

worker::Frame encode_retry_settlement(const worker::Token& token,
                                      const Envelope& envelope_value,
                                      const RetrySettlement& value) {
    Bytes body;
    for (const u64 field : {value.source_dev,
                            value.source_inode,
                            value.child_pid,
                            value.child_start,
                            value.attempt_state})
        put(body, field);
    put_settlement(body, value.settlement);
    put_cleanup(body, value.cleanup);
    put(body, value.final_capture_len);
    return make(token, envelope_value, ReportKind::RetrySettlement, body, kRetrySettlementMax);
}

worker::Frame encode_retry_final_capture(const worker::Token& token,
                                         const Envelope& envelope_value,
                                         const RetryFinalCapture& value) {
    if (value.capture_len != value.capture.size() || value.capture_len > kMaxCapture) return {};
    Bytes body;
    put(body, value.capture_len);
    put_bytes(body, value.capture);
    return make(token, envelope_value, ReportKind::RetryFinalCapture, body, kRetryFinalCaptureMax);
}

bool decode_reservation_source(const worker::Frame& frame,
                               const worker::Token& token,
                               const Envelope& expected,
                               ReservationSource& output) {
    Envelope got;
    std::size_t position = 0u;
    ReservationSource value;
    u64* fields[] = {&value.reservation_state,
                     &value.g_fd,
                     &value.g_f_getfd,
                     &value.g_f_getfl,
                     &value.ipv4,
                     &value.port,
                     &value.dev,
                     &value.ino,
                     &value.mode,
                     &value.rdev,
                     &value.socket_domain,
                     &value.socket_type,
                     &value.socket_protocol,
                     &value.reuseaddr,
                     &value.reuseport,
                     &value.acceptconn,
                     &value.proc_link_len,
                     &value.directory_dev,
                     &value.directory_ino,
                     &value.directory_mode,
                     &value.directory_uid,
                     &value.directory_gid,
                     &value.source_state,
                     &value.source_dev,
                     &value.source_ino,
                     &value.source_mode,
                     &value.source_uid,
                     &value.source_gid,
                     &value.source_size,
                     &value.source_nlink,
                     &value.path_len,
                     &value.bytes_len};
    if (!start(frame, token, expected, ReportKind::ReservationSource, got, position)) return false;
    for (u64* field : fields)
        if (!get(frame.payload, position, *field)) return false;
    const std::size_t remaining = frame.payload.size() - position;
    if (value.reservation_state != static_cast<u64>(ReservationState::Held) ||
        value.g_f_getfd != static_cast<u64>(FD_CLOEXEC) ||
        (value.g_f_getfl & static_cast<u64>(O_ACCMODE)) != static_cast<u64>(O_RDWR) ||
        (value.g_f_getfl & static_cast<u64>(O_NONBLOCK | O_APPEND | O_ASYNC)) != 0u ||
        value.source_state != static_cast<u64>(SourceState::Active) ||
        !canonical_bool(value.reuseaddr) || !canonical_bool(value.reuseport) ||
        !canonical_bool(value.acceptconn) || value.proc_link_len > kMaxProcLink ||
        value.path_len > kMaxSourcePath || value.bytes_len > kMaxSourceBytes ||
        value.proc_link_len > remaining || value.path_len > remaining - value.proc_link_len ||
        value.bytes_len != remaining - value.proc_link_len - value.path_len)
        return false;
    if (!get_bytes(frame.payload, position, value.proc_link_len, value.proc_link) ||
        !get_bytes(frame.payload, position, value.path_len, value.source_path) ||
        !get_bytes(frame.payload, position, value.bytes_len, value.source_bytes) ||
        !at_end(frame.payload, position) || !bounded_string(value.proc_link, kMaxProcLink) ||
        !bounded_string(value.source_path, kMaxSourcePath) ||
        value.proc_link != "socket:[" + std::to_string(value.ino) + "]")
        return false;
    output = value;
    return true;
}

bool decode_collision_attempt(const worker::Frame& frame,
                              const worker::Token& token,
                              const Envelope& expected,
                              CollisionAttempt& output) {
    Envelope got;
    std::size_t position = 0u;
    CollisionAttempt value;
    u64* fields[] = {&value.cross.g_fd,
                     &value.cross.g_inode,
                     &value.cross.source_dev,
                     &value.cross.source_inode,
                     &value.header.attempt_state,
                     &value.header.outcome,
                     &value.header.error_number,
                     &value.header.child_pid,
                     &value.header.child_start,
                     &value.header.cmdline_provenance,
                     &value.header.cmdline_len};
    if (!start(frame, token, expected, ReportKind::CollisionAttempt, got, position)) return false;
    for (u64* field : fields)
        if (!get(frame.payload, position, *field)) return false;
    if (!valid_header(value.header) || !get_pair(frame.payload, position, value.procs) ||
        !get_settlement(frame.payload, position, value.settlement) ||
        !get_cleanup(frame.payload, position, value.cleanup))
        return false;
    u64* classifier[] = {&value.classifier.backend,
                         &value.classifier.opt,
                         &value.classifier.error_number,
                         &value.classifier.error_source,
                         &value.classifier.capture_len};
    for (u64* field : classifier)
        if (!get(frame.payload, position, *field)) return false;
    if (value.classifier.backend < static_cast<u64>(ClassifierBackend::Epoll) ||
        value.classifier.backend > static_cast<u64>(ClassifierBackend::IoUring) ||
        value.classifier.capture_len > kMaxCapture || value.header.cmdline_len > kMaxCmdline ||
        value.header.cmdline_len != frame.payload.size() - position ||
        !get_bytes(frame.payload, position, value.header.cmdline_len, value.cmdline) ||
        !at_end(frame.payload, position) || !valid_cmdline(value.cmdline))
        return false;
    output = value;
    return true;
}

bool decode_collision_capture(const worker::Frame& frame,
                              const worker::Token& token,
                              const Envelope& expected,
                              CollisionCapture& output) {
    Envelope got;
    std::size_t position = 0u;
    CollisionCapture value;
    if (!start(frame, token, expected, ReportKind::CollisionCapture, got, position) ||
        !get(frame.payload, position, value.capture_len) ||
        !capture_body(frame.payload, position, value.capture_len, value.capture))
        return false;
    output = value;
    return true;
}

bool decode_evidence_closed(const worker::Frame& frame,
                            const worker::Token& token,
                            const Envelope& expected,
                            EvidenceClosed& output) {
    Envelope got;
    std::size_t position = 0u;
    EvidenceClosed value;
    u64* fields[] = {&value.g_fd,
                     &value.g_inode,
                     &value.source_dev,
                     &value.source_inode,
                     &value.child_pid,
                     &value.child_start,
                     &value.attempt_state,
                     &value.reservation_state,
                     &value.source_state,
                     &value.capture_len};
    if (!start(frame, token, expected, ReportKind::EvidenceClosed, got, position)) return false;
    for (u64* field : fields)
        if (!get(frame.payload, position, *field)) return false;
    if (!get_cleanup(frame.payload, position, value.cleanup) || !at_end(frame.payload, position) ||
        value.capture_len > kMaxCapture)
        return false;
    output = value;
    return true;
}

bool decode_release(const worker::Frame& frame,
                    const worker::Token& token,
                    const Envelope& expected,
                    Release& output) {
    Envelope got;
    std::size_t position = 0u;
    Release value;
    u64* fields[] = {&value.g_fd, &value.ipv4, &value.port, &value.g_inode};
    if (!start(frame, token, expected, ReportKind::Release, got, position)) return false;
    for (u64* field : fields)
        if (!get(frame.payload, position, *field)) return false;
    if (!get_release(frame.payload, position, value.receipt) || !at_end(frame.payload, position))
        return false;
    output = value;
    return true;
}

bool decode_retry_live(const worker::Frame& frame,
                       const worker::Token& token,
                       const Envelope& expected,
                       RetryLive& output) {
    Envelope got;
    std::size_t position = 0u;
    RetryLive value;
    u64* fields[] = {&value.source_dev,
                     &value.source_inode,
                     &value.source_size,
                     &value.source_path_len,
                     &value.g_inode,
                     &value.port,
                     &value.header.attempt_state,
                     &value.header.outcome,
                     &value.header.error_number,
                     &value.header.child_pid,
                     &value.header.child_start,
                     &value.header.cmdline_provenance,
                     &value.header.cmdline_len};
    if (!start(frame, token, expected, ReportKind::RetryLive, got, position)) return false;
    for (u64* field : fields)
        if (!get(frame.payload, position, *field)) return false;
    if (!valid_header(value.header) || !get_pair(frame.payload, position, value.procs))
        return false;
    u64* pidfd_and_startup[] = {&value.pidfd.pidfd_fd,
                                &value.pidfd.poll_result,
                                &value.pidfd.revents,
                                &value.pidfd.fdinfo_pid,
                                &value.startup.backend,
                                &value.startup.opt,
                                &value.startup.port,
                                &value.startup.capture_len};
    for (u64* field : pidfd_and_startup)
        if (!get(frame.payload, position, *field)) return false;
    if (value.pidfd.pidfd_fd > static_cast<u64>(INT_MAX) || value.pidfd.poll_result != 0u ||
        value.pidfd.revents != 0u || value.pidfd.fdinfo_pid == 0u ||
        value.startup.backend < static_cast<u64>(ClassifierBackend::Epoll) ||
        value.startup.backend > static_cast<u64>(ClassifierBackend::IoUring) ||
        value.startup.capture_len > kMaxCapture || value.source_path_len > kMaxSourcePath ||
        value.header.cmdline_len > kMaxCmdline ||
        value.source_path_len > frame.payload.size() - position ||
        !get_bytes(frame.payload, position, value.source_path_len, value.source_path) ||
        value.header.cmdline_len != frame.payload.size() - position ||
        !get_bytes(frame.payload, position, value.header.cmdline_len, value.cmdline) ||
        !at_end(frame.payload, position) || !bounded_string(value.source_path, kMaxSourcePath) ||
        !valid_cmdline(value.cmdline, value.source_path))
        return false;
    output = value;
    return true;
}

bool decode_retry_live_capture(const worker::Frame& frame,
                               const worker::Token& token,
                               const Envelope& expected,
                               RetryLiveCapture& output) {
    Envelope got;
    std::size_t position = 0u;
    RetryLiveCapture value;
    if (!start(frame, token, expected, ReportKind::RetryLiveCapture, got, position) ||
        !get(frame.payload, position, value.capture_len) ||
        !capture_body(frame.payload, position, value.capture_len, value.capture))
        return false;
    output = value;
    return true;
}

bool decode_retry_settlement(const worker::Frame& frame,
                             const worker::Token& token,
                             const Envelope& expected,
                             RetrySettlement& output) {
    Envelope got;
    std::size_t position = 0u;
    RetrySettlement value;
    u64* fields[] = {&value.source_dev,
                     &value.source_inode,
                     &value.child_pid,
                     &value.child_start,
                     &value.attempt_state};
    if (!start(frame, token, expected, ReportKind::RetrySettlement, got, position)) return false;
    for (u64* field : fields)
        if (!get(frame.payload, position, *field)) return false;
    if (!get_settlement(frame.payload, position, value.settlement) ||
        !get_cleanup(frame.payload, position, value.cleanup) ||
        !get(frame.payload, position, value.final_capture_len) ||
        !at_end(frame.payload, position) || value.final_capture_len > kMaxCapture)
        return false;
    output = value;
    return true;
}

bool decode_retry_final_capture(const worker::Frame& frame,
                                const worker::Token& token,
                                const Envelope& expected,
                                RetryFinalCapture& output) {
    Envelope got;
    std::size_t position = 0u;
    RetryFinalCapture value;
    if (!start(frame, token, expected, ReportKind::RetryFinalCapture, got, position) ||
        !get(frame.payload, position, value.capture_len) ||
        !capture_body(frame.payload, position, value.capture_len, value.capture))
        return false;
    output = value;
    return true;
}

bool Receiver::envelope_ok(
    const Envelope& value, ReportKind kind, Binding binding, Phase phase, u64 sequence) const {
    return valid_envelope(value, kind) && value.transaction == context_.transaction &&
           value.domain == context_.domain && value.kind == kind && value.binding == binding &&
           value.phase == phase && value.sequence == sequence && value.target == context_.target;
}

bool Receiver::observe(const worker::Frame& frame) {
    if (state_ == State::Failed || state_ == State::Complete || state_ == State::AwaitFinish)
        return fail();

    Envelope expected;
    expected.transaction = context_.transaction;
    expected.domain = context_.domain;
    expected.target = context_.target;

    switch (state_) {
        case State::AwaitReservationSource: {
            expected.kind = ReportKind::ReservationSource;
            expected.binding = Binding::Phase;
            expected.phase = Phase::ReservationHeld;
            expected.sequence = 1u;
            ReservationSource value;
            if (!envelope_ok(
                    expected, expected.kind, expected.binding, expected.phase, expected.sequence) ||
                !decode_reservation_source(frame, context_.token, expected, value) ||
                context_.expected_source.proc_link.empty() || value != context_.expected_source ||
                !valid_cmdline(context_.expected_cmdline, context_.expected_source.source_path))
                return fail();
            source_ = value;
            state_ = State::AwaitCollisionAttempt;
            return true;
        }
        case State::AwaitCollisionAttempt: {
            expected.kind = ReportKind::CollisionAttempt;
            expected.binding = Binding::Phase;
            expected.phase = Phase::CollisionNaturallyRejectedEvidenceOpen;
            expected.sequence = 3u;
            CollisionAttempt value;
            if (!decode_collision_attempt(frame, context_.token, expected, value) ||
                value.cross.g_fd != source_.g_fd || value.cross.g_inode != source_.ino ||
                value.cross.source_dev != source_.source_dev ||
                value.cross.source_inode != source_.source_ino ||
                value.header.outcome != static_cast<u64>(CollisionOutcome::NaturallyRejected) ||
                value.header.error_number != EADDRINUSE ||
                value.header.cmdline_len != context_.expected_cmdline.size() ||
                value.cmdline != context_.expected_cmdline || value.classifier.backend < 1u ||
                value.classifier.backend > 2u || value.classifier.opt != 2u ||
                value.classifier.error_number != EADDRINUSE ||
                value.classifier.error_source != 4u || value.classifier.capture_len == 0u ||
                value.classifier.capture_len > kMaxCapture || !cleanup_phase(value.cleanup, false))
                return fail();

            const bool early =
                value.header.attempt_state == static_cast<u64>(AttemptState::EarlyDeath) &&
                value.header.cmdline_provenance ==
                    static_cast<u64>(CmdlineProvenance::OwnedExpected) &&
                value.procs == ProcPair{};
            const bool live =
                value.header.attempt_state == static_cast<u64>(AttemptState::ExecObservedLive) &&
                value.header.cmdline_provenance ==
                    static_cast<u64>(CmdlineProvenance::BracketedProc) &&
                value.procs.first_tag == 1u && value.procs.second_tag == 1u &&
                value.procs.first == value.procs.second &&
                value.procs.first.pid == value.header.child_pid &&
                value.procs.first.start == value.header.child_start &&
                value.procs.first.ppid != 0u && value.procs.first.netns != 0u &&
                value.procs.first.ppid == context_.target.pid &&
                value.procs.first.netns == context_.target.netns;
            if (!early && !live) return fail();
            if (value.settlement.child_pid != value.header.child_pid ||
                value.settlement.identity_pid != value.header.child_pid ||
                value.settlement.identity_start != value.header.child_start ||
                value.settlement.identity_ppid != context_.target.pid ||
                value.settlement.identity_netns != context_.target.netns ||
                value.settlement.terminal != 1u || value.settlement.reaped != 1u ||
                value.settlement.error_number != 0u || value.settlement.wait_status != 256u)
                return fail();
            collision_ = value;
            state_ = State::AwaitCollisionCapture;
            return true;
        }
        case State::AwaitCollisionCapture: {
            expected.kind = ReportKind::CollisionCapture;
            expected.binding = Binding::Phase;
            expected.phase = Phase::CollisionNaturallyRejectedEvidenceOpen;
            expected.sequence = 3u;
            CollisionCapture value;
            if (!decode_collision_capture(frame, context_.token, expected, value) ||
                value.capture_len != collision_.classifier.capture_len || value.capture.empty())
                return fail();
            collision_capture_ = value;
            state_ = State::AwaitEvidenceClosed;
            return true;
        }
        case State::AwaitEvidenceClosed: {
            expected.kind = ReportKind::EvidenceClosed;
            expected.binding = Binding::Phase;
            expected.phase = Phase::EvidenceClosedReservationHeld;
            expected.sequence = 5u;
            EvidenceClosed value;
            if (!decode_evidence_closed(frame, context_.token, expected, value) ||
                value.g_fd != source_.g_fd || value.g_inode != source_.ino ||
                value.source_dev != source_.source_dev ||
                value.source_inode != source_.source_ino ||
                value.child_pid != collision_.header.child_pid ||
                value.child_start != collision_.header.child_start ||
                value.attempt_state != collision_.header.attempt_state ||
                value.reservation_state != static_cast<u64>(ReservationState::Held) ||
                value.source_state != static_cast<u64>(SourceState::Active) ||
                value.capture_len != collision_capture_.capture_len ||
                !cleanup_phase(value.cleanup, true))
                return fail();
            closed_ = value;
            state_ = State::AwaitRelease;
            return true;
        }
        case State::AwaitRelease: {
            expected.kind = ReportKind::Release;
            expected.binding = Binding::Phase;
            expected.phase = Phase::ReservationReleased;
            expected.sequence = 7u;
            Release value;
            const u64 invalid_fgetfd = std::numeric_limits<u64>::max();
            if (!decode_release(frame, context_.token, expected, value) ||
                value.g_fd != source_.g_fd || value.ipv4 != source_.ipv4 ||
                value.port != source_.port || value.g_inode != source_.ino ||
                value.receipt.attempted != 1u || value.receipt.destructor != 0u ||
                value.receipt.real_close_attempts != 1u || value.receipt.real_close_result != 0u ||
                value.receipt.real_close_error != 0u || value.receipt.reported_close_error != 0u ||
                value.receipt.immediate_fgetfd_result != invalid_fgetfd ||
                value.receipt.immediate_fgetfd_error != EBADF ||
                value.receipt.immediate_ebadf != 1u || value.receipt.post_inventory_checked != 1u ||
                value.receipt.baseline_restored != 1u || value.receipt.socket_inode_absent != 1u ||
                value.receipt.reportable_success != 1u ||
                value.receipt.state != static_cast<u64>(ReleaseState::Released) ||
                value.receipt.diagnostic_phase != 0u || value.receipt.diagnostic_error != 0u)
                return fail();
            release_ = value;
            state_ = State::AwaitRetryLive;
            return true;
        }
        case State::AwaitRetryLive: {
            expected.kind = ReportKind::RetryLive;
            expected.binding = Binding::Phase;
            expected.phase = Phase::RetryLive;
            expected.sequence = 9u;
            RetryLive value;
            if (!decode_retry_live(frame, context_.token, expected, value) ||
                value.source_dev != source_.source_dev ||
                value.source_inode != source_.source_ino ||
                value.source_size != source_.source_size ||
                value.source_path != source_.source_path || value.g_inode != source_.ino ||
                value.g_inode != release_.g_inode || value.port != release_.port ||
                value.header.attempt_state != static_cast<u64>(AttemptState::ExecObservedLive) ||
                value.header.outcome != static_cast<u64>(CollisionOutcome::NaturallyRejected) ||
                value.header.error_number != EADDRINUSE ||
                value.header.cmdline_provenance !=
                    static_cast<u64>(CmdlineProvenance::BracketedProc) ||
                value.header.child_pid == 0u || value.header.child_start == 0u ||
                value.header.child_pid == collision_.header.child_pid ||
                value.header.child_start == collision_.header.child_start ||
                value.header.cmdline_len != context_.expected_cmdline.size() ||
                value.cmdline != context_.expected_cmdline || value.procs.first_tag != 1u ||
                value.procs.second_tag != 1u || value.procs.first != value.procs.second ||
                value.procs.first.pid != value.header.child_pid ||
                value.procs.first.start != value.header.child_start ||
                value.procs.first.ppid != context_.target.pid ||
                value.procs.first.netns != context_.target.netns ||
                value.pidfd.pidfd_fd > static_cast<u64>(INT_MAX) || value.pidfd.poll_result != 0u ||
                value.pidfd.revents != 0u || value.pidfd.fdinfo_pid != value.header.child_pid ||
                value.startup.backend != collision_.classifier.backend || value.startup.opt != 2u ||
                value.startup.port != value.port || value.startup.capture_len == 0u ||
                value.startup.capture_len > kMaxCapture)
                return fail();
            retry_live_ = value;
            state_ = State::AwaitRetryLiveCapture;
            return true;
        }
        case State::AwaitRetryLiveCapture: {
            expected.kind = ReportKind::RetryLiveCapture;
            expected.binding = Binding::Phase;
            expected.phase = Phase::RetryLive;
            expected.sequence = 9u;
            RetryLiveCapture value;
            if (!decode_retry_live_capture(frame, context_.token, expected, value) ||
                value.capture_len != retry_live_.startup.capture_len || value.capture.empty())
                return fail();
            live_capture_ = value.capture;
            state_ = State::AwaitRetrySettlement;
            return true;
        }
        case State::AwaitRetrySettlement: {
            expected.kind = ReportKind::RetrySettlement;
            expected.binding = Binding::Settlement;
            expected.phase = Phase::RetryLive;
            expected.sequence = 11u;
            RetrySettlement value;
            if (!decode_retry_settlement(frame, context_.token, expected, value) ||
                value.source_dev != retry_live_.source_dev ||
                value.source_inode != retry_live_.source_inode ||
                value.child_pid != retry_live_.header.child_pid ||
                value.child_start != retry_live_.header.child_start ||
                value.attempt_state != retry_live_.header.attempt_state ||
                value.settlement.child_pid != value.child_pid ||
                value.settlement.identity_pid != value.child_pid ||
                value.settlement.identity_start != value.child_start ||
                value.settlement.identity_ppid != context_.target.pid ||
                value.settlement.identity_netns != context_.target.netns ||
                value.settlement.terminal != 1u || value.settlement.reaped != 1u ||
                value.settlement.error_number != 0u || value.settlement.wait_status != 9u ||
                !cleanup_phase(value.cleanup, false) ||
                value.final_capture_len < live_capture_.size() ||
                value.final_capture_len > kMaxCapture)
                return fail();
            retry_settlement_ = value;
            state_ = State::AwaitRetryFinalCapture;
            return true;
        }
        case State::AwaitRetryFinalCapture: {
            expected.kind = ReportKind::RetryFinalCapture;
            expected.binding = Binding::Settlement;
            expected.phase = Phase::RetryLive;
            expected.sequence = 11u;
            RetryFinalCapture value;
            if (!decode_retry_final_capture(frame, context_.token, expected, value) ||
                value.capture_len != retry_settlement_.final_capture_len ||
                value.capture.size() < live_capture_.size() ||
                std::memcmp(value.capture.data(), live_capture_.data(), live_capture_.size()) != 0)
                return fail();
            state_ = State::AwaitFinish;
            return true;
        }
        default:
            return fail();
    }
}

bool Receiver::finish() {
    if (state_ != State::AwaitFinish) {
        state_ = State::Failed;
        return false;
    }
    state_ = State::Complete;
    return true;
}

}  // namespace rut::test::fixture_collision_release_evidence_protocol
