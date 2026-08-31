#pragma once

#include "fixture_worker_protocol.h"
#include <cstddef>
#include <cstdint>
#include <string>

namespace rut::test::fixture_collision_release_evidence_protocol {
namespace worker = fixture_worker_protocol;
using u64 = worker::u64;
inline constexpr worker::u16 kEvidenceFrameType = 59u;
inline constexpr u64 kVersion = 2u, kClosedEvidenceDomain = 1u;
inline constexpr std::size_t kEnvelopeBytes = 11u * sizeof(u64);
inline constexpr std::size_t kProcScalars = 13u, kProcPairScalars = 28u;
inline constexpr std::size_t kSettlementScalars = 9u, kCleanupScalars = 14u;
inline constexpr std::size_t kReleaseReceiptScalars = 16u;
inline constexpr std::size_t kMaxProcLink = 29u, kMaxSourcePath = 181u;
inline constexpr std::size_t kMaxSourceBytes = 255u, kMaxCmdline = 4316u, kMaxCapture = 4096u;
inline constexpr std::size_t kReservationSourceMax = 809u, kCollisionAttemptMax = 4940u;
inline constexpr std::size_t kCollisionCaptureMax = 4192u, kEvidenceClosedMax = 280u;
inline constexpr std::size_t kReleaseMax = 248u, kRetryLiveMax = 4977u;
inline constexpr std::size_t kRetryLiveCaptureMax = 4192u, kRetrySettlementMax = 320u;
inline constexpr std::size_t kRetryFinalCaptureMax = 4192u;

enum class ReportKind : u64 {
    ReservationSource = 1,
    CollisionAttempt = 2,
    CollisionCapture = 3,
    EvidenceClosed = 4,
    Release = 5,
    RetryLive = 6,
    RetryLiveCapture = 7,
    RetrySettlement = 8,
    RetryFinalCapture = 9
};
enum class Binding : u64 { Phase = 1, Settlement = 2 };
enum class Phase : u64 {
    ReservationHeld = 1,
    CollisionNaturallyRejectedEvidenceOpen = 2,
    EvidenceClosedReservationHeld = 3,
    ReservationReleased = 4,
    RetryLive = 5
};
enum class AttemptState : u64 { EarlyDeath = 1, ExecObservedLive = 2 };
enum class CollisionOutcome : u64 { NaturallyRejected = 1 };
enum class CmdlineProvenance : u64 { OwnedExpected = 1, BracketedProc = 2 };
enum class ClassifierBackend : u64 { Epoll = 1, IoUring = 2 };
enum class ReservationState : u64 { Held = 1, Released = 2 };
enum class SourceState : u64 { Active = 1 };
enum class ReleaseState : u64 { Released = 4 };

struct Target {
    u64 pid = 0, start = 0, netns = 0;
    bool operator==(const Target&) const = default;
};
struct Envelope {
    u64 version = kVersion, transaction = 0, domain = kClosedEvidenceDomain;
    ReportKind kind = ReportKind::ReservationSource;
    Binding binding = Binding::Phase;
    Phase phase = Phase::ReservationHeld;
    u64 sequence = 1;
    Target target;
};
struct Proc13 {
    u64 pid = 0, ppid = 0, sid = 0, start = 0, pgid = 0, uid = 0, gid = 0, netns = 0, exe_dev = 0,
        exe_ino = 0, no_new_privs = 0, capabilities_clear = 0, supplementary_groups = 0;
    bool operator==(const Proc13&) const = default;
};
struct ProcPair {
    u64 first_tag = 0;
    Proc13 first;
    u64 second_tag = 0;
    Proc13 second;
    bool operator==(const ProcPair&) const = default;
};
struct Settlement9 {
    u64 child_pid = 0, identity_pid = 0, identity_ppid = 0, identity_start = 0, identity_netns = 0,
        terminal = 0, reaped = 0, wait_status = 0, error_number = 0;
    bool operator==(const Settlement9&) const = default;
};
struct Cleanup14 {
    u64 destructor_attempted = 0, destructor_reportable_success = 0, child_attempted = 0,
        child_settled = 0, handoff_attempted = 0, handoff_closed = 0, null_attempted = 0,
        null_closed = 0, capture_settle_attempted = 0, capture_settled = 0,
        capture_close_attempted = 0, capture_closed = 0, diagnostic_phase = 0, diagnostic_error = 0;
    bool operator==(const Cleanup14&) const = default;
};
struct Release16 {
    u64 attempted = 0, destructor = 0, real_close_attempts = 0, real_close_result = 0,
        real_close_error = 0, reported_close_error = 0, immediate_fgetfd_result = 0,
        immediate_fgetfd_error = 0, immediate_ebadf = 0, post_inventory_checked = 0,
        baseline_restored = 0, socket_inode_absent = 0, reportable_success = 0, state = 0,
        diagnostic_phase = 0, diagnostic_error = 0;
    bool operator==(const Release16&) const = default;
};
using ReleaseReceipt16 = Release16;

struct ReservationSource {
    u64 reservation_state = 0, g_fd = 0, g_f_getfd = 0, g_f_getfl = 0, ipv4 = 0, port = 0, dev = 0,
        ino = 0, mode = 0, rdev = 0, socket_domain = 0, socket_type = 0, socket_protocol = 0,
        reuseaddr = 0, reuseport = 0, acceptconn = 0, proc_link_len = 0;
    u64 directory_dev = 0, directory_ino = 0, directory_mode = 0, directory_uid = 0,
        directory_gid = 0;
    u64 source_state = 0, source_dev = 0, source_ino = 0, source_mode = 0, source_uid = 0,
        source_gid = 0, source_size = 0, source_nlink = 0;
    u64 path_len = 0, bytes_len = 0;
    std::string proc_link, source_path, source_bytes;
    bool operator==(const ReservationSource&) const = default;
};
struct CollisionCross4 {
    u64 g_fd = 0, g_inode = 0, source_dev = 0, source_inode = 0;
    bool operator==(const CollisionCross4&) const = default;
};
struct CollisionHeader7 {
    u64 attempt_state = 0, outcome = 0, error_number = 0, child_pid = 0, child_start = 0,
        cmdline_provenance = 0, cmdline_len = 0;
    bool operator==(const CollisionHeader7&) const = default;
};
struct Classifier5 {
    u64 backend = 0, opt = 0, error_number = 0, error_source = 0, capture_len = 0;
    bool operator==(const Classifier5&) const = default;
};
struct CollisionAttempt {
    CollisionCross4 cross;
    CollisionHeader7 header;
    ProcPair procs;
    Settlement9 settlement;
    Cleanup14 cleanup;
    Classifier5 classifier;
    std::string cmdline;
    bool operator==(const CollisionAttempt&) const = default;
};
struct CollisionCapture {
    u64 capture_len = 0;
    std::string capture;
    bool operator==(const CollisionCapture&) const = default;
};
struct EvidenceClosed {
    u64 g_fd = 0, g_inode = 0, source_dev = 0, source_inode = 0, child_pid = 0, child_start = 0,
        attempt_state = 0, reservation_state = 0, source_state = 0, capture_len = 0;
    Cleanup14 cleanup;
    bool operator==(const EvidenceClosed&) const = default;
};
struct Release {
    u64 g_fd = 0, ipv4 = 0, port = 0, g_inode = 0;
    Release16 receipt;
    bool operator==(const Release&) const = default;
};
struct RetryPidfd4 {
    u64 pidfd_fd = 0, poll_result = 0, revents = 0, fdinfo_pid = 0;
    bool operator==(const RetryPidfd4&) const = default;
};
struct RetryStartup4 {
    u64 backend = 0, opt = 0, port = 0, capture_len = 0;
    bool operator==(const RetryStartup4&) const = default;
};
struct RetryLive {
    u64 source_dev = 0, source_inode = 0, source_size = 0, source_path_len = 0, g_inode = 0,
        port = 0;
    CollisionHeader7 header;
    ProcPair procs;
    RetryPidfd4 pidfd;
    RetryStartup4 startup;
    std::string source_path, cmdline;
    bool operator==(const RetryLive&) const = default;
};
struct RetryLiveCapture {
    u64 capture_len = 0;
    std::string capture;
    bool operator==(const RetryLiveCapture&) const = default;
};
struct RetrySettlement {
    u64 source_dev = 0, source_inode = 0, child_pid = 0, child_start = 0, attempt_state = 0;
    Settlement9 settlement;
    Cleanup14 cleanup;
    u64 final_capture_len = 0;
    bool operator==(const RetrySettlement&) const = default;
};
struct RetryFinalCapture {
    u64 capture_len = 0;
    std::string capture;
    bool operator==(const RetryFinalCapture&) const = default;
};

bool valid_envelope(const Envelope&, ReportKind);
bool valid_cmdline(const std::string&, const std::string& = {});
std::size_t max_payload(ReportKind);
worker::Frame encode_reservation_source(const worker::Token&,
                                        const Envelope&,
                                        const ReservationSource&);
worker::Frame encode_collision_attempt(const worker::Token&,
                                       const Envelope&,
                                       const CollisionAttempt&);
worker::Frame encode_collision_capture(const worker::Token&,
                                       const Envelope&,
                                       const CollisionCapture&);
worker::Frame encode_evidence_closed(const worker::Token&, const Envelope&, const EvidenceClosed&);
worker::Frame encode_release(const worker::Token&, const Envelope&, const Release&);
worker::Frame encode_retry_live(const worker::Token&, const Envelope&, const RetryLive&);
worker::Frame encode_retry_live_capture(const worker::Token&,
                                        const Envelope&,
                                        const RetryLiveCapture&);
worker::Frame encode_retry_settlement(const worker::Token&,
                                      const Envelope&,
                                      const RetrySettlement&);
worker::Frame encode_retry_final_capture(const worker::Token&,
                                         const Envelope&,
                                         const RetryFinalCapture&);
bool decode_reservation_source(const worker::Frame&,
                               const worker::Token&,
                               const Envelope&,
                               ReservationSource&);
bool decode_collision_attempt(const worker::Frame&,
                              const worker::Token&,
                              const Envelope&,
                              CollisionAttempt&);
bool decode_collision_capture(const worker::Frame&,
                              const worker::Token&,
                              const Envelope&,
                              CollisionCapture&);
bool decode_evidence_closed(const worker::Frame&,
                            const worker::Token&,
                            const Envelope&,
                            EvidenceClosed&);
bool decode_release(const worker::Frame&, const worker::Token&, const Envelope&, Release&);
bool decode_retry_live(const worker::Frame&, const worker::Token&, const Envelope&, RetryLive&);
bool decode_retry_live_capture(const worker::Frame&,
                               const worker::Token&,
                               const Envelope&,
                               RetryLiveCapture&);
bool decode_retry_settlement(const worker::Frame&,
                             const worker::Token&,
                             const Envelope&,
                             RetrySettlement&);
bool decode_retry_final_capture(const worker::Frame&,
                                const worker::Token&,
                                const Envelope&,
                                RetryFinalCapture&);

enum class State : std::uint8_t {
    AwaitReservationSource,
    AwaitCollisionAttempt,
    AwaitCollisionCapture,
    AwaitEvidenceClosed,
    AwaitRelease,
    AwaitRetryLive,
    AwaitRetryLiveCapture,
    AwaitRetrySettlement,
    AwaitRetryFinalCapture,
    AwaitFinish,
    Complete,
    Failed
};
struct ReceiverContext {
    worker::Token token;
    u64 transaction = 0;
    u64 domain = kClosedEvidenceDomain;
    Target target;
    ReservationSource expected_source;
    std::string expected_cmdline;
};
class Receiver {
public:
    explicit Receiver(const ReceiverContext& c) : context_(c) {}
    bool observe(const worker::Frame&);
    bool finish();
    State state() const { return state_; }
    const ReservationSource& source() const { return source_; }
    const RetryLive& retry_live() const { return retry_live_; }

private:
    bool fail() {
        state_ = State::Failed;
        return false;
    }
    bool envelope_ok(const Envelope&, ReportKind, Binding, Phase, u64) const;
    ReceiverContext context_;
    State state_ = State::AwaitReservationSource;
    ReservationSource source_;
    CollisionAttempt collision_;
    CollisionCapture collision_capture_;
    EvidenceClosed closed_;
    Release release_;
    RetryLive retry_live_;
    std::string live_capture_;
    RetrySettlement retry_settlement_;
};
using CanonicalEvidenceReceiver = Receiver;
using EvidenceEnvelope = Envelope;
}  // namespace rut::test::fixture_collision_release_evidence_protocol
