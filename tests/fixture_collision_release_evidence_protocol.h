#pragma once

#include "fixture_worker_protocol.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rut::test::fixture_collision_release_evidence_protocol {

namespace worker = fixture_worker_protocol;
using u64 = worker::u64;

inline constexpr worker::u16 kEvidenceFrameType = 59u;
inline constexpr u64 kVersion = 2u;
inline constexpr u64 kClosedEvidenceDomain = 1u;
inline constexpr std::size_t kEnvelopeBytes = 11u * sizeof(u64);
inline constexpr std::size_t kProcScalars = 13u;
inline constexpr std::size_t kProcPairScalars = 28u;
inline constexpr std::size_t kSettlementScalars = 9u;
inline constexpr std::size_t kCleanupScalars = 14u;
inline constexpr std::size_t kReleaseReceiptScalars = 16u;
inline constexpr std::size_t kMaxProcLink = 29u;
inline constexpr std::size_t kMaxSourcePath = 181u;
inline constexpr std::size_t kMaxSourceBytes = 255u;
inline constexpr std::size_t kMaxCmdline = 4316u;
inline constexpr std::size_t kMaxCapture = 4096u;

// The maxima include the 88-byte envelope.  They are deliberately exposed so
// callers can test the exact boundary without depending on implementation
// layout.
inline constexpr std::size_t kReservationSourceMax = 809u;
inline constexpr std::size_t kCollisionAttemptMax = 4940u;
inline constexpr std::size_t kCollisionCaptureMax = 4192u;
inline constexpr std::size_t kEvidenceClosedMax = 280u;
inline constexpr std::size_t kReleaseMax = 248u;
inline constexpr std::size_t kRetryLiveMax = 4977u;
inline constexpr std::size_t kRetryLiveCaptureMax = 4192u;
inline constexpr std::size_t kRetrySettlementMax = 320u;
inline constexpr std::size_t kRetryFinalCaptureMax = 4192u;

enum class ReportKind : u64 {
    ReservationSource = 1u,
    CollisionAttempt = 2u,
    CollisionCapture = 3u,
    EvidenceClosed = 4u,
    Release = 5u,
    RetryLive = 6u,
    RetryLiveCapture = 7u,
    RetrySettlement = 8u,
    RetryFinalCapture = 9u,
};
enum class Binding : u64 { Phase = 1u, Settlement = 2u };
enum class Phase : u64 {
    ReservationHeld = 1u,
    CollisionNaturallyRejectedEvidenceOpen = 2u,
    EvidenceClosedReservationHeld = 3u,
    ReservationReleased = 4u,
    RetryLive = 5u,
};

struct Target {
    u64 pid = 0u;
    u64 start = 0u;
    u64 netns = 0u;
    bool operator==(const Target&) const = default;
};
struct Envelope {
    u64 version = kVersion;
    u64 transaction = 0u;
    u64 domain = kClosedEvidenceDomain;
    ReportKind kind = ReportKind::ReservationSource;
    Binding binding = Binding::Phase;
    Phase phase = Phase::ReservationHeld;
    u64 sequence = 1u;
    Target target;
};

// These are scalar projections.  In particular, none is an ABI copy of a
// procfs record, wait status, fd snapshot, or cleanup receipt.
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
        terminal = 0, reaped = 0, wait_status = 0, error = 0;
    bool operator==(const Settlement9&) const = default;
};
struct Cleanup14 {
    u64 attempted = 0, succeeded = 0, child_attempted = 0, child_settled = 0, handoff_attempted = 0,
        handoff_closed = 0, null_attempted = 0, null_closed = 0, capture_settle_attempted = 0,
        capture_settled = 0, capture_close_attempted = 0, capture_closed = 0, diagnostic_phase = 0,
        diagnostic_error = 0;
    bool operator==(const Cleanup14&) const = default;
};
struct ReleaseReceipt16 {
    u64 attempted = 0, destructor = 0, real_close_attempts = 0, real_close_result = 0,
        real_close_error = 0, reported_close_error = 0, immediate_fgetfd_result = 0,
        immediate_fgetfd_error = 0, immediate_ebadf = 0, post_inventory_checked = 0,
        baseline_restored = 0, socket_inode_absent = 0, reportable_success = 0, state = 0,
        diagnostic_phase = 0, diagnostic_error = 0;
    bool operator==(const ReleaseReceipt16&) const = default;
};

struct ReservationSource {
    // G17 occupies [0..16] (state, fd, F_GETFD, F_GETFL, B, P, dev, ino,
    // mode, rdev, domain, type, protocol, reuseaddr, reuseport, acceptconn,
    // link length). The remaining scalar slots carry Directory5, Source8,
    // endpoint and the three variable lengths. Keeping this projection
    // scalar-only avoids copying FdSnapshot or stat ABI objects.
    std::array<u64, 32> scalars{};
    std::string proc_link, source_path, source_bytes;
    bool operator==(const ReservationSource&) const = default;
};
struct CollisionAttempt {
    std::array<u64, 16> meta{};
    ProcPair procs;
    Settlement9 settlement;
    Cleanup14 cleanup;
    std::string cmdline;
};
struct CollisionCapture {
    u64 marker = 0;
    std::string capture;
};
struct EvidenceClosed {
    std::array<u64, 10> meta{};
    Cleanup14 cleanup;
};
struct Release {
    std::array<u64, 4> meta{};
    ReleaseReceipt16 receipt;
};
struct RetryLive {
    std::array<u64, 16> meta{};
    ProcPair procs;
    Settlement9 settlement;
    Cleanup14 cleanup;
    std::string cmdline, metadata;
};
struct RetryLiveCapture {
    u64 marker = 0;
    std::string capture;
};
struct RetrySettlement {
    std::array<u64, 20> meta{};
    Settlement9 settlement;
};
struct RetryFinalCapture {
    u64 marker = 0;
    std::string capture;
};

bool valid_envelope(const Envelope& envelope, ReportKind kind);
bool valid_cmdline(const std::string& cmdline, const std::string& source_path = {});
std::size_t max_payload(ReportKind kind);

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
    u64 transaction = 0u;
    u64 domain = kClosedEvidenceDomain;
    Target target;
    ReservationSource expected_source;
    std::string expected_cmdline;
};

class Receiver {
public:
    explicit Receiver(const ReceiverContext& context) : context_(context) {}
    bool observe(const worker::Frame& frame);
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
    RetryLive retry_live_;
    std::string live_capture_;
};

using CanonicalEvidenceReceiver = Receiver;
using EvidenceEnvelope = Envelope;

}  // namespace rut::test::fixture_collision_release_evidence_protocol
