#include "fixture_collision_release_evidence_protocol.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <sys/wait.h>

namespace rut::test::fixture_collision_release_evidence_protocol {
namespace {

using Bytes = std::vector<unsigned char>;
void put(Bytes& b, u64 v) {
    for (unsigned s = 0; s != 64; s += 8) b.push_back(static_cast<unsigned char>(v >> s));
}
bool get(const Bytes& b, std::size_t& p, u64& v) {
    if (p > b.size() || b.size() - p < 8) return false;
    v = 0;
    for (unsigned s = 0; s != 64; s += 8) v |= static_cast<u64>(b[p++]) << s;
    return true;
}
void put_string(Bytes& b, const std::string& s) {
    b.insert(b.end(), s.begin(), s.end());
}
bool get_string(const Bytes& b, std::size_t& p, std::size_t n, std::string& s) {
    if (p > b.size() || n > b.size() - p) return false;
    s.assign(reinterpret_cast<const char*>(b.data() + p), n);
    p += n;
    return true;
}
template <std::size_t N>
void put_array(Bytes& b, const std::array<u64, N>& a) {
    for (u64 v : a) put(b, v);
}
template <std::size_t N>
bool get_array(const Bytes& b, std::size_t& p, std::array<u64, N>& a) {
    for (u64& v : a)
        if (!get(b, p, v)) return false;
    return true;
}
void put_proc(Bytes& b, const Proc13& x) {
    put(b, x.pid);
    put(b, x.ppid);
    put(b, x.sid);
    put(b, x.start);
    put(b, x.pgid);
    put(b, x.uid);
    put(b, x.gid);
    put(b, x.netns);
    put(b, x.exe_dev);
    put(b, x.exe_ino);
    put(b, x.no_new_privs);
    put(b, x.capabilities_clear);
    put(b, x.supplementary_groups);
}
bool get_proc(const Bytes& b, std::size_t& p, Proc13& x) {
    return get(b, p, x.pid) && get(b, p, x.ppid) && get(b, p, x.sid) && get(b, p, x.start) &&
           get(b, p, x.pgid) && get(b, p, x.uid) && get(b, p, x.gid) && get(b, p, x.netns) &&
           get(b, p, x.exe_dev) && get(b, p, x.exe_ino) && get(b, p, x.no_new_privs) &&
           get(b, p, x.capabilities_clear) && get(b, p, x.supplementary_groups);
}
void put_pair(Bytes& b, const ProcPair& x) {
    put(b, x.first_tag);
    put_proc(b, x.first);
    put(b, x.second_tag);
    put_proc(b, x.second);
}
bool get_pair(const Bytes& b, std::size_t& p, ProcPair& x) {
    return get(b, p, x.first_tag) && get_proc(b, p, x.first) && get(b, p, x.second_tag) &&
           get_proc(b, p, x.second);
}
void put_settlement(Bytes& b, const Settlement9& x) {
    put(b, x.child_pid);
    put(b, x.identity_pid);
    put(b, x.identity_ppid);
    put(b, x.identity_start);
    put(b, x.identity_netns);
    put(b, x.terminal);
    put(b, x.reaped);
    put(b, x.wait_status);
    put(b, x.error);
}
bool get_settlement(const Bytes& b, std::size_t& p, Settlement9& x) {
    return get(b, p, x.child_pid) && get(b, p, x.identity_pid) && get(b, p, x.identity_ppid) &&
           get(b, p, x.identity_start) && get(b, p, x.identity_netns) && get(b, p, x.terminal) &&
           get(b, p, x.reaped) && get(b, p, x.wait_status) && get(b, p, x.error);
}
void put_cleanup(Bytes& b, const Cleanup14& x) {
    put(b, x.attempted);
    put(b, x.succeeded);
    put(b, x.child_attempted);
    put(b, x.child_settled);
    put(b, x.handoff_attempted);
    put(b, x.handoff_closed);
    put(b, x.null_attempted);
    put(b, x.null_closed);
    put(b, x.capture_settle_attempted);
    put(b, x.capture_settled);
    put(b, x.capture_close_attempted);
    put(b, x.capture_closed);
    put(b, x.diagnostic_phase);
    put(b, x.diagnostic_error);
}
bool get_cleanup(const Bytes& b, std::size_t& p, Cleanup14& x) {
    return get(b, p, x.attempted) && get(b, p, x.succeeded) && get(b, p, x.child_attempted) &&
           get(b, p, x.child_settled) && get(b, p, x.handoff_attempted) &&
           get(b, p, x.handoff_closed) && get(b, p, x.null_attempted) && get(b, p, x.null_closed) &&
           get(b, p, x.capture_settle_attempted) && get(b, p, x.capture_settled) &&
           get(b, p, x.capture_close_attempted) && get(b, p, x.capture_closed) &&
           get(b, p, x.diagnostic_phase) && get(b, p, x.diagnostic_error);
}
void put_receipt(Bytes& b, const ReleaseReceipt16& x) {
    put(b, x.attempted);
    put(b, x.destructor);
    put(b, x.real_close_attempts);
    put(b, x.real_close_result);
    put(b, x.real_close_error);
    put(b, x.reported_close_error);
    put(b, x.immediate_fgetfd_result);
    put(b, x.immediate_fgetfd_error);
    put(b, x.immediate_ebadf);
    put(b, x.post_inventory_checked);
    put(b, x.baseline_restored);
    put(b, x.socket_inode_absent);
    put(b, x.reportable_success);
    put(b, x.state);
    put(b, x.diagnostic_phase);
    put(b, x.diagnostic_error);
}
bool get_receipt(const Bytes& b, std::size_t& p, ReleaseReceipt16& x) {
    return get(b, p, x.attempted) && get(b, p, x.destructor) && get(b, p, x.real_close_attempts) &&
           get(b, p, x.real_close_result) && get(b, p, x.real_close_error) &&
           get(b, p, x.reported_close_error) && get(b, p, x.immediate_fgetfd_result) &&
           get(b, p, x.immediate_fgetfd_error) && get(b, p, x.immediate_ebadf) &&
           get(b, p, x.post_inventory_checked) && get(b, p, x.baseline_restored) &&
           get(b, p, x.socket_inode_absent) && get(b, p, x.reportable_success) &&
           get(b, p, x.state) && get(b, p, x.diagnostic_phase) && get(b, p, x.diagnostic_error);
}

Bytes envelope_bytes(const Envelope& e, std::size_t body) {
    Bytes b;
    b.reserve(kEnvelopeBytes);
    put(b, e.version);
    put(b, e.transaction);
    put(b, e.domain);
    put(b, static_cast<u64>(e.kind));
    put(b, static_cast<u64>(e.binding));
    put(b, static_cast<u64>(e.phase));
    put(b, e.sequence);
    put(b, e.target.pid);
    put(b, e.target.start);
    put(b, e.target.netns);
    put(b, body);
    return b;
}
bool parse_envelope(const Bytes& b, Envelope& e, std::size_t& p) {
    u64 kind = 0, binding = 0, phase = 0;
    if (b.size() < kEnvelopeBytes || !get(b, p, e.version) || !get(b, p, e.transaction) ||
        !get(b, p, e.domain) || !get(b, p, kind) || !get(b, p, binding) || !get(b, p, phase) ||
        !get(b, p, e.sequence) || !get(b, p, e.target.pid) || !get(b, p, e.target.start) ||
        !get(b, p, e.target.netns))
        return false;
    u64 body = 0;
    if (!get(b, p, body) || body != b.size() - kEnvelopeBytes || kind == 0 || kind > 9 ||
        binding < 1 || binding > 2 || phase < 1 || phase > 5)
        return false;
    e.kind = static_cast<ReportKind>(kind);
    e.binding = static_cast<Binding>(binding);
    e.phase = static_cast<Phase>(phase);
    return true;
}
bool frame_start(const worker::Frame& f,
                 const worker::Token& t,
                 const Envelope& expected,
                 ReportKind k,
                 Envelope& e,
                 std::size_t& p) {
    if (f.type != kEvidenceFrameType || !worker::token_equal(f.token, t) ||
        f.payload.size() > worker::kMaxPayload || f.payload.size() > max_payload(k))
        return false;
    if (!parse_envelope(f.payload, e, p) || e.kind != k || !valid_envelope(e, k) ||
        e.version != expected.version || e.transaction != expected.transaction ||
        e.domain != expected.domain || e.binding != expected.binding || e.phase != expected.phase ||
        e.sequence != expected.sequence || !(e.target == expected.target))
        return false;
    return true;
}
template <typename T>
worker::Frame make(
    const worker::Token& t, const Envelope& e, ReportKind k, const Bytes& body, T max) {
    if (e.kind != k || !valid_envelope(e, k) || body.size() + kEnvelopeBytes > max)
        return {0, {}, {}};
    Bytes p = envelope_bytes(e, body.size());
    p.insert(p.end(), body.begin(), body.end());
    return {kEvidenceFrameType, t, std::move(p)};
}
bool end(const Bytes& b, std::size_t p) {
    return p == b.size();
}
bool all_zero(const Proc13& x) {
    static const Proc13 z{};
    return x == z;
}

template <std::size_t N>
bool decode_fixed(const worker::Frame& f,
                  const worker::Token& t,
                  const Envelope& e,
                  ReportKind k,
                  std::array<u64, N>& a) {
    Envelope got;
    std::size_t p = 0;
    if (!frame_start(f, t, e, k, got, p) || !get_array(f.payload, p, a) || !end(f.payload, p))
        return false;
    return true;
}
}  // namespace

bool valid_envelope(const Envelope& e, ReportKind k) {
    return e.version == kVersion && e.transaction != 0 && e.domain == kClosedEvidenceDomain &&
           e.kind == k && e.sequence != 0 && e.target.pid != 0 && e.target.start != 0 &&
           e.target.netns != 0;
}
std::size_t max_payload(ReportKind k) {
    switch (k) {
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
    return 0;
}

bool valid_cmdline(const std::string& s, const std::string& path) {
    if (s.empty() || s.size() > kMaxCmdline || s.back() != '\0') return false;
    std::vector<std::string> a;
    std::size_t p = 0;
    while (p < s.size()) {
        std::size_t q = s.find('\0', p);
        if (q == std::string::npos || q == p) return false;
        a.emplace_back(s, p, q - p);
        p = q + 1;
    }
    if (a.size() != 9 || a[0].empty() || a[0].size() > 4095 || (!path.empty() && a[1] != path) ||
        a[1].size() > 181)
        return false;
    return a[2] == "--shards" && a[3] == "1" && a[4] == "--no-pin" && a[5] == "--drain" &&
           a[6] == "0" && a[7] == "--opt" && a[8] == "2";
}

worker::Frame encode_reservation_source(const worker::Token& t,
                                        const Envelope& e,
                                        const ReservationSource& x) {
    if (x.proc_link.size() > kMaxProcLink || x.source_path.size() > kMaxSourcePath ||
        x.source_bytes.size() > kMaxSourceBytes || x.scalars[16] != x.proc_link.size() ||
        x.scalars[30] != x.source_path.size() || x.scalars[31] != x.source_bytes.size() ||
        x.source_path.find('\0') != std::string::npos ||
        x.proc_link.find('\0') != std::string::npos)
        return {0, {}, {}};
    Bytes b;
    put_array(b, x.scalars);
    put_string(b, x.proc_link);
    put_string(b, x.source_path);
    put_string(b, x.source_bytes);
    return make(t, e, ReportKind::ReservationSource, b, kReservationSourceMax);
}
worker::Frame encode_collision_attempt(const worker::Token& t,
                                       const Envelope& e,
                                       const CollisionAttempt& x) {
    Bytes b;
    put_array(b, x.meta);
    put_pair(b, x.procs);
    put_settlement(b, x.settlement);
    put_cleanup(b, x.cleanup);
    put_string(b, x.cmdline);
    return make(t, e, ReportKind::CollisionAttempt, b, kCollisionAttemptMax);
}
worker::Frame encode_collision_capture(const worker::Token& t,
                                       const Envelope& e,
                                       const CollisionCapture& x) {
    Bytes b;
    put(b, x.marker);
    put_string(b, x.capture);
    return make(t, e, ReportKind::CollisionCapture, b, kCollisionCaptureMax);
}
worker::Frame encode_evidence_closed(const worker::Token& t,
                                     const Envelope& e,
                                     const EvidenceClosed& x) {
    Bytes b;
    put_array(b, x.meta);
    put_cleanup(b, x.cleanup);
    return make(t, e, ReportKind::EvidenceClosed, b, kEvidenceClosedMax);
}
worker::Frame encode_release(const worker::Token& t, const Envelope& e, const Release& x) {
    Bytes b;
    put_array(b, x.meta);
    put_receipt(b, x.receipt);
    return make(t, e, ReportKind::Release, b, kReleaseMax);
}
worker::Frame encode_retry_live(const worker::Token& t, const Envelope& e, const RetryLive& x) {
    if (x.cmdline.size() > kMaxCmdline || x.metadata.size() > 37u) return {0, {}, {}};
    Bytes b;
    auto m = x.meta;
    m[15] = x.metadata.size();
    put_array(b, m);
    put_pair(b, x.procs);
    put_settlement(b, x.settlement);
    put_cleanup(b, x.cleanup);
    put_string(b, x.cmdline);
    put_string(b, x.metadata);
    return make(t, e, ReportKind::RetryLive, b, kRetryLiveMax);
}
worker::Frame encode_retry_live_capture(const worker::Token& t,
                                        const Envelope& e,
                                        const RetryLiveCapture& x) {
    Bytes b;
    put(b, x.marker);
    put_string(b, x.capture);
    return make(t, e, ReportKind::RetryLiveCapture, b, kRetryLiveCaptureMax);
}
worker::Frame encode_retry_settlement(const worker::Token& t,
                                      const Envelope& e,
                                      const RetrySettlement& x) {
    Bytes b;
    put_array(b, x.meta);
    put_settlement(b, x.settlement);
    return make(t, e, ReportKind::RetrySettlement, b, kRetrySettlementMax);
}
worker::Frame encode_retry_final_capture(const worker::Token& t,
                                         const Envelope& e,
                                         const RetryFinalCapture& x) {
    Bytes b;
    put(b, x.marker);
    put_string(b, x.capture);
    return make(t, e, ReportKind::RetryFinalCapture, b, kRetryFinalCaptureMax);
}

bool decode_reservation_source(const worker::Frame& f,
                               const worker::Token& t,
                               const Envelope& e,
                               ReservationSource& o) {
    Envelope g;
    std::size_t p = 0;
    ReservationSource x;
    if (!frame_start(f, t, e, ReportKind::ReservationSource, g, p) ||
        !get_array(f.payload, p, x.scalars))
        return false;
    const std::size_t n = f.payload.size() - p;
    if (x.scalars[16] > kMaxProcLink || x.scalars[30] > kMaxSourcePath ||
        x.scalars[31] > kMaxSourceBytes || x.scalars[16] > n || x.scalars[30] > n - x.scalars[16] ||
        x.scalars[31] != n - x.scalars[16] - x.scalars[30])
        return false;
    if (x.scalars[2] != static_cast<u64>(FD_CLOEXEC) ||
        (x.scalars[3] & 3u) != static_cast<u64>(O_RDWR) ||
        (x.scalars[3] & (O_NONBLOCK | O_APPEND | O_ASYNC)) != 0u)
        return false;
    if (!get_string(f.payload, p, x.scalars[16], x.proc_link) ||
        !get_string(f.payload, p, x.scalars[30], x.source_path) ||
        !get_string(f.payload, p, x.scalars[31], x.source_bytes) || !end(f.payload, p) ||
        x.proc_link != "socket:[" + std::to_string(x.scalars[7]) + ']' ||
        x.source_path.find('\0') != std::string::npos)
        return false;
    o = x;
    return true;
}
bool decode_collision_attempt(const worker::Frame& f,
                              const worker::Token& t,
                              const Envelope& e,
                              CollisionAttempt& o) {
    Envelope g;
    std::size_t p = 0;
    CollisionAttempt x;
    if (!frame_start(f, t, e, ReportKind::CollisionAttempt, g, p) ||
        !get_array(f.payload, p, x.meta) || !get_pair(f.payload, p, x.procs) ||
        !get_settlement(f.payload, p, x.settlement) || !get_cleanup(f.payload, p, x.cleanup))
        return false;
    if (!get_string(f.payload, p, f.payload.size() - p, x.cmdline) || !end(f.payload, p) ||
        !valid_cmdline(x.cmdline))
        return false;
    o = x;
    return true;
}
bool decode_collision_capture(const worker::Frame& f,
                              const worker::Token& t,
                              const Envelope& e,
                              CollisionCapture& o) {
    Envelope g;
    std::size_t p = 0;
    CollisionCapture x;
    if (!frame_start(f, t, e, ReportKind::CollisionCapture, g, p) || !get(f.payload, p, x.marker) ||
        f.payload.size() - p > kMaxCapture ||
        !get_string(f.payload, p, f.payload.size() - p, x.capture) || !end(f.payload, p))
        return false;
    o = x;
    return true;
}
bool decode_evidence_closed(const worker::Frame& f,
                            const worker::Token& t,
                            const Envelope& e,
                            EvidenceClosed& o) {
    Envelope g;
    std::size_t p = 0;
    EvidenceClosed x;
    if (!frame_start(f, t, e, ReportKind::EvidenceClosed, g, p) ||
        !get_array(f.payload, p, x.meta) || !get_cleanup(f.payload, p, x.cleanup) ||
        !end(f.payload, p))
        return false;
    o = x;
    return true;
}
bool decode_release(const worker::Frame& f, const worker::Token& t, const Envelope& e, Release& o) {
    Envelope g;
    std::size_t p = 0;
    Release x;
    if (!frame_start(f, t, e, ReportKind::Release, g, p) || !get_array(f.payload, p, x.meta) ||
        !get_receipt(f.payload, p, x.receipt) || !end(f.payload, p))
        return false;
    o = x;
    return true;
}
bool decode_retry_live(const worker::Frame& f,
                       const worker::Token& t,
                       const Envelope& e,
                       RetryLive& o) {
    Envelope g;
    std::size_t p = 0;
    RetryLive x;
    if (!frame_start(f, t, e, ReportKind::RetryLive, g, p) || !get_array(f.payload, p, x.meta) ||
        x.meta[15] > 37 || !get_pair(f.payload, p, x.procs) ||
        !get_settlement(f.payload, p, x.settlement) || !get_cleanup(f.payload, p, x.cleanup))
        return false;
    const std::size_t n = f.payload.size() - p;
    if (n < 1 + x.meta[15] || n > kMaxCmdline + 37) return false;
    const std::size_t cmd_n = n - x.meta[15];
    if (!get_string(f.payload, p, cmd_n, x.cmdline) ||
        !get_string(f.payload, p, x.meta[15], x.metadata) || !end(f.payload, p) ||
        !valid_cmdline(x.cmdline))
        return false;
    o = x;
    return true;
}
bool decode_retry_live_capture(const worker::Frame& f,
                               const worker::Token& t,
                               const Envelope& e,
                               RetryLiveCapture& o) {
    Envelope g;
    std::size_t p = 0;
    RetryLiveCapture x;
    if (!frame_start(f, t, e, ReportKind::RetryLiveCapture, g, p) || !get(f.payload, p, x.marker) ||
        f.payload.size() - p > kMaxCapture ||
        !get_string(f.payload, p, f.payload.size() - p, x.capture) || !end(f.payload, p))
        return false;
    o = x;
    return true;
}
bool decode_retry_settlement(const worker::Frame& f,
                             const worker::Token& t,
                             const Envelope& e,
                             RetrySettlement& o) {
    Envelope g;
    std::size_t p = 0;
    RetrySettlement x;
    if (!frame_start(f, t, e, ReportKind::RetrySettlement, g, p) ||
        !get_array(f.payload, p, x.meta) || !get_settlement(f.payload, p, x.settlement) ||
        !end(f.payload, p))
        return false;
    o = x;
    return true;
}
bool decode_retry_final_capture(const worker::Frame& f,
                                const worker::Token& t,
                                const Envelope& e,
                                RetryFinalCapture& o) {
    Envelope g;
    std::size_t p = 0;
    RetryFinalCapture x;
    if (!frame_start(f, t, e, ReportKind::RetryFinalCapture, g, p) ||
        !get(f.payload, p, x.marker) || f.payload.size() - p > kMaxCapture ||
        !get_string(f.payload, p, f.payload.size() - p, x.capture) || !end(f.payload, p))
        return false;
    o = x;
    return true;
}

bool Receiver::envelope_ok(const Envelope& e, ReportKind k, Binding b, Phase p, u64 seq) const {
    return e.version == kVersion && e.transaction == context_.transaction &&
           e.domain == context_.domain && e.kind == k && e.binding == b && e.phase == p &&
           e.sequence == seq && e.target == context_.target;
}
bool Receiver::observe(const worker::Frame& f) {
    if (state_ == State::Failed || state_ == State::Complete || state_ == State::AwaitFinish)
        return fail();
    Envelope e;
    e.version = kVersion;
    e.transaction = context_.transaction;
    e.domain = context_.domain;
    e.target = context_.target;
    switch (state_) {
        case State::AwaitReservationSource: {
            e.kind = ReportKind::ReservationSource;
            e.binding = Binding::Phase;
            e.phase = Phase::ReservationHeld;
            e.sequence = 1;
            ReservationSource x;
            if (!envelope_ok(e, e.kind, e.binding, e.phase, e.sequence) ||
                !decode_reservation_source(f, context_.token, e, x))
                return fail();
            if (!context_.expected_source.proc_link.empty() &&
                !(x.proc_link == context_.expected_source.proc_link &&
                  x.source_path == context_.expected_source.source_path &&
                  x.source_bytes == context_.expected_source.source_bytes))
                return fail();
            source_ = x;
            state_ = State::AwaitCollisionAttempt;
            return true;
        }
        case State::AwaitCollisionAttempt: {
            e.kind = ReportKind::CollisionAttempt;
            e.binding = Binding::Phase;
            e.phase = Phase::CollisionNaturallyRejectedEvidenceOpen;
            e.sequence = 3;
            CollisionAttempt x;
            if (!decode_collision_attempt(f, context_.token, e, x) ||
                !valid_cmdline(x.cmdline, source_.source_path) || x.meta[0] != 2 ||
                x.meta[1] != 98 || x.meta[2] != 4)
                return fail();
            const bool absent = x.procs.first_tag == 0 && x.procs.second_tag == 0 &&
                                all_zero(x.procs.first) && all_zero(x.procs.second);
            const bool live = x.procs.first_tag == 1 && x.procs.second_tag == 1 &&
                              x.procs.first == x.procs.second &&
                              x.procs.first.pid == x.settlement.child_pid &&
                              x.procs.first.ppid == context_.target.pid &&
                              x.procs.first.netns == context_.target.netns;
            if (!absent && !live) return fail();
            if (!context_.expected_cmdline.empty() && x.cmdline != context_.expected_cmdline)
                return fail();
            if (x.settlement.terminal != 1 || x.settlement.reaped != 1 || x.settlement.error != 0 ||
                x.settlement.identity_ppid != context_.target.pid ||
                x.settlement.identity_netns != context_.target.netns ||
                ((x.settlement.wait_status & 0x7fu) != 0u) ||
                ((x.settlement.wait_status >> 8u) & 0xffu) != 1u)
                return fail();
            collision_ = x;
            state_ = State::AwaitCollisionCapture;
            return true;
        }
        case State::AwaitCollisionCapture: {
            e.kind = ReportKind::CollisionCapture;
            e.binding = Binding::Phase;
            e.phase = Phase::CollisionNaturallyRejectedEvidenceOpen;
            e.sequence = 3;
            CollisionCapture x;
            if (!decode_collision_capture(f, context_.token, e, x) || x.marker != 1 ||
                x.capture.empty())
                return fail();
            state_ = State::AwaitEvidenceClosed;
            return true;
        }
        case State::AwaitEvidenceClosed: {
            e.kind = ReportKind::EvidenceClosed;
            e.binding = Binding::Phase;
            e.phase = Phase::EvidenceClosedReservationHeld;
            e.sequence = 5;
            EvidenceClosed x;
            if (!decode_evidence_closed(f, context_.token, e, x) || x.cleanup.succeeded != 1 ||
                x.cleanup.capture_closed != 1)
                return fail();
            state_ = State::AwaitRelease;
            return true;
        }
        case State::AwaitRelease: {
            e.kind = ReportKind::Release;
            e.binding = Binding::Phase;
            e.phase = Phase::ReservationReleased;
            e.sequence = 7;
            Release x;
            if (!decode_release(f, context_.token, e, x) || x.receipt.real_close_attempts != 1 ||
                x.receipt.real_close_result != 0 || x.receipt.reported_close_error != 0 ||
                x.receipt.immediate_fgetfd_result != ~u64(0) ||
                x.receipt.immediate_fgetfd_error != 9 || x.receipt.immediate_ebadf != 1 ||
                x.receipt.post_inventory_checked != 1 || x.receipt.baseline_restored != 1 ||
                x.receipt.socket_inode_absent != 1 || x.receipt.reportable_success != 1 ||
                x.receipt.state != 4 || x.receipt.diagnostic_phase != 0 ||
                x.receipt.diagnostic_error != 0)
                return fail();
            state_ = State::AwaitRetryLive;
            return true;
        }
        case State::AwaitRetryLive: {
            e.kind = ReportKind::RetryLive;
            e.binding = Binding::Phase;
            e.phase = Phase::RetryLive;
            e.sequence = 9;
            RetryLive x;
            if (!decode_retry_live(f, context_.token, e, x) ||
                !valid_cmdline(x.cmdline, source_.source_path) || x.procs.first_tag != 1 ||
                x.procs.second_tag != 1 || !(x.procs.first == x.procs.second) ||
                x.procs.first.ppid != context_.target.pid ||
                x.procs.first.netns != context_.target.netns ||
                x.procs.first.pid == collision_.settlement.child_pid ||
                x.procs.first.start == collision_.procs.first.start)
                return fail();
            retry_live_ = x;
            state_ = State::AwaitRetryLiveCapture;
            return true;
        }
        case State::AwaitRetryLiveCapture: {
            e.kind = ReportKind::RetryLiveCapture;
            e.binding = Binding::Phase;
            e.phase = Phase::RetryLive;
            e.sequence = 9;
            RetryLiveCapture x;
            if (!decode_retry_live_capture(f, context_.token, e, x) || x.marker != 1 ||
                x.capture.empty())
                return fail();
            live_capture_ = x.capture;
            state_ = State::AwaitRetrySettlement;
            return true;
        }
        case State::AwaitRetrySettlement: {
            e.kind = ReportKind::RetrySettlement;
            e.binding = Binding::Settlement;
            e.phase = Phase::RetryLive;
            e.sequence = 11;
            RetrySettlement x;
            if (!decode_retry_settlement(f, context_.token, e, x) ||
                x.settlement.identity_pid != retry_live_.procs.first.pid ||
                x.settlement.identity_start != retry_live_.procs.first.start ||
                x.settlement.terminal != 1 || x.settlement.reaped != 1)
                return fail();
            state_ = State::AwaitRetryFinalCapture;
            return true;
        }
        case State::AwaitRetryFinalCapture: {
            e.kind = ReportKind::RetryFinalCapture;
            e.binding = Binding::Settlement;
            e.phase = Phase::RetryLive;
            e.sequence = 11;
            RetryFinalCapture x;
            if (!decode_retry_final_capture(f, context_.token, e, x) ||
                x.capture.size() < live_capture_.size() || x.capture.size() > kMaxCapture ||
                std::memcmp(x.capture.data(), live_capture_.data(), live_capture_.size()) != 0)
                return fail();
            state_ = State::AwaitFinish;
            return true;
        }
        default:
            return fail();
    }
}
bool Receiver::finish() {
    if (state_ != State::AwaitFinish) return fail();
    state_ = State::Complete;
    return true;
}

}  // namespace rut::test::fixture_collision_release_evidence_protocol
