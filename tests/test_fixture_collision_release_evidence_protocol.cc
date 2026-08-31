#include "fixture_collision_release_evidence_protocol.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <limits>

namespace p = rut::test::fixture_collision_release_evidence_protocol;
namespace w = rut::test::fixture_worker_protocol;

static w::Token token() {
    w::Token t{};
    for (std::size_t i = 0; i < t.bytes.size(); ++i) t.bytes[i] = static_cast<unsigned char>(i + 3);
    return t;
}
static std::string argv() {
    std::string s;
    for (const char* a :
         {"/bin/rut", "/tmp/source", "--shards", "1", "--no-pin", "--drain", "0", "--opt", "2"}) {
        s += a;
        s.push_back('\0');
    }
    return s;
}
static p::Envelope env(p::ReportKind k, p::Binding b, p::Phase phase, w::u64 seq) {
    p::Envelope e;
    e.transaction = 0x37759;
    e.kind = k;
    e.binding = b;
    e.phase = phase;
    e.sequence = seq;
    e.target = {77, 991, 55};
    return e;
}
static p::ReservationSource source() {
    p::ReservationSource x;
    x.scalars[2] = 1;
    x.scalars[3] = 2;
    x.scalars[7] = 123456;
    x.proc_link = "socket:[123456]";
    x.source_path = "/tmp/source";
    x.source_bytes = std::string(32, 's');
    x.scalars[16] = x.proc_link.size();
    x.scalars[30] = x.source_path.size();
    x.scalars[31] = x.source_bytes.size();
    return x;
}
static p::ProcPair live_proc(w::u64 pid, w::u64 start = 1000) {
    p::ProcPair x;
    x.first_tag = x.second_tag = 1;
    x.first = {pid, 77, 1, start, 1, 1000, 1000, 55, 2, 3, 1, 1, 0};
    x.second = x.first;
    return x;
}
static p::Settlement9 settle(w::u64 pid, w::u64 start) {
    return {pid, pid, 77, start, 55, 1, 1, 256, 0};
}

static void boundary() {
    assert(p::kEvidenceFrameType == 59);
    assert(p::kEnvelopeBytes == 88);
    assert(p::kReservationSourceMax == 809 && p::kCollisionAttemptMax == 4940);
    assert(p::kCollisionCaptureMax == 4192 && p::kEvidenceClosedMax == 280);
    assert(p::kReleaseMax == 248 && p::kRetryLiveMax == 4977);
    assert(p::kRetryLiveCaptureMax == 4192 && p::kRetrySettlementMax == 320 &&
           p::kRetryFinalCaptureMax == 4192);
    assert(p::max_payload(p::ReportKind::RetryFinalCapture) == 4192);
    // Frame allocation is deliberately disjoint from common 1..5, broker 20..46,
    // reserved 47..50, and the old v1 51..58 range.
    for (w::u16 i = 1; i <= 5; ++i) assert(i != p::kEvidenceFrameType);
    for (w::u16 i = 20; i <= 58; ++i) assert(i != p::kEvidenceFrameType);
}

static void codec() {
    const auto t = token();
    auto s = source();
    auto e = env(p::ReportKind::ReservationSource, p::Binding::Phase, p::Phase::ReservationHeld, 1);
    auto f = p::encode_reservation_source(t, e, s);
    assert(f.type == 59 && f.payload.size() == 88 + 32 * 8 + 15 + 11 + 32);
    p::ReservationSource got;
    assert(p::decode_reservation_source(f, t, e, got));
    assert(got == s);
    auto before = got;
    f.payload[0] = 3;
    assert(!p::decode_reservation_source(f, t, e, got));
    assert(got == before);
    assert(!p::decode_reservation_source(f, w::Token{}, e, got));
    s.source_bytes.push_back('x');
    s.scalars[31] = s.source_bytes.size();
    auto too = p::encode_reservation_source(t, e, s);
    assert(too.type == 59);  // under the exact 255-byte bound
    s.source_bytes.assign(256, 'x');
    s.scalars[31] = s.source_bytes.size();
    too = p::encode_reservation_source(t, e, s);
    assert(too.type == 0);
    p::CollisionCapture c;
    c.marker = 4;
    c.capture = "sealed";
    auto ce = env(p::ReportKind::CollisionCapture,
                  p::Binding::Phase,
                  p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                  3);
    auto cf = p::encode_collision_capture(t, ce, c);
    p::CollisionCapture co;
    assert(p::decode_collision_capture(cf, t, ce, co) && co.capture == "sealed");
}

static void exact_report_sizes() {
    const auto t = token();
    auto s = source();
    s.proc_link = "socket:[12345678901234567890]";
    s.scalars[7] = 12345678901234567890ULL;
    s.source_path.assign(p::kMaxSourcePath, 'p');
    s.source_bytes.assign(p::kMaxSourceBytes, 'b');
    s.scalars[16] = s.proc_link.size();
    s.scalars[30] = s.source_path.size();
    s.scalars[31] = s.source_bytes.size();
    assert(
        p::encode_reservation_source(
            t,
            env(p::ReportKind::ReservationSource, p::Binding::Phase, p::Phase::ReservationHeld, 1),
            s)
            .payload.size() == p::kReservationSourceMax);
    p::CollisionAttempt ca;
    ca.cmdline.assign(p::kMaxCmdline, 'c');
    assert(p::encode_collision_attempt(t,
                                       env(p::ReportKind::CollisionAttempt,
                                           p::Binding::Phase,
                                           p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                           3),
                                       ca)
               .payload.size() == p::kCollisionAttemptMax);
    p::CollisionCapture cc;
    cc.capture.assign(p::kMaxCapture, 'c');
    assert(p::encode_collision_capture(t,
                                       env(p::ReportKind::CollisionCapture,
                                           p::Binding::Phase,
                                           p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                           3),
                                       cc)
               .payload.size() == p::kCollisionCaptureMax);
    p::EvidenceClosed ec;
    assert(p::encode_evidence_closed(t,
                                     env(p::ReportKind::EvidenceClosed,
                                         p::Binding::Phase,
                                         p::Phase::EvidenceClosedReservationHeld,
                                         5),
                                     ec)
               .payload.size() == p::kEvidenceClosedMax);
    p::Release rel;
    assert(p::encode_release(
               t,
               env(p::ReportKind::Release, p::Binding::Phase, p::Phase::ReservationReleased, 7),
               rel)
               .payload.size() == p::kReleaseMax);
    p::RetryLive rl;
    rl.cmdline.assign(p::kMaxCmdline, 'r');
    rl.metadata.assign(37, 'm');
    assert(p::encode_retry_live(
               t, env(p::ReportKind::RetryLive, p::Binding::Phase, p::Phase::RetryLive, 9), rl)
               .payload.size() == p::kRetryLiveMax);
    p::RetryLiveCapture lc;
    lc.capture.assign(p::kMaxCapture, 'l');
    assert(
        p::encode_retry_live_capture(
            t, env(p::ReportKind::RetryLiveCapture, p::Binding::Phase, p::Phase::RetryLive, 9), lc)
            .payload.size() == p::kRetryLiveCaptureMax);
    p::RetrySettlement rs;
    assert(p::encode_retry_settlement(
               t,
               env(p::ReportKind::RetrySettlement, p::Binding::Settlement, p::Phase::RetryLive, 11),
               rs)
               .payload.size() == p::kRetrySettlementMax);
    p::RetryFinalCapture fc;
    fc.capture.assign(p::kMaxCapture, 'f');
    assert(
        p::encode_retry_final_capture(
            t,
            env(p::ReportKind::RetryFinalCapture, p::Binding::Settlement, p::Phase::RetryLive, 11),
            fc)
            .payload.size() == p::kRetryFinalCaptureMax);
}

static void transcript(bool collision_live) {
    const auto t = token();
    const auto s = source();
    p::ReceiverContext c;
    c.token = t;
    c.transaction = 0x37759;
    c.target = {77, 991, 55};
    c.expected_source = s;
    c.expected_cmdline = argv();
    p::Receiver r(c);
    auto e1 =
        env(p::ReportKind::ReservationSource, p::Binding::Phase, p::Phase::ReservationHeld, 1);
    assert(r.observe(p::encode_reservation_source(t, e1, s)));
    p::CollisionAttempt ca;
    ca.meta[0] = 2;
    ca.meta[1] = 98;
    ca.meta[2] = 4;
    ca.cmdline = argv();
    ca.procs = collision_live ? live_proc(88) : p::ProcPair{};
    ca.settlement = settle(88, collision_live ? 1000 : 88);
    auto e2 = env(p::ReportKind::CollisionAttempt,
                  p::Binding::Phase,
                  p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                  3);
    assert(r.observe(p::encode_collision_attempt(t, e2, ca)));
    p::CollisionCapture cc;
    cc.marker = 1;
    cc.capture = "collision";
    auto e3 = env(p::ReportKind::CollisionCapture,
                  p::Binding::Phase,
                  p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                  3);
    assert(r.observe(p::encode_collision_capture(t, e3, cc)));
    p::EvidenceClosed ec;
    ec.cleanup.succeeded = 1;
    ec.cleanup.capture_closed = 1;
    auto e4 = env(p::ReportKind::EvidenceClosed,
                  p::Binding::Phase,
                  p::Phase::EvidenceClosedReservationHeld,
                  5);
    assert(r.observe(p::encode_evidence_closed(t, e4, ec)));
    p::Release rel;
    rel.receipt = {1, 0, 1, 0, 0, 0, std::numeric_limits<w::u64>::max(), 9, 1, 1, 1, 1, 1, 4, 0, 0};
    auto e5 = env(p::ReportKind::Release, p::Binding::Phase, p::Phase::ReservationReleased, 7);
    assert(r.observe(p::encode_release(t, e5, rel)));
    p::RetryLive rl;
    rl.cmdline = argv();
    rl.metadata = "live";
    rl.procs = live_proc(99, 1999);
    rl.settlement = settle(99, 1999);
    auto e6 = env(p::ReportKind::RetryLive, p::Binding::Phase, p::Phase::RetryLive, 9);
    assert(r.observe(p::encode_retry_live(t, e6, rl)));
    p::RetryLiveCapture lc{1, "prefix"};
    auto e7 = env(p::ReportKind::RetryLiveCapture, p::Binding::Phase, p::Phase::RetryLive, 9);
    assert(r.observe(p::encode_retry_live_capture(t, e7, lc)));
    p::RetrySettlement rs;
    rs.settlement = settle(99, 1999);
    auto e8 = env(p::ReportKind::RetrySettlement, p::Binding::Settlement, p::Phase::RetryLive, 11);
    assert(r.observe(p::encode_retry_settlement(t, e8, rs)));
    p::RetryFinalCapture fc{1, "prefix-final"};
    auto e9 =
        env(p::ReportKind::RetryFinalCapture, p::Binding::Settlement, p::Phase::RetryLive, 11);
    assert(r.observe(p::encode_retry_final_capture(t, e9, fc)));
    assert(r.finish());
    assert(r.state() == p::State::Complete);
    assert(!r.finish());
}

int main() {
    boundary();
    codec();
    exact_report_sizes();
    transcript(false);
    transcript(true);
    std::cout << "collision-release-evidence-ok\n";
}
