#include "fixture_collision_release_evidence_protocol.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace p = rut::test::fixture_collision_release_evidence_protocol;
namespace w = rut::test::fixture_worker_protocol;
using u64 = w::u64;
using Bytes = std::vector<unsigned char>;

static w::Token token() {
    w::Token value{};
    for (std::size_t index = 0u; index < value.bytes.size(); ++index)
        value.bytes[index] = static_cast<unsigned char>(index + 3u);
    return value;
}

static void put(Bytes& bytes, u64 value) {
    for (unsigned shift = 0u; shift < 64u; shift += 8u)
        bytes.push_back(static_cast<unsigned char>(value >> shift));
}

static u64 read(const Bytes& bytes, std::size_t offset) {
    u64 value = 0u;
    for (unsigned shift = 0u; shift < 64u; shift += 8u)
        value |= static_cast<u64>(bytes[offset + shift / 8u]) << shift;
    return value;
}

static void set_word(w::Frame& frame, std::size_t body_index, u64 value) {
    Bytes encoded;
    put(encoded, value);
    const std::size_t offset = p::kEnvelopeBytes + body_index * sizeof(u64);
    std::copy(encoded.begin(), encoded.end(), frame.payload.begin() + offset);
}

static void set_envelope_word(w::Frame& frame, std::size_t index, u64 value) {
    Bytes encoded;
    put(encoded, value);
    const std::size_t offset = index * sizeof(u64);
    std::copy(encoded.begin(), encoded.end(), frame.payload.begin() + offset);
}

static std::string cmdline(const std::string& path = "/tmp/source", std::size_t total = 0u) {
    const std::string executable = "/bin/rut";
    const char* fixed[] = {"--shards", "1", "--no-pin", "--drain", "0", "--opt", "2"};
    std::size_t base = executable.size() + 1u + path.size() + 1u;
    for (const char* argument : fixed) base += std::strlen(argument) + 1u;
    std::string first = executable;
    if (total != 0u) first.append(total - base, 'x');
    std::string value = first;
    value.push_back('\0');
    value += path;
    value.push_back('\0');
    for (const char* argument : fixed) {
        value += argument;
        value.push_back('\0');
    }
    return value;
}

static p::Envelope env(p::ReportKind kind, p::Binding binding, p::Phase phase, u64 sequence) {
    p::Envelope value;
    value.transaction = 0x37759u;
    value.kind = kind;
    value.binding = binding;
    value.phase = phase;
    value.sequence = sequence;
    value.target = {77u, 991u, 55u};
    return value;
}

static p::ReservationSource source() {
    p::ReservationSource value;
    value.reservation_state = 1u;
    value.g_fd = 12u;
    value.g_f_getfd = 1u;
    value.g_f_getfl = 2u;
    value.ipv4 = 0x7f000001u;
    value.port = 34567u;
    value.dev = 22u;
    value.ino = 123456u;
    value.mode = 0140000u;
    value.rdev = 0u;
    value.socket_domain = 2u;
    value.socket_type = 1u;
    value.socket_protocol = 6u;
    value.reuseaddr = 1u;
    value.reuseport = 1u;
    value.acceptconn = 0u;
    value.proc_link = "socket:[123456]";
    value.proc_link_len = value.proc_link.size();
    value.directory_dev = 22u;
    value.directory_ino = 77u;
    value.directory_mode = 01777u;
    value.directory_uid = 1000u;
    value.directory_gid = 1000u;
    value.source_state = 1u;
    value.source_dev = 33u;
    value.source_ino = 44u;
    value.source_mode = 0100600u;
    value.source_uid = 1000u;
    value.source_gid = 1000u;
    value.source_size = 32u;
    value.source_nlink = 1u;
    value.source_path = "/tmp/source";
    value.source_bytes.assign(32u, 's');
    value.path_len = value.source_path.size();
    value.bytes_len = value.source_bytes.size();
    return value;
}

static p::Cleanup14 cleanup_open() {
    return {0u, 0u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 0u, 0u, 0u, 0u};
}

static p::Cleanup14 cleanup_closed() {
    return {0u, 0u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 0u, 0u};
}

static p::ProcPair procs(u64 pid, u64 start) {
    p::ProcPair value;
    value.first_tag = 1u;
    value.second_tag = 1u;
    value.first = {pid, 77u, 1u, start, 1u, 1000u, 1000u, 55u, 2u, 3u, 1u, 1u, 0u};
    value.second = value.first;
    return value;
}

static p::Settlement9 exited(u64 pid, u64 start) {
    return {pid, pid, 77u, start, 55u, 1u, 1u, 256u, 0u};
}

static p::CollisionAttempt collision(const p::ReservationSource& reservation, bool live) {
    p::CollisionAttempt value;
    value.cross = {
        reservation.g_fd, reservation.ino, reservation.source_dev, reservation.source_ino};
    value.header = {live ? 2u : 1u,
                    1u,
                    98u,
                    88u,
                    1000u,
                    live ? 2u : 1u,
                    cmdline(reservation.source_path).size()};
    value.procs = live ? procs(88u, 1000u) : p::ProcPair{};
    value.settlement = exited(88u, 1000u);
    value.cleanup = cleanup_open();
    value.classifier = {1u, 2u, 98u, 4u, 9u};
    value.cmdline = cmdline(reservation.source_path);
    return value;
}

static p::EvidenceClosed closed(const p::ReservationSource& reservation,
                                const p::CollisionAttempt& attempt) {
    p::EvidenceClosed value;
    value.g_fd = reservation.g_fd;
    value.g_inode = reservation.ino;
    value.source_dev = reservation.source_dev;
    value.source_inode = reservation.source_ino;
    value.child_pid = attempt.header.child_pid;
    value.child_start = attempt.header.child_start;
    value.attempt_state = attempt.header.attempt_state;
    value.reservation_state = 1u;
    value.source_state = 1u;
    value.capture_len = 9u;
    value.cleanup = cleanup_closed();
    return value;
}

static p::Release release(const p::ReservationSource& reservation) {
    p::Release value;
    value.g_fd = reservation.g_fd;
    value.ipv4 = reservation.ipv4;
    value.port = reservation.port;
    value.g_inode = reservation.ino;
    value.receipt = {1u,
                     0u,
                     1u,
                     0u,
                     0u,
                     0u,
                     std::numeric_limits<u64>::max(),
                     9u,
                     1u,
                     1u,
                     1u,
                     1u,
                     1u,
                     4u,
                     0u,
                     0u};
    return value;
}

static p::RetryLive retry_live(const p::ReservationSource& reservation) {
    p::RetryLive value;
    value.source_dev = reservation.source_dev;
    value.source_inode = reservation.source_ino;
    value.source_size = reservation.source_size;
    value.source_path = reservation.source_path;
    value.source_path_len = value.source_path.size();
    value.g_inode = reservation.ino;
    value.port = reservation.port;
    value.header = {2u, 1u, 98u, 99u, 1999u, 2u, cmdline(value.source_path).size()};
    value.procs = procs(99u, 1999u);
    value.pidfd = {4u, 0u, 0u, 99u};
    value.startup = {1u, 2u, value.port, 6u};
    value.cmdline = cmdline(value.source_path);
    return value;
}

static p::RetrySettlement retry_settlement(const p::ReservationSource& reservation) {
    return {reservation.source_dev,
            reservation.source_ino,
            99u,
            1999u,
            2u,
            {99u, 99u, 77u, 1999u, 55u, 1u, 1u, 9u, 0u},
            cleanup_open(),
            12u};
}

static Bytes words(std::initializer_list<u64> values) {
    Bytes bytes;
    for (const u64 value : values) put(bytes, value);
    return bytes;
}

static Bytes independent_payload(const p::Envelope& envelope_value,
                                 std::initializer_list<u64> body_words,
                                 const std::string& body_bytes) {
    Bytes body = words(body_words);
    body.insert(body.end(), body_bytes.begin(), body_bytes.end());
    Bytes payload = words({envelope_value.version,
                           envelope_value.transaction,
                           envelope_value.domain,
                           static_cast<u64>(envelope_value.kind),
                           static_cast<u64>(envelope_value.binding),
                           static_cast<u64>(envelope_value.phase),
                           envelope_value.sequence,
                           envelope_value.target.pid,
                           envelope_value.target.start,
                           envelope_value.target.netns,
                           body.size()});
    payload.insert(payload.end(), body.begin(), body.end());
    return payload;
}

static Bytes independent_payload(const p::Envelope& envelope_value,
                                 const std::vector<u64>& body_words,
                                 const std::string& body_bytes) {
    Bytes body;
    for (const u64 value : body_words) put(body, value);
    body.insert(body.end(), body_bytes.begin(), body_bytes.end());
    Bytes payload = words({envelope_value.version,
                           envelope_value.transaction,
                           envelope_value.domain,
                           static_cast<u64>(envelope_value.kind),
                           static_cast<u64>(envelope_value.binding),
                           static_cast<u64>(envelope_value.phase),
                           envelope_value.sequence,
                           envelope_value.target.pid,
                           envelope_value.target.start,
                           envelope_value.target.netns,
                           body.size()});
    payload.insert(payload.end(), body.begin(), body.end());
    return payload;
}

static Bytes independent_payload(const p::Envelope& envelope_value,
                                 const std::vector<u64>& body_words,
                                 const Bytes& body_bytes) {
    Bytes body;
    for (const u64 value : body_words) put(body, value);
    body.insert(body.end(), body_bytes.begin(), body_bytes.end());
    Bytes payload = words({envelope_value.version,
                           envelope_value.transaction,
                           envelope_value.domain,
                           static_cast<u64>(envelope_value.kind),
                           static_cast<u64>(envelope_value.binding),
                           static_cast<u64>(envelope_value.phase),
                           envelope_value.sequence,
                           envelope_value.target.pid,
                           envelope_value.target.start,
                           envelope_value.target.netns,
                           body.size()});
    payload.insert(payload.end(), body.begin(), body.end());
    return payload;
}

static void assert_exact_words(const Bytes& payload, const std::vector<u64>& expected) {
    assert(payload.size() >= expected.size() * sizeof(u64));
    for (std::size_t index = 0u; index < expected.size(); ++index)
        assert(read(payload, index * sizeof(u64)) == expected[index]);
}

static void golden() {
    const auto t = token();
    const auto s = source();
    const auto c = collision(s, false);
    const auto ec = closed(s, c);
    const auto rel = release(s);
    const auto rl = retry_live(s);
    const auto rs = retry_settlement(s);
    const std::string line = cmdline(s.source_path);

    const p::Envelope source_env =
        env(p::ReportKind::ReservationSource, p::Binding::Phase, p::Phase::ReservationHeld, 1u);
    Bytes source_tail;
    source_tail.insert(source_tail.end(), s.proc_link.begin(), s.proc_link.end());
    source_tail.insert(source_tail.end(), s.source_path.begin(), s.source_path.end());
    source_tail.insert(source_tail.end(), s.source_bytes.begin(), s.source_bytes.end());
    const std::vector<u64> source_words = {
        1u, 12u, 1u,  2u,       0x7f000001u, 34567u, 22u, 123456u, 0140000u, 0u,    2u,
        1u, 6u,  1u,  1u,       0u,          15u,    22u, 77u,     01777u,   1000u, 1000u,
        1u, 33u, 44u, 0100600u, 1000u,       1000u,  32u, 1u,      11u,      32u};
    const Bytes source_expected = independent_payload(source_env, source_words, source_tail);
    const auto source_frame = p::encode_reservation_source(t, source_env, s);
    assert(source_frame.type == 59u && source_frame.token.bytes == t.bytes);
    assert(source_frame.payload == source_expected && source_frame.payload.size() == 402u);
    assert_exact_words(source_frame.payload,
                       {2u, 0x37759u, 1u, 1u, 1u, 1u, 1u, 77u, 991u, 55u, 314u});
    p::ReservationSource source_out;
    assert(p::decode_reservation_source(source_frame, t, source_env, source_out) &&
           source_out == s);

    const p::Envelope collision_env = env(p::ReportKind::CollisionAttempt,
                                          p::Binding::Phase,
                                          p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                          3u);
    std::vector<u64> collision_words = {12u, 123456u, 33u, 44u, 1u, 1u, 98u, 88u, 1000u, 1u, 59u};
    const std::array<u64, 28u> absent_process = {};
    collision_words.insert(collision_words.end(), absent_process.begin(), absent_process.end());
    collision_words.insert(collision_words.end(), {88u, 88u, 77u, 1000u, 55u, 1u, 1u, 256u, 0u});
    collision_words.insert(collision_words.end(),
                           {0u, 0u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 1u, 0u, 0u, 0u, 0u});
    collision_words.insert(collision_words.end(), {1u, 2u, 98u, 4u, 9u});
    assert(collision_words.size() == 67u);
    const Bytes collision_expected = independent_payload(collision_env, collision_words, line);
    const auto collision_frame = p::encode_collision_attempt(t, collision_env, c);
    assert(collision_frame.payload == collision_expected && collision_frame.payload.size() == 683u);
    assert_exact_words(collision_frame.payload,
                       {2u, 0x37759u, 1u, 2u, 1u, 2u, 3u, 77u, 991u, 55u, 595u});
    p::CollisionAttempt collision_out;
    assert(p::decode_collision_attempt(collision_frame, t, collision_env, collision_out) &&
           collision_out == c);

    const p::Envelope capture_env = env(p::ReportKind::CollisionCapture,
                                        p::Binding::Phase,
                                        p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                        3u);
    const Bytes capture_expected = independent_payload(capture_env, {3u}, "abc");
    const auto capture_frame = p::encode_collision_capture(t, capture_env, {3u, "abc"});
    assert(capture_frame.payload == capture_expected && capture_frame.payload.size() == 99u);
    assert_exact_words(capture_frame.payload,
                       {2u, 0x37759u, 1u, 3u, 1u, 2u, 3u, 77u, 991u, 55u, 11u, 3u});
    p::CollisionCapture capture_out;
    assert(p::decode_collision_capture(capture_frame, t, capture_env, capture_out) &&
           capture_out == (p::CollisionCapture{3u, "abc"}));

    const p::Envelope closed_env = env(p::ReportKind::EvidenceClosed,
                                       p::Binding::Phase,
                                       p::Phase::EvidenceClosedReservationHeld,
                                       5u);
    const std::vector<u64> closed_words = {12u, 123456u, 33u, 44u, 88u, 1000u, 1u, 1u,
                                           1u,  9u,      0u,  0u,  1u,  1u,    1u, 1u,
                                           1u,  1u,      1u,  1u,  1u,  1u,    0u, 0u};
    const Bytes closed_expected = independent_payload(closed_env, closed_words, std::string{});
    const auto closed_frame = p::encode_evidence_closed(t, closed_env, ec);
    assert(closed_frame.payload == closed_expected && closed_frame.payload.size() == 280u);
    assert_exact_words(closed_frame.payload,
                       {2u, 0x37759u, 1u, 4u, 1u, 3u, 5u, 77u, 991u, 55u, 192u});
    p::EvidenceClosed closed_out;
    assert(p::decode_evidence_closed(closed_frame, t, closed_env, closed_out) && closed_out == ec);

    const p::Envelope release_env =
        env(p::ReportKind::Release, p::Binding::Phase, p::Phase::ReservationReleased, 7u);
    const std::vector<u64> release_words = {
        12u, 0x7f000001u, 34567u, 123456u, 1u, 0u, 1u, 0u, 0u, 0u, std::numeric_limits<u64>::max(),
        9u,  1u,          1u,     1u,      1u, 1u, 4u, 0u, 0u};
    const Bytes release_expected = independent_payload(release_env, release_words, std::string{});
    const auto release_frame = p::encode_release(t, release_env, rel);
    assert(release_frame.payload == release_expected && release_frame.payload.size() == 248u);
    assert_exact_words(release_frame.payload,
                       {2u, 0x37759u, 1u, 5u, 1u, 4u, 7u, 77u, 991u, 55u, 160u});
    p::Release release_out;
    assert(p::decode_release(release_frame, t, release_env, release_out) && release_out == rel);

    const p::Envelope retry_env =
        env(p::ReportKind::RetryLive, p::Binding::Phase, p::Phase::RetryLive, 9u);
    std::vector<u64> retry_words = {
        33u, 44u, 32u, 11u, 123456u, 34567u, 2u, 1u, 98u, 99u, 1999u, 2u, 59u};
    const std::array<u64, 13u> proc = {
        99u, 77u, 1u, 1999u, 1u, 1000u, 1000u, 55u, 2u, 3u, 1u, 1u, 0u};
    retry_words.push_back(1u);
    retry_words.insert(retry_words.end(), proc.begin(), proc.end());
    retry_words.push_back(1u);
    retry_words.insert(retry_words.end(), proc.begin(), proc.end());
    retry_words.insert(retry_words.end(), {4u, 0u, 0u, 99u, 1u, 2u, 34567u, 6u});
    assert(retry_words.size() == 49u);
    const Bytes retry_expected = independent_payload(retry_env, retry_words, s.source_path + line);
    const auto retry_frame = p::encode_retry_live(t, retry_env, rl);
    assert(retry_frame.payload == retry_expected && retry_frame.payload.size() == 550u);
    assert_exact_words(retry_frame.payload,
                       {2u, 0x37759u, 1u, 6u, 1u, 5u, 9u, 77u, 991u, 55u, 462u});
    p::RetryLive retry_out;
    assert(p::decode_retry_live(retry_frame, t, retry_env, retry_out) && retry_out == rl);

    const p::Envelope live_capture_env =
        env(p::ReportKind::RetryLiveCapture, p::Binding::Phase, p::Phase::RetryLive, 9u);
    const Bytes live_capture_expected = independent_payload(live_capture_env, {6u}, "prefix");
    const auto live_capture_frame =
        p::encode_retry_live_capture(t, live_capture_env, {6u, "prefix"});
    assert(live_capture_frame.payload == live_capture_expected &&
           live_capture_frame.payload.size() == 102u);
    assert_exact_words(live_capture_frame.payload,
                       {2u, 0x37759u, 1u, 7u, 1u, 5u, 9u, 77u, 991u, 55u, 14u, 6u});
    p::RetryLiveCapture live_capture_out;
    assert(
        p::decode_retry_live_capture(live_capture_frame, t, live_capture_env, live_capture_out) &&
        live_capture_out == (p::RetryLiveCapture{6u, "prefix"}));

    const p::Envelope settlement_env =
        env(p::ReportKind::RetrySettlement, p::Binding::Settlement, p::Phase::RetryLive, 11u);
    const std::vector<u64> settlement_words = {33u, 44u, 99u, 1999u, 2u, 99u, 99u, 77u, 1999u, 55u,
                                               1u,  1u,  9u,  0u,    0u, 0u,  1u,  1u,  1u,    1u,
                                               1u,  1u,  1u,  1u,    0u, 0u,  0u,  0u,  12u};
    const Bytes settlement_expected =
        independent_payload(settlement_env, settlement_words, std::string{});
    const auto settlement_frame = p::encode_retry_settlement(t, settlement_env, rs);
    assert(settlement_frame.payload == settlement_expected &&
           settlement_frame.payload.size() == 320u);
    assert_exact_words(settlement_frame.payload,
                       {2u, 0x37759u, 1u, 8u, 2u, 5u, 11u, 77u, 991u, 55u, 232u});
    p::RetrySettlement settlement_out;
    assert(p::decode_retry_settlement(settlement_frame, t, settlement_env, settlement_out) &&
           settlement_out == rs);

    const p::Envelope final_env =
        env(p::ReportKind::RetryFinalCapture, p::Binding::Settlement, p::Phase::RetryLive, 11u);
    const Bytes final_expected = independent_payload(final_env, {12u}, "prefix-final");
    const auto final_frame = p::encode_retry_final_capture(t, final_env, {12u, "prefix-final"});
    assert(final_frame.payload == final_expected && final_frame.payload.size() == 108u);
    assert_exact_words(final_frame.payload,
                       {2u, 0x37759u, 1u, 9u, 2u, 5u, 11u, 77u, 991u, 55u, 20u, 12u});
    p::RetryFinalCapture final_out;
    assert(p::decode_retry_final_capture(final_frame, t, final_env, final_out) &&
           final_out == (p::RetryFinalCapture{12u, "prefix-final"}));
}

static void maxima() {
    const auto t = token();
    auto s = source();
    s.proc_link.assign(p::kMaxProcLink, 'x');
    s.proc_link[0] = 's';
    s.proc_link.back() = ']';
    s.proc_link_len = s.proc_link.size();
    s.source_path.assign(p::kMaxSourcePath, 'p');
    s.source_bytes.assign(p::kMaxSourceBytes, 'b');
    s.path_len = s.source_path.size();
    s.bytes_len = s.source_bytes.size();
    assert(
        p::encode_reservation_source(
            t,
            env(p::ReportKind::ReservationSource, p::Binding::Phase, p::Phase::ReservationHeld, 1u),
            s)
            .payload.size() == p::kReservationSourceMax);
    auto c = collision(s, false);
    c.cmdline = cmdline(s.source_path, p::kMaxCmdline);
    c.header.cmdline_len = c.cmdline.size();
    assert(p::encode_collision_attempt(t,
                                       env(p::ReportKind::CollisionAttempt,
                                           p::Binding::Phase,
                                           p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                           3u),
                                       c)
               .payload.size() == p::kCollisionAttemptMax);
    const p::CollisionCapture capture{p::kMaxCapture, std::string(p::kMaxCapture, 'c')};
    assert(p::encode_collision_capture(t,
                                       env(p::ReportKind::CollisionCapture,
                                           p::Binding::Phase,
                                           p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                           3u),
                                       capture)
               .payload.size() == p::kCollisionCaptureMax);
    p::EvidenceClosed evidence;
    evidence.cleanup = cleanup_closed();
    assert(p::encode_evidence_closed(t,
                                     env(p::ReportKind::EvidenceClosed,
                                         p::Binding::Phase,
                                         p::Phase::EvidenceClosedReservationHeld,
                                         5u),
                                     evidence)
               .payload.size() == p::kEvidenceClosedMax);
    p::Release rel;
    assert(p::encode_release(
               t,
               env(p::ReportKind::Release, p::Binding::Phase, p::Phase::ReservationReleased, 7u),
               rel)
               .payload.size() == p::kReleaseMax);
    p::RetryLive live;
    live.source_path.assign(p::kMaxSourcePath, 'p');
    live.source_path_len = live.source_path.size();
    live.cmdline = cmdline(live.source_path, p::kMaxCmdline);
    live.header.cmdline_len = live.cmdline.size();
    assert(p::encode_retry_live(
               t, env(p::ReportKind::RetryLive, p::Binding::Phase, p::Phase::RetryLive, 9u), live)
               .payload.size() == p::kRetryLiveMax);
    assert(p::encode_retry_live_capture(
               t,
               env(p::ReportKind::RetryLiveCapture, p::Binding::Phase, p::Phase::RetryLive, 9u),
               {p::kMaxCapture, std::string(p::kMaxCapture, 'x')})
               .payload.size() == p::kRetryLiveCaptureMax);
    p::RetrySettlement settlement;
    assert(
        p::encode_retry_settlement(
            t,
            env(p::ReportKind::RetrySettlement, p::Binding::Settlement, p::Phase::RetryLive, 11u),
            settlement)
            .payload.size() == p::kRetrySettlementMax);
    assert(
        p::encode_retry_final_capture(
            t,
            env(p::ReportKind::RetryFinalCapture, p::Binding::Settlement, p::Phase::RetryLive, 11u),
            {p::kMaxCapture, std::string(p::kMaxCapture, 'x')})
            .payload.size() == p::kRetryFinalCaptureMax);
}

static p::ReceiverContext context(const w::Token& t,
                                  const p::ReservationSource& s,
                                  const std::string& expected_line) {
    p::ReceiverContext value;
    value.token = t;
    value.transaction = 0x37759u;
    value.target = {77u, 991u, 55u};
    value.expected_source = s;
    value.expected_cmdline = expected_line;
    return value;
}

static std::array<w::Frame, 9u> transcript_frames(const w::Token& t,
                                                  const p::ReservationSource& s,
                                                  bool live) {
    const auto c = collision(s, live);
    const auto rl = retry_live(s);
    return {
        p::encode_reservation_source(
            t,
            env(p::ReportKind::ReservationSource, p::Binding::Phase, p::Phase::ReservationHeld, 1u),
            s),
        p::encode_collision_attempt(t,
                                    env(p::ReportKind::CollisionAttempt,
                                        p::Binding::Phase,
                                        p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                        3u),
                                    c),
        p::encode_collision_capture(t,
                                    env(p::ReportKind::CollisionCapture,
                                        p::Binding::Phase,
                                        p::Phase::CollisionNaturallyRejectedEvidenceOpen,
                                        3u),
                                    {9u, "collision"}),
        p::encode_evidence_closed(t,
                                  env(p::ReportKind::EvidenceClosed,
                                      p::Binding::Phase,
                                      p::Phase::EvidenceClosedReservationHeld,
                                      5u),
                                  closed(s, c)),
        p::encode_release(
            t,
            env(p::ReportKind::Release, p::Binding::Phase, p::Phase::ReservationReleased, 7u),
            release(s)),
        p::encode_retry_live(
            t, env(p::ReportKind::RetryLive, p::Binding::Phase, p::Phase::RetryLive, 9u), rl),
        p::encode_retry_live_capture(
            t,
            env(p::ReportKind::RetryLiveCapture, p::Binding::Phase, p::Phase::RetryLive, 9u),
            {6u, "prefix"}),
        p::encode_retry_settlement(
            t,
            env(p::ReportKind::RetrySettlement, p::Binding::Settlement, p::Phase::RetryLive, 11u),
            retry_settlement(s)),
        p::encode_retry_final_capture(
            t,
            env(p::ReportKind::RetryFinalCapture, p::Binding::Settlement, p::Phase::RetryLive, 11u),
            {12u, "prefix-final"})};
}

static void transcript(bool live) {
    const auto t = token();
    const auto s = source();
    const auto line = cmdline(s.source_path);
    p::Receiver receiver(context(t, s, line));
    const auto frames = transcript_frames(t, s, live);
    for (const auto& frame : frames) assert(receiver.observe(frame));
    assert(receiver.finish() && receiver.state() == p::State::Complete);
    assert(!receiver.observe({}) && receiver.state() == p::State::Failed);
}

static void expect_source_failure(const p::ReceiverContext& receiver_context,
                                  const std::function<void(w::Frame&)>& mutate) {
    p::Receiver receiver(receiver_context);
    auto frames =
        transcript_frames(receiver_context.token, receiver_context.expected_source, false);
    mutate(frames[0]);
    assert(!receiver.observe(frames[0]) && receiver.state() == p::State::Failed);
    assert(receiver.source() == p::ReservationSource{});
}

static void expect_stage_failure(const p::ReceiverContext& receiver_context,
                                 std::size_t stage,
                                 const std::function<void(w::Frame&)>& mutate) {
    p::Receiver receiver(receiver_context);
    auto frames =
        transcript_frames(receiver_context.token, receiver_context.expected_source, false);
    for (std::size_t index = 0u; index < stage; ++index) assert(receiver.observe(frames[index]));
    mutate(frames[stage]);
    assert(!receiver.observe(frames[stage]) && receiver.state() == p::State::Failed);
    assert(receiver.source() == receiver_context.expected_source);
    if (stage > 5u) assert(receiver.retry_live() == retry_live(receiver_context.expected_source));
}

static void rejection_matrix() {
    const auto t = token();
    const auto s = source();
    const auto line = cmdline(s.source_path);
    const auto c = context(t, s, line);

    // Each envelope component, frame type, and authentication token is isolated at stage one.
    for (const std::size_t field : {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u})
        expect_source_failure(c, [field](w::Frame& frame) { set_envelope_word(frame, field, 0u); });
    expect_source_failure(c, [](w::Frame& frame) { frame.type = 58u; });
    expect_source_failure(c, [](w::Frame& frame) { frame.token.bytes[0] ^= 1u; });

    // Source scalar, malformed variable-length, and all collision cross/branch evidence.
    expect_source_failure(c, [](w::Frame& frame) { set_word(frame, 0u, 2u); });
    for (const std::size_t field : {0u, 1u, 2u, 3u})
        expect_stage_failure(c, 1u, [field](w::Frame& frame) { set_word(frame, field, 999999u); });
    expect_stage_failure(c, 1u, [](w::Frame& frame) { set_word(frame, 4u, 2u); });
    expect_stage_failure(c, 1u, [](w::Frame& frame) { set_word(frame, 9u, 2u); });
    expect_stage_failure(c, 1u, [](w::Frame& frame) { set_word(frame, 12u, 1u); });
    for (const std::size_t field : {39u, 40u, 41u, 42u, 43u, 44u, 45u, 46u, 47u})
        expect_stage_failure(c, 1u, [field](w::Frame& frame) { set_word(frame, field, 7u); });
    for (const std::size_t field : {48u, 49u, 50u, 51u, 52u, 53u, 54u, 55u, 56u, 57u, 58u, 59u})
        expect_stage_failure(c, 1u, [field](w::Frame& frame) {
            const bool expected_zero = field == 48u || field == 49u || field == 58u || field == 59u;
            set_word(frame, field, expected_zero ? 1u : 0u);
        });
    for (const std::size_t field : {62u, 63u, 64u, 65u, 66u})
        expect_stage_failure(c, 1u, [field](w::Frame& frame) { set_word(frame, field, 0u); });
    expect_stage_failure(c, 1u, [](w::Frame& frame) {
        set_word(frame, 11u, 0u);
        set_word(frame, 12u, 1u);
    });
    expect_stage_failure(c, 2u, [](w::Frame& frame) { set_word(frame, 0u, 8u); });

    // Evidence-closed cleanup has a distinct capture-close predicate.
    expect_stage_failure(c, 3u, [](w::Frame& frame) { set_word(frame, 20u, 0u); });
    expect_stage_failure(c, 3u, [](w::Frame& frame) { set_word(frame, 21u, 0u); });

    // Release receipt key fields are all independently bound to the reservation release.
    for (const std::size_t field :
         {4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u, 17u, 18u, 19u})
        expect_stage_failure(c, 4u, [field](w::Frame& frame) { set_word(frame, field, 7u); });

    // Retry source links, exact argv[0], pidfd, startup, and the final capture link.
    for (const std::size_t field : {0u, 1u, 2u, 3u, 4u, 5u})
        expect_stage_failure(c, 5u, [field](w::Frame& frame) { set_word(frame, field, 777u); });
    expect_stage_failure(c, 5u, [](w::Frame& frame) {
        frame.payload[p::kEnvelopeBytes + 49u * sizeof(u64) + 1u] = 'X';
    });
    expect_stage_failure(c, 5u, [](w::Frame& frame) {
        frame.payload[p::kEnvelopeBytes + 49u * sizeof(u64) + 11u + 1u] = 'X';
    });
    expect_stage_failure(
        c, 5u, [](w::Frame& frame) { set_word(frame, 41u, std::numeric_limits<u64>::max()); });
    for (const std::size_t field : {42u, 43u, 44u})
        expect_stage_failure(c, 5u, [field](w::Frame& frame) { set_word(frame, field, 7u); });
    for (const std::size_t field : {45u, 46u, 47u})
        expect_stage_failure(c, 5u, [field](w::Frame& frame) { set_word(frame, field, 7u); });
    expect_stage_failure(c, 5u, [](w::Frame& frame) { set_word(frame, 48u, 0u); });
    expect_stage_failure(c, 6u, [](w::Frame& frame) { set_word(frame, 0u, 5u); });
    expect_stage_failure(c, 7u, [](w::Frame& frame) { set_word(frame, 12u, 8u); });
    expect_stage_failure(c, 7u, [](w::Frame& frame) { set_word(frame, 14u, 1u); });
    expect_stage_failure(c, 8u, [](w::Frame& frame) { set_word(frame, 0u, 11u); });
    expect_stage_failure(
        c, 8u, [](w::Frame& frame) { frame.payload[p::kEnvelopeBytes + 8u] = 'X'; });
}

int main() {
    golden();
    maxima();
    transcript(false);
    transcript(true);
    rejection_matrix();
    std::cout << "collision-release-evidence-ok\n";
}
