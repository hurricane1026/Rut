#include "fixture_collision_release_evidence_transport.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace transport = rut::test::fixture_collision_release_evidence_transport;
namespace evidence = rut::test::fixture_collision_release_evidence_protocol;
namespace worker = rut::test::fixture_worker_protocol;

namespace {

using Clock = std::chrono::steady_clock;
using Bytes = std::vector<unsigned char>;

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s\n", message);
    return condition;
}

worker::Token token(unsigned char seed = 0x20u) {
    worker::Token value{};
    for (std::size_t index = 0u; index != value.bytes.size(); ++index)
        value.bytes[index] = static_cast<unsigned char>(seed + index);
    return value;
}

worker::Frame frame(const worker::Token& frame_token,
                    std::size_t payload_size = evidence::kEnvelopeBytes + 7u) {
    worker::Frame value;
    value.type = transport::kEvidenceFrameType;
    value.token = frame_token;
    value.payload.resize(payload_size);
    for (std::size_t index = 0u; index != value.payload.size(); ++index)
        value.payload[index] = static_cast<unsigned char>(index * 3u + 1u);
    return value;
}

bool same_frame(const worker::Frame& left, const worker::Frame& right) {
    return left.type == right.type && left.token.bytes == right.token.bytes &&
           left.payload == right.payload;
}

bool write_all(int fd, const unsigned char* data, std::size_t size) {
    std::size_t offset = 0u;
    while (offset != size) {
        const ssize_t count = ::send(fd, data + offset, size - offset, MSG_NOSIGNAL);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

void put16(Bytes& bytes, worker::u16 value) {
    bytes.push_back(static_cast<unsigned char>(value));
    bytes.push_back(static_cast<unsigned char>(value >> 8u));
}

void put32(Bytes& bytes, worker::u32 value) {
    for (unsigned shift = 0u; shift != 32u; shift += 8u)
        bytes.push_back(static_cast<unsigned char>(value >> shift));
}

void put64(Bytes& bytes, worker::u64 value) {
    for (unsigned shift = 0u; shift != 64u; shift += 8u)
        bytes.push_back(static_cast<unsigned char>(value >> shift));
}

Bytes wire_header(worker::u16 type,
                  const worker::Token& frame_token,
                  worker::u32 payload_size,
                  worker::u32 magic = worker::kMagic,
                  worker::u16 version = worker::kVersion) {
    Bytes bytes;
    bytes.reserve(worker::kHeaderBytes);
    put32(bytes, magic);
    put16(bytes, version);
    put16(bytes, type);
    put32(bytes, payload_size);
    bytes.insert(bytes.end(), frame_token.bytes.begin(), frame_token.bytes.end());
    return bytes;
}

bool no_peer_bytes(int fd) {
    unsigned char byte = 0u;
    const ssize_t count = ::recv(fd, &byte, sizeof(byte), MSG_DONTWAIT);
    return count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}

bool open_pair(int descriptors[2]) {
    return ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors) == 0;
}

void close_pair(int descriptors[2]) {
    if (descriptors[0] >= 0) ::close(descriptors[0]);
    if (descriptors[1] >= 0) ::close(descriptors[1]);
    descriptors[0] = -1;
    descriptors[1] = -1;
}

struct HookState {
    std::size_t chunk = std::numeric_limits<std::size_t>::max();
    unsigned poll_eintr = 0u;
    unsigned recv_eintr = 0u;
    unsigned send_eintr = 0u;
    unsigned poll_calls = 0u;
    unsigned recv_calls = 0u;
    unsigned send_calls = 0u;
    unsigned recv_fail_after = std::numeric_limits<unsigned>::max();
    unsigned send_fail_after = std::numeric_limits<unsigned>::max();
    unsigned poll_zero_after = std::numeric_limits<unsigned>::max();
    int failure_errno = EIO;
    bool poll_failure = false;
    bool recv_failure = false;
    bool send_failure = false;
};

int ready_poll(pollfd* descriptors, nfds_t count, int, void* opaque) {
    auto& state = *static_cast<HookState*>(opaque);
    ++state.poll_calls;
    if (state.poll_eintr != 0u) {
        --state.poll_eintr;
        errno = EINTR;
        return -1;
    }
    if (state.poll_failure) {
        errno = state.failure_errno;
        return -1;
    }
    if (state.poll_calls > state.poll_zero_after) {
        descriptors[0].revents = 0;
        return 0;
    }
    for (nfds_t index = 0u; index != count; ++index)
        descriptors[index].revents = descriptors[index].events;
    return 1;
}

ssize_t fragmented_recv(int fd, void* data, std::size_t size, int flags, void* opaque) {
    auto& state = *static_cast<HookState*>(opaque);
    ++state.recv_calls;
    if (state.recv_eintr != 0u) {
        --state.recv_eintr;
        errno = EINTR;
        return -1;
    }
    if (state.recv_failure || state.recv_calls > state.recv_fail_after) {
        errno = state.failure_errno;
        return -1;
    }
    const std::size_t count = std::min(size, state.chunk);
    return ::recv(fd, data, count, flags | MSG_DONTWAIT);
}

ssize_t fragmented_send(int fd, const void* data, std::size_t size, int flags, void* opaque) {
    auto& state = *static_cast<HookState*>(opaque);
    ++state.send_calls;
    if (state.send_eintr != 0u) {
        --state.send_eintr;
        errno = EINTR;
        return -1;
    }
    if (state.send_failure || state.send_calls > state.send_fail_after) {
        errno = state.failure_errno;
        return -1;
    }
    const std::size_t count = std::min(size, state.chunk);
    return ::send(fd, data, count, flags);
}

transport::HooksForTesting hooks(HookState& state,
                                 transport::HooksForTesting::Poll poll = ready_poll,
                                 transport::HooksForTesting::Recv recv = fragmented_recv,
                                 transport::HooksForTesting::Send send = fragmented_send) {
    return {poll, recv, send, &state};
}

bool expect_diagnostic(const transport::Diagnostic& actual,
                       transport::DiagnosticCode code,
                       transport::Stage stage,
                       int error_number,
                       std::size_t bytes,
                       const char* message) {
    return check(actual == transport::Diagnostic{code, stage, error_number, bytes}, message);
}

bool test_canonical_and_exact_wire() {
    int descriptors[2] = {-1, -1};
    if (!check(open_pair(descriptors), "canonical socketpair")) return false;
    const worker::Token expected = token();
    const worker::Frame sent = frame(expected);
    transport::Diagnostic diagnostic;
    bool ok = transport::send_frame(descriptors[0],
                                    expected,
                                    worker::kMaxPayload,
                                    Clock::now() + std::chrono::seconds(2),
                                    sent,
                                    diagnostic);
    ok &= check(ok && diagnostic == transport::Diagnostic{}, "canonical send");

    Bytes expected_wire =
        wire_header(sent.type, expected, static_cast<worker::u32>(sent.payload.size()));
    expected_wire.insert(expected_wire.end(), sent.payload.begin(), sent.payload.end());
    Bytes actual_wire(expected_wire.size());
    ok &= check(::recv(descriptors[1], actual_wire.data(), actual_wire.size(), MSG_WAITALL) ==
                    static_cast<ssize_t>(actual_wire.size()),
                "exact wire size");
    ok &= check(actual_wire == expected_wire, "exact common frame bytes");

    ok &= check(write_all(descriptors[0], expected_wire.data(), expected_wire.size()),
                "canonical raw frame write");
    worker::Frame received = frame(token(0x90u), 91u);
    const worker::Frame original = received;
    diagnostic = {transport::DiagnosticCode::BadMagic, transport::Stage::ReadPayload, EIO, 19u};
    ok &= check(transport::receive_frame(descriptors[1],
                                         expected,
                                         worker::kMaxPayload,
                                         Clock::now() + std::chrono::seconds(2),
                                         received,
                                         diagnostic),
                "canonical receive");
    ok &= check(same_frame(received, sent), "canonical received frame");
    ok &= check(diagnostic == transport::Diagnostic{}, "canonical receive diagnostic");
    ok &= check(!same_frame(received, original), "canonical output committed");
    close_pair(descriptors);
    return ok;
}

bool test_fragmented_eintr() {
    int descriptors[2] = {-1, -1};
    if (!check(open_pair(descriptors), "fragment socketpair")) return false;
    const worker::Token expected = token();
    const worker::Frame sent = frame(expected, evidence::kEnvelopeBytes + 211u);
    HookState send_state;
    send_state.chunk = 3u;
    send_state.send_eintr = 2u;
    send_state.poll_eintr = 2u;
    transport::Diagnostic diagnostic;
    transport::HooksForTesting send_hooks = hooks(send_state);
    bool ok = transport::send_frame(descriptors[0],
                                    expected,
                                    worker::kMaxPayload,
                                    Clock::now() + std::chrono::seconds(2),
                                    sent,
                                    diagnostic,
                                    send_hooks);
    ok &= check(ok && diagnostic == transport::Diagnostic{}, "fragmented send");
    ok &= check(send_state.send_calls > 20u && send_state.poll_calls > 20u,
                "partial write and EINTR exercised");

    HookState receive_state;
    receive_state.chunk = 5u;
    receive_state.recv_eintr = 3u;
    receive_state.poll_eintr = 2u;
    worker::Frame received = frame(token(0x90u), 91u);
    transport::HooksForTesting receive_hooks = hooks(receive_state);
    ok &= check(transport::receive_frame(descriptors[1],
                                         expected,
                                         worker::kMaxPayload,
                                         Clock::now() + std::chrono::seconds(2),
                                         received,
                                         diagnostic,
                                         receive_hooks),
                "fragmented receive");
    ok &= check(same_frame(received, sent), "fragmented frame unchanged");
    ok &= check(diagnostic == transport::Diagnostic{}, "fragmented diagnostic");
    ok &= check(receive_state.recv_calls > 50u && receive_state.poll_calls > 50u,
                "partial read and EINTR exercised");
    close_pair(descriptors);
    return ok;
}

bool test_deadlines_and_eof() {
    bool ok = true;
    const worker::Token expected = token();

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "expired socketpair");
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              worker::kMaxPayload,
                                              Clock::now() - std::chrono::milliseconds(1),
                                              output,
                                              diagnostic),
                    "expired before header");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::Deadline,
                                transport::Stage::ReadHeader,
                                ETIMEDOUT,
                                0u,
                                "expired header diagnostic");
        ok &= check(same_frame(output, original), "expired header output untouched");
        close_pair(descriptors);
    }

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "payload deadline socketpair");
        const Bytes header = wire_header(transport::kEvidenceFrameType,
                                         expected,
                                         static_cast<worker::u32>(evidence::kEnvelopeBytes));
        ok &= check(write_all(descriptors[0], header.data(), header.size()),
                    "payload deadline header");
        HookState state;
        state.poll_zero_after = 1u;
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              worker::kMaxPayload,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic,
                                              hooks(state)),
                    "deadline between header and payload");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::Deadline,
                                transport::Stage::ReadPayload,
                                ETIMEDOUT,
                                worker::kHeaderBytes,
                                "payload deadline diagnostic");
        ok &= check(same_frame(output, original), "payload deadline output untouched");
        close_pair(descriptors);
    }

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "clean EOF socketpair");
        ::close(descriptors[0]);
        descriptors[0] = -1;
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              worker::kMaxPayload,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic),
                    "clean EOF before header");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::CleanEofBeforeHeader,
                                transport::Stage::ReadHeader,
                                0,
                                0u,
                                "clean EOF diagnostic");
        ok &= check(same_frame(output, original), "clean EOF output untouched");
        close_pair(descriptors);
    }

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "truncated header socketpair");
        const Bytes header = wire_header(transport::kEvidenceFrameType,
                                         expected,
                                         static_cast<worker::u32>(evidence::kEnvelopeBytes));
        ok &= check(write_all(descriptors[0], header.data(), 7u), "truncated header write");
        ::close(descriptors[0]);
        descriptors[0] = -1;
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              worker::kMaxPayload,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic),
                    "truncated header");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::TruncatedHeader,
                                transport::Stage::ReadHeader,
                                0,
                                7u,
                                "truncated header diagnostic");
        ok &= check(same_frame(output, original), "truncated header output untouched");
        close_pair(descriptors);
    }

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "truncated payload socketpair");
        const worker::Frame sent = frame(expected, evidence::kEnvelopeBytes + 20u);
        const Bytes header =
            wire_header(sent.type, expected, static_cast<worker::u32>(sent.payload.size()));
        ok &= check(write_all(descriptors[0], header.data(), header.size()),
                    "truncated payload header");
        ok &= check(write_all(descriptors[0], sent.payload.data(), 4u), "truncated payload bytes");
        ::close(descriptors[0]);
        descriptors[0] = -1;
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              worker::kMaxPayload,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic),
                    "truncated payload");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::TruncatedPayload,
                                transport::Stage::ReadPayload,
                                0,
                                worker::kHeaderBytes + 4u,
                                "truncated payload diagnostic");
        ok &= check(same_frame(output, original), "truncated payload output untouched");
        close_pair(descriptors);
    }
    return ok;
}

bool test_protocol_rejections() {
    struct Case {
        const char* name;
        worker::u32 magic;
        worker::u16 version;
        worker::u16 type;
        const worker::Token* frame_token;
        worker::u32 length;
        transport::DiagnosticCode code;
    };
    const worker::Token expected = token();
    const worker::Token wrong = token(0x90u);
    const Case cases[] = {
        {"bad magic",
         worker::kMagic ^ 1u,
         worker::kVersion,
         transport::kEvidenceFrameType,
         &expected,
         static_cast<worker::u32>(evidence::kEnvelopeBytes),
         transport::DiagnosticCode::BadMagic},
        {"bad version",
         worker::kMagic,
         worker::kVersion + 1u,
         transport::kEvidenceFrameType,
         &expected,
         static_cast<worker::u32>(evidence::kEnvelopeBytes),
         transport::DiagnosticCode::BadVersion},
        {"bad type",
         worker::kMagic,
         worker::kVersion,
         58u,
         &expected,
         static_cast<worker::u32>(evidence::kEnvelopeBytes),
         transport::DiagnosticCode::BadType},
        {"bad token",
         worker::kMagic,
         worker::kVersion,
         transport::kEvidenceFrameType,
         &wrong,
         static_cast<worker::u32>(evidence::kEnvelopeBytes),
         transport::DiagnosticCode::BadToken},
        {"short payload",
         worker::kMagic,
         worker::kVersion,
         transport::kEvidenceFrameType,
         &expected,
         static_cast<worker::u32>(evidence::kEnvelopeBytes - 1u),
         transport::DiagnosticCode::PayloadTooSmall},
        {"large payload",
         worker::kMagic,
         worker::kVersion,
         transport::kEvidenceFrameType,
         &expected,
         static_cast<worker::u32>(worker::kMaxPayload + 1u),
         transport::DiagnosticCode::PayloadTooLarge},
        {"u32 max payload",
         worker::kMagic,
         worker::kVersion,
         transport::kEvidenceFrameType,
         &expected,
         std::numeric_limits<worker::u32>::max(),
         transport::DiagnosticCode::PayloadTooLarge},
    };

    bool ok = true;
    for (const Case& test : cases) {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), test.name);
        const Bytes header =
            wire_header(test.type, *test.frame_token, test.length, test.magic, test.version);
        ok &= check(write_all(descriptors[0], header.data(), header.size()), test.name);
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              worker::kMaxPayload,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic),
                    test.name);
        ok &= expect_diagnostic(diagnostic,
                                test.code,
                                transport::Stage::ReadHeader,
                                0,
                                worker::kHeaderBytes,
                                test.name);
        ok &= check(same_frame(output, original), test.name);
        close_pair(descriptors);
    }
    return ok;
}

bool test_argument_and_send_validation() {
    const worker::Token expected = token();
    bool ok = true;
    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "caller bound receive socketpair");
        const worker::Frame value = frame(expected);
        const Bytes header =
            wire_header(value.type, expected, static_cast<worker::u32>(value.payload.size()));
        ok &= check(write_all(descriptors[0], header.data(), header.size()),
                    "caller bound receive header");
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              evidence::kEnvelopeBytes,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic),
                    "caller receive bound");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::PayloadTooLarge,
                                transport::Stage::ReadHeader,
                                0,
                                worker::kHeaderBytes,
                                "caller receive bound diagnostic");
        ok &= check(same_frame(output, original), "caller receive bound output untouched");
        close_pair(descriptors);

        int send_descriptors[2] = {-1, -1};
        ok &= check(open_pair(send_descriptors), "caller bound send socketpair");
        ok &= check(!transport::send_frame(send_descriptors[0],
                                           expected,
                                           evidence::kEnvelopeBytes,
                                           Clock::now() + std::chrono::seconds(1),
                                           value,
                                           diagnostic),
                    "caller send bound");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::PayloadTooLarge,
                                transport::Stage::None,
                                0,
                                0u,
                                "caller send bound diagnostic");
        ok &= check(no_peer_bytes(send_descriptors[1]), "caller send bound no I/O");
        close_pair(send_descriptors);
    }
    for (const std::size_t maximum : {std::size_t(0u),
                                      evidence::kEnvelopeBytes - 1u,
                                      worker::kMaxPayload + 1u,
                                      std::numeric_limits<std::size_t>::max()}) {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "maximum validation socketpair");
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              maximum,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic),
                    "invalid caller maximum");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::Argument,
                                transport::Stage::None,
                                EINVAL,
                                0u,
                                "invalid maximum diagnostic");
        ok &= check(same_frame(output, original) && no_peer_bytes(descriptors[1]),
                    "invalid maximum no I/O");
        close_pair(descriptors);

        int send_descriptors[2] = {-1, -1};
        ok &= check(open_pair(send_descriptors), "send maximum validation socketpair");
        ok &= check(!transport::send_frame(send_descriptors[0],
                                           expected,
                                           maximum,
                                           Clock::now() + std::chrono::seconds(1),
                                           frame(expected),
                                           diagnostic),
                    "invalid send caller maximum");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::Argument,
                                transport::Stage::None,
                                EINVAL,
                                0u,
                                "invalid send maximum diagnostic");
        ok &= check(no_peer_bytes(send_descriptors[1]), "invalid send maximum no I/O");
        close_pair(send_descriptors);
    }

    const worker::Frame valid = frame(expected);
    struct SendCase {
        const char* name;
        worker::Frame value;
        transport::DiagnosticCode code;
    };
    worker::Frame wrong_type = valid;
    wrong_type.type = 58u;
    worker::Frame wrong_token = valid;
    wrong_token.token = token(0x90u);
    worker::Frame short_payload = valid;
    short_payload.payload.resize(evidence::kEnvelopeBytes - 1u);
    worker::Frame large_payload = valid;
    large_payload.payload.resize(worker::kMaxPayload + 1u);
    const SendCase cases[] = {
        {"send wrong type", wrong_type, transport::DiagnosticCode::BadType},
        {"send wrong token", wrong_token, transport::DiagnosticCode::BadToken},
        {"send short payload", short_payload, transport::DiagnosticCode::PayloadTooSmall},
        {"send large payload", large_payload, transport::DiagnosticCode::PayloadTooLarge},
    };
    for (const SendCase& test : cases) {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), test.name);
        transport::Diagnostic diagnostic;
        ok &= check(!transport::send_frame(descriptors[0],
                                           expected,
                                           worker::kMaxPayload,
                                           Clock::now() + std::chrono::seconds(1),
                                           test.value,
                                           diagnostic),
                    test.name);
        ok &= expect_diagnostic(diagnostic, test.code, transport::Stage::None, 0, 0u, test.name);
        ok &= check(no_peer_bytes(descriptors[1]), "invalid send leaves peer empty");
        close_pair(descriptors);
    }
    return ok;
}

bool test_poll_and_syscall_errors() {
    const worker::Token expected = token();
    const worker::Frame value = frame(expected);
    bool ok = true;

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "poll receive socketpair");
        HookState state;
        state.poll_failure = true;
        state.failure_errno = ENOMEM;
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              worker::kMaxPayload,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic,
                                              hooks(state)),
                    "poll receive error");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::PollError,
                                transport::Stage::ReadHeader,
                                ENOMEM,
                                0u,
                                "poll receive diagnostic");
        ok &= check(same_frame(output, original), "poll error output untouched");
        close_pair(descriptors);
    }

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "recv syscall socketpair");
        HookState state;
        state.recv_failure = true;
        state.failure_errno = EIO;
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              worker::kMaxPayload,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic,
                                              hooks(state)),
                    "recv syscall error");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::SyscallError,
                                transport::Stage::ReadHeader,
                                EIO,
                                0u,
                                "recv syscall diagnostic");
        ok &= check(same_frame(output, original), "recv error output untouched");
        close_pair(descriptors);
    }

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "poll send socketpair");
        HookState state;
        state.poll_failure = true;
        state.failure_errno = EBADF;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::send_frame(descriptors[0],
                                           expected,
                                           worker::kMaxPayload,
                                           Clock::now() + std::chrono::seconds(1),
                                           value,
                                           diagnostic,
                                           hooks(state)),
                    "poll send error");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::PollError,
                                transport::Stage::WriteHeader,
                                EBADF,
                                0u,
                                "poll send diagnostic");
        ok &= check(no_peer_bytes(descriptors[1]), "poll send no bytes");
        close_pair(descriptors);
    }

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "send syscall socketpair");
        HookState state;
        state.send_failure = true;
        state.failure_errno = EIO;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::send_frame(descriptors[0],
                                           expected,
                                           worker::kMaxPayload,
                                           Clock::now() + std::chrono::seconds(1),
                                           value,
                                           diagnostic,
                                           hooks(state)),
                    "send syscall error");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::SyscallError,
                                transport::Stage::WriteHeader,
                                EIO,
                                0u,
                                "send syscall diagnostic");
        ok &= check(no_peer_bytes(descriptors[1]), "send syscall no bytes");
        close_pair(descriptors);
    }
    return ok;
}

bool test_partial_terminal_errors() {
    const worker::Token expected = token();
    const worker::Frame value = frame(expected);
    bool ok = true;

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "partial recv error socketpair");
        const Bytes wire =
            wire_header(value.type, expected, static_cast<worker::u32>(value.payload.size()));
        ok &= check(write_all(descriptors[0], wire.data(), wire.size()), "partial recv header");
        HookState state;
        state.chunk = 7u;
        state.recv_fail_after = 2u;
        worker::Frame output = frame(token(0x90u), 91u);
        const worker::Frame original = output;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::receive_frame(descriptors[1],
                                              expected,
                                              worker::kMaxPayload,
                                              Clock::now() + std::chrono::seconds(1),
                                              output,
                                              diagnostic,
                                              hooks(state)),
                    "partial recv error");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::SyscallError,
                                transport::Stage::ReadHeader,
                                EIO,
                                14u,
                                "partial recv cumulative bytes");
        ok &= check(same_frame(output, original), "partial recv output untouched");
        close_pair(descriptors);
    }

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "partial send error socketpair");
        HookState state;
        state.chunk = 5u;
        state.send_fail_after = 2u;
        transport::Diagnostic diagnostic;
        ok &= check(!transport::send_frame(descriptors[0],
                                           expected,
                                           worker::kMaxPayload,
                                           Clock::now() + std::chrono::seconds(1),
                                           value,
                                           diagnostic,
                                           hooks(state)),
                    "partial send error");
        ok &= expect_diagnostic(diagnostic,
                                transport::DiagnosticCode::SyscallError,
                                transport::Stage::WriteHeader,
                                EIO,
                                10u,
                                "partial send cumulative bytes");
        std::array<unsigned char, 10> peer_bytes{};
        ok &= check(::recv(descriptors[1], peer_bytes.data(), peer_bytes.size(), MSG_WAITALL) ==
                        static_cast<ssize_t>(peer_bytes.size()),
                    "partial send peer bytes");
        const Bytes expected_header =
            wire_header(value.type, expected, static_cast<worker::u32>(value.payload.size()));
        ok &= check(std::equal(peer_bytes.begin(), peer_bytes.end(), expected_header.begin()),
                    "partial send bytes are header prefix");
        close_pair(descriptors);
    }
    return ok;
}

bool test_peer_close_and_decoder_rejection() {
    const worker::Token expected = token();
    bool ok = true;
    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "peer close socketpair");
        ::close(descriptors[1]);
        descriptors[1] = -1;
        transport::Diagnostic diagnostic;
        const worker::Frame value = frame(expected);
        ok &= check(!transport::send_frame(descriptors[0],
                                           expected,
                                           worker::kMaxPayload,
                                           Clock::now() + std::chrono::seconds(1),
                                           value,
                                           diagnostic),
                    "peer close send fails");
        ok &= check(diagnostic.code == transport::DiagnosticCode::SyscallError &&
                        diagnostic.stage == transport::Stage::WriteHeader &&
                        diagnostic.error_number == EPIPE && diagnostic.bytes_transferred == 0u,
                    "peer close causal EPIPE and no SIGPIPE");
        close_pair(descriptors);
    }

    {
        int descriptors[2] = {-1, -1};
        ok &= check(open_pair(descriptors), "decoder socketpair");
        Bytes payload;
        const worker::u64 fields[] = {
            evidence::kVersion,
            0x37759u,
            evidence::kClosedEvidenceDomain,
            static_cast<worker::u64>(evidence::ReportKind::EvidenceClosed),
            static_cast<worker::u64>(evidence::Binding::Phase),
            static_cast<worker::u64>(evidence::Phase::EvidenceClosedReservationHeld),
            1u,
            77u,
            991u,
            55u,
            14u * sizeof(worker::u64)};
        for (const worker::u64 field : fields) put64(payload, field);
        payload.resize(evidence::kEnvelopeBytes + 14u * sizeof(worker::u64), 0u);
        const worker::Frame malformed{transport::kEvidenceFrameType, expected, payload};
        transport::Diagnostic diagnostic;
        ok &= check(transport::send_frame(descriptors[0],
                                          expected,
                                          worker::kMaxPayload,
                                          Clock::now() + std::chrono::seconds(1),
                                          malformed,
                                          diagnostic),
                    "malformed evidence transport send");
        worker::Frame received;
        ok &= check(transport::receive_frame(descriptors[1],
                                             expected,
                                             worker::kMaxPayload,
                                             Clock::now() + std::chrono::seconds(1),
                                             received,
                                             diagnostic),
                    "malformed evidence transport receive");
        evidence::EvidenceClosed decoded;
        ok &= check(!evidence::decode_evidence_closed(
                        received,
                        expected,
                        evidence::Envelope{evidence::kVersion,
                                           0x37759u,
                                           evidence::kClosedEvidenceDomain,
                                           evidence::ReportKind::EvidenceClosed,
                                           evidence::Binding::Phase,
                                           evidence::Phase::EvidenceClosedReservationHeld,
                                           1u,
                                           {77u, 991u, 55u}},
                        decoded),
                    "existing decoder rejects malformed transported body");
        close_pair(descriptors);
    }
    return ok;
}

}  // namespace

int main() {
    bool ok = true;
    ok &= test_canonical_and_exact_wire();
    ok &= test_fragmented_eintr();
    ok &= test_deadlines_and_eof();
    ok &= test_protocol_rejections();
    ok &= test_argument_and_send_validation();
    ok &= test_poll_and_syscall_errors();
    ok &= test_partial_terminal_errors();
    ok &= test_peer_close_and_decoder_rejection();
    if (!ok) return 1;
    std::puts("collision-release-evidence-transport-ok");
    return 0;
}
