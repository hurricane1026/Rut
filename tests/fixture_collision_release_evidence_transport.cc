#include "fixture_collision_release_evidence_transport.h"

#include <array>
#include <cerrno>
#include <climits>
#include <cstring>
#include <utility>

#include <sys/socket.h>

namespace rut::test::fixture_collision_release_evidence_transport {
namespace {

using Clock = std::chrono::steady_clock;
using Header = std::array<unsigned char, worker::kHeaderBytes>;

int real_poll(pollfd* descriptors, nfds_t count, int timeout, void*) {
    return ::poll(descriptors, count, timeout);
}

ssize_t real_recv(int fd, void* data, std::size_t size, int flags, void*) {
    return ::recv(fd, data, size, flags);
}

ssize_t real_send(int fd, const void* data, std::size_t size, int flags, void*) {
    return ::send(fd, data, size, flags);
}

HooksForTesting::Poll poll_hook(const HooksForTesting& hooks) {
    return hooks.poll == nullptr ? real_poll : hooks.poll;
}

HooksForTesting::Recv recv_hook(const HooksForTesting& hooks) {
    return hooks.recv == nullptr ? real_recv : hooks.recv;
}

HooksForTesting::Send send_hook(const HooksForTesting& hooks) {
    return hooks.send == nullptr ? real_send : hooks.send;
}

bool valid_maximum(std::size_t maximum) {
    return maximum >= kEnvelopeBytes && maximum <= worker::kMaxPayload;
}

bool valid_fd(int fd) {
    return fd >= 0;
}

void set_diagnostic(Diagnostic& diagnostic,
                    DiagnosticCode code,
                    Stage stage,
                    int error_number,
                    std::size_t bytes_transferred) {
    diagnostic = {code, stage, error_number, bytes_transferred};
}

bool fail(Diagnostic& diagnostic,
          DiagnosticCode code,
          Stage stage,
          int error_number,
          std::size_t bytes_transferred) {
    set_diagnostic(diagnostic, code, stage, error_number, bytes_transferred);
    return false;
}

int poll_timeout(Clock::time_point deadline, Clock::time_point now) {
    const auto remaining = deadline - now;
    if (remaining > std::chrono::milliseconds(INT_MAX)) return INT_MAX;
    const auto whole_milliseconds =
        std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
    auto milliseconds = whole_milliseconds.count();
    if (remaining > whole_milliseconds) ++milliseconds;
    return milliseconds <= 0 ? 1 : static_cast<int>(milliseconds);
}

bool wait_ready(int fd,
                short events,
                Stage stage,
                Clock::time_point deadline,
                std::size_t bytes_transferred,
                const HooksForTesting& hooks,
                Diagnostic& diagnostic) {
    for (;;) {
        const Clock::time_point now = Clock::now();
        if (now >= deadline)
            return fail(diagnostic, DiagnosticCode::Deadline, stage, ETIMEDOUT, bytes_transferred);

        pollfd descriptor{fd, events, 0};
        errno = 0;
        const int result =
            poll_hook(hooks)(&descriptor, 1, poll_timeout(deadline, now), hooks.context);
        if (result < 0) {
            const int error_number = errno;
            if (error_number == EINTR) continue;
            return fail(
                diagnostic, DiagnosticCode::PollError, stage, error_number, bytes_transferred);
        }
        if (result == 0)
            return fail(diagnostic, DiagnosticCode::Deadline, stage, ETIMEDOUT, bytes_transferred);
        if (Clock::now() >= deadline)
            return fail(diagnostic, DiagnosticCode::Deadline, stage, ETIMEDOUT, bytes_transferred);
        if ((descriptor.revents & POLLNVAL) != 0)
            return fail(diagnostic, DiagnosticCode::PollError, stage, EBADF, bytes_transferred);
        if ((descriptor.revents & (events | POLLERR | POLLHUP)) != 0) return true;
    }
}

bool read_exact(int fd,
                unsigned char* data,
                std::size_t size,
                Stage stage,
                Clock::time_point deadline,
                std::size_t& total,
                const HooksForTesting& hooks,
                Diagnostic& diagnostic) {
    std::size_t done = 0;
    while (done != size) {
        if (!wait_ready(fd, POLLIN, stage, deadline, total, hooks, diagnostic)) return false;
        errno = 0;
        const ssize_t count = recv_hook(hooks)(fd, data + done, size - done, 0, hooks.context);
        if (count > 0) {
            if (static_cast<std::size_t>(count) > size - done)
                return fail(diagnostic, DiagnosticCode::SyscallError, stage, EIO, total);
            done += static_cast<std::size_t>(count);
            total += static_cast<std::size_t>(count);
            continue;
        }
        if (count == 0) {
            const DiagnosticCode code =
                stage == Stage::ReadHeader && done == 0 ? DiagnosticCode::CleanEofBeforeHeader
                : stage == Stage::ReadHeader            ? DiagnosticCode::TruncatedHeader
                                                        : DiagnosticCode::TruncatedPayload;
            return fail(diagnostic, code, stage, 0, total);
        }
        const int error_number = errno;
        if (error_number == EINTR) continue;
        return fail(diagnostic, DiagnosticCode::SyscallError, stage, error_number, total);
    }
    return true;
}

bool write_exact(int fd,
                 const unsigned char* data,
                 std::size_t size,
                 Stage stage,
                 Clock::time_point deadline,
                 std::size_t& total,
                 const HooksForTesting& hooks,
                 Diagnostic& diagnostic) {
    std::size_t done = 0;
    while (done != size) {
        if (!wait_ready(fd, POLLOUT, stage, deadline, total, hooks, diagnostic)) return false;
        errno = 0;
        const ssize_t count =
            send_hook(hooks)(fd, data + done, size - done, MSG_NOSIGNAL, hooks.context);
        if (count > 0) {
            if (static_cast<std::size_t>(count) > size - done)
                return fail(diagnostic, DiagnosticCode::SyscallError, stage, EIO, total);
            done += static_cast<std::size_t>(count);
            total += static_cast<std::size_t>(count);
            continue;
        }
        if (count == 0) return fail(diagnostic, DiagnosticCode::SyscallError, stage, EPIPE, total);
        const int error_number = errno;
        if (error_number == EINTR) continue;
        return fail(diagnostic, DiagnosticCode::SyscallError, stage, error_number, total);
    }
    return true;
}

void put16(unsigned char* destination, worker::u16 value) {
    destination[0] = static_cast<unsigned char>(value);
    destination[1] = static_cast<unsigned char>(value >> 8u);
}

void put32(unsigned char* destination, worker::u32 value) {
    for (unsigned shift = 0u; shift != 32u; shift += 8u)
        destination[shift / 8u] = static_cast<unsigned char>(value >> shift);
}

worker::u16 get16(const unsigned char* source) {
    return static_cast<worker::u16>(source[0]) |
           static_cast<worker::u16>(static_cast<worker::u16>(source[1]) << 8u);
}

worker::u32 get32(const unsigned char* source) {
    worker::u32 value = 0u;
    for (unsigned shift = 0u; shift != 32u; shift += 8u)
        value |= static_cast<worker::u32>(source[shift / 8u]) << shift;
    return value;
}

void make_header(const worker::Frame& frame, Header& header) {
    put32(header.data(), worker::kMagic);
    put16(header.data() + 4u, worker::kVersion);
    put16(header.data() + 6u, frame.type);
    put32(header.data() + 8u, static_cast<worker::u32>(frame.payload.size()));
    std::memcpy(header.data() + 12u, frame.token.bytes.data(), worker::kTokenBytes);
}

}  // namespace

bool receive_frame(int fd,
                   const worker::Token& expected_token,
                   std::size_t maximum_payload,
                   Clock::time_point deadline,
                   worker::Frame& output,
                   Diagnostic& diagnostic,
                   const HooksForTesting& hooks) {
    diagnostic = {};
    if (!valid_maximum(maximum_payload))
        return fail(diagnostic, DiagnosticCode::Argument, Stage::None, EINVAL, 0u);
    if (!valid_fd(fd)) return fail(diagnostic, DiagnosticCode::Argument, Stage::None, EBADF, 0u);

    Header header{};
    std::size_t total = 0u;
    if (!read_exact(fd,
                    header.data(),
                    header.size(),
                    Stage::ReadHeader,
                    deadline,
                    total,
                    hooks,
                    diagnostic))
        return false;

    if (get32(header.data()) != worker::kMagic)
        return fail(diagnostic, DiagnosticCode::BadMagic, Stage::ReadHeader, 0, total);
    if (get16(header.data() + 4u) != worker::kVersion)
        return fail(diagnostic, DiagnosticCode::BadVersion, Stage::ReadHeader, 0, total);
    if (get16(header.data() + 6u) != kEvidenceFrameType)
        return fail(diagnostic, DiagnosticCode::BadType, Stage::ReadHeader, 0, total);
    if (std::memcmp(header.data() + 12u, expected_token.bytes.data(), worker::kTokenBytes) != 0)
        return fail(diagnostic, DiagnosticCode::BadToken, Stage::ReadHeader, 0, total);

    const worker::u32 length = get32(header.data() + 8u);
    if (length < kEnvelopeBytes)
        return fail(diagnostic, DiagnosticCode::PayloadTooSmall, Stage::ReadHeader, 0, total);
    if (length > maximum_payload || length > worker::kMaxPayload)
        return fail(diagnostic, DiagnosticCode::PayloadTooLarge, Stage::ReadHeader, 0, total);

    worker::Frame candidate;
    candidate.type = kEvidenceFrameType;
    std::memcpy(candidate.token.bytes.data(), header.data() + 12u, worker::kTokenBytes);
    candidate.payload.resize(static_cast<std::size_t>(length));
    if (!read_exact(fd,
                    candidate.payload.data(),
                    candidate.payload.size(),
                    Stage::ReadPayload,
                    deadline,
                    total,
                    hooks,
                    diagnostic))
        return false;

    output = std::move(candidate);
    diagnostic = {};
    return true;
}

bool send_frame(int fd,
                const worker::Token& expected_token,
                std::size_t maximum_payload,
                Clock::time_point deadline,
                const worker::Frame& frame,
                Diagnostic& diagnostic,
                const HooksForTesting& hooks) {
    diagnostic = {};
    if (!valid_maximum(maximum_payload))
        return fail(diagnostic, DiagnosticCode::Argument, Stage::None, EINVAL, 0u);
    if (!valid_fd(fd)) return fail(diagnostic, DiagnosticCode::Argument, Stage::None, EBADF, 0u);
    if (frame.type != kEvidenceFrameType)
        return fail(diagnostic, DiagnosticCode::BadType, Stage::None, 0, 0u);
    if (!worker::token_equal(frame.token, expected_token))
        return fail(diagnostic, DiagnosticCode::BadToken, Stage::None, 0, 0u);
    if (frame.payload.size() < kEnvelopeBytes)
        return fail(diagnostic, DiagnosticCode::PayloadTooSmall, Stage::None, 0, 0u);
    if (frame.payload.size() > maximum_payload || frame.payload.size() > worker::kMaxPayload)
        return fail(diagnostic, DiagnosticCode::PayloadTooLarge, Stage::None, 0, 0u);

    Header header{};
    make_header(frame, header);
    std::size_t total = 0u;
    if (!write_exact(fd,
                     header.data(),
                     header.size(),
                     Stage::WriteHeader,
                     deadline,
                     total,
                     hooks,
                     diagnostic))
        return false;
    if (!write_exact(fd,
                     frame.payload.data(),
                     frame.payload.size(),
                     Stage::WritePayload,
                     deadline,
                     total,
                     hooks,
                     diagnostic))
        return false;

    diagnostic = {};
    return true;
}

}  // namespace rut::test::fixture_collision_release_evidence_transport
