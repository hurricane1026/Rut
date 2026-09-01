#include "fixture_bounded_http_exchange.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <string_view>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rut::test::bounded_http_exchange {
namespace {

std::int64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

int wait_for(int fd, short events, std::int64_t deadline) {
    for (;;) {
        const std::int64_t left = deadline - now_ns();
        if (left <= 0) return 0;
        const int ms = static_cast<int>(std::min<std::int64_t>((left + 999999) / 1000000, 30000));
        pollfd p{fd, events, 0};
        const int result = poll(&p, 1, ms);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return result;
        if (p.revents & (events | POLLERR | POLLHUP | POLLNVAL)) return p.revents;
    }
}

bool token(std::string_view value, bool name) {
    if (value.empty()) return false;
    for (unsigned char c : value) {
        if (name ? !(std::isalnum(c) || c == '-' || c == '_') : (c == '\r' || c == '\n'))
            return false;
    }
    return true;
}

bool decimal(std::string_view value, unsigned max, unsigned& out) {
    if (value.empty()) return false;
    unsigned n = 0;
    for (unsigned char c : value) {
        if (c < '0' || c > '9' || n > (max - (c - '0')) / 10) return false;
        n = n * 10 + (c - '0');
    }
    out = n;
    return true;
}

}  // namespace

bool parse_response(const std::string& raw,
                    ParsedResponse& parsed,
                    std::string& error,
                    std::size_t limit) {
    parsed = {};
    error.clear();
    if (raw.empty() || raw.size() > limit) {
        error = "response exceeds bounded byte limit";
        return false;
    }
    const std::size_t head_end = raw.find("\r\n\r\n");
    if (head_end == std::string::npos) {
        error = "response headers are incomplete";
        return false;
    }
    const std::size_t line_end = raw.find("\r\n");
    if (line_end == std::string::npos || line_end >= head_end) {
        error = "response status line is malformed";
        return false;
    }
    const std::string status_line = raw.substr(0, line_end);
    if (status_line.size() < 13 || status_line.compare(0, 5, "HTTP/") != 0 ||
        status_line[8] != ' ') {
        error = "response status line is malformed";
        return false;
    }
    parsed.version = status_line.substr(5, 3);
    unsigned status = 0;
    if (!decimal(std::string_view(status_line).substr(9, 3), 999, status) || status < 100 ||
        status_line[12] != ' ') {
        error = "response status code is malformed";
        return false;
    }
    parsed.status = static_cast<std::uint16_t>(status);
    parsed.reason = status_line.substr(13);
    std::size_t cursor = line_end + 2;
    std::size_t content_length_count = 0;
    std::size_t content_length = 0;
    while (cursor < head_end) {
        const std::size_t end = raw.find("\r\n", cursor);
        if (end == std::string::npos || end == cursor) {
            error = "response header line is malformed";
            return false;
        }
        const std::string line = raw.substr(cursor, end - cursor);
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos || !token(line.substr(0, colon), true) ||
            colon + 1 >= line.size() || line[colon + 1] != ' ') {
            error = "response header line is malformed";
            return false;
        }
        const std::string name = line.substr(0, colon);
        const std::string value = line.substr(colon + 2);
        if (!token(value, false)) {
            error = "response header value is malformed";
            return false;
        }
        if (name == "Content-Length") {
            ++content_length_count;
            unsigned parsed_length = 0;
            if (!decimal(value, static_cast<unsigned>(limit), parsed_length)) {
                error = "content length is malformed";
                return false;
            }
            content_length = parsed_length;
        }
        parsed.headers.push_back({name, value});
        cursor = end + 2;
    }
    if (content_length_count != 1) {
        error = "response must contain exactly one Content-Length";
        return false;
    }
    const std::size_t body_start = head_end + 4;
    if (content_length > raw.size() - body_start) {
        error = "response body is truncated";
        return false;
    }
    if (raw.size() - body_start != content_length) {
        error = "response contains trailing bytes";
        return false;
    }
    parsed.body.assign(raw.data() + body_start, content_length);
    return true;
}

bool exchange(const std::string& ipv4,
              std::uint16_t port,
              const std::string& request,
              std::int64_t deadline_ns,
              Observation& observation,
              std::size_t limit) {
    observation = {};
    observation.attempted = true;
    observation.request = request;
    observation.start_nanoseconds = now_ns();
    const auto fail = [&](Outcome outcome, const char* message) {
        observation.outcome = outcome;
        observation.terminal_frozen = true;
        observation.diagnostic = message;
        observation.completion_nanoseconds = now_ns();
        return false;
    };
    in_addr address{};
    if (inet_pton(AF_INET, ipv4.c_str(), &address) != 1 || port == 0 || request.empty() ||
        request.size() > limit || deadline_ns <= observation.start_nanoseconds)
        return fail(Outcome::InvalidArgument, "invalid bounded exchange argument");
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return fail(Outcome::SocketCreateFailed, "IPv4 socket creation failed");
    struct FdGuard {
        int fd;
        ~FdGuard() {
            if (fd >= 0) close(fd);
        }
    } guard{fd};
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr = address;
    observation.connect_started = true;
    int result = connect(fd, reinterpret_cast<sockaddr*>(&target), sizeof(target));
    if (result != 0 && errno != EINPROGRESS) return fail(Outcome::ConnectFailed, "connect failed");
    if (result != 0) {
        const int events = wait_for(fd, POLLOUT, deadline_ns);
        if (events <= 0) return fail(Outcome::DeadlineExceeded, "connect deadline exceeded");
        int status = 0;
        socklen_t length = sizeof(status);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &length) != 0 || status != 0)
            return fail(Outcome::ConnectFailed, "connect failed");
    }
    if (now_ns() >= deadline_ns)
        return fail(Outcome::DeadlineExceeded, "connect deadline exceeded");
    observation.connect_completed = true;
    observation.connect_completed_nanoseconds = now_ns();
    observation.send_started = true;
    std::size_t sent = 0;
    while (sent < request.size()) {
        if (now_ns() >= deadline_ns)
            return fail(Outcome::DeadlineExceeded, "send deadline exceeded");
        const ssize_t count = send(fd, request.data() + sent, request.size() - sent, MSG_NOSIGNAL);
        if (count > 0) {
            sent += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (wait_for(fd, POLLOUT, deadline_ns) <= 0)
                return fail(Outcome::DeadlineExceeded, "send deadline exceeded");
            continue;
        }
        return fail(Outcome::SendFailed, "send failed");
    }
    observation.send_completed = true;
    observation.send_completed_nanoseconds = now_ns();
    observation.read_started = true;
    std::array<char, 1024> buffer{};
    for (;;) {
        if (now_ns() >= deadline_ns)
            return fail(Outcome::DeadlineExceeded, "read deadline exceeded");
        const ssize_t count = recv(fd, buffer.data(), buffer.size(), 0);
        if (count > 0) {
            if (observation.raw_response.size() + static_cast<std::size_t>(count) > limit)
                return fail(Outcome::ResponseLimitExceeded, "response exceeds bounded byte limit");
            observation.raw_response.append(buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0) {
            observation.eof_observed = true;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            const int events = wait_for(fd, POLLIN, deadline_ns);
            if (events <= 0) return fail(Outcome::DeadlineExceeded, "read deadline exceeded");
            continue;
        }
        return fail(Outcome::ReadFailed, "read failed");
    }
    std::string error;
    if (!parse_response(observation.raw_response, observation.parsed, error, limit)) {
        observation.diagnostic = error;
        observation.outcome = error.find("truncated") != std::string::npos
                                  ? Outcome::ResponseTruncated
                                  : Outcome::ResponseMalformed;
        observation.terminal_frozen = true;
        observation.completion_nanoseconds = now_ns();
        return false;
    }
    observation.outcome = Outcome::Complete;
    observation.terminal_frozen = true;
    observation.completion_nanoseconds = now_ns();
    return true;
}

}  // namespace rut::test::bounded_http_exchange
