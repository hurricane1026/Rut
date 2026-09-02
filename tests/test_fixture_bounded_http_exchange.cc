#include "fixture_bounded_http_exchange.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rut::test::bounded_http_exchange;

static bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
}

static int open_listener(std::uint16_t& port) {
    const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (!check(listener >= 0, "listener socket creation")) return -1;
    int one = 1;
    if (!check(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0,
               "listener setsockopt")) {
        close(listener);
        return -1;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (!check(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
               "listener bind")) {
        close(listener);
        return -1;
    }
    if (!check(listen(listener, 1) == 0, "listener listen")) {
        close(listener);
        return -1;
    }
    socklen_t length = sizeof(address);
    if (!check(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0,
               "listener getsockname")) {
        close(listener);
        return -1;
    }
    port = ntohs(address.sin_port);
    if (!check(port != 0, "listener assigned an ephemeral port")) {
        close(listener);
        return -1;
    }
    return listener;
}

static int open_unlistened_socket(std::uint16_t& port) {
    const int reservation = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (!check(reservation >= 0, "refusal socket creation")) return -1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (!check(bind(reservation, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
               "refusal socket bind")) {
        close(reservation);
        return -1;
    }
    socklen_t length = sizeof(address);
    if (!check(getsockname(reservation, reinterpret_cast<sockaddr*>(&address), &length) == 0,
               "refusal socket getsockname")) {
        close(reservation);
        return -1;
    }
    port = ntohs(address.sin_port);
    if (!check(port != 0, "refusal socket assigned an ephemeral port")) {
        close(reservation);
        return -1;
    }
    return reservation;
}

static int open_fd_count() {
    int count = 0;
    for (int fd = 0; fd < 4096; ++fd)
        if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}

static std::string valid_response() {
    return "HTTP/1.1 502 Bad Gateway\r\nServer: nginx/1.29.7\r\n"
           "Date: Tue, 01 Jan 2030 00:00:00 GMT\r\nContent-Type: text/html\r\n"
           "Content-Length: 2\r\nConnection: close\r\n\r\nok";
}

struct ServerState {
    bool failed = false;
    const char* diagnostic = nullptr;
    bool allow_send_failure = false;
    bool allow_empty_request = false;
    bool wait_for_request_eof = true;
};

static void server_failure(ServerState& state, const char* diagnostic) {
    state.failed = true;
    state.diagnostic = diagnostic;
}

static void serve_response(int listener, const std::string& response, ServerState& state) {
    int client = -1;
    try {
        do {
            pollfd descriptor{listener, POLLIN, 0};
            int ready;
            do {
                ready = poll(&descriptor, 1, 3000);
            } while (ready < 0 && errno == EINTR);
            if (!check(ready > 0, "server listener poll")) {
                server_failure(state, "server listener poll failed");
                break;
            }
            if (!check((descriptor.revents & POLLIN) != 0 &&
                           (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0,
                       "server listener poll events")) {
                server_failure(state, "server listener reported an error");
                break;
            }
            client = accept(listener, nullptr, nullptr);
            if (!check(client >= 0, "server accept")) {
                server_failure(state, "server accept failed");
                break;
            }
            char request[128]{};
            std::size_t received_total = 0;
            for (;;) {
                pollfd request_descriptor{client, POLLIN, 0};
                int request_ready;
                do {
                    request_ready = poll(&request_descriptor, 1, 3000);
                } while (request_ready < 0 && errno == EINTR);
                if (!check(request_ready > 0, "server request poll")) {
                    server_failure(state, "server request poll failed");
                    break;
                }
                if (request_descriptor.revents & (POLLERR | POLLNVAL)) {
                    server_failure(state, "server request poll reported an error");
                    break;
                }
                if (received_total == sizeof(request)) {
                    server_failure(state, "server request exceeded bounded size");
                    break;
                }
                const std::size_t available = std::min(received_total, sizeof(request));
                const ssize_t received =
                    recv(client, request + available, sizeof(request) - available, 0);
                if (received == 0) break;
                if (received < 0 && errno == EINTR) continue;
                if (received < 0) {
                    server_failure(state, "server recv failed");
                    break;
                }
                if (received_total + static_cast<std::size_t>(received) > sizeof(request)) {
                    server_failure(state, "server request exceeded bounded size");
                    break;
                }
                received_total += static_cast<std::size_t>(received);
                if (!state.wait_for_request_eof && received_total >= 4u &&
                    std::string(request, received_total).find("\r\n\r\n") != std::string::npos)
                    break;
            }
            if (state.failed) break;
            if (received_total == 0 && state.allow_empty_request) break;
            if (!check(received_total > 0, "server recv request")) {
                server_failure(state, "server recv failed");
                break;
            }
            std::size_t sent = 0;
            while (sent < response.size()) {
                const ssize_t count =
                    send(client, response.data() + sent, response.size() - sent, MSG_NOSIGNAL);
                if (count <= 0 && state.allow_send_failure) break;
                if (!check(count > 0, "server send response")) {
                    server_failure(state, "server send failed");
                    break;
                }
                sent += static_cast<std::size_t>(count);
            }
        } while (false);
    } catch (...) {
        server_failure(state, "server thread raised an exception");
    }
    if (client >= 0) close(client);
}

static bool exchange_server(const std::string& response,
                            Outcome expected,
                            Observation* result_observation = nullptr,
                            bool allow_send_failure = false,
                            std::int64_t deadline_ns_override = 0,
                            bool allow_empty_request = false,
                            bool shutdown_write_after_send = true) {
    bool ok = true;
    std::uint16_t port = 0;
    const int listener = open_listener(port);
    if (listener < 0) return false;
    ServerState state;
    state.allow_send_failure = allow_send_failure;
    state.allow_empty_request = allow_empty_request;
    state.wait_for_request_eof = shutdown_write_after_send;
    std::thread server;
    try {
        server = std::thread(serve_response, listener, std::cref(response), std::ref(state));
    } catch (...) {
        close(listener);
        return check(false, "server thread creation");
    }
    Observation observation;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    const auto deadline_ns =
        deadline_ns_override != 0
            ? deadline_ns_override
            : std::chrono::duration_cast<std::chrono::nanoseconds>(deadline.time_since_epoch())
                  .count();
    const bool complete = exchange("127.0.0.1",
                                   port,
                                   "GET / HTTP/1.1\r\n\r\n",
                                   deadline_ns,
                                   observation,
                                   kResponseByteLimit,
                                   shutdown_write_after_send);
    if (result_observation != nullptr) *result_observation = observation;
    if (!check(observation.outcome == expected, "bounded exchange outcome")) ok = false;
    if (!check(complete == (expected == Outcome::Complete), "bounded exchange completion result"))
        ok = false;
    if (server.joinable()) server.join();
    if (!check(!state.failed,
               state.diagnostic != nullptr ? state.diagnostic : "server case failed"))
        ok = false;
    if (!check(close(listener) == 0, "listener close")) ok = false;
    return ok;
}

#ifdef RUT_BOUNDED_HTTP_EXCHANGE_TEST_SEAM
static int shutdown_calls = 0;
static std::int64_t seam_now_value = 0;
static std::int64_t seam_deadline = 0;
static int seam_clock_calls = 0;
static int seam_deadline_call = 0;

static std::int64_t fixed_seam_clock() {
    return seam_now_value;
}

static std::int64_t threshold_seam_clock() {
    ++seam_clock_calls;
    return seam_clock_calls >= seam_deadline_call ? seam_deadline : seam_now_value;
}

static int shutdown_eintr_then_success(int fd, int how) {
    ++shutdown_calls;
    if (shutdown_calls == 1) {
        errno = EINTR;
        return -1;
    }
    return ::shutdown(fd, how);
}

static int shutdown_not_connected(int, int) {
    ++shutdown_calls;
    errno = ENOTCONN;
    return -1;
}

static int shutdown_eintr_until_deadline(int, int) {
    ++shutdown_calls;
    errno = EINTR;
    seam_now_value += 250000000LL;
    return -1;
}
#endif

int main() {
    bool ok = true;
    ParsedResponse parsed;
    std::string error;
    if (!check(parse_response(valid_response(), parsed, error), "valid response parses"))
        ok = false;
    if (!check(parsed.status == 502 && parsed.headers.size() == 5 && parsed.body == "ok",
               "valid response fields"))
        ok = false;

    std::string duplicate_length = valid_response();
    duplicate_length.replace(duplicate_length.find("Connection:"),
                             std::strlen("Connection:"),
                             "Content-Length: 2\r\nConnection:");
    std::string control_value = valid_response();
    control_value.replace(control_value.find("text/html"), 9u, "bad\x01value");
    std::string nul_value = valid_response();
    nul_value.replace(nul_value.find("text/html"), 9u, std::string("bad\0value", 9u));
    for (const std::string& mutation_response :
         {valid_response() + "x",
          valid_response().substr(0, valid_response().size() - 1),
          duplicate_length,
          control_value,
          nul_value}) {
        if (!check(!parse_response(mutation_response, parsed, error),
                   "malformed response is rejected"))
            ok = false;
    }

    std::string status_mutation = valid_response();
    status_mutation.replace(status_mutation.find("502"), 3u, "503");
    if (!check(parse_response(status_mutation, parsed, error), "status mutation parses"))
        ok = false;
    std::string order_mutation = valid_response();
    const std::size_t server = order_mutation.find("Server:");
    const std::size_t date = order_mutation.find("Date:");
    const std::size_t date_end = order_mutation.find("\r\n", date) + 2u;
    const std::string server_line = order_mutation.substr(server, date - server);
    const std::string date_line = order_mutation.substr(date, date_end - date);
    order_mutation.replace(server, date_end - server, date_line + server_line);
    if (!check(parse_response(order_mutation, parsed, error), "header order mutation parses"))
        ok = false;
    if (!check(!parse_response(valid_response(), parsed, error, valid_response().size() - 1u),
               "response limit is enforced"))
        ok = false;

    const int descriptors_before = open_fd_count();
    if (!exchange_server(valid_response(), Outcome::Complete)) ok = false;
    {
        Observation observation;
        if (!exchange_server(
                valid_response(), Outcome::Complete, &observation, false, 0, false, false) ||
            !check(observation.send_completed && !observation.write_shutdown_started &&
                       !observation.write_shutdown_completed && observation.read_started &&
                       observation.eof_observed,
                   "normal client exchange reads without write shutdown"))
            ok = false;
    }
#ifdef RUT_BOUNDED_HTTP_EXCHANGE_TEST_SEAM
    {
        Observation observation;
        shutdown_calls = 0;
        test_seam::install(nullptr, shutdown_eintr_then_success);
        const bool exchanged = exchange_server(valid_response(), Outcome::Complete, &observation);
        test_seam::reset();
        if (!check(exchanged && shutdown_calls == 2, "shutdown EINTR is retried")) ok = false;
        if (!check(observation.send_completed && observation.write_shutdown_started &&
                       observation.write_shutdown_completed && observation.read_started &&
                       observation.eof_observed &&
                       observation.send_completed_nanoseconds <
                           observation.write_shutdown_completed_nanoseconds &&
                       observation.write_shutdown_completed_nanoseconds <
                           observation.completion_nanoseconds,
                   "successful exchange observes send/shutdown/read ordering"))
            ok = false;
    }
    {
        Observation observation;
        shutdown_calls = 0;
        test_seam::install(nullptr, shutdown_not_connected);
        const bool exchanged =
            exchange_server(valid_response(), Outcome::WriteShutdownFailed, &observation, true);
        test_seam::reset();
        if (!check(exchanged && shutdown_calls == 1 &&
                       observation.outcome == Outcome::WriteShutdownFailed &&
                       observation.error_number == ENOTCONN && observation.send_completed &&
                       observation.write_shutdown_started &&
                       !observation.write_shutdown_completed && !observation.read_started &&
                       !observation.eof_observed,
                   "terminal shutdown error preserves errno and prevents reads"))
            ok = false;
    }
    {
        bool found = false;
        for (seam_deadline_call = 6; seam_deadline_call <= 24 && !found; ++seam_deadline_call) {
            Observation observation;
            seam_now_value = 1000000000000LL;
            seam_deadline = seam_now_value + 1000000000LL;
            seam_clock_calls = 0;
            test_seam::install(threshold_seam_clock, nullptr);
            (void)exchange_server(valid_response(),
                                  Outcome::DeadlineExceeded,
                                  &observation,
                                  true,
                                  seam_deadline,
                                  true);
            test_seam::reset();
            found = observation.outcome == Outcome::DeadlineExceeded &&
                    observation.send_completed && !observation.write_shutdown_started &&
                    !observation.write_shutdown_completed && !observation.read_started;
        }
        if (!check(found, "deadline before shutdown is deterministic")) ok = false;
    }
    {
        Observation observation;
        shutdown_calls = 0;
        seam_now_value = 1000000000000LL;
        seam_deadline = seam_now_value + 1000000000LL;
        test_seam::install(fixed_seam_clock, shutdown_eintr_until_deadline);
        const bool exchanged = exchange_server(
            valid_response(), Outcome::DeadlineExceeded, &observation, true, seam_deadline);
        test_seam::reset();
        if (!check(exchanged && shutdown_calls == 4 &&
                       observation.outcome == Outcome::DeadlineExceeded &&
                       observation.send_completed && observation.write_shutdown_started &&
                       !observation.write_shutdown_completed && !observation.read_started &&
                       !observation.eof_observed,
                   "repeated shutdown EINTR stops at deadline"))
            ok = false;
    }
#endif
    const std::string truncated = valid_response().substr(0, valid_response().size() - 1u);
    if (!exchange_server(truncated, Outcome::ResponseTruncated)) ok = false;
    if (!exchange_server(std::string(5000u, 'x'), Outcome::ResponseLimitExceeded)) ok = false;
    if (!check(open_fd_count() == descriptors_before, "FD count after server exchanges"))
        ok = false;

    std::uint16_t refused_port = 0;
    const int reservation = open_unlistened_socket(refused_port);
    if (reservation < 0) {
        ok = false;
    } else {
        Observation failure;
        const auto failed_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        const auto failed_deadline_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(failed_deadline.time_since_epoch())
                .count();
        if (!check(!exchange("127.0.0.1",
                             refused_port,
                             "GET / HTTP/1.1\r\n\r\n",
                             failed_deadline_ns,
                             failure),
                   "connection refusal exchange fails"))
            ok = false;
        if (!check(failure.outcome == Outcome::ConnectFailed, "connection refusal outcome"))
            ok = false;
        const auto expired = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        const auto expired_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(expired.time_since_epoch())
                .count();
        if (!check(
                !exchange("127.0.0.1", refused_port, "GET / HTTP/1.1\r\n\r\n", expired_ns, failure),
                "expired exchange fails"))
            ok = false;
        if (!check(failure.outcome == Outcome::DeadlineExceeded, "expired exchange outcome"))
            ok = false;
        if (!check(close(reservation) == 0, "refusal socket close")) ok = false;
    }
    if (!check(open_fd_count() == descriptors_before, "FD count after all exchanges")) ok = false;
    return ok ? 0 : 1;
}
