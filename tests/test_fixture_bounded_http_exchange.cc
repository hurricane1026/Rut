#include "fixture_bounded_http_exchange.h"
#include <cassert>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <thread>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rut::test::bounded_http_exchange;

static int open_listener(std::uint16_t& port) {
    const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(listener >= 0);
    int one = 1;
    assert(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    assert(listen(listener, 1) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0);
    port = ntohs(address.sin_port);
    return listener;
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

int main() {
    ParsedResponse parsed;
    std::string error;
    assert(parse_response(valid_response(), parsed, error));
    assert(parsed.status == 502 && parsed.headers.size() == 5 && parsed.body == "ok");
    std::string duplicate_length = valid_response();
    duplicate_length.replace(duplicate_length.find("Connection:"), std::strlen("Connection:"),
                              "Content-Length: 2\r\nConnection:");
    std::string control_value = valid_response();
    control_value.replace(control_value.find("text/html"), 9u, "bad\x01value");
    std::string nul_value = valid_response();
    nul_value.replace(nul_value.find("text/html"), 9u, std::string("bad\0value", 9u));
    for (const std::string& mutation :
         {valid_response() + "x", valid_response().substr(0, valid_response().size() - 1),
          duplicate_length, control_value, nul_value})
        assert(!parse_response(mutation, parsed, error));

    std::string status_mutation = valid_response();
    status_mutation.replace(status_mutation.find("502"), 3u, "503");
    assert(parse_response(status_mutation, parsed, error));
    std::string order_mutation = valid_response();
    const std::size_t server = order_mutation.find("Server:");
    const std::size_t date = order_mutation.find("Date:");
    const std::size_t date_end = order_mutation.find("\r\n", date) + 2u;
    const std::string server_line = order_mutation.substr(server, date - server);
    const std::string date_line = order_mutation.substr(date, date_end - date);
    order_mutation.replace(server, date_end - server, date_line + server_line);
    assert(parse_response(order_mutation, parsed, error));
    assert(!parse_response(valid_response(), parsed, error, valid_response().size() - 1u));

    auto exchange_server = [&](const std::string& response, Outcome expected) {
        std::uint16_t port = 0;
        const int listener = open_listener(port);
        std::thread server([&] {
        const int client = accept(listener, nullptr, nullptr);
        assert(client >= 0);
        char request[128]{};
        (void)recv(client, request, sizeof(request), 0);
        std::size_t sent = 0;
        while (sent < response.size()) {
            const ssize_t count = send(client, response.data() + sent, response.size() - sent,
                                       MSG_NOSIGNAL);
            assert(count > 0);
            sent += static_cast<std::size_t>(count);
        }
        close(client);
        });
        Observation observation;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        const auto deadline_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     deadline.time_since_epoch())
                                     .count();
        const bool complete = exchange("127.0.0.1", port, "GET / HTTP/1.1\r\n\r\n", deadline_ns,
                                        observation);
        assert(observation.outcome == expected);
        assert(complete == (expected == Outcome::Complete));
        server.join();
        close(listener);
    };
    const int descriptors_before = open_fd_count();
    exchange_server(valid_response(), Outcome::Complete);
    const std::string truncated = valid_response().substr(0, valid_response().size() - 1u);
    exchange_server(truncated, Outcome::ResponseTruncated);
    exchange_server(std::string(5000u, 'x'), Outcome::ResponseLimitExceeded);
    assert(open_fd_count() == descriptors_before);

    Observation failure;
    const auto failed_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    const auto failed_deadline_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        failed_deadline.time_since_epoch())
                                        .count();
    assert(!exchange("127.0.0.1", 1u, "GET / HTTP/1.1\r\n\r\n", failed_deadline_ns, failure));
    assert(failure.outcome == Outcome::ConnectFailed);
    const auto expired = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    const auto expired_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(expired.time_since_epoch()).count();
    assert(!exchange("127.0.0.1", 1u, "GET / HTTP/1.1\r\n\r\n", expired_ns, failure));
    assert(failure.outcome == Outcome::DeadlineExceeded);
    assert(open_fd_count() == descriptors_before);
    return 0;
}
