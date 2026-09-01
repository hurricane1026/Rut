#include "fixture_bounded_http_exchange.h"
#include <cassert>
#include <chrono>
#include <cstring>
#include <thread>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rut::test::bounded_http_exchange;

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
    for (const std::string& mutation :
         {valid_response() + "x",
          valid_response().substr(0, valid_response().size() - 1),
          valid_response().replace(valid_response().find("Connection:"),
                                   std::strlen("Connection:"),
                                   "Content-Length: 2\r\nConnection:")})
        assert(!parse_response(mutation, parsed, error));

    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
    const std::uint16_t port = ntohs(address.sin_port);
    std::thread server([&] {
        const int client = accept(listener, nullptr, nullptr);
        assert(client >= 0);
        char request[128]{};
        (void)recv(client, request, sizeof(request), 0);
        const std::string response = valid_response();
        assert(send(client, response.data(), response.size(), MSG_NOSIGNAL) ==
               static_cast<ssize_t>(response.size()));
        close(client);
    });
    Observation observation;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    const auto deadline_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(deadline.time_since_epoch()).count();
    assert(exchange("127.0.0.1", port, "GET / HTTP/1.1\r\n\r\n", deadline_ns, observation));
    assert(observation.outcome == Outcome::Complete && observation.eof_observed);
    server.join();
    close(listener);
    return 0;
}
