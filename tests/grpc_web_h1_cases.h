#pragma once

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <string>
#include <vector>

namespace {

inline void grpc_web_test_init_raw_request(
    rut::Connection& conn, u8* storage, u32 cap, const char* request, u32 request_len) {
    conn.reset();
    conn.bind_request_receive_buffer(storage, cap);
    __builtin_memcpy(storage, request, request_len);
    conn.recv_buf.commit(request_len);
    for (u32 i = 3; i < request_len; i++) {
        if (storage[i - 3] == '\r' && storage[i - 2] == '\n' && storage[i - 1] == '\r' &&
            storage[i] == '\n') {
            conn.req_header_end = i + 1;
            return;
        }
    }
}

inline void grpc_web_test_init_request(rut::Connection& conn, u8* storage, u32 cap) {
    static constexpr char kRequest[] =
        "POST /test.Echo/Call HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/grpc-web\r\n"
        "Content-Length: 0\r\n\r\n";
    grpc_web_test_init_raw_request(conn, storage, cap, kRequest, sizeof(kRequest) - 1);
}

inline std::vector<u8> grpc_web_test_base64(const std::vector<u8>& input) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<u8> output;
    output.reserve(((input.size() + 2) / 3) * 4);
    for (size_t i = 0; i < input.size(); i += 3) {
        const u32 left = static_cast<u32>(input.size() - i);
        const u8 a = input[i];
        const u8 b = left > 1 ? input[i + 1] : 0;
        const u8 c = left > 2 ? input[i + 2] : 0;
        output.push_back(kAlphabet[a >> 2]);
        output.push_back(kAlphabet[((a & 3) << 4) | (b >> 4)]);
        output.push_back(left > 1 ? kAlphabet[((b & 15) << 2) | (c >> 6)] : '=');
        output.push_back(left > 2 ? kAlphabet[c & 63] : '=');
    }
    return output;
}

inline bool grpc_web_test_decode_text_response(const std::vector<u8>& response,
                                              std::vector<u8>& decoded) {
    static constexpr char kBoundary[] = "\r\n\r\n";
    const auto boundary = std::search(response.begin(), response.end(),
                                      kBoundary, kBoundary + sizeof(kBoundary) - 1);
    if (boundary == response.end()) return false;
    const auto body_offset = static_cast<size_t>(boundary - response.begin()) +
                             sizeof(kBoundary) - 1;
    if (body_offset > response.size()) return false;
    const u8* body = response.data() + body_offset;
    const u32 body_len = static_cast<u32>(response.size() - body_offset);
    decoded.resize(body_len);
    GrpcWebBase64Decoder decoder{};
    decoder.init();
    u32 consumed = 0, written = 0;
    if (decoder.feed(body, body_len, consumed, decoded.data(), body_len, written) !=
            GrpcWebCodecStatus::Ok ||
        consumed != body_len || decoder.finish() != GrpcWebCodecStatus::Ok)
        return false;
    decoded.resize(written);
    return true;
}

inline bool grpc_web_test_h1_abort_partial_upload(EchoServer& server, u16 port) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    set_socket_timeouts(fd, 5);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return false;
    }
    static constexpr char kRequest[] =
        "POST /test.Echo/Call HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/grpc-web\r\n"
        "Content-Length: 12\r\n"
        "Connection: close\r\n\r\n";
    static constexpr u8 kPartialBody[] = {0, 0, 0, 0, 7, 0xaa};
    const bool sent = write_all_fd(fd, reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1) &&
                      write_all_fd(fd, kPartialBody, sizeof(kPartialBody));
    const u64 deadline = monotonic_us() + 3000000;
    while (sent && !server.requests.load() && monotonic_us() < deadline) usleep(1000);
    const bool reached_backend = server.requests.load() != 0;
    shutdown(fd, SHUT_RDWR);
    close(fd);
    return sent && reached_backend;
}

inline bool grpc_web_test_h1_exchange(u16 port,
                                      bool text,
                                      bool chunked,
                                      const std::vector<u8>& body,
                                      std::vector<u8>& response,
                                      bool tls = false,
                                      const std::vector<u8>* expected_body = nullptr,
                                      const char* extra_headers = "") {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    set_socket_timeouts(fd, 5);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return false;
    }
    SSL_CTX* tls_context = tls ? SSL_CTX_new(TLS_client_method()) : nullptr;
    SSL* ssl = nullptr;
    if (tls) {
        if (!tls_context) {
            close(fd);
            return false;
        }
        SSL_CTX_set_verify(tls_context, SSL_VERIFY_NONE, nullptr);
        ssl = SSL_new(tls_context);
        if (!ssl || !SSL_set_fd(ssl, fd) || SSL_connect(ssl) != 1) {
            if (ssl) SSL_free(ssl);
            SSL_CTX_free(tls_context);
            close(fd);
            return false;
        }
    }

    std::vector<u8> wire;
    const char* content_type = text ? "Application/Grpc-Web-Text" : "Application/Grpc-Web";
    char header[512];
    const int header_len =
        snprintf(header,
                 sizeof(header),
                 "POST /test.Echo/Call HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "%s"
                 "Content-Type: %s\r\n"
                 "%s"
                 "Connection: close\r\n\r\n",
                 extra_headers,
                 content_type,
                 chunked ? "Transfer-Encoding: chunked\r\n" : "Content-Length: 0\r\n");
    if (header_len <= 0 || static_cast<size_t>(header_len) >= sizeof(header)) {
        close(fd);
        return false;
    }
    wire.insert(wire.end(), header, header + header_len);
    if (!chunked) {
        // Replace the placeholder Content-Length line before appending body.
        static constexpr char kPlaceholder[] = "Content-Length: 0\r\n";
        const auto found = std::search(
            wire.begin(), wire.end(), kPlaceholder, kPlaceholder + sizeof(kPlaceholder) - 1);
        if (found == wire.end()) {
            close(fd);
            return false;
        }
        const size_t offset = static_cast<size_t>(found - wire.begin());
        char actual[48];
        const int actual_len =
            snprintf(actual, sizeof(actual), "Content-Length: %zu\r\n", body.size());
        wire.erase(wire.begin() + offset, wire.begin() + offset + sizeof(kPlaceholder) - 1);
        wire.insert(wire.begin() + offset, actual, actual + actual_len);
        wire.insert(wire.end(), body.begin(), body.end());
    } else {
        constexpr size_t kChunk = 1024;
        for (size_t offset = 0; offset < body.size();) {
            const size_t n = std::min(kChunk, body.size() - offset);
            char size[24];
            const int size_len = snprintf(size, sizeof(size), "%zx\r\n", n);
            wire.insert(wire.end(), size, size + size_len);
            wire.insert(wire.end(), body.begin() + offset, body.begin() + offset + n);
            wire.push_back('\r');
            wire.push_back('\n');
            offset += n;
        }
        static constexpr char kEnd[] = "0\r\n\r\n";
        wire.insert(wire.end(), kEnd, kEnd + sizeof(kEnd) - 1);
    }
    bool sent = false;
    if (!tls) {
        sent = write_all_fd(fd, wire.data(), static_cast<u32>(wire.size()));
    } else {
        sent = true;
        size_t offset = 0;
        while (offset < wire.size()) {
            const int n =
                SSL_write(ssl, wire.data() + offset, static_cast<int>(wire.size() - offset));
            if (n <= 0) {
                sent = false;
                break;
            }
            offset += static_cast<size_t>(n);
        }
    }
    if (sent) {
        u8 buf[8192];
        for (;;) {
            const ssize_t n = tls ? SSL_read(ssl, buf, sizeof(buf)) : recv(fd, buf, sizeof(buf), 0);
            if (n == 0) break;
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) {
                const int ssl_error = tls ? SSL_get_error(ssl, static_cast<int>(n)) : 0;
                if (tls && (ssl_error == SSL_ERROR_ZERO_RETURN ||
                            (ssl_error == SSL_ERROR_SYSCALL && errno == 0)))
                    break;
                close(fd);
                if (ssl) SSL_free(ssl);
                if (tls_context) SSL_CTX_free(tls_context);
                return false;
            }
            response.insert(response.end(), buf, buf + n);
            if (expected_body &&
                std::search(response.begin(), response.end(), expected_body->begin(),
                            expected_body->end()) != response.end())
                break;
            if (response.size() > 256 * 1024) {
                close(fd);
                return false;
            }
        }
    }
    if (ssl) SSL_free(ssl);
    if (tls_context) SSL_CTX_free(tls_context);
    close(fd);
    return sent;
}

template <typename Loop>
void grpc_web_h1_streaming_text_message_case(rut::test::TestCase* _tc,
                                             u32 native_len,
                                             bool partial_next) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->stream_response_len = native_len;
    server->stream_response_partial_next = partial_next;
    server->reply_mode = 5;
    auto shard = std::make_unique<Shard<Loop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log());
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    std::vector<u8> message(native_len);
    message[0] = 0;
    const u32 payload_len = native_len - 5;
    message[1] = static_cast<u8>(payload_len >> 24);
    message[2] = static_cast<u8>(payload_len >> 16);
    message[3] = static_cast<u8>(payload_len >> 8);
    message[4] = static_cast<u8>(payload_len);
    for (u32 i = 5; i < native_len; i++) message[i] = static_cast<u8>(0xa0 + i);
    const auto expected = grpc_web_test_base64(message);
    const std::vector<u8> empty;
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(
        get_port(listener), true, false, empty, response, false, &expected));
    CHECK(std::search(response.begin(), response.end(), expected.begin(), expected.end()) !=
          response.end());

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    CHECK_EQ(server->requests.load(), 1u);
}

void grpc_web_h1_trailers_only_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 1;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> rpc_body{0, 0, 0, 0, 1, 0};
    const auto request_body = grpc_web_test_base64(rpc_body);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, request_body, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        const u32 payload_len = (static_cast<u32>(decoded[1]) << 24) |
                                (static_cast<u32>(decoded[2]) << 16) |
                                (static_cast<u32>(decoded[3]) << 8) | decoded[4];
        CHECK_EQ(payload_len, decoded.size() - 5);
        CHECK(std::search(decoded.begin() + 5, decoded.end(), "grpc-status: 7",
                          "grpc-status: 7" + 14) != decoded.end());
    }
    CHECK_EQ(server->requests.load(), 1u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_decoded_request_limit_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    config.upstreams[0].max_request_message_bytes = 1;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> native_request{0, 0, 0, 0, 2, 0xaa, 0xbb};
    const auto request_body = grpc_web_test_base64(native_request);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, request_body, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK_EQ(decoded[4], 16u);
        CHECK(std::search(decoded.begin() + 5, decoded.end(), "grpc-status: 8",
                          "grpc-status: 8" + 14) != decoded.end());
    }
    CHECK_EQ(server->requests.load(), 0u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_deadline_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 6;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> native_request{0, 0, 0, 0, 1, 0};
    const auto request_body = grpc_web_test_base64(native_request);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, request_body, response,
                                   false, nullptr, "grpc-timeout: 1n\r\n"));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK(std::search(decoded.begin() + 5, decoded.end(), "grpc-status: 4",
                          "grpc-status: 4" + 14) != decoded.end());
    }

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_decoded_response_limit_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    config.upstreams[0].max_response_message_bytes = 1;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> native_request{0, 0, 0, 0, 2, 0xaa, 0xbb};
    const auto request_body = grpc_web_test_base64(native_request);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, request_body, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK_EQ(decoded[4], 16u);
        CHECK(std::search(decoded.begin() + 5, decoded.end(), "grpc-status: 8",
                          "grpc-status: 8" + 14) != decoded.end());
    }
    CHECK_EQ(server->requests.load(), 1u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_json_response_rejected_case(rut::test::TestCase* _tc, u32 response_mode) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = response_mode;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> native_request{0, 0, 0, 0, 1, 0};
    const auto request_body = grpc_web_test_base64(native_request);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, request_body, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK(std::search(decoded.begin() + 5, decoded.end(), "grpc-status: 13",
                          "grpc-status: 13" + 15) != decoded.end());
    }
    CHECK_EQ(server->requests.load(), 1u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_abort_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 6;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log());
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    CHECK(grpc_web_test_h1_abort_partial_upload(*server, get_port(listener)));
    const u64 deadline = monotonic_us() + 3000000;
    while (!server->resets.load() && monotonic_us() < deadline) usleep(1000);
    CHECK_GT(server->resets.load(), 0u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    AccessLogEntry entry{};
    CHECK(shard->log_ring->pop(entry));
    CHECK_EQ(entry.grpc_status_plus_one, 2u);
    CHECK(!shard->log_ring->pop(entry));

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

template <typename Loop>
void grpc_web_h1_roundtrip_case(rut::test::TestCase* _tc,
                                bool text,
                                bool chunked,
                                u32 payload_len) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<Loop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    std::vector<u8> rpc_body(5 + payload_len);
    rpc_body[0] = 0;
    rpc_body[1] = static_cast<u8>(payload_len >> 24);
    rpc_body[2] = static_cast<u8>(payload_len >> 16);
    rpc_body[3] = static_cast<u8>(payload_len >> 8);
    rpc_body[4] = static_cast<u8>(payload_len);
    for (u32 i = 0; i < payload_len; i++) rpc_body[5 + i] = static_cast<u8>((i * 17u) & 0xff);
    std::vector<u8> request_body = text ? grpc_web_test_base64(rpc_body) : rpc_body;
    std::vector<u8> response;
    const bool exchanged =
        grpc_web_test_h1_exchange(get_port(listener), text, chunked, request_body, response);
    if (!exchanged) {
        std::fprintf(stderr,
                     "H1 failed: text=%u chunked=%u len=%zu backend=%u response=%zu\n",
                     (u32)text,
                     (u32)chunked,
                     request_body.size(),
                     server->requests.load(),
                     response.size());
        if (!response.empty()) {
            std::fprintf(stderr,
                         "response prefix: %.*s\n",
                         static_cast<int>(std::min<size_t>(response.size(), 250)),
                         response.data());
            for (u8 b : response) std::fprintf(stderr, "%02x ", b);
            std::fprintf(stderr, "\n");
        }
    }
    CHECK(exchanged);
    if (exchanged) {
        static constexpr char kBoundary[] = "\r\n\r\n";
        const auto boundary = std::search(
            response.begin(), response.end(), kBoundary, kBoundary + sizeof(kBoundary) - 1);
        CHECK(boundary != response.end());
        if (boundary != response.end()) {
            const size_t body_offset = static_cast<size_t>(boundary - response.begin()) + 4;
            CHECK(response.size() >= body_offset);
            CHECK(std::search(response.begin(), boundary, "HTTP/1.1 200", "HTTP/1.1 200" + 12) !=
                  boundary);
            const auto headers_end = boundary;
            const std::string headers(response.begin(), headers_end);
            CHECK(headers.find(text ? "application/grpc-web-text" : "application/grpc-web") !=
                  std::string::npos);
            std::vector<u8> decoded;
            if (text) {
                decoded.resize(response.size() - body_offset);
                GrpcWebBase64Decoder decoder;
                decoder.init();
                u32 consumed = 0, written = 0;
                const auto status = decoder.feed(response.data() + body_offset,
                                                 static_cast<u32>(response.size() - body_offset),
                                                 consumed,
                                                 decoded.data(),
                                                 static_cast<u32>(decoded.size()),
                                                 written);
                CHECK_EQ(static_cast<u32>(status), static_cast<u32>(GrpcWebCodecStatus::Ok));
                CHECK_EQ(consumed, static_cast<u32>(response.size() - body_offset));
                CHECK_EQ(static_cast<u32>(decoder.finish()),
                         static_cast<u32>(GrpcWebCodecStatus::Ok));
                decoded.resize(written);
            } else {
                decoded.assign(response.begin() + body_offset, response.end());
            }
            CHECK(decoded.size() >= rpc_body.size() + 5);
            if (decoded.size() >= rpc_body.size() + 5) {
                CHECK(std::equal(rpc_body.begin(), rpc_body.end(), decoded.begin()));
                const size_t trailer_offset = rpc_body.size();
                CHECK_EQ(decoded[trailer_offset], 0x80u);
                const u32 trailer_len = (static_cast<u32>(decoded[trailer_offset + 1]) << 24) |
                                        (static_cast<u32>(decoded[trailer_offset + 2]) << 16) |
                                        (static_cast<u32>(decoded[trailer_offset + 3]) << 8) |
                                        static_cast<u32>(decoded[trailer_offset + 4]);
                CHECK_EQ(trailer_offset + 5 + trailer_len, decoded.size());
                const std::string trailers(decoded.begin() + trailer_offset + 5, decoded.end());
                CHECK(trailers.find("grpc-status: 0\r\n") != std::string::npos);
                CHECK(trailers.find("x-trailer: present\r\n") != std::string::npos);
            }
        }
    }

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    CHECK_EQ(server->requests.load(), 1u);
}

template <typename Loop>
void grpc_web_h1_tls_roundtrip_case(rut::test::TestCase* _tc, bool text) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<Loop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    auto tls_result = create_tls_server_context(
        RUT_GRPC_FIXTURES "/localhost_cert.pem", RUT_GRPC_FIXTURES "/localhost_key.pem", false);
    REQUIRE(tls_result);
    TlsServerContext* tls_server = tls_result.value();
    shard->loop->tls_server = tls_server;
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> rpc_body{0, 0, 0, 0, 1, 0x7f};
    const std::vector<u8> request_body = text ? grpc_web_test_base64(rpc_body) : rpc_body;
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), text, false, request_body, response, true));
    CHECK(std::search(response.begin(), response.end(), "HTTP/1.1 200", "HTTP/1.1 200" + 12) !=
          response.end());
    CHECK(std::search(response.begin(), response.end(), "grpc-web", "grpc-web" + 8) !=
          response.end());

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    destroy_tls_server_context(tls_server);
    CHECK_EQ(server->requests.load(), 1u);
}

}  // namespace

TEST(grpc_proxy, h1_content_type_override_fails_closed) {
    Connection conn;
    u8 storage[256]{};
    grpc_web_test_init_request(conn, storage, sizeof(storage));
    conn.req_header_override_count = 1;
    conn.req_header_overrides[0] = {{"cOnTeNt-TyPe", 12}, {"application/grpc", 16}};
    CHECK_EQ(static_cast<u32>(grpc_web_h1_start<EpollEventLoop>(nullptr, conn, nullptr, 0, true)),
             static_cast<u32>(GrpcWebH1Start::Rejected));
}

TEST(grpc_proxy, h1_http1_policy_fails_closed) {
    Connection conn;
    u8 storage[256]{};
    grpc_web_test_init_request(conn, storage, sizeof(storage));
    CHECK_EQ(static_cast<u32>(grpc_web_h1_start<EpollEventLoop>(nullptr, conn, nullptr, 0, false)),
             static_cast<u32>(GrpcWebH1Start::Rejected));
}

TEST(grpc_proxy, h1_transfer_encoding_chain_fails_closed) {
    Connection conn;
    u8 storage[256]{};
    static constexpr char kRequest[] =
        "POST /test.Echo/Call HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/grpc-web\r\n"
        "Transfer-Encoding: chunked, gzip\r\n\r\n"
        "0\r\n\r\n";
    grpc_web_test_init_raw_request(conn, storage, sizeof(storage), kRequest, sizeof(kRequest) - 1);
    CHECK_EQ(static_cast<u32>(grpc_web_h1_start<EpollEventLoop>(nullptr, conn, nullptr, 0, true)),
             static_cast<u32>(GrpcWebH1Start::Rejected));
}

TEST(grpc_proxy, h1_invalid_text_base64_returns_grpc_status) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log());
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> invalid{'A', 'B', '=', 'C'};
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, invalid, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK_EQ(decoded[4], 17u);
        CHECK(std::search(decoded.begin() + 5, decoded.end(), "grpc-status: 13",
                          "grpc-status: 13" + 15) != decoded.end());
    }
    CHECK_EQ(server->requests.load(), 0u);
    CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[13], 1u);
    AccessLogEntry entry{};
    u32 log_count = 0;
    while (shard->log_ring->pop(entry)) {
        log_count++;
        CHECK_EQ(entry.grpc_status_plus_one, 14u);
        CHECK_EQ(entry.status, 200u);
    }
    CHECK_EQ(log_count, 1u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}
TEST(grpc_proxy, h1_trailers_only_backend_response) {
    grpc_web_h1_trailers_only_case(_tc);
}
TEST(grpc_proxy, h1_decoded_request_message_limit) {
    grpc_web_h1_decoded_request_limit_case(_tc);
}
TEST(grpc_proxy, h1_deadline_returns_status) {
    grpc_web_h1_deadline_case(_tc);
}
TEST(grpc_proxy, h1_decoded_response_message_limit) {
    grpc_web_h1_decoded_response_limit_case(_tc);
}
TEST(grpc_proxy, h1_json_response_rejected) {
    grpc_web_h1_json_response_rejected_case(_tc, 7);
}
TEST(grpc_proxy, h1_duplicate_json_proto_response_rejected) {
    grpc_web_h1_json_response_rejected_case(_tc, 8);
}
TEST(grpc_proxy, h1_duplicate_proto_json_response_rejected) {
    grpc_web_h1_json_response_rejected_case(_tc, 9);
}
TEST(grpc_proxy, h1_client_abort_cancels_upstream_once) {
    grpc_web_h1_abort_case(_tc);
}

TEST(grpc_proxy, h1_path_and_safe_header_overrides_remain_supported) {
    Connection conn;
    u8 storage[256]{};
    grpc_web_test_init_request(conn, storage, sizeof(storage));
    static constexpr char kPath[] = "/rewritten";
    conn.req_path_overridden = true;
    conn.req_path_override = {kPath, sizeof(kPath) - 1};
    conn.req_header_override_count = 1;
    conn.req_header_overrides[0] = {{"X-Trace", 7}, {"kept", 4}};
    REQUIRE(h2_apply_forward_request_overrides(conn));
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    req.reset();
    REQUIRE(parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &req) == ParseStatus::Complete);
    CHECK(req.path.eq({kPath, sizeof(kPath) - 1}));
    bool found = false;
    for (u32 i = 0; i < req.header_count; i++)
        if (http_header_name_eq_ci(
                req.headers[i].name.ptr, req.headers[i].name.len, "x-trace", 7) &&
            req.headers[i].value.eq({"kept", 4}))
            found = true;
    CHECK(found);
}

TEST(grpc_proxy, h1_binary_coalesced_content_length_epoll) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, false, false, 1);
}
TEST(grpc_proxy, h1_text_chunked_large_response_epoll) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, true, true, 130000);
}
TEST(grpc_proxy, h1_text_coalesced_content_length_epoll) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, true, false, 17);
}
TEST(grpc_proxy, h1_binary_chunked_large_epoll) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, false, true, 130000);
}
TEST(grpc_proxy, h1_binary_coalesced_content_length_iouring) {
    grpc_web_h1_roundtrip_case<IoUringEventLoop>(_tc, false, false, 1);
}
TEST(grpc_proxy, h1_text_chunked_large_iouring) {
    grpc_web_h1_roundtrip_case<IoUringEventLoop>(_tc, true, true, 130000);
}
TEST(grpc_proxy, h1_binary_tls_epoll) {
    grpc_web_h1_tls_roundtrip_case<EpollEventLoop>(_tc, false);
}
TEST(grpc_proxy, h1_text_tls_epoll) {
    grpc_web_h1_tls_roundtrip_case<EpollEventLoop>(_tc, true);
}
TEST(grpc_proxy, h1_text_streaming_message_mod3_zero) {
    grpc_web_h1_streaming_text_message_case<EpollEventLoop>(_tc, 6, false);
}
TEST(grpc_proxy, h1_text_streaming_message_mod3_one) {
    grpc_web_h1_streaming_text_message_case<EpollEventLoop>(_tc, 7, false);
}
TEST(grpc_proxy, h1_text_streaming_message_mod3_two) {
    grpc_web_h1_streaming_text_message_case<EpollEventLoop>(_tc, 8, false);
}
TEST(grpc_proxy, h1_text_streaming_message_then_partial_next_same_data) {
    grpc_web_h1_streaming_text_message_case<EpollEventLoop>(_tc, 7, true);
}
