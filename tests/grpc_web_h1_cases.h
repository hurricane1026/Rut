#pragma once

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <string>
#include <vector>

namespace {

inline void grpc_web_test_init_request(rut::Connection& conn, u8* storage, u32 cap) {
    static constexpr char kRequest[] =
        "POST /test.Echo/Call HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/grpc-web\r\n"
        "Content-Length: 0\r\n\r\n";
    conn.reset();
    conn.bind_request_receive_buffer(storage, cap);
    __builtin_memcpy(storage, kRequest, sizeof(kRequest) - 1);
    conn.recv_buf.commit(sizeof(kRequest) - 1);
    conn.req_header_end = sizeof(kRequest) - 1;
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

inline bool grpc_web_test_h1_exchange(
    u16 port, bool text, bool chunked, const std::vector<u8>& body, std::vector<u8>& response) {
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

    std::vector<u8> wire;
    const char* content_type = text ? "Application/Grpc-Web-Text" : "Application/Grpc-Web";
    char header[512];
    const int header_len =
        snprintf(header,
                 sizeof(header),
                 "POST /test.Echo/Call HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "Content-Type: %s\r\n"
                 "%s"
                 "Connection: close\r\n\r\n",
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
    const bool sent = write_all_fd(fd, wire.data(), static_cast<u32>(wire.size()));
    if (sent) {
        u8 buf[8192];
        for (;;) {
            const ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n == 0) break;
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) {
                std::fprintf(stderr, "H1 recv error=%d after=%zu\n", errno, response.size());
                close(fd);
                return false;
            }
            response.insert(response.end(), buf, buf + n);
            if (response.size() > 256 * 1024) {
                close(fd);
                return false;
            }
        }
    }
    close(fd);
    return sent;
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
