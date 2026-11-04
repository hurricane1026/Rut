#include "rut/runtime/password_gateway.h"
#include "test_helpers.h"
#ifdef __linux__
#include "rut/runtime/iouring_event_loop.h"
#endif
#include <memory>
#include <string>

namespace {
constexpr auto kRecord = lit_str(
    "$rut-pbkdf2-sha256$600000$000102030405060708090a0b0c0d0e0f$"
    "3bc37118e625093e9b79ed08930ea7af7389591233fdd92dddf369371e60dbc0");

u64 password_handler(void* connection, jit::HandlerCtx*, const u8* data, u32 length, void*) {
    ParsedRequest request{};
    HttpParser parser{};
    if (parser.parse(data, length, &request) != ParseStatus::Complete)
        return jit::HandlerResult::make_status(400).pack();
    // Test-only credential transport. Production callers choose and validate
    // their own extraction policy; this is not a shipped Basic/login helper.
    Str password{};
    u32 count = 0;
    for (u32 i = 0; i < request.header_count; ++i) {
        if (!request.headers[i].name.eq(lit_str("X-Password")) &&
            !request.headers[i].name.eq(lit_str("x-password")))
            continue;
        password = request.headers[i].value;
        ++count;
    }
    if (count != 1) return jit::HandlerResult::make_status(400).pack();
    const u32 timeout = request.path.eq(lit_str("/timeout")) ? 1 : 10000;
    const auto result = verify_password_for_request(connection, password, kRecord, timeout);
    if (request.path.eq(lit_str("/abandon"))) return jit::HandlerResult::make_status(204).pack();
    if (result.status == PasswordRequestStatus::Pending)
        return jit::HandlerResult::make_yield_payload(1, jit::YieldKind::Timer, result.retry_ms)
            .pack();
    const u16 status = result.status == PasswordRequestStatus::Matched    ? 200
                       : result.status == PasswordRequestStatus::Rejected ? 401
                       : result.status == PasswordRequestStatus::TimedOut ? 504
                                                                          : 503;
    return jit::HandlerResult::make_status(status).pack();
}

template <typename Loop>
struct PasswordServer {
    std::unique_ptr<Loop> loop = std::make_unique<Loop>();
    std::unique_ptr<RouteConfig> config = std::make_unique<RouteConfig>();
    const RouteConfig* current = config.get();
    PasswordGateway gateway;
    pthread_t thread{};
    bool started = false;
    bool initialized = false;
    i32 listener = -1;
    u16 port = 0;
    Error error{};
    bool setup() {
        auto fd = create_listen_socket(0);
        if (!fd) {
            error = fd.error();
            return false;
        }
        listener = fd.value();
        port = get_port(listener);
        auto init = [&] {
#ifdef __linux__
            if constexpr (requires { loop->init(0, listener, 0, 32); })
                return loop->init(0, listener, 0, 32);
#endif
            return loop->init(0, listener, 32);
        }();
        if (!init) {
            error = init.error();
            return false;
        }
        initialized = true;
        if (!config->add_jit_handler("/ok", static_cast<u8>(HttpMethod::GET), password_handler) ||
            !config->add_jit_handler(
                "/timeout", static_cast<u8>(HttpMethod::GET), password_handler) ||
            !config->add_jit_handler(
                "/abandon", static_cast<u8>(HttpMethod::GET), password_handler) ||
            !config->add_static("/plain", static_cast<u8>(HttpMethod::GET), 204))
            return false;
        auto gw = gateway.start();
        if (!gw) {
            error = gw.error();
            return false;
        }
        loop->password_gateway = &gateway;
        loop->config_ptr = &current;
        if (pthread_create(
                &thread,
                nullptr,
                [](void* opaque) -> void* {
                    static_cast<Loop*>(opaque)->run();
                    return nullptr;
                },
                loop.get()) != 0)
            return false;
        started = true;
        return true;
    }
    void finish() {
        if (started) {
            loop->stop();
            // Wake an otherwise idle backend without mutating its shard state.
            const i32 wake = connect_to(port);
            if (wake >= 0) close(wake);
            pthread_join(thread, nullptr);
            started = false;
        }
        if (initialized) {
            loop->force_close_all();
            loop->password_gateway = nullptr;
            loop->shutdown();
            initialized = false;
        }
        if (listener >= 0) {
            close(listener);
            listener = -1;
        }
    }
    ~PasswordServer() { finish(); }
};

template <typename Loop>
void exercise_password_server(rut::test::TestCase* _tc, PasswordServer<Loop>& server) {
    const auto exchange = [&](const char* path, const char* password, const char* expected) {
        const i32 fd = connect_to(server.port);
        CHECK(fd >= 0);
        if (fd < 0) return;
        const std::string request = std::string("GET ") + path +
                                    " HTTP/1.1\r\nHost: localhost\r\nX-Password: " + password +
                                    "\r\nConnection: close\r\n\r\n";
        CHECK(send_all(fd, request.data(), static_cast<u32>(request.size())));
        char response[1024]{};
        const i32 count = recv_timeout(fd, response, sizeof(response), 10000);
        CHECK(count > 0);
        if (count > 0) CHECK(buf_contains(response, static_cast<u32>(count), expected, 12));
        close(fd);
    };
    // A quiet loop must finish without another request or completion source.
    exchange("/ok", "password", "HTTP/1.1 200");
    exchange("/ok", "wrong", "HTTP/1.1 401");
    exchange("/timeout", "password", "HTTP/1.1 504");
    exchange("/abandon", "password", "HTTP/1.1 204");
    // Close while verification is pending, then reuse connection slots.
    const i32 closed = connect_to(server.port);
    REQUIRE(closed >= 0);
    constexpr char kClose[] =
        "GET /ok HTTP/1.1\r\nHost: localhost\r\nX-Password: password\r\nConnection: close\r\n\r\n";
    REQUIRE(send_all(closed, kClose, sizeof(kClose) - 1));
    close(closed);
    exchange("/plain", "", "HTTP/1.1 204");
    exchange("/ok", "wrong", "HTTP/1.1 401");
    server.finish();
    CHECK(server.gateway.active_requests() == 0);
}
}  // namespace

TEST(password_gateway, real_default_backend_http1) {
    PasswordServer<RealLoop> server;
    REQUIRE(server.setup());
    exercise_password_server(_tc, server);
}
#ifdef __linux__
TEST(password_gateway, real_iouring_http1) {
    PasswordServer<IoUringEventLoop> server;
    if (!server.setup()) {
        if (io_uring_init_error_is_unsupported(server.error,
                                               io_uring_init_failure_detail(*server.loop)))
            SKIP("io_uring unavailable");
        REQUIRE(false);
    }
    exercise_password_server(_tc, server);
}
#endif

TEST(password_gateway, native_binding_and_close_cleanup) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    PasswordGateway gateway;
    REQUIRE(gateway.start().has_value());
    loop->password_gateway = &gateway;
    auto* connection = loop->alloc_conn();
    REQUIRE(connection != nullptr);
    connection->fd = 42;
    connection->handler_gen = 1;
    connection->transition_to_exec_handler_wait();
    CHECK(verify_password_for_request(connection, lit_str("password"), kRecord, 1000).status ==
          PasswordRequestStatus::Unavailable);
    {
        PasswordHandlerScope scope(&gateway, connection);
        CHECK(verify_password_for_request(nullptr, lit_str("password"), kRecord, 1000).status ==
              PasswordRequestStatus::Unavailable);
        CHECK(verify_password_for_request(connection, lit_str("password"), kRecord, 1000).status ==
              PasswordRequestStatus::Pending);
        {
            PasswordHandlerScope nested(nullptr, connection);
            CHECK(verify_password_for_request(connection, lit_str("password"), kRecord, 1000)
                      .status == PasswordRequestStatus::Unavailable);
        }
        CHECK(verify_password_for_request(connection, lit_str("changed"), kRecord, 1).status ==
              PasswordRequestStatus::Pending);
        connection->state = ConnState::Idle;
        CHECK(verify_password_for_request(connection, lit_str("password"), kRecord, 1000).status ==
              PasswordRequestStatus::Unavailable);
        connection->transition_to_exec_handler_wait();
        connection->protocol = ConnProtocol::Http2;
        CHECK(verify_password_for_request(connection, lit_str("password"), kRecord, 1000).status ==
              PasswordRequestStatus::Unavailable);
        connection->protocol = ConnProtocol::Http11;
        CHECK(gateway.active_requests() == 1);
    }
    CHECK(verify_password_for_request(connection, lit_str("password"), kRecord, 1000).status ==
          PasswordRequestStatus::Unavailable);
    loop->close_conn(*connection);
    CHECK(gateway.active_requests() == 0);
    loop->password_gateway = nullptr;
}

TEST(password_gateway, timer_failure_cancels_before_response) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    PasswordGateway gateway;
    REQUIRE(gateway.start().has_value());
    loop->password_gateway = &gateway;
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 42;
    conn->handler_gen = 1;
    conn->transition_to_exec_handler_wait();
    conn->req_method = static_cast<u8>(LogHttpMethod::Get);
    auto* ctx = conn->reset_jit_ctx();
    constexpr char kRequest[] =
        "GET /ok HTTP/1.1\r\nHost: localhost\r\nX-Password: password\r\n\r\n";
    auto outcome = invoke_jit_handler(password_handler,
                                      conn,
                                      *ctx,
                                      reinterpret_cast<const u8*>(kRequest),
                                      sizeof(kRequest) - 1,
                                      nullptr,
                                      &gateway);
    REQUIRE(outcome.kind == JitDispatchOutcome::Kind::TimerYield);
    CHECK(gateway.active_requests() == 1);
    // Force the mock wheel's out-of-range scheduling failure. It must retire
    // the task before sending 500, without waiting for connection close.
    outcome.timer_ms = 64000;
    handle_jit_outcome(loop.get(), *conn, outcome, password_handler, true);
    CHECK(conn->resp_status == 500);
    CHECK(gateway.active_requests() == 0);
    loop->close_conn(*conn);
    loop->password_gateway = nullptr;
}

TEST(password_gateway, terminal_handler_abandons_pending_task) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    PasswordGateway gateway;
    REQUIRE(gateway.start().has_value());
    loop->password_gateway = &gateway;
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 42;
    conn->handler_gen = 1;
    conn->transition_to_exec_handler_wait();
    {
        PasswordHandlerScope scope(&gateway, conn);
        CHECK(verify_password_for_request(conn, lit_str("password"), kRecord, 1000).status ==
              PasswordRequestStatus::Pending);
    }
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::ReturnStatus;
    outcome.status_code = 204;
    handle_jit_outcome(loop.get(), *conn, outcome, password_handler, true);
    CHECK(gateway.active_requests() == 0);
    loop->close_conn(*conn);
    loop->password_gateway = nullptr;
}

TEST(password_gateway, generation_change_and_deadline_are_not_replaceable) {
    PasswordGateway gateway;
    REQUIRE(gateway.start().has_value());
    CHECK(gateway.verify(1, 0, lit_str("password"), kRecord, 10, 100).status ==
          PasswordRequestStatus::Unavailable);
    CHECK(gateway.verify(1, 1, lit_str("password"), kRecord, 10, 100).status ==
          PasswordRequestStatus::Pending);
    CHECK(gateway.verify(1, 1, lit_str("changed"), kRecord, 110, 60000).status ==
          PasswordRequestStatus::TimedOut);
    CHECK(gateway.active_requests() == 0);
    CHECK(gateway.verify(2, 1, lit_str("password"), kRecord, 10, 100).status ==
          PasswordRequestStatus::Pending);
    CHECK(gateway.verify(2, 2, lit_str("wrong"), kRecord, 20, 100).status ==
          PasswordRequestStatus::Pending);
    CHECK(gateway.active_requests() == 1);
    gateway.cancel(2);
    CHECK(gateway.active_requests() == 0);
}

namespace {
struct PasswordH2Client {
    i32 fd = -1;
    u8 input[16384]{};
    u32 used = 0;
    u16 statuses[32]{};
    hpack::DynamicTable dynamic{};
    PasswordH2Client() { dynamic.init(4096); }
    ~PasswordH2Client() {
        if (fd >= 0) close(fd);
    }
    static u32 request(u8* output, u32 capacity, u32 stream, Str path, Str password) {
        const hpack::Header headers[] = {{lit_str(":method"), lit_str("GET")},
                                         {lit_str(":scheme"), lit_str("http")},
                                         {lit_str(":path"), path},
                                         {lit_str(":authority"), lit_str("localhost")},
                                         {lit_str("x-password"), password}};
        return http2_write_headers(output, capacity, stream, headers, 5, true);
    }
    bool connect(u16 port) {
        fd = connect_to(port);
        if (fd < 0) return false;
        u8 prologue[256];
        memcpy(prologue, kClientPreface, kClientPrefaceLen);
        Http2Settings settings{};
        settings.set_defaults();
        const u32 count =
            kClientPrefaceLen + write_settings_frame(prologue + kClientPrefaceLen, settings);
        return send_all(fd, reinterpret_cast<const char*>(prologue), count);
    }
    bool send_request(u32 stream, Str path, Str password) {
        u8 out[1024];
        const u32 count = request(out, sizeof(out), stream, path, password);
        return count != 0 && send_all(fd, reinterpret_cast<const char*>(out), count);
    }
    bool receive_status(u32 stream, u16 status) {
        const i64 deadline = test_mono_ms() + 10000;
        for (;;) {
            Http2FrameHeader header{};
            if (parse_frame_header(input, used, &header) == ParseStatus::Complete &&
                header.length <= used - kFrameHeaderSize) {
                if (header.type == static_cast<u8>(Http2FrameType::Goaway)) return false;
                if (header.type == static_cast<u8>(Http2FrameType::Headers)) {
                    if (!(header.flags & http2_flag::kEndHeaders) || header.stream_id >= 32)
                        return false;
                    hpack::Header headers[32];
                    u8 decoded[4096];
                    u32 count = 0;
                    if (!hpack::decode_header_block(dynamic,
                                                    input + kFrameHeaderSize,
                                                    header.length,
                                                    decoded,
                                                    sizeof(decoded),
                                                    headers,
                                                    32,
                                                    &count))
                        return false;
                    for (u32 i = 0; i < count; ++i) {
                        if (!headers[i].name.eq(lit_str(":status"))) continue;
                        const auto value = headers[i].value;
                        if (value.len != 3) return false;
                        for (u32 j = 0; j < 3; ++j)
                            if (value.ptr[j] < '0' || value.ptr[j] > '9') return false;
                        statuses[header.stream_id] =
                            static_cast<u16>((value.ptr[0] - '0') * 100 +
                                             (value.ptr[1] - '0') * 10 + value.ptr[2] - '0');
                    }
                }
                const u32 consumed = kFrameHeaderSize + header.length;
                memmove(input, input + consumed, used - consumed);
                used -= consumed;
                if (statuses[stream] != 0) return statuses[stream] == status;
                continue;
            }
            if (used == sizeof(input) || test_mono_ms() >= deadline) return false;
            const i32 got = recv_timeout(fd,
                                         reinterpret_cast<char*>(input + used),
                                         sizeof(input) - used,
                                         static_cast<i32>(deadline - test_mono_ms()));
            if (got <= 0) return false;
            used += static_cast<u32>(got);
        }
    }
};

template <typename Loop>
void exercise_password_h2(rut::test::TestCase* _tc, PasswordServer<Loop>& server) {
    PasswordH2Client client;
    REQUIRE(client.connect(server.port));
    REQUIRE(client.send_request(1, lit_str("/ok"), lit_str("password")));
    CHECK(client.receive_status(1, 200));
    REQUIRE(client.send_request(3, lit_str("/ok"), lit_str("wrong")));
    CHECK(client.receive_status(3, 401));
    REQUIRE(client.send_request(5, lit_str("/timeout"), lit_str("password")));
    CHECK(client.receive_status(5, 504));
    REQUIRE(client.send_request(7, lit_str("/abandon"), lit_str("password")));
    CHECK(client.receive_status(7, 204));
    // A coalesced RST must retire stream 9 before stream 11 can start. A late
    // matching worker result must never authenticate stream 11's wrong input.
    u8 batch[2048];
    u32 count =
        PasswordH2Client::request(batch, sizeof(batch), 9, lit_str("/ok"), lit_str("password"));
    REQUIRE(count != 0);
    count += write_rst_stream(batch + count, 9, Http2Error::Cancel);
    const u32 second = PasswordH2Client::request(
        batch + count, sizeof(batch) - count, 11, lit_str("/ok"), lit_str("wrong"));
    REQUIRE(second != 0);
    count += second;
    REQUIRE(send_all(client.fd, reinterpret_cast<const char*>(batch), count));
    CHECK(client.receive_status(11, 401));
    CHECK(client.statuses[9] == 0);
    REQUIRE(client.send_request(13, lit_str("/ok"), lit_str("password")));
    close(client.fd);
    client.fd = -1;
    server.finish();
    CHECK(server.gateway.active_requests() == 0);
}
}  // namespace

TEST(password_gateway, real_default_backend_http2) {
    PasswordServer<RealLoop> server;
    REQUIRE(server.setup());
    exercise_password_h2(_tc, server);
}
#ifdef __linux__
TEST(password_gateway, real_iouring_http2) {
    PasswordServer<IoUringEventLoop> server;
    if (!server.setup()) {
        if (io_uring_init_error_is_unsupported(server.error,
                                               io_uring_init_failure_detail(*server.loop)))
            SKIP("io_uring unavailable");
        REQUIRE(false);
    }
    exercise_password_h2(_tc, server);
}
#endif

TEST(password_gateway, h2_stream_binding_busy_context_and_reset_isolation) {
    auto loop = std::make_unique<SmallLoop>();
    loop->setup();
    PasswordGateway gateway;
    REQUIRE(gateway.start().has_value());
    loop->password_gateway = &gateway;
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = 42;
    conn->protocol = ConnProtocol::Http2;
    auto h2 = std::make_unique<Http2Conn>();
    h2->init();
    h2->nstreams = 2;
    h2->streams[0] = {1, Http2StreamState::HalfClosedRemote, 65535, 65535, true};
    h2->streams[1] = {3, Http2StreamState::HalfClosedRemote, 65535, 65535, true};
    conn->h2 = h2.get();
    auto* ctx = conn->reset_jit_ctx();
    ctx->store_slot<u64>(0, 123456);
    CHECK(password_h2_generation(1) != 1u);
    {
        PasswordHandlerScope unbound(&gateway, conn);
        CHECK(verify_password_for_request(conn, lit_str("password"), kRecord, 1000).status ==
              PasswordRequestStatus::Unavailable);
    }
    {
        PasswordHandlerScope scope(&gateway, conn, 1);
        CHECK(verify_password_for_request(conn, lit_str("password"), kRecord, 1000).status ==
              PasswordRequestStatus::Pending);
        h2->async_stream = 1;
        {
            PasswordHandlerScope other(&gateway, conn, 3);
            CHECK(verify_password_for_request(conn, lit_str("wrong"), kRecord, 1000).status ==
                  PasswordRequestStatus::Unavailable);
        }
        CHECK(verify_password_for_request(conn, lit_str("changed"), kRecord, 1000).status ==
              PasswordRequestStatus::Pending);
    }
    u8 response[8192]{};
    H2Dispatch<SmallLoop> dispatch{loop.get(), conn, response, sizeof(response), 0, false};
    RouteEntry route{};
    route.fn = password_handler;
    // Refuse the competing stream before it can reset the shared handler frame.
    h2_invoke_emit(dispatch, 3, &route, nullptr, 0, nullptr, nullptr, 0, false, true);
    CHECK(ctx->load_slot<u64>(0) == 123456);
    CHECK(h2->async_stream == 1);
    CHECK(gateway.active_requests() == 1);
    h2_on_reset_dispatch_cb<SmallLoop>(&dispatch, *h2, 3, Http2Error::Cancel);
    CHECK(h2->async_stream == 1);
    CHECK(gateway.active_requests() == 1);
    h2_on_reset_dispatch_cb<SmallLoop>(&dispatch, *h2, 1, Http2Error::Cancel);
    CHECK(h2->async_stream == 0);
    CHECK(gateway.active_requests() == 0);
    conn->h2 = nullptr;
    loop->close_conn(*conn);
    loop->password_gateway = nullptr;
}
