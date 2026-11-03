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
        if (!request.headers[i].name.eq(lit_str("X-Password"))) continue;
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
