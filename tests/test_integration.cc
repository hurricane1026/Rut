// Real-socket integration tests. Ported from libuv/libevent2 scenarios.
#include "epoll_tls_test_hooks.h"
#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#if RUT_ENABLE_JIT_TESTS
#include "rut/jit/codegen.h"
#include "rut/jit/jit_engine.h"
#endif
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/io_uring_backend.h"
#include "rut/runtime/shard.h"
#include "rut/runtime/tls.h"
#include "test.h"
#include "test_helpers.h"
#include <atomic>

#include <openssl/ssl.h>
#include <stdlib.h>

// Helper: Connection with local buffer storage (for tests that use raw backends).
static constexpr u32 kTestBufSize = 4096;

struct TestConn {
    Connection conn;
    u8 recv_storage[kTestBufSize];
    u8 send_storage[kTestBufSize];

    void init(u32 id, i32 fd) {
        conn.reset();
        conn.id = id;
        conn.fd = fd;
        conn.recv_slice = recv_storage;
        conn.send_slice = send_storage;
        conn.recv_buf.bind(recv_storage, kTestBufSize);
        conn.send_buf.bind(send_storage, kTestBufSize);
    }
};

namespace {

struct ScriptedTlsState {
    i32 accept_calls = 0;
    i32 read_calls = 0;
    i32 write_calls = 0;
    i32 last_error = SSL_ERROR_SSL;
    i32 accept_first_rc = -1;
    i32 accept_second_rc = -1;
    i32 accept_first_error = SSL_ERROR_SSL;
    i32 accept_second_error = SSL_ERROR_SSL;
    i32 read_first_rc = -1;
    i32 read_second_rc = -1;
    i32 read_first_error = SSL_ERROR_WANT_WRITE;
    i32 read_second_error = SSL_ERROR_NONE;
    i32 write_first_rc = -1;
    i32 write_second_rc = -1;
    i32 write_first_error = SSL_ERROR_WANT_READ;
    i32 write_second_error = SSL_ERROR_NONE;
};

ScriptedTlsState* g_scripted_tls = nullptr;

i32 scripted_ssl_accept(SSL* /*ssl*/) {
    if (!g_scripted_tls) return -1;
    g_scripted_tls->accept_calls++;
    if (g_scripted_tls->accept_calls == 1) {
        g_scripted_tls->last_error = g_scripted_tls->accept_first_error;
        return g_scripted_tls->accept_first_rc;
    }
    g_scripted_tls->last_error = g_scripted_tls->accept_second_error;
    return g_scripted_tls->accept_second_rc;
}

i32 scripted_ssl_read(SSL* /*ssl*/, void* buf, i32 len) {
    if (!g_scripted_tls) return -1;
    g_scripted_tls->read_calls++;
    i32 rc = g_scripted_tls->read_second_rc;
    i32 err = g_scripted_tls->read_second_error;
    if (g_scripted_tls->read_calls == 1) {
        rc = g_scripted_tls->read_first_rc;
        err = g_scripted_tls->read_first_error;
    }

    if (rc > 0 && len >= rc) {
        for (i32 i = 0; i < rc; i++) static_cast<char*>(buf)[i] = static_cast<char>('A' + i);
    }
    g_scripted_tls->last_error = err;
    return rc;
}

i32 scripted_ssl_write(SSL* /*ssl*/, const void* /*buf*/, i32 /*len*/) {
    if (!g_scripted_tls) return -1;
    g_scripted_tls->write_calls++;
    if (g_scripted_tls->write_calls == 1) {
        g_scripted_tls->last_error = g_scripted_tls->write_first_error;
        return g_scripted_tls->write_first_rc;
    }
    g_scripted_tls->last_error = g_scripted_tls->write_second_error;
    return g_scripted_tls->write_second_rc;
}

i32 scripted_ssl_get_error(SSL* /*ssl*/, i32 /*rc*/) {
    if (!g_scripted_tls) return SSL_ERROR_SSL;
    return g_scripted_tls->last_error;
}

struct ScopedTlsHooks {
    explicit ScopedTlsHooks(ScriptedTlsState& state) {
        g_scripted_tls = &state;
        hooks_ = {
            scripted_ssl_accept, scripted_ssl_read, scripted_ssl_write, scripted_ssl_get_error};
        set_epoll_tls_hooks_for_test(&hooks_);
    }

    ~ScopedTlsHooks() {
        reset_epoll_tls_hooks_for_test();
        g_scripted_tls = nullptr;
    }

    EpollTlsHooks hooks_{};
};

struct TlsRecvRetryCase {
    bool handshake_first = false;
    i32 first_error = SSL_ERROR_WANT_READ;
    u32 first_wakeup_events = EPOLLIN;
    i32 final_read_rc = 0;
    u32 expected_buf_len = 0;
};

struct TlsSendRetryCase {
    i32 first_error = SSL_ERROR_WANT_READ;
    u32 second_wakeup_events = EPOLLIN;
    u32 payload_len = 0;
};

static constexpr TlsRecvRetryCase kTlsRecvRetryCases[] = {
    {.handshake_first = false,
     .first_error = SSL_ERROR_WANT_WRITE,
     .first_wakeup_events = EPOLLOUT,
     .final_read_rc = 3,
     .expected_buf_len = 3},
    {.handshake_first = false,
     .first_error = SSL_ERROR_WANT_WRITE,
     .first_wakeup_events = EPOLLIN | EPOLLOUT,
     .final_read_rc = 2,
     .expected_buf_len = 2},
    {.handshake_first = false,
     .first_error = SSL_ERROR_WANT_READ,
     .first_wakeup_events = EPOLLIN,
     .final_read_rc = 2,
     .expected_buf_len = 2},
    {.handshake_first = false,
     .first_error = SSL_ERROR_WANT_READ,
     .first_wakeup_events = EPOLLIN | EPOLLOUT,
     .final_read_rc = 1,
     .expected_buf_len = 1},
    {.handshake_first = true,
     .first_error = SSL_ERROR_WANT_WRITE,
     .first_wakeup_events = EPOLLOUT,
     .final_read_rc = 2,
     .expected_buf_len = 2},
    {.handshake_first = true,
     .first_error = SSL_ERROR_WANT_WRITE,
     .first_wakeup_events = EPOLLIN | EPOLLOUT,
     .final_read_rc = 1,
     .expected_buf_len = 1},
    {.handshake_first = true,
     .first_error = SSL_ERROR_WANT_READ,
     .first_wakeup_events = EPOLLIN,
     .final_read_rc = 1,
     .expected_buf_len = 1},
    {.handshake_first = true,
     .first_error = SSL_ERROR_WANT_READ,
     .first_wakeup_events = EPOLLIN | EPOLLOUT,
     .final_read_rc = 3,
     .expected_buf_len = 3},
};

static constexpr TlsSendRetryCase kTlsSendRetryCases[] = {
    {.first_error = SSL_ERROR_WANT_READ, .second_wakeup_events = EPOLLIN, .payload_len = 4},
    {.first_error = SSL_ERROR_WANT_READ,
     .second_wakeup_events = EPOLLIN | EPOLLOUT,
     .payload_len = 4},
    {.first_error = SSL_ERROR_WANT_WRITE, .second_wakeup_events = EPOLLOUT, .payload_len = 4},
    {.first_error = SSL_ERROR_WANT_WRITE,
     .second_wakeup_events = EPOLLIN | EPOLLOUT,
     .payload_len = 4},
};

static void run_tls_recv_retry_case(rut::test::TestCase* test_case,
                                    const TlsRecvRetryCase& tc_cfg) {
    auto* _tc = test_case;
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;
    conn.tls_active = true;
    conn.tls_handshake_complete = !tc_cfg.handshake_first;
    conn.tls = reinterpret_cast<SSL*>(0x1);

    ScriptedTlsState tls_state;
    if (tc_cfg.handshake_first) {
        tls_state.accept_first_rc = -1;
        tls_state.accept_first_error = tc_cfg.first_error;
        tls_state.accept_second_rc = 1;
        tls_state.accept_second_error = SSL_ERROR_NONE;
        tls_state.read_first_rc = tc_cfg.final_read_rc;
        tls_state.read_first_error = SSL_ERROR_NONE;
    } else {
        tls_state.read_first_rc = -1;
        tls_state.read_first_error = tc_cfg.first_error;
        tls_state.read_second_rc = tc_cfg.final_read_rc;
        tls_state.read_second_error = SSL_ERROR_NONE;
    }
    ScopedTlsHooks hooks(tls_state);

    backend.add_recv(fds[0], 0);
    REQUIRE(send_all(fds[1], "x", 1));

    IoEvent events[8];
    u32 n = backend.wait(events, 8, &conn, 1);
    CHECK_EQ(n, 0u);

    struct epoll_event ev;
    ev.events = tc_cfg.first_wakeup_events;
    ev.data.u64 = static_cast<u64>(IoEventType::Recv);
    REQUIRE_EQ(epoll_ctl(backend.epoll_fd, EPOLL_CTL_MOD, fds[0], &ev), 0);
    if ((tc_cfg.first_wakeup_events & EPOLLIN) != 0) {
        REQUIRE(send_all(fds[1], "r", 1));
    }

    n = backend.wait(events, 8, &conn, 1);
    REQUIRE_EQ(n, 1u);
    CHECK_EQ(events[0].type, IoEventType::Recv);
    CHECK_EQ(events[0].result, tc_cfg.final_read_rc);
    CHECK_EQ(conn.recv_buf.len(), tc_cfg.expected_buf_len);
    CHECK(conn.tls_handshake_complete);
    if (tc_cfg.handshake_first) {
        CHECK_EQ(tls_state.accept_calls, 2);
        CHECK_EQ(tls_state.read_calls, 1);
    } else {
        CHECK_EQ(tls_state.read_calls, 2);
    }

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

static void run_tls_send_retry_case(rut::test::TestCase* test_case,
                                    const TlsSendRetryCase& tc_cfg) {
    auto* _tc = test_case;
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    backend.downstream_fd_map[0] = fds[0];

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;
    conn.tls_active = true;
    conn.tls_handshake_complete = true;
    conn.tls = reinterpret_cast<SSL*>(0x1);

    ScriptedTlsState tls_state;
    tls_state.write_first_rc = -1;
    tls_state.write_first_error = tc_cfg.first_error;
    tls_state.write_second_rc = static_cast<i32>(tc_cfg.payload_len);
    tls_state.write_second_error = SSL_ERROR_NONE;
    ScopedTlsHooks hooks(tls_state);

    static const u8 kPayload[] = {'p', 'i', 'n', 'g'};
    REQUIRE(tc_cfg.payload_len <= sizeof(kPayload));
    REQUIRE(backend.add_send_tls(conn, kPayload, tc_cfg.payload_len));
    CHECK_EQ(tls_state.write_calls, 1);
    CHECK_EQ(backend.send_state[0].remaining, tc_cfg.payload_len);
    CHECK(backend.send_state[0].tls);

    struct epoll_event ev;
    ev.events = tc_cfg.second_wakeup_events;
    ev.data.u64 = static_cast<u64>(IoEventType::Send);
    REQUIRE_EQ(epoll_ctl(backend.epoll_fd, EPOLL_CTL_MOD, fds[0], &ev), 0);
    if ((tc_cfg.second_wakeup_events & EPOLLIN) != 0) {
        REQUIRE(send_all(fds[1], "r", 1));
    }

    IoEvent events[8];
    u32 n = backend.wait(events, 8, &conn, 1);
    REQUIRE_EQ(n, 1u);
    CHECK_EQ(tls_state.write_calls, 2);
    CHECK_EQ(events[0].type, IoEventType::Send);
    CHECK_EQ(events[0].result, static_cast<i32>(tc_cfg.payload_len));
    CHECK_EQ(backend.send_state[0].remaining, 0u);

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

static void run_tls_send_readable_while_waiting_for_write_case(rut::test::TestCase* test_case) {
    auto* _tc = test_case;
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    backend.downstream_fd_map[0] = fds[0];

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;
    conn.tls_active = true;
    conn.tls_handshake_complete = true;
    conn.tls = reinterpret_cast<SSL*>(0x1);

    ScriptedTlsState tls_state;
    tls_state.write_first_rc = -1;
    tls_state.write_first_error = SSL_ERROR_WANT_WRITE;
    tls_state.write_second_rc = 4;
    tls_state.write_second_error = SSL_ERROR_NONE;
    tls_state.read_first_rc = 2;
    tls_state.read_first_error = SSL_ERROR_NONE;
    ScopedTlsHooks hooks(tls_state);

    static const u8 kPayload[] = {'p', 'i', 'n', 'g'};
    REQUIRE(backend.add_send_tls(conn, kPayload, sizeof(kPayload)));
    CHECK_EQ(tls_state.write_calls, 1);
    CHECK_EQ(backend.send_state[0].remaining, sizeof(kPayload));

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = static_cast<u64>(IoEventType::Send);
    REQUIRE_EQ(epoll_ctl(backend.epoll_fd, EPOLL_CTL_MOD, fds[0], &ev), 0);
    REQUIRE(send_all(fds[1], "r", 1));

    IoEvent events[8];
    u32 n = backend.wait(events, 8, &conn, 1);
    REQUIRE_EQ(n, 1u);
    CHECK_EQ(events[0].type, IoEventType::Recv);
    CHECK_EQ(events[0].result, 2);
    CHECK_EQ(conn.recv_buf.len(), 2u);
    CHECK_EQ(tls_state.write_calls, 1);
    CHECK_EQ(backend.send_state[0].remaining, sizeof(kPayload));

    ev.events = EPOLLOUT;
    ev.data.u64 = static_cast<u64>(IoEventType::Send);
    REQUIRE_EQ(epoll_ctl(backend.epoll_fd, EPOLL_CTL_MOD, fds[0], &ev), 0);

    n = backend.wait(events, 8, &conn, 1);
    REQUIRE_EQ(n, 1u);
    CHECK_EQ(events[0].type, IoEventType::Send);
    CHECK_EQ(events[0].result, 4);
    CHECK_EQ(tls_state.write_calls, 2);
    CHECK_EQ(backend.send_state[0].remaining, 0u);

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

}  // namespace

#ifndef RUT_TESTDATA_DIR
#error "RUT_TESTDATA_DIR must be defined for test_integration"
#endif

static constexpr char kTestCertPath[] = RUT_TESTDATA_DIR "/localhost_cert.pem";
static constexpr char kTestKeyPath[] = RUT_TESTDATA_DIR "/localhost_key.pem";

static bool ssl_write_all(SSL* ssl, const char* data, u32 len) {
    u32 sent = 0;
    while (sent < len) {
        i32 n = SSL_write(ssl, data + sent, static_cast<i32>(len - sent));
        if (n <= 0) return false;
        sent += static_cast<u32>(n);
    }
    return true;
}

static void set_socket_timeouts(i32 fd, i32 secs) {
    struct timeval tv;
    tv.tv_sec = secs;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static SSL_CTX* create_test_client_ctx() {
    SSL_CTX* client_ctx = SSL_CTX_new(TLS_client_method());
    if (client_ctx) SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr);
    return client_ctx;
}

// === Socket Setup (libuv: test-tcp-bind-error, test-tcp-flags, test-tcp-reuseport) ===

TEST(socket, nonblocking) {
    i32 fd = create_listen_socket(0).value_or(-1);
    REQUIRE(fd >= 0);
    CHECK(fcntl(fd, F_GETFL, 0) & O_NONBLOCK);
    close(fd);
}

TEST(socket, reuseport) {
    i32 fd = create_listen_socket(0).value_or(-1);
    REQUIRE(fd >= 0);
    i32 val = 0;
    socklen_t len = sizeof(val);
    getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, &len);
    CHECK_EQ(val, 1);
    close(fd);
}

TEST(socket, nodelay) {
    i32 fd = create_listen_socket(0).value_or(-1);
    REQUIRE(fd >= 0);
    i32 val = 0;
    socklen_t len = sizeof(val);
    getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, &len);
    CHECK_EQ(val, 1);
    close(fd);
}

TEST(socket, two_listeners_same_port) {
    i32 fd1 = create_listen_socket(0).value_or(-1);
    REQUIRE(fd1 >= 0);
    i32 fd2 = create_listen_socket(get_port(fd1)).value_or(-1);
    CHECK(fd2 >= 0);
    if (fd2 >= 0) close(fd2);
    close(fd1);
}

TEST(socket, connect_refused) {
    i32 fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    REQUIRE(fd >= 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = __builtin_bswap16(19999);
    a.sin_addr.s_addr = __builtin_bswap32(0x7F000001);
    i32 rc = connect(fd, reinterpret_cast<struct sockaddr*>(&a), sizeof(a));
    CHECK(rc < 0);
    CHECK(errno == EINPROGRESS || errno == ECONNREFUSED);
    close(fd);
}

TEST(socket, double_bind_error) {
    i32 fd = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = __builtin_bswap32(0x7F000001);
    CHECK_EQ(bind(fd, reinterpret_cast<struct sockaddr*>(&a), sizeof(a)), 0);
    a.sin_port = __builtin_bswap16(18888);
    CHECK(bind(fd, reinterpret_cast<struct sockaddr*>(&a), sizeof(a)) < 0);
    close(fd);
}

TEST(socket, double_listen_ok) {
    i32 fd = create_listen_socket(0).value_or(-1);
    REQUIRE(fd >= 0);
    CHECK_EQ(listen(fd, 4096), 0);
    close(fd);
}

// === Basic I/O (libuv: test-tcp-connect, libevent: test_simpleread/write) ===

TEST(io, simple_request_response) {
    TestServer srv;
    REQUIRE(srv.setup(10));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    REQUIRE(send_all(c, HTTP_REQ, HTTP_REQ_LEN));
    char buf[4096];
    i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
    CHECK(n > 0);
    CHECK(has_200(buf, n));
    close(c);
    srv.teardown();
}

TEST(io, keepalive_3_requests) {
    TestServer srv;
    REQUIRE(srv.setup(30));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    for (int i = 0; i < 3; i++) {
        REQUIRE(send_all(c, HTTP_REQ, HTTP_REQ_LEN));
        char buf[4096];
        i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
        CHECK(n > 0);
    }
    close(c);
    srv.teardown();
}

TEST(io, large_request_2kb) {
    TestServer srv;
    REQUIRE(srv.setup(20));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    char big[2048];
    memset(big, 'A', sizeof(big));
    memcpy(big, HTTP_REQ, HTTP_REQ_LEN);
    REQUIRE(send_all(c, big, sizeof(big)));
    char buf[4096];
    CHECK(recv_timeout(c, buf, sizeof(buf), 2000) > 0);
    close(c);
    srv.teardown();
}

TEST(io, zero_length_send) {
    TestServer srv;
    REQUIRE(srv.setup(10));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    send(c, "", 0, MSG_NOSIGNAL);
    REQUIRE(send_all(c, HTTP_REQ, HTTP_REQ_LEN));
    char buf[4096];
    CHECK(recv_timeout(c, buf, sizeof(buf), 2000) > 0);
    close(c);
    srv.teardown();
}

TEST(io, pipelining_3_requests) {
    TestServer srv;
    REQUIRE(srv.setup(30));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    for (int i = 0; i < 3; i++) REQUIRE(send_all(c, HTTP_REQ, HTTP_REQ_LEN));
    int responses = 0;
    for (int i = 0; i < 3; i++) {
        char buf[4096];
        if (recv_timeout(c, buf, sizeof(buf), 2000) > 0) responses++;
    }
    CHECK_GE(responses, 1);
    close(c);
    srv.teardown();
}

TEST(io, client_half_close) {
    TestServer srv;
    REQUIRE(srv.setup(20));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    REQUIRE(send_all(c, HTTP_REQ, HTTP_REQ_LEN));
    shutdown(c, SHUT_WR);
    char buf[4096];
    CHECK(recv_timeout(c, buf, sizeof(buf), 2000) > 0);
    close(c);
    srv.teardown();
}

// === Concurrency (libevent: test_multiple, test-many-connections) ===

TEST(concurrent, five_clients) {
    TestServer srv;
    REQUIRE(srv.setup(50));
    i32 clients[5];
    for (int i = 0; i < 5; i++) {
        clients[i] = connect_to(srv.port);
        REQUIRE(clients[i] >= 0);
    }
    for (int i = 0; i < 5; i++) REQUIRE(send_all(clients[i], HTTP_REQ, HTTP_REQ_LEN));
    for (int i = 0; i < 5; i++) {
        char buf[4096];
        CHECK(recv_timeout(clients[i], buf, sizeof(buf), 2000) > 0);
    }
    for (int i = 0; i < 5; i++) close(clients[i]);
    srv.teardown();
}

TEST(concurrent, ten_clients_multi_req) {
    TestServer srv;
    REQUIRE(srv.setup(200));
    i32 clients[10];
    for (int i = 0; i < 10; i++) {
        clients[i] = connect_to(srv.port);
        REQUIRE(clients[i] >= 0);
    }
    for (int round = 0; round < 3; round++) {
        for (int i = 0; i < 10; i++) REQUIRE(send_all(clients[i], HTTP_REQ, HTTP_REQ_LEN));
        for (int i = 0; i < 10; i++) {
            char buf[4096];
            CHECK(recv_timeout(clients[i], buf, sizeof(buf), 2000) > 0);
        }
    }
    for (int i = 0; i < 10; i++) close(clients[i]);
    srv.teardown();
}

TEST(concurrent, rapid_connect_disconnect_50) {
    TestServer srv;
    REQUIRE(srv.setup(500));
    for (int i = 0; i < 50; i++) {
        i32 c = connect_to(srv.port);
        if (c >= 0) close(c);
    }
    usleep(200000);
    srv.teardown();
}

TEST(concurrent, interleaved_io) {
    TestServer srv;
    REQUIRE(srv.setup(50));
    i32 c1 = connect_to(srv.port);
    i32 c2 = connect_to(srv.port);
    REQUIRE(c1 >= 0);
    REQUIRE(c2 >= 0);
    REQUIRE(send_all(c1, HTTP_REQ, HTTP_REQ_LEN));
    REQUIRE(send_all(c2, HTTP_REQ, HTTP_REQ_LEN));
    char buf[4096];
    CHECK(recv_timeout(c1, buf, sizeof(buf), 2000) > 0);
    CHECK(recv_timeout(c2, buf, sizeof(buf), 2000) > 0);
    close(c1);
    close(c2);
    srv.teardown();
}

// === Error Handling (libuv: test-tcp-close, test-tcp-write-fail) ===

TEST(error, client_eof) {
    TestServer srv;
    REQUIRE(srv.setup(20));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    close(c);
    usleep(100000);
    srv.teardown();
}

TEST(error, client_rst) {
    TestServer srv;
    REQUIRE(srv.setup(20));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    send_all(c, "GET", 3);
    struct linger lg = {1, 0};
    setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    close(c);
    usleep(100000);
    srv.teardown();
}

TEST(error, send_no_read_close) {
    TestServer srv;
    REQUIRE(srv.setup(20));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    send_all(c, HTTP_REQ, HTTP_REQ_LEN);
    close(c);
    usleep(100000);
    i32 c2 = connect_to(srv.port);
    REQUIRE(c2 >= 0);
    send_all(c2, HTTP_REQ, HTTP_REQ_LEN);
    char buf[4096];
    CHECK(recv_timeout(c2, buf, sizeof(buf), 2000) > 0);
    close(c2);
    srv.teardown();
}

TEST(error, server_shutdown_with_clients) {
    TestServer srv;
    REQUIRE(srv.setup(10));
    i32 clients[3];
    for (int i = 0; i < 3; i++) {
        clients[i] = connect_to(srv.port);
        REQUIRE(clients[i] >= 0);
    }
    srv.teardown();
    for (int i = 0; i < 3; i++) {
        char buf[64];
        recv_timeout(clients[i], buf, sizeof(buf), 500);
        close(clients[i]);
    }
}

TEST(error, double_close_no_crash) {
    i32 fd = create_listen_socket(0).value_or(-1);
    REQUIRE(fd >= 0);
    close(fd);
    CHECK(close(fd) < 0);
}

TEST(error, fd_recycle_no_stale) {
    TestServer srv;
    REQUIRE(srv.setup(30));
    i32 c1 = connect_to(srv.port);
    REQUIRE(c1 >= 0);
    send_all(c1, HTTP_REQ, HTTP_REQ_LEN);
    char buf[4096];
    recv_timeout(c1, buf, sizeof(buf), 1000);
    close(c1);
    usleep(50000);
    i32 c2 = connect_to(srv.port);
    REQUIRE(c2 >= 0);
    send_all(c2, HTTP_REQ, HTTP_REQ_LEN);
    CHECK(recv_timeout(c2, buf, sizeof(buf), 2000) > 0);
    close(c2);
    srv.teardown();
}

TEST(error, fd_leak_100_cycles) {
    TestServer srv;
    REQUIRE(srv.setup(2000));
    for (int i = 0; i < 100; i++) {
        i32 c = connect_to(srv.port);
        if (c < 0) continue;
        send_all(c, HTTP_REQ, HTTP_REQ_LEN);
        char buf[4096];
        recv_timeout(c, buf, sizeof(buf), 500);
        close(c);
    }
    srv.teardown();
}

// === Loop Control (libevent: test_loopexit) ===

TEST(loop, stop_from_outside) {
    TestServer srv;
    REQUIRE(srv.setup(1000));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    send_all(c, HTTP_REQ, HTTP_REQ_LEN);
    char buf[4096];
    recv_timeout(c, buf, sizeof(buf), 1000);
    srv.loop->stop();
    close(c);
    srv.teardown();
}

// === Partial send (real socket) ===

// Verify EpollBackend::send_state is initialized to zero.
// After init, no connection should have outstanding send state.
TEST(partial_send, state_initialized) {
    auto* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    i32 fd = create_listen_socket(0).value_or(-1);
    REQUIRE(fd >= 0);
    REQUIRE(loop->init(0, fd).has_value());
    // EpollBackend send_state should be zero-initialized
    for (u32 i = 0; i < EpollBackend::kMaxFdMap; i++) {
        CHECK_EQ(loop->backend.send_state[i].remaining, 0u);
    }
    loop->shutdown();
    close(fd);
    destroy_real_loop(loop);
}

// Real partial send test: fill socket buffer to force EAGAIN, then drain.
// Uses socketpair to control both ends.
// Force actual partial send via backpressure: fill the socket send buffer
// by not reading on the peer side, then drain and verify completion.
TEST(partial_send, real_epollout_completion) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    // Set minimal send buffer to force partial sends / EAGAIN quickly.
    // Linux doubles the value, so minimum effective is ~2*sndbuf.
    i32 sndbuf = 2048;
    REQUIRE_EQ(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)), 0);
    // Also limit recv buffer on peer to create backpressure faster
    i32 rcvbuf = 2048;
    REQUIRE_EQ(setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)), 0);

    // Use init() so timerfd is created — gives wait() a bounded 1-second wakeup
    // to prevent indefinite hangs if EPOLLOUT doesn't fire immediately.
    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    backend.downstream_fd_map[0] = fds[0];

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;

    // Fill send_buf with 4096 bytes (larger than the tiny socket buffer)
    u8 fill_data[4096];
    for (u32 j = 0; j < sizeof(fill_data); j++) fill_data[j] = static_cast<u8>(j & 0xFF);
    conn.send_buf.write(fill_data, sizeof(fill_data));

    // add_send tries immediate send — may be partial or EAGAIN
    backend.add_send(fds[0], 0, conn.send_buf.data(), conn.send_buf.len());

    // Check for immediate completion via synthetic pending events (non-blocking).
    // If add_send succeeded fully, pending_count > 0 with the completion.
    IoEvent events[16];
    bool got_full_send = false;
    if (backend.pending_count > 0) {
        u32 n = backend.wait(events, 16, &conn, 1);
        for (u32 i = 0; i < n; i++) {
            if (events[i].type == IoEventType::Send && events[i].result == 4096) {
                got_full_send = true;
            }
        }
    }

    if (!got_full_send) {
        // Partial send or EAGAIN path — drain peer to make socket writable,
        // then wait for EPOLLOUT completion. Drain fully before wait() to
        // ensure EPOLLOUT is ready (wait uses blocking epoll_wait).
        char drain[8192];
        for (int attempt = 0; attempt < 20; attempt++) {
            // Drain all available data from peer
            for (;;) {
                ssize_t nr = recv(fds[1], drain, sizeof(drain), MSG_DONTWAIT);
                if (nr <= 0) break;
            }
            usleep(1000);  // 1ms — let kernel update socket writability

            u32 n = backend.wait(events, 16, &conn, 1);
            for (u32 i = 0; i < n; i++) {
                if (events[i].type == IoEventType::Send) {
                    CHECK_EQ(events[i].result, 4096);
                    got_full_send = true;
                }
            }
            if (got_full_send) break;
        }
    }
    CHECK(got_full_send);

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

// === Partial send: real socket edge cases ===

// Verify EpollBackend correctly handles immediate full send on socketpair
TEST(partial_send, socketpair_full_send) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    backend.downstream_fd_map[0] = fds[0];

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;

    // Small payload — immediate full send
    conn.send_buf.write(reinterpret_cast<const u8*>("OK"), 2);
    backend.add_send(fds[0], 0, conn.send_buf.data(), conn.send_buf.len());

    IoEvent events[8];
    u32 n = backend.wait(events, 8, &conn, 1);
    bool found = false;
    for (u32 i = 0; i < n; i++) {
        if (events[i].type == IoEventType::Send) {
            CHECK_EQ(events[i].result, 2);
            found = true;
        }
    }
    CHECK(found);

    // Verify receiver got the data
    char buf[8];
    ssize_t nr = recv(fds[1], buf, sizeof(buf), 0);
    CHECK_EQ(nr, 2);
    CHECK_EQ(buf[0], 'O');
    CHECK_EQ(buf[1], 'K');

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

// Verify add_send error path: send to closed peer
TEST(partial_send, send_to_closed_peer) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    // Close receiver immediately
    close(fds[1]);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;
    conn.send_buf.write(reinterpret_cast<const u8*>("data"), 4);

    // send to closed peer — may succeed (kernel buffers) or fail with EPIPE/ECONNRESET
    backend.add_send(fds[0], 0, conn.send_buf.data(), conn.send_buf.len());

    IoEvent events[8];
    u32 n = backend.wait(events, 8, &conn, 1);
    // Should get a completion (either success or error)
    bool found = false;
    for (u32 i = 0; i < n; i++) {
        if (events[i].type == IoEventType::Send) {
            found = true;
            // result is either positive (buffered) or negative (-errno)
        }
    }
    CHECK(found);

    close(fds[0]);
    backend.shutdown();
}

// Verify send_state is zeroed per connection after init
TEST(partial_send, state_zeroed_per_conn) {
    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    // Spot check several entries
    CHECK_EQ(backend.send_state[0].offset, 0u);
    CHECK_EQ(backend.send_state[0].remaining, 0u);
    CHECK_EQ(backend.send_state[100].remaining, 0u);
    CHECK_EQ(backend.send_state[EpollBackend::kMaxFdMap - 1].remaining, 0u);
    backend.shutdown();
}

// Verify EPOLLOUT with no pending send switches back to EPOLLIN (no busy loop).
// After a successful immediate send, send_state.remaining == 0.
// If a spurious EPOLLOUT fires with no pending send, wait() should drop
// EPOLLOUT, avoid a spin, and continue delivering Recv events.
TEST(partial_send, epollout_no_pending_switches_to_epollin) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    backend.downstream_fd_map[0] = fds[0];

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;

    // Do a small immediate send — completes fully, send_state.remaining stays 0
    conn.send_buf.write(reinterpret_cast<const u8*>("hi"), 2);
    backend.add_send(fds[0], 0, conn.send_buf.data(), conn.send_buf.len());

    // Drain the synthetic completion
    IoEvent events[8];
    if (backend.pending_count > 0) {
        backend.wait(events, 8, &conn, 1);
    }

    // send_state should have remaining == 0 after full immediate send
    CHECK_EQ(backend.send_state[0].remaining, 0u);

    // Ensure fd is registered with epoll (add_recv registers for EPOLLIN),
    // then switch to EPOLLOUT to simulate a spurious wakeup.
    backend.add_recv(fds[0], 0);
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.u64 = (static_cast<u64>(0) << 8) | static_cast<u64>(IoEventType::Send);
    REQUIRE_EQ(epoll_ctl(backend.epoll_fd, EPOLL_CTL_MOD, fds[0], &ev), 0);

    // wait() should see EPOLLOUT with no pending send and not emit a Send event.
    u32 n = backend.wait(events, 8, &conn, 1);
    bool got_send = false;
    for (u32 i = 0; i < n; i++) {
        if (events[i].type == IoEventType::Send) got_send = true;
    }
    CHECK(!got_send);

    REQUIRE(send_all(fds[1], "x", 1));
    n = backend.wait(events, 8, &conn, 1);
    REQUIRE_EQ(n, 1u);
    CHECK_EQ(events[0].type, IoEventType::Recv);
    CHECK_EQ(events[0].result, 1);

    // Drain peer
    char buf[8];
    (void)recv(fds[1], buf, sizeof(buf), MSG_DONTWAIT);

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

TEST(partial_send, non_tls_send_completes_with_smaller_conn_table) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    i32 sndbuf = 2048;
    REQUIRE_EQ(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)), 0);
    i32 rcvbuf = 2048;
    REQUIRE_EQ(setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    static constexpr u32 kConnId = 7;
    backend.downstream_fd_map[kConnId] = fds[0];

    TestConn tc;
    tc.init(kConnId, fds[0]);
    Connection& conn = tc.conn;

    u8 fill_data[4096];
    for (u32 j = 0; j < sizeof(fill_data); j++) fill_data[j] = static_cast<u8>(j & 0xFF);
    conn.send_buf.write(fill_data, sizeof(fill_data));

    backend.add_send(fds[0], kConnId, conn.send_buf.data(), conn.send_buf.len());

    IoEvent events[16];
    bool got_full_send = false;
    if (backend.pending_count > 0) {
        u32 n = backend.wait(events, 16, &conn, 1);
        for (u32 i = 0; i < n; i++) {
            if (events[i].type == IoEventType::Send && events[i].conn_id == kConnId &&
                events[i].result == 4096) {
                got_full_send = true;
            }
        }
    }

    if (!got_full_send) {
        char drain[8192];
        for (int attempt = 0; attempt < 20; attempt++) {
            for (;;) {
                ssize_t nr = recv(fds[1], drain, sizeof(drain), MSG_DONTWAIT);
                if (nr <= 0) break;
            }
            usleep(1000);

            u32 n = backend.wait(events, 16, &conn, 1);
            for (u32 i = 0; i < n; i++) {
                if (events[i].type == IoEventType::Send && events[i].conn_id == kConnId &&
                    events[i].result == 4096) {
                    got_full_send = true;
                }
            }
            if (got_full_send) break;
        }
    }
    CHECK(got_full_send);

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

TEST(tls_state_machine, recv_retry_matrix) {
    for (const auto& tc : kTlsRecvRetryCases) {
        run_tls_recv_retry_case(_tc, tc);
    }
}

TEST(tls_state_machine, send_retry_matrix) {
    for (const auto& tc : kTlsSendRetryCases) {
        run_tls_send_retry_case(_tc, tc);
    }
}

TEST(tls_state_machine, send_want_write_readable_wakeup_buffers_recv) {
    run_tls_send_readable_while_waiting_for_write_case(_tc);
}

TEST(tls_state_machine, send_rejects_out_of_range_conn_id) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());

    TestConn tc;
    tc.init(EpollBackend::kMaxFdMap, fds[0]);
    Connection& conn = tc.conn;
    conn.tls_active = true;
    conn.tls_handshake_complete = true;
    conn.tls = reinterpret_cast<SSL*>(0x1);

    ScriptedTlsState tls_state;
    tls_state.write_first_rc = -1;
    tls_state.write_first_error = SSL_ERROR_WANT_WRITE;
    ScopedTlsHooks hooks(tls_state);

    static const u8 kPayload[] = {'b', 'a', 'd'};
    REQUIRE(backend.add_send_tls(conn, kPayload, sizeof(kPayload)));
    CHECK_EQ(tls_state.write_calls, 1);
    REQUIRE_EQ(backend.pending_count, 1u);

    IoEvent events[8];
    u32 n = backend.wait(events, 8, &conn, 1);
    REQUIRE_EQ(n, 1u);
    CHECK_EQ(events[0].conn_id, EpollBackend::kMaxFdMap);
    CHECK_EQ(events[0].type, IoEventType::Send);
    CHECK_EQ(events[0].result, -EINVAL);

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

TEST(tls_state_machine, send_arm_failure_returns_error_completion) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;
    conn.tls_active = true;
    conn.tls_handshake_complete = true;
    conn.tls = reinterpret_cast<SSL*>(0x1);

    ScriptedTlsState tls_state;
    tls_state.write_first_rc = -1;
    tls_state.write_first_error = SSL_ERROR_WANT_WRITE;
    ScopedTlsHooks hooks(tls_state);

    close(fds[0]);
    conn.fd = fds[0];

    static const u8 kPayload[] = {'f', 'a', 'i', 'l'};
    REQUIRE(backend.add_send_tls(conn, kPayload, sizeof(kPayload)));
    CHECK_EQ(tls_state.write_calls, 1);
    CHECK_EQ(backend.send_state[0].remaining, 0u);
    CHECK_EQ(backend.send_state[0].fd, -1);
    REQUIRE_EQ(backend.pending_count, 1u);

    IoEvent events[8];
    u32 n = backend.wait(events, 8, &conn, 1);
    REQUIRE_EQ(n, 1u);
    CHECK_EQ(events[0].conn_id, 0u);
    CHECK_EQ(events[0].type, IoEventType::Send);
    CHECK_EQ(events[0].result, -EBADF);

    close(fds[1]);
    backend.shutdown();
}

TEST(tls_state_machine, send_rejects_out_of_range_conn_id_with_full_pending_ring) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());

    for (u32 i = 0; i < 64; i++) {
        backend.pending_completions[i].conn_id = i;
        backend.pending_completions[i].type = IoEventType::Recv;
        backend.pending_completions[i].result = static_cast<i32>(i);
        backend.pending_completions[i].buf_id = 0;
        backend.pending_completions[i].has_buf = 0;
        backend.pending_completions[i].more = 0;
    }
    backend.pending_count = 64;

    TestConn tc;
    tc.init(EpollBackend::kMaxFdMap, fds[0]);
    Connection& conn = tc.conn;
    conn.tls_active = true;
    conn.tls_handshake_complete = true;
    conn.tls = reinterpret_cast<SSL*>(0x1);

    ScriptedTlsState tls_state;
    tls_state.write_first_rc = -1;
    tls_state.write_first_error = SSL_ERROR_WANT_WRITE;
    ScopedTlsHooks hooks(tls_state);

    static const u8 kPayload[] = {'f', 'u', 'l', 'l'};
    REQUIRE(backend.add_send_tls(conn, kPayload, sizeof(kPayload)));
    CHECK_EQ(tls_state.write_calls, 1);
    REQUIRE_EQ(backend.pending_count, 64u);
    CHECK_EQ(backend.pending_completions[63].conn_id, EpollBackend::kMaxFdMap);
    CHECK_EQ(backend.pending_completions[63].type, IoEventType::Send);
    CHECK_EQ(backend.pending_completions[63].result, -EINVAL);

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

TEST(tls_state_machine, send_arm_failure_returns_error_with_full_pending_ring) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());

    for (u32 i = 0; i < 64; i++) {
        backend.pending_completions[i].conn_id = i;
        backend.pending_completions[i].type = IoEventType::Recv;
        backend.pending_completions[i].result = static_cast<i32>(i);
        backend.pending_completions[i].buf_id = 0;
        backend.pending_completions[i].has_buf = 0;
        backend.pending_completions[i].more = 0;
    }
    backend.pending_count = 64;

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;
    conn.tls_active = true;
    conn.tls_handshake_complete = true;
    conn.tls = reinterpret_cast<SSL*>(0x1);

    ScriptedTlsState tls_state;
    tls_state.write_first_rc = -1;
    tls_state.write_first_error = SSL_ERROR_WANT_WRITE;
    ScopedTlsHooks hooks(tls_state);

    close(fds[0]);
    conn.fd = fds[0];

    static const u8 kPayload[] = {'f', 'a', 'i', 'l'};
    REQUIRE(backend.add_send_tls(conn, kPayload, sizeof(kPayload)));
    CHECK_EQ(tls_state.write_calls, 1);
    CHECK_EQ(backend.send_state[0].remaining, 0u);
    CHECK_EQ(backend.send_state[0].fd, -1);
    REQUIRE_EQ(backend.pending_count, 64u);
    CHECK_EQ(backend.pending_completions[63].conn_id, 0u);
    CHECK_EQ(backend.pending_completions[63].type, IoEventType::Send);
    CHECK_EQ(backend.pending_completions[63].result, -EBADF);

    close(fds[1]);
    backend.shutdown();
}

TEST(tls_state_machine, spurious_epollout_with_empty_tls_send_state_is_ignored) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    EpollBackend backend;
    REQUIRE(backend.init(0, -1).has_value());
    backend.downstream_fd_map[0] = fds[0];

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;
    conn.tls_active = true;
    conn.tls_handshake_complete = true;
    conn.tls = reinterpret_cast<SSL*>(0x1);

    ScriptedTlsState tls_state;
    tls_state.write_first_rc = 4;
    tls_state.write_first_error = SSL_ERROR_NONE;
    ScopedTlsHooks hooks(tls_state);

    static const u8 kPayload[] = {'p', 'o', 'n', 'g'};
    REQUIRE(backend.add_send_tls(conn, kPayload, sizeof(kPayload)));
    CHECK_EQ(tls_state.write_calls, 1);
    CHECK_EQ(backend.send_state[0].remaining, 0u);

    IoEvent events[8];
    if (backend.pending_count > 0) {
        u32 n = backend.wait(events, 8, &conn, 1);
        REQUIRE_EQ(n, 1u);
        CHECK_EQ(events[0].type, IoEventType::Send);
        CHECK_EQ(events[0].result, 4);
    }

    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.u64 = static_cast<u64>(IoEventType::Send);
    i32 rc = epoll_ctl(backend.epoll_fd, EPOLL_CTL_MOD, fds[0], &ev);
    if (rc < 0 && errno == ENOENT) {
        rc = epoll_ctl(backend.epoll_fd, EPOLL_CTL_ADD, fds[0], &ev);
    }
    REQUIRE_EQ(rc, 0);

    u32 n = backend.wait(events, 8, &conn, 1);
    bool got_send = false;
    for (u32 i = 0; i < n; i++) {
        if (events[i].type == IoEventType::Send) got_send = true;
    }
    CHECK(!got_send);
    CHECK_EQ(tls_state.write_calls, 1);
    CHECK_EQ(backend.send_state[0].remaining, 0u);

    tls_state.read_first_rc = 1;
    tls_state.read_first_error = SSL_ERROR_NONE;
    REQUIRE(send_all(fds[1], "r", 1));

    n = backend.wait(events, 8, &conn, 1);
    REQUIRE_EQ(n, 1u);
    CHECK_EQ(events[0].type, IoEventType::Recv);
    CHECK_EQ(events[0].result, 1);

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

// === io_uring backend smoke coverage ===

// Verify IoUringBackend::init creates a timerfd
TEST(uring, init_creates_timerfd) {
    // io_uring requires Linux 6.0+. If init fails, skip gracefully.
    IoUringBackend backend;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    auto rc = backend.init(0, lfd);
    if (!rc) {
        // io_uring not available — skip
        close(lfd);
        CHECK(true);
        return;
    }
    CHECK(backend.timer_fd >= 0);
    backend.shutdown();
    close(lfd);
}

// Verify return_buffer doesn't crash (ring structure test)
TEST(uring, return_buffer_no_crash) {
    IoUringBackend backend;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    auto rc = backend.init(0, lfd);
    if (!rc) {
        close(lfd);
        CHECK(true);
        return;
    }
    // Return buffer 0 — should not crash
    backend.return_buffer(0);
    // Return buffer at boundary
    backend.return_buffer(static_cast<u16>(kProvidedBufCount - 1));
    backend.shutdown();
    close(lfd);
}

// Verify wait() turns a timerfd expiration into a Timeout IoEvent.
TEST(uring, wait_emits_timeout_tick) {
    IoUringBackend backend;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    auto rc = backend.init(0, lfd);
    if (!rc) {
        close(lfd);
        CHECK(true);
        return;
    }

    // Override the default 1-second periodic tick with an immediate one-shot
    // so the already-armed timer read completes on this wait().
    struct itimerspec ts{};
    ts.it_value.tv_nsec = 1;
    REQUIRE_EQ(timerfd_settime(backend.timer_fd, 0, &ts, nullptr), 0);

    IoEvent events[4]{};
    u32 n = backend.wait(events, 4, nullptr, 0);
    REQUIRE_GE(n, 1u);
    CHECK_EQ(events[0].type, IoEventType::Timeout);
    CHECK_GE(events[0].result, 1);
    CHECK_EQ(events[0].has_buf, 0u);
    CHECK_EQ(events[0].buf_id, 0u);

    backend.shutdown();
    close(lfd);
}

// Verify provided-buffer recv CQEs are copied into Connection.recv_buf and the
// emitted IoEvent no longer owns a provided buffer.
TEST(uring, wait_copies_recv_into_conn_buffer) {
    i32 fds[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds), 0);

    IoUringBackend backend;
    auto init_rc = backend.init(0, -1);
    if (!init_rc) {
        close(fds[0]);
        close(fds[1]);
        CHECK(true);
        return;
    }

    TestConn tc;
    tc.init(0, fds[0]);
    Connection& conn = tc.conn;

    REQUIRE(backend.add_recv(fds[0], conn.id));
    static const u8 kReq[] = "GET / HTTP/1.1\r\n\r\n";
    static constexpr u32 kExpectedLen = sizeof(kReq) - 1;
    REQUIRE(send_all(fds[1], reinterpret_cast<const char*>(kReq), kExpectedLen));

    // Accumulate Recv CQEs across wait() calls until recv_buf holds the full
    // request (POSIX permits SOCK_STREAM recv to split an 18-byte write across
    // CQEs; non-Recv CQEs are skipped). add_recv uses IORING_RECV_MULTISHOT,
    // so one SQE yields multiple CQEs without resubmission.
    //
    // The 8-attempt cap + init's default 1s periodic timerfd act together as
    // a hang guard: if multishot recv is silently broken (error CQE, no
    // buffer, etc.), timer CQEs wake wait() every 1s and the loop exits in
    // ~8s with a clean REQUIRE failure instead of deadlocking.
    IoEvent events[4]{};
    bool saw_any_event = false;
    bool saw_recv_event = false;
    for (u32 attempt = 0; attempt < 8 && conn.recv_buf.len() < kExpectedLen; ++attempt) {
        u32 n = backend.wait(events, 4, &conn, 1);
        if (n > 0) saw_any_event = true;
        for (u32 i = 0; i < n; ++i) {
            if (events[i].type != IoEventType::Recv) continue;
            saw_recv_event = true;
            CHECK_EQ(events[i].conn_id, conn.id);
            CHECK_GT(events[i].result, 0);
            CHECK_EQ(events[i].has_buf, 0u);
            CHECK_EQ(events[i].buf_id, 0u);
        }
    }
    REQUIRE(saw_any_event);
    REQUIRE(saw_recv_event);
    REQUIRE_EQ(conn.recv_buf.len(), kExpectedLen);
    CHECK_EQ(memcmp(conn.recv_buf.data(), kReq, kExpectedLen), 0);

    close(fds[0]);
    close(fds[1]);
    backend.shutdown();
}

// === Shard lifecycle ===

// Shard init + shutdown without spawning a thread
TEST(shard, init_shutdown) {
    Shard<EpollEventLoop> shard;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(shard.init(0, lfd).has_value());
    CHECK(shard.loop != nullptr);
    CHECK_EQ(shard.id, 0u);
    CHECK_EQ(shard.listen_fd, lfd);
    shard.shutdown();
    CHECK(shard.loop == nullptr);
    close(lfd);
}

// Shard spawn + stop + join
TEST(shard, spawn_stop_join) {
    Shard<EpollEventLoop> shard;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(shard.init(0, lfd).has_value());
    REQUIRE(shard.spawn(-1).has_value());  // no CPU pinning
    CHECK(shard.thread_spawned);

    // Let the shard run briefly, then stop
    usleep(50000);  // 50ms
    shard.stop();
    shard.join();
    CHECK(!shard.thread_spawned);
    shard.shutdown();
    close(lfd);
}

// Shard handles requests while running
TEST(shard, serves_requests) {
    Shard<EpollEventLoop> shard;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    u16 port = get_port(lfd);
    REQUIRE(shard.init(0, lfd).has_value());
    REQUIRE(shard.spawn(-1).has_value());

    usleep(50000);  // let shard start
    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    REQUIRE(send_all(c, HTTP_REQ, HTTP_REQ_LEN));
    char buf[4096];
    i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
    CHECK(n > 0);
    CHECK(has_200(buf, n));
    close(c);

    shard.stop();
    shard.join();
    shard.shutdown();
    close(lfd);
}

TEST(shard, serves_https_requests) {
    auto tls_ctx = create_tls_server_context(kTestCertPath, kTestKeyPath);
    REQUIRE(tls_ctx.has_value());

    Shard<EpollEventLoop> shard;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    u16 port = get_port(lfd);
    REQUIRE(shard.init(0, lfd).has_value());
    shard.loop->tls_server = tls_ctx.value();
    REQUIRE(shard.spawn(-1).has_value());

    usleep(50000);

    SSL_CTX* client_ctx = create_test_client_ctx();
    REQUIRE(client_ctx != nullptr);

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    set_socket_timeouts(c, 2);

    SSL* ssl = SSL_new(client_ctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, c) == 1);
    REQUIRE(SSL_connect(ssl) == 1);
    REQUIRE(ssl_write_all(ssl, HTTP_REQ, HTTP_REQ_LEN));

    char buf[4096];
    i32 n = SSL_read(ssl, buf, sizeof(buf));
    CHECK(n > 0);
    if (n > 0) CHECK(has_200(buf, n));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(c);
    SSL_CTX_free(client_ctx);

    shard.stop();
    shard.join();
    shard.shutdown();
    close(lfd);
    destroy_tls_server_context(tls_ctx.value());
}

TEST(tls, rejects_invalid_private_key_file) {
    auto tls_ctx = create_tls_server_context(kTestCertPath, kTestCertPath);
    CHECK(!tls_ctx.has_value());
}

TEST(shard, serves_https_keepalive_requests) {
    auto tls_ctx = create_tls_server_context(kTestCertPath, kTestKeyPath);
    REQUIRE(tls_ctx.has_value());

    Shard<EpollEventLoop> shard;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    u16 port = get_port(lfd);
    REQUIRE(shard.init(0, lfd).has_value());
    shard.loop->tls_server = tls_ctx.value();
    REQUIRE(shard.spawn(-1).has_value());

    usleep(50000);

    SSL_CTX* client_ctx = create_test_client_ctx();
    REQUIRE(client_ctx != nullptr);

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    set_socket_timeouts(c, 2);

    SSL* ssl = SSL_new(client_ctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, c) == 1);
    REQUIRE(SSL_connect(ssl) == 1);

    for (int i = 0; i < 3; i++) {
        REQUIRE(ssl_write_all(ssl, HTTP_REQ, HTTP_REQ_LEN));
        char buf[4096];
        i32 n = SSL_read(ssl, buf, sizeof(buf));
        CHECK(n > 0);
        if (n > 0) CHECK(has_200(buf, n));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(c);
    SSL_CTX_free(client_ctx);

    shard.stop();
    shard.join();
    shard.shutdown();
    close(lfd);
    destroy_tls_server_context(tls_ctx.value());
}

TEST(shard, recovers_after_failed_tls_handshake) {
    auto tls_ctx = create_tls_server_context(kTestCertPath, kTestKeyPath);
    REQUIRE(tls_ctx.has_value());

    Shard<EpollEventLoop> shard;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    u16 port = get_port(lfd);
    REQUIRE(shard.init(0, lfd).has_value());
    shard.loop->tls_server = tls_ctx.value();
    REQUIRE(shard.spawn(-1).has_value());

    usleep(50000);

    i32 bad = connect_to(port);
    REQUIRE(bad >= 0);
    set_socket_timeouts(bad, 1);
    REQUIRE(send_all(bad, HTTP_REQ, HTTP_REQ_LEN));
    char drain[64];
    recv_timeout(bad, drain, sizeof(drain), 200);
    close(bad);

    SSL_CTX* client_ctx = create_test_client_ctx();
    REQUIRE(client_ctx != nullptr);

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    set_socket_timeouts(c, 2);

    SSL* ssl = SSL_new(client_ctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, c) == 1);
    REQUIRE(SSL_connect(ssl) == 1);
    REQUIRE(ssl_write_all(ssl, HTTP_REQ, HTTP_REQ_LEN));

    char buf[4096];
    i32 n = SSL_read(ssl, buf, sizeof(buf));
    CHECK(n > 0);
    if (n > 0) CHECK(has_200(buf, n));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(c);
    SSL_CTX_free(client_ctx);

    shard.stop();
    shard.join();
    shard.shutdown();
    close(lfd);
    destroy_tls_server_context(tls_ctx.value());
}

// Two shards on same port (SO_REUSEPORT)
TEST(shard, two_shards_same_port) {
    i32 lfd1 = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd1 >= 0);
    u16 port = get_port(lfd1);
    i32 lfd2 = create_listen_socket(port).value_or(-1);
    REQUIRE(lfd2 >= 0);

    Shard<EpollEventLoop> s1, s2;
    REQUIRE(s1.init(0, lfd1).has_value());
    REQUIRE(s2.init(1, lfd2).has_value());
    REQUIRE(s1.spawn(-1).has_value());
    REQUIRE(s2.spawn(-1).has_value());

    usleep(50000);

    // Send requests — kernel distributes across shards
    for (int i = 0; i < 5; i++) {
        i32 c = connect_to(port);
        REQUIRE(c >= 0);
        REQUIRE(send_all(c, HTTP_REQ, HTTP_REQ_LEN));
        char buf[4096];
        i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
        CHECK(n > 0);
        close(c);
    }

    s1.stop();
    s2.stop();
    s1.join();
    s2.join();
    s1.shutdown();
    s2.shutdown();
    close(lfd1);
    close(lfd2);
}

// detect_cpu_count returns > 0
TEST(shard, detect_cpu_count) {
    u32 cpus = detect_cpu_count();
    CHECK(cpus > 0);
    CHECK(cpus <= 1024);  // sanity upper bound
}

// Two shards with ephemeral port (port=0) bind the same port
TEST(shard, ephemeral_port_two_shards) {
    // First shard gets ephemeral port
    i32 lfd1 = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd1 >= 0);
    u16 port = get_port(lfd1);
    CHECK(port > 0);

    // Second shard should bind the same port (SO_REUSEPORT)
    i32 lfd2 = create_listen_socket(port).value_or(-1);
    REQUIRE(lfd2 >= 0);
    CHECK_EQ(get_port(lfd2), port);

    Shard<EpollEventLoop> s1, s2;
    REQUIRE(s1.init(0, lfd1).has_value());
    REQUIRE(s2.init(1, lfd2).has_value());
    REQUIRE(s1.spawn(-1).has_value());
    REQUIRE(s2.spawn(-1).has_value());

    usleep(50000);
    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    REQUIRE(send_all(c, HTTP_REQ, HTTP_REQ_LEN));
    char buf[4096];
    CHECK(recv_timeout(c, buf, sizeof(buf), 2000) > 0);
    close(c);

    s1.stop();
    s2.stop();
    s1.join();
    s2.join();
    s1.shutdown();
    s2.shutdown();
    close(lfd1);
    close(lfd2);
}

// Shard with owns_listen_fd closes it on shutdown
TEST(shard, owns_listen_fd) {
    Shard<EpollEventLoop> shard;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(shard.init(0, lfd).has_value());
    shard.owns_listen_fd = true;
    shard.shutdown();
    // lfd should be closed now — verify by trying to close again
    CHECK(close(lfd) < 0);
}

// Shard has upstream pool after init
TEST(shard, upstream_pool_initialized) {
    Shard<EpollEventLoop> shard;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(shard.init(0, lfd).has_value());
    CHECK(shard.upstream != nullptr);
    // Pool should be fresh (all free)
    auto* c = shard.upstream->alloc();
    CHECK(c != nullptr);
    shard.upstream->free(c);
    shard.shutdown();
    close(lfd);
}

// Shard can hold a route config
TEST(shard, route_config_attached) {
    RouteConfig cfg;
    cfg.add_static("/health", 0, 200);
    cfg.add_upstream("api", 0x7F000001, 8080);
    cfg.add_proxy("/api/", 0, 0);

    Shard<EpollEventLoop> shard;
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(shard.init(0, lfd).has_value());
    shard.route_config = &cfg;
    CHECK(shard.route_config != nullptr);
    CHECK_EQ(shard.route_config->route_count, 2u);
    CHECK_EQ(shard.route_config->upstream_count, 1u);
    shard.shutdown();
    close(lfd);
}

// === Copilot-found: epoll add_recv EEXIST after send ===
// Real socket test: multiple keep-alive cycles exercise the
// EPOLL_CTL_MOD fallback in add_recv (fd already registered).
TEST(copilot, keepalive_5_cycles_no_eexist) {
    TestServer srv;
    REQUIRE(srv.setup(100));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    for (int i = 0; i < 5; i++) {
        REQUIRE(send_all(c, HTTP_REQ, HTTP_REQ_LEN));
        char buf[4096];
        i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
        CHECK(n > 0);
    }
    close(c);
    srv.teardown();
}

// Regression: 20 keep-alive cycles — proves MOD+ADD fallback works.
// Without it, cycle 2+ fails with EEXIST when fd is already registered.
TEST(copilot, keepalive_20_cycles_eexist_regression) {
    TestServer srv;
    REQUIRE(srv.setup(200));
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    int success = 0;
    for (int i = 0; i < 20; i++) {
        if (!send_all(c, HTTP_REQ, HTTP_REQ_LEN)) break;
        char buf[4096];
        i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
        if (n <= 0) break;
        success++;
    }
    CHECK_EQ(success, 20);
    close(c);
    srv.teardown();
}

// Regression: listen_fd must be closeable after server teardown.
// Proves the fd isn't leaked or double-closed.
TEST(copilot6, listen_fd_not_leaked) {
    i32 fd1 = create_listen_socket(0).value_or(-1);
    REQUIRE(fd1 >= 0);
    u16 port = get_port(fd1);

    // Use the fd in a server, tear it down
    auto* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    REQUIRE(loop->init(0, fd1).has_value());
    // Don't run the loop, just init + shutdown
    loop->shutdown();
    destroy_real_loop(loop);

    // fd1 should still be open (shutdown doesn't close listen_fd)
    // Close it explicitly — should succeed (not EBADF)
    CHECK_EQ(close(fd1), 0);

    // Now the port should be reusable
    i32 fd2 = create_listen_socket(port).value_or(-1);
    CHECK(fd2 >= 0);
    if (fd2 >= 0) close(fd2);
}

// Regression: keepalive_timeout must be 60 in real EventLoop after mmap+init.
// Without explicit init, mmap zeroes → keepalive_timeout=0 → instant timeout.
TEST(copilot6, real_loop_keepalive_timeout) {
    auto* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    i32 fd = create_listen_socket(0).value_or(-1);
    REQUIRE(fd >= 0);
    REQUIRE(loop->init(0, fd).has_value());
    CHECK_EQ(loop->keepalive_timeout, 60u);
    loop->shutdown();
    close(fd);
    destroy_real_loop(loop);
}

// === Epoll event loop: drain, metrics, epoch ===

TEST(epoll_drain, drain_closes_idle_connections) {
    auto* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(loop->init(0, lfd).has_value());
    CHECK(!loop->is_draining());
    loop->drain(1);  // 1-second drain period
    CHECK(loop->is_draining());
    loop->stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

TEST(epoll_drain, drain_with_active_connections) {
    TestServer srv;
    REQUIRE(srv.setup(50));
    // Connect and send request
    i32 c = connect_to(srv.port);
    REQUIRE(c >= 0);
    send_all(c, HTTP_REQ, HTTP_REQ_LEN);
    char buf[4096];
    i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
    CHECK(n > 0);
    // After response, connection is keep-alive. Now drain.
    srv.loop->drain(1);
    CHECK(srv.loop->is_draining());
    close(c);
    srv.teardown();
}

TEST(epoll_metrics, accept_and_request_counted) {
    auto* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(loop->init(0, lfd).has_value());
    ShardMetrics metrics{};
    loop->metrics = &metrics;
    u16 port = get_port(lfd);
    LoopThread lt = {loop, {}, 3};
    lt.start();
    usleep(100000);
    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    send_all(c, HTTP_REQ, HTTP_REQ_LEN);
    char buf[4096];
    i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
    CHECK(n > 0);
    for (i32 i = 0; i < 200 && !lt.done.load(std::memory_order_acquire); i++) usleep(1000);
    CHECK(lt.done.load(std::memory_order_acquire));
    close(c);
    lt.stop();
    CHECK_GT(metrics.connections_total, 0u);
    CHECK_GT(metrics.requests_total, 0u);
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

TEST(epoll_epoch, epoch_increments_on_request) {
    auto* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(loop->init(0, lfd).has_value());
    ShardEpoch epoch{};
    epoch.epoch.store(0, std::memory_order_relaxed);
    loop->epoch = &epoch;
    u16 port = get_port(lfd);
    LoopThread lt = {loop, {}, 20};
    lt.start();
    usleep(10000);
    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    send_all(c, HTTP_REQ, HTTP_REQ_LEN);
    char buf[4096];
    recv_timeout(c, buf, sizeof(buf), 2000);
    close(c);
    lt.stop();
    // Epoch should have advanced (enter + leave = +2 per request)
    CHECK_GT(epoch.epoch.load(std::memory_order_relaxed), 0u);
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

TEST(epoll_command, config_swap_via_control) {
    auto* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(loop->init(0, lfd).has_value());
    ShardControlBlock ctrl{};
    RouteConfig cfg{};
    const RouteConfig* cfg_ptr = nullptr;
    loop->control = &ctrl;
    loop->config_ptr = &cfg_ptr;
    ctrl.pending_config.store(&cfg, std::memory_order_relaxed);
    loop->poll_command();
    CHECK_EQ(cfg_ptr, &cfg);
    // JIT swap
    void* fake_jit = reinterpret_cast<void*>(0x1234);
    void* jit_ptr = nullptr;
    loop->jit_code_ptr = &jit_ptr;
    ctrl.pending_jit.store(fake_jit, std::memory_order_relaxed);
    loop->poll_command();
    CHECK_EQ(jit_ptr, fake_jit);
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

// === Shard lifecycle ===

TEST(shard, init_and_shutdown) {
    // Test Shard init with real event loop type
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    Shard<EpollEventLoop> shard;
    auto res = shard.init(0, lfd);
    CHECK(res.has_value());
    shard.shutdown();
    close(lfd);
}

TEST(shard, metrics_wired) {
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    Shard<EpollEventLoop> shard;
    auto res = shard.init(0, lfd);
    REQUIRE(res.has_value());
    CHECK(shard.loop->metrics != nullptr);
    CHECK_EQ(shard.loop->metrics->connections_total, 0u);
    shard.shutdown();
    close(lfd);
}

TEST(epoll_drain, drain_completes_naturally) {
    // Start loop, connect a client, drain, let it complete
    auto* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    REQUIRE(loop->init(0, lfd).has_value());
    u16 port = get_port(lfd);

    // Start loop in thread with enough iterations to complete drain
    LoopThread lt = {loop, {}, 100};
    lt.start();
    usleep(10000);

    // Connect and send a request (creates active connection)
    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    send_all(c, HTTP_REQ, HTTP_REQ_LEN);
    char buf[4096];
    recv_timeout(c, buf, sizeof(buf), 2000);

    // Start drain with 1-second period
    loop->drain(1);
    CHECK(loop->is_draining());

    // Close client to allow drain to complete (no active connections)
    close(c);
    usleep(500000);  // wait for drain

    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

TEST(shard, access_log_init) {
    i32 lfd = create_listen_socket(0).value_or(-1);
    REQUIRE(lfd >= 0);
    Shard<EpollEventLoop> shard;
    auto res = shard.init(0, lfd);
    REQUIRE(res.has_value());
    // Access log is lazily allocated
    CHECK(shard.loop->access_log == nullptr);
    auto log_res = shard.init_access_log();
    CHECK(log_res.has_value());
    CHECK(shard.loop->access_log != nullptr);
    shard.shutdown();
    close(lfd);
}

// === Route matching via real sockets (covers EpollEventLoop instantiation) ===

TEST(route, static_200_real_socket) {
    RouteConfig cfg;
    cfg.add_static("/health", 0, 200);
    cfg.add_static("/", 0, 404);
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 20};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    send_all(c, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n", 33);
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 500);
    CHECK_GT(n, 0);
    CHECK(has_200(buf, n));
    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

TEST(route, static_404_real_socket) {
    RouteConfig cfg;
    cfg.add_static("/", 0, 404);
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 20};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    send_all(c, "GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 35);
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 500);
    CHECK_GT(n, 0);
    // Should contain "404"
    bool found_404 = false;
    for (i32 i = 0; i < n - 2; i++) {
        if (buf[i] == '4' && buf[i + 1] == '0' && buf[i + 2] == '4') {
            found_404 = true;
            break;
        }
    }
    CHECK(found_404);
    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

TEST(route, multiple_status_codes_real_socket) {
    RouteConfig cfg;
    cfg.add_static("/e201", 0, 201);
    cfg.add_static("/e204", 0, 204);
    cfg.add_static("/e301", 0, 301);
    cfg.add_static("/e403", 0, 403);
    cfg.add_static("/e500", 0, 500);
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 50};
    lt.start();

    struct {
        const char* req;
        u32 req_len;
        const char* expect;
    } cases[] = {
        {"GET /e201 HTTP/1.1\r\nHost: x\r\n\r\n", 31, "201"},
        {"GET /e204 HTTP/1.1\r\nHost: x\r\n\r\n", 31, "204"},
        {"GET /e301 HTTP/1.1\r\nHost: x\r\n\r\n", 31, "301"},
        {"GET /e403 HTTP/1.1\r\nHost: x\r\n\r\n", 31, "403"},
        {"GET /e500 HTTP/1.1\r\nHost: x\r\n\r\n", 31, "500"},
    };
    for (auto& tc : cases) {
        i32 c = connect_to(port);
        REQUIRE(c >= 0);
        send_all(c, tc.req, tc.req_len);
        char buf[1024];
        i32 n = recv_timeout(c, buf, sizeof(buf), 500);
        CHECK_GT(n, 0);
        bool found = false;
        for (i32 i = 0; i < n - 2; i++) {
            if (buf[i] == tc.expect[0] && buf[i + 1] == tc.expect[1] &&
                buf[i + 2] == tc.expect[2]) {
                found = true;
                break;
            }
        }
        CHECK(found);
        close(c);
    }
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

TEST(route, post_put_patch_method_filter_real_socket) {
    RouteConfig cfg;
    REQUIRE(cfg.add_static("/write", kRouteMethodPost, 201));
    REQUIRE(cfg.add_static("/write", kRouteMethodPut, 202));
    REQUIRE(cfg.add_static("/write", kRouteMethodPatch, 203));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 50};
    lt.start();

    struct {
        const char* req;
        u32 req_len;
        const char* expect;
    } cases[] = {{"POST /write HTTP/1.1\r\nHost: x\r\n\r\n", 33, "201"},
                 {"PUT /write HTTP/1.1\r\nHost: x\r\n\r\n", 32, "202"},
                 {"PATCH /write HTTP/1.1\r\nHost: x\r\n\r\n", 34, "203"}};
    for (auto& tc : cases) {
        i32 c = connect_to(port);
        REQUIRE(c >= 0);
        send_all(c, tc.req, tc.req_len);
        char buf[1024];
        i32 n = recv_timeout(c, buf, sizeof(buf), 500);
        CHECK_GT(n, 0);
        bool found = false;
        for (i32 i = 0; i < n - 2; i++) {
            if (buf[i] == tc.expect[0] && buf[i + 1] == tc.expect[1] &&
                buf[i + 2] == tc.expect[2]) {
                found = true;
                break;
            }
        }
        CHECK(found);
        close(c);
    }
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

TEST(route, capture_real_socket) {
    RouteConfig cfg;
    cfg.add_static("/", 0, 200);
    const RouteConfig* active = &cfg;
    CaptureRing ring;
    ring.init();

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    loop->set_capture(&ring);
    LoopThread lt = {loop, {}, 200};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    send_all(c, "GET /cap HTTP/1.1\r\nHost: x\r\n\r\n", 31);
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 500);
    CHECK_GT(n, 0);
    close(c);

    for (i32 i = 0; i < 200 && ring.available() == 0; i++) usleep(1000);
    CHECK_EQ(ring.available(), 1u);

    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

#if RUT_ENABLE_JIT_TESTS
// End-to-end wait(ms) through the real EpollEventLoop: compile a route
// that yields briefly and returns 204, register it as a JitHandler
// in the RouteConfig, drive a real TCP connection, and assert the client
// observes the 204 response after the timer fires.
//
// Timing note: EpollEventLoop now uses a one-shot yield_timer_fd + min-heap
// driven by absolute CLOCK_MONOTONIC deadlines with ms precision (no
// TimerWheel bucketing). Use a non-1s wait so this smoke test does not race
// the periodic keepalive wheel tick; exact sub-second timing is covered by
// wait_ms_precision_sub_second below.
TEST(route, wait_jit_handler_real_socket) {
    using namespace rut;  // pull in compiler helpers (lex / parse_file / ...)

    const char* src = "route GET \"/sleep\" { wait(250) return 204 }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    REQUIRE(cfg.add_jit_handler("/sleep", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 200};
    lt.start();
    // Let the loop thread register the listener before the client connects.
    // Without this, this smoke test can be flaky when it runs immediately
    // after io_uring backend tests on a busy runner.
    usleep(10000);

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    REQUIRE(send_all(c, "GET /sleep HTTP/1.1\r\nHost: x\r\n\r\n", 32));
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 3000);
    CHECK_GT(n, 0);
    // Response should contain the 204 status code.
    bool found_204 = false;
    for (i32 i = 0; i + 2 < n; i++) {
        if (buf[i] == '2' && buf[i + 1] == '0' && buf[i + 2] == '4') {
            found_204 = true;
            break;
        }
    }
    CHECK(found_204);
    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

// wait(50) — sub-second precision verification. The legacy TimerWheel
// would round this up to 1000ms (one full tick), so this test fails
// immediately if the yield_timer_fd / min-heap path regresses back to
// the wheel. Observed wall time must land well below one second.
TEST(route, wait_ms_precision_sub_second) {
    using namespace rut;

    const char* src = "route GET \"/snooze\" { wait(50) return 204 }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    REQUIRE(cfg.add_jit_handler("/snooze", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 200};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    send_all(c, "GET /snooze HTTP/1.1\r\nHost: x\r\n\r\n", 33);
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    // Compute delta in signed nanoseconds so tv_nsec underflow (t1.tv_nsec
    // < t0.tv_nsec) doesn't wrap to a huge u64 when the tv_sec carry should
    // handle it.
    i64 elapsed_ns = static_cast<i64>(t1.tv_sec - t0.tv_sec) * 1'000'000'000LL +
                     (static_cast<i64>(t1.tv_nsec) - static_cast<i64>(t0.tv_nsec));
    i64 elapsed_ms = elapsed_ns / 1'000'000LL;

    CHECK_GT(n, 0);
    bool found_204 = false;
    for (i32 i = 0; i + 2 < n; i++) {
        if (buf[i] == '2' && buf[i + 1] == '0' && buf[i + 2] == '4') {
            found_204 = true;
            break;
        }
    }
    CHECK(found_204);
    // 50ms wait should complete in well under a second. The legacy
    // TimerWheel rounds to 1000ms; a 500ms ceiling proves we're using
    // the yield_timer_fd / IORING_OP_TIMEOUT path. Floor at 40ms
    // protects against any accidental zero-wait regression.
    CHECK_GT(elapsed_ms, 40);
    CHECK_LT(elapsed_ms, 500);

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

// Slice 1: a let initializer whose value drives the terminal return
// must survive across a wait. The current codegen re-materializes the
// local inside the terminal block, which works for pure initializers.
// End-to-end check via a real JIT + epoll loop that `let code = 201;
// wait(100); if code == 201 { return 201 } else { return 500 }` returns
// 201, proving the local's value reaches the branch post-yield.
TEST(route, let_across_wait_drives_return_real_socket) {
    using namespace rut;

    const char* src =
        "route GET \"/let\" { let code = 201 wait(100) if code == 201 { return 201 } else { "
        "return 500 } }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    REQUIRE(cfg.add_jit_handler("/let", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 200};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    const char kLetReq[] = "GET /let HTTP/1.1\r\nHost: x\r\n\r\n";
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    send_all(c, kLetReq, sizeof(kLetReq) - 1);
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    i64 elapsed_ns = static_cast<i64>(t1.tv_sec - t0.tv_sec) * 1'000'000'000LL +
                     (static_cast<i64>(t1.tv_nsec) - static_cast<i64>(t0.tv_nsec));
    i64 elapsed_ms = elapsed_ns / 1'000'000LL;

    CHECK_GT(n, 0);
    bool found_201 = false;
    for (i32 i = 0; i + 2 < n; i++) {
        if (buf[i] == '2' && buf[i + 1] == '0' && buf[i + 2] == '1') {
            found_201 = true;
            break;
        }
    }
    CHECK(found_201);
    // wait(100) must actually fire — otherwise this test could pass
    // even if the yield path was bypassed and state 0 fell through
    // to state N immediately. Floor at 80ms for scheduler jitter on
    // slow CI; ceiling at 500ms to flag anything unusually slow.
    CHECK_GT(elapsed_ms, 80);
    CHECK_LT(elapsed_ms, 500);

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

// Regression: a wait(ms) longer than keepalive_timeout must NOT be woken
// early by the 1-second TimerWheel tick. Before the fix, yielded conns
// remained on the keepalive wheel and the tick callback resumed them via
// the `pending_handler_fn` branch — a wait(2000) would fire at ~1000ms.
//
// Uses keepalive_timeout=1s + wait(2000ms) to hit the bug fast. Asserts
// elapsed >= 1700ms (clear margin above the 1s tick).
TEST(route, wait_longer_than_keepalive_not_resumed_by_wheel) {
    using namespace rut;

    const char* src = "route GET \"/deep\" { wait(2000) return 204 }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    REQUIRE(cfg.add_jit_handler("/deep", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    // Shrink keepalive so a 2s wait clearly exceeds it. Wheel tick
    // before the fix would resume the handler around 1s.
    loop->keepalive_timeout = 1;
    LoopThread lt = {loop, {}, 200};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    send_all(c, "GET /deep HTTP/1.1\r\nHost: x\r\n\r\n", 31);
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 4000);
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    // Compute delta in signed nanoseconds so tv_nsec underflow (t1.tv_nsec
    // < t0.tv_nsec) doesn't wrap to a huge u64 when the tv_sec carry should
    // handle it.
    i64 elapsed_ns = static_cast<i64>(t1.tv_sec - t0.tv_sec) * 1'000'000'000LL +
                     (static_cast<i64>(t1.tv_nsec) - static_cast<i64>(t0.tv_nsec));
    i64 elapsed_ms = elapsed_ns / 1'000'000LL;

    CHECK_GT(n, 0);
    bool found_204 = false;
    for (i32 i = 0; i + 2 < n; i++) {
        if (buf[i] == '2' && buf[i + 1] == '0' && buf[i + 2] == '4') {
            found_204 = true;
            break;
        }
    }
    CHECK(found_204);
    // Must not have been woken by the 1s wheel tick. 1700ms floor leaves
    // comfortable margin above the tick; 3000ms ceiling catches stuck
    // timers. wait(2000) on an unloaded loop lands near 2000ms.
    CHECK_GT(elapsed_ms, 1700);
    CHECK_LT(elapsed_ms, 3000);

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}
#endif

// Minimal hand-written handler that returns a Forward action. Matches the
// jit::HandlerFn ABI so callbacks_impl.h's handle_jit_outcome can dispatch
// it the same way it would a real JIT-compiled handler.
static u64 forward_upstream_0_handler(void* /*conn*/,
                                      rut::jit::HandlerCtx* /*ctx*/,
                                      const u8* /*req*/,
                                      u32 /*len*/,
                                      void* /*arena*/) {
    auto r = rut::jit::HandlerResult::make_forward(0);
    return r.pack();
}

// End-to-end: a JIT handler returning Forward must kick off the same
// proxy flow as a RouteAction::Proxy match. Before the JIT forward wire-up,
// handle_jit_outcome::Forward returned 500; this test guards against that
// regression. Mirrors replay_gap::proxy_route_enters_proxy_state but with
// the JitHandler route action.
TEST(route, forward_jit_handler_enters_proxy_state) {
    using namespace rut;

    RouteConfig cfg{};
    auto up = cfg.add_upstream("backend", 0x7F000001, 9999);
    REQUIRE(up.has_value());
    REQUIRE_EQ(up.value(), 0u);  // first upstream → id 0 in cfg
    REQUIRE(cfg.add_jit_handler("/api", 'G', &forward_upstream_0_handler));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    send_all(c, "GET /api HTTP/1.1\r\nHost: x\r\n\r\n", 30);

    // The request triggers the JIT handler → Forward → submit_connect
    // to 127.0.0.1:9999. No upstream is listening, so the connect will
    // fail with ECONNREFUSED and the loop will send a 502 (or close).
    // The assertion we care about is that a 502 came back — proving
    // Forward routed through the proxy path instead of the pre-fix
    // 500 response.
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 500);
    CHECK_GT(n, 0);
    bool found_502 = false;
    for (i32 i = 0; i + 2 < n; i++) {
        if (buf[i] == '5' && buf[i + 1] == '0' && buf[i + 2] == '2') {
            found_502 = true;
            break;
        }
    }
    CHECK(found_502);

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

// Bad upstream_id (out of bounds) → handle_jit_outcome must return 502
// rather than crash or hang. Guards the defensive bound check in the
// Forward branch.
static u64 forward_upstream_99_handler(void* /*conn*/,
                                       rut::jit::HandlerCtx* /*ctx*/,
                                       const u8* /*req*/,
                                       u32 /*len*/,
                                       void* /*arena*/) {
    auto r = rut::jit::HandlerResult::make_forward(99);
    return r.pack();
}

TEST(route, forward_jit_handler_rejects_unknown_upstream_id) {
    using namespace rut;

    RouteConfig cfg{};
    // Only one upstream at id 0; handler returns 99.
    REQUIRE(cfg.add_upstream("backend", 0x7F000001, 9999));
    REQUIRE(cfg.add_jit_handler("/api", 'G', &forward_upstream_99_handler));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    send_all(c, "GET /api HTTP/1.1\r\nHost: x\r\n\r\n", 30);
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 500);
    CHECK_GT(n, 0);
    bool found_502 = false;
    for (i32 i = 0; i + 2 < n; i++) {
        if (buf[i] == '5' && buf[i + 1] == '0' && buf[i + 2] == '2') {
            found_502 = true;
            break;
        }
    }
    CHECK(found_502);

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

// Minimal hand-written JIT handler that returns ReturnStatus(200)
// with upstream_id = 1 — the ABI slot for a 1-based response-body
// index. Used to validate the runtime body-render path without
// needing the (not-yet-wired) compiler pipeline for bodies.
static u64 return_200_with_body_1_handler(void* /*conn*/,
                                          rut::jit::HandlerCtx* /*ctx*/,
                                          const u8* /*req*/,
                                          u32 /*len*/,
                                          void* /*arena*/) {
    rut::jit::HandlerResult r{rut::jit::HandlerAction::ReturnStatus,
                              200,
                              /*upstream_id=*/1,
                              0,
                              rut::jit::YieldKind::HttpGet};
    return r.pack();
}

// End-to-end: handler returns ReturnStatus with body_idx=1;
// RouteConfig has a body pre-registered; runtime formats response
// with the body bytes + matching Content-Length + default Content-Type.
TEST(route, jit_handler_custom_body_real_socket) {
    using namespace rut;

    RouteConfig cfg{};
    const char kBody[] = "Hello, world";
    const u16 body_idx = cfg.add_response_body(kBody, sizeof(kBody) - 1);
    REQUIRE_EQ(body_idx, 1u);
    REQUIRE(cfg.add_jit_handler("/hello", 'G', &return_200_with_body_1_handler));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    const char kReq[] = "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n";
    send_all(c, kReq, sizeof(kReq) - 1);
    char buf[2048];
    i32 n = recv_timeout(c, buf, sizeof(buf), 1000);
    CHECK_GT(n, 0);
    buf[n < static_cast<i32>(sizeof(buf)) ? n : static_cast<i32>(sizeof(buf)) - 1] = '\0';

    // Response must contain "200", "Content-Length: 12", default
    // Content-Type, and the body bytes literal.
    const Str response{buf, static_cast<u32>(n)};
    bool has_200 = false;
    bool has_cl = false;
    bool has_ct = false;
    bool has_body = false;
    for (u32 i = 0; i + 2 < response.len; i++) {
        if (response.ptr[i] == '2' && response.ptr[i + 1] == '0' && response.ptr[i + 2] == '0') {
            has_200 = true;
            break;
        }
    }
    static const char kCL[] = "Content-Length: 12";
    for (u32 i = 0; i + sizeof(kCL) - 1 <= response.len; i++) {
        bool match = true;
        for (u32 j = 0; j < sizeof(kCL) - 1; j++) {
            if (response.ptr[i + j] != static_cast<u8>(kCL[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            has_cl = true;
            break;
        }
    }
    static const char kCT[] = "Content-Type: text/plain";
    for (u32 i = 0; i + sizeof(kCT) - 1 <= response.len; i++) {
        bool match = true;
        for (u32 j = 0; j < sizeof(kCT) - 1; j++) {
            if (response.ptr[i + j] != static_cast<u8>(kCT[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            has_ct = true;
            break;
        }
    }
    for (u32 i = 0; i + sizeof(kBody) - 1 <= response.len; i++) {
        bool match = true;
        for (u32 j = 0; j < sizeof(kBody) - 1; j++) {
            if (response.ptr[i + j] != static_cast<u8>(kBody[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            has_body = true;
            break;
        }
    }
    CHECK(has_200);
    CHECK(has_cl);
    CHECK(has_ct);
    CHECK(has_body);

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

struct ScriptedUpstreamServer {
    i32 listen_fd = -1;
    u16 port = 0;
    const char* response = nullptr;
    u32 response_len = 0;
    std::atomic<bool> running{false};
    bool started = false;
    pthread_t thread{};

    ~ScriptedUpstreamServer() { teardown(); }

    static bool set_blocking(i32 fd) {
        i32 flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) return false;
        return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0;
    }

    static void* run(void* arg) {
        auto* server = static_cast<ScriptedUpstreamServer*>(arg);
        i32 client = -1;
        const i32 accept_fd = server->listen_fd;
        while (server->running.load(std::memory_order_acquire)) {
            client = accept(accept_fd, nullptr, nullptr);
            if (client >= 0) break;
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) break;
            usleep(1000);
        }
        if (client >= 0) {
            if (set_blocking(client)) {
                char req[1024];
                (void)recv_timeout(client, req, sizeof(req), 1000);
                if (server->response != nullptr && server->response_len > 0) {
                    (void)send_all(client, server->response, server->response_len);
                }
            }
            close(client);
        }
        return nullptr;
    }

    bool setup(const char* bytes, u32 len) {
        auto lfd_result = create_listen_socket(0);
        if (!lfd_result.has_value()) return false;
        listen_fd = lfd_result.value();
        port = get_port(listen_fd);
        response = bytes;
        response_len = len;
        running.store(true, std::memory_order_release);
        if (pthread_create(&thread, nullptr, run, this) != 0) {
            running.store(false, std::memory_order_release);
            close(listen_fd);
            listen_fd = -1;
            return false;
        }
        started = true;
        return true;
    }

    void teardown() {
        running.store(false, std::memory_order_release);
        if (started) {
            pthread_join(thread, nullptr);
            started = false;
        }
        if (listen_fd >= 0) {
            close(listen_fd);
            listen_fd = -1;
        }
    }
};

struct ScopedProxyLoop {
    RealLoop* loop = nullptr;
    i32 listen_fd = -1;
    u16 port = 0;
    LoopThread lt{};
    bool loop_started = false;

    ~ScopedProxyLoop() { teardown(); }

    bool setup(const RouteConfig** active, i32 iters) {
        loop = create_real_loop();
        if (loop == nullptr) return false;
        auto lfd_result = create_listen_socket(0);
        if (!lfd_result.has_value()) {
            teardown();
            return false;
        }
        listen_fd = lfd_result.value();
        port = get_port(listen_fd);
        if (!loop->init(0, listen_fd).has_value()) {
            teardown();
            return false;
        }
        loop->config_ptr = active;
        lt.loop = loop;
        lt.thread = {};
        lt.max_iters = iters;
        lt.done.store(false, std::memory_order_release);
        lt.start();
        loop_started = true;
        return true;
    }

    void teardown() {
        if (loop_started) {
            lt.stop();
            loop_started = false;
        }
        if (loop != nullptr) {
            loop->shutdown();
        }
        if (listen_fd >= 0) {
            close(listen_fd);
            listen_fd = -1;
        }
        port = 0;
        if (loop != nullptr) {
            destroy_real_loop(loop);
            loop = nullptr;
        }
    }
};

struct MalformedUpstreamCase {
    const char* name;
    const char* response;
    u32 response_len;
    bool expect_502;
};

static void run_malformed_upstream_case(rut::test::TestCase* test_case,
                                        const MalformedUpstreamCase& tc_cfg) {
    auto* _tc = test_case;

    ScriptedUpstreamServer upstream;
    REQUIRE(upstream.setup(tc_cfg.response, tc_cfg.response_len));

    RouteConfig cfg{};
    auto upstream_id = cfg.add_upstream("malformed", 0x7F000001, upstream.port);
    REQUIRE(upstream_id.has_value());
    REQUIRE(cfg.add_proxy("/api", 0, upstream_id.value()));
    const RouteConfig* active = &cfg;

    ScopedProxyLoop proxy;
    REQUIRE(proxy.setup(&active, 500));

    i32 client = connect_to(proxy.port);
    CHECK_MSG(client >= 0, tc_cfg.name);
    if (client < 0) return;
    const char kReq[] = "GET /api HTTP/1.1\r\nHost: x\r\n\r\n";
    bool sent = send_all(client, kReq, sizeof(kReq) - 1);
    CHECK_MSG(sent, tc_cfg.name);
    if (!sent) {
        close(client);
        return;
    }

    char buf[4096];
    u32 total = 0;
    i32 n = 0;
    while (total < sizeof(buf)) {
        n = recv_timeout(client, buf + total, sizeof(buf) - total, 2000);
        if (n <= 0) break;
        total += static_cast<u32>(n);
        if (buf_contains(buf, total, "\r\n\r\n", 4)) break;
    }
    if (tc_cfg.expect_502) {
        CHECK_MSG(total > 0, tc_cfg.name);
        CHECK_MSG(buf_contains(buf, total, "502", 3), tc_cfg.name);
        CHECK_MSG(buf_contains(buf, total, "Connection: close", 17), tc_cfg.name);
    } else {
        const bool closed = n == 0 || n == -ECONNRESET || n == -ECONNABORTED || n == -EPIPE;
        CHECK_MSG(total == 0 && closed, tc_cfg.name);
    }

    close(client);
}

TEST(proxy_e2e, malformed_upstream_responses_fail_closed) {
    static const char kBadStatus[] = "HTTP/1.1 XYZ Bad\r\nContent-Length: 0\r\n\r\n";
    static const char kPartialStatus[] = "HTTP/1.1 20";
    static const char kBadHeaderCrlf[] = "HTTP/1.1 200 OK\r\nX-Test: bad\rX-Next: y\r\n\r\n";
    static const char kBadContentLength[] = "HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n";
    static const char kStatusTooLow[] = "HTTP/1.1 099 Low\r\nContent-Length: 0\r\n\r\n";
    static const char kStatusTooHigh[] = "HTTP/1.1 600 High\r\nContent-Length: 0\r\n\r\n";
    static const char kBadVersion[] = "HTTP/1.2 200 OK\r\nContent-Length: 0\r\n\r\n";
    static const char kEmptyHeaderName[] = "HTTP/1.1 200 OK\r\n: bad\r\n\r\n";
    static const char kConflictingContentLength[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 1\r\n"
        "Content-Length: 2\r\n"
        "\r\n";
    static const char kMalformedChunkedInitial[] =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "XYZ\r\n";
    static const char kChunkedBeatsContentLengthButStillValidatesChunks[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 100\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "ZZ\r\n";

    static const MalformedUpstreamCase kCases[] = {
        {"bad status code", kBadStatus, sizeof(kBadStatus) - 1, true},
        {"partial status then eof", kPartialStatus, sizeof(kPartialStatus) - 1, true},
        {"malformed header crlf", kBadHeaderCrlf, sizeof(kBadHeaderCrlf) - 1, true},
        {"invalid content length", kBadContentLength, sizeof(kBadContentLength) - 1, true},
        {"status below range", kStatusTooLow, sizeof(kStatusTooLow) - 1, true},
        {"status above range", kStatusTooHigh, sizeof(kStatusTooHigh) - 1, true},
        {"unsupported http version", kBadVersion, sizeof(kBadVersion) - 1, true},
        {"empty header name", kEmptyHeaderName, sizeof(kEmptyHeaderName) - 1, true},
        {"conflicting content length",
         kConflictingContentLength,
         sizeof(kConflictingContentLength) - 1,
         true},
        {"malformed chunked initial body",
         kMalformedChunkedInitial,
         sizeof(kMalformedChunkedInitial) - 1,
         true},
        {"chunked wins over content length but malformed chunks fail",
         kChunkedBeatsContentLengthButStillValidatesChunks,
         sizeof(kChunkedBeatsContentLengthButStillValidatesChunks) - 1,
         true},
        {"empty eof", nullptr, 0, false},
    };

    for (const auto& tc_cfg : kCases) {
        run_malformed_upstream_case(_tc, tc_cfg);
    }
}

// Handler returns ReturnStatus with an out-of-range body_idx (e.g. no
// body was registered). Runtime must fall back to the default status-
// reason body rather than rendering garbage or hanging.
static u64 return_200_with_body_99_handler(void* /*conn*/,
                                           rut::jit::HandlerCtx* /*ctx*/,
                                           const u8* /*req*/,
                                           u32 /*len*/,
                                           void* /*arena*/) {
    rut::jit::HandlerResult r{rut::jit::HandlerAction::ReturnStatus,
                              200,
                              /*upstream_id=*/99,
                              0,
                              rut::jit::YieldKind::HttpGet};
    return r.pack();
}

TEST(route, jit_handler_unknown_body_idx_falls_back) {
    using namespace rut;

    RouteConfig cfg{};
    // No response bodies registered. upstream_id=99 is out of range.
    REQUIRE(cfg.add_jit_handler("/hello", 'G', &return_200_with_body_99_handler));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    const char kReq[] = "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n";
    send_all(c, kReq, sizeof(kReq) - 1);
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 1000);
    CHECK_GT(n, 0);
    // Assert the default reason-phrase body — not just that 200 is
    // anywhere in the response. For 200 the default body is "OK" (2
    // bytes), and format_static_response does NOT emit Content-Type,
    // so the response shape is distinct from the custom-body path.
    const Str response{buf, static_cast<u32>(n)};
    auto has = [&](const char* needle, u32 nlen) {
        return buf_contains(
            reinterpret_cast<const char*>(response.ptr), response.len, needle, nlen);
    };
    CHECK(has("200 OK", 6));
    CHECK(has("Content-Length: 2\r\n", 19));
    // Default formatter must NOT emit Content-Type — that would mean
    // the custom-body path ran despite the out-of-range index.
    CHECK(!has("Content-Type:", 13));
    // Body bytes at end of response: "...\r\n\r\nOK".
    CHECK(has("\r\n\r\nOK", 6));

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

// Handler returns ReturnStatus with a valid headers_idx but an
// out-of-range body_idx. The dispatch path must still render the
// default reason-phrase body so the response isn't silently empty —
// matches the no-headers fallback behavior of format_static_response.
static u64 return_200_body_99_headers_1_handler(void* /*conn*/,
                                                rut::jit::HandlerCtx* /*ctx*/,
                                                const u8* /*req*/,
                                                u32 /*len*/,
                                                void* /*arena*/) {
    rut::jit::HandlerResult r{rut::jit::HandlerAction::ReturnStatus,
                              200,
                              /*upstream_id=*/99,  // body_idx: out of range
                              /*next_state=*/1,    // headers_idx: valid
                              rut::jit::YieldKind::HttpGet};
    return r.pack();
}

TEST(route, jit_handler_unknown_body_idx_with_headers_falls_back) {
    using namespace rut;

    RouteConfig cfg{};
    // Register one header set (idx 1) but no bodies — body_idx=99
    // is out of range.
    const char* keys[] = {"X-Service"};
    u32 key_lens[] = {9};
    const char* vals[] = {"auth"};
    u32 val_lens[] = {4};
    REQUIRE_EQ(cfg.add_response_header_set(keys, key_lens, vals, val_lens, 1), 1u);
    REQUIRE(cfg.add_jit_handler("/hello", 'G', &return_200_body_99_headers_1_handler));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    const char kReq[] = "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n";
    send_all(c, kReq, sizeof(kReq) - 1);
    char buf[1024];
    i32 n = recv_timeout(c, buf, sizeof(buf), 1000);
    CHECK_GT(n, 0);
    const Str response{buf, static_cast<u32>(n)};
    auto has = [&](const char* needle, u32 nlen) {
        return buf_contains(
            reinterpret_cast<const char*>(response.ptr), response.len, needle, nlen);
    };
    CHECK(has("200 OK", 6));
    // Body fell back to the default reason phrase "OK" (2 bytes) even
    // though headers were present.
    CHECK(has("Content-Length: 2\r\n", 19));
    CHECK(has("\r\n\r\nOK", 6));
    // Custom header still emitted alongside the fallback body.
    CHECK(has("X-Service: auth\r\n", 17));
    // Fallback-reason-phrase body must NOT carry the default
    // Content-Type — matches format_static_response's wire shape so
    // the two fallback paths (with / without headers) are
    // byte-compatible modulo the extra user headers.
    CHECK(!has("Content-Type:", 13));

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
}

TEST(route, add_response_header_set_rejects_count_over_per_set_cap) {
    using namespace rut;
    // Above the per-set cap: registration must refuse the set rather
    // than accept it and let the dispatch formatter silently truncate.
    // Use unique key names per slot so we stress the capacity check
    // rather than the duplicate-key check.
    RouteConfig cfg{};
    constexpr u32 kOver = RouteConfig::kMaxHeadersPerSet + 1;
    char key_bufs[kOver][8];
    const char* keys[kOver];
    u32 key_lens[kOver];
    const char* vals[kOver];
    u32 val_lens[kOver];
    for (u32 i = 0; i < kOver; i++) {
        // Format as "K<number>" by hand (no stdlib allowed on hot path).
        key_bufs[i][0] = 'K';
        u32 pos = 1;
        u32 v = i;
        if (v == 0) {
            key_bufs[i][pos++] = '0';
        } else {
            char digits[4];
            u32 d = 0;
            while (v > 0) {
                digits[d++] = static_cast<char>('0' + (v % 10));
                v /= 10;
            }
            for (u32 k = 0; k < d; k++) key_bufs[i][pos++] = digits[d - 1 - k];
        }
        keys[i] = key_bufs[i];
        key_lens[i] = pos;
        vals[i] = "V";
        val_lens[i] = 1;
    }
    CHECK_EQ(cfg.add_response_header_set(keys, key_lens, vals, val_lens, kOver), 0u);
    CHECK_EQ(cfg.response_header_set_count, 0u);
    // At the cap it still succeeds.
    CHECK_EQ(
        cfg.add_response_header_set(keys, key_lens, vals, val_lens, RouteConfig::kMaxHeadersPerSet),
        1u);
}

TEST(route, add_response_header_set_rejects_case_insensitive_duplicate) {
    using namespace rut;
    // Manual RouteConfig path must reject duplicate names the same
    // way the DSL parser does, case-insensitively. Two entries with
    // "X-Foo" / "x-foo" would produce ambiguous singleton headers on
    // the wire, so registration fails up front.
    RouteConfig cfg{};
    const char* keys[2] = {"X-Foo", "x-foo"};
    u32 key_lens[2] = {5, 5};
    const char* vals[2] = {"1", "2"};
    u32 val_lens[2] = {1, 1};
    CHECK_EQ(cfg.add_response_header_set(keys, key_lens, vals, val_lens, 2), 0u);
    CHECK_EQ(cfg.response_header_set_count, 0u);
}

TEST(route, add_response_header_set_rejects_malformed_headers) {
    using namespace rut;
    // The runtime API must reject the same things the DSL parser does:
    // CR in a value (response splitting), invalid key chars (space),
    // and reserved framing names. Manual JIT-handler setups would
    // otherwise bypass the parser-level validation.
    RouteConfig cfg{};
    const char* ok_key = "X-Ok";
    u32 ok_key_len = 4;
    const char* ok_val = "ok";
    u32 ok_val_len = 2;

    // CR in value → rejected.
    const char* crlf_key = "X-Bad";
    u32 crlf_key_len = 5;
    const char* crlf_val = "a\r\nInjected: 1";
    u32 crlf_val_len = 14;
    CHECK_EQ(cfg.add_response_header_set(&crlf_key, &crlf_key_len, &crlf_val, &crlf_val_len, 1),
             0u);

    // Space in key → rejected.
    const char* space_key = "X Bad";
    u32 space_key_len = 5;
    CHECK_EQ(cfg.add_response_header_set(&space_key, &space_key_len, &ok_val, &ok_val_len, 1), 0u);

    // Reserved framing names → rejected.
    const char* cl_key = "Content-Length";
    u32 cl_key_len = 14;
    CHECK_EQ(cfg.add_response_header_set(&cl_key, &cl_key_len, &ok_val, &ok_val_len, 1), 0u);
    const char* te_key = "transfer-encoding";
    u32 te_key_len = 17;
    CHECK_EQ(cfg.add_response_header_set(&te_key, &te_key_len, &ok_val, &ok_val_len, 1), 0u);
    const char* conn_key = "connection";
    u32 conn_key_len = 10;
    CHECK_EQ(cfg.add_response_header_set(&conn_key, &conn_key_len, &ok_val, &ok_val_len, 1), 0u);

    // Confirm no partial state leaked: set count still zero after all
    // the rejected attempts.
    CHECK_EQ(cfg.response_header_set_count, 0u);

    // Valid pair still works afterwards.
    CHECK_EQ(cfg.add_response_header_set(&ok_key, &ok_key_len, &ok_val, &ok_val_len, 1), 1u);
}

TEST(route, add_response_header_set_rejects_null_arguments) {
    using namespace rut;
    // Null-pointer-table guards: any of the four input tables being
    // null with count > 0 returns 0 without touching state. Same for
    // a null data pointer paired with a non-zero length.
    RouteConfig cfg{};
    const char* keys[1] = {"X-Ok"};
    u32 key_lens[1] = {4};
    const char* vals[1] = {"v"};
    u32 val_lens[1] = {1};

    // count == 0 → 0 (explicit short-circuit; no pointers touched).
    CHECK_EQ(cfg.add_response_header_set(keys, key_lens, vals, val_lens, 0), 0u);

    // Each of the four tables being null individually rejects.
    CHECK_EQ(cfg.add_response_header_set(nullptr, key_lens, vals, val_lens, 1), 0u);
    CHECK_EQ(cfg.add_response_header_set(keys, nullptr, vals, val_lens, 1), 0u);
    CHECK_EQ(cfg.add_response_header_set(keys, key_lens, nullptr, val_lens, 1), 0u);
    CHECK_EQ(cfg.add_response_header_set(keys, key_lens, vals, nullptr, 1), 0u);

    // Null data pointer with non-zero length for a pair → 0.
    const char* null_key[1] = {nullptr};
    CHECK_EQ(cfg.add_response_header_set(null_key, key_lens, vals, val_lens, 1), 0u);
    const char* null_val[1] = {nullptr};
    CHECK_EQ(cfg.add_response_header_set(keys, key_lens, null_val, val_lens, 1), 0u);

    CHECK_EQ(cfg.response_header_set_count, 0u);

    // Zero-length key with null pointer still fails the empty-key
    // validator (caught by validate_response_header before the null
    // check hits, but either way rejection is consistent).
    const char* empty_key[1] = {nullptr};
    u32 empty_key_len[1] = {0};
    CHECK_EQ(cfg.add_response_header_set(empty_key, empty_key_len, vals, val_lens, 1), 0u);
}

TEST(route, add_response_header_set_rejects_when_bytes_pool_full) {
    using namespace rut;
    // The bytes pool (header_bytes_pool) is 8 KB. A single pair with
    // key_len + value_len exceeding that cap must be rejected; we
    // can't split header bytes across multiple allocations. The
    // rejection path is the `total_bytes > pool available` guard
    // that runs after validation succeeds.
    RouteConfig cfg{};
    constexpr u32 kHugeVal = 9 * 1024;  // > 8 KB header_bytes_pool
    char big_val_buf[kHugeVal];
    for (u32 i = 0; i < kHugeVal; i++) big_val_buf[i] = 'a';
    const char* keys[1] = {"X-Big"};
    u32 key_lens[1] = {5};
    const char* vals[1] = {big_val_buf};
    u32 val_lens[1] = {kHugeVal};
    CHECK_EQ(cfg.add_response_header_set(keys, key_lens, vals, val_lens, 1), 0u);
    CHECK_EQ(cfg.response_header_set_count, 0u);
    // Modest pair still accepted after the rejected one.
    const char* ok_vals[1] = {"ok"};
    u32 ok_val_lens[1] = {2};
    CHECK_EQ(cfg.add_response_header_set(keys, key_lens, ok_vals, ok_val_lens, 1), 1u);
}

TEST(route, add_response_header_set_rejects_when_kv_array_full) {
    using namespace rut;
    // The (key, value) arrays cap at kMaxHeaderPoolEntries = 512
    // pairs across all sets. If a new set's count would push us past
    // that total, the subtraction-safe check rejects it before any
    // per-pair work.
    RouteConfig cfg{};
    // Fill the pool almost full: 32-pair sets up to kMaxHeaderPoolEntries
    // (512). 512 / 32 = 16 sets of 32, but we also need to stay
    // under kMaxHeaderSets=128 (no risk here). After 15 sets = 480
    // pairs used, a 32-pair set would need 32 more and fit; a 33-pair
    // set would overflow — but per-set cap is already 32, so we'd
    // hit that first. Use unique 1-byte keys so each 32-pair set fits
    // in the bytes pool (~64 bytes per set, well under 8KB).
    constexpr u32 kPerSet = 32;
    for (u32 s = 0; s < 15; s++) {
        char key_bufs[kPerSet][8];
        const char* keys[kPerSet];
        u32 key_lens[kPerSet];
        const char* vals[kPerSet];
        u32 val_lens[kPerSet];
        for (u32 i = 0; i < kPerSet; i++) {
            // Unique across all sets: "K<set>_<i>" encoded as digits.
            u32 pos = 0;
            key_bufs[i][pos++] = 'K';
            // Simple encoding: avoid duplicates by mixing set & index.
            u32 code = s * 32 + i;  // 0..479
            char digits[4];
            u32 d = 0;
            if (code == 0) {
                digits[d++] = '0';
            } else {
                while (code > 0) {
                    digits[d++] = static_cast<char>('0' + (code % 10));
                    code /= 10;
                }
            }
            for (u32 k = 0; k < d; k++) key_bufs[i][pos++] = digits[d - 1 - k];
            keys[i] = key_bufs[i];
            key_lens[i] = pos;
            vals[i] = "v";
            val_lens[i] = 1;
        }
        const u16 idx = cfg.add_response_header_set(keys, key_lens, vals, val_lens, kPerSet);
        REQUIRE_EQ(idx, static_cast<u16>(s + 1));
    }
    // After 15×32 = 480 pairs consumed, a 32-pair set would bring the
    // total to 512 (== kMaxHeaderPoolEntries) — exactly the cap, still
    // accepted. A 33-pair set would overflow but the per-set cap
    // already rejects that earlier. To force the kv-array-full branch
    // without the per-set check catching it first, we submit a 32-pair
    // set after filling to 481+, which we engineer via a 1-pair set.
    const char* one_key[1] = {"Single"};
    u32 one_key_len[1] = {6};
    const char* one_val[1] = {"v"};
    u32 one_val_len[1] = {1};
    REQUIRE_EQ(cfg.add_response_header_set(one_key, one_key_len, one_val, one_val_len, 1), 16u);
    // Pool used = 481. A 32-pair set needs 32 more → 513 > 512.
    // Build a 32-pair set; we expect the kv-array-full branch to fire.
    char overflow_bufs[32][8];
    const char* over_keys[32];
    u32 over_key_lens[32];
    const char* over_vals[32];
    u32 over_val_lens[32];
    for (u32 i = 0; i < 32; i++) {
        overflow_bufs[i][0] = 'Z';
        overflow_bufs[i][1] = static_cast<char>('A' + (i / 10));
        overflow_bufs[i][2] = static_cast<char>('0' + (i % 10));
        over_keys[i] = overflow_bufs[i];
        over_key_lens[i] = 3;
        over_vals[i] = "v";
        over_val_lens[i] = 1;
    }
    CHECK_EQ(cfg.add_response_header_set(over_keys, over_key_lens, over_vals, over_val_lens, 32),
             0u);
    CHECK_EQ(cfg.response_header_set_count, 16u);  // unchanged
}

TEST(http_header_validation, is_http_tchar_covers_all_special_chars) {
    using namespace rut;
    // The tchar grammar accepts alphanum plus 15 special chars. Each
    // case in the switch needs a live hit for full branch coverage;
    // miss any and a future grammar-tightening change could silently
    // drop a character without flagging a test.
    static const u8 kAccepted[] = {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~'};
    for (u8 c : kAccepted) {
        CHECK(is_http_tchar(c));
    }
    // Spot-check the default branch: anything outside tchar is
    // rejected. Cover a control char, space, and the separators the
    // HTTP grammar explicitly excludes.
    static const u8 kRejected[] = {0x00, 0x1f, ' ', '(', ')', '<', '>', '@', ',', ';', ':',
                                   '\\', '"',  '/', '[', ']', '?', '=', '{', '}', 0x7f};
    for (u8 c : kRejected) {
        CHECK(!is_http_tchar(c));
    }
}

TEST(http_header_validation, validate_response_header_accepts_tab_in_value) {
    using namespace rut;
    // Horizontal tab is permitted inside header values per RFC 7230.
    // No other test hits this branch directly; without this the
    // "c == '\t' continue" line stays uncovered.
    const char* key = "X-Traced";
    const char* val = "a\tb";
    CHECK_EQ(validate_response_header(key, 8, val, 3), HttpHeaderValidation::Ok);
}

TEST(http_header_validation, http_header_name_eq_ci_length_mismatch) {
    using namespace rut;
    // Early-out on length mismatch is its own branch — cover it so a
    // future refactor that replaces the early-out can't silently drop
    // safety.
    CHECK(!http_header_name_eq_ci("Host", 4, "Hostname", 8));
    CHECK(!http_header_name_eq_ci("X", 1, "", 0));
}

#if RUT_ENABLE_JIT_TESTS
// End-to-end: compile `route GET "/x" { return response(200, body: "Hi!") }`
// from source, populate RouteConfig.response_bodies from the compiled
// rir::Module, and verify a real client receives the exact body.
TEST(route, dsl_response_body_real_socket) {
    using namespace rut;

    const char* src = "route GET \"/x\" { return response(200, body: \"Hi!\") }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    // Mirror the module's body table (1-based) into cfg. This loop is
    // what a future compile→RouteConfig helper will do in production.
    REQUIRE_EQ(rir.module.response_body_count, 1u);
    for (u32 i = 0; i < rir.module.response_body_count; i++) {
        const auto& body = rir.module.response_bodies[i];
        const u16 idx = cfg.add_response_body(body.ptr, body.len);
        REQUIRE_EQ(idx, static_cast<u16>(i + 1));
    }
    REQUIRE(cfg.add_jit_handler("/x", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    const char kReq[] = "GET /x HTTP/1.1\r\nHost: x\r\n\r\n";
    send_all(c, kReq, sizeof(kReq) - 1);
    char buf[2048];
    i32 n = recv_timeout(c, buf, sizeof(buf), 1000);
    CHECK_GT(n, 0);
    const Str response{buf, static_cast<u32>(n)};
    auto has = [&](const char* needle, u32 nlen) {
        return buf_contains(
            reinterpret_cast<const char*>(response.ptr), response.len, needle, nlen);
    };
    CHECK(has("200 OK", 6));
    CHECK(has("Content-Length: 3\r\n", 19));
    CHECK(has("Content-Type: text/plain", 24));
    CHECK(has("\r\n\r\nHi!", 7));

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

// End-to-end: compile a route with custom headers (user-supplied
// Content-Type must suppress the default text/plain) and assert the
// real-socket response contains exactly what we expect. Reserved
// framing headers (Content-Length / Transfer-Encoding / Connection)
// are rejected at parse time — see parse_return_response_rejects_
// reserved_header_names in test_frontend.cc.
TEST(route, dsl_response_headers_real_socket) {
    using namespace rut;

    const char* src =
        "route GET \"/x\" { return response(200, body: \"hello-json\", headers: "
        "{ \"Content-Type\": \"application/json\", "
        "\"X-Service\": \"auth\" }) }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    REQUIRE_EQ(rir.module.response_body_count, 1u);
    for (u32 i = 0; i < rir.module.response_body_count; i++) {
        const auto& body = rir.module.response_bodies[i];
        const u16 idx = cfg.add_response_body(body.ptr, body.len);
        REQUIRE_EQ(idx, static_cast<u16>(i + 1));
    }
    // Mirror header sets from rir::Module into RouteConfig the same
    // way bodies are mirrored above (1-based index preserved).
    REQUIRE_EQ(rir.module.header_set_count, 1u);
    for (u32 i = 0; i < rir.module.header_set_count; i++) {
        const auto& ref = rir.module.header_sets[i];
        const char* keys[16];
        u32 key_lens[16];
        const char* vals[16];
        u32 val_lens[16];
        REQUIRE(ref.count <= 16u);
        for (u16 j = 0; j < ref.count; j++) {
            keys[j] = rir.module.header_keys[ref.offset + j].ptr;
            key_lens[j] = rir.module.header_keys[ref.offset + j].len;
            vals[j] = rir.module.header_values[ref.offset + j].ptr;
            val_lens[j] = rir.module.header_values[ref.offset + j].len;
        }
        const u16 idx = cfg.add_response_header_set(keys, key_lens, vals, val_lens, ref.count);
        REQUIRE_EQ(idx, static_cast<u16>(i + 1));
    }
    REQUIRE(cfg.add_jit_handler("/x", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    const char kReq[] = "GET /x HTTP/1.1\r\nHost: x\r\n\r\n";
    send_all(c, kReq, sizeof(kReq) - 1);
    char buf[2048];
    i32 n = recv_timeout(c, buf, sizeof(buf), 1000);
    CHECK_GT(n, 0);
    const Str response{buf, static_cast<u32>(n)};
    auto has = [&](const char* needle, u32 nlen) {
        return buf_contains(
            reinterpret_cast<const char*>(response.ptr), response.len, needle, nlen);
    };
    // Body is exactly 10 bytes (`hello-json`), and the formatter
    // recomputes Content-Length from that.
    CHECK(has("200 OK", 6));
    CHECK(has("Content-Length: 10\r\n", 20));
    // User's Content-Type wins; default text/plain is suppressed.
    CHECK(has("Content-Type: application/json\r\n", 32));
    CHECK(!has("text/plain", 10));
    // Other user header is emitted verbatim.
    CHECK(has("X-Service: auth\r\n", 17));
    // Body bytes at the end: 4 CRLF + 10 body = 14 bytes.
    CHECK(has("\r\n\r\nhello-json", 14));

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

// Redirect-style: headers without body. Verify Content-Length: 0,
// the Location header is emitted, and no body bytes follow.
TEST(route, dsl_response_headers_only_real_socket) {
    using namespace rut;

    const char* src =
        "route GET \"/old\" { return response(301, headers: "
        "{ \"Location\": \"/new\" }) }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    CHECK_EQ(rir.module.response_body_count, 0u);
    REQUIRE_EQ(rir.module.header_set_count, 1u);
    const auto& ref = rir.module.header_sets[0];
    const char* keys[4];
    u32 key_lens[4];
    const char* vals[4];
    u32 val_lens[4];
    REQUIRE(ref.count <= 4u);
    for (u16 j = 0; j < ref.count; j++) {
        keys[j] = rir.module.header_keys[ref.offset + j].ptr;
        key_lens[j] = rir.module.header_keys[ref.offset + j].len;
        vals[j] = rir.module.header_values[ref.offset + j].ptr;
        val_lens[j] = rir.module.header_values[ref.offset + j].len;
    }
    REQUIRE_EQ(cfg.add_response_header_set(keys, key_lens, vals, val_lens, ref.count), 1u);
    REQUIRE(cfg.add_jit_handler("/old", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    const char kReq[] = "GET /old HTTP/1.1\r\nHost: x\r\n\r\n";
    send_all(c, kReq, sizeof(kReq) - 1);
    char buf[2048];
    i32 n = recv_timeout(c, buf, sizeof(buf), 1000);
    CHECK_GT(n, 0);
    const Str response{buf, static_cast<u32>(n)};
    auto has = [&](const char* needle, u32 nlen) {
        return buf_contains(
            reinterpret_cast<const char*>(response.ptr), response.len, needle, nlen);
    };
    CHECK(has("301 ", 4));
    CHECK(has("Content-Length: 0\r\n", 19));
    CHECK(has("Location: /new\r\n", 16));
    // Response must terminate exactly at the blank line — the last
    // four bytes must be "\r\n\r\n" and nothing else should follow.
    // Substring-containment alone wouldn't catch a stray body payload
    // appended after the terminator.
    REQUIRE_GE(response.len, 4u);
    CHECK_EQ(response.ptr[response.len - 4], '\r');
    CHECK_EQ(response.ptr[response.len - 3], '\n');
    CHECK_EQ(response.ptr[response.len - 2], '\r');
    CHECK_EQ(response.ptr[response.len - 1], '\n');

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

// End-to-end DSL forward: compile `upstream backend route GET "/api"
// { return forward(backend) }`, register the upstream in RouteConfig
// pointing at 127.0.0.1:9999 (nothing listening → ECONNREFUSED),
// and assert the client sees a 502. This proves the full compile
// pipeline wired `return forward(<ident>)` through HIR/MIR/RIR/codegen
// into HandlerAction::Forward, and the runtime dispatched it onto the
// proxy connect path (mirrors forward_jit_handler_enters_proxy_state
// but starts from DSL source instead of a hand-written handler).
TEST(route, dsl_return_forward_enters_proxy_state) {
    using namespace rut;

    const char* src = "upstream backend\nroute GET \"/api\" { return forward(backend) }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    // Register the upstream at index 0 so it matches the DSL's
    // compile-time upstream_index. 9999 has nothing listening; the
    // connect will ECONNREFUSED and the proxy path will 502. The
    // assertion we care about is "502 came back", which proves the
    // DSL-compiled handler really returned Forward rather than
    // accidentally falling through to 200 or 500.
    REQUIRE(cfg.add_upstream("backend", 0x7F000001, 9999).has_value());
    REQUIRE(cfg.add_jit_handler("/api", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    const char kReq[] = "GET /api HTTP/1.1\r\nHost: x\r\n\r\n";
    send_all(c, kReq, sizeof(kReq) - 1);
    // Read until the status line is complete. Loopback typically
    // returns everything in one recv, but TCP is free to fragment,
    // so loop until we see the "\r\n" that terminates the status
    // line (or the buffer fills / timeout). That makes the
    // "HTTP/1.1 502" assertion below robust against split-recv.
    char buf[1024];
    i32 total = 0;
    while (total < static_cast<i32>(sizeof(buf))) {
        i32 n = recv_timeout(c, buf + total, sizeof(buf) - total, 500);
        if (n <= 0) break;
        total += n;
        if (buf_contains(buf, static_cast<u32>(total), "\r\n", 2)) break;
    }
    CHECK_GT(total, 0);
    const Str response{buf, static_cast<u32>(total)};
    auto has = [&](const char* needle, u32 nlen) {
        return buf_contains(
            reinterpret_cast<const char*>(response.ptr), response.len, needle, nlen);
    };
    // Match the full status line — "502" alone could hit a timestamp,
    // a header value, or a body byte pattern. Locking in "HTTP/1.1 502"
    // makes the assertion about the status line specifically.
    CHECK(has("HTTP/1.1 502", 12));

    close(c);
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}
#endif

// populate_route_config requires bodies / header sets / routes to
// start empty (there's no merge semantics). Upstreams are more
// flexible: either empty (helper binds from the module) or exactly
// mod.upstream_count (caller pre-bound, helper verifies + just
// populates bodies/headers). Anything else — partial bodies, partial
// routes, partial header sets, or upstream_count mismatch — rejects.
TEST(route, populate_route_config_rejects_partial_cfg) {
    using namespace rut;
    FrontendRirModule rir{};
    REQUIRE(rir.init(1, 8));
    RouteConfig cfg_with_route{};
    REQUIRE(cfg_with_route.add_static("/x", 0, 200));
    CHECK(!populate_route_config(cfg_with_route, rir.module));
    // upstream_count == 1 but module has 0 → mismatch, reject.
    RouteConfig cfg_upstream_mismatch{};
    REQUIRE(cfg_upstream_mismatch.add_upstream("x", 0x7F000001, 1).has_value());
    CHECK(!populate_route_config(cfg_upstream_mismatch, rir.module));
    RouteConfig cfg_with_body{};
    REQUIRE_EQ(cfg_with_body.add_response_body("hi", 2), 1u);
    CHECK(!populate_route_config(cfg_with_body, rir.module));
    RouteConfig cfg_with_headers{};
    const char* keys[1] = {"X-Foo"};
    u32 klens[1] = {5};
    const char* vals[1] = {"v"};
    u32 vlens[1] = {1};
    REQUIRE_EQ(cfg_with_headers.add_response_header_set(keys, klens, vals, vlens, 1), 1u);
    CHECK(!populate_route_config(cfg_with_headers, rir.module));
    rir.destroy();
}

// Pre-bound upstream mode: caller registers upstreams manually (e.g.
// because the DSL declared them name-only, addresses come from a
// runtime config file), then the helper fills in bodies / header
// sets only. This is the workflow the reviewer called out as a
// first-class use case.
TEST(route, populate_route_config_accepts_pre_bound_upstreams) {
    using namespace rut;
    const char* src =
        "upstream backend\n"
        "route GET \"/api\" { return forward(backend) }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    REQUIRE_EQ(rir.module.upstream_count, 1u);
    CHECK(!rir.module.upstreams[0].has_address);  // name-only

    RouteConfig cfg{};
    // Caller binds the upstream manually — same name, in DSL order.
    REQUIRE(cfg.add_upstream("backend", 0x7F000001, 8080).has_value());
    // Helper accepts the pre-bound cfg (upstream_count matches) and
    // returns true even though the module had a name-only upstream.
    CHECK(populate_route_config(cfg, rir.module));
    // The manually-bound address is untouched.
    CHECK_EQ(cfg.upstreams[0].addr.sin_port, __builtin_bswap16(8080));
    rir.destroy();
}

// Pre-bound mode with a name mismatch: caller populated cfg in the
// wrong order / with wrong names. Helper verifies name-for-name
// (ASCII case-sensitive) and rejects so forward() can't resolve to
// the wrong backend silently.
TEST(route, populate_route_config_rejects_pre_bound_name_mismatch) {
    using namespace rut;
    const char* src =
        "upstream backend\n"
        "route GET \"/api\" { return forward(backend) }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);

    RouteConfig cfg{};
    // Wrong name ("other" vs DSL's "backend"). upstream_count matches,
    // so the shape check passes, but the per-slot name compare fails.
    REQUIRE(cfg.add_upstream("other", 0x7F000001, 8080).has_value());
    CHECK(!populate_route_config(cfg, rir.module));
    rir.destroy();
}

// Pre-bound mode: a module upstream with a name longer than the cfg
// can hold (kMaxUpstreamNameLen - 1 = 31 bytes) can't round-trip
// through set_name without truncation. Two such names with the same
// first 31 bytes would compare equal after truncation, letting a
// caller pre-bind in the wrong order and slip past the verification.
// Helper rejects over-long names up front in pre-bound mode to close
// that gap.
TEST(route, populate_route_config_rejects_pre_bound_over_long_name) {
    using namespace rut;
    // 32 bytes — one past the 31-byte cap. Build at compile time so
    // the DSL source is deterministic.
    const char* src =
        "upstream "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"  // 32 'a's
        "route GET \"/api\" { return forward(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    REQUIRE_EQ(rir.module.upstream_count, 1u);
    REQUIRE_EQ(rir.module.upstreams[0].name.len, 32u);

    RouteConfig cfg{};
    // Caller pre-binds using the truncated name (what set_name would
    // store anyway). Under the old comparison this would have matched
    // the truncated module name and incorrectly accepted the config.
    REQUIRE(cfg.add_upstream("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  // 31 'a's
                             0x7F000001,
                             8080)
                .has_value());
    CHECK(!populate_route_config(cfg, rir.module));
    rir.destroy();
}

#if RUT_ENABLE_JIT_TESTS
TEST(route, register_jit_routes_selects_segment_trie_and_adds_param_route) {
    using namespace rut;
    const char* src =
        "route GET \"/users/:id\" { if req.param(\"id\") == \"42\" { return 201 } else { return "
        "404 } }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);

    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, rir.module));
    REQUIRE(register_jit_routes(cfg, rir.module, engine));
    CHECK_EQ(cfg.dispatch_kind(), RouteConfig::DispatchKind::SegmentTrie);
    REQUIRE_EQ(cfg.route_count, 1u);
    CHECK_EQ(cfg.routes[0].action, RouteAction::JitHandler);
    CHECK_FALSE(cfg.routes[0].needs_req_body);

    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    const auto* matched = cfg.match_canonical(
        Str{"users/42", 8}, kRouteMethodGet, params, &param_count, kMaxRouteParams);
    REQUIRE(matched != nullptr);
    CHECK_EQ(matched, &cfg.routes[0]);
    REQUIRE_EQ(param_count, 1u);
    CHECK((Str{params[0].name, params[0].name_len}.eq(Str{"id", 2})));
    CHECK((Str{params[0].value, params[0].value_len}.eq(Str{"42", 2})));

    engine.shutdown();
    rir.destroy();
}

TEST(route, register_jit_routes_marks_req_body_dependency) {
    using namespace rut;
    const char* src =
        "route POST \"/upload\" { if req.body == \"payload\" { return 204 } else { return 400 } "
        "}\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);

    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, rir.module));
    REQUIRE(register_jit_routes(cfg, rir.module, engine));
    REQUIRE_EQ(cfg.route_count, 1u);
    CHECK(cfg.routes[0].needs_req_body);

    engine.shutdown();
    rir.destroy();
}

TEST(route, req_param_jit_handler_real_socket) {
    using namespace rut;
    const char* src =
        "route GET \"/users/:id\" { if req.param(\"id\") == \"42\" { return 201 } else { return "
        "404 } }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);

    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, rir.module));
    REQUIRE(register_jit_routes(cfg, rir.module, engine));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 200};
    lt.start();
    usleep(10000);

    auto check_status = [&](const char* req, u32 req_len, const char* status) {
        i32 c = connect_to(port);
        REQUIRE(c >= 0);
        REQUIRE(send_all(c, req, req_len));
        char buf[1024];
        i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
        CHECK_GT(n, 0);
        bool found = false;
        for (i32 i = 0; i + 2 < n; i++) {
            if (buf[i] == status[0] && buf[i + 1] == status[1] && buf[i + 2] == status[2]) {
                found = true;
                break;
            }
        }
        CHECK(found);
        close(c);
    };

    const char kHitReq[] = "GET /users/42 HTTP/1.1\r\nHost: x\r\n\r\n";
    check_status(kHitReq, sizeof(kHitReq) - 1, "201");
    const char kMissReq[] = "GET /users/41 HTTP/1.1\r\nHost: x\r\n\r\n";
    check_status(kMissReq, sizeof(kMissReq) - 1, "404");

    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

TEST(route, req_header_jit_handler_real_socket) {
    using namespace rut;
    const char* src =
        "route GET \"/auth\" { let token = or(req.header(\"Authorization\"), \"\") if token == "
        "\"Bearer ok\" { return 204 } else { return 401 } }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);

    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, rir.module));
    REQUIRE(register_jit_routes(cfg, rir.module, engine));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 200};
    lt.start();
    usleep(10000);

    auto check_status = [&](const char* req, u32 req_len, const char* status) {
        i32 c = connect_to(port);
        REQUIRE(c >= 0);
        REQUIRE(send_all(c, req, req_len));
        char buf[1024];
        i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
        CHECK_GT(n, 0);
        bool found = false;
        for (i32 i = 0; i + 2 < n; i++) {
            if (buf[i] == status[0] && buf[i + 1] == status[1] && buf[i + 2] == status[2]) {
                found = true;
                break;
            }
        }
        CHECK(found);
        close(c);
    };

    const char kHitReq[] = "GET /auth HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ok\r\n\r\n";
    check_status(kHitReq, sizeof(kHitReq) - 1, "204");
    const char kBadReq[] = "GET /auth HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer nope\r\n\r\n";
    check_status(kBadReq, sizeof(kBadReq) - 1, "401");
    const char kMissingReq[] = "GET /auth HTTP/1.1\r\nHost: x\r\n\r\n";
    check_status(kMissingReq, sizeof(kMissingReq) - 1, "401");

    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

TEST(route, req_cookie_jit_handler_real_socket) {
    using namespace rut;
    const char* src =
        "route GET \"/session\" { let sid = or(req.cookie(\"sid\"), \"\") if sid == \"ok\" { "
        "return 204 } else { return 401 } }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);

    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, rir.module));
    REQUIRE(register_jit_routes(cfg, rir.module, engine));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 200};
    lt.start();
    usleep(10000);

    auto check_status = [&](const char* req, u32 req_len, const char* status) {
        i32 c = connect_to(port);
        REQUIRE(c >= 0);
        REQUIRE(send_all(c, req, req_len));
        char buf[1024];
        i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
        CHECK_GT(n, 0);
        bool found = false;
        for (i32 i = 0; i + 2 < n; i++) {
            if (buf[i] == status[0] && buf[i + 1] == status[1] && buf[i + 2] == status[2]) {
                found = true;
                break;
            }
        }
        CHECK(found);
        close(c);
    };

    const char kHitReq[] =
        "GET /session HTTP/1.1\r\nHost: x\r\nCookie: theme=dark; sid=ok; lang=en\r\n\r\n";
    check_status(kHitReq, sizeof(kHitReq) - 1, "204");
    const char kBadReq[] =
        "GET /session HTTP/1.1\r\nHost: x\r\nCookie: theme=dark; sid=nope\r\n\r\n";
    check_status(kBadReq, sizeof(kBadReq) - 1, "401");
    const char kMissingReq[] = "GET /session HTTP/1.1\r\nHost: x\r\nCookie: theme=dark\r\n\r\n";
    check_status(kMissingReq, sizeof(kMissingReq) - 1, "401");

    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

TEST(route, req_query_jit_handler_real_socket) {
    using namespace rut;
    const char* src =
        "route GET \"/search\" { let q = req.query(\"q\") let value = or(q, \"\") if value == "
        "\"rut\" { return 204 } else { "
        "return 401 } }\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);

    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));

    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, rir.module));
    REQUIRE(register_jit_routes(cfg, rir.module, engine));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 200};
    lt.start();
    usleep(10000);

    auto check_status = [&](const char* req, u32 req_len, const char* status) {
        i32 c = connect_to(port);
        REQUIRE(c >= 0);
        REQUIRE(send_all(c, req, req_len));
        char buf[1024];
        i32 n = recv_timeout(c, buf, sizeof(buf), 2000);
        CHECK_GT(n, 0);
        bool found = false;
        for (i32 i = 0; i + 2 < n; i++) {
            if (buf[i] == status[0] && buf[i + 1] == status[1] && buf[i + 2] == status[2]) {
                found = true;
                break;
            }
        }
        CHECK(found);
        close(c);
    };

    const char kHitReq[] = "GET /search?q=rut HTTP/1.1\r\nHost: x\r\n\r\n";
    check_status(kHitReq, sizeof(kHitReq) - 1, "204");
    const char kMissReq[] = "GET /search?q=cpp HTTP/1.1\r\nHost: x\r\n\r\n";
    check_status(kMissReq, sizeof(kMissReq) - 1, "401");
    const char kMissingReq[] = "GET /search HTTP/1.1\r\nHost: x\r\n\r\n";
    check_status(kMissingReq, sizeof(kMissingReq) - 1, "401");

    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}
#endif

#if RUT_ENABLE_JIT_TESTS
// End-to-end: compile DSL with an address-carrying `upstream` decl and
// let populate_route_config bind the RouteConfig. Since no real backend
// is listening on the compiled port, the forward will ECONNREFUSED and
// the client will get 502 — which proves:
//   1. `upstream X at "127.0.0.1:NNN"` parses + validates + lowers.
//   2. populate_route_config called add_upstream with the compiled
//      (ip, port) — otherwise the runtime would have had no upstream
//      entry and returned some other error.
TEST(route, populate_route_config_binds_upstream_from_dsl) {
    using namespace rut;

    // Reserve an ephemeral port for the "unreachable backend". Hard-
    // coding 9999 would be flaky: if the CI runner already has
    // something listening there, the test would behave differently.
    // Bind (but don't listen) on 127.0.0.1:0 so the kernel picks a
    // free port, capture it, keep the socket open for the duration
    // of the test so no other process can steal it, and feed the
    // number into the DSL source. Connect attempts during the test
    // get ECONNREFUSED — exactly the "no backend is listening"
    // behaviour we want to drive.
    //
    // Guard closes the fd on scope exit so an early REQUIRE failure
    // (before the explicit close at the bottom) doesn't leak the
    // reserved socket and starve subsequent tests of ephemeral ports.
    struct FdGuard {
        i32 fd;
        ~FdGuard() {
            if (fd >= 0) close(fd);
        }
    };
    FdGuard reserve{socket(AF_INET, SOCK_STREAM, 0)};
    REQUIRE_GE(reserve.fd, 0);
    const i32 reserve_fd = reserve.fd;
    struct sockaddr_in reserve_addr{};
    reserve_addr.sin_family = AF_INET;
    reserve_addr.sin_addr.s_addr = __builtin_bswap32(0x7F000001u);
    reserve_addr.sin_port = 0;
    REQUIRE_EQ(
        bind(reserve_fd, reinterpret_cast<struct sockaddr*>(&reserve_addr), sizeof(reserve_addr)),
        0);
    struct sockaddr_in got{};
    socklen_t got_len = sizeof(got);
    REQUIRE_EQ(getsockname(reserve_fd, reinterpret_cast<struct sockaddr*>(&got), &got_len), 0);
    const u16 upstream_port = __builtin_bswap16(got.sin_port);

    char src_buf[256];
    const int src_len = snprintf(src_buf,
                                 sizeof(src_buf),
                                 "upstream backend at \"127.0.0.1:%u\"\n"
                                 "route GET \"/api\" { return forward(backend) }\n",
                                 upstream_port);
    REQUIRE(src_len > 0 && src_len < static_cast<int>(sizeof(src_buf)));
    auto lexed = lex(Str{src_buf, static_cast<u32>(src_len)});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    // RIR module carries the declared upstream with its address.
    REQUIRE_EQ(rir.module.upstream_count, 1u);
    CHECK(rir.module.upstreams[0].has_address);
    CHECK_EQ(rir.module.upstreams[0].ip, 0x7F000001u);
    CHECK_EQ(rir.module.upstreams[0].port, upstream_port);

    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    // The helper walks mod.upstreams / response_bodies / header_sets
    // and calls the corresponding cfg.add_* methods. For this test
    // only the upstream gets populated; routes still need to be
    // registered explicitly (they depend on the JIT-compiled fn).
    REQUIRE(populate_route_config(cfg, rir.module));
    // Strong assertion that the helper actually bound the DSL upstream:
    // the slot must exist, be at the same index the compiler emits,
    // carry the DSL name verbatim, and resolve to the declared address.
    // Without these, a "not-found → 502" could masquerade as the
    // "connect refused → 502" below and let this test pass spuriously.
    REQUIRE_EQ(cfg.upstream_count, 1u);
    CHECK_EQ(cfg.upstreams[0].name_len, 7u);
    const Str actual_name{cfg.upstreams[0].name, 7u};
    const Str expected_name{"backend", 7u};
    CHECK(actual_name.eq(expected_name));
    CHECK_EQ(cfg.upstreams[0].addr.sin_port, __builtin_bswap16(upstream_port));
    CHECK_EQ(cfg.upstreams[0].addr.sin_addr.s_addr, __builtin_bswap32(0x7F000001));
    REQUIRE(cfg.add_jit_handler("/api", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();

    i32 c = connect_to(port);
    REQUIRE(c >= 0);
    const char kReq[] = "GET /api HTTP/1.1\r\nHost: x\r\n\r\n";
    send_all(c, kReq, sizeof(kReq) - 1);
    char buf[1024];
    i32 total = 0;
    while (total < static_cast<i32>(sizeof(buf))) {
        i32 n = recv_timeout(c, buf + total, sizeof(buf) - total, 500);
        if (n <= 0) break;
        total += n;
        if (buf_contains(buf, static_cast<u32>(total), "\r\n", 2)) break;
    }
    CHECK_GT(total, 0);
    const Str response{buf, static_cast<u32>(total)};
    // Connect to 127.0.0.1:<reserved port> fails with ECONNREFUSED
    // (nothing listening because reserve_fd never called listen()) →
    // 502. If populate_route_config had NOT populated the upstream,
    // the runtime's upstream_id lookup would have failed earlier and
    // the error shape would differ (still 502 today, but the branch
    // is different). The upstream_count / name / (ip, port) asserts
    // above are the strong evidence that the DSL-compiled address
    // reached cfg.
    CHECK(buf_contains(
        reinterpret_cast<const char*>(response.ptr), response.len, "HTTP/1.1 502", 12));

    close(c);
    // reserve_fd is closed by FdGuard at scope exit.
    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}
#endif

#if RUT_ENABLE_JIT_TESTS
// End-to-end: `guard req.method == POST else { return 405 }` inside a
// DSL handler. Registers the handler with method=0 so both GET and
// POST reach it — the guard (not RouteConfig's method filter) is what
// discriminates. Asserts POST → 200, GET → 405.
TEST(route, dsl_req_method_guard_real_socket) {
    using namespace rut;

    const char* src =
        "route POST \"/x\" { "
        "guard req.method == POST else { return 405 } "
        "return 200 "
        "}\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    // method=0 means "any method" — both GET and POST requests reach
    // the handler so the DSL-level guard is what we're actually
    // exercising. The DSL's `route POST` token is irrelevant here.
    REQUIRE(cfg.add_jit_handler("/x", 0, handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();
    usleep(10000);  // let accept registration settle before the first client connect

    // Helper: send one request and record response + pass/fail
    // against expected substrings. Uses CHECK (not REQUIRE) and
    // guards socket use behind fd >= 0 so lt.stop() still runs at
    // the end — REQUIRE's early-return would leak the loop thread.
    auto exercise = [&](const char* req,
                        u32 req_len,
                        const char* want,
                        u32 want_len,
                        const char* reject,
                        u32 reject_len) {
        const i32 c = connect_to(port);
        CHECK_GE(c, 0);
        if (c < 0) return;
        send_all(c, req, req_len);
        char buf[2048];
        const i32 n = recv_timeout(c, buf, sizeof(buf), 1000);
        close(c);
        CHECK_GT(n, 0);
        if (n <= 0) return;
        const auto len = static_cast<u32>(n);
        CHECK(buf_contains(buf, len, want, want_len));
        CHECK(!buf_contains(buf, len, reject, reject_len));
    };

    // POST /x → guard passes → 200 OK.
    const char kPostReq[] = "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
    exercise(kPostReq, sizeof(kPostReq) - 1, "200 OK", 6, "405", 3);

    // GET /x → guard fails → 405.
    const char kGetReq[] = "GET /x HTTP/1.1\r\nHost: x\r\n\r\n";
    exercise(kGetReq, sizeof(kGetReq) - 1, "405", 3, "200 OK", 6);

    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}

TEST(route, dsl_regex_guard_real_socket) {
    using namespace rut;

    const char* src =
        "route GET \"/api/users\" { "
        "guard req.path.matches(re\"^/api/users$\") else { return 404 } "
        "return 200 "
        "}\n";
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    REQUIRE(lexed);
    auto ast = parse_file(lexed.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    REQUIRE(hir);
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    REQUIRE(mir);
    std::unique_ptr<MirModule> mir_owned(mir.value());
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir_owned, rir);
    REQUIRE(lowered);
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    auto handler_fn = reinterpret_cast<jit::HandlerFn>(engine.lookup("handler_route_0"));
    REQUIRE(handler_fn != nullptr);

    RouteConfig cfg{};
    REQUIRE(cfg.add_jit_handler("/api/users", 'G', handler_fn));
    const RouteConfig* active = &cfg;

    RealLoop* loop = create_real_loop();
    REQUIRE(loop != nullptr);
    auto lfd_result = create_listen_socket(0);
    REQUIRE(lfd_result.has_value());
    i32 lfd = lfd_result.value();
    u16 port = get_port(lfd);
    REQUIRE(loop->init(0, lfd).has_value());
    loop->config_ptr = &active;
    LoopThread lt = {loop, {}, 100};
    lt.start();
    usleep(10000);

    auto exercise = [&](const char* req, u32 req_len, const char* want, u32 want_len) {
        const i32 c = connect_to(port);
        CHECK_GE(c, 0);
        if (c < 0) return;
        send_all(c, req, req_len);
        char buf[2048];
        const i32 n = recv_timeout(c, buf, sizeof(buf), 1000);
        close(c);
        CHECK_GT(n, 0);
        if (n <= 0) return;
        CHECK(buf_contains(buf, static_cast<u32>(n), want, want_len));
    };

    const char kMatchReq[] = "GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n";
    exercise(kMatchReq, sizeof(kMatchReq) - 1, "200 OK", 6);

    const char kQueryReq[] = "GET /api/users?x=1 HTTP/1.1\r\nHost: x\r\n\r\n";
    exercise(kQueryReq, sizeof(kQueryReq) - 1, "404", 3);

    lt.stop();
    loop->shutdown();
    close(lfd);
    destroy_real_loop(loop);
    engine.shutdown();
    rir.destroy();
}
#endif

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
