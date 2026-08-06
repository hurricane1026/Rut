// Graceful shutdown + connection draining tests.
#include "rut/runtime/drain.h"
#include "rut/runtime/event_loop.h"
#include "test.h"
#include "test_helpers.h"

// ============================================================
// Helpers
// ============================================================

// Search for a substring in a Buffer's data.
static bool buf_contains(const Buffer& buf, const char* needle) {
    const char* data = reinterpret_cast<const char*>(buf.data());
    rut::u32 len = buf.len();
    rut::u32 nlen = 0;
    while (needle[nlen]) nlen++;
    if (nlen == 0 || nlen > len) return false;
    for (rut::u32 i = 0; i + nlen <= len; i++) {
        bool match = true;
        for (rut::u32 j = 0; j < nlen; j++) {
            if (data[i + j] != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// Write an HTTP response string into conn's upstream_recv_buf and dispatch
// the UpstreamRecv event. Unlike inject_upstream_response() in test_helpers.h,
// this takes an arbitrary response string (for testing header rewriting).
// Returns false if the response doesn't fit in the buffer.
static bool inject_custom_upstream_resp(SmallLoop& loop, Connection& c, const char* resp) {
    c.upstream_recv_buf.reset();
    rut::u32 resp_len = 0;
    while (resp[resp_len]) resp_len++;
    if (resp_len > c.upstream_recv_buf.write_avail()) return false;
    rut::u8* dst = c.upstream_recv_buf.write_ptr();
    for (rut::u32 i = 0; i < resp_len; i++) dst[i] = static_cast<rut::u8>(resp[i]);
    c.upstream_recv_buf.commit(resp_len);

    IoEvent ev = make_ev(c.id, IoEventType::UpstreamRecv, static_cast<rut::i32>(resp_len));
    loop.backend.inject(ev);
    IoEvent events[8];
    rut::u32 n = loop.backend.wait(events, 8);
    for (rut::u32 i = 0; i < n; i++) loop.dispatch(events[i]);
    return true;
}

// ============================================================
// Fixture: SmallLoop wired for drain + proxy
// ============================================================

// Covers: accept → recv → proxy wire → connect → forward request.
struct DrainProxyF {
    SmallLoop loop;
    Connection* c = nullptr;
    rut::u32 cid = 0;

    void SetUp() {
        loop.setup();
        loop.draining = true;
    }
    void TearDown() {}

    // Wire the proxy path. Returns false if accept/recv failed.
    bool wire_proxy() {
        loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
        c = loop.find_fd(42);
        if (!c) return false;
        cid = c->id;
        loop.inject_and_dispatch(make_ev(cid, IoEventType::Recv, 100));
        c->upstream_fd = 99;
        c->on_upstream_send = &on_upstream_connected<SmallLoop>;
        loop.inject_and_dispatch(make_ev(cid, IoEventType::UpstreamConnect, 0));
        rut::u32 req_len = c->recv_buf.len();
        loop.inject_and_dispatch(
            make_ev(cid, IoEventType::UpstreamSend, static_cast<rut::i32>(req_len)));
        return true;
    }
};

// === DrainConfig defaults ===

TEST(drain_config, defaults) {
    rut::DrainConfig cfg;
    CHECK_EQ(cfg.period_secs, 30u);
}

// === should_drain_close ===

TEST(drain_prob, always_true_at_deadline) {
    // At elapsed == period, every connection should close.
    for (rut::u32 id = 0; id < 100; id++) {
        CHECK(rut::should_drain_close(id, 1000, 1030, 30));
    }
}

TEST(drain_prob, always_true_past_deadline) {
    for (rut::u32 id = 0; id < 100; id++) {
        CHECK(rut::should_drain_close(id, 1000, 1100, 30));
    }
}

TEST(drain_prob, always_true_zero_period) {
    for (rut::u32 id = 0; id < 100; id++) {
        CHECK(rut::should_drain_close(id, 1000, 1000, 0));
    }
}

TEST(drain_prob, none_at_start) {
    // At elapsed == 0, threshold < 0 is never true → no closes.
    rut::u32 closed = 0;
    for (rut::u32 id = 0; id < 1000; id++) {
        if (rut::should_drain_close(id, 1000, 1000, 30)) closed++;
    }
    CHECK_EQ(closed, 0u);
}

TEST(drain_prob, increases_over_time) {
    // At 10% through, ~10% should close. At 50%, ~50%.
    // Use large sample for statistical stability.
    auto count_closes = [](rut::u64 elapsed, rut::u32 period) {
        rut::u32 closed = 0;
        for (rut::u32 id = 0; id < 10000; id++) {
            if (rut::should_drain_close(id, 0, elapsed, period)) closed++;
        }
        return closed;
    };

    rut::u32 at_10pct = count_closes(3, 30);   // 10%
    rut::u32 at_50pct = count_closes(15, 30);  // 50%
    rut::u32 at_90pct = count_closes(27, 30);  // 90%

    // Allow ±15% tolerance due to hash distribution.
    CHECK(at_10pct > 0);
    CHECK(at_10pct < 2500);  // < 25%
    CHECK(at_50pct > 3500);  // > 35%
    CHECK(at_50pct < 6500);  // < 65%
    CHECK(at_90pct > 7500);  // > 75%
}

// === monotonic_secs ===

TEST(monotonic, returns_nonzero) {
    rut::u64 t = rut::monotonic_secs();
    CHECK(t > 0);
}

TEST(monotonic, non_decreasing) {
    rut::u64 a = rut::monotonic_secs();
    rut::u64 b = rut::monotonic_secs();
    CHECK(b >= a);
}

// === EventLoop drain mode ===

TEST(event_loop_drain, initial_state_not_draining) {
    SmallLoop loop;
    loop.setup();
    CHECK(!loop.is_draining());
}

TEST(event_loop_drain, active_count_empty) {
    using rut::EpollBackend;
    using rut::EventLoop;
    // Use SmallLoop which tracks free_top
    SmallLoop loop;
    loop.setup();
    CHECK_EQ(loop.free_top, SmallLoop::kMaxConns);
}

TEST(event_loop, pause_upstream_recv_adapts_void_backend_hook) {
    SmallLoop loop;
    loop.setup();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    loop.backend.op_count = 0;
    CHECK(loop.pause_upstream_recv(*conn));
    REQUIRE_EQ(loop.backend.op_count, 1u);
    CHECK_EQ(loop.backend.ops[0].type, MockOp::PauseUpstreamRecv);
    CHECK_EQ(loop.backend.ops[0].conn_id, conn->id);
}

TEST(event_loop, delegates_shared_upstream_concurrency) {
    using rut::EventLoop;
    using rut::MockBackend;
    using rut::UpstreamConcurrency;
    auto loop = std::make_unique<EventLoop<MockBackend>>();
    REQUIRE(loop->init(0, -1).has_value());

    CHECK(loop->upstream_acquire(3, 1));  // no shared limiter means unlimited
    UpstreamConcurrency concurrency{};
    concurrency.reset();
    loop->upstream_cc = &concurrency;
    CHECK(loop->upstream_acquire(3, 1));
    CHECK_FALSE(loop->upstream_acquire(3, 1));
    loop->upstream_release(3);
    CHECK(loop->upstream_acquire(3, 1));
    loop->upstream_release(3);
    loop->shutdown();
}

TEST(event_loop, dispatch_event_ignores_non_connection_event_kinds) {
    SmallLoop loop;
    loop.setup();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    for (const auto type : {IoEventType::Accept,
                            IoEventType::Timeout,
                            IoEventType::HandlerTimer,
                            IoEventType::Count}) {
        IoEvent event = make_ev(conn->id, type, 0);
        loop.dispatch_event(*conn, event);
        CHECK_EQ(conn->fd, 42);
    }
}

TEST(event_loop, lazily_allocates_and_reclaims_proxy_and_terminate_buffers) {
    using rut::EventLoop;
    using rut::MockBackend;
    auto loop = std::make_unique<EventLoop<MockBackend>>();
    REQUIRE(loop->init(0, -1).has_value());
    Connection* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);

    CHECK(loop->alloc_upstream_buf(*conn));
    auto* upstream = conn->upstream_recv_slice;
    REQUIRE(upstream != nullptr);
    CHECK(loop->alloc_upstream_buf(*conn));
    CHECK_EQ(conn->upstream_recv_slice, upstream);

    CHECK(loop->alloc_ws_terminate_bufs(*conn));
    REQUIRE(conn->ws_c2u_msg != nullptr);
    REQUIRE(conn->ws_u2c_msg != nullptr);
    CHECK(loop->alloc_ws_terminate_bufs(*conn));

    loop->free_conn(*conn);
    loop->shutdown();
}

TEST(event_loop, unsupported_jit_outcome_fails_closed) {
    SmallLoop loop;
    loop.setup();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    Connection* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::Error;

    handle_jit_outcome<SmallLoop>(&loop, *conn, outcome, nullptr, /*keep_alive=*/true);

    CHECK_EQ(conn->resp_status, 500u);
    CHECK_FALSE(conn->keep_alive);
    CHECK_EQ(conn->state, ConnState::Sending);
}

TEST(event_loop, jit_forward_to_unknown_upstream_fails_closed) {
    SmallLoop loop;
    loop.setup();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    Connection* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::Forward;
    outcome.upstream_id = 7;

    handle_jit_outcome<SmallLoop>(&loop, *conn, outcome, nullptr, /*keep_alive=*/true);

    CHECK_EQ(conn->resp_status, 502u);
    CHECK_FALSE(conn->keep_alive);
    CHECK_EQ(conn->state, ConnState::Sending);
}

// === Drain accepts: served gracefully, not RST'd ===

TEST(drain_accept, accepts_during_drain_get_response) {
    SmallLoop loop;
    loop.setup();
    loop.draining = true;

    // Accept during drain — should still be processed, not closed.
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* c = loop.find_fd(42);
    REQUIRE(c != nullptr);
    // Connection is accepted and keep_alive should be false.
    CHECK(!c->keep_alive);
    CHECK_EQ(c->state, ConnState::ReadingHeader);
}

TEST(drain_accept, drain_accept_full_cycle) {
    SmallLoop loop;
    loop.setup();
    loop.draining = true;
    ShardMetrics m;
    m.init();
    loop.metrics = &m;

    // Accept → recv → send → closed
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* c = loop.find_fd(42);
    REQUIRE(c != nullptr);
    rut::u32 cid = c->id;

    loop.inject_and_dispatch(make_ev(cid, IoEventType::Recv, 100));
    rut::u32 send_len = c->send_buf.len();
    loop.inject_and_dispatch(make_ev(cid, IoEventType::Send, static_cast<rut::i32>(send_len)));

    // After response with Connection: close, connection should be freed.
    CHECK_EQ(loop.conns[cid].fd, -1);
    CHECK_EQ(m.requests_total, 1u);
    CHECK_EQ(m.requests_active, 0u);
}

// === Callbacks respect drain ===

TEST(drain_callback, response_has_connection_close) {
    SmallLoop loop;
    loop.setup();
    loop.draining = true;

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* c = loop.find_fd(42);
    REQUIRE(c != nullptr);
    loop.backend.clear_ops();

    loop.inject_and_dispatch(make_ev(c->id, IoEventType::Recv, 100));

    CHECK(!c->keep_alive);
    CHECK_EQ(c->state, ConnState::Sending);
    CHECK(buf_contains(c->send_buf, "close"));
}

TEST(drain_callback, non_drain_response_has_keep_alive) {
    SmallLoop loop;
    loop.setup();

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* c = loop.find_fd(42);
    REQUIRE(c != nullptr);
    loop.backend.clear_ops();

    loop.inject_and_dispatch(make_ev(c->id, IoEventType::Recv, 100));

    CHECK(c->keep_alive);
    CHECK(buf_contains(c->send_buf, "keep-alive"));
}

TEST(drain_callback, close_after_drain_response_sent) {
    SmallLoop loop;
    loop.setup();
    loop.draining = true;

    // Accept + recv
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* c = loop.find_fd(42);
    REQUIRE(c != nullptr);
    rut::u32 cid = c->id;
    loop.inject_and_dispatch(make_ev(cid, IoEventType::Recv, 100));

    // Send response — since keep_alive=false, connection should be closed after send
    rut::u32 send_len = c->send_buf.len();
    loop.inject_and_dispatch(make_ev(cid, IoEventType::Send, static_cast<rut::i32>(send_len)));

    // Connection should have been freed (fd == -1 after close_conn)
    CHECK_EQ(loop.conns[cid].fd, -1);
}

// === Proxy drain: upstream response rewrite ===

TEST_F(DrainProxyF, upstream_response_rewrites_connection_header) {
    REQUIRE(self.wire_proxy());
    REQUIRE(inject_custom_upstream_resp(
        self.loop,
        *self.c,
        "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nOK"));
    CHECK(buf_contains(self.c->upstream_recv_buf, "Connection: close"));
}

TEST_F(DrainProxyF, upstream_response_rewrites_lowercase_connection_header) {
    REQUIRE(self.wire_proxy());
    REQUIRE(inject_custom_upstream_resp(
        self.loop,
        *self.c,
        "HTTP/1.1 200 OK\r\nconnection: keep-alive\r\nContent-Length: 2\r\n\r\nOK"));
    CHECK(buf_contains(self.c->upstream_recv_buf, "connection: close"));
}

TEST_F(DrainProxyF, upstream_response_injects_close_when_missing) {
    REQUIRE(self.wire_proxy());
    REQUIRE(inject_custom_upstream_resp(
        self.loop, *self.c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"));
    CHECK(!self.c->keep_alive);
}

TEST(drain_proxy, upstream_status_parsed) {
    // Non-draining proxy — tests status code parsing only.
    SmallLoop loop;
    loop.setup();

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* c = loop.find_fd(42);
    REQUIRE(c != nullptr);
    rut::u32 cid = c->id;
    loop.inject_and_dispatch(make_ev(cid, IoEventType::Recv, 100));

    c->upstream_fd = 99;
    c->on_upstream_send = &on_upstream_connected<SmallLoop>;
    loop.inject_and_dispatch(make_ev(cid, IoEventType::UpstreamConnect, 0));
    rut::u32 req_len = c->recv_buf.len();
    loop.inject_and_dispatch(
        make_ev(cid, IoEventType::UpstreamSend, static_cast<rut::i32>(req_len)));

    REQUIRE(inject_custom_upstream_resp(
        loop, *c, "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found"));
    CHECK_EQ(c->resp_status, static_cast<rut::u16>(404));
}

// === Drain: slice pool state ===

TEST(drain_pool, all_slices_returned_after_drain) {
    SmallLoop loop;
    loop.setup();
    loop.draining = true;

    // Accept 5 connections, complete their request cycles
    rut::u32 cids[5];
    for (rut::u32 i = 0; i < 5; i++) {
        loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, static_cast<rut::i32>(100 + i)));
        auto* c = loop.find_fd(static_cast<rut::i32>(100 + i));
        REQUIRE(c != nullptr);
        cids[i] = c->id;
        loop.inject_and_dispatch(make_ev(cids[i], IoEventType::Recv, 50));
        rut::u32 send_len = loop.conns[cids[i]].send_buf.len();
        loop.inject_and_dispatch(
            make_ev(cids[i], IoEventType::Send, static_cast<rut::i32>(send_len)));
        // Connection closed by drain (keep_alive=false)
        CHECK_EQ(loop.conns[cids[i]].fd, -1);
    }

    // Sync backend: all connections freed immediately during dispatch.
    CHECK_EQ(loop.free_top, SmallLoop::kMaxConns);
    // Slice pointers cleared by reset.
    for (rut::u32 i = 0; i < 5; i++) {
        CHECK_EQ(loop.conns[cids[i]].recv_slice, nullptr);
        CHECK_EQ(loop.conns[cids[i]].send_slice, nullptr);
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
