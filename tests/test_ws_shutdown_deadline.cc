#include "test_helpers.h"
#include <memory>

#ifdef __linux__
#include "rut/runtime/iouring_event_loop.h"
#endif

using namespace rut;

// This feature toggle is supplied by CMake rather than a header.
// NOLINTNEXTLINE(misc-include-cleaner)
#if RUT_ENABLE_WEBSOCKET
namespace {
// This test intentionally uses the shared runtime/mock aggregate from test_helpers.h.
// NOLINTBEGIN(misc-include-cleaner)
WsFrameAction ws_close_handler(void*, WsOpcode, const u8*, u64, bool) {
    return WsFrameAction::Close;
}

void ws_noop_recv(void*, Connection&, IoEvent) {}

u32 ws_yield_handler_calls = 0;
u64 ws_yield_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    ws_yield_handler_calls++;
    return jit::HandlerResult::make_status(204).pack();
}
}  // namespace

TEST(websocket, handler_close_drain_deadline_expires_before_http_yield) {
    SmallLoop loop;
    loop.setup();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    conn->upstream_fd = 43;
    conn->is_ws_tunnel = true;
    conn->is_ws_terminate = true;
    conn->ws_handler = &ws_close_handler;
    conn->ws_max_message_size = 128;
    u8 c2u_message[128]{};
    u8 c2u_output[256]{};
    u8 u2c_message[128]{};
    u8 u2c_output[256]{};
    conn->ws_c2u_msg = c2u_message;
    conn->ws_c2u_out = c2u_output;
    conn->ws_u2c_msg = u2c_message;
    conn->ws_u2c_out = u2c_output;
    conn->ws_c2u.masked = true;
    conn->ws_c2u.from_client = true;

    // One masked text byte; both Close sends remain pending in MockBackend.
    const u8 kMaskedFrame[] = {0x81, 0x81, 1, 2, 3, 4, static_cast<u8>('x' ^ 1)};
    REQUIRE_EQ(conn->recv_buf.write(kMaskedFrame, sizeof(kMaskedFrame)), sizeof(kMaskedFrame));
    on_ws_client_recv<SmallLoop>(
        &loop, *conn, make_ev(conn->id, IoEventType::Recv, sizeof(kMaskedFrame)));
    REQUIRE(conn->ws_closing);
    REQUIRE(conn->ws_shutdown_deadline_armed);
    REQUIRE(conn->ws_client_send_pending);
    REQUIRE(conn->ws_upstream_send_pending);

    // Ordinary activity cannot extend the timer, and stale HTTP yield state
    // must not resume once the WebSocket shutdown deadline is due.
    conn->state = ConnState::Proxying;
    conn->proxy_resp_started = false;
    ws_yield_handler_calls = 0;
    conn->pending_handler_fn = &ws_yield_handler;
    conn->pending_yield_kind = jit::YieldKind::Timer;
    conn->yield_armed = true;
    conn->on_recv = &ws_noop_recv;
    loop.dispatch(make_ev(conn->id, IoEventType::Recv, 1));
    for (u32 tick = 0; tick < kWsShutdownDrainTimeoutSeconds; tick++) {
        loop.dispatch(make_ev(0, IoEventType::Timeout, 1));
        CHECK_EQ(conn->fd, 42);
    }
    loop.dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_EQ(conn->fd, -1);
    CHECK_FALSE(conn->ws_shutdown_deadline_armed);
    CHECK_EQ(ws_yield_handler_calls, 0u);
}

TEST(websocket, half_close_deadline_is_one_shot_and_normal_drain_reclaims_slot) {
    SmallLoop loop;
    loop.setup();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    conn->is_ws_tunnel = true;
    conn->upstream_fd = 43;
    conn->ws_client_send_pending = true;
    const u32 kConnId = conn->id;

    on_ws_client_recv<SmallLoop>(&loop, *conn, make_ev(kConnId, IoEventType::Recv, 0));
    REQUIRE(conn->ws_shutdown_deadline_armed);
    loop.dispatch(make_ev(0, IoEventType::Timeout, 1));
    loop.dispatch(make_ev(0, IoEventType::Timeout, 1));
    on_ws_upstream_recv<SmallLoop>(&loop, *conn, make_ev(kConnId, IoEventType::UpstreamRecv, 0));
    conn->on_recv = &ws_noop_recv;
    loop.dispatch(make_ev(kConnId, IoEventType::Recv, 1));

    for (u32 tick = 0; tick < kWsShutdownDrainTimeoutSeconds - 2; tick++) {
        loop.dispatch(make_ev(0, IoEventType::Timeout, 1));
        CHECK_EQ(conn->fd, 42);
    }
    loop.dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_EQ(conn->fd, -1);

    // A complete drain closes early, removes the deadline, and slot reset clears
    // the one-shot flag before the connection can be allocated again.
    SmallLoop clean_loop;
    clean_loop.setup();
    clean_loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 52));
    auto* clean = clean_loop.find_fd(52);
    REQUIRE(clean != nullptr);
    clean->is_ws_tunnel = true;
    clean->upstream_fd = 53;
    clean->ws_client_send_pending = true;
    const u32 kCleanId = clean->id;
    on_ws_client_recv<SmallLoop>(&clean_loop, *clean, make_ev(kCleanId, IoEventType::Recv, 0));
    REQUIRE(clean->ws_shutdown_deadline_armed);
    on_ws_client_to_upstream_sent<SmallLoop>(
        &clean_loop, *clean, make_ev(kCleanId, IoEventType::UpstreamSend, 1));
    CHECK_EQ(clean->fd, -1);
    CHECK_FALSE(clean->ws_shutdown_deadline_armed);
    auto* reused = clean_loop.alloc_conn();
    REQUIRE(reused != nullptr);
    CHECK_EQ(reused->id, kCleanId);
    CHECK_FALSE(reused->ws_shutdown_deadline_armed);
    reused->fd = 62;
    reused->state = ConnState::ReadingHeader;
    for (u32 tick = 0; tick < kWsShutdownDrainTimeoutSeconds + 1; tick++)
        clean_loop.dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_EQ(reused->fd, 62);  // The completed drain left no stale timer on the reused slot.
    clean_loop.free_conn(*reused);
}

TEST(websocket, async_deadline_retains_output_until_target_and_cancel_retire) {
    auto loop = std::make_unique<EventLoop<AsyncMockBackend>>();
    REQUIRE(loop->init(0, -1, 0, 64).has_value());
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    REQUIRE(loop->alloc_ws_terminate_bufs(*conn));
    const u8* const kOutput = conn->ws_c2u_out;
    REQUIRE(kOutput != nullptr);
    REQUIRE(loop->submit_send(*conn, kOutput, 16));
    CHECK_EQ(conn->pending_ops, 1u);
    conn->is_ws_tunnel = true;
    conn->ws_shutdown_deadline_armed = true;
    loop->timer.add(conn, kWsShutdownDrainTimeoutSeconds);
    const u32 kConnId = conn->id;

    loop->dispatch(
        make_ev(0, IoEventType::Timeout, static_cast<i32>(kWsShutdownDrainTimeoutSeconds + 1)));
    CHECK_EQ(conn->fd, -1);
    CHECK_EQ(conn->pending_ops, 2u);  // send target + close cancel
    CHECK_EQ(conn->ws_c2u_out, kOutput);
    CHECK_EQ(loop->active_count(), 1u);
    CHECK_EQ(loop->backend.count_ops(MockOp::Cancel), 1u);

    // The target and its cancellation can retire in either order. The output
    // slice and slot stay owned until the final completion.
    loop->dispatch(make_ev(kConnId, IoEventType::Send, 16));
    CHECK_EQ(conn->pending_ops, 1u);
    CHECK_EQ(conn->ws_c2u_out, kOutput);
    CHECK_EQ(loop->active_count(), 1u);
    loop->dispatch(make_ev(kConnId, IoEventType::Send, -ECANCELED));
    CHECK_EQ(loop->active_count(), 0u);
    CHECK_EQ(conn->ws_c2u_out, nullptr);
    auto* reused = loop->alloc_conn();
    REQUIRE(reused != nullptr);
    CHECK_EQ(reused->id, kConnId);
    CHECK_FALSE(reused->ws_shutdown_deadline_armed);
    loop->free_conn(*reused);
    loop->shutdown();
}

TEST(legacy_loop, ws_shutdown_deadline_preempts_proxy_timeout) {
    auto loop = std::make_unique<EventLoop<MockBackend>>();
    REQUIRE(loop->init(0, -1).has_value());
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = -1;
    conn->state = ConnState::Proxying;
    conn->proxy_resp_started = false;
    conn->is_ws_tunnel = true;
    conn->ws_shutdown_deadline_armed = true;
    loop->timer.add(conn, 1);
    loop->dispatch(make_ev(0, IoEventType::Timeout, 2));
    CHECK_EQ(conn->state, ConnState::Idle);
    CHECK_EQ(conn->fd, -1);
    CHECK_EQ(loop->backend.count_ops(MockOp::Send), 0u);
    loop->shutdown();
}

TEST(legacy_loop, quiet_websocket_remains_exempt_from_idle_timeout) {
    auto loop = std::make_unique<EventLoop<MockBackend>>();
    REQUIRE(loop->init(0, -1).has_value());
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = -1;
    conn->is_ws_tunnel = true;
    loop->timer.add(conn, 1);
    loop->dispatch(make_ev(0, IoEventType::Timeout, 2));
    CHECK(conn->is_ws_tunnel);
    CHECK_FALSE(conn->ws_shutdown_deadline_armed);
    loop->free_conn(*conn);
    loop->shutdown();
}

#ifdef __linux__
TEST(websocket, epoll_send_progress_does_not_extend_shutdown_deadline) {
    auto loop = std::make_unique<EpollEventLoop>();
    REQUIRE(loop->init(0, -1, 0, 64).has_value());
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->is_ws_tunnel = true;
    conn->ws_shutdown_deadline_armed = true;
    conn->on_recv = &ws_noop_recv;
    loop->timer.add(conn, kWsShutdownDrainTimeoutSeconds);

    loop->dispatch({conn->id, 1, 0, 0, IoEventType::Send, 0, kEpollSendProgressAux});
    loop->dispatch({conn->id, 0, 0, 0, IoEventType::Recv, 0});
    loop->dispatch(
        {0, static_cast<i32>(kWsShutdownDrainTimeoutSeconds), 0, 0, IoEventType::Timeout, 0});
    CHECK(conn->is_ws_tunnel);
    CHECK(conn->ws_shutdown_deadline_armed);
    loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK_EQ(conn->state, ConnState::Idle);
    CHECK_FALSE(conn->ws_shutdown_deadline_armed);
    loop->shutdown();
}

TEST(websocket, iouring_dispatch_expires_shutdown_deadline_before_http_yield) {
    auto loop = std::make_unique<IoUringEventLoop>();
    if (!init_iouring_loop_with_retry(*loop, "websocket shutdown deadline", 64))
        SKIP("io_uring unavailable");
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->is_ws_tunnel = true;
    conn->ws_shutdown_deadline_armed = true;
    conn->state = ConnState::Proxying;
    conn->proxy_resp_started = false;
    ws_yield_handler_calls = 0;
    conn->pending_handler_fn = &ws_yield_handler;
    conn->pending_yield_kind = jit::YieldKind::Timer;
    conn->yield_armed = true;
    conn->on_recv = &ws_noop_recv;
    loop->timer.add(conn, kWsShutdownDrainTimeoutSeconds);

    loop->dispatch({conn->id, 1, 0, 0, IoEventType::Recv, 0});
    loop->dispatch(
        {0, static_cast<i32>(kWsShutdownDrainTimeoutSeconds + 1), 0, 0, IoEventType::Timeout, 0});
    CHECK_EQ(conn->state, ConnState::Idle);
    CHECK_FALSE(conn->ws_shutdown_deadline_armed);
    CHECK_EQ(ws_yield_handler_calls, 0u);
    loop->shutdown();
}
#endif
// NOLINTEND(misc-include-cleaner)
#endif  // RUT_ENABLE_WEBSOCKET

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
