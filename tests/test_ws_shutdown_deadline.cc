#include "test_helpers.h"

#include <sys/mman.h>
#include <unistd.h>

#ifdef __linux__
#include "rut/runtime/iouring_event_loop.h"
#endif

using namespace rut;

// This feature toggle is supplied by CMake rather than a header.
// NOLINTNEXTLINE(misc-include-cleaner)
#if RUT_ENABLE_WEBSOCKET
namespace {
template <typename Loop>
struct MmapLoopOwner {
    Loop* loop = nullptr;
    bool initialized = false;

    MmapLoopOwner() {
        // Placement construction writes into this mapping, so the pointee stays writable.
        // NOLINTNEXTLINE(misc-const-correctness)
        void* const kStorage =
            mmap(nullptr, sizeof(Loop), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (kStorage != MAP_FAILED) loop = new (kStorage) Loop();
    }

    ~MmapLoopOwner() {
        if (!loop) return;
        if (initialized) loop->shutdown();
        loop->~Loop();
        munmap(loop, sizeof(Loop));
    }

    void mark_initialized() { initialized = true; }
};

struct SocketPairOwner {
    int fds[2] = {-1, -1};

    ~SocketPairOwner() {
        for (const int kFd : fds) {
            if (kFd >= 0) close(kFd);
        }
    }
};

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
    MmapLoopOwner<EventLoop<AsyncMockBackend>> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    REQUIRE(loop->init(0, -1, 0, 64).has_value());
    owner.mark_initialized();
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
}

TEST(legacy_loop, ws_shutdown_deadline_preempts_proxy_timeout) {
    MmapLoopOwner<EventLoop<MockBackend>> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    REQUIRE(loop->init(0, -1).has_value());
    owner.mark_initialized();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = -1;
    conn->state = ConnState::Proxying;
    conn->proxy_resp_started = false;
    conn->is_ws_tunnel = true;
    ws_arm_shutdown_deadline(loop, *conn);
    for (u32 tick = 0; tick < kWsShutdownDrainTimeoutSeconds + 1; tick++)
        loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_EQ(conn->state, ConnState::Idle);
    CHECK_EQ(conn->fd, -1);
    CHECK_EQ(loop->backend.count_ops(MockOp::Send), 0u);
}

TEST(legacy_loop, quiet_websocket_remains_exempt_from_idle_timeout) {
    MmapLoopOwner<EventLoop<MockBackend>> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    REQUIRE(loop->init(0, -1).has_value());
    owner.mark_initialized();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = -1;
    conn->is_ws_tunnel = true;
    loop->timer.add(conn, 1);
    loop->dispatch(make_ev(0, IoEventType::Timeout, 2));
    CHECK(conn->is_ws_tunnel);
    CHECK_FALSE(conn->ws_shutdown_deadline_armed);
    loop->free_conn(*conn);
}

TEST(legacy_loop, throttled_websocket_wheel_wake_resumes_without_idle_close) {
    MmapLoopOwner<EventLoop<MockBackend>> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    REQUIRE(loop->init(0, -1).has_value());
    owner.mark_initialized();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = -1;
    conn->upstream_fd = 43;
    conn->is_ws_tunnel = true;
    conn->throttle_paused = true;
    conn->throttle_down_bps = 1;
    conn->throttle_tat_ns = 0;  // Budget has recovered at the fallback wake.
    loop->timer.add(conn, 1);

    loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
    loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_FALSE(conn->throttle_paused);
    CHECK(conn->is_ws_tunnel);
    CHECK_EQ(conn->fd, -1);
    CHECK(loop->backend.count_ops(MockOp::Recv) > 0);
    loop->free_conn(*conn);
}

TEST(legacy_loop, shutdown_deadline_bounds_repeated_throttle_fallback_wakes) {
    MmapLoopOwner<EventLoop<MockBackend>> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    REQUIRE(loop->init(0, -1).has_value());
    owner.mark_initialized();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = -1;
    conn->is_ws_tunnel = true;
    conn->throttle_paused = true;
    conn->throttle_down_bps = 1;
    conn->throttle_tat_ns = monotonic_ns() + 60'000'000'000ull;
    loop->timer.add(conn, 1);  // Existing coarse fallback wake must be retained.
    ws_arm_shutdown_deadline(loop, *conn);
    REQUIRE(conn->ws_shutdown_deadline_armed);
    CHECK_EQ(conn->ws_shutdown_started_tick, loop->timer.cursor);
    CHECK_FALSE(conn->timer_node.empty());

    for (u32 tick = 0; tick < kWsShutdownDrainTimeoutSeconds; tick++) {
        loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
        CHECK_EQ(conn->fd, -1);
        CHECK(conn->ws_shutdown_deadline_armed);
    }
    loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_FALSE(conn->ws_shutdown_deadline_armed);
    CHECK_EQ(conn->state, ConnState::Idle);
}

TEST(legacy_loop, recovered_throttle_send_keeps_original_shutdown_deadline) {
    MmapLoopOwner<EventLoop<MockBackend>> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    REQUIRE(loop->init(0, -1).has_value());
    owner.mark_initialized();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = -1;
    conn->upstream_fd = 43;
    conn->is_ws_tunnel = true;
    conn->throttle_paused = true;
    conn->throttle_down_bps = 1;
    conn->throttle_pending_len = 1;
    conn->throttle_tat_ns = monotonic_ns() + 60'000'000'000ull;
    REQUIRE(loop->alloc_upstream_buf(*conn));
    const u8 kPayload = 'x';
    REQUIRE_EQ(conn->upstream_recv_buf.write(&kPayload, 1), 1u);
    loop->timer.add(conn, 1);
    ws_arm_shutdown_deadline(loop, *conn);

    loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
    loop->dispatch(make_ev(0, IoEventType::Timeout, 1));  // Early fallback wake.
    CHECK(conn->throttle_paused);
    conn->throttle_tat_ns = 0;  // Rate budget recovers before the shutdown deadline.
    loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_FALSE(conn->throttle_paused);
    CHECK(conn->ws_upstream_send_pending);
    CHECK(loop->backend.count_ops(MockOp::Send) > 0);
    CHECK_FALSE(conn->timer_node.empty());
    for (u32 tick = 0; tick < kWsShutdownDrainTimeoutSeconds - 3; tick++)
        loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK(conn->ws_shutdown_deadline_armed);
    loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_EQ(conn->state, ConnState::Idle);
    CHECK_FALSE(conn->ws_shutdown_deadline_armed);
}

TEST(legacy_loop, shutdown_deadline_uses_unsigned_elapsed_ticks_across_wrap) {
    MmapLoopOwner<EventLoop<MockBackend>> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    REQUIRE(loop->init(0, -1).has_value());
    owner.mark_initialized();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = -1;
    conn->is_ws_tunnel = true;
    loop->timer.cursor = UINT32_MAX - 2;
    ws_arm_shutdown_deadline(loop, *conn);
    CHECK_EQ(conn->ws_shutdown_started_tick, UINT32_MAX - 2);

    for (u32 tick = 0; tick < kWsShutdownDrainTimeoutSeconds + 1; tick++)
        loop->dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_EQ(conn->state, ConnState::Idle);
    CHECK_FALSE(conn->ws_shutdown_deadline_armed);
}

#ifdef __linux__
TEST(websocket, precise_throttle_timer_preserves_wheel_shutdown_deadline) {
    MmapLoopOwner<EpollEventLoop> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    REQUIRE(loop->init(0, -1, 0, 64).has_value());
    owner.mark_initialized();
    SocketPairOwner socket_pair;
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, socket_pair.fds), 0);
    const u8 kFill[4096]{};
    while (send(socket_pair.fds[0], kFill, sizeof(kFill), MSG_NOSIGNAL) > 0) {
    }
    REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = socket_pair.fds[0];
    socket_pair.fds[0] = -1;  // The loop owns this descriptor from here.
    conn->is_ws_tunnel = true;
    conn->throttle_paused = true;
    conn->throttle_down_bps = 1;
    conn->throttle_pending_len = 1;
    conn->throttle_tat_ns = monotonic_ns() + 60'000'000'000ull;
    REQUIRE(loop->alloc_upstream_buf(*conn));
    const u8 kPayload = 'x';
    REQUIRE_EQ(conn->upstream_recv_buf.write(&kPayload, 1), 1u);
    REQUIRE(loop->arm_throttle_timer(*conn, 0));
    ws_arm_shutdown_deadline(loop, *conn);
    CHECK_FALSE(conn->timer_node.empty());
    loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK(conn->ws_shutdown_deadline_armed);
    conn->throttle_tat_ns = 0;  // The precise wake observes a recovered rate budget.
    loop->drain_yield_heap();
    CHECK_FALSE(conn->throttle_paused);
    CHECK(conn->ws_upstream_send_pending);  // EAGAIN leaves the send blocked on EPOLLOUT.
    CHECK_FALSE(conn->timer_node.empty());

    for (u32 tick = 0; tick < kWsShutdownDrainTimeoutSeconds - 2; tick++) {
        loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
        CHECK(conn->fd >= 0);
    }
    loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK_EQ(conn->state, ConnState::Idle);
    CHECK_FALSE(conn->ws_shutdown_deadline_armed);
}
#endif

#ifdef __linux__
TEST(websocket, epoll_send_progress_does_not_extend_shutdown_deadline) {
    MmapLoopOwner<EpollEventLoop> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    REQUIRE(loop->init(0, -1, 0, 64).has_value());
    owner.mark_initialized();
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
}

TEST(websocket, iouring_dispatch_expires_shutdown_deadline_before_http_yield) {
    MmapLoopOwner<IoUringEventLoop> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    if (!init_iouring_loop_with_retry(*loop, "websocket shutdown deadline", 64))
        SKIP("io_uring unavailable");
    owner.mark_initialized();
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
}

TEST(websocket, iouring_deadline_reuses_precise_throttle_owner_until_cancel_retires) {
    MmapLoopOwner<IoUringEventLoop> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    if (!init_iouring_loop_with_retry(*loop, "WebSocket throttle deadline owner", 64))
        SKIP("io_uring unavailable");
    owner.mark_initialized();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = -1;
    conn->is_ws_tunnel = true;
    conn->throttle_paused = true;
    conn->throttle_down_bps = 1;
    conn->throttle_tat_ns = monotonic_ns() + 60'000'000'000ull;
    REQUIRE(loop->arm_throttle_timer(*conn, 60'000'000'000ull));
    ws_arm_shutdown_deadline(loop, *conn);
    const u32 kOwnerGeneration = conn->yield_timer_gen;
    const u32 kOwnerCount = conn->pending_ops;
    const auto kOwnerTimespec = conn->yield_timespec;
    REQUIRE(loop->arm_throttle_timer(*conn, 30'000'000'000ull));
    CHECK_EQ(conn->yield_timer_gen, kOwnerGeneration);
    CHECK_EQ(conn->pending_ops, kOwnerCount);
    CHECK_EQ(conn->yield_timespec.tv_sec, kOwnerTimespec.tv_sec);
    CHECK_EQ(conn->yield_timespec.tv_nsec, kOwnerTimespec.tv_nsec);

    const u32 kConnId = conn->id;
    loop->dispatch(make_ev(0, IoEventType::Timeout, kWsShutdownDrainTimeoutSeconds + 1));
    CHECK_EQ(conn->fd, -1);
    CHECK_EQ(conn->pending_ops, kOwnerCount + 1);  // Original timer plus close-path cancel.
    const u64 kRetireByNs = monotonic_ns() + 1'000'000'000ull;
    IoEvent events[8]{};
    u32 retired_handlers = 0;
    while (conn->pending_ops > 0 && monotonic_ns() < kRetireByNs) {
        const u32 kCount = loop->backend.wait(
            events, 8, loop->conns, loop->slots_initialized, /*wait_for_event=*/false);
        for (u32 i = 0; i < kCount; i++) {
            if (events[i].type == IoEventType::HandlerTimer) retired_handlers++;
            loop->dispatch(events[i]);
        }
    }
    CHECK_EQ(conn->pending_ops, 0u);
    CHECK_EQ(retired_handlers, 2u);
    CHECK_EQ(loop->active_count(), 0u);
    auto* reused = loop->alloc_conn();
    REQUIRE(reused != nullptr);
    CHECK_EQ(reused->id, kConnId);
    CHECK_FALSE(reused->ws_shutdown_deadline_armed);
    loop->free_conn(*reused);
}
#endif
// NOLINTEND(misc-include-cleaner)
#endif  // RUT_ENABLE_WEBSOCKET

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
