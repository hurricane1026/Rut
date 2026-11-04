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

struct WsCloseObservation {
    u32 calls = 0;
    bool clean = false;
    bool client_received = false;
    bool upstream_received = false;
    u16 original_code = 0;
    u16 client_code = 0;
    u16 upstream_code = 0;
    bool client_reason_ack = false;
    bool upstream_reason_ack = false;
};
WsCloseObservation ws_close_observation;
void ws_observe_close(void*, Connection& c) {
    ++ws_close_observation.calls;
    ws_close_observation.clean = c.ws_close_handshake_complete;
    ws_close_observation.client_received = c.ws_close_client_received;
    ws_close_observation.upstream_received = c.ws_close_upstream_received;
    ws_close_observation.original_code = c.ws_close_payload.code;
    const auto kContext = c.ws_session_close_context();
    ws_close_observation.client_code = kContext.client.code;
    ws_close_observation.upstream_code = kContext.upstream.code;
    ws_close_observation.client_reason_ack = kContext.client.reason.eq(lit_str("ack"));
    ws_close_observation.upstream_reason_ack = kContext.upstream.reason.eq(lit_str("ack"));
}

struct WsClosingFixture {
    SmallLoop loop;
    Connection* conn = nullptr;
    u8 c2u_message[128]{}, c2u_output[256]{};
    u8 u2c_message[128]{}, u2c_output[256]{};

    void setup() {
        loop.setup();
        loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
        conn = loop.find_fd(42);
        if (!conn) return;
        loop.alloc_upstream_buf(*conn);
        conn->upstream_fd = 43;
        conn->is_ws_tunnel = true;
        conn->is_ws_terminate = true;
        conn->ws_handler = &ws_close_handler;
        conn->ws_max_message_size = 128;
        conn->ws_c2u_msg = c2u_message;
        conn->ws_c2u_out = c2u_output;
        conn->ws_u2c_msg = u2c_message;
        conn->ws_u2c_out = u2c_output;
        conn->ws_c2u.masked = true;
        conn->ws_c2u.from_client = true;
        conn->ws_u2c.masked = false;
        conn->on_close = &ws_observe_close;
        ws_close_observation = {};
    }
    bool start() {
        const u8 frame[] = {0x81, 0x81, 1, 2, 3, 4, static_cast<u8>('x' ^ 1)};
        if (!conn || conn->recv_buf.write(frame, sizeof(frame)) != sizeof(frame)) return false;
        on_ws_client_recv<SmallLoop>(
            &loop, *conn, make_ev(conn->id, IoEventType::Recv, sizeof(frame)));
        return conn->ws_closing;
    }
    void sent(bool client) {
        if (client)
            on_ws_upstream_to_client_sent<SmallLoop>(
                &loop, *conn, make_ev(conn->id, IoEventType::Send, 1));
        else
            on_ws_client_to_upstream_sent<SmallLoop>(
                &loop, *conn, make_ev(conn->id, IoEventType::UpstreamSend, 1));
    }
    bool receive(bool client, const u8* frame, u32 len) {
        auto& buffer = client ? conn->recv_buf : conn->upstream_recv_buf;
        if (buffer.write(frame, len) != len) return false;
        if (client)
            on_ws_client_recv<SmallLoop>(&loop, *conn, make_ev(conn->id, IoEventType::Recv, len));
        else
            on_ws_upstream_recv<SmallLoop>(
                &loop, *conn, make_ev(conn->id, IoEventType::UpstreamRecv, len));
        return true;
    }
    bool acknowledge(bool client) {
        u8 frame[32];
        u64 rng = 0;
        const u32 len = ws_emit_close_frame(
            frame, sizeof(frame), client, rng, client ? 3001 : 3002, lit_str("ack"));
        return len && receive(client, frame, len);
    }
};

u32 ws_yield_handler_calls = 0;
u64 ws_yield_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    ws_yield_handler_calls++;
    return jit::HandlerResult::make_status(204).pack();
}
}  // namespace

namespace {
struct LifecycleObservation {
    u32 opened = 0, messages = 0, closed = 0;
    bool before_message = false, before_cleanup = false;
    u16 code = 0;
} lifecycle_observation;
WsFrameAction observe_session_open(void* value, WsOpcode, const u8*, u64, bool) {
    auto& conn = *static_cast<Connection*>(value);
    ++lifecycle_observation.opened;
    lifecycle_observation.before_message = conn.is_ws_terminate && conn.ws_c2u_msg &&
                                           conn.ws_u2c_out && conn.is_ws_tunnel &&
                                           lifecycle_observation.messages == 0;
    return WsFrameAction::Drop;
}
WsFrameAction observe_session_message(void*, WsOpcode, const u8*, u64, bool) {
    ++lifecycle_observation.messages;
    return WsFrameAction::Drop;
}
WsFrameAction observe_session_close(void* value, WsOpcode, const u8*, u64, bool) {
    auto& conn = *static_cast<Connection*>(value);
    ++lifecycle_observation.closed;
    lifecycle_observation.before_cleanup =
        conn.fd == 42 && conn.ws_c2u_msg && conn.ws_session_close_notified;
    lifecycle_observation.code = conn.ws_session_close_context().client.code;
    return WsFrameAction::Drop;
}
}  // namespace

struct WsLifecycleLoop : SmallLoop {
    u8 c2u_msg[128]{}, u2c_msg[128]{}, c2u_out[256]{}, u2c_out[256]{};
    bool alloc_ws_terminate_bufs(Connection& conn) {
        conn.ws_c2u_msg = c2u_msg;
        conn.ws_u2c_msg = u2c_msg;
        conn.ws_c2u_out = c2u_out;
        conn.ws_u2c_out = u2c_out;
        return true;
    }
};

TEST(websocket, lifecycle_open_precedes_coalesced_message_and_close_precedes_retirement) {
    WsLifecycleLoop loop;
    loop.setup();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn);
    loop.alloc_upstream_buf(*conn);
    conn->upstream_fd = 43;
    conn->is_ws_terminate_route = true;
    conn->ws_max_message_size = 128;
    conn->ws_handshake_slice = loop.alloc_ws_handshake_slice();
    REQUIRE(conn->ws_handshake_slice);
    conn->ws_handshake_phase = WsHandshakePhase::Validated;
    conn->req_wants_upgrade = true;
    conn->req_upgrade_is_websocket = true;
    conn->resp_upgrade_is_websocket = true;
    conn->ws_open_handler = &observe_session_open;
    conn->ws_close_handler = &observe_session_close;
    conn->ws_handler = &observe_session_message;
    lifecycle_observation = {};
    const u8 kFrame[] = {0x81, 0x81, 1, 2, 3, 4, static_cast<u8>('x' ^ 1)};
    REQUIRE_EQ(conn->recv_buf.write(kFrame, sizeof(kFrame)), sizeof(kFrame));
    on_ws_101_sent<WsLifecycleLoop>(&loop, *conn, make_ev(conn->id, IoEventType::Send, 64));
    CHECK_EQ(lifecycle_observation.opened, 1u);
    CHECK_EQ(lifecycle_observation.messages, 1u);
    CHECK(lifecycle_observation.before_message);
    CHECK_EQ(lifecycle_observation.closed, 0u);
    loop.close_conn(*conn);
    CHECK_EQ(lifecycle_observation.closed, 1u);
    CHECK(lifecycle_observation.before_cleanup);
    CHECK_EQ(lifecycle_observation.code, 1006u);
    close_conn_if_live(&loop, *conn);  // a late callback cannot close the retired slot twice
    CHECK_EQ(lifecycle_observation.closed, 1u);
    CHECK_FALSE(conn->ws_session_started);
    CHECK(conn->ws_open_handler == nullptr);
    CHECK(conn->ws_close_handler == nullptr);
}

TEST(websocket, failed_upgrade_has_no_session_lifecycle_events) {
    SmallLoop loop;
    loop.setup();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn);
    conn->ws_open_handler = &observe_session_open;
    conn->ws_close_handler = &observe_session_close;
    lifecycle_observation = {};
    on_ws_101_sent<SmallLoop>(&loop, *conn, make_ev(conn->id, IoEventType::Send, -EPIPE));
    CHECK_EQ(lifecycle_observation.opened, 0u);
    CHECK_EQ(lifecycle_observation.closed, 0u);
    CHECK_EQ(conn->fd, -1);
}

TEST(websocket, deferred_peer_close_reply_survives_inspector_reset) {
    constexpr bool kDirections[] = {false, true};
    for (bool from_client : kDirections) {
        SmallLoop loop;
        loop.setup();
        loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
        auto* conn = loop.find_fd(42);
        REQUIRE(conn != nullptr);
        conn->upstream_fd = 43;
        REQUIRE(loop.alloc_upstream_buf(*conn));
        conn->is_ws_tunnel = true;
        conn->is_ws_terminate = true;
        conn->ws_handler = &ws_close_handler;  // must never run for a control frame
        conn->ws_max_message_size = 128;
        u8 c2u_message[128]{}, c2u_output[256]{};
        u8 u2c_message[128]{}, u2c_output[256]{};
        conn->ws_c2u_msg = c2u_message;
        conn->ws_c2u_out = c2u_output;
        conn->ws_u2c_msg = u2c_message;
        conn->ws_u2c_out = u2c_output;
        conn->ws_c2u.masked = true;
        conn->ws_c2u.from_client = true;
        conn->ws_u2c.masked = false;
        u8 frame[128];
        const Str reason{"a\0\xe2\x82\xac", 5};
        u64 rng = 0;
        const u32 length =
            ws_emit_close_frame(frame, sizeof(frame), from_client, rng, 1009, reason);
        REQUIRE(length > 0);
        if (from_client) {
            conn->ws_upstream_send_pending = true;  // earlier server output occupies reply slot
            REQUIRE_EQ(conn->recv_buf.write(frame, length), length);
            on_ws_client_recv<SmallLoop>(
                &loop, *conn, make_ev(conn->id, IoEventType::Recv, length));
            REQUIRE(conn->ws_close_client_need);
            conn->ws_c2u.reset();
            on_ws_upstream_to_client_sent<SmallLoop>(
                &loop, *conn, make_ev(conn->id, IoEventType::Send, 1));
        } else {
            conn->ws_client_send_pending = true;
            REQUIRE_EQ(conn->upstream_recv_buf.write(frame, length), length);
            on_ws_upstream_recv<SmallLoop>(
                &loop, *conn, make_ev(conn->id, IoEventType::UpstreamRecv, length));
            REQUIRE(conn->ws_close_upstream_need);
            conn->ws_u2c.reset();
            on_ws_client_to_upstream_sent<SmallLoop>(
                &loop, *conn, make_ev(conn->id, IoEventType::UpstreamSend, 1));
        }
        REQUIRE(conn->ws_closing);
        REQUIRE(conn->ws_close_client_inflight);
        REQUIRE(conn->ws_close_upstream_inflight);
        CHECK_EQ(conn->ws_close_payload.code, 1009u);
        CHECK(conn->ws_close_payload.reason().eq(reason));
        const u8* reply = from_client ? conn->ws_close_frame_client : conn->ws_close_frame_upstream;
        WsFrameHeader header;
        REQUIRE(ws_parse_header(reply, 128, !from_client, &header) == ParseStatus::Complete);
        CHECK(header.opcode == WsOpcode::Close);
        REQUIRE_EQ(header.payload_len, 7u);
        u8 body[7];
        for (u32 j = 0; j < sizeof(body); ++j) body[j] = reply[header.header_len + j];
        if (header.masked) ws_unmask(body, sizeof(body), header.mask_key);
        CHECK_EQ(body[0], 3u);
        CHECK_EQ(body[1], 241u);
        CHECK(memcmp(body + 2, reason.ptr, reason.len) == 0);
    }
}

TEST(websocket, close_waits_for_both_acknowledgements_and_preserves_first_cause) {
    constexpr bool kOrders[] = {false, true};
    for (bool first_client : kOrders) {
        WsClosingFixture f;
        f.setup();
        REQUIRE(f.start());
        f.sent(first_client);
        f.sent(!first_client);
        REQUIRE_EQ(f.conn->fd, 42);
        CHECK_EQ(ws_close_observation.calls, 0u);
        REQUIRE(f.acknowledge(first_client));
        REQUIRE_EQ(f.conn->fd, 42);
        CHECK_EQ(ws_close_observation.calls, 0u);
        REQUIRE(f.acknowledge(!first_client));
        CHECK_EQ(f.conn->fd, -1);
        CHECK_EQ(f.loop.ws_client_write_shutdowns, 1u);
        CHECK_EQ(ws_close_observation.calls, 1u);
        CHECK(ws_close_observation.clean);
        CHECK(ws_close_observation.client_received);
        CHECK(ws_close_observation.upstream_received);
        CHECK_EQ(ws_close_observation.original_code, 1000u);
        CHECK_EQ(ws_close_observation.client_code, 3001u);
        CHECK_EQ(ws_close_observation.upstream_code, 3002u);
        CHECK(ws_close_observation.client_reason_ack);
        CHECK(ws_close_observation.upstream_reason_ack);
    }
}

TEST(websocket, downstream_ack_sends_fin_while_upstream_close_send_is_blocked) {
    WsClosingFixture f;
    f.setup();
    REQUIRE(f.start());
    u8 retained[8];
    memcpy(retained, f.c2u_output, sizeof(retained));
    f.sent(true);
    REQUIRE(f.conn->ws_client_send_pending);
    REQUIRE(f.acknowledge(true));
    CHECK_EQ(f.loop.ws_client_write_shutdowns, 1u);
    CHECK(f.conn->ws_client_write_shutdown);
    CHECK_EQ(f.conn->fd, 42);
    CHECK_EQ(ws_close_observation.calls, 0u);
    CHECK(memcmp(retained, f.c2u_output, sizeof(retained)) == 0);
    f.sent(false);
    REQUIRE(f.acknowledge(false));
    CHECK_EQ(f.conn->fd, -1);
    CHECK(ws_close_observation.clean);
}

TEST(websocket, closing_ping_replies_to_sender_before_coalesced_ack) {
    WsClosingFixture f;
    f.setup();
    REQUIRE(f.start());
    f.sent(true);
    f.sent(false);
    // A late message is ignored, then Ping gets a local Pong. The Close behind
    // it remains buffered until the Pong send retires, without duplicate Close.
    const u8 wire[] = {0x81,
                       0x81,
                       1,
                       2,
                       3,
                       4,
                       static_cast<u8>('z' ^ 1),
                       0x89,
                       0x81,
                       1,
                       2,
                       3,
                       4,
                       static_cast<u8>('p' ^ 1),
                       0x88,
                       0x82,
                       1,
                       2,
                       3,
                       4,
                       static_cast<u8>(3 ^ 1),
                       static_cast<u8>(232 ^ 2)};
    REQUIRE(f.receive(true, wire, sizeof(wire)));
    CHECK(f.conn->ws_upstream_send_pending);
    CHECK_FALSE(f.conn->ws_close_client_received);
    CHECK_FALSE(f.conn->ws_close_client_inflight);
    CHECK_EQ(f.conn->ws_close_frame_client[0], 0x8au);
    CHECK_EQ(f.conn->ws_close_frame_client[1], 1u);
    CHECK_EQ(f.conn->ws_close_frame_client[2], static_cast<u8>('p'));
    REQUIRE(f.acknowledge(false));
    CHECK_EQ(f.conn->fd, 42);
    f.sent(true);  // Pong completion processes the already-buffered client acknowledgement.
    CHECK_EQ(f.conn->fd, -1);
    CHECK(ws_close_observation.clean);
    CHECK_EQ(ws_close_observation.calls, 1u);
}

TEST(websocket, closing_eof_without_ack_is_abnormal_and_other_leg_can_finish) {
    WsClosingFixture f;
    f.setup();
    REQUIRE(f.start());
    f.sent(true);
    f.sent(false);
    on_ws_client_recv<SmallLoop>(&f.loop, *f.conn, make_ev(f.conn->id, IoEventType::Recv, 0));
    CHECK_EQ(f.conn->fd, 42);
    CHECK_FALSE(f.conn->ws_close_client_received);
    REQUIRE(f.acknowledge(false));
    CHECK_EQ(f.conn->fd, -1);
    CHECK_FALSE(ws_close_observation.clean);
    CHECK_FALSE(ws_close_observation.client_received);
    CHECK(ws_close_observation.upstream_received);
    CHECK_EQ(ws_close_observation.client_code, 1006u);
    CHECK_EQ(ws_close_observation.upstream_code, 3002u);
}

TEST(websocket, close_context_owns_each_first_peer_reason_independently) {
    constexpr bool kDirections[] = {false, true};
    for (bool from_client : kDirections) {
        WsClosingFixture f;
        f.setup();
        REQUIRE(f.start());
        f.sent(true);
        f.sent(false);
        const Str kReason{"a\0\xe2\x82\xac", 5};
        u8 frame[128];
        u64 rng = 0;
        const u32 kLength =
            ws_emit_close_frame(frame, sizeof(frame), from_client, rng, 3003, kReason);
        REQUIRE(kLength != 0);
        REQUIRE(f.receive(from_client, frame, kLength));
        auto& inspector = from_client ? f.conn->ws_c2u : f.conn->ws_u2c;
        inspector.reset();
        REQUIRE(inspector.set_echo_close_reason(lit_str("different")));
        inspector.echo_close_code = 4000;
        inspector.received_close = true;
        REQUIRE(f.conn->ws_record_peer_close(from_client, inspector));
        const auto kContext = f.conn->ws_session_close_context();
        const auto& peer = from_client ? kContext.client : kContext.upstream;
        const auto& other = from_client ? kContext.upstream : kContext.client;
        CHECK(peer.received);
        CHECK_EQ(peer.code, 3003u);
        CHECK(peer.reason.eq(kReason));
        CHECK_FALSE(other.received);
        CHECK_EQ(other.code, 1006u);
        CHECK(other.reason.empty());
        CHECK_FALSE(kContext.was_clean);
        CHECK_EQ(f.conn->ws_close_payload.code, 1000u);
        REQUIRE(f.acknowledge(!from_client));
        CHECK_EQ(f.conn->fd, -1);
        CHECK(ws_close_observation.clean);
        CHECK_EQ(
            from_client ? ws_close_observation.client_code : ws_close_observation.upstream_code,
            3003u);
    }
}

TEST(websocket, close_context_distinguishes_empty_close_from_missing_and_resets) {
    WsClosingFixture f;
    f.setup();
    REQUIRE(f.start());
    f.sent(true);
    f.sent(false);
    const u8 kEmptyClose[] = {0x88, 0x80, 1, 2, 3, 4};
    REQUIRE(f.receive(true, kEmptyClose, sizeof(kEmptyClose)));
    const auto kContext = f.conn->ws_session_close_context();
    CHECK_EQ(kContext.client.code, 1005u);
    CHECK(kContext.client.received);
    CHECK(kContext.client.reason.empty());
    CHECK_EQ(kContext.upstream.code, 1006u);
    CHECK_FALSE(kContext.upstream.received);
    // A timeout observes the received status without claiming a clean session.
    f.loop.close_conn(*f.conn);
    CHECK_EQ(ws_close_observation.client_code, 1005u);
    CHECK_EQ(ws_close_observation.upstream_code, 1006u);
    CHECK_FALSE(ws_close_observation.clean);
    const auto kReset = f.conn->ws_session_close_context();
    CHECK_EQ(kReset.client.code, 1006u);
    CHECK_EQ(kReset.upstream.code, 1006u);
    CHECK_FALSE(kReset.was_clean);
}

TEST(websocket, close_context_records_valid_receipt_even_when_reply_cannot_fit) {
    WsClosingFixture f;
    f.setup();
    u8 frame[32];
    u64 rng = 0;
    const u32 kLength = ws_emit_close_frame(frame, sizeof(frame), true, rng, 3005, lit_str("peer"));
    REQUIRE(kLength != 0);
    u32 consumed = 0, produced = 0;
    // Valid receive, failed send capacity. This is still a received Close,
    // while the session remains unclean because the reply never completed.
    CHECK(ws_inspect(f.conn->ws_c2u,
                     frame,
                     kLength,
                     f.c2u_output,
                     0,
                     f.c2u_message,
                     sizeof(f.c2u_message),
                     f.conn->ws_handler,
                     f.conn,
                     &consumed,
                     &produced) == WsInspectStatus::Error);
    CHECK_EQ(produced, 0u);
    REQUIRE(f.conn->ws_record_peer_close(true, f.conn->ws_c2u));
    const auto kContext = f.conn->ws_session_close_context();
    CHECK_EQ(kContext.client.code, 3005u);
    CHECK(kContext.client.reason.eq(lit_str("peer")));
    CHECK(kContext.client.received);
    CHECK_FALSE(kContext.was_clean);
}

TEST(websocket, malformed_close_ack_fails_without_waiting_for_more_input) {
    WsClosingFixture f;
    f.setup();
    REQUIRE(f.start());
    f.sent(true);
    f.sent(false);
    const u8 invalid[] = {0x88, 0x82, 1, 2, 3, 4, static_cast<u8>(3 ^ 1), static_cast<u8>(238 ^ 2)};
    REQUIRE(f.receive(true, invalid, sizeof(invalid)));
    CHECK_EQ(f.conn->fd, -1);
    CHECK_EQ(ws_close_observation.calls, 1u);
    CHECK_FALSE(ws_close_observation.clean);
}

TEST(websocket, acknowledgement_wait_deadline_is_not_refreshed_by_closing_controls) {
    WsClosingFixture f;
    f.setup();
    REQUIRE(f.start());
    f.sent(true);
    f.sent(false);
    const u32 kStarted = f.conn->ws_shutdown_started_tick;
    const u8 ping[] = {0x89, 0x81, 1, 2, 3, 4, static_cast<u8>('p' ^ 1)};
    for (u32 tick = 0; tick < kWsShutdownDrainTimeoutSeconds; ++tick) {
        REQUIRE(f.receive(true, ping, sizeof(ping)));
        f.sent(true);
        CHECK_EQ(f.conn->ws_shutdown_started_tick, kStarted);
        f.loop.dispatch(make_ev(0, IoEventType::Timeout, 1));
        CHECK_EQ(f.conn->fd, 42);
    }
    f.loop.dispatch(make_ev(0, IoEventType::Timeout, 1));
    CHECK_EQ(f.conn->fd, -1);
    CHECK_EQ(ws_close_observation.calls, 1u);
    CHECK_FALSE(ws_close_observation.clean);
}

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
    constexpr u32 kLimits[] = {kWsTerminateMessageCapacity, kWsMaxMessageCapacity};
    constexpr bool kOrders[] = {false, true};
    for (u32 limit : kLimits) {
        for (bool with_codecs : kOrders) {
            for (bool cancel_first : kOrders) {
                MmapLoopOwner<EventLoop<AsyncMockBackend>> owner;
                REQUIRE(owner.loop != nullptr);
                auto* loop = owner.loop;
                REQUIRE(loop->init(0, -1, 0, 64).has_value());
                owner.mark_initialized();
                auto* conn = loop->alloc_conn();
                REQUIRE(conn != nullptr);
                const u32 kBulkBefore = loop->pool.bulk_available();
                conn->ws_max_message_size = limit;
                conn->ws_downstream_deflate.enabled = with_codecs;
                conn->ws_upstream_deflate.enabled = with_codecs;
                REQUIRE(loop->alloc_ws_terminate_bufs(*conn));
                CHECK_EQ(conn->ws_downstream_codec != nullptr, with_codecs);
                CHECK_EQ(conn->ws_upstream_codec != nullptr, with_codecs);
                u8* const kOutput = conn->ws_c2u_out;
                REQUIRE(kOutput != nullptr);
                const u32 kLength = limit + kWsMaxHeaderSize;
                kOutput[0] = 0x5a;
                kOutput[kLength - 1] = 0xa5;
                CHECK_EQ(loop->pool.is_bulk(kOutput), limit > kWsTerminateMessageCapacity);
                REQUIRE(loop->submit_send(*conn, kOutput, kLength));
                CHECK_EQ(conn->pending_ops, 1u);
                conn->is_ws_tunnel = true;
                conn->ws_shutdown_deadline_armed = true;
                loop->timer.add(conn, kWsShutdownDrainTimeoutSeconds);
                const u32 kConnId = conn->id;

                loop->dispatch(make_ev(
                    0, IoEventType::Timeout, static_cast<i32>(kWsShutdownDrainTimeoutSeconds + 1)));
                CHECK_EQ(conn->fd, -1);
                CHECK_EQ(conn->pending_ops, 2u);
                CHECK_EQ(conn->ws_c2u_out, kOutput);
                CHECK_EQ(loop->active_count(), 1u);
                CHECK_EQ(loop->backend.count_ops(MockOp::Cancel), 1u);
                // The parser's CPU storage is free, while both outputs remain owned.
                CHECK(conn->ws_downstream_codec == nullptr);
                CHECK(conn->ws_upstream_codec == nullptr);
                CHECK_EQ(loop->pool.bulk_available(),
                         limit > kWsTerminateMessageCapacity ? kBulkBefore - 2u : kBulkBefore);
                loop->dispatch(make_ev(kConnId,
                                       IoEventType::Send,
                                       cancel_first ? -ECANCELED : static_cast<i32>(kLength)));
                CHECK_EQ(conn->pending_ops, 1u);
                CHECK_EQ(conn->ws_c2u_out, kOutput);
                CHECK_EQ(loop->active_count(), 1u);
                CHECK_EQ(kOutput[0], 0x5au);
                CHECK_EQ(kOutput[kLength - 1], 0xa5u);
                loop->dispatch(make_ev(kConnId,
                                       IoEventType::Send,
                                       cancel_first ? static_cast<i32>(kLength) : -ECANCELED));
                CHECK_EQ(loop->active_count(), 0u);
                CHECK_EQ(conn->ws_c2u_out, nullptr);
                CHECK_EQ(loop->pool.bulk_available(), kBulkBefore);
                auto* reused = loop->alloc_conn();
                REQUIRE(reused != nullptr);
                CHECK_EQ(reused->id, kConnId);
                CHECK_FALSE(reused->ws_shutdown_deadline_armed);
                CHECK_FALSE(reused->ws_downstream_deflate.enabled);
                CHECK_FALSE(reused->ws_upstream_deflate.enabled);
                loop->free_conn(*reused);
            }
        }
    }
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

TEST(websocket, iouring_bulk_reads_keep_downstream_ring_and_bound_each_submission) {
    MmapLoopOwner<IoUringEventLoop> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    if (!init_iouring_loop_with_retry(*loop, "WebSocket bounded receive", 64))
        SKIP("io_uring unavailable");
    owner.mark_initialized();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    SocketPairOwner pair;
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair.fds), 0);
    conn->fd = pair.fds[0];
    pair.fds[0] = -1;  // The connection owns this endpoint through shutdown.
    conn->is_ws_tunnel = true;
    conn->is_ws_terminate = true;
    conn->ws_max_message_size = kWsMaxMessageCapacity;
    const u32 kTail = __atomic_load_n(loop->backend.sq_tail, __ATOMIC_ACQUIRE);
    REQUIRE(loop->submit_recv_impl(*conn));
    const auto& sqe = loop->backend.sq_entries[kTail & *loop->backend.sq_ring_mask];
    CHECK_EQ(sqe.opcode, IORING_OP_RECV);
    CHECK_EQ(sqe.len, kProvidedBufSize);
    CHECK_EQ(sqe.buf_group, kBufGroupId);
    CHECK_EQ(sqe.flags, IOSQE_BUFFER_SELECT);
    CHECK_EQ(sqe.ioprio & IORING_RECV_MULTISHOT, 0u);
    CHECK(conn->recv_armed);
    CHECK_EQ(conn->pending_ops, 1u);
    CHECK_FALSE(loop->backend.add_recv_once(conn->fd, conn->id, 0));
    CHECK_FALSE(loop->backend.add_recv_once(-1, conn->id, 1));
    CHECK_FALSE(loop->backend.add_recv_once(conn->fd, loop->connection_capacity, 1));
}

TEST(websocket, iouring_terminal_receive_rearms_after_another_callback_consumed_its_bytes) {
    MmapLoopOwner<IoUringEventLoop> owner;
    REQUIRE(owner.loop != nullptr);
    auto* loop = owner.loop;
    if (!init_iouring_loop_with_retry(*loop, "WebSocket consumed terminal", 64))
        SKIP("io_uring unavailable");
    owner.mark_initialized();
    auto* conn = loop->alloc_conn();
    REQUIRE(conn != nullptr);
    SocketPairOwner client, upstream;
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, client.fds), 0);
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, upstream.fds), 0);
    conn->fd = client.fds[0];
    client.fds[0] = -1;
    conn->upstream_fd = upstream.fds[0];
    upstream.fds[0] = -1;
    REQUIRE(loop->alloc_upstream_buf(*conn));
    conn->upstream_episode = 1;
    conn->is_ws_tunnel = true;
    conn->is_ws_terminate = true;
    conn->ws_max_message_size = kWsMaxMessageCapacity;
    conn->set_slots(&on_ws_client_recv<IoUringEventLoop>,
                    &on_ws_upstream_to_client_sent<IoUringEventLoop>,
                    &on_ws_upstream_recv<IoUringEventLoop>,
                    &on_ws_client_to_upstream_sent<IoUringEventLoop>);
    // Backend.wait copied this positive terminal's bytes before dispatch. An
    // opposite send completion has already inspected and consumed that prefix.
    REQUIRE_EQ(conn->recv_buf.len(), 0u);
    REQUIRE_EQ(conn->upstream_recv_buf.len(), 0u);
    on_ws_client_recv<IoUringEventLoop>(loop, *conn, make_ev(conn->id, IoEventType::Recv, 16));
    CHECK(conn->recv_armed);
    on_ws_upstream_recv<IoUringEventLoop>(
        loop, *conn, make_ev(conn->id, IoEventType::UpstreamRecv, 16));
    CHECK(conn->upstream_recv_armed);
    CHECK_EQ(conn->pending_ops, 2u);
    CHECK_FALSE(conn->ws_client_send_pending);
    CHECK_FALSE(conn->ws_upstream_send_pending);
    // Repeated pumps share the existing receive owners rather than duplicating SQEs.
    CHECK(ws_try_send_client_to_upstream(loop, *conn));
    CHECK(ws_try_send_upstream_to_client(loop, *conn));
    CHECK_EQ(conn->pending_ops, 2u);
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
