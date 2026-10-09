#include "posix.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/io_backend.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/socket.h"
#include "test.h"
#include "test_helpers.h"

#include <errno.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace rut;

namespace {
struct LoopStorage {
    void* memory = MAP_FAILED;
    IoUringEventLoop* loop = nullptr;
    bool initialized = false;
    bool init() {
        memory = mmap(nullptr,
                      sizeof(IoUringEventLoop),
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1,
                      0);
        if (memory == MAP_FAILED) return false;
        loop = new (memory) IoUringEventLoop();
        initialized = init_iouring_loop_with_retry(*loop, "WebSocket burst loop");
        return initialized;
    }
    ~LoopStorage() {
        if (loop) {
            if (initialized) loop->shutdown();
            loop->~IoUringEventLoop();
        }
        if (memory != MAP_FAILED) munmap(memory, sizeof(IoUringEventLoop));
    }
};
struct Peer {
    int fd = -1;
    ~Peer() {
        if (fd >= 0) close(fd);
    }
};
bool write_burst(int fd, const u8* bytes, u32 length) {
    u32 offset = 0;
    while (offset < length) {
        ssize_t const kN = send(fd, bytes + offset, length - offset, MSG_NOSIGNAL);
        if (kN < 0 && errno == EINTR) continue;
        if (kN <= 0) return false;
        offset += static_cast<u32>(kN);
    }
    return true;
}
bool read_available(int fd, u8* bytes, u32* offset, u32 length) {
    while (*offset < length) {
        ssize_t const kN = recv(fd, bytes + *offset, length - *offset, MSG_DONTWAIT);
        if (kN < 0 && errno == EINTR) continue;
        if (kN < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
        if (kN <= 0) return false;
        *offset += static_cast<u32>(kN);
    }
    return true;
}
}  // namespace

static void full_duplex_burst(test::TestCase* _tc,
                              bool cache,
                              bool early_close = false,
                              bool slow_reader = false,
                              bool splice = false,
                              bool half_close = false,
                              u32 prefix = 0,
                              bool pipe_failure = false) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    if (cache) REQUIRE(loop.backend.enable_ws_recv_cache());
    if (splice) REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    const Peer kClient{downstream[1]}, kOrigin{upstream[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = downstream[0];
    conn->upstream_fd = upstream[0];
    REQUIRE(set_nonblocking(conn->fd));
    REQUIRE(set_nonblocking(conn->upstream_fd));
    REQUIRE(loop.alloc_upstream_buf(*conn));
    if (slow_reader) {
        const int kSmall = 4096;
        // NOLINTNEXTLINE(misc-include-cleaner): sys/socket.h provides socket options.
        REQUIRE_EQ(setsockopt(conn->fd, SOL_SOCKET, SO_SNDBUF, &kSmall, sizeof(kSmall)), 0);
        REQUIRE_EQ(setsockopt(conn->upstream_fd, SOL_SOCKET, SO_SNDBUF, &kSmall, sizeof(kSmall)),
                   0);
    }
    conn->protocol = ConnProtocol::Http11;
    conn->state = ConnState::Sending;
    conn->upstream_episode = 1;
    conn->is_ws_tunnel = true;
    conn->set_slots(&on_ws_client_recv<IoUringEventLoop>,
                    &on_ws_upstream_to_client_sent<IoUringEventLoop>,
                    &on_ws_upstream_recv<IoUringEventLoop>,
                    &on_ws_client_to_upstream_sent<IoUringEventLoop>);
    constexpr u32 kBytes = 64 * 1024 + 73;
    u8 sent_client[kBytes], sent_origin[kBytes], received_client[kBytes], received_origin[kBytes];
    for (u32 i = 0; i < kBytes; ++i) {
        sent_client[i] = static_cast<u8>(i * 29u + 3u);
        sent_origin[i] = static_cast<u8>(i * 37u + 11u);
    }
    if (prefix != 0) {
        __builtin_memcpy(conn->recv_buf.write_ptr(), sent_client, prefix);
        conn->recv_buf.commit(prefix);
        __builtin_memcpy(conn->upstream_recv_buf.write_ptr(), sent_origin, prefix);
        conn->upstream_recv_buf.commit(prefix);
        REQUIRE(ws_try_send_client_to_upstream(&loop, *conn));
        REQUIRE(ws_try_send_upstream_to_client(&loop, *conn));
    }
    REQUIRE(write_burst(kClient.fd, sent_client + prefix, kBytes - prefix));
    REQUIRE(write_burst(kOrigin.fd, sent_origin + prefix, kBytes - prefix));
    REQUIRE(loop.submit_recv(*conn));
    REQUIRE(loop.submit_recv_upstream(*conn));
    if (pipe_failure) {
        struct rlimit saved{};
        REQUIRE_EQ(getrlimit(RLIMIT_NOFILE, &saved), 0);
        struct rlimit limited = saved;
        limited.rlim_cur = 0;
        REQUIRE_EQ(setrlimit(RLIMIT_NOFILE, &limited), 0);
        loop.ws_splice.progress(loop);
        const int kRestore = setrlimit(RLIMIT_NOFILE, &saved);
        REQUIRE_EQ(kRestore, 0);
        REQUIRE(loop.ws_splice.owners[conn->id].failed);
    }
    if (early_close) {
        for (u32 i = 0; i < 100 && (splice ? loop.ws_splice.admissions == 0
                                           : loop.backend.ws_recv_cache_count == 0);
             ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            usleep(1000);
        }
        REQUIRE(splice ? loop.ws_splice.admissions > 0 : loop.backend.ws_recv_cache_count > 0);
        loop.close_conn(*conn);
        for (u32 i = 0; i < 1000 && conn->pending_ops != 0; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            if (kCount == 0) usleep(1000);
        }
        CHECK_EQ(loop.backend.failure_code(), 0);
        CHECK_EQ(loop.backend.ws_recv_cache_count, 0u);
        CHECK_EQ(conn->pending_ops, 0u);
        return;
    }
    u32 client_bytes = 0, origin_bytes = 0;
    const u64 kStart = monotonic_ns();
    const u64 kDeadline = kStart + 4ull * 1000 * 1000 * 1000;
    while ((client_bytes < kBytes || origin_bytes < kBytes) && monotonic_ns() < kDeadline) {
        IoEvent events[kMaxEventsPerWait]{};
        u32 const kCount =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, kCount);
        REQUIRE_EQ(loop.backend.failure_code(), 0);
        REQUIRE(conn->fd >= 0);
        if (!slow_reader || monotonic_ns() - kStart >= 30ull * 1000 * 1000) {
            REQUIRE(read_available(kClient.fd, received_client, &client_bytes, kBytes));
            REQUIRE(read_available(kOrigin.fd, received_origin, &origin_bytes, kBytes));
        }
        if (kCount == 0) usleep(1000);
    }
    REQUIRE_EQ(client_bytes, kBytes);
    REQUIRE_EQ(origin_bytes, kBytes);
    CHECK(__builtin_memcmp(received_client, sent_origin, kBytes) == 0);
    CHECK(__builtin_memcmp(received_origin, sent_client, kBytes) == 0);
    if (cache) {
        CHECK(loop.backend.ws_recv_cache_deferred > 0);
        CHECK_EQ(loop.backend.ws_recv_cache_count, 0u);
    }
    if (splice) {
        CHECK_EQ(loop.ws_splice.admissions, pipe_failure ? 0u : 1u);
        CHECK_EQ(loop.ws_splice.transferred[0], pipe_failure ? 0u : kBytes - prefix);
        CHECK_EQ(loop.ws_splice.transferred[1], pipe_failure ? 0u : kBytes - prefix);
    }
    if (half_close) {
        REQUIRE_EQ(shutdown(kClient.fd, SHUT_WR), 0);
        for (u32 i = 0; i < 1000 && !loop.ws_splice.owners[conn->id].direction[0].eof; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            if (kCount == 0) usleep(1000);
        }
        REQUIRE(loop.ws_splice.owners[conn->id].direction[0].eof);
        REQUIRE(conn->fd >= 0);
        constexpr u32 kReply = 19;
        u8 reply[kReply];
        u32 reply_bytes = 0;
        REQUIRE(write_burst(kOrigin.fd, sent_origin, kReply));
        for (u32 i = 0; i < 1000 && reply_bytes < kReply; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            REQUIRE(read_available(kClient.fd, reply, &reply_bytes, kReply));
            if (kCount == 0) usleep(1000);
        }
        REQUIRE_EQ(reply_bytes, kReply);
        CHECK(__builtin_memcmp(reply, sent_origin, kReply) == 0);
        REQUIRE_EQ(shutdown(kOrigin.fd, SHUT_WR), 0);
        for (u32 i = 0; i < 1000 && conn->fd >= 0; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            if (kCount == 0) usleep(1000);
        }
        REQUIRE(conn->fd < 0);
    } else
        loop.close_conn(*conn);
    for (u32 i = 0; i < 1000 && conn->pending_ops != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 kCount =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, kCount);
        if (kCount == 0) usleep(1000);
    }
    CHECK_EQ(conn->pending_ops, 0u);
}

TEST(websocket, iouring_full_duplex_burst_exceeds_receive_slice) {
    full_duplex_burst(_tc, false);
}
TEST(websocket, iouring_multishot_cache_full_duplex_burst) {
    full_duplex_burst(_tc, true);
}

TEST(websocket, iouring_multishot_cache_close_with_held_blocks) {
    full_duplex_burst(_tc, true, true);
}

TEST(websocket, iouring_multishot_cache_slow_reader) {
    full_duplex_burst(_tc, true, false, true);
}

TEST(websocket, iouring_splice_full_duplex) {
    full_duplex_burst(_tc, false, false, false, true);
}
TEST(websocket, iouring_splice_slow_reader) {
    full_duplex_burst(_tc, false, false, true, true);
}
TEST(websocket, iouring_splice_close_with_polls) {
    full_duplex_burst(_tc, false, true, true, true);
}
TEST(websocket, iouring_splice_half_close_reverse_reply) {
    full_duplex_burst(_tc, false, false, true, true, true);
}

TEST(websocket, iouring_splice_buffered_prefix_handoff) {
    full_duplex_burst(_tc, false, false, false, true, false, 37);
}
TEST(websocket, iouring_splice_pipe_creation_failure_fallback) {
    full_duplex_burst(_tc, false, false, false, true, false, 0, true);
}

TEST(websocket, iouring_splice_excludes_tls_inspection_and_throttle) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    Connection conn{};
    conn.id = 0;
    conn.fd = 123;
    conn.upstream_fd = 124;
    conn.protocol = ConnProtocol::Http11;
    conn.is_ws_tunnel = true;
    conn.tls_active = true;
    CHECK(!loop.ws_splice.intercept_recv(loop, conn));
    conn.tls_active = false;
    conn.is_ws_terminate_route = true;
    CHECK(!loop.ws_splice.intercept_recv(loop, conn));
    conn.is_ws_terminate_route = false;
    conn.throttle_down_bps = 1;
    CHECK(!loop.ws_splice.intercept_recv(loop, conn));
    conn.throttle_down_bps = 0;
    conn.response_policy_id = 1;
    CHECK(!loop.ws_splice.intercept_recv(loop, conn));
    CHECK_EQ(conn.pending_ops, 0u);
    CHECK_EQ(loop.ws_splice.queued_count, 0u);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
