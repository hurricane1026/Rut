#include "posix.h"
#include "rut/runtime/iouring_event_loop.h"
#include "test.h"
#include "test_helpers.h"

#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
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
        ssize_t n = send(fd, bytes + offset, length - offset, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        offset += static_cast<u32>(n);
    }
    return true;
}
bool read_available(int fd, u8* bytes, u32* offset, u32 length) {
    while (*offset < length) {
        ssize_t n = recv(fd, bytes + *offset, length - *offset, MSG_DONTWAIT);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
        if (n <= 0) return false;
        *offset += static_cast<u32>(n);
    }
    return true;
}
}  // namespace

static void full_duplex_burst(test::TestCase* _tc,
                              bool cache,
                              bool early_close = false,
                              bool slow_reader = false) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    if (cache) REQUIRE(loop.backend.enable_ws_recv_cache());
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    Peer client{downstream[1]}, origin{upstream[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = downstream[0];
    conn->upstream_fd = upstream[0];
    REQUIRE(set_nonblocking(conn->fd));
    REQUIRE(set_nonblocking(conn->upstream_fd));
    REQUIRE(loop.alloc_upstream_buf(*conn));
    if (slow_reader) {
        const int small = 4096;
        REQUIRE_EQ(setsockopt(conn->fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)), 0);
        REQUIRE_EQ(setsockopt(conn->upstream_fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)), 0);
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
    REQUIRE(write_burst(client.fd, sent_client, kBytes));
    REQUIRE(write_burst(origin.fd, sent_origin, kBytes));
    REQUIRE(loop.submit_recv(*conn));
    REQUIRE(loop.submit_recv_upstream(*conn));
    if (early_close) {
        for (u32 i = 0; i < 100 && loop.backend.ws_recv_cache_count == 0; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 count = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, count);
            usleep(1000);
        }
        REQUIRE(loop.backend.ws_recv_cache_count > 0);
        loop.close_conn(*conn);
        for (u32 i = 0; i < 1000 && conn->pending_ops != 0; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 count = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, count);
            if (count == 0) usleep(1000);
        }
        CHECK_EQ(loop.backend.failure_code(), 0);
        CHECK_EQ(loop.backend.ws_recv_cache_count, 0u);
        CHECK_EQ(conn->pending_ops, 0u);
        return;
    }
    u32 client_bytes = 0, origin_bytes = 0;
    const u64 start = monotonic_ns();
    const u64 deadline = start + 4ull * 1000 * 1000 * 1000;
    while ((client_bytes < kBytes || origin_bytes < kBytes) && monotonic_ns() < deadline) {
        IoEvent events[kMaxEventsPerWait]{};
        u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        REQUIRE_EQ(loop.backend.failure_code(), 0);
        REQUIRE(conn->fd >= 0);
        if (!slow_reader || monotonic_ns() - start >= 30ull * 1000 * 1000) {
            REQUIRE(read_available(client.fd, received_client, &client_bytes, kBytes));
            REQUIRE(read_available(origin.fd, received_origin, &origin_bytes, kBytes));
        }
        if (count == 0) usleep(1000);
    }
    REQUIRE_EQ(client_bytes, kBytes);
    REQUIRE_EQ(origin_bytes, kBytes);
    CHECK(__builtin_memcmp(received_client, sent_origin, kBytes) == 0);
    CHECK(__builtin_memcmp(received_origin, sent_client, kBytes) == 0);
    if (cache) {
        CHECK(loop.backend.ws_recv_cache_deferred > 0);
        CHECK_EQ(loop.backend.ws_recv_cache_count, 0u);
    }
    loop.close_conn(*conn);
    for (u32 i = 0; i < 1000 && conn->pending_ops != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
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

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
