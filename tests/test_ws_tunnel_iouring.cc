#include "posix.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/io_backend.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/slice_pool.h"
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
                              bool pipe_failure = false,
                              u32 segment = 65536,
                              u32 budget = 8,
                              bool copy_first = false,
                              u32 payload_bytes = 64 * 1024 + 73,
                              u32 copy_limit = 4096,
                              bool check_available = false,
                              bool fast_batch = false,
                              bool sync_send = false,
                              u32 direct_recv_limit = 0,
                              bool poll_first = false,
                              bool queued_fin = false,
                              bool fin_before_drain = false,
                              bool fail_first_cancel = false) {
    REQUIRE(!half_close || splice);
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_ws_sync_send = sync_send;
    loop.study_ws_direct_recv_limit = direct_recv_limit;
    loop.study_ws_poll_first = poll_first;
    if (cache) REQUIRE(loop.backend.enable_ws_recv_cache());
    if (splice) {
        REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
        loop.ws_splice.chunk_size = segment;
        loop.ws_splice.call_budget = budget;
        loop.ws_splice.copy_first = copy_first;
        loop.ws_splice.copy_limit = copy_limit;
        loop.ws_splice.check_available = check_available;
        loop.ws_splice.fast_batch = fast_batch;
        loop.ws_splice.fast_scan = fast_batch;
        if (fast_batch) {
            loop.backend.study_io_stats = true;
            // Force both sampled syscall paths while exercising real byte
            // transfer, slow-reader backpressure, FIN and cancellation.
            loop.study_splice_calls[0] = loop.study_splice_calls[1] = 63;
        }
    }
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
    constexpr u32 kMaxBytes = 64 * 1024 + 73;
    const u32 kBytes = payload_bytes;
    REQUIRE(kBytes <= kMaxBytes);
    u8 sent_client[kMaxBytes], sent_origin[kMaxBytes], received_client[kMaxBytes],
        received_origin[kMaxBytes];
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
    // Keep the opposite peer open while the splice pipe drains bytes that
    // were queued before the first FIN. This exercises directional EOF rather
    // than allowing the full-duplex loop to finish both directions together.
    if (fin_before_drain) {
        loop.test_fail_next_ws_splice_cancel = fail_first_cancel;
        REQUIRE_EQ(shutdown(kClient.fd, SHUT_WR), 0);
    }
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
        for (u32 i = 0; i < 100 && (splice  ? loop.ws_splice.admissions == 0
                                    : cache ? loop.backend.ws_recv_cache_count == 0
                                            : (!conn->send_armed && !conn->upstream_send_armed));
             ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            usleep(1000);
        }
        REQUIRE(splice  ? loop.ws_splice.admissions > 0
                : cache ? loop.backend.ws_recv_cache_count > 0
                        : (conn->send_armed || conn->upstream_send_armed));
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
    if (queued_fin) {
        REQUIRE(cache);
        for (u32 i = 0; i < 100 && loop.backend.ws_recv_cache_count == 0; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            if (kCount == 0) usleep(1000);
        }
        REQUIRE(loop.backend.ws_recv_cache_count > 0);
        REQUIRE_EQ(shutdown(kClient.fd, SHUT_WR), 0);
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
        REQUIRE(fin_before_drain || queued_fin || conn->fd >= 0);
        if (!slow_reader || monotonic_ns() - kStart >= 30ull * 1000 * 1000) {
            REQUIRE(read_available(kClient.fd, received_client, &client_bytes, kBytes));
            REQUIRE(read_available(kOrigin.fd, received_origin, &origin_bytes, kBytes));
        }
        if (kCount == 0) usleep(1000);
    }
    REQUIRE_EQ(client_bytes, kBytes);
    REQUIRE_EQ(origin_bytes, kBytes);
    if (direct_recv_limit != 0) CHECK(loop.study_ws_direct_recv_arms > 0);
    if (poll_first) CHECK(loop.study_ws_poll_first_arms > 0);
    if (sync_send) {
        CHECK(loop.study_ws_sync_attempts > 0);
        if (cache) CHECK(loop.study_ws_sync_cached > 0);
        if (slow_reader)
            CHECK(loop.study_ws_sync_partial + loop.study_ws_sync_blocked > 0);
        else
            CHECK(loop.study_ws_sync_full > 0);
    }
    CHECK(__builtin_memcmp(received_client, sent_origin, kBytes) == 0);
    CHECK(__builtin_memcmp(received_origin, sent_client, kBytes) == 0);
    if (cache) {
        if (kBytes > SlicePool::kSliceSize) CHECK(loop.backend.ws_recv_cache_deferred > 0);
        CHECK_EQ(loop.backend.ws_recv_cache_count, 0u);
    }
    if (splice) {
        CHECK_EQ(loop.ws_splice.admissions, pipe_failure ? 0u : 1u);
        CHECK_EQ(loop.ws_splice.transferred[0], pipe_failure ? 0u : kBytes - prefix);
        CHECK_EQ(loop.ws_splice.transferred[1], pipe_failure ? 0u : kBytes - prefix);
    }
    if (fin_before_drain) {
        // The first FIN terminates the tunnel after already-buffered bytes
        // drain. No reverse payload or second FIN is sent; the peer socket
        // itself remains open until its owner observes the close.
        for (u32 i = 0; i < 1000 && conn->fd >= 0; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            if (kCount == 0) usleep(1000);
        }
        CHECK(loop.ws_splice.owners[conn->id].direction[0].eof);
        CHECK(loop.ws_splice.owners[conn->id].direction[1].eof);
        CHECK(loop.ws_splice.owners[conn->id].eof_closing);
        CHECK_EQ(loop.ws_splice.owners[conn->id].direction[0].buffered, 0u);
        CHECK_EQ(loop.ws_splice.owners[conn->id].direction[1].buffered, 0u);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].direction[0].armed);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].direction[1].armed);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].direction[0].cancel_owned);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].direction[1].cancel_owned);
        REQUIRE(conn->fd < 0);
        u8 probe = 0;
        // The client never sends a second FIN; EOF here is generated only by
        // the tunnel closing after its buffered bytes were drained.
        CHECK_EQ(recv(kClient.fd, &probe, sizeof(probe), MSG_DONTWAIT), 0);
    } else if (queued_fin) {
        for (u32 i = 0; i < 1000 && conn->fd >= 0; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            if (kCount == 0) usleep(1000);
        }
        REQUIRE(conn->fd < 0);
    } else if (half_close) {
        REQUIRE_EQ(shutdown(kClient.fd, SHUT_WR), 0);
        for (u32 i = 0; i < 1000 && !loop.ws_splice.owners[conn->id].direction[0].eof; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            if (kCount == 0) usleep(1000);
        }
        REQUIRE(loop.ws_splice.owners[conn->id].direction[0].eof);
        for (u32 i = 0; i < 1000 && conn->fd >= 0; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            if (kCount == 0) usleep(1000);
        }
        REQUIRE(conn->fd < 0);
        // The first FIN is terminal after the already-buffered opposite pipe
        // drains; never inject reverse data or a second FIN.
        u8 probe = 0;
        CHECK_EQ(recv(kClient.fd, &probe, sizeof(probe), MSG_DONTWAIT), 0);
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
    if (fast_batch && half_close) {
        // The initial burst can drain synchronously during handoff. FIN and
        // cancellation force actual readiness completions afterward.
        CHECK(loop.ws_splice.deadline_batches_skipped > 0);
        CHECK(loop.ws_splice.terminal_scans_skipped > 0);
    }
}

TEST(websocket, iouring_full_duplex_burst_exceeds_receive_slice) {
    full_duplex_burst(_tc, false);
}
TEST(websocket, iouring_sync_send_full_duplex_small) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      false,
                      false,
                      false,
                      0,
                      false,
                      65536,
                      8,
                      false,
                      64,
                      4096,
                      false,
                      false,
                      true);
}
TEST(websocket, iouring_sync_send_short_write_suffix_and_slow_reader) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true);
}

TEST(websocket, iouring_sync_send_reserves_suffix_before_direct_write) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_ws_sync_send = true;
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    const Peer kClient{downstream[1]}, kOrigin{upstream[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = downstream[0];
    conn->upstream_fd = upstream[0];
    REQUIRE(loop.alloc_upstream_buf(*conn));
    conn->protocol = ConnProtocol::Http11;
    conn->state = ConnState::Sending;
    conn->upstream_episode = 1;
    conn->is_ws_tunnel = true;
    static constexpr u8 kPayload[] = "short-write-reservation";
    __builtin_memcpy(conn->recv_buf.write_ptr(), kPayload, sizeof(kPayload) - 1);
    conn->recv_buf.commit(sizeof(kPayload) - 1);
    const u32 head = __atomic_load_n(loop.backend.sq_head, __ATOMIC_ACQUIRE);
    __atomic_store_n(loop.backend.sq_tail, head + loop.backend.sq_ring_entries, __ATOMIC_RELEASE);
    loop.backend.disable_full_sq_flush = true;
    i32 sent = 0;
    CHECK_FALSE(
        loop.try_ws_sync_send(*conn, true, conn->recv_buf.data(), conn->recv_buf.len(), &sent));
    CHECK_EQ(sent, 0);
    u8 probe = 0;
    errno = 0;
    CHECK_EQ(recv(kOrigin.fd, &probe, sizeof(probe), MSG_DONTWAIT), -1);
    CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
    conn->pending_ops = 0;
    loop.close_conn(*conn);
}
TEST(websocket, iouring_sync_send_close_with_async_suffix_owned) {
    full_duplex_burst(_tc,
                      false,
                      true,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true);
}

TEST(websocket, iouring_direct_recv_sync_full_duplex_slow_and_close) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true,
                      4096);
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true,
                      16384);
    full_duplex_burst(_tc,
                      false,
                      true,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true,
                      16384);
}

static void direct_recv_idle_close(test::TestCase* _tc, bool poll_first) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_ws_direct_recv_limit = 16384;
    loop.study_ws_poll_first = poll_first;
    int fds[2];
    REQUIRE_EQ(test::stream_socketpair(fds), 0);
    const Peer kOrigin{fds[1]};
    int clients[2];
    REQUIRE_EQ(test::stream_socketpair(clients), 0);
    const Peer kClient{clients[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = clients[0];
    conn->upstream_fd = fds[0];
    REQUIRE(set_nonblocking(conn->upstream_fd));
    REQUIRE(loop.alloc_upstream_buf(*conn));
    conn->protocol = ConnProtocol::Http11;
    conn->upstream_episode = 1;
    conn->is_ws_tunnel = true;
    REQUIRE(loop.submit_recv_upstream(*conn));
    REQUIRE(conn->upstream_recv_direct_armed);
    REQUIRE_EQ(conn->pending_ops, 1u);
    const u8* const kDestination = conn->upstream_recv_slice;
    // Submit the receive while the peer is idle, before closing the owner.
    // This covers kernel-held storage as well as queued SQE ownership.
    IoEvent idle_events[kMaxEventsPerWait]{};
    REQUIRE_EQ(loop.backend.wait(
                   idle_events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false),
               0u);
    REQUIRE_EQ(loop.backend.pending, 0u);
    REQUIRE(conn->upstream_recv_direct_armed);
    loop.close_conn(*conn);
    CHECK(conn->upstream_recv_slice == kDestination);
    for (u32 i = 0; i < 1000 && conn->pending_ops != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 kCount =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, kCount);
        if (kCount == 0) usleep(1000);
    }
    CHECK_EQ(loop.backend.failure_code(), 0);
    CHECK_EQ(conn->pending_ops, 0u);
    CHECK(!conn->upstream_recv_direct_armed);
    CHECK(conn->upstream_recv_slice == nullptr);
}

TEST(websocket, iouring_direct_recv_close_while_kernel_owns_destination) {
    direct_recv_idle_close(_tc, false);
    direct_recv_idle_close(_tc, true);
}

TEST(websocket, iouring_poll_first_sync_small_slow_and_close) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      false,
                      false,
                      false,
                      0,
                      false,
                      65536,
                      8,
                      false,
                      64,
                      4096,
                      false,
                      false,
                      true,
                      0,
                      true);
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true,
                      0,
                      true);
    full_duplex_burst(_tc,
                      false,
                      true,
                      true,
                      false,
                      false,
                      0,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true,
                      0,
                      true);
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true,
                      16384,
                      true);
}

TEST(websocket, iouring_multishot_sync_small_slow_and_close) {
    full_duplex_burst(_tc,
                      true,
                      false,
                      false,
                      false,
                      false,
                      0,
                      false,
                      65536,
                      8,
                      false,
                      64,
                      4096,
                      false,
                      false,
                      true);
    full_duplex_burst(_tc,
                      true,
                      false,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true);
    full_duplex_burst(_tc,
                      true,
                      true,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true);
    full_duplex_burst(_tc,
                      true,
                      false,
                      true,
                      false,
                      false,
                      12345,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true,
                      0,
                      false,
                      true);
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

TEST(websocket, iouring_multishot_cache_slow_reader_rearms_after_return) {
    // A slow destination retains every selected block briefly. The upstream
    // terminal must park until one is returned, then resume the tunnel without
    // repeatedly submitting doomed -ENOBUFS receives.
    full_duplex_burst(_tc,
                      true,
                      false,
                      true,
                      false,
                      false,
                      0,
                      false,
                      65536,
                      2,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      true);
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
TEST(websocket, iouring_splice_first_eof_drains_pipe_and_keeps_peer_open) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      true,
                      0,
                      false,
                      65536,
                      2,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      false,
                      0,
                      false,
                      false,
                      true);
}
TEST(websocket, iouring_splice_eof_retries_cancel_after_sq_full) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      true,
                      0,
                      false,
                      65536,
                      2,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      false,
                      0,
                      false,
                      false,
                      true,
                      true);
}

TEST(websocket, iouring_splice_buffered_prefix_handoff) {
    full_duplex_burst(_tc, false, false, false, true, false, 37);
}
TEST(websocket, iouring_splice_pipe_creation_failure_fallback) {
    full_duplex_burst(_tc, false, false, false, true, false, 0, true);
}

TEST(websocket, iouring_splice_large_pipe_short_turn_half_close) {
    full_duplex_burst(_tc, false, false, true, true, true, 0, false, 131072, 2);
}
TEST(websocket, iouring_splice_large_pipe_long_turn) {
    full_duplex_burst(_tc, false, false, true, true, false, 37, false, 131072, 16);
}

TEST(websocket, iouring_splice_copy_first_small_and_threshold) {
    full_duplex_burst(_tc, false, false, false, true, true, 0, false, 65536, 2, true, 64);
    full_duplex_burst(_tc, false, false, true, true, false, 0, false, 65536, 2, true, 4096);
    full_duplex_burst(_tc, false, false, true, true, false, 0, false, 65536, 2, true, 4097);
}

TEST(websocket, iouring_splice_copy_first_large_prefix_boundaries) {
    full_duplex_burst(_tc, false, false, true, true, false, 0, false, 65536, 2, true, 16384, 16384);
    full_duplex_burst(_tc, false, false, true, true, true, 37, false, 65536, 2, true, 16385, 16384);
    full_duplex_burst(_tc, false, true, true, true, false, 0, false, 65536, 2, true, 65536, 16384);
}

TEST(websocket, iouring_splice_available_bytes_gate) {
    full_duplex_burst(
        _tc, false, false, false, true, true, 0, false, 65536, 2, true, 64, 4096, true);
    full_duplex_burst(
        _tc, false, false, true, true, false, 37, false, 65536, 2, true, 65536, 4096, true);
    full_duplex_burst(
        _tc, false, true, true, true, false, 0, false, 65536, 2, true, 65536, 4096, true);
}

TEST(websocket, iouring_splice_fast_batch_preserves_mixed_preparation) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    loop.ws_splice.fast_batch = true;
    IoEvent events[2]{};
    events[0].type = IoEventType::RelayRead;
    events[0].aux = 32;
    loop.response_read_batch_owner_index[0] = 17;
    loop.prepare_response_read_deadline_batch(events, 1);
    CHECK_EQ(loop.ws_splice.deadline_batches_skipped, 1u);
    CHECK(!loop.response_read_batch_owner_index_active);
    CHECK_EQ(loop.response_read_batch_owner_count, 0u);
    CHECK_EQ(loop.response_read_batch_event_owner[0], 0u);
    // An HTTP/timer completion forces the ordinary preparation and clears
    // the old inactive index before it can be reused by a future owner.
    events[1].type = IoEventType::ResponseReadTimer;
    events[1].conn_id = loop.connection_capacity;
    loop.prepare_response_read_deadline_batch(events, 2);
    CHECK_EQ(loop.ws_splice.deadline_batches_skipped, 1u);
    CHECK(loop.response_read_batch_owner_index_active);
    CHECK_EQ(loop.response_read_batch_owner_index[0], 0u);
    events[0].aux = 0;  // Ordinary HTTP relay events must also use normal preparation.
    loop.prepare_response_read_deadline_batch(events, 1);
    CHECK_EQ(loop.ws_splice.deadline_batches_skipped, 1u);
}
TEST(websocket, iouring_splice_fast_scan_invalidates_on_http_terminal_owner) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    loop.ws_splice.fast_batch = loop.ws_splice.fast_scan = true;
    int fds[2];
    REQUIRE_EQ(test::stream_socketpair(fds), 0);
    const Peer kPeer{fds[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = fds[0];
    IoEvent event{};
    event.type = IoEventType::RelayRead;
    event.aux = 32;
    event.conn_id = loop.connection_capacity;  // retired relay identity, no live owner
    loop.dispatch_batch(&event, 1);
    CHECK(!loop.response_read_terminal_scan_needed);
    loop.dispatch_batch(&event, 1);
    CHECK_EQ(loop.ws_splice.terminal_scans_skipped, 1u);
    conn->send_armed = true;  // HTTP terminal must wait for its existing send
    loop.mark_response_read_terminal_pending(*conn);
    REQUIRE(loop.response_read_terminal_scan_needed);
    loop.dispatch_batch(&event, 1);
    CHECK(loop.response_read_terminal_scan_needed);
    CHECK_EQ(loop.ws_splice.terminal_scans_skipped, 1u);
    conn->response_read_deadline_post_commit_terminal_pending = false;
    conn->send_armed = false;
    loop.dispatch_batch(&event, 1);
    CHECK(!loop.response_read_terminal_scan_needed);
    loop.dispatch_batch(&event, 1);
    CHECK_EQ(loop.ws_splice.terminal_scans_skipped, 2u);
    event.type = IoEventType::ResponseReadTimer;
    loop.dispatch_batch(&event, 1);
    CHECK_EQ(loop.ws_splice.terminal_scans_skipped, 2u);
    loop.close_conn(*conn);
}

TEST(websocket, iouring_splice_fast_batch_half_close_and_cancel) {
    full_duplex_burst(
        _tc, false, false, true, true, true, 37, false, 65536, 2, true, 65536, 4096, false, true);
    full_duplex_burst(
        _tc, false, true, true, true, false, 0, false, 65536, 2, true, 65536, 4096, false, true);
}

TEST(websocket, iouring_splice_copy_first_slow_half_close) {
    full_duplex_burst(_tc, false, false, true, true, true, 0, false, 65536, 2, true);
}
TEST(websocket, iouring_splice_copy_first_prefix_and_close) {
    full_duplex_burst(_tc, false, true, true, true, false, 37, false, 65536, 8, true);
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
