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
                              bool require_dual_positive_batch = false,
                              bool asynchronous = false,
                              bool cancel_retry = false,
                              bool linked = false,
                              bool poll_next_read = false,
                              u32 splice_fallback_bytes = 0) {
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
        loop.ws_splice.asynchronous = asynchronous;
        loop.ws_splice.linked = linked;
        loop.ws_splice.poll_next_read = poll_next_read;
        if (asynchronous) REQUIRE(loop.backend.splice_supported);
        loop.ws_splice.chunk_size = segment;
        loop.ws_splice.call_budget = budget;
        loop.ws_splice.copy_first = copy_first;
        loop.ws_splice.copy_limit = copy_limit;
        loop.ws_splice.check_available = check_available;
        loop.ws_splice.fast_batch = fast_batch;
        loop.ws_splice.fast_scan = fast_batch;
        if (fast_batch) {
            loop.study_http_terminal_scan = false;
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
    const u32 free_top_after_alloc = loop.free_top;
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
        if (cancel_retry) loop.test_fail_ws_splice_cancel_count = 2;
        const int closing_client = conn->fd;
        const int closing_upstream = conn->upstream_fd;
        loop.close_conn(*conn);
        if (asynchronous) {
            REQUIRE_EQ(loop.ws_splice.owners[conn->id].retiring_client, closing_client);
            REQUIRE_EQ(loop.ws_splice.owners[conn->id].retiring_upstream, closing_upstream);
            REQUIRE(fcntl(closing_client, F_GETFD) >= 0);
            REQUIRE(fcntl(closing_upstream, F_GETFD) >= 0);
        }
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
        if (asynchronous) {
            CHECK_EQ(fcntl(closing_client, F_GETFD), -1);
            CHECK_EQ(errno, EBADF);
            CHECK_EQ(fcntl(closing_upstream, F_GETFD), -1);
            CHECK_EQ(errno, EBADF);
        }
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
    bool fin_sent = false;
    bool first_batch = true;
    bool assert_first_batch_rearm = false;
    const u64 kStart = monotonic_ns();
    const u64 kDeadline = kStart + 4ull * 1000 * 1000 * 1000;
    while ((client_bytes < kBytes || origin_bytes < kBytes) && monotonic_ns() < kDeadline) {
        IoEvent events[kMaxEventsPerWait]{};
        u32 const kCount =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        if (first_batch && require_dual_positive_batch) {
            bool client_recv = false;
            bool upstream_recv = false;
            for (u32 i = 0; i < kCount; ++i) {
                client_recv =
                    client_recv || (events[i].conn_id == conn->id &&
                                    events[i].type == IoEventType::Recv && events[i].result > 0);
                upstream_recv = upstream_recv || (events[i].conn_id == conn->id &&
                                                  events[i].type == IoEventType::UpstreamRecv &&
                                                  events[i].result > 0);
            }
            REQUIRE(client_recv);
            REQUIRE(upstream_recv);
            assert_first_batch_rearm = true;
        }
        first_batch = false;
        if (linked) {
            // Completion order must not determine the accounting of a pair.
            for (u32 i = 0; i < kCount / 2; ++i) {
                const auto saved = events[i];
                events[i] = events[kCount - i - 1];
                events[kCount - i - 1] = saved;
            }
        }
        const u64 calls_before_turn = loop.ws_splice.calls;
        loop.dispatch_batch(events, kCount);
        if (assert_first_batch_rearm) {
            CHECK(loop.conns[conn->id].recv_armed);
            CHECK(loop.conns[conn->id].upstream_recv_armed);
            CHECK_FALSE(loop.conns[conn->id].ws_client_send_pending);
            CHECK_FALSE(loop.conns[conn->id].ws_upstream_send_pending);
            CHECK_EQ(loop.deferred_sync_send_count, 0u);
            assert_first_batch_rearm = false;
        }
        if (splice) CHECK(loop.ws_splice.calls - calls_before_turn <= budget);
        REQUIRE_EQ(loop.backend.failure_code(), 0);
        REQUIRE(fin_before_drain || queued_fin || conn->fd >= 0);
        // Trigger the first FIN only after reverse-direction bytes are already
        // in the pipe, so this case proves buffered drain without depending on
        // new reads or a reverse reply after EOF.
        if (fin_before_drain && !fin_sent &&
            loop.ws_splice.owners[conn->id].direction[1].buffered != 0 &&
            loop.ws_splice.owners[conn->id].direction[1].armed &&
            loop.ws_splice.owners[conn->id].direction[1].writing) {
            REQUIRE_EQ(shutdown(kClient.fd, SHUT_WR), 0);
            fin_sent = true;
        }
        if (fin_before_drain) {
            const auto& eof_owner = loop.ws_splice.owners[conn->id];
            if (eof_owner.eof_closing && eof_owner.direction[1].buffered != 0)
                CHECK_FALSE(eof_owner.eof_reverse_write_cancel_attempted);
        }
        if (!slow_reader || monotonic_ns() - kStart >= 30ull * 1000 * 1000) {
            const bool client_read_ok =
                read_available(kClient.fd, received_client, &client_bytes, kBytes);
            REQUIRE(client_read_ok || conn->fd < 0 ||
                    loop.ws_splice.owners[conn->id].direction[1].eof);
            REQUIRE(read_available(kOrigin.fd, received_origin, &origin_bytes, kBytes));
        }
        if (fin_before_drain && fin_sent &&
            (conn->fd < 0 || loop.ws_splice.owners[conn->id].eof_closing))
            break;
        if (kCount == 0) usleep(1000);
    }
    if (fin_before_drain) {
        REQUIRE(fin_sent);
        CHECK(client_bytes <= kBytes);
        CHECK(origin_bytes <= kBytes);
    } else {
        REQUIRE_EQ(client_bytes, kBytes);
        REQUIRE_EQ(origin_bytes, kBytes);
    }
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
        if (fin_before_drain) {
            CHECK_EQ(loop.ws_splice.transferred[0], origin_bytes);
            CHECK_EQ(loop.ws_splice.transferred[1], client_bytes);
        } else if (splice_fallback_bytes != 0) {
            const u32 expected_splice_max = kBytes - prefix;
            const u32 expected_splice_min = expected_splice_max - splice_fallback_bytes;
            CHECK_GE(loop.ws_splice.transferred[0], expected_splice_min);
            CHECK_LE(loop.ws_splice.transferred[0], expected_splice_max);
            CHECK_GE(loop.ws_splice.transferred[1], expected_splice_min);
            CHECK_LE(loop.ws_splice.transferred[1], expected_splice_max);
        } else {
            const u32 expected_splice_bytes = kBytes - prefix;
            CHECK_EQ(loop.ws_splice.transferred[0], pipe_failure ? 0u : expected_splice_bytes);
            CHECK_EQ(loop.ws_splice.transferred[1], pipe_failure ? 0u : expected_splice_bytes);
        }
    }
    if (fin_before_drain) {
        // The first FIN terminates after already-buffered bytes drain; no
        // reverse reply is expected after terminal EOF.
        for (u32 i = 0; i < 1000 && conn->fd >= 0; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 kCount = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, kCount);
            const bool client_read_ok =
                read_available(kClient.fd, received_client, &client_bytes, kBytes);
            REQUIRE(client_read_ok || conn->fd < 0 ||
                    loop.ws_splice.owners[conn->id].direction[1].eof);
            if (kCount == 0) usleep(1000);
        }
        CHECK(loop.ws_splice.owners[conn->id].direction[0].eof);
        CHECK(loop.ws_splice.owners[conn->id].direction[1].eof);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].eof_closing);
        CHECK_EQ(loop.ws_splice.owners[conn->id].direction[0].buffered, 0u);
        CHECK_EQ(loop.ws_splice.owners[conn->id].direction[1].buffered, 0u);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].direction[0].armed);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].direction[1].armed);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].direction[0].cancel_owned);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].direction[1].cancel_owned);
        REQUIRE(conn->fd < 0);
        const auto& owner = loop.ws_splice.owners[conn->id];
        REQUIRE(owner.eof_snapshot_taken);
        REQUIRE(owner.eof_opposite_buffered_at_snapshot != 0);
        CHECK_FALSE(owner.eof_reverse_write_cancel_attempted);
        CHECK_EQ(loop.ws_splice.read_calls[0], owner.eof_read_calls[0]);
        CHECK_EQ(loop.ws_splice.read_calls[1], owner.eof_read_calls[1]);
        CHECK_EQ(loop.ws_splice.transferred[0], owner.eof_forwarded_bytes[0]);
        CHECK_EQ(loop.ws_splice.transferred[1], owner.eof_forwarded_bytes[1]);
        CHECK_EQ(origin_bytes, owner.eof_forwarded_bytes[0]);
        CHECK_EQ(client_bytes, owner.eof_forwarded_bytes[1]);
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
    } else if (half_close && asynchronous) {
        REQUIRE_EQ(shutdown(kClient.fd, SHUT_WR), 0);
        for (u32 i = 0; i < 1000 && !loop.ws_splice.owners[conn->id].direction[0].eof; ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 count = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, count);
            if (count == 0) usleep(1000);
        }
        REQUIRE(loop.ws_splice.owners[conn->id].direction[0].eof);
        REQUIRE(conn->fd >= 0);
        const u8 reply[] = {9, 8, 7, 6};
        REQUIRE(write_burst(kOrigin.fd, reply, sizeof(reply)));
        REQUIRE_EQ(shutdown(kOrigin.fd, SHUT_WR), 0);
        u8 received[4]{};
        u32 offset = 0;
        for (u32 i = 0; i < 1000 && (conn->pending_ops != 0 || offset != sizeof(reply)); ++i) {
            IoEvent events[kMaxEventsPerWait]{};
            const u32 count = loop.backend.wait(
                events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
            loop.dispatch_batch(events, count);
            REQUIRE(read_available(kClient.fd, received, &offset, sizeof(reply)));
            if (count == 0) usleep(1000);
        }
        CHECK_EQ(offset, sizeof(reply));
        CHECK(__builtin_memcmp(received, reply, sizeof(reply)) == 0);
        CHECK(conn->fd < 0);
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
    if (fin_before_drain) {
        CHECK_EQ(loop.free_top, free_top_after_alloc + 1);
        loop.ws_splice.progress(loop);
        CHECK_FALSE(loop.ws_splice.owners[conn->id].queued);
        CHECK_EQ(loop.ws_splice.queued_count, 0u);
    }
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
TEST(websocket, iouring_sync_send_two_positive_recv_cqes_rearm_after_batch) {
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
                      64,
                      false,
                      false,
                      true,
                      64,
                      false,
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

// Exercise the production tunnel callbacks in both directions. A small send
// buffer makes the first synchronous write short; the callback must then keep
// the complete source buffer alive until the async suffix completes.
static void sync_callback_short_write(test::TestCase* _tc, bool client_to_upstream, bool sq_full) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_ws_sync_send = true;
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    int filler[2];
    REQUIRE_EQ(test::stream_socketpair(filler), 0);
    const Peer kClient{downstream[1]}, kOrigin{upstream[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = downstream[0];
    conn->upstream_fd = upstream[0];
    REQUIRE(set_nonblocking(conn->fd));
    REQUIRE(set_nonblocking(conn->upstream_fd));
    REQUIRE(loop.alloc_upstream_buf(*conn));
    conn->protocol = ConnProtocol::Http11;
    conn->state = ConnState::Sending;
    conn->upstream_episode = 1;
    conn->is_ws_tunnel = true;
    conn->set_slots(&on_ws_client_recv<IoUringEventLoop>,
                    &on_ws_upstream_to_client_sent<IoUringEventLoop>,
                    &on_ws_upstream_recv<IoUringEventLoop>,
                    &on_ws_client_to_upstream_sent<IoUringEventLoop>);

    constexpr u32 kLength = SlicePool::kSliceSize;
    u8 expected[kLength], received[kLength];
    for (u32 i = 0; i < kLength; ++i) expected[i] = static_cast<u8>(i * 31u + 7u);
    auto& buffer = client_to_upstream ? conn->recv_buf : conn->upstream_recv_buf;
    __builtin_memcpy(buffer.write_ptr(), expected, kLength);
    buffer.commit(kLength);
    int small = 4096;
    const i32 target = client_to_upstream ? conn->upstream_fd : conn->fd;
    const i32 peer = client_to_upstream ? kOrigin.fd : kClient.fd;
    REQUIRE_EQ(setsockopt(target, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)), 0);
    REQUIRE_EQ(setsockopt(peer, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)), 0);

    if (sq_full) {
        u32 guard = 0;
        while (loop.backend.sq_has_room() && guard++ < 4u * loop.backend.sq_ring_entries)
            (void)loop.backend.add_recv(filler[0], loop.connection_capacity - 1u);
        REQUIRE_FALSE(loop.backend.sq_has_room());
    }

    const bool queued = client_to_upstream ? ws_try_send_client_to_upstream(&loop, *conn)
                                           : ws_try_send_upstream_to_client(&loop, *conn);
    REQUIRE(queued);
    CHECK(client_to_upstream ? conn->ws_client_send_pending : conn->ws_upstream_send_pending);
    CHECK(client_to_upstream ? conn->upstream_send_armed : conn->send_armed);
    if (sq_full) {
        CHECK_EQ(loop.study_ws_sync_attempts, 0u);
        CHECK_EQ(loop.study_ws_sync_bytes, 0u);
    } else {
        CHECK(loop.study_ws_sync_partial > 0);
    }
    CHECK_EQ(buffer.len(), kLength);  // Original bytes stay owned through the suffix send.

    u32 received_len = 0;
    const u64 deadline = monotonic_ns() + 4ull * 1000 * 1000 * 1000;
    while (received_len < kLength && monotonic_ns() < deadline) {
        REQUIRE(read_available(peer, received, &received_len, kLength));
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        REQUIRE_EQ(loop.backend.failure_code(), 0);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(received_len, kLength);
    CHECK(__builtin_memcmp(received, expected, kLength) == 0);
    CHECK_EQ(buffer.len(), 0u);
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

TEST(websocket, iouring_sync_callback_short_write_client_to_upstream) {
    sync_callback_short_write(_tc, true, false);
}
TEST(websocket, iouring_sync_callback_short_write_upstream_to_client) {
    sync_callback_short_write(_tc, false, false);
}
TEST(websocket, iouring_sync_callback_full_sq_fallback_client_to_upstream) {
    sync_callback_short_write(_tc, true, true);
}
TEST(websocket, iouring_sync_callback_full_sq_fallback_upstream_to_client) {
    sync_callback_short_write(_tc, false, true);
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
TEST(websocket, iouring_splice_shard_budget_one) {
    full_duplex_burst(_tc, false, false, false, true, false, 0, false, 65536, 1, false, 2048);
}
TEST(websocket, iouring_splice_last_budget_eintr_remains_runnable) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    loop.ws_splice.call_budget = 1;
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    Peer client{downstream[1]}, origin{upstream[1]};
    auto* connection = loop.alloc_conn();
    REQUIRE(connection != nullptr);
    connection->fd = downstream[0];
    connection->upstream_fd = upstream[0];
    connection->upstream_episode = 1;
    REQUIRE(set_nonblocking(connection->fd));
    REQUIRE(set_nonblocking(connection->upstream_fd));
    auto& owner = loop.ws_splice.owners[connection->id];
    owner.active = true;
    owner.episode = connection->upstream_episode;
    ++connection->pending_ops;
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        owner.direction[direction].read_fd = fds[0];
        owner.direction[direction].write_fd = fds[1];
    }
    loop.ws_splice.enqueue(connection->id);
    static constexpr u8 kPayload[] = "retry after interrupted final syscall";
    REQUIRE(write_burst(client.fd, kPayload, sizeof(kPayload)));

    loop.test_eintr_next_ws_splice_call = true;
    const u64 calls_before = loop.ws_splice.calls;
    loop.ws_splice.progress(loop);
    CHECK_EQ(loop.ws_splice.calls - calls_before, 1u);
    CHECK(loop.ws_splice.owners[connection->id].budget_deferred);
    CHECK(loop.ws_splice.budget_deferred_runnable);
    CHECK_EQ(loop.ws_splice.budget_deferred_runnable_count, 1u);
    CHECK_FALSE(loop.should_wait_for_event());

    u8 received[sizeof(kPayload)]{};
    u32 received_bytes = 0;
    for (u32 turn = 0; turn < 32 && received_bytes < sizeof(kPayload); ++turn) {
        loop.ws_splice.progress(loop);
        REQUIRE(read_available(origin.fd, received, &received_bytes, sizeof(kPayload)));
    }
    REQUIRE_EQ(received_bytes, sizeof(kPayload));
    CHECK(__builtin_memcmp(received, kPayload, sizeof(kPayload)) == 0);

    loop.close_conn(*connection);
    for (u32 i = 0; i < 1000 && connection->pending_ops != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(connection->pending_ops, 0u);
    CHECK_EQ(loop.backend.failure_code(), 0);
}
TEST(websocket, iouring_splice_budget_deferred_work_skips_blocking_wait) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    loop.ws_splice.call_budget = 1;
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    Peer client{downstream[1]}, origin{upstream[1]};
    auto* connection = loop.alloc_conn();
    REQUIRE(connection != nullptr);
    connection->fd = downstream[0];
    connection->upstream_fd = upstream[0];
    connection->upstream_episode = 1;
    REQUIRE(set_nonblocking(connection->fd));
    REQUIRE(set_nonblocking(connection->upstream_fd));
    auto& owner = loop.ws_splice.owners[connection->id];
    owner.active = true;
    owner.episode = connection->upstream_episode;
    ++connection->pending_ops;
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        owner.direction[direction].read_fd = fds[0];
        owner.direction[direction].write_fd = fds[1];
    }
    loop.ws_splice.enqueue(connection->id);
    const u8 payload[] = "budget deferred";
    REQUIRE(write_burst(client.fd, payload, sizeof(payload)));

    const u64 calls_before = loop.ws_splice.calls;
    loop.ws_splice.progress(loop);
    CHECK_EQ(loop.ws_splice.calls - calls_before, 1u);
    CHECK(loop.ws_splice.budget_deferred_runnable);
    CHECK_EQ(loop.ws_splice.budget_deferred_runnable_count, 1u);
    CHECK_FALSE(loop.should_wait_for_event());

    loop.close_conn(*connection);
    for (u32 i = 0; i < 1000 && connection->pending_ops != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(connection->pending_ops, 0u);
    CHECK_EQ(loop.backend.failure_code(), 0);
}
TEST(websocket, iouring_splice_armed_owner_allows_blocking_wait) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    loop.ws_splice.call_budget = 1;
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    Peer client{downstream[1]}, origin{upstream[1]};
    auto* connection = loop.alloc_conn();
    REQUIRE(connection != nullptr);
    connection->fd = downstream[0];
    connection->upstream_fd = upstream[0];
    connection->upstream_episode = 1;
    REQUIRE(set_nonblocking(connection->fd));
    REQUIRE(set_nonblocking(connection->upstream_fd));
    auto& owner = loop.ws_splice.owners[connection->id];
    owner.active = true;
    owner.episode = connection->upstream_episode;
    ++connection->pending_ops;
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        owner.direction[direction].read_fd = fds[0];
        owner.direction[direction].write_fd = fds[1];
    }
    loop.ws_splice.enqueue(connection->id);

    for (u32 turn = 0; turn < 4 && (!loop.ws_splice.owners[connection->id].direction[0].armed ||
                                    !loop.ws_splice.owners[connection->id].direction[1].armed);
         ++turn)
        loop.ws_splice.progress(loop);
    CHECK_FALSE(loop.ws_splice.budget_deferred_runnable);
    CHECK_EQ(loop.ws_splice.budget_deferred_runnable_count, 0u);
    CHECK(loop.ws_splice.owners[connection->id].direction[0].armed);
    CHECK(loop.ws_splice.owners[connection->id].direction[1].armed);
    CHECK(loop.should_wait_for_event());

    loop.close_conn(*connection);
    for (u32 i = 0; i < 1000 && connection->pending_ops != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(connection->pending_ops, 0u);
    CHECK_EQ(loop.backend.failure_code(), 0);
}
TEST(websocket, iouring_splice_retires_last_external_owner_pin) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    auto* connection = loop.alloc_conn();
    REQUIRE(connection != nullptr);
    const u32 id = connection->id;
    auto& owner = loop.ws_splice.owners[id];
    owner.closing = true;
    owner.episode = 1;
    connection->pending_ops = 1;  // Deferred free is held by the splice owner pin.
    loop.free_conn(*connection);
    REQUIRE_EQ(loop.pending_free_count, 1u);
    REQUIRE_EQ(loop.conns[id].pending_ops, 1u);
    loop.ws_splice.enqueue(id);

    loop.ws_splice.progress(loop);
    CHECK_EQ(loop.conns[id].pending_ops, 0u);
    CHECK_EQ(loop.pending_free_count, 0u);
    CHECK_EQ(loop.free_top, loop.connection_capacity);
    auto* reused = loop.alloc_conn();
    REQUIRE(reused != nullptr);
    CHECK_EQ(reused->id, id);
    loop.free_conn(*reused);
}
TEST(websocket, iouring_splice_external_close_reclaims_queued_owner_slot) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    Peer client{downstream[1]}, origin{upstream[1]};
    auto* connection = loop.alloc_conn();
    REQUIRE(connection != nullptr);
    const u32 id = connection->id;
    const u32 free_top_before = loop.free_top;
    connection->fd = downstream[0];
    connection->upstream_fd = upstream[0];
    connection->upstream_episode = 1;
    REQUIRE(set_nonblocking(connection->fd));
    REQUIRE(set_nonblocking(connection->upstream_fd));
    auto& owner = loop.ws_splice.owners[id];
    owner.active = true;
    owner.episode = connection->upstream_episode;
    ++connection->pending_ops;
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        owner.direction[direction].read_fd = fds[0];
        owner.direction[direction].write_fd = fds[1];
    }
    REQUIRE(loop.ws_splice.arm(loop, *connection, 0, false));
    loop.ws_splice.enqueue(id);
    REQUIRE_EQ(connection->pending_ops, 2u);

    loop.close_conn(*connection);
    REQUIRE_EQ(loop.pending_free_count, 1u);
    for (u32 i = 0; i < 1000 && loop.pending_free_count != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(loop.backend.failure_code(), 0);
    CHECK_EQ(loop.pending_free_count, 0u);
    CHECK_EQ(loop.free_top, free_top_before + 1);
    CHECK_FALSE(loop.ws_splice.owners[id].reclaim_pending);
    auto* reused = loop.alloc_conn();
    REQUIRE(reused != nullptr);
    CHECK_EQ(reused->id, id);
    loop.free_conn(*reused);
}
TEST(websocket, iouring_splice_shard_budget_fair_across_active_owners) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    loop.ws_splice.call_budget = 1;
    Connection* connections[2]{};
    Peer clients[2], origins[2];
    u8 sent_client[2][64], sent_origin[2][64], received_client[2][64]{}, received_origin[2][64]{};
    u32 client_bytes[2]{}, origin_bytes[2]{};
    for (u32 owner_index = 0; owner_index < 2; ++owner_index) {
        int downstream[2], upstream[2];
        REQUIRE_EQ(test::stream_socketpair(downstream), 0);
        REQUIRE_EQ(test::stream_socketpair(upstream), 0);
        clients[owner_index].fd = downstream[1];
        origins[owner_index].fd = upstream[1];
        connections[owner_index] = loop.alloc_conn();
        REQUIRE(connections[owner_index] != nullptr);
        auto& connection = *connections[owner_index];
        connection.fd = downstream[0];
        connection.upstream_fd = upstream[0];
        connection.upstream_episode = 1;
        REQUIRE(set_nonblocking(connection.fd));
        REQUIRE(set_nonblocking(connection.upstream_fd));
        auto& owner = loop.ws_splice.owners[connection.id];
        owner.active = true;
        owner.episode = connection.upstream_episode;
        ++connection.pending_ops;
        for (u32 direction = 0; direction < 2; ++direction) {
            int fds[2];
            REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
            owner.direction[direction].read_fd = fds[0];
            owner.direction[direction].write_fd = fds[1];
        }
        loop.ws_splice.enqueue(connection.id);
        for (u32 i = 0; i < 64; ++i) {
            sent_client[owner_index][i] = static_cast<u8>(owner_index * 71u + i * 3u);
            sent_origin[owner_index][i] = static_cast<u8>(owner_index * 89u + i * 5u);
        }
        REQUIRE(write_burst(clients[owner_index].fd, sent_client[owner_index], 64));
        REQUIRE(write_burst(origins[owner_index].fd, sent_origin[owner_index], 64));
    }

    bool complete = false;
    for (u32 turn = 0; turn < 128 && !complete; ++turn) {
        const u64 calls_before_turn = loop.ws_splice.calls;
        loop.ws_splice.progress(loop);
        CHECK_EQ(loop.ws_splice.calls - calls_before_turn, 1u);
        complete = true;
        for (u32 owner_index = 0; owner_index < 2; ++owner_index) {
            REQUIRE(read_available(clients[owner_index].fd,
                                   received_client[owner_index],
                                   &client_bytes[owner_index],
                                   64));
            REQUIRE(read_available(origins[owner_index].fd,
                                   received_origin[owner_index],
                                   &origin_bytes[owner_index],
                                   64));
            complete =
                complete && client_bytes[owner_index] == 64 && origin_bytes[owner_index] == 64;
        }
    }
    REQUIRE(complete);
    for (u32 owner_index = 0; owner_index < 2; ++owner_index) {
        CHECK(__builtin_memcmp(received_client[owner_index], sent_origin[owner_index], 64) == 0);
        CHECK(__builtin_memcmp(received_origin[owner_index], sent_client[owner_index], 64) == 0);
        loop.close_conn(*connections[owner_index]);
    }
    loop.ws_splice.progress(loop);
}

TEST(websocket, iouring_splice_requested_owner_survives_exhausted_turn_admission) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    loop.ws_splice.call_budget = 2;
    Connection* connections[2]{};
    Peer clients[2], origins[2];
    u8 sent_client[64], sent_origin[64], received_client[64]{}, received_origin[64]{};
    u32 client_bytes[2]{}, origin_bytes[2]{};

    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    clients[0].fd = downstream[1];
    origins[0].fd = upstream[1];
    connections[0] = loop.alloc_conn();
    REQUIRE(connections[0] != nullptr);
    auto& active_connection = *connections[0];
    active_connection.fd = downstream[0];
    active_connection.upstream_fd = upstream[0];
    active_connection.upstream_episode = 1;
    REQUIRE(set_nonblocking(active_connection.fd));
    REQUIRE(set_nonblocking(active_connection.upstream_fd));
    auto& active_owner = loop.ws_splice.owners[active_connection.id];
    active_owner.active = true;
    active_owner.episode = active_connection.upstream_episode;
    ++active_connection.pending_ops;
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        active_owner.direction[direction].read_fd = fds[0];
        active_owner.direction[direction].write_fd = fds[1];
    }
    loop.ws_splice.enqueue(active_connection.id);

    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    clients[1].fd = downstream[1];
    origins[1].fd = upstream[1];
    connections[1] = loop.alloc_conn();
    REQUIRE(connections[1] != nullptr);
    auto& requested_connection = *connections[1];
    requested_connection.fd = downstream[0];
    requested_connection.upstream_fd = upstream[0];
    requested_connection.upstream_episode = 1;
    requested_connection.protocol = ConnProtocol::Http11;
    requested_connection.is_ws_tunnel = true;
    REQUIRE(loop.alloc_upstream_buf(requested_connection));
    REQUIRE(loop.ws_splice.intercept_recv(loop, requested_connection));
    CHECK(loop.ws_splice.owners[requested_connection.id].requested);

    for (u32 i = 0; i < 64; ++i) {
        sent_client[i] = static_cast<u8>(i * 7u + 3u);
        sent_origin[i] = static_cast<u8>(i * 11u + 4u);
    }
    // The active owner has no source bytes, so its two EAGAIN probes spend
    // the whole turn before the requested owner is admitted. Its pumps must
    // preserve the new owner as runnable without spending calls.
    REQUIRE(write_burst(clients[1].fd, sent_client, 64));
    REQUIRE(write_burst(origins[1].fd, sent_origin, 64));

    const u64 calls_before = loop.ws_splice.calls;
    loop.ws_splice.progress(loop);
    CHECK_EQ(loop.ws_splice.calls - calls_before, 2u);
    auto& deferred_owner = loop.ws_splice.owners[requested_connection.id];
    CHECK_FALSE(deferred_owner.requested);
    CHECK(deferred_owner.active);
    CHECK(deferred_owner.queued);
    CHECK(deferred_owner.budget_deferred);
    CHECK_FALSE(loop.should_wait_for_event());

    bool transferred_all = false;
    for (u32 turn = 0; turn < 256 && !transferred_all; ++turn) {
        const u64 before_turn = loop.ws_splice.calls;
        loop.ws_splice.progress(loop);
        CHECK(loop.ws_splice.calls - before_turn <= loop.ws_splice.call_budget);
        REQUIRE(read_available(clients[1].fd, received_client, &client_bytes[1], 64));
        REQUIRE(read_available(origins[1].fd, received_origin, &origin_bytes[1], 64));
        transferred_all = client_bytes[1] == 64 && origin_bytes[1] == 64;
    }
    REQUIRE(transferred_all);
    CHECK(deferred_owner.active || deferred_owner.eof_closing);
    CHECK(__builtin_memcmp(received_client, sent_origin, 64) == 0);
    CHECK(__builtin_memcmp(received_origin, sent_client, 64) == 0);
    loop.close_conn(*connections[0]);
    loop.close_conn(*connections[1]);
    for (u32 i = 0;
         i < 1000 && (connections[0]->pending_ops != 0 || connections[1]->pending_ops != 0);
         ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(connections[0]->pending_ops, 0u);
    CHECK_EQ(connections[1]->pending_ops, 0u);
    CHECK_EQ(loop.backend.failure_code(), 0);
    loop.ws_splice.progress(loop);
    CHECK_EQ(loop.ws_splice.queued_count, 0u);
}

TEST(websocket, iouring_splice_failed_admission_does_not_starve_next_owner) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    loop.ws_splice.call_budget = 1;
    Connection* connections[2]{};
    Peer clients[2], origins[2];
    for (u32 index = 0; index < 2; ++index) {
        int downstream[2], upstream[2];
        REQUIRE_EQ(test::stream_socketpair(downstream), 0);
        REQUIRE_EQ(test::stream_socketpair(upstream), 0);
        clients[index].fd = downstream[1];
        origins[index].fd = upstream[1];
        connections[index] = loop.alloc_conn();
        REQUIRE(connections[index] != nullptr);
        auto& connection = *connections[index];
        connection.fd = downstream[0];
        connection.upstream_fd = upstream[0];
        connection.upstream_episode = 1;
        connection.protocol = ConnProtocol::Http11;
        connection.is_ws_tunnel = true;
        REQUIRE(loop.alloc_upstream_buf(connection));
        REQUIRE(loop.ws_splice.intercept_recv(loop, connection));
    }

    struct rlimit saved{};
    REQUIRE_EQ(getrlimit(RLIMIT_NOFILE, &saved), 0);
    struct rlimit limited = saved;
    limited.rlim_cur = 0;
    REQUIRE_EQ(setrlimit(RLIMIT_NOFILE, &limited), 0);
    loop.ws_splice.progress(loop);
    REQUIRE_EQ(setrlimit(RLIMIT_NOFILE, &saved), 0);
    CHECK(loop.ws_splice.owners[connections[0]->id].failed);
    CHECK(loop.ws_splice.owners[connections[1]->id].requested);
    REQUIRE_EQ(loop.ws_splice.queued_count, 1u);
    CHECK_EQ(loop.ws_splice.queued[loop.ws_splice.queued_head], connections[1]->id);

    const u64 calls_before_admission = loop.ws_splice.calls;
    const u64 admissions_before_admission = loop.ws_splice.admissions;
    loop.ws_splice.progress(loop);
    CHECK(loop.ws_splice.owners[connections[1]->id].active);
    CHECK_EQ(loop.ws_splice.admissions - admissions_before_admission, 1u);
    CHECK(loop.ws_splice.calls - calls_before_admission <= 1u);
    CHECK_EQ(loop.ws_splice.queued_count, 1u);
    CHECK_EQ(loop.ws_splice.queued[loop.ws_splice.queued_head], connections[1]->id);

    loop.close_conn(*connections[0]);
    loop.close_conn(*connections[1]);
    for (u32 i = 0;
         i < 1000 && (connections[0]->pending_ops != 0 || connections[1]->pending_ops != 0);
         ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(loop.backend.failure_code(), 0);
    CHECK_EQ(connections[0]->pending_ops, 0u);
    CHECK_EQ(connections[1]->pending_ops, 0u);
    loop.ws_splice.progress(loop);
    CHECK_EQ(loop.ws_splice.queued_count, 0u);
}
TEST(websocket, iouring_splice_slow_reader) {
    full_duplex_burst(_tc, false, false, true, true);
}
TEST(websocket, iouring_splice_close_with_polls) {
    full_duplex_burst(_tc, false, true, true, true);
}
TEST(websocket, iouring_splice_first_eof_stops_reads_after_buffered_data) {
    full_duplex_burst(_tc, false, false, true, true, true);
}
TEST(websocket, iouring_splice_first_eof_drains_pipe_and_closes_peer) {
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
TEST(websocket, iouring_splice_eof_retries_failed_read_cancel_without_wait) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    Peer client{downstream[1]}, origin{upstream[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = downstream[0];
    conn->upstream_fd = upstream[0];
    conn->upstream_episode = 1;
    REQUIRE(set_nonblocking(conn->fd));
    REQUIRE(set_nonblocking(conn->upstream_fd));
    auto& owner = loop.ws_splice.owners[conn->id];
    owner.active = true;
    owner.requested = true;
    owner.episode = conn->upstream_episode;
    ++conn->pending_ops;
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        owner.direction[direction].read_fd = fds[0];
        owner.direction[direction].write_fd = fds[1];
    }
    REQUIRE(loop.ws_splice.arm(loop, *conn, 1, false));
    REQUIRE_EQ(shutdown(client.fd, SHUT_WR), 0);
    loop.ws_splice.enqueue(conn->id);
    loop.test_fail_next_ws_splice_cancel = true;

    loop.ws_splice.progress(loop);
    CHECK(owner.eof_closing);
    CHECK(owner.eof_cancel_retry_deferred);
    CHECK(owner.budget_deferred);
    CHECK(owner.queued);
    CHECK(owner.direction[1].armed);
    CHECK_FALSE(loop.should_wait_for_event());

    loop.close_conn(*conn);
    for (u32 i = 0; i < 1000 && conn->pending_ops != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(conn->pending_ops, 0u);
    CHECK_EQ(loop.backend.failure_code(), 0);
}

TEST(websocket, iouring_splice_external_close_retries_failed_poll_cancel_without_wait) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    Peer client{downstream[1]}, origin{upstream[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    const u32 free_before = loop.free_top;
    conn->fd = downstream[0];
    conn->upstream_fd = upstream[0];
    conn->upstream_episode = 1;
    REQUIRE(set_nonblocking(conn->fd));
    REQUIRE(set_nonblocking(conn->upstream_fd));
    auto& owner = loop.ws_splice.owners[conn->id];
    owner.active = true;
    owner.requested = true;
    owner.episode = conn->upstream_episode;
    ++conn->pending_ops;
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        owner.direction[direction].read_fd = fds[0];
        owner.direction[direction].write_fd = fds[1];
    }
    REQUIRE(loop.ws_splice.arm(loop, *conn, 1, false));
    loop.test_fail_next_ws_splice_cancel = true;

    loop.close_conn(*conn);
    CHECK(owner.closing);
    CHECK(owner.queued);
    CHECK(owner.budget_deferred);
    CHECK_EQ(loop.ws_splice.budget_deferred_runnable_count, 1u);
    CHECK_FALSE(loop.should_wait_for_event());

    // Retry the failed cancel before any wait; the cancel CQE and target CQE
    // then retire the owner pin exactly once.
    loop.ws_splice.progress(loop);
    CHECK(owner.direction[1].cancel_owned || !owner.direction[1].armed);
    for (u32 i = 0; i < 1000 && conn->pending_ops != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(conn->pending_ops, 0u);
    CHECK_EQ(loop.free_top, free_before + 1u);
    CHECK_EQ(loop.ws_splice.budget_deferred_runnable_count, 0u);
    CHECK_EQ(loop.backend.failure_code(), 0);
}

TEST(websocket, iouring_splice_repeated_eof_cancel_failures_stay_runnable) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    Peer client{downstream[1]}, origin{upstream[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    const u32 free_before = loop.free_top;
    conn->fd = downstream[0];
    conn->upstream_fd = upstream[0];
    conn->upstream_episode = 1;
    REQUIRE(set_nonblocking(conn->fd));
    REQUIRE(set_nonblocking(conn->upstream_fd));
    auto& owner = loop.ws_splice.owners[conn->id];
    owner.active = true;
    owner.eof_closing = true;
    owner.episode = conn->upstream_episode;
    owner.direction[0].eof = owner.direction[1].eof = true;
    ++conn->pending_ops;  // owner pin
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        owner.direction[direction].read_fd = fds[0];
        owner.direction[direction].write_fd = fds[1];
    }
    REQUIRE(loop.ws_splice.arm(loop, *conn, 1, false));
    owner.direction[0].armed = true;  // synthetic completed read poll
    ++conn->pending_ops;
    CHECK_EQ(loop.ws_splice.queued_count, 0u);

    loop.test_fail_next_ws_splice_cancel = true;
    loop.test_fail_ws_splice_cancel_count = 16;
    const IoEvent completed_read{conn->id, 0, 0, 0, IoEventType::RelayRead, 0, 32, owner.episode};
    loop.dispatch_batch(&completed_read, 1);
    CHECK(owner.queued);
    CHECK(owner.budget_deferred);
    CHECK_FALSE(loop.should_wait_for_event());

    // progress() clears the marker before each retry. Multiple failures in
    // that pass must restore it, otherwise a quiet shard may block forever.
    loop.ws_splice.progress(loop);
    CHECK(owner.queued);
    CHECK(owner.budget_deferred);
    CHECK_FALSE(loop.should_wait_for_event());

    loop.test_fail_ws_splice_cancel_count = 0;
    loop.ws_splice.progress(loop);
    CHECK(owner.direction[1].cancel_owned);
    for (u32 i = 0; i < 1000 && conn->pending_ops != 0; ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(conn->pending_ops, 0u);
    CHECK_EQ(loop.free_top, free_before + 1u);
    CHECK_EQ(loop.backend.failure_code(), 0);
}

TEST(websocket, iouring_splice_recv_cache_partial_configuration_is_reclaimable) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& backend = storage.loop->backend;
    backend.test_fail_ws_recv_cache_owners_init = true;
    CHECK_FALSE(backend.enable_ws_recv_cache());
    CHECK_FALSE(backend.ws_recv_cache_enabled);
    CHECK(backend.ws_recv_cache_nodes.initialized());
    CHECK_FALSE(backend.ws_recv_cache_owners.initialized());
    backend.shutdown();
    CHECK_FALSE(backend.ws_recv_cache_nodes.initialized());
    CHECK_FALSE(backend.ws_recv_cache_owners.initialized());
}

TEST(websocket, iouring_splice_eof_close_retires_owner_once) {
    for (const bool delayed_cancel : {false, true}) {
        LoopStorage storage;
        if (!storage.init()) return;
        auto& loop = *storage.loop;
        REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
        int peers[2];
        REQUIRE_EQ(test::stream_socketpair(peers), 0);
        const Peer kPeer{peers[1]};
        auto* conn = loop.alloc_conn();
        REQUIRE(conn != nullptr);
        const u32 free_before = loop.free_top;
        conn->fd = peers[0];
        conn->pending_ops = delayed_cancel ? 2u : 1u;  // owner pin and optional cancel
        auto& owner = loop.ws_splice.owners[conn->id];
        owner.episode = 7;
        owner.active = true;
        owner.requested = true;
        owner.eof_closing = true;
        for (auto& direction : owner.direction) direction.eof = true;
        if (delayed_cancel) owner.direction[0].cancel_owned = true;
        loop.ws_splice.enqueue(conn->id);

        if (delayed_cancel) {
            loop.ws_splice.progress(loop);
            loop.ws_splice.progress(loop);
            CHECK_EQ(loop.free_top, free_before);
            CHECK_EQ(conn->pending_ops, 2u);
            const IoEvent cancel{
                conn->id, -ENOENT, 0, 0, IoEventType::RelayRead, 0, 96, owner.episode};
            CHECK(loop.ws_splice.dispatch(loop, cancel));
        } else {
            loop.ws_splice.progress(loop);
        }
        loop.ws_splice.progress(loop);
        loop.ws_splice.progress(loop);
        CHECK_EQ(conn->pending_ops, 0u);
        CHECK_EQ(loop.free_top, free_before + 1);
        CHECK_EQ(loop.ws_splice.queued_count, 0u);
        CHECK_FALSE(owner.eof_closing);
        u8 probe = 0;
        CHECK_EQ(recv(kPeer.fd, &probe, sizeof(probe), 0), 0);
        // A repeated progress turn must not retire the same connection twice.
        loop.ws_splice.progress(loop);
        CHECK_EQ(loop.free_top, free_before + 1);
    }
}

TEST(websocket, iouring_splice_cancel_ack_and_target_retire_in_either_order) {
    for (const bool ack_first : {false, true}) {
        LoopStorage storage;
        if (!storage.init()) return;
        auto& loop = *storage.loop;
        REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
        int peers[2];
        REQUIRE_EQ(test::stream_socketpair(peers), 0);
        Peer peer{peers[1]};
        auto* conn = loop.alloc_conn();
        REQUIRE(conn != nullptr);
        const u32 free_before = loop.free_top;
        conn->fd = peers[0];
        conn->upstream_episode = 7;
        auto& owner = loop.ws_splice.owners[conn->id];
        owner.episode = conn->upstream_episode;
        owner.active = true;
        owner.requested = true;
        ++conn->pending_ops;  // splice owner pin
        REQUIRE(loop.ws_splice.arm(loop, *conn, 0, false));

        const u32 before_close = __atomic_load_n(loop.backend.sq_tail, __ATOMIC_ACQUIRE);
        loop.close_conn(*conn);
        CHECK(conn->fd < 0);
        REQUIRE(owner.direction[0].cancel_owned);
        CHECK_EQ(__atomic_load_n(loop.backend.sq_tail, __ATOMIC_ACQUIRE), before_close + 1u);
        const u32 after_cancel = __atomic_load_n(loop.backend.sq_tail, __ATOMIC_ACQUIRE);

        const IoEvent kCancelAck{
            conn->id, -EALREADY, 0, 0, IoEventType::RelayRead, 0, 96, owner.episode};
        const IoEvent kTarget{
            conn->id, -ECANCELED, 0, 0, IoEventType::RelayRead, 0, 32, owner.episode};
        if (ack_first) {
            CHECK(loop.ws_splice.dispatch(loop, kCancelAck));
            CHECK_FALSE(owner.direction[0].cancel_owned);
            CHECK(owner.direction[0].cancel_acknowledged);
            CHECK(owner.direction[0].armed);
            CHECK_EQ(conn->pending_ops, 2u);  // owner pin + target poll
            loop.ws_splice.progress(loop);
            CHECK_FALSE(owner.direction[0].cancel_owned);
            CHECK(owner.direction[0].cancel_acknowledged);
            CHECK_EQ(__atomic_load_n(loop.backend.sq_tail, __ATOMIC_ACQUIRE), after_cancel);
            CHECK(loop.ws_splice.dispatch(loop, kTarget));
        } else {
            CHECK(loop.ws_splice.dispatch(loop, kTarget));
            CHECK_FALSE(owner.direction[0].armed);
            CHECK(owner.direction[0].cancel_owned);
            CHECK_FALSE(owner.direction[0].cancel_acknowledged);
            CHECK_EQ(conn->pending_ops, 2u);  // owner pin + cancel CQE
            loop.ws_splice.progress(loop);
            CHECK(owner.direction[0].cancel_owned);
            CHECK_EQ(__atomic_load_n(loop.backend.sq_tail, __ATOMIC_ACQUIRE), after_cancel);
            CHECK(loop.ws_splice.dispatch(loop, kCancelAck));
        }

        // The slot's owner pin is released from the dispatch path, then the
        // queued reclaim handoff drains without another readiness event.
        loop.ws_splice.progress(loop);
        CHECK_FALSE(owner.direction[0].armed);
        CHECK_FALSE(owner.direction[0].cancel_owned);
        CHECK_FALSE(owner.direction[0].cancel_acknowledged);
        CHECK_EQ(conn->pending_ops, 0u);
        CHECK_EQ(loop.free_top, free_before + 1u);
        CHECK_EQ(loop.ws_splice.queued_count, 0u);
        CHECK_FALSE(owner.closing);
        CHECK_EQ(loop.backend.failure_code(), 0);
    }
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
    loop.study_http_terminal_scan = false;
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

TEST(http, iouring_empty_terminal_scan_invalidates_on_real_publisher) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_http_terminal_scan = true;
    CHECK_FALSE(loop.report_http_terminal_scan);
    IoEvent event{};
    event.type = IoEventType::UpstreamRecv;
    event.conn_id = loop.connection_capacity;  // stale HTTP identity, not a WS auxiliary
    loop.dispatch_batch(&event, 1);
    REQUIRE(!loop.response_read_terminal_scan_needed);
    loop.dispatch_batch(&event, 1);
    CHECK_EQ(loop.study_http_terminal_scans_skipped, 1u);
    int fds[2];
    REQUIRE_EQ(test::stream_socketpair(fds), 0);
    const Peer kPeer{fds[1]};
    auto* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    conn->fd = fds[0];
    conn->send_armed = true;
    loop.mark_response_read_terminal_pending(*conn);
    REQUIRE(loop.response_read_terminal_scan_needed);
    loop.dispatch_batch(&event, 1);
    CHECK(loop.response_read_terminal_scan_needed);
    CHECK_EQ(loop.study_http_terminal_scans_skipped, 1u);
    conn->response_read_deadline_post_commit_terminal_pending = false;
    conn->send_armed = false;
    loop.dispatch_batch(&event, 1);
    CHECK(!loop.response_read_terminal_scan_needed);
    loop.dispatch_batch(&event, 1);
    CHECK_EQ(loop.study_http_terminal_scans_skipped, 2u);
    loop.close_conn(*conn);
}

TEST(http, iouring_boundary_ready_set_preserves_reblocked_and_stale_owners) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_http_boundary_ready_set = true;
    loop.initialize_slots_to(128);
    int first[2];
    int second[2];
    REQUIRE_EQ(test::stream_socketpair(first), 0);
    const Peer kFirstPeer{first[1]};
    REQUIRE_EQ(test::stream_socketpair(second), 0);
    const Peer kSecondPeer{second[1]};
    auto& low = loop.conns[63];
    auto& high = loop.conns[64];
    low.fd = first[0];
    high.fd = second[0];
    low.http1_boundary_deferred = high.http1_boundary_deferred = true;
    loop.maybe_publish_http1_boundary_ready(low);
    loop.maybe_publish_http1_boundary_ready(high);
    REQUIRE(low.http1_boundary_ready);
    REQUIRE(high.http1_boundary_ready);
    // Another CQE in the same batch can re-block an already published owner.
    low.upstream_recv_cancel_inflight = high.upstream_recv_cancel_inflight = true;
    loop.resume_deferred_http1_boundaries();
    CHECK(!low.http1_boundary_ready);
    CHECK(!high.http1_boundary_ready);
    CHECK(low.http1_boundary_deferred);
    CHECK(high.http1_boundary_deferred);
    CHECK_EQ(loop.study_http_boundary_slots_visited, 2u);
    low.upstream_recv_cancel_inflight = high.upstream_recv_cancel_inflight = false;
    loop.maybe_publish_http1_boundary_ready(low);
    loop.maybe_publish_http1_boundary_ready(high);
    // Close/reset may invalidate readiness before the batch boundary.
    low.http1_boundary_ready = false;
    low.http1_boundary_deferred = high.http1_boundary_deferred = false;
    loop.resume_deferred_http1_boundaries();
    CHECK(!high.http1_boundary_ready);
    CHECK_EQ(loop.http1_boundary_ready_words[0], 0u);
    CHECK_EQ(loop.http1_boundary_ready_words[1], 0u);
    CHECK_EQ(loop.study_http_boundary_slots_visited, 4u);
    low.fd = high.fd = -1;
    close(first[0]);
    close(second[0]);
}

TEST(http, iouring_boundary_default_scan_keeps_ready_bitset_unpublished) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.initialize_slots_to(64);
    int fds[2];
    REQUIRE_EQ(test::stream_socketpair(fds), 0);
    const Peer peer{fds[1]};
    auto& conn = loop.conns[7];
    conn.fd = fds[0];
    conn.http1_boundary_deferred = true;
    loop.maybe_publish_http1_boundary_ready(conn);
    REQUIRE(conn.http1_boundary_ready);
    REQUIRE(loop.http1_boundary_ready_pending);
    CHECK_EQ(loop.http1_boundary_ready_words[0], 0u);
    conn.http1_boundary_deferred = false;
    loop.resume_deferred_http1_boundaries();
    CHECK(!conn.http1_boundary_ready);
    CHECK(!loop.http1_boundary_ready_pending);
    CHECK_EQ(loop.http1_boundary_ready_words[0], 0u);
    conn.fd = -1;
    close(fds[0]);
}

TEST(http, iouring_relay_ring_preserves_fifo_across_wrap_removal_and_duplicate) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_http_relay_ring = true;
    loop.initialize_slots_to(loop.kDeferredRelayReadLimit);
    for (u32 id = 0; id < loop.kDeferredRelayReadLimit; ++id) {
        auto& conn = loop.conns[id];
        conn.relay_owner.upstream_episode = id + 1u;
        loop.defer_response_splice_read(conn);
    }
    CHECK_EQ(loop.deferred_relay_read_count, loop.kDeferredRelayReadLimit);
    // Duplicate publication at capacity must not fall through to a kernel poll.
    loop.defer_response_splice_read(loop.conns[0]);
    CHECK_EQ(loop.deferred_relay_read_count, loop.kDeferredRelayReadLimit);
    u32 id = 0;
    u32 episode = 0;
    for (u32 expected = 0; expected < 100; ++expected) {
        REQUIRE(loop.pop_deferred_relay_read(id, episode));
        CHECK_EQ(id, expected);
        CHECK_EQ(episode, expected + 1u);
    }
    for (u32 next = 0; next < 100; ++next) loop.defer_response_splice_read(loop.conns[next]);
    loop.clear_deferred_relay_read(0);    // wrapped entry
    loop.clear_deferred_relay_read(200);  // middle entry
    CHECK_EQ(loop.deferred_relay_read_count, loop.kDeferredRelayReadLimit - 2u);
    for (u32 offset = 0; offset < loop.kDeferredRelayReadLimit; ++offset) {
        const u32 kExpected = (100u + offset) % loop.kDeferredRelayReadLimit;
        if (kExpected == 0 || kExpected == 200) continue;
        REQUIRE(loop.pop_deferred_relay_read(id, episode));
        CHECK_EQ(id, kExpected);
        CHECK_EQ(episode, kExpected + 1u);
    }
    CHECK(!loop.pop_deferred_relay_read(id, episode));
    // A reused identity with a different episode is a distinct queue owner.
    loop.defer_response_splice_read(loop.conns[7]);
    loop.conns[7].relay_owner.upstream_episode = 999;
    loop.defer_response_splice_read(loop.conns[7]);
    CHECK_EQ(loop.deferred_relay_read_count, 2u);
    loop.clear_deferred_relay_read(7);
    CHECK_EQ(loop.deferred_relay_read_count, 0u);
}

static void byte_fairness(test::TestCase* _tc, bool byte_gate) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_http_byte_yield = byte_gate;
    loop.study_relay_turn_byte_limit = 512 * 1024;
    loop.ordinary_cq_wait_limit_ns = 0;
    int first_up[2];
    int second_up[2];
    int first_down[2];
    int second_down[2];
    REQUIRE_EQ(test::stream_socketpair(first_up), 0);
    REQUIRE_EQ(test::stream_socketpair(second_up), 0);
    REQUIRE_EQ(test::stream_socketpair(first_down), 0);
    REQUIRE_EQ(test::stream_socketpair(second_down), 0);
    const Peer kFirstUpPeer{first_up[1]};
    const Peer kSecondUpPeer{second_up[1]};
    const Peer kFirstDownPeer{first_down[1]};
    const Peer kSecondDownPeer{second_down[1]};
    int buffer_size = 1024 * 1024;
    REQUIRE_EQ(setsockopt(first_up[1], SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)),
               0);
    REQUIRE_EQ(setsockopt(first_down[0], SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)),
               0);
    static u8 payload[128 * 1024]{};
    REQUIRE(write_burst(first_up[1], payload, sizeof(payload)));
    auto* first = loop.alloc_conn();
    auto* second = loop.alloc_conn();
    REQUIRE(first != nullptr);
    REQUIRE(second != nullptr);
    first->fd = first_down[0];
    first->upstream_fd = first_up[0];
    second->fd = second_down[0];
    second->upstream_fd = second_up[0];
    Connection* targets[2] = {first, second};
    for (auto* conn : targets) {
        REQUIRE_EQ(fcntl(conn->fd, F_SETFL, fcntl(conn->fd, F_GETFL) | O_NONBLOCK), 0);
        REQUIRE_EQ(
            fcntl(conn->upstream_fd, F_SETFL, fcntl(conn->upstream_fd, F_GETFL) | O_NONBLOCK), 0);
        conn->protocol = ConnProtocol::Http11;
        conn->state = ConnState::Proxying;
        conn->req_method = static_cast<u8>(LogHttpMethod::Get);
        conn->request_upload_complete = true;
        conn->resp_body_mode = BodyMode::ContentLength;
        conn->resp_body_remaining = sizeof(payload);
        conn->resp_status = 200;
        conn->keep_alive = false;
        conn->upstream_keep_alive = false;
        loop.relay_budget_calls = 0;
        REQUIRE(loop.start_response_splice(*conn));
    }
    REQUIRE_EQ(loop.deferred_relay_read_count, 2u);
    loop.relay_budget_calls = 16;
    loop.relay_budget_bytes = 512 * 1024;
    u32 fake_head = 0;
    u32 fake_tail = 1;
    u32 fake_mask = 0;
    const u32 kFreeTopBeforeFlush = loop.free_top;
    io_uring_cqe ordinary{};
    ordinary.user_data = encode_non_upstream_user_data({second->id, IoEventType::Send, 1});
    auto* saved_head = loop.backend.cq_head;
    auto* saved_tail = loop.backend.cq_tail;
    auto* saved_entries = loop.backend.cq_entries;
    auto* saved_mask = loop.backend.cq_ring_mask;
    loop.backend.cq_head = &fake_head;
    loop.backend.cq_tail = &fake_tail;
    loop.backend.cq_entries = &ordinary;
    loop.backend.cq_ring_mask = &fake_mask;
    loop.flush_deferred_relay_reads();
    loop.backend.cq_head = saved_head;
    loop.backend.cq_tail = saved_tail;
    loop.backend.cq_entries = saved_entries;
    loop.backend.cq_ring_mask = saved_mask;
    // The first read/write spends half the bytes while calls remain. A
    // pending ordinary completion must leave the second relay queued.
    CHECK_EQ(loop.relay_written_bytes, sizeof(payload));
    CHECK_EQ(loop.deferred_relay_read_count, byte_gate ? 1u : 0u);
    CHECK_EQ(second->relay_owner.read_armed, !byte_gate);
    CHECK_EQ(loop.study_relay_yields, byte_gate ? 1u : 0u);
    CHECK_EQ(loop.free_top, kFreeTopBeforeFlush + 1u);
    CHECK_EQ(first->fd, -1);
    CHECK(second->fd >= 0);
    // The synchronous relay can complete the first response and return its
    // slot during flush_deferred_relay_reads(). Only close the still-live
    // second owner; closing the already-reset first slot would free it twice.
    if (first->fd >= 0) loop.close_conn(*first);
    if (second->fd >= 0) loop.close_conn(*second);
    for (u32 i = 0; i < 1000 && (first->pending_ops != 0 || second->pending_ops != 0); ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 kCount =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, kCount);
        if (kCount == 0) usleep(1000);
    }
    CHECK_EQ(first->pending_ops, 0u);
    CHECK_EQ(second->pending_ops, 0u);
    CHECK_EQ(loop.free_top, kFreeTopBeforeFlush + 2u);
}

TEST(http, byte_budget_completion_observation) {
    byte_fairness(_tc, true);
}
TEST(http, call_budget_default_completion_observation) {
    byte_fairness(_tc, false);
}

TEST(http, taskrun_readiness_is_observed_before_cq_publication) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    u32 head = 0;
    u32 tail = 0;
    u32 flags = 0;
    auto* saved_head = loop.backend.cq_head;
    auto* saved_tail = loop.backend.cq_tail;
    auto* saved_flags = loop.backend.sq_flags;
    loop.backend.cq_head = &head;
    loop.backend.cq_tail = &tail;
    loop.backend.sq_flags = &flags;
    loop.study_http_taskrun_yield = true;
    CHECK(!loop.has_ordinary_cq_work());
    flags = IORING_SQ_TASKRUN;
    CHECK(loop.has_ordinary_cq_work());
    CHECK_EQ(head, 0u);
    CHECK_EQ(flags, static_cast<u32>(IORING_SQ_TASKRUN));
    flags = IORING_SQ_CQ_OVERFLOW;
    CHECK(loop.has_ordinary_cq_work());
    flags = IORING_SQ_NEED_WAKEUP;
    CHECK(!loop.has_ordinary_cq_work());
    loop.study_http_taskrun_yield = false;
    flags = IORING_SQ_TASKRUN;
    CHECK(!loop.has_ordinary_cq_work());
    loop.backend.cq_head = saved_head;
    loop.backend.cq_tail = saved_tail;
    loop.backend.sq_flags = saved_flags;
}

TEST(http, newly_dispatched_relay_read_preserves_older_runnable_owner) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    int first_up[2], second_up[2], first_down[2], second_down[2];
    REQUIRE_EQ(test::stream_socketpair(first_up), 0);
    REQUIRE_EQ(test::stream_socketpair(second_up), 0);
    REQUIRE_EQ(test::stream_socketpair(first_down), 0);
    REQUIRE_EQ(test::stream_socketpair(second_down), 0);
    const Peer first_up_peer{first_up[1]}, second_up_peer{second_up[1]};
    const Peer first_down_peer{first_down[1]}, second_down_peer{second_down[1]};
    static u8 payload[128 * 1024]{};
    int capacity = 1024 * 1024;
    for (int fd : {first_up[1], second_up[1], first_down[0], second_down[0]})
        REQUIRE_EQ(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)), 0);
    REQUIRE(write_burst(first_up[1], payload, sizeof(payload)));
    REQUIRE(write_burst(second_up[1], payload, sizeof(payload)));
    auto* first = loop.alloc_conn();
    auto* second = loop.alloc_conn();
    REQUIRE(first != nullptr);
    REQUIRE(second != nullptr);
    const u32 kFirstId = first->id;
    const u32 kSecondId = second->id;
    first->fd = first_down[0];
    first->upstream_fd = first_up[0];
    second->fd = second_down[0];
    second->upstream_fd = second_up[0];
    Connection* targets[2] = {first, second};
    for (auto* c : targets) {
        REQUIRE_EQ(fcntl(c->fd, F_SETFL, fcntl(c->fd, F_GETFL) | O_NONBLOCK), 0);
        REQUIRE_EQ(fcntl(c->upstream_fd, F_SETFL, fcntl(c->upstream_fd, F_GETFL) | O_NONBLOCK), 0);
        c->protocol = ConnProtocol::Http11;
        c->state = ConnState::Proxying;
        c->req_method = static_cast<u8>(LogHttpMethod::Get);
        c->request_upload_complete = true;
        c->resp_body_mode = BodyMode::ContentLength;
        c->resp_body_remaining = sizeof(payload);
        c->keep_alive = false;
        c->upstream_keep_alive = false;
    }
    loop.relay_budget_calls = 0;
    REQUIRE(loop.start_response_splice(*first));
    loop.relay_budget_calls = 2;
    loop.relay_budget_bytes = 256 * 1024;
    loop.study_inside_cq = true;
    REQUIRE(loop.start_response_splice(*second));
    CHECK_EQ(loop.relay_written_bytes, 0u);
    CHECK_EQ(loop.deferred_relay_read_count, 2u);
    loop.study_inside_cq = false;
    const u32 kFreeTopBeforeFlush = loop.free_top;
    loop.flush_deferred_relay_reads();
    CHECK_EQ(loop.relay_written_bytes, sizeof(payload));
    CHECK_EQ(second->resp_body_remaining, sizeof(payload));
    CHECK_EQ(loop.deferred_relay_read_count, 1u);
    CHECK_EQ(loop.deferred_relay_read_ids[loop.deferred_relay_read_slot(0)], second->id);
    // The first relay completes synchronously in the flush and, with
    // keep_alive=false, closes and returns its slot before this test's cleanup.
    CHECK_EQ(loop.free_top, kFreeTopBeforeFlush + 1u);
    CHECK_EQ(first->fd, -1);
    CHECK(second->fd >= 0);
    if (first->fd >= 0) loop.close_conn(*first);
    if (second->fd >= 0) loop.close_conn(*second);
    for (u32 i = 0; i < 1000 && (first->pending_ops != 0 || second->pending_ops != 0); ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 kCount =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, kCount);
        if (kCount == 0) usleep(1000);
    }
    CHECK_EQ(first->pending_ops, 0u);
    CHECK_EQ(second->pending_ops, 0u);
    CHECK_EQ(loop.free_top, kFreeTopBeforeFlush + 2u);
    CHECK(kFirstId != kSecondId);
    CHECK((loop.free_stack[kFreeTopBeforeFlush] == kFirstId &&
           loop.free_stack[kFreeTopBeforeFlush + 1] == kSecondId) ||
          (loop.free_stack[kFreeTopBeforeFlush] == kSecondId &&
           loop.free_stack[kFreeTopBeforeFlush + 1] == kFirstId));
}

static void early_submit(test::TestCase* _tc, bool enabled, bool failure = false) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_http_submit_before_relay = enabled;
    int sender_fds[2];
    int relay_up[2];
    int relay_down[2];
    REQUIRE_EQ(test::stream_socketpair(sender_fds), 0);
    REQUIRE_EQ(test::stream_socketpair(relay_up), 0);
    REQUIRE_EQ(test::stream_socketpair(relay_down), 0);
    const Peer kSenderPeer{sender_fds[1]};
    const Peer kRelayUpPeer{relay_up[1]};
    const Peer kRelayDownPeer{relay_down[1]};
    auto* sender = loop.alloc_conn();
    auto* relay = loop.alloc_conn();
    REQUIRE(sender != nullptr);
    REQUIRE(relay != nullptr);
    sender->fd = sender_fds[0];
    sender->state = ConnState::Sending;
    relay->fd = relay_down[0];
    relay->upstream_fd = relay_up[0];
    relay->protocol = ConnProtocol::Http11;
    relay->state = ConnState::Proxying;
    relay->req_method = static_cast<u8>(LogHttpMethod::Get);
    relay->request_upload_complete = true;
    relay->resp_body_mode = BodyMode::ContentLength;
    relay->resp_body_remaining = 128 * 1024;
    loop.relay_budget_calls = 0;
    REQUIRE(loop.start_response_splice(*relay));
    static const u8 kPayload[] = {1, 2, 3, 4};
    REQUIRE(loop.submit_send_impl(*sender, kPayload, sizeof(kPayload)));
    REQUIRE(loop.backend.pending != 0);
    IoEvent empty[1]{};
    if (failure) loop.backend.fatal_error.store(EIO);
    loop.dispatch_batch(empty, 0);
    // With a runnable relay still queued, ordinary I/O starts at this batch
    // boundary instead of waiting behind its next compute quantum.
    pollfd ready{sender_fds[1], POLLIN, 0};
    const bool kSubmitted = enabled && !failure;
    const int kReady = poll(&ready, 1, kSubmitted ? 20 : 0);
    CHECK_EQ(kReady, kSubmitted ? 1 : 0);
    CHECK_EQ(loop.study_http_submit_before_relay_attempts, enabled ? 1u : 0u);
    CHECK_EQ(loop.deferred_relay_read_count, 1u);
    CHECK_EQ(sender->pending_ops, 1u);  // submission is not completion consumption
    CHECK(sender->send_armed);
    if (failure) {
        CHECK_EQ(loop.backend.failure_code(), EIO);
        CHECK(loop.backend.pending != 0);
        loop.backend.fatal_error.store(0);  // release the deterministic failure for cleanup
    }
    IoEvent events[8]{};
    const u32 kCount = loop.backend.wait(events, 8, loop.conns, loop.slots_initialized, false);
    loop.dispatch_batch(events, kCount);
    loop.close_conn(*sender);
    loop.close_conn(*relay);
}

TEST(http, submits_ordinary_io_before_deferred_relay_work) {
    early_submit(_tc, true);
}
TEST(http, default_retains_submission_until_wait) {
    early_submit(_tc, false);
}

TEST(http, coalesced_close_response_requires_complete_body_and_owned_capacity) {
    Connection c;
    c.reset();
    c.protocol = ConnProtocol::Http11;
    c.req_http_version = static_cast<u8>(HttpVersion::Http11);
    c.req_method = static_cast<u8>(LogHttpMethod::Get);
    c.request_policy_id = static_cast<u16>(RequestPolicyId::Http11FixedStrip);
    c.req_keep_alive = true;
    c.req_client_connection_close = true;
    c.req_client_connection_close_exact = true;
    c.req_client_connection_count = 1;
    c.resp_body_mode = BodyMode::ContentLength;
    c.resp_body_remaining = 4;
    u8 raw[128]{}, rewritten[128]{};
    c.upstream_recv_buf.bind(raw, sizeof(raw));
    c.response_header_buf.bind(rewritten, sizeof(rewritten));
    static const u8 wire[] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
    static const u8 header[] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n";
    constexpr u32 raw_header = sizeof(wire) - 1 - 4;
    REQUIRE_EQ(c.upstream_recv_buf.write(wire, sizeof(wire) - 1), sizeof(wire) - 1);
    REQUIRE_EQ(c.response_header_buf.write(header, sizeof(header) - 1), sizeof(header) - 1);
    const u32 header_size = c.response_header_buf.len();
    c.upstream_recv_buf.set_len(sizeof(wire) - 2);  // incomplete body
    CHECK(!coalesce_complete_native_close_response(c, raw_header));
    CHECK_EQ(c.response_header_buf.len(), header_size);
    c.upstream_recv_buf.set_len(sizeof(wire) - 1);
    c.resp_body_remaining = 3;  // surplus bytes must not be pooled
    CHECK(!coalesce_complete_native_close_response(c, raw_header));
    c.resp_body_remaining = 4;
    c.throttle_down_bps = 1;
    CHECK(!coalesce_complete_native_close_response(c, raw_header));
    c.throttle_down_bps = 0;
    c.response_header_buf.bind(rewritten, header_size + 3);
    c.response_header_buf.set_len(header_size);
    CHECK(!coalesce_complete_native_close_response(c, raw_header));
    c.response_header_buf.bind(rewritten, sizeof(rewritten));
    c.response_header_buf.set_len(header_size);
    REQUIRE(coalesce_complete_native_close_response(c, raw_header));
    CHECK_EQ(c.resp_body_remaining, 0u);
    CHECK_EQ(c.upstream_send_len, sizeof(wire) - 1);
    CHECK_EQ(c.resp_body_sent, header_size + 4);
    CHECK_EQ(memcmp(c.response_header_buf.data() + header_size, "body", 4), 0);
    CHECK_EQ(memcmp(raw, wire, sizeof(wire) - 1), 0);
}

TEST(http, direct_complete_proxy_response_keeps_completion_owner_after_fin) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    if (!loop.backend.nop_inject_result) return;
    loop.study_http_direct_close_response = true;
    int down[2];
    REQUIRE_EQ(test::stream_socketpair(down), 0);
    const Peer peer{down[1]};
    auto* c = loop.alloc_conn();
    REQUIRE(c != nullptr);
    c->fd = down[0];
    c->protocol = ConnProtocol::Http11;
    c->req_method = static_cast<u8>(LogHttpMethod::Get);
    c->req_body_mode = BodyMode::None;
    c->req_client_connection_close_exact = true;
    c->req_client_connection_count = 1;
    c->request_upload_complete = true;
    c->resp_body_mode = BodyMode::ContentLength;
    c->resp_body_remaining = 0;
    c->on_send = &on_proxy_response_sent<IoUringEventLoop>;
    REQUIRE(loop.alloc_response_header_buf(*c));
    static const u8 wire[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody";
    REQUIRE_EQ(c->response_header_buf.write(wire, sizeof(wire) - 1), sizeof(wire) - 1);
    c->resp_body_sent = sizeof(wire) - 1;
    REQUIRE(loop.submit_send_impl(*c, c->response_header_buf.data(), c->response_header_buf.len()));
    CHECK_EQ(loop.study_http_direct_close_completed, 1u);
    CHECK(c->write_half_closed());
    CHECK(c->send_armed);
    CHECK(c->direct_write_completion_pending);
    CHECK_EQ(c->pending_ops, 1u);
    u8 received[sizeof(wire)]{};
    REQUIRE_EQ(recv(down[1], received, sizeof(received), MSG_DONTWAIT), sizeof(wire) - 1);
    CHECK_EQ(memcmp(received, wire, sizeof(wire) - 1), 0);
    CHECK_EQ(recv(down[1], received, sizeof(received), MSG_DONTWAIT), 0);
    IoEvent events[8]{};
    u32 count = 0;
    for (u32 retry = 0; retry < 100 && count == 0; ++retry)
        count = loop.backend.wait(events, 8, loop.conns, loop.slots_initialized, false);
    REQUIRE_EQ(count, 1u);
    CHECK_EQ(events[0].type, IoEventType::Send);
    CHECK_EQ(events[0].result, sizeof(wire) - 1);
    // The wire has completed, but the common dispatcher still owns retirement.
    CHECK_EQ(c->pending_ops, 1u);
    c->pending_ops = 0;
    c->send_armed = false;
    c->direct_write_completion_pending = false;
    loop.close_conn(*c);
    CHECK(!c->write_half_closed());
}

static void initial_http_receive_owner(test::TestCase* _tc, bool enabled, bool completed_request) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    loop.study_http_initial_recv_once = enabled;
    int sockets[2];
    REQUIRE_EQ(test::stream_socketpair(sockets), 0);
    const Peer peer{sockets[1]};
    auto* c = loop.alloc_conn();
    REQUIRE(c != nullptr);
    c->fd = sockets[0];
    c->protocol = ConnProtocol::Http11;
    c->state = ConnState::ReadingHeader;
    c->downstream_completed_request_count = completed_request ? 1 : 0;
    c->on_recv = [](void*, Connection& conn, IoEvent) { ++conn.handler_gen; };
    REQUIRE_EQ(send(sockets[1], "x", 1, MSG_NOSIGNAL), 1);
    REQUIRE(loop.submit_recv_impl(*c));
    CHECK_EQ(c->pending_ops, 1u);
    IoEvent events[8]{};
    u32 count = 0;
    for (u32 retry = 0; retry < 100 && count == 0; ++retry)
        count = loop.backend.wait(events, 8, loop.conns, loop.slots_initialized, false);
    REQUIRE_EQ(count, 1u);
    const bool once = enabled && !completed_request;
    CHECK_EQ(events[0].more, once ? 0u : 1u);
    loop.dispatch_batch(events, count);
    CHECK_EQ(c->recv_armed, !once);
    CHECK_EQ(c->pending_ops, once ? 0u : 1u);
    CHECK_EQ(c->recv_buf.len(), 1u);
    CHECK_EQ(c->recv_buf.data()[0], static_cast<u8>('x'));
    loop.close_conn(*c);
}

TEST(http, initial_oneshot_receive_retires_kernel_owner_with_data) {
    initial_http_receive_owner(_tc, true, false);
}
TEST(http, initial_receive_default_retains_multishot_owner) {
    initial_http_receive_owner(_tc, false, false);
}
TEST(http, later_request_receive_retains_multishot_owner) {
    initial_http_receive_owner(_tc, true, true);
}

TEST(ws, asynchronous_splice_full_duplex_backpressure) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
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
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true);
}
TEST(ws, asynchronous_splice_close_with_operations_inflight) {
    full_duplex_burst(_tc,
                      false,
                      true,
                      true,
                      true,
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
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true);
}

TEST(ws, asynchronous_splice_half_close_preserves_reverse_reply) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      true,
                      0,
                      false,
                      65536,
                      8,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true);
}
TEST(ws, asynchronous_splice_tiny_budget_preserves_progress) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      false,
                      0,
                      false,
                      16384,
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
                      false,
                      false,
                      true);
}

TEST(ws, asynchronous_splice_close_retries_cancel_submission) {
    full_duplex_burst(_tc,
                      false,
                      true,
                      true,
                      true,
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
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      true);
}

TEST(ws, linked_splice_duplex_backpressure) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      false,
                      0,
                      false,
                      65536,
                      8,
                      false,
                      65609,
                      4096,
                      false,
                      false,
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      false,
                      true);
}
TEST(ws, linked_splice_half_close_reply) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      true,
                      0,
                      false,
                      65536,
                      8,
                      false,
                      65609,
                      4096,
                      false,
                      false,
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      false,
                      true);
}
TEST(ws, linked_splice_cancel_retry) {
    full_duplex_burst(_tc,
                      false,
                      true,
                      true,
                      true,
                      false,
                      0,
                      false,
                      65536,
                      8,
                      false,
                      65609,
                      4096,
                      false,
                      false,
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      true,
                      true);
}
TEST(ws, linked_splice_short_read) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
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
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      false,
                      true);
}
TEST(ws, linked_splice_tiny_budget) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      false,
                      0,
                      false,
                      65536,
                      2,
                      false,
                      65609,
                      4096,
                      false,
                      false,
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      false,
                      true,
                      false,
                      73);
}
TEST(ws, linked_splice_poll_next_half_close) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      true,
                      0,
                      false,
                      65536,
                      8,
                      false,
                      65609,
                      4096,
                      false,
                      false,
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      false,
                      true,
                      true);
}
TEST(ws, linked_splice_poll_next_short_read) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
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
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      false,
                      true,
                      true);
}
TEST(ws, linked_splice_128k_fast_batch_half_close) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      true,
                      0,
                      false,
                      131072,
                      16,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      true,
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      false,
                      true,
                      true);
}
TEST(ws, linked_splice_one_operation_budget_progresses_both_directions) {
    full_duplex_burst(_tc,
                      false,
                      false,
                      true,
                      true,
                      false,
                      0,
                      false,
                      65536,
                      1,
                      false,
                      64 * 1024 + 73,
                      4096,
                      false,
                      false,
                      false,
                      0,
                      false,
                      false,
                      false,
                      false,
                      true,
                      false,
                      true,
                      true,
                      73);
}

TEST(ws, async_splice_queue_budget_is_opt_in_and_resolves_sq_capacity) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    auto& splice = loop.ws_splice;
    splice.asynchronous = true;
    splice.call_budget = 1;
    splice.begin_turn(loop);
    CHECK_EQ(splice.turn_call_limit, 1u);

    const bool supported = loop.backend.splice_supported;
    loop.backend.splice_supported = false;
    splice.async_queue_budget = true;
    splice.begin_turn(loop);
    CHECK_EQ(splice.turn_call_limit, 1u);
    loop.backend.splice_supported = supported;
    if (!supported) return;

    splice.begin_turn(loop);
    CHECK_EQ(splice.turn_call_limit, loop.backend.sq_ring_entries);
    CHECK(splice.turn_call_limit > 8u);

    Connection* reclaim[10]{};
    for (u32 i = 0; i < 10; ++i) {
        reclaim[i] = loop.alloc_conn();
        REQUIRE(reclaim[i] != nullptr);
        reclaim[i]->pending_ops = 1;
        loop.free_conn(*reclaim[i]);
        reclaim[i]->pending_ops = 0;
        splice.owners[reclaim[i]->id].reclaim_pending = true;
        splice.enqueue(reclaim[i]->id);
    }
    const u32 free_before = loop.free_top;
    splice.progress(loop);
    CHECK_EQ(loop.free_top, free_before + 10u);

    splice.asynchronous = false;
    splice.begin_turn(loop);
    CHECK_EQ(splice.turn_call_limit, 1u);
}

TEST(ws, async_splice_ordinary_cq_budget_yield_keeps_owner_runnable) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    if (!loop.backend.splice_supported) return;
    int downstream[2], upstream[2];
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    Peer client{downstream[1]}, origin{upstream[1]};
    auto* connection = loop.alloc_conn();
    REQUIRE(connection != nullptr);
    connection->fd = downstream[0];
    connection->upstream_fd = upstream[0];
    connection->upstream_episode = 1;
    REQUIRE(set_nonblocking(connection->fd));
    REQUIRE(set_nonblocking(connection->upstream_fd));
    auto& splice = loop.ws_splice;
    splice.asynchronous = true;
    splice.async_queue_budget = true;
    splice.call_budget = 1;
    auto& owner = splice.owners[connection->id];
    owner.active = true;
    owner.episode = connection->upstream_episode;
    ++connection->pending_ops;
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        owner.direction[direction].read_fd = fds[0];
        owner.direction[direction].write_fd = fds[1];
    }
    splice.enqueue(connection->id);

    u32 head = 0, tail = 1, flags = IORING_SQ_TASKRUN;
    auto* saved_head = loop.backend.cq_head;
    auto* saved_tail = loop.backend.cq_tail;
    auto* saved_flags = loop.backend.sq_flags;
    loop.backend.cq_head = &head;
    loop.backend.cq_tail = &tail;
    loop.backend.sq_flags = &flags;
    loop.study_http_taskrun_yield = true;
    loop.ordinary_cq_wait_limit_ns = 0;
    int downstream2[2], upstream2[2];
    REQUIRE_EQ(test::stream_socketpair(downstream2), 0);
    REQUIRE_EQ(test::stream_socketpair(upstream2), 0);
    Peer client2{downstream2[1]}, origin2{upstream2[1]};
    auto* connection2 = loop.alloc_conn();
    REQUIRE(connection2 != nullptr);
    connection2->fd = downstream2[0];
    connection2->upstream_fd = upstream2[0];
    connection2->upstream_episode = 1;
    REQUIRE(set_nonblocking(connection2->fd));
    REQUIRE(set_nonblocking(connection2->upstream_fd));
    auto& owner2 = splice.owners[connection2->id];
    owner2.active = true;
    owner2.episode = connection2->upstream_episode;
    ++connection2->pending_ops;
    for (u32 direction = 0; direction < 2; ++direction) {
        int fds[2];
        REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
        owner2.direction[direction].read_fd = fds[0];
        owner2.direction[direction].write_fd = fds[1];
    }
    splice.enqueue(connection2->id);
    splice.begin_turn(loop);
    const u64 before = splice.calls;
    splice.pump_async(loop, *connection, 0);
    CHECK_EQ(splice.calls, before);
    CHECK(splice.queue_budget_yielded);
    CHECK(splice.owners[connection->id].budget_deferred);
    CHECK_FALSE(loop.should_wait_for_event());
    splice.progress(loop);
    CHECK_EQ(splice.queued_count, 2u);
    CHECK(splice.owners[connection->id].budget_deferred);
    CHECK(splice.owners[connection2->id].budget_deferred);
    CHECK_FALSE(loop.should_wait_for_event());

    flags = 0;
    tail = head;
    splice.begin_turn(loop);
    splice.progress(loop);
    CHECK(splice.calls >= before + 2);
    CHECK(splice.owners[connection->id].direction[0].splice_inflight);
    CHECK(splice.owners[connection2->id].direction[0].splice_inflight);
    loop.backend.cq_head = saved_head;
    loop.backend.cq_tail = saved_tail;
    loop.backend.sq_flags = saved_flags;
    loop.study_http_taskrun_yield = false;
    loop.close_conn(*connection);
    loop.close_conn(*connection2);
    for (u32 i = 0; i < 1000 && (connection->pending_ops != 0 || connection2->pending_ops != 0);
         ++i) {
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    CHECK_EQ(connection->pending_ops, 0u);
    CHECK_EQ(connection2->pending_ops, 0u);
    CHECK_EQ(loop.backend.failure_code(), 0);
}

TEST(ws, async_splice_queue_budget_submits_linked_work_for_more_than_eight_owners) {
    LoopStorage storage;
    if (!storage.init()) return;
    auto& loop = *storage.loop;
    REQUIRE(loop.ws_splice.enable(loop.connection_capacity));
    if (!loop.backend.splice_supported) return;
    auto& splice = loop.ws_splice;
    splice.asynchronous = true;
    splice.linked = true;
    splice.async_queue_budget = true;
    splice.call_budget = 1;
    constexpr u32 kOwners = 10;
    Connection* connections[kOwners]{};
    Peer clients[kOwners], origins[kOwners];
    for (u32 i = 0; i < kOwners; ++i) {
        int downstream[2], upstream[2];
        REQUIRE_EQ(test::stream_socketpair(downstream), 0);
        REQUIRE_EQ(test::stream_socketpair(upstream), 0);
        clients[i].fd = downstream[1];
        origins[i].fd = upstream[1];
        connections[i] = loop.alloc_conn();
        REQUIRE(connections[i] != nullptr);
        auto& connection = *connections[i];
        connection.fd = downstream[0];
        connection.upstream_fd = upstream[0];
        connection.upstream_episode = 1;
        REQUIRE(set_nonblocking(connection.fd));
        REQUIRE(set_nonblocking(connection.upstream_fd));
        auto& owner = splice.owners[connection.id];
        owner.active = true;
        owner.episode = connection.upstream_episode;
        ++connection.pending_ops;
        for (u32 direction = 0; direction < 2; ++direction) {
            int fds[2];
            REQUIRE_EQ(pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
            owner.direction[direction].read_fd = fds[0];
            owner.direction[direction].write_fd = fds[1];
        }
        splice.enqueue(connection.id);
    }

    splice.begin_turn(loop);
    REQUIRE(splice.turn_call_limit >= 2u * kOwners * 2u);
    const u64 calls_before = splice.calls;
    splice.progress(loop);
    CHECK_EQ(splice.calls - calls_before, 4u * kOwners);
    CHECK(splice.calls - calls_before <= splice.turn_call_limit);
    for (u32 i = 0; i < kOwners; ++i) {
        const auto& owner = splice.owners[connections[i]->id];
        CHECK(owner.direction[0].pair_active);
        CHECK(owner.direction[1].pair_active);
    }

    for (u32 i = 0; i < kOwners; ++i) loop.close_conn(*connections[i]);
    bool pending = true;
    for (u32 i = 0; i < 1000 && pending; ++i) {
        pending = false;
        for (u32 j = 0; j < kOwners; ++j) pending = pending || connections[j]->pending_ops != 0;
        if (!pending) break;
        IoEvent events[kMaxEventsPerWait]{};
        const u32 count =
            loop.backend.wait(events, kMaxEventsPerWait, loop.conns, loop.slots_initialized, false);
        loop.dispatch_batch(events, count);
        if (count == 0) usleep(1000);
    }
    for (u32 i = 0; i < kOwners; ++i) CHECK_EQ(connections[i]->pending_ops, 0u);
    CHECK_EQ(loop.backend.failure_code(), 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
