#include "posix.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/upstream_pool.h"
#include "test.h"
#include "test_helpers.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rut;

namespace {

#ifdef __linux__
struct ScopedIoUringLoop {
    void* storage = MAP_FAILED;
    IoUringEventLoop* loop = nullptr;
    bool initialized = false;

    bool init() {
        storage = mmap(nullptr,
                       sizeof(IoUringEventLoop),
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);
        if (storage == MAP_FAILED) {
            report_unexpected_io_uring_init_failure(Error::from_errno(Error::Source::Mmap),
                                                    "splice-test storage mmap");
            return false;
        }
        loop = new (storage) IoUringEventLoop();
        initialized = init_iouring_loop_with_retry(*loop, "splice-test loop.init");
        return initialized;
    }

    ~ScopedIoUringLoop() {
        if (loop != nullptr) {
            if (initialized) loop->shutdown();
            loop->~IoUringEventLoop();
        }
        if (storage != MAP_FAILED) munmap(storage, sizeof(IoUringEventLoop));
    }
};

bool set_fd_nonblocking(i32 fd) {
    const i32 flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

Connection* make_eligible(IoUringEventLoop& loop,
                          i32 upstream_fd,
                          i32 downstream_fd,
                          u32 body_len,
                          bool client_keepalive = false) {
    Connection* c = loop.alloc_conn();
    if (c == nullptr) return nullptr;
    c->fd = downstream_fd;
    c->upstream_fd = upstream_fd;
    if (!set_fd_nonblocking(c->fd) || !set_fd_nonblocking(c->upstream_fd)) return nullptr;
    c->protocol = ConnProtocol::Http11;
    c->state = ConnState::Proxying;
    c->req_method = static_cast<u8>(LogHttpMethod::Get);
    c->req_body_mode = BodyMode::None;
    c->request_upload_complete = true;
    c->resp_body_mode = BodyMode::ContentLength;
    c->resp_body_remaining = body_len;
    c->resp_status = 200;
    c->req_start_us = 1;
    c->keep_alive = client_keepalive;
    c->upstream_keep_alive = false;
    return c;
}

u8 pattern(u32 i) {
    return static_cast<u8>(i * 37u + 11u);
}

bool send_all(i32 fd, const u8* data, u32 len) {
    u32 off = 0;
    while (off < len) {
        const ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        off += static_cast<u32>(n);
    }
    return true;
}

bool read_exact(i32 fd, u8* data, u32 len) {
    u32 off = 0;
    while (off < len) {
        const ssize_t n = ::recv(fd, data + off, len - off, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        off += static_cast<u32>(n);
    }
    return true;
}

bool pump_once(IoUringEventLoop& loop) {
    IoEvent events[kMaxEventsPerWait]{};
    const u32 count =
        loop.backend.wait(events, kMaxEventsPerWait, loop.conns, IoUringEventLoop::kMaxConns);
    if (count == 0) return false;
    // Match the production run loop's fresh per-wait shared splice budget.
    loop.relay_budget_calls = 8;
    loop.relay_budget_bytes = 512 * 1024;
    loop.dispatch_batch(events, count);
    return true;
}

template <typename Done>
bool pump_until(IoUringEventLoop& loop, Done done, u32 max_waits = 32) {
    for (u32 i = 0; i < max_waits && !done(); ++i) {
        if (!pump_once(loop)) return false;
    }
    return done();
}

void fill_pattern(u8* buf, u32 len) {
    for (u32 i = 0; i < len; ++i) buf[i] = pattern(i);
}

bool exact_pattern(const u8* buf, u32 len) {
    for (u32 i = 0; i < len; ++i) {
        if (buf[i] != pattern(i)) return false;
    }
    return true;
}
#endif

}  // namespace

#ifdef __linux__
TEST(iouring_splice, shared_budget_yields_and_finishes_exact_body) {
    ScopedIoUringLoop guard;
    if (!guard.init()) SKIP("io_uring unavailable");
    auto& loop = *guard.loop;
    constexpr u32 kFirstTurn = 64 * 1024;
    constexpr u32 kBody = 128 * 1024;
    static u8 expected0[kBody];
    static u8 expected1[kBody];
    static u8 received[kBody];
    fill_pattern(expected0, kBody);
    fill_pattern(expected1, kBody);
    i32 upstream[2][2] = {{-1, -1}, {-1, -1}};
    i32 downstream[2][2] = {{-1, -1}, {-1, -1}};
    int sndbuf = 1024 * 1024;
    Connection* conns[2]{};
    for (u32 i = 0; i < 2; ++i) {
        REQUIRE_EQ(test::stream_socketpair(upstream[i]), 0);
        REQUIRE_EQ(test::stream_socketpair(downstream[i]), 0);
        REQUIRE_EQ(setsockopt(upstream[i][1], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)), 0);
        REQUIRE_EQ(setsockopt(downstream[i][0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)), 0);
        const u8* initial = i == 0 ? expected0 : expected1;
        REQUIRE(send_all(upstream[i][1], initial, kFirstTurn));
        conns[i] = make_eligible(loop, upstream[i][0], downstream[i][0], kBody);
        REQUIRE(conns[i] != nullptr);
        upstream[i][0] = downstream[i][0] = -1;
    }
    REQUIRE(loop.test_start_response_splice(*conns[0]));
    REQUIRE(loop.test_start_response_splice(*conns[1]));
    CHECK_EQ(loop.relay_pulled_bytes, 128u * 1024u);
    CHECK_EQ(loop.relay_written_bytes, 128u * 1024u);
    CHECK_EQ(loop.relay_budget_calls, 4u);
    CHECK_EQ(loop.relay_budget_bytes, 256u * 1024u);
    CHECK_EQ(loop.deferred_relay_read_count, 2u);
    for (Connection* c : conns) {
        CHECK_FALSE(c->relay_owner.read_armed);
        CHECK_EQ(c->pending_ops, 0u);
    }
    IoEvent empty_batch[1]{};
    loop.dispatch_batch(empty_batch, 0);
    CHECK_EQ(loop.deferred_relay_read_count, 0u);
    for (Connection* c : conns) {
        CHECK(c->relay_owner.read_armed);
        CHECK_EQ(c->pending_ops, 1u);
    }
    for (u32 i = 0; i < 2; ++i)
        REQUIRE(send_all(
            upstream[i][1], (i == 0 ? expected0 : expected1) + kFirstTurn, kBody - kFirstTurn));
    constexpr u64 kTotalBody = static_cast<u64>(kBody) * 2;
    REQUIRE(pump_until(
        loop,
        [&] {
            return loop.relay_written_bytes == kTotalBody && !conns[0]->relay_owner.active() &&
                   !conns[1]->relay_owner.active();
        },
        32));
    for (u32 i = 0; i < 2; ++i) {
        const u32 body_len = kBody;
        const u8* expected = i == 0 ? expected0 : expected1;
        REQUIRE(read_exact(downstream[i][1], received, body_len));
        CHECK_EQ(memcmp(received, expected, body_len), 0);
        close(upstream[i][1]);
        close(downstream[i][1]);
        if (conns[i]->fd >= 0 || conns[i]->upstream_fd >= 0) loop.close_conn(*conns[i]);
    }
    CHECK_EQ(loop.relay_pulled_bytes, kTotalBody);
    CHECK_EQ(loop.relay_written_bytes, kTotalBody);
}

TEST(iouring_splice, positive_progress_refreshes_relay_timer_but_eagain_does_not) {
    {
        ScopedIoUringLoop guard;
        if (!guard.init()) SKIP("io_uring unavailable");
        auto& loop = *guard.loop;
        constexpr u32 kBody = 128 * 1024;
        static u8 body[kBody];
        fill_pattern(body, kBody);
        i32 upstream[2] = {-1, -1};
        i32 downstream[2] = {-1, -1};
        REQUIRE_EQ(test::stream_socketpair(upstream), 0);
        REQUIRE_EQ(test::stream_socketpair(downstream), 0);
        Connection* c = make_eligible(loop, upstream[0], downstream[0], kBody);
        REQUIRE(c != nullptr);
        upstream[0] = downstream[0] = -1;
        loop.upstream_timeout = 3;
        loop.timer.add(c, 1);

        auto timer_slot_contains = [&](u32 slot) {
            ListNode* head = &loop.timer.slots[slot & (TimerWheel::kSlots - 1)];
            for (ListNode* node = head->next; node != head; node = node->next)
                if (node == &c->timer_node) return true;
            return false;
        };
        REQUIRE(loop.test_start_response_splice(*c));
        CHECK(c->relay_owner.read_armed);
        CHECK(timer_slot_contains(1));
        REQUIRE(send_all(upstream[1], body, 64 * 1024));
        REQUIRE(pump_once(loop));

        CHECK(timer_slot_contains(3));
        CHECK_FALSE(timer_slot_contains(1));
        u32 expired = 0;
        loop.timer.tick([&](Connection* expired_conn) {
            CHECK_EQ(expired_conn, c);
            ++expired;
        });
        loop.timer.tick([&](Connection* expired_conn) {
            CHECK_EQ(expired_conn, c);
            ++expired;
        });
        CHECK_EQ(expired, 0u);
        close(upstream[1]);
        close(downstream[1]);
        if (c->fd >= 0 || c->upstream_fd >= 0) loop.close_conn(*c);
    }

    {
        ScopedIoUringLoop guard;
        if (!guard.init()) SKIP("io_uring unavailable");
        auto& loop = *guard.loop;
        i32 upstream[2] = {-1, -1};
        i32 downstream[2] = {-1, -1};
        REQUIRE_EQ(test::stream_socketpair(upstream), 0);
        REQUIRE_EQ(test::stream_socketpair(downstream), 0);
        Connection* c = make_eligible(loop, upstream[0], downstream[0], 128 * 1024);
        REQUIRE(c != nullptr);
        upstream[0] = downstream[0] = -1;
        loop.upstream_timeout = 3;
        loop.timer.add(c, 1);
        REQUIRE(loop.test_start_response_splice(*c));
        CHECK(c->relay_owner.read_armed);

        u32 expired = 0;
        loop.timer.tick([&](Connection* expired_conn) {
            CHECK_EQ(expired_conn, c);
            ++expired;
        });
        loop.timer.tick([&](Connection* expired_conn) {
            CHECK_EQ(expired_conn, c);
            ++expired;
        });
        CHECK_EQ(expired, 1u);
        close(upstream[1]);
        close(downstream[1]);
        if (c->fd >= 0 || c->upstream_fd >= 0) loop.close_conn(*c);
    }
}

TEST(iouring_splice, active_relay_preserves_response_on_late_recv_overflow) {
    ScopedIoUringLoop guard;
    if (!guard.init()) SKIP("io_uring unavailable");
    auto& loop = *guard.loop;
    i32 upstream[2] = {-1, -1};
    i32 downstream[2] = {-1, -1};
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    Connection* c = make_eligible(loop, upstream[0], downstream[0], 128 * 1024);
    REQUIRE(c != nullptr);
    upstream[0] = downstream[0] = -1;
    REQUIRE(loop.test_start_response_splice(*c));
    REQUIRE(c->relay_owner.active());

    c->state = ConnState::Sending;
    c->proxy_resp_started = true;
    c->clear_slots();
    CHECK(preserved_response_late_recv_owner<IoUringEventLoop>(*c));
    const IoEvent overflow{c->id, -ENOBUFS, 0, 0, IoEventType::Recv, 0};
    loop.dispatch_event(*c, overflow);
    CHECK(c->req_body_lossy_successor);
    CHECK_FALSE(c->keep_alive);
    CHECK_GE(c->fd, 0);
    CHECK_GE(c->upstream_fd, 0);
    CHECK(c->relay_owner.active());
    CHECK_EQ(c->recv_buf.len(), 0u);

    const u8 late_bytes[] = {'l', 'a', 't', 'e'};
    REQUIRE_EQ(c->recv_buf.write(late_bytes, sizeof(late_bytes)), sizeof(late_bytes));
    const IoEvent late_recv{
        c->id, static_cast<i32>(sizeof(late_bytes)), 0, 0, IoEventType::Recv, 0};
    loop.dispatch_event(*c, late_recv);
    CHECK(c->req_body_lossy_successor);
    CHECK_FALSE(c->keep_alive);
    CHECK_GE(c->fd, 0);
    CHECK_GE(c->upstream_fd, 0);
    CHECK(c->relay_owner.active());
    CHECK_EQ(c->recv_buf.len(), 0u);

    close(upstream[1]);
    close(downstream[1]);
    if (c->fd >= 0 || c->upstream_fd >= 0) loop.close_conn(*c);
}

TEST(iouring_splice, shutdown_closes_relay_pipe_after_cancel_is_queued) {
    ScopedIoUringLoop guard;
    if (!guard.init()) SKIP("io_uring unavailable");
    auto& loop = *guard.loop;
    i32 upstream[2] = {-1, -1};
    i32 downstream[2] = {-1, -1};
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    Connection* c = make_eligible(loop, upstream[0], downstream[0], 128 * 1024);
    REQUIRE(c != nullptr);
    upstream[0] = downstream[0] = -1;
    REQUIRE(loop.test_start_response_splice(*c));
    REQUIRE(c->relay_owner.read_armed);
    const int pipe_read = c->relay_owner.pipe_read;
    const int pipe_write = c->relay_owner.pipe_write;
    REQUIRE_GE(pipe_read, 0);
    REQUIRE_GE(pipe_write, 0);
    loop.close_conn(*c);
    CHECK(c->relay_owner.close_pending);
    CHECK_EQ(fcntl(pipe_read, F_GETFD) >= 0, true);
    CHECK_EQ(fcntl(pipe_write, F_GETFD) >= 0, true);

    loop.shutdown();
    guard.initialized = false;
    CHECK_EQ(fcntl(pipe_read, F_GETFD), -1);
    CHECK_EQ(errno, EBADF);
    CHECK_EQ(fcntl(pipe_write, F_GETFD), -1);
    CHECK_EQ(errno, EBADF);
    CHECK_EQ(loop.relay_cancel_retry_count, 0u);
    close(upstream[1]);
    close(downstream[1]);
}

TEST(iouring_splice, large_owner_set_shares_budget_before_batch_flush) {
    ScopedIoUringLoop guard;
    if (!guard.init()) SKIP("io_uring unavailable");
    auto& loop = *guard.loop;
    constexpr u32 kOwnerCount = 5;
    constexpr u32 kFirstTurn = 64 * 1024;
    constexpr u32 kBody = 128 * 1024;
    static u8 expected[kOwnerCount][kBody];
    static u8 received[kBody];
    i32 upstream[kOwnerCount][2];
    i32 downstream[kOwnerCount][2];
    Connection* conns[kOwnerCount]{};
    int sndbuf = 1024 * 1024;
    for (u32 i = 0; i < kOwnerCount; ++i) {
        fill_pattern(expected[i], kBody);
        upstream[i][0] = upstream[i][1] = -1;
        downstream[i][0] = downstream[i][1] = -1;
        REQUIRE_EQ(test::stream_socketpair(upstream[i]), 0);
        REQUIRE_EQ(test::stream_socketpair(downstream[i]), 0);
        REQUIRE_EQ(setsockopt(upstream[i][1], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)), 0);
        REQUIRE_EQ(setsockopt(downstream[i][0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)), 0);
        REQUIRE(send_all(upstream[i][1], expected[i], kFirstTurn));
        conns[i] = make_eligible(loop, upstream[i][0], downstream[i][0], kBody);
        REQUIRE(conns[i] != nullptr);
        upstream[i][0] = downstream[i][0] = -1;
    }

    for (Connection* c : conns) REQUIRE(loop.test_start_response_splice(*c));

    CHECK_EQ(loop.relay_pulled_bytes, 4u * kFirstTurn);
    CHECK_EQ(loop.relay_written_bytes, 4u * kFirstTurn);
    CHECK_EQ(loop.relay_budget_calls, 0u);
    CHECK_EQ(loop.relay_budget_bytes, 0u);
    CHECK_EQ(loop.deferred_relay_read_count, 4u);
    for (u32 i = 0; i < kOwnerCount - 1; ++i) {
        CHECK(conns[i]->relay_owner.active());
        CHECK_FALSE(conns[i]->relay_owner.read_armed);
        CHECK_FALSE(conns[i]->relay_owner.write_armed);
        CHECK_EQ(conns[i]->relay_owner.body_bytes, kFirstTurn);
        CHECK_EQ(conns[i]->pending_ops, 0u);
    }
    CHECK(conns[kOwnerCount - 1]->relay_owner.read_armed);
    CHECK_EQ(conns[kOwnerCount - 1]->pending_ops, 1u);

    // The first four owners were parked until the batch boundary.  Flushing
    // admits their real read polls; all later progress comes from kernel CQEs.
    loop.flush_deferred_relay_reads();
    CHECK_EQ(loop.deferred_relay_read_count, 0u);
    for (Connection* c : conns) {
        CHECK(c->relay_owner.read_armed);
        CHECK_EQ(c->pending_ops, 1u);
    }
    for (u32 i = 0; i < kOwnerCount; ++i)
        REQUIRE(send_all(upstream[i][1], expected[i] + kFirstTurn, kBody - kFirstTurn));

    constexpr u64 kTotalBody = static_cast<u64>(kOwnerCount) * kBody;
    REQUIRE(pump_until(
        loop,
        [&] {
            for (Connection* c : conns) {
                if (c->relay_owner.active()) return false;
            }
            return loop.relay_written_bytes == kTotalBody;
        },
        64));
    for (u32 i = 0; i < kOwnerCount; ++i) {
        REQUIRE(read_exact(downstream[i][1], received, kBody));
        CHECK_EQ(memcmp(received, expected[i], kBody), 0);
        close(upstream[i][1]);
        close(downstream[i][1]);
        if (conns[i]->fd >= 0 || conns[i]->upstream_fd >= 0) loop.close_conn(*conns[i]);
    }
    CHECK_EQ(loop.relay_pulled_bytes, kTotalBody);
    CHECK_EQ(loop.relay_written_bytes, kTotalBody);
}

TEST(iouring_splice, deferred_read_does_not_target_reused_slot) {
    ScopedIoUringLoop guard;
    if (!guard.init()) SKIP("io_uring unavailable");
    auto& loop = *guard.loop;
    constexpr u32 kBody = 64 * 1024;
    static u8 old_body[kBody];
    static u8 expected[kBody];
    static u8 received[kBody];
    fill_pattern(old_body, kBody);
    fill_pattern(expected, kBody);
    i32 old_upstream[2] = {-1, -1};
    i32 old_downstream[2] = {-1, -1};
    i32 peer_upstream[2] = {-1, -1};
    i32 peer_downstream[2] = {-1, -1};
    i32 new_upstream[2] = {-1, -1};
    i32 new_downstream[2] = {-1, -1};
    REQUIRE_EQ(test::stream_socketpair(old_upstream), 0);
    REQUIRE_EQ(test::stream_socketpair(old_downstream), 0);
    REQUIRE_EQ(test::stream_socketpair(peer_upstream), 0);
    REQUIRE_EQ(test::stream_socketpair(peer_downstream), 0);
    REQUIRE(send_all(old_upstream[1], old_body, kBody));

    Connection* old = make_eligible(loop, old_upstream[0], old_downstream[0], 2 * kBody);
    REQUIRE(old != nullptr);
    Connection* other = make_eligible(loop, peer_upstream[0], peer_downstream[0], kBody);
    REQUIRE(other != nullptr);
    old_upstream[0] = old_downstream[0] = -1;
    peer_upstream[0] = peer_downstream[0] = -1;
    const u32 reused_id = old->id;
    const u32 old_episode = old->upstream_episode;
    REQUIRE(loop.test_start_response_splice(*old));
    CHECK_EQ(loop.deferred_relay_read_count, 1u);
    CHECK_FALSE(old->relay_owner.read_armed);
    CHECK_EQ(old->pending_ops, 0u);
    CHECK_EQ(loop.relay_written_bytes, kBody);

    loop.close_conn(*old);
    CHECK_EQ(loop.deferred_relay_read_count, 0u);
    close(old_upstream[1]);
    close(old_downstream[1]);

    REQUIRE_EQ(test::stream_socketpair(new_upstream), 0);
    REQUIRE_EQ(test::stream_socketpair(new_downstream), 0);
    Connection* reused = make_eligible(loop, new_upstream[0], new_downstream[0], kBody);
    REQUIRE(reused != nullptr);
    new_upstream[0] = new_downstream[0] = -1;
    CHECK_EQ(reused->id, reused_id);
    CHECK_EQ(reused->upstream_episode, old_episode);
    REQUIRE(loop.test_start_response_splice(*reused));
    CHECK(reused->relay_owner.read_armed);
    CHECK_EQ(reused->pending_ops, 1u);
    const u32 new_episode = reused->upstream_episode;

    // Slot reuse preserves the episode, so close must remove the old entry.
    // Flushing after reuse must leave the new poll owner untouched.
    loop.flush_deferred_relay_reads();
    CHECK_EQ(loop.deferred_relay_read_count, 0u);
    CHECK_EQ(reused->upstream_episode, new_episode);
    CHECK(reused->relay_owner.read_armed);
    CHECK_EQ(reused->pending_ops, 1u);
    REQUIRE(send_all(new_upstream[1], expected, kBody));
    REQUIRE(pump_until(
        loop,
        [&] { return loop.relay_written_bytes == 2u * kBody && !reused->relay_owner.active(); },
        32));
    REQUIRE(read_exact(new_downstream[1], received, kBody));
    CHECK_EQ(memcmp(received, expected, kBody), 0);
    close(new_upstream[1]);
    close(new_downstream[1]);
    close(peer_upstream[1]);
    close(peer_downstream[1]);
    if (other->fd >= 0 || other->upstream_fd >= 0) loop.close_conn(*other);
}

TEST(iouring_splice, slow_downstream_arms_real_pollout_and_completes) {
    ScopedIoUringLoop guard;
    if (!guard.init()) SKIP("io_uring unavailable");
    auto& loop = *guard.loop;
    constexpr u32 kBody = 128 * 1024;
    static u8 expected[kBody];
    static u8 received[kBody];
    u8 filler[4096]{};
    fill_pattern(expected, kBody);
    i32 upstream[2] = {-1, -1};
    i32 downstream[2] = {-1, -1};
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    REQUIRE(set_fd_nonblocking(downstream[0]));
    u32 filler_len = 0;
    for (;;) {
        const ssize_t n = ::send(downstream[0], filler, sizeof(filler), MSG_NOSIGNAL);
        if (n > 0) {
            filler_len += static_cast<u32>(n);
            continue;
        }
        REQUIRE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        break;
    }
    REQUIRE(send_all(upstream[1], expected, kBody));
    Connection* c = make_eligible(loop, upstream[0], downstream[0], kBody);
    REQUIRE(c != nullptr);
    upstream[0] = downstream[0] = -1;
    REQUIRE(loop.test_start_response_splice(*c));
    REQUIRE(c->relay_owner.write_armed);
    REQUIRE_GT(c->relay_owner.segment_len, c->relay_owner.segment_sent);
    REQUIRE_GT(c->pending_ops, 0u);

    REQUIRE(set_fd_nonblocking(downstream[1]));
    u32 discarded = 0;
    for (;;) {
        const ssize_t n = ::recv(downstream[1], filler, sizeof(filler), 0);
        if (n > 0) {
            discarded += static_cast<u32>(n);
            continue;
        }
        REQUIRE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        break;
    }
    REQUIRE_EQ(discarded, filler_len);
    u32 body_read = 0;
    for (u32 i = 0; i < 16 && loop.relay_written_bytes < kBody; ++i) {
        REQUIRE(pump_once(loop));
        if (body_read < kBody) {
            const ssize_t n = ::recv(downstream[1], received + body_read, kBody - body_read, 0);
            if (n > 0)
                body_read += static_cast<u32>(n);
            else
                REQUIRE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        }
    }
    if (body_read < kBody)
        REQUIRE(read_exact(downstream[1], received + body_read, kBody - body_read));
    body_read = kBody;
    REQUIRE_EQ(body_read, kBody);
    CHECK_EQ(loop.relay_written_bytes, kBody);
    CHECK_FALSE(c->relay_owner.active());
    CHECK_EQ(c->pending_ops, 0u);
    CHECK(exact_pattern(received, kBody));
    close(upstream[1]);
    close(downstream[1]);
    if (c->fd >= 0 || c->upstream_fd >= 0) loop.close_conn(*c);
}

TEST(iouring_splice, exact_cl_overrun_is_rejected_by_idle_pool_probe) {
    ScopedIoUringLoop guard;
    if (!guard.init()) SKIP("io_uring unavailable");
    auto& loop = *guard.loop;
    UpstreamPool pool;
    pool.init();
    loop.upstream = &pool;
    constexpr u32 kBody = 64 * 1024;
    static u8 expected[kBody];
    static u8 received[kBody + 1];
    fill_pattern(expected, kBody);
    i32 upstream[2] = {-1, -1};
    i32 downstream[2] = {-1, -1};
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    u8 surplus = 0xE7;
    REQUIRE(send_all(upstream[1], expected, kBody));
    REQUIRE(send_all(upstream[1], &surplus, 1));
    Connection* c = make_eligible(loop, upstream[0], downstream[0], kBody, true);
    REQUIRE(c != nullptr);
    upstream[0] = downstream[0] = -1;
    c->upstream_keep_alive = true;
    c->upstream_idx = 17;
    c->upstream_backend_idx = 2;
    REQUIRE(loop.test_start_response_splice(*c));
    REQUIRE(pump_until(
        loop, [&] { return loop.relay_written_bytes == kBody && pool.idle_count.load() == 1; }));
    REQUIRE(read_exact(downstream[1], received, kBody));
    CHECK(exact_pattern(received, kBody));
    char byte = 0;
    const ssize_t extra = ::recv(downstream[1], &byte, 1, MSG_DONTWAIT);
    CHECK_EQ(extra, -1);
    CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
    CHECK_EQ(pool.idle_count.load(), 1u);
    CHECK_EQ(pool.take_idle(17, 2), -1);
    CHECK_EQ(pool.idle_count.load(), 0u);
    close(upstream[1]);
    close(downstream[1]);
    if (c->fd >= 0 || c->upstream_fd >= 0) loop.close_conn(*c);
    loop.upstream = nullptr;
    pool.shutdown();
}

TEST(iouring_splice, eof_and_post_pull_poll_failure_fail_closed) {
    {
        ScopedIoUringLoop guard;
        if (!guard.init()) SKIP("io_uring unavailable");
        auto& loop = *guard.loop;
        i32 upstream[2] = {-1, -1};
        i32 downstream[2] = {-1, -1};
        REQUIRE_EQ(test::stream_socketpair(upstream), 0);
        REQUIRE_EQ(test::stream_socketpair(downstream), 0);
        Connection* c = make_eligible(loop, upstream[0], downstream[0], 64 * 1024);
        REQUIRE(c != nullptr);
        upstream[0] = downstream[0] = -1;
        close(upstream[1]);
        upstream[1] = -1;
        CHECK(loop.test_start_response_splice(*c));
        CHECK_EQ(loop.relay_admissions, 1u);
        CHECK_EQ(c->fd, -1);
        CHECK_EQ(c->upstream_fd, -1);
        CHECK_EQ(c->relay_owner.pipe_read, -1);
        close(downstream[1]);
    }
    {
        ScopedIoUringLoop guard;
        if (!guard.init()) SKIP("io_uring unavailable");
        auto& loop = *guard.loop;
        i32 upstream[2] = {-1, -1};
        i32 downstream[2] = {-1, -1};
        REQUIRE_EQ(test::stream_socketpair(upstream), 0);
        REQUIRE_EQ(test::stream_socketpair(downstream), 0);
        REQUIRE(set_fd_nonblocking(downstream[0]));
        u8 filler[4096]{};
        for (;;) {
            const ssize_t n = ::send(downstream[0], filler, sizeof(filler), MSG_NOSIGNAL);
            if (n > 0) continue;
            REQUIRE(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
            break;
        }
        u8 body[64 * 1024];
        fill_pattern(body, sizeof(body));
        REQUIRE(send_all(upstream[1], body, sizeof(body)));
        Connection* c = make_eligible(loop, upstream[0], downstream[0], sizeof(body));
        REQUIRE(c != nullptr);
        upstream[0] = downstream[0] = -1;
        loop.test_fail_next_relay_poll = true;
        CHECK(loop.test_start_response_splice(*c));
        CHECK_GT(loop.relay_pulled_bytes, 0u);
        CHECK_EQ(loop.relay_written_bytes, 0u);
        CHECK_EQ(c->fd, -1);
        CHECK_EQ(c->relay_owner.pipe_read, -1);
        close(upstream[1]);
        close(downstream[1]);
    }
}

TEST(iouring_splice, close_drains_real_read_poll_before_reclaim) {
    ScopedIoUringLoop guard;
    if (!guard.init()) SKIP("io_uring unavailable");
    auto& loop = *guard.loop;
    const u32 free_before = loop.free_top;
    i32 upstream[2] = {-1, -1};
    i32 downstream[2] = {-1, -1};
    REQUIRE_EQ(test::stream_socketpair(upstream), 0);
    REQUIRE_EQ(test::stream_socketpair(downstream), 0);
    Connection* c = make_eligible(loop, upstream[0], downstream[0], 64 * 1024);
    REQUIRE(c != nullptr);
    upstream[0] = downstream[0] = -1;
    REQUIRE(loop.test_start_response_splice(*c));
    REQUIRE(c->relay_owner.read_armed);
    REQUIRE_EQ(c->pending_ops, 1u);
    loop.close_conn(*c);
    for (u32 i = 0; i < 8 && loop.pending_free_count != 0; ++i) REQUIRE(pump_once(loop));
    CHECK_EQ(loop.pending_free_count, 0u);
    CHECK_EQ(loop.free_top, free_before);
    CHECK_EQ(c->relay_owner.pipe_read, -1);
    CHECK_EQ(c->relay_owner.pipe_write, -1);
    close(upstream[1]);
    close(downstream[1]);
}

TEST(iouring_splice, stale_episode_and_cancel_target_orders_preserve_owner) {
    for (u32 order = 0; order < 2; ++order) {
        ScopedIoUringLoop guard;
        if (!guard.init()) SKIP("io_uring unavailable");
        auto& loop = *guard.loop;
        const u32 free_before = loop.free_top;
        Connection* c = loop.alloc_conn();
        REQUIRE(c != nullptr);
        int pipe_fds[2] = {-1, -1};
        REQUIRE_EQ(::pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC), 0);
        RelayOwner& owner = c->relay_owner;
        owner.pipe_read = pipe_fds[0];
        owner.pipe_write = pipe_fds[1];
        owner.phase = RelayPhase::Reading;
        owner.upstream_episode = 41;
        owner.close_pending = true;
        owner.read_armed = true;
        owner.read_cancel_owned = true;
        c->upstream_episode = owner.upstream_episode;
        c->pending_ops = 2;
        loop.pending_free[loop.pending_free_count++] = c->id;

        const IoEvent foreign{c->id, POLLIN, 0, 0, IoEventType::RelayRead, 0, 0, 42};
        loop.dispatch_batch(&foreign, 1);
        CHECK_EQ(c->pending_ops, 2u);
        CHECK(owner.read_armed);
        CHECK(owner.read_cancel_owned);
        CHECK_EQ(owner.upstream_episode, 41u);
        CHECK_EQ(loop.pending_free_count, 1u);
        CHECK_EQ(loop.free_top, free_before - 1);

        const IoEvent target{c->id, POLLIN, 0, 0, IoEventType::RelayRead, 0, 0, 41};
        const IoEvent cancel{
            c->id, 0, 0, 0, IoEventType::RelayRead, 0, kUpstreamRetirementCancelAux, 41};
        const IoEvent in_order[2] = {order == 0 ? target : cancel, order == 0 ? cancel : target};
        loop.dispatch_batch(in_order, 2);
        CHECK_EQ(loop.pending_free_count, 0u);
        CHECK_EQ(loop.free_top, free_before);
        CHECK_EQ(owner.pipe_read, -1);
        CHECK_EQ(owner.pipe_write, -1);
        CHECK_FALSE(owner.active());
    }
}

template <typename T>
concept HasResponseSpliceSeam =
    requires(T& loop, Connection& c) { loop.test_start_response_splice(c); };

static_assert(HasResponseSpliceSeam<IoUringEventLoop>);
static_assert(!HasResponseSpliceSeam<EpollEventLoop>);

#endif  // __linux__

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
