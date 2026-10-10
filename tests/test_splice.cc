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
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
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
    const bool runnable = loop.deferred_relay_read_count != 0;
    const u32 count = loop.backend.wait(
        events, kMaxEventsPerWait, loop.conns, IoUringEventLoop::kMaxConns, !runnable);
    if (loop.backend.failure_code() != 0 || (count == 0 && !runnable)) return false;
    // Match the production run loop's fresh per-wait shared splice budget.
    loop.relay_budget_calls = IoUringEventLoop::kRelayTurnMaxCalls;
    loop.relay_budget_bytes = IoUringEventLoop::kRelayTurnMaxBytes;
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
namespace {
struct StableEpollFixture {
    EpollBackend backend{};
    UpstreamPool pool{};
    Connection conns[2]{};
    u8 buffers[2][64]{};
    i32 peer = -1;

    bool init(bool edge = false) {
        if (!backend.init(0, -1, 4).has_value()) return false;
        const char* configured = getenv("RUT_TEST_EPOLL_ET");
        edge |= configured != nullptr && strcmp(configured, "on") == 0;
        if (edge && !backend.enable_edge_trigger()) return false;
        if (!backend.enable_stable_upstream_events()) return false;
        pool.init();
        backend.bind_stable_pool(&pool);
        for (u32 i = 0; i < 2; ++i) {
            conns[i].reset();
            conns[i].id = i;
            conns[i].upstream_recv_buf.bind(buffers[i], sizeof(buffers[i]));
        }
        i32 fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds) < 0) return false;
        peer = fds[1];
        conns[0].upstream_fd = fds[0];
        return backend.begin_upstream_episode(0, conns[0].upstream_episode) &&
               backend.add_recv_upstream(fds[0], 0, conns[0].upstream_episode);
    }

    bool park(u32 owner) {
        i32 fd = -1;
        if (!backend.detach_upstream(conns[owner], &fd)) return false;
        u32 slot = UpstreamPool::kNoSlot;
        if (!pool.put_idle(fd, 0, 0, 1, &slot)) {
            pool.close_idle_fd(fd);
            return false;
        }
        backend.park_stable_upstream(fd, slot);
        return true;
    }

    i32 borrow(u32 owner) {
        const i32 fd = pool.take_idle(0, 0);
        if (fd < 0) return fd;
        if (!backend.begin_upstream_episode(owner, conns[owner].upstream_episode)) {
            pool.close_idle_fd(fd);
            return -1;
        }
        conns[owner].upstream_fd = fd;
        backend.upstream_fd_map[owner] = fd;
        backend.claim_stable_upstream(fd, owner, conns[owner].upstream_episode);
        return fd;
    }

    ~StableEpollFixture() {
        for (auto& conn : conns)
            if (conn.upstream_fd >= 0) backend.detach_upstream(conn);
        pool.shutdown();
        backend.shutdown();
        if (peer >= 0) close(peer);
    }
};
}  // namespace

namespace {
struct EdgeEpollFixture {
    EpollBackend backend{};
    Connection conn{};
    u8 buffer[64]{};
    i32 peer = -1;
    bool init() {
        if (!backend.init(0, -1, 4) || !backend.enable_edge_trigger()) return false;
        i32 fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds) < 0) return false;
        conn.reset();
        conn.id = 0;
        conn.fd = fds[0];
        peer = fds[1];
        conn.recv_buf.bind(buffer, sizeof(buffer));
        return backend.add_recv(conn.fd, conn.id);
    }
    ~EdgeEpollFixture() {
        if (conn.fd >= 0) close(conn.fd);
        if (peer >= 0) close(peer);
        backend.shutdown();
    }
};
}  // namespace

TEST(epoll_full_edge, one_peer_write_drains_across_multiple_buffer_turns) {
    EdgeEpollFixture f;
    ASSERT_TRUE(f.init());
    u8 payload[256];
    fill_pattern(payload, sizeof(payload));
    ASSERT_TRUE(send_all(f.peer, payload, sizeof(payload)));
    IoEvent event{};
    u32 received = 0;
    for (u32 turn = 0; turn < 8 && received < sizeof(payload); ++turn) {
        const u32 count = f.backend.wait(&event, 1, &f.conn, 1);
        if (count == 0) continue;
        ASSERT_TRUE(event.type == IoEventType::Recv);
        ASSERT_TRUE(event.result > 0);
        for (u32 i = 0; i < static_cast<u32>(event.result); ++i)
            ASSERT_EQ(f.buffer[i], pattern(received + i));
        received += static_cast<u32>(event.result);
        f.conn.recv_buf.reset();
        if (received < sizeof(payload)) ASSERT_TRUE(f.backend.add_recv(f.conn.fd, f.conn.id));
    }
    ASSERT_EQ(received, sizeof(payload));
}

TEST(epoll_full_edge, pause_and_resume_unread_bytes_without_a_new_peer_write) {
    EdgeEpollFixture f;
    ASSERT_TRUE(f.init());
    u8 payload[128]{};
    ASSERT_TRUE(send_all(f.peer, payload, sizeof(payload)));
    IoEvent event{};
    ASSERT_EQ(f.backend.wait(&event, 1, &f.conn, 1), 1u);
    ASSERT_EQ(event.result, 64);
    f.backend.pause_recv(f.conn.id);
    ASSERT_EQ(f.backend.edge_runnable[0].events, 0u);
    f.conn.recv_buf.reset();
    ASSERT_TRUE(f.backend.add_recv(f.conn.fd, f.conn.id));
    ASSERT_EQ(f.backend.wait(&event, 1, &f.conn, 1), 1u);
    ASSERT_EQ(event.result, 64);
    ASSERT_EQ(f.backend.edge_count, 0u);
    f.backend.forget_fd_interest(0);
    epoll_event raw{};
    ASSERT_TRUE(!f.backend.pop_edge(raw));
    ASSERT_EQ(f.backend.edge_count, 0u);
}

TEST(epoll_full_edge, runnable_queue_deduplicates_and_survives_slot_reuse) {
    EdgeEpollFixture f;
    ASSERT_TRUE(f.init());
    epoll_event raw{};
    ASSERT_TRUE(!f.backend.pop_edge(raw));
    for (u32 slot = 0; slot < 8; ++slot) {
        f.backend.fd_interest[slot] = {f.conn.fd, EPOLLIN, slot + 1, 1};
        for (u32 n = 0; n < 16; ++n) f.backend.queue_edge(slot, EPOLLIN);
    }
    ASSERT_EQ(f.backend.edge_count, 8u);
    f.backend.forget_fd_interest(0);
    // Reuse while the old queue entries still exist; no extra entry is added.
    ASSERT_TRUE(f.backend.add_recv(f.conn.fd, 0));
    f.backend.queue_edge(0, EPOLLIN);
    ASSERT_EQ(f.backend.edge_count, 8u);
    u32 popped = 0;
    while (f.backend.pop_edge(raw)) ++popped;
    ASSERT_EQ(popped, 7u);
    ASSERT_EQ(f.backend.edge_count, 0u);
}

TEST(epoll_full_edge, partial_send_and_half_close_preserve_reverse_data) {
    EdgeEpollFixture f;
    ASSERT_TRUE(f.init());
    const i32 send_buffer = 4096;
    ASSERT_EQ(setsockopt(f.conn.fd, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)), 0);
    u8 payload[32768];
    fill_pattern(payload, sizeof(payload));
    ASSERT_TRUE(f.backend.add_send(f.conn.fd, 0, payload, sizeof(payload)));
    ASSERT_TRUE(f.backend.send_state[0].remaining > 0);
    ASSERT_TRUE(send_all(f.peer, reinterpret_cast<const u8*>("reply"), 5));
    ASSERT_EQ(shutdown(f.peer, SHUT_WR), 0);
    u32 received = 0;
    bool send_completed = false, read_completed = false;
    for (u32 turn = 0; turn < 64 && (!send_completed || !read_completed); ++turn) {
        u8 buffer[4096];
        for (;;) {
            const ssize_t n = recv(f.peer, buffer, sizeof(buffer), 0);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            ASSERT_TRUE(n > 0);
            for (u32 i = 0; i < static_cast<u32>(n); ++i)
                ASSERT_EQ(buffer[i], pattern(received + i));
            received += static_cast<u32>(n);
        }
        IoEvent event{};
        if (f.backend.wait(&event, 1, &f.conn, 1) == 0) continue;
        if (event.type == IoEventType::Send) {
            ASSERT_EQ(event.result, static_cast<i32>(sizeof(payload)));
            send_completed = true;
        } else if (event.type == IoEventType::Recv && event.result > 0) {
            ASSERT_EQ(event.result, 5);
            ASSERT_EQ(memcmp(f.buffer, "reply", 5), 0);
            f.conn.recv_buf.reset();
            read_completed = true;
        }
    }
    ASSERT_TRUE(send_completed);
    ASSERT_TRUE(read_completed);
    u8 tail[32768];
    for (;;) {
        const ssize_t n = recv(f.peer, tail, sizeof(tail), 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        ASSERT_TRUE(n > 0);
        for (u32 i = 0; i < static_cast<u32>(n); ++i) ASSERT_EQ(tail[i], pattern(received + i));
        received += static_cast<u32>(n);
    }
    ASSERT_EQ(received, sizeof(payload));
}

TEST(epoll_full_edge, other_side_invalidation_preserves_a_harvested_edge) {
    EdgeEpollFixture f;
    ASSERT_TRUE(f.init());
    ASSERT_TRUE(send_all(f.peer, reinterpret_cast<const u8*>("x"), 1));
    auto& interest = f.backend.fd_interest[0];
    f.backend.ready_head = 0;
    f.backend.ready_count = 1;
    f.backend.ready[0] = {EPOLLIN, {}};
    f.backend.ready[0].data.u64 = interest.data;
    f.backend.ready_slot[0] = 0;
    f.backend.ready_gen[0] = interest.gen;
    f.backend.invalidate_fd_interest(0, 123456);
    ASSERT_EQ(f.backend.edge_count, 1u);
    IoEvent event{};
    ASSERT_EQ(f.backend.wait(&event, 1, &f.conn, 1), 1u);
    ASSERT_EQ(event.type, IoEventType::Recv);
    ASSERT_EQ(event.result, 1);
    ASSERT_EQ(f.buffer[0], static_cast<u8>('x'));
}

TEST(epoll_full_edge, enabling_after_socket_registration_is_rejected) {
    EpollBackend backend{};
    ASSERT_TRUE(backend.init(0, -1, 4).has_value());
    i32 sockets[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);
    ASSERT_TRUE(backend.add_recv(sockets[0], 0));
    const bool enabled = backend.enable_edge_trigger();
    close(sockets[0]);
    close(sockets[1]);
    backend.shutdown();
    ASSERT_TRUE(!enabled);
}

TEST(epoll_full_edge, stale_readiness_cannot_complete_an_unsubmitted_read) {
    EdgeEpollFixture f;
    ASSERT_TRUE(f.init());
    u8 payload[128]{};
    ASSERT_TRUE(send_all(f.peer, payload, sizeof(payload)));
    IoEvent event{};
    ASSERT_EQ(f.backend.wait(&event, 1, &f.conn, 1), 1u);
    ASSERT_EQ(event.result, 64);
    f.conn.recv_buf.reset();
    const auto& interest = f.backend.fd_interest[0];
    f.backend.ready_head = 0;
    f.backend.ready_count = 1;
    f.backend.ready[0] = {EPOLLIN, {}};
    f.backend.ready[0].data.u64 = interest.data;
    f.backend.ready_slot[0] = 0;
    f.backend.ready_gen[0] = interest.gen;
    // An already expired absolute timer makes the no-read assertion bounded.
    f.backend.arm_yield_timerfd(1);
    bool timer_seen = false;
    for (u32 turn = 0; turn < 4 && !timer_seen; ++turn) {
        if (f.backend.wait(&event, 1, &f.conn, 1) == 0) continue;
        ASSERT_EQ(event.type, IoEventType::HandlerTimer);
        timer_seen = true;
    }
    ASSERT_TRUE(timer_seen);
    ASSERT_EQ(f.conn.recv_buf.len(), 0u);
    ASSERT_TRUE(f.backend.add_recv(f.conn.fd, 0));
    ASSERT_EQ(f.backend.wait(&event, 1, &f.conn, 1), 1u);
    ASSERT_EQ(event.result, 64);
}

TEST(epoll_full_edge, short_read_retries_and_half_close_still_completes) {
    for (bool half_close : {false, true}) {
        EdgeEpollFixture f;
        ASSERT_TRUE(f.init());
        ASSERT_TRUE(send_all(f.peer, reinterpret_cast<const u8*>("short"), 5));
        if (half_close) ASSERT_EQ(shutdown(f.peer, SHUT_WR), 0);
        IoEvent event{};
        ASSERT_EQ(f.backend.wait(&event, 1, &f.conn, 1), 1u);
        ASSERT_EQ(event.result, 5);
        f.conn.recv_buf.reset();
        ASSERT_TRUE(f.backend.add_recv(f.conn.fd, 0));
        if (!half_close) {
            ASSERT_TRUE(send_all(f.peer, reinterpret_cast<const u8*>("next"), 4));
        }
        ASSERT_EQ(f.backend.wait(&event, 1, &f.conn, 1), 1u);
        ASSERT_EQ(event.result, half_close ? 0 : 4);
    }
}

TEST(epoll_full_edge, short_positive_read_requeues_until_eagain_without_a_new_write) {
    EdgeEpollFixture f;
    ASSERT_TRUE(f.init());
    f.conn.recv_buf.bind(f.buffer, 5);
    ASSERT_TRUE(send_all(f.peer, reinterpret_cast<const u8*>("123456789"), 9));
    IoEvent event{};
    ASSERT_EQ(f.backend.wait(&event, 1, &f.conn, 1), 1u);
    ASSERT_EQ(event.result, 5);
    ASSERT_EQ(memcmp(f.buffer, "12345", 5), 0);
    f.conn.recv_buf.reset();
    ASSERT_TRUE(f.backend.add_recv(f.conn.fd, 0));
    ASSERT_TRUE(f.backend.edge_runnable[0].queued);
    ASSERT_EQ(f.backend.wait(&event, 1, &f.conn, 1), 1u);
    ASSERT_EQ(event.result, 4);
    ASSERT_EQ(memcmp(f.buffer, "6789", 4), 0);
}

TEST(epoll_stable_edge, disabled_owner_retains_data_and_fin_until_receive_submission) {
    StableEpollFixture f;
    REQUIRE(f.init(true));
    const i32 fd = f.conns[0].upstream_fd;
    const u64 token = f.backend.fd_interest[1].data;
    REQUIRE(f.park(0));
    REQUIRE_EQ(f.borrow(1), fd);
    REQUIRE_EQ(::send(f.peer, "body", 4, MSG_NOSIGNAL), 4);
    REQUIRE_EQ(::shutdown(f.peer, SHUT_WR), 0);
    IoEvent event{};
    CHECK_EQ(f.backend.wait(&event, 1, f.conns, 2), 0u);
    CHECK_EQ(f.conns[1].upstream_recv_buf.len(), 0u);
    REQUIRE(f.backend.add_recv_upstream(fd, 1, f.conns[1].upstream_episode));
    CHECK_EQ(f.backend.fd_interest[3].data, token);
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    CHECK_EQ(event.conn_id, 1u);
    CHECK_EQ(event.result, 4);
    CHECK_EQ(memcmp(f.conns[1].upstream_recv_buf.data(), "body", 4), 0);
    f.conns[1].upstream_recv_buf.reset();
    REQUIRE(f.backend.add_recv_upstream(fd, 1, f.conns[1].upstream_episode));
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    CHECK_EQ(event.type, IoEventType::UpstreamRecv);
    CHECK_EQ(event.conn_id, 1u);
    CHECK_EQ(event.result, 0);
    CHECK_EQ(f.conns[0].upstream_recv_buf.len(), 0u);
}

TEST(epoll_stable_edge, consumed_fin_is_not_lost_when_returning_to_idle_pool) {
    StableEpollFixture f;
    REQUIRE(f.init(true));
    const i32 fd = f.conns[0].upstream_fd;
    REQUIRE_EQ(::send(f.peer, "body", 4, MSG_NOSIGNAL), 4);
    REQUIRE_EQ(::shutdown(f.peer, SHUT_WR), 0);
    IoEvent event{};
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    REQUIRE_EQ(event.result, 4);
    REQUIRE(f.park(0));
    CHECK_FALSE(f.backend.stable_upstream[fd].registered);
    CHECK_EQ(f.pool.take_idle(0, 0), -1);
    CHECK_EQ(fcntl(fd, F_GETFD), -1);
    CHECK_EQ(errno, EBADF);
}

TEST(epoll_stable_edge, full_reads_continue_with_an_unchanged_kernel_registration) {
    StableEpollFixture f;
    REQUIRE(f.init(true));
    const i32 fd = f.conns[0].upstream_fd;
    const u64 token = f.backend.fd_interest[1].data;
    const u32 generation = f.backend.fd_interest[1].gen;
    u8 bytes[256];
    fill_pattern(bytes, sizeof(bytes));
    REQUIRE(send_all(f.peer, bytes, sizeof(bytes)));
    u32 received = 0;
    IoEvent event{};
    for (u32 turn = 0; turn < 8 && received < sizeof(bytes); ++turn) {
        REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
        REQUIRE_EQ(event.type, IoEventType::UpstreamRecv);
        REQUIRE(event.result > 0);
        for (u32 i = 0; i < static_cast<u32>(event.result); ++i)
            CHECK_EQ(f.conns[0].upstream_recv_buf.data()[i], pattern(received + i));
        received += static_cast<u32>(event.result);
        f.conns[0].upstream_recv_buf.reset();
        if (received < sizeof(bytes))
            REQUIRE(f.backend.add_recv_upstream(fd, 0, f.conns[0].upstream_episode));
    }
    CHECK_EQ(received, sizeof(bytes));
    CHECK_EQ(f.backend.fd_interest[1].data, token);
    CHECK_EQ(f.backend.fd_interest[1].gen, generation);
}

TEST(epoll_accept_edge, fd_exhaustion_retries_on_timer_without_another_connection) {
    const pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        alarm(5);
        const i32 listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(address);
        if (listener < 0 || bind(listener, reinterpret_cast<sockaddr*>(&address), length) != 0 ||
            listen(listener, 8) != 0 ||
            getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) != 0)
            _exit(1);
        EpollBackend backend{};
        if (!backend.init(0, listener, 4).has_value()) _exit(2);
        backend.study_accept_edge_trigger = true;
        backend.add_accept();
        const i32 peer = socket(AF_INET, SOCK_STREAM, 0);
        if (peer < 0 || connect(peer, reinterpret_cast<sockaddr*>(&address), length) != 0) _exit(3);
        struct rlimit limit{};
        if (getrlimit(RLIMIT_NOFILE, &limit) != 0) _exit(4);
        limit.rlim_cur = 64;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) _exit(5);
        i32 held[64]{};
        u32 count = 0;
        for (; count < 64; ++count) {
            held[count] = dup(peer);
            if (held[count] < 0) break;
        }
        if (count == 0 || errno != EMFILE) _exit(6);
        IoEvent event{};
        if (backend.wait(&event, 1, nullptr, 0) != 0 || !backend.accept_pending ||
            !backend.accept_retry_on_timer)
            _exit(7);
        close(held[--count]);
        if (backend.wait(&event, 1, nullptr, 0) != 1 || event.type != IoEventType::Timeout ||
            backend.accept_retry_on_timer)
            _exit(8);
        if (backend.wait(&event, 1, nullptr, 0) != 1 || event.type != IoEventType::Accept ||
            event.result < 0)
            _exit(9);
        const i32 accepted = event.result;
        const u8 byte = 'z';
        if (!backend.add_send(accepted, 0, &byte, 1)) _exit(10);
        // A continuation must restore completion service after its burst quota.
        backend.pending_streak = EpollBackend::kPendingBurstQuota;
        backend.accept_io_budget = 0;
        close(held[--count]);
        if (backend.wait(&event, 1, nullptr, 0) != 0 || backend.accept_pending ||
            backend.pending_streak != 0)
            _exit(11);
        if (backend.wait(&event, 1, nullptr, 0) != 1 || event.type != IoEventType::Send ||
            event.result != 1)
            _exit(12);
        close(accepted);
        for (u32 i = 0; i < count; ++i) close(held[i]);
        backend.shutdown();
        close(peer);
        close(listener);
        _exit(0);
    }
    i32 status = 0;
    REQUIRE_EQ(waitpid(child, &status, 0), child);
    REQUIRE(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), 0);
}

TEST(epoll_stable_relay, same_registration_changes_consumer_without_reading_bytes) {
    StableEpollFixture f;
    REQUIRE(f.init());
    f.backend.study_stable_upstream_relay = true;
    auto& c = f.conns[0];
    const u64 kToken = f.backend.fd_interest[1].data;
    const u32 kVersion = f.backend.stable_upstream[c.upstream_fd].version;
    c.fd = f.peer;
    c.relay_owner.phase = RelayPhase::Reading;
    c.relay_owner.source_fd = c.upstream_fd;
    c.relay_owner.destination_fd = c.fd;
    c.relay_owner.upstream_episode = c.upstream_episode;
    c.relay_owner.read_armed = true;
    // Retire a record harvested for the previous recv consumer.
    f.backend.ready[0] = {};
    f.backend.ready[0].events = EPOLLIN;
    f.backend.ready[0].data.u64 = kToken;
    f.backend.ready_slot[0] = EpollBackend::kStableReadySlotBit | static_cast<u32>(c.upstream_fd);
    f.backend.ready_gen[0] = kVersion;
    f.backend.ready_head = 0;
    f.backend.ready_count = 1;
    REQUIRE(
        f.backend.add_relay_poll(c.upstream_fd, c.id, IoEventType::RelayRead, c.upstream_episode));
    CHECK_EQ(f.backend.fd_interest[1].data, kToken);
    CHECK_EQ(f.backend.stable_upstream[c.upstream_fd].version, kVersion + 1);
    REQUIRE_EQ(::send(f.peer, "body", 4, MSG_NOSIGNAL), 4);
    IoEvent events[4]{};
    REQUIRE_EQ(f.backend.wait(events, 4, f.conns, 2), 1u);
    // ET can resume from retained userspace readiness without a new harvest.
    if (!f.backend.study_edge_trigger) CHECK_EQ(f.backend.ready_gen[0], kVersion + 1);
    CHECK_EQ(events[0].conn_id, c.id);
    CHECK_EQ(events[0].type, IoEventType::RelayRead);
    CHECK_EQ(c.upstream_recv_buf.len(), 0u);
    u8 bytes[4]{};
    REQUIRE_EQ(::recv(c.upstream_fd, bytes, sizeof(bytes), MSG_DONTWAIT), 4);
    CHECK_EQ(__builtin_memcmp(bytes, "body", 4), 0);
    c.relay_owner = {};
    REQUIRE(f.backend.add_recv_upstream(c.upstream_fd, c.id, c.upstream_episode));
    CHECK_EQ(f.backend.fd_interest[1].data, kToken);
    CHECK_FALSE(f.backend.stable_upstream[c.upstream_fd].relay_read);
}

TEST(epoll_stable_relay, valid_relay_read_spends_accept_io_budget) {
    StableEpollFixture f;
    REQUIRE(f.init(true));
    f.backend.study_stable_upstream_relay = true;
    auto& c = f.conns[0];
    c.fd = f.peer;
    c.relay_owner.phase = RelayPhase::Reading;
    c.relay_owner.source_fd = c.upstream_fd;
    c.relay_owner.destination_fd = c.fd;
    c.relay_owner.upstream_episode = c.upstream_episode;
    c.relay_owner.read_armed = true;
    REQUIRE(
        f.backend.add_relay_poll(c.upstream_fd, c.id, IoEventType::RelayRead, c.upstream_episode));
    f.backend.accept_io_budget = 2;
    REQUIRE_EQ(::send(f.peer, "x", 1, MSG_NOSIGNAL), 1);
    IoEvent event{};
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    CHECK_EQ(event.type, IoEventType::RelayRead);
    CHECK_EQ(event.conn_id, c.id);
    CHECK_EQ(f.backend.accept_io_budget, 1u);
}

TEST(epoll_stable_relay, valid_relay_write_spends_accept_io_budget) {
    StableEpollFixture f;
    REQUIRE(f.init(true));
    auto& c = f.conns[0];
    c.fd = f.peer;
    f.backend.downstream_fd_map[c.id] = c.fd;
    c.relay_owner.phase = RelayPhase::Writing;
    c.relay_owner.source_fd = c.upstream_fd;
    c.relay_owner.destination_fd = c.fd;
    c.relay_owner.upstream_episode = c.upstream_episode;
    c.relay_owner.write_armed = true;
    REQUIRE(f.backend.add_relay_poll(c.fd, c.id, IoEventType::RelayWrite, c.upstream_episode));
    f.backend.accept_io_budget = 2;
    IoEvent event{};
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    CHECK_EQ(event.type, IoEventType::RelayWrite);
    CHECK_EQ(event.conn_id, c.id);
    CHECK_EQ(f.backend.accept_io_budget, 1u);
}

TEST(epoll_stable, transfer_keeps_kernel_token_and_waits_for_receive_submission) {
    StableEpollFixture f;
    REQUIRE(f.init());
    const i32 fd = f.conns[0].upstream_fd;
    const u64 token =
        f.backend.fd_interest[EpollBackend::fd_interest_slot(0, IoEventType::UpstreamRecv)].data;
    const u32 downstream_generation = f.backend.fd_interest[0].gen;
    REQUIRE(f.park(0));
    CHECK_EQ(f.backend.fd_interest[0].gen, downstream_generation + 1);
    REQUIRE_EQ(f.borrow(1), fd);
    const u8 byte = 'x';
    REQUIRE_EQ(send(f.peer, &byte, 1, 0), 1);
    IoEvent event{};
    CHECK_EQ(f.backend.wait(&event, 1, f.conns, 2), 0u);
    CHECK_EQ(f.conns[1].upstream_recv_buf.len(), 0u);
    REQUIRE(f.backend.add_recv_upstream(fd, 1, f.conns[1].upstream_episode));
    CHECK_EQ(
        f.backend.fd_interest[EpollBackend::fd_interest_slot(1, IoEventType::UpstreamRecv)].data,
        token);
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    CHECK_EQ(event.conn_id, 1u);
    CHECK_EQ(event.upstream_episode, f.conns[1].upstream_episode);
    CHECK_EQ(event.result, 1);
    CHECK_EQ(f.conns[1].upstream_recv_buf.data()[0], byte);
    CHECK_EQ(f.conns[0].upstream_recv_buf.len(), 0u);
}

TEST(epoll_stable, old_harvested_owner_is_dropped_before_socket_read) {
    StableEpollFixture f;
    REQUIRE(f.init());
    const i32 fd = f.conns[0].upstream_fd;
    const u64 token =
        f.backend.fd_interest[EpollBackend::fd_interest_slot(0, IoEventType::UpstreamRecv)].data;
    const u32 version = f.backend.stable_upstream[fd].version;
    REQUIRE(f.park(0));
    REQUIRE_EQ(f.borrow(1), fd);
    REQUIRE(f.backend.add_recv_upstream(fd, 1, f.conns[1].upstream_episode));
    f.backend.ready[0] = {EPOLLIN, {.u64 = token}};
    f.backend.ready_slot[0] = EpollBackend::kStableReadySlotBit | static_cast<u32>(fd);
    f.backend.ready_gen[0] = version;
    f.backend.ready_head = 0;
    f.backend.ready_count = 1;
    const u8 byte = 'n';
    REQUIRE_EQ(send(f.peer, &byte, 1, 0), 1);
    IoEvent event{};
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    CHECK_EQ(event.conn_id, 1u);
    CHECK_EQ(f.conns[1].upstream_recv_buf.len(), 1u);
    CHECK_EQ(f.conns[1].upstream_recv_buf.data()[0], byte);
}

TEST(epoll_stable, idle_fin_and_unsolicited_bytes_discard_only_the_idle_socket) {
    for (u32 data = 0; data < 2; ++data) {
        StableEpollFixture f;
        REQUIRE(f.init());
        const i32 fd = f.conns[0].upstream_fd;
        REQUIRE(f.park(0));
        if (data) {
            const u8 byte = 'z';
            REQUIRE_EQ(send(f.peer, &byte, 1, 0), 1);
        } else {
            REQUIRE_EQ(shutdown(f.peer, SHUT_WR), 0);
        }
        IoEvent event{};
        CHECK_EQ(f.backend.wait(&event, 1, f.conns, 2), 0u);
        CHECK_EQ(f.pool.idle_count.load(), 0u);
        CHECK_FALSE(f.backend.stable_upstream[fd].registered);
        CHECK_EQ(f.conns[0].upstream_recv_buf.len(), 0u);
        CHECK_EQ(f.conns[1].upstream_recv_buf.len(), 0u);
        CHECK_EQ(fcntl(fd, F_GETFD), -1);
        CHECK_EQ(errno, EBADF);
    }
}

TEST(epoll_stable, borrow_probe_and_reload_still_reject_idle_transport) {
    StableEpollFixture f;
    REQUIRE(f.init());
    const i32 fd = f.conns[0].upstream_fd;
    REQUIRE(f.park(0));
    const u8 byte = 's';
    REQUIRE_EQ(send(f.peer, &byte, 1, 0), 1);
    CHECK_EQ(f.pool.take_idle(0, 0), -1);
    CHECK_FALSE(f.backend.stable_upstream[fd].registered);
    CHECK_EQ(f.pool.idle_count.load(), 0u);

    StableEpollFixture reload;
    REQUIRE(reload.init());
    const i32 reload_fd = reload.conns[0].upstream_fd;
    REQUIRE(reload.park(0));
    reload.pool.drain();
    CHECK_FALSE(reload.backend.stable_upstream[reload_fd].registered);
    CHECK_EQ(reload.pool.idle_count.load(), 0u);
}

TEST(epoll_stable, generation_rejects_old_token_even_when_owner_version_matches) {
    StableEpollFixture f;
    REQUIRE(f.init());
    const i32 fd = f.conns[0].upstream_fd;
    const u64 old_token =
        f.backend.fd_interest[EpollBackend::fd_interest_slot(0, IoEventType::UpstreamRecv)].data;
    f.backend.pause_upstream_recv(0, f.conns[0].upstream_episode, false);
    CHECK_FALSE(f.backend.stable_upstream[fd].registered);
    REQUIRE(f.backend.add_recv_upstream(fd, 0, f.conns[0].upstream_episode));
    CHECK_NE(f.backend.stable_upstream[fd].generation, static_cast<u32>(old_token >> 32));
    f.backend.ready[0] = {EPOLLIN, {.u64 = old_token}};
    f.backend.ready_slot[0] = EpollBackend::kStableReadySlotBit | static_cast<u32>(fd);
    f.backend.ready_gen[0] = f.backend.stable_upstream[fd].version;
    f.backend.ready_head = 0;
    f.backend.ready_count = 1;
    const u8 byte = 'g';
    REQUIRE_EQ(send(f.peer, &byte, 1, 0), 1);
    IoEvent event{};
    CHECK_EQ(f.backend.wait(&event, 1, f.conns, 2), 0u);
    CHECK_EQ(f.conns[0].upstream_recv_buf.len(), 0u);
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    CHECK_EQ(f.conns[0].upstream_recv_buf.data()[0], byte);
}

TEST(epoll_stable, exhausted_owner_version_uses_full_detach_without_wrapping) {
    StableEpollFixture f;
    REQUIRE(f.init());
    const i32 fd = f.conns[0].upstream_fd;
    f.backend.stable_upstream[fd].version = 0xffffffffu;
    REQUIRE(f.park(0));
    CHECK_FALSE(f.backend.stable_upstream[fd].registered);
    CHECK_EQ(f.pool.idle_count.load(), 1u);
    REQUIRE_EQ(f.borrow(1), fd);
    REQUIRE(f.backend.add_recv_upstream(fd, 1, f.conns[1].upstream_episode));
    CHECK(f.backend.stable_upstream[fd].registered);
    CHECK_NE(f.backend.stable_upstream[fd].generation, 1u);
}

TEST(epoll_stable, failed_registration_reports_local_error_without_consuming_bytes) {
    StableEpollFixture f;
    REQUIRE(f.init());
    const i32 fd = f.conns[0].upstream_fd;
    f.backend.invalidate_stable_upstream(fd);
    const i32 epoll_fd = f.backend.epoll_fd;
    f.backend.epoll_fd = f.peer;  // valid socket, deliberately not an epoll descriptor
    const bool submitted = f.backend.add_recv_upstream(fd, 0, f.conns[0].upstream_episode);
    f.backend.epoll_fd = epoll_fd;
    REQUIRE(submitted);  // a local-submit failure is delivered as a completion
    IoEvent event{};
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    CHECK_EQ(event.type, IoEventType::UpstreamRecv);
    CHECK_EQ(event.aux, kLocalSubmitFailureAux);
    CHECK_EQ(event.result, -EINVAL);
    CHECK_EQ(event.upstream_episode, f.conns[0].upstream_episode);
    CHECK_FALSE(f.backend.stable_upstream[fd].registered);
    CHECK_EQ(f.backend.upstream_fd_map[0], -1);
    CHECK_EQ(f.conns[0].upstream_recv_buf.len(), 0u);
}

TEST(epoll_stable, reused_descriptor_cannot_accept_the_previous_socket_token) {
    StableEpollFixture f;
    REQUIRE(f.init());
    const i32 fd = f.conns[0].upstream_fd;
    const u64 old_token =
        f.backend.fd_interest[EpollBackend::fd_interest_slot(0, IoEventType::UpstreamRecv)].data;
    REQUIRE(f.park(0));
    f.pool.drain();
    close(f.peer);
    f.peer = -1;
    i32 fresh[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fresh), 0);
    if (fresh[0] != fd) {
        if (fresh[1] == fd) {
            f.peer = fcntl(fresh[1], F_DUPFD_CLOEXEC, 0);
            REQUIRE(f.peer >= 0);
            close(fresh[1]);
        } else {
            f.peer = fresh[1];
        }
        REQUIRE_EQ(dup2(fresh[0], fd), fd);
        close(fresh[0]);
    } else {
        f.peer = fresh[1];
    }
    f.conns[1].upstream_fd = fd;
    REQUIRE(f.backend.begin_upstream_episode(1, f.conns[1].upstream_episode));
    REQUIRE(f.backend.add_recv_upstream(fd, 1, f.conns[1].upstream_episode));
    CHECK_NE(f.backend.stable_upstream[fd].generation, static_cast<u32>(old_token >> 32));
    f.backend.ready[0] = {EPOLLIN, {.u64 = old_token}};
    f.backend.ready_slot[0] = EpollBackend::kStableReadySlotBit | static_cast<u32>(fd);
    f.backend.ready_gen[0] = f.backend.stable_upstream[fd].version;
    f.backend.ready_head = 0;
    f.backend.ready_count = 1;
    const u8 byte = 'r';
    REQUIRE_EQ(send(f.peer, &byte, 1, 0), 1);
    IoEvent event{};
    CHECK_EQ(f.backend.wait(&event, 1, f.conns, 2), 0u);
    CHECK_EQ(f.conns[1].upstream_recv_buf.len(), 0u);
    REQUIRE_EQ(f.backend.wait(&event, 1, f.conns, 2), 1u);
    CHECK_EQ(event.conn_id, 1u);
    CHECK_EQ(f.conns[1].upstream_recv_buf.data()[0], byte);
}

TEST(epoll_stable, partial_send_keeps_write_interest_and_restores_stable_read_owner) {
    StableEpollFixture f;
    REQUIRE(f.init());
    const i32 fd = f.conns[0].upstream_fd;
    const i32 send_capacity = 4096;
    REQUIRE_EQ(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_capacity, sizeof(send_capacity)), 0);
    u8 payload[64 * 1024];
    for (auto& byte : payload) byte = 0xa5;
    REQUIRE(
        f.backend.add_send_upstream(fd, 0, payload, sizeof(payload), f.conns[0].upstream_episode));
    REQUIRE(f.backend.upstream_send_state[0].remaining > 0);
    CHECK_FALSE(f.backend.stable_upstream[fd].registered);
    REQUIRE(f.backend.add_recv_upstream(fd, 0, f.conns[0].upstream_episode));
    CHECK_FALSE(f.backend.stable_upstream[fd].registered);
    u32 received = 0;
    bool completed = false;
    u8 bytes[2048];
    for (u32 turn = 0; turn < 128 && !completed; ++turn) {
        for (;;) {
            const ssize_t count = recv(f.peer, bytes, sizeof(bytes), 0);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && errno == EAGAIN) break;
            REQUIRE(count > 0);
            received += static_cast<u32>(count);
            for (ssize_t i = 0; i < count; ++i) CHECK_EQ(bytes[i], 0xa5);
        }
        IoEvent event{};
        if (f.backend.wait(&event, 1, f.conns, 2) != 0 && event.type == IoEventType::UpstreamSend) {
            CHECK_EQ(event.upstream_episode, f.conns[0].upstream_episode);
            CHECK_EQ(event.result, static_cast<i32>(sizeof(payload)));
            completed = true;
        }
    }
    REQUIRE(completed);
    while (received < sizeof(payload)) {
        const ssize_t count = recv(f.peer, bytes, sizeof(bytes), 0);
        REQUIRE(count > 0);
        received += static_cast<u32>(count);
        for (ssize_t i = 0; i < count; ++i) CHECK_EQ(bytes[i], 0xa5);
    }
    CHECK_EQ(received, sizeof(payload));
    CHECK_EQ(f.backend.upstream_send_state[0].remaining, 0u);
    CHECK(f.backend.stable_upstream[fd].registered);
    CHECK(f.backend.stable_upstream[fd].recv_enabled);
}

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
    CHECK_EQ(loop.relay_budget_calls, IoUringEventLoop::kRelayTurnMaxCalls - 4u);
    CHECK_EQ(loop.relay_budget_bytes, IoUringEventLoop::kRelayTurnMaxBytes - 256u * 1024u);
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
    constexpr u32 kOwnersPerTurn = IoUringEventLoop::kRelayTurnMaxCalls / 2;
    constexpr u32 kOwnerCount = kOwnersPerTurn + 1;
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

    CHECK_EQ(loop.relay_pulled_bytes, kOwnersPerTurn * kFirstTurn);
    CHECK_EQ(loop.relay_written_bytes, kOwnersPerTurn * kFirstTurn);
    CHECK_EQ(loop.relay_budget_calls, 0u);
    CHECK_EQ(loop.relay_budget_bytes, 0u);
    CHECK_EQ(loop.deferred_relay_read_count, kOwnerCount);
    for (u32 i = 0; i < kOwnerCount - 1; ++i) {
        CHECK(conns[i]->relay_owner.active());
        CHECK_FALSE(conns[i]->relay_owner.read_armed);
        CHECK_FALSE(conns[i]->relay_owner.write_armed);
        CHECK_EQ(conns[i]->relay_owner.body_bytes, kFirstTurn);
        CHECK_EQ(conns[i]->pending_ops, 0u);
    }
    CHECK_FALSE(conns[kOwnerCount - 1]->relay_owner.read_armed);
    CHECK_EQ(conns[kOwnerCount - 1]->relay_owner.body_bytes, 0u);
    CHECK_EQ(conns[kOwnerCount - 1]->pending_ops, 0u);

    // An exhausted turn keeps all owners runnable, including the owner that
    // has not moved a byte yet. It must not manufacture readiness polls.
    loop.flush_deferred_relay_reads();
    CHECK_EQ(loop.deferred_relay_read_count, kOwnerCount);
    for (Connection* c : conns) {
        CHECK_FALSE(c->relay_owner.read_armed);
        CHECK_EQ(c->pending_ops, 0u);
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

TEST(request_policy_parse_witness, exact_wire_and_stale_extent_rejection) {
    Connection conn{};
    u8 recv[512]{};
    u8 send[512]{};
    static constexpr char kRequest[] =
        "GET /item?q=1 HTTP/1.1\r\nHost: client\r\nX-Test: yes\r\n\r\n";
    static constexpr char kExpected[] =
        "GET /item?q=1 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\nX-Test: yes\r\n\r\n";
    conn.reset();
    conn.recv_slice = recv;
    conn.send_slice = send;
    conn.bind_request_receive_buffer(recv, sizeof(recv));
    conn.send_buf.bind(send, sizeof(send));
    REQUIRE_EQ(conn.recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
               sizeof(kRequest) - 1);
    capture_request_metadata(conn);
    RequestPolicyParseWitness witness;
    REQUIRE_EQ(inspect_request_policy_body(conn, 1, &witness), RequestPolicyBodyState::Complete);
    REQUIRE_EQ(witness.source, conn.recv_buf.data());
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(0x7f000001u);
    endpoint.sin_port = htons(9000);
    const u32 kSourceLength = witness.source_len;
    ++witness.source_len;
    CHECK_FALSE(materialize_validated_request_policy(conn, endpoint, 1, &witness));
    CHECK_EQ(conn.recv_buf.len(), sizeof(kRequest) - 1);
    witness.source_len = kSourceLength;
    const u8* kSource = witness.source;
    witness.source = send;
    CHECK_FALSE(materialize_validated_request_policy(conn, endpoint, 1, &witness));
    witness.source = kSource;
    REQUIRE(materialize_validated_request_policy(conn, endpoint, 1, &witness));
    REQUIRE_EQ(conn.recv_buf.len(), sizeof(kExpected) - 1);
    CHECK_EQ(__builtin_memcmp(conn.recv_buf.data(), kExpected, sizeof(kExpected) - 1), 0);
}

TEST(request_policy_parse_witness, waiting_and_invalid_do_not_publish) {
    Connection conn{};
    u8 recv[512]{};
    u8 send[512]{};
    const char* requests[] = {
        "GET /item HTTP/1.1\r\nHost: client\r\nContent-Length: 3\r\n\r\na",
        "GET /item HTTP/1.1\r\nHost: client\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"};
    for (u32 i = 0; i < 2; ++i) {
        conn.reset();
        conn.recv_slice = recv;
        conn.send_slice = send;
        conn.bind_request_receive_buffer(recv, sizeof(recv));
        conn.send_buf.bind(send, sizeof(send));
        const u32 kLength = static_cast<u32>(__builtin_strlen(requests[i]));
        REQUIRE_EQ(conn.recv_buf.write(reinterpret_cast<const u8*>(requests[i]), kLength), kLength);
        capture_request_metadata(conn);
        RequestPolicyParseWitness witness;
        CHECK_EQ(inspect_request_policy_body(conn, 1, &witness),
                 i == 0 ? RequestPolicyBodyState::Waiting : RequestPolicyBodyState::Invalid);
        CHECK_EQ(witness.source, nullptr);
    }
}

TEST(request_metadata_parse_reuse, preserves_framing_routing_and_client_headers) {
    const char* wires[] = {
        "GET /item?q=1 HTTP/1.1\r\nHost: client\r\nConnection: close\r\n\r\n",
        "POST /upload HTTP/1.1\r\nHost: client\r\nContent-Length: 4\r\n\r\nab",
        "GET /item#fragment HTTP/1.1\r\nHost: client\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: client\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        "GET /item HTTP/1.1\r\nHost: client\r\nTE: trailers\r\nConnection: close\r\nConnection: "
        "keep-alive\r\n\r\n",
        "GET /first HTTP/1.1\r\nHost: client\r\n\r\nGET /second HTTP/1.1\r\nHost: client\r\n\r\n"};
    for (const char* wire : wires) {
        Connection legacy{};
        Connection reused{};
        u8 legacy_recv[512]{};
        u8 reused_recv[512]{};
        legacy.reset();
        reused.reset();
        legacy.bind_request_receive_buffer(legacy_recv, sizeof(legacy_recv));
        reused.bind_request_receive_buffer(reused_recv, sizeof(reused_recv));
        const u32 kLength = static_cast<u32>(__builtin_strlen(wire));
        REQUIRE_EQ(legacy.recv_buf.write(reinterpret_cast<const u8*>(wire), kLength), kLength);
        REQUIRE_EQ(reused.recv_buf.write(reinterpret_cast<const u8*>(wire), kLength), kLength);
        HttpParser parser;
        ParsedRequest request;
        parser.reset();
        REQUIRE_EQ(parser.parse(reused.recv_buf.data(), kLength, &request), ParseStatus::Complete);
        capture_request_metadata(legacy);
        capture_parsed_request_metadata(reused, request, parser.header_end);
        CHECK_EQ(reused.req_method, legacy.req_method);
        CHECK_EQ(reused.req_header_end, legacy.req_header_end);
        CHECK_EQ(reused.req_initial_send_len, legacy.req_initial_send_len);
        CHECK_EQ(reused.req_http_version, legacy.req_http_version);
        CHECK_EQ(reused.req_body_mode, legacy.req_body_mode);
        CHECK_EQ(reused.req_body_remaining, legacy.req_body_remaining);
        CHECK_EQ(reused.req_content_length, legacy.req_content_length);
        CHECK_EQ(reused.req_target_has_fragment, legacy.req_target_has_fragment);
        CHECK_EQ(reused.req_target_form_unsupported, legacy.req_target_form_unsupported);
        CHECK_EQ(reused.req_malformed, legacy.req_malformed);
        CHECK_EQ(reused.req_keep_alive, legacy.req_keep_alive);
        CHECK_EQ(reused.req_client_connection_close, legacy.req_client_connection_close);
        CHECK_EQ(reused.req_client_connection_count, legacy.req_client_connection_count);
        CHECK_EQ(reused.req_client_has_te, legacy.req_client_has_te);
        CHECK_EQ(reused.req_wants_upgrade, legacy.req_wants_upgrade);
        CHECK_EQ(reused.req_upgrade_is_websocket, legacy.req_upgrade_is_websocket);
        CHECK_EQ(reused.capture_header_len, legacy.capture_header_len);
        CHECK_EQ(__builtin_strcmp(reused.req_path, legacy.req_path), 0);
        REQUIRE_EQ(reused.req_path_canon.len, legacy.req_path_canon.len);
        CHECK_EQ(
            __builtin_memcmp(
                reused.req_path_canon.ptr, legacy.req_path_canon.ptr, reused.req_path_canon.len),
            0);
        CHECK_EQ(reused.recv_buf.len(), kLength);
        CHECK_EQ(__builtin_memcmp(reused.recv_buf.data(), wire, kLength), 0);
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
