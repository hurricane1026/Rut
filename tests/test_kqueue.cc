#include "fault_injection.h"
#include "rut/platform/socket.h"
#include "rut/runtime/kqueue_backend.h"
#include "test.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

using namespace rut;

namespace {
struct Pair {
    int fd[2] = {-1, -1};
    bool init() {
        return socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0 && platform::prepare_socket(fd[0]) &&
               platform::prepare_socket(fd[1]);
    }
    ~Pair() {
        for (int f : fd)
            if (f >= 0) close(f);
    }
};
u64 now_ns() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return static_cast<u64>(now.tv_sec) * 1'000'000'000ull + now.tv_nsec;
}
struct Backend {
    KqueueBackend* value = nullptr;
    bool init() {
        void* mem = mmap(nullptr,
                         sizeof(KqueueBackend),
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1,
                         0);
        if (mem == MAP_FAILED) return false;
        value = new (mem) KqueueBackend();
        return value->init(0, -1).has_value();
    }
    ~Backend() {
        if (!value) return;
        value->shutdown();
        value->~KqueueBackend();
        munmap(value, sizeof(KqueueBackend));
    }
};
bool ready(KqueueBackend& backend, int timeout_ms = 1000) {
    struct pollfd fd{backend.kqueue_fd, POLLIN, 0};
    return poll(&fd, 1, timeout_ms) == 1;
}
}  // namespace

TEST(kqueue, pause_resume_and_half_close) {
    Backend backend;
    REQUIRE(backend.init());
    auto& b = *backend.value;
    CHECK(fcntl(b.kqueue_fd, F_GETFD) & FD_CLOEXEC);
    Pair pair;
    REQUIRE(pair.init());
    Connection conn{};
    conn.reset();
    conn.id = 0;
    conn.fd = pair.fd[0];
    u8 bytes[32];
    conn.recv_buf.bind(bytes, sizeof(bytes));
    REQUIRE(b.add_recv(pair.fd[0], 0));
    b.pause_recv(0);
    REQUIRE_EQ(write(pair.fd[1], "abc", 3), 3);
    CHECK(!ready(b, 10));
    REQUIRE(b.add_recv(pair.fd[0], 0));
    REQUIRE(ready(b));
    IoEvent event;
    REQUIRE_EQ(b.wait(&event, 1, &conn, 1), 1u);
    CHECK_EQ(event.type, IoEventType::Recv);
    CHECK_EQ(event.result, 3);
    CHECK_EQ(conn.recv_buf.len(), 3u);
    b.pause_recv(0);
    REQUIRE_EQ(shutdown(pair.fd[1], SHUT_WR), 0);
    REQUIRE(ready(b));
    REQUIRE_EQ(b.wait(&event, 1, &conn, 1), 1u);
    CHECK_EQ(event.result, 0);
    b.quiesce_recv(0, false, 0);
    CHECK(!ready(b, 10));
}

TEST(kqueue, periodic_ticks_precise_yield_and_wakeup) {
    Backend backend;
    REQUIRE(backend.init());
    auto& b = *backend.value;
    IoEvent event;
    b.arm_yield_timer(now_ns() + 20'000'000);
    REQUIRE(ready(b));
    // Model a busy event loop: Darwin can count multiple elapsed intervals
    // even for EV_ONESHOT, but a handler timer must report one expiration.
    const struct timespec delay{0, 60'000'000};
    REQUIRE_EQ(nanosleep(&delay, nullptr), 0);
    REQUIRE_EQ(b.wait(&event, 1, nullptr, 0), 1u);
    CHECK_EQ(event.type, IoEventType::HandlerTimer);
    CHECK_EQ(event.result, 1);
    b.arm_yield_timer(now_ns() + 20'000'000);
    b.arm_yield_timer(0);
    b.wake();
    REQUIRE(ready(b));
    CHECK_EQ(b.wait(&event, 1, nullptr, 0), 0u);
    REQUIRE(ready(b, 2000));
    REQUIRE_EQ(b.wait(&event, 1, nullptr, 0), 1u);
    CHECK_EQ(event.type, IoEventType::Timeout);
    CHECK(event.result >= 1);
}

TEST(kqueue, closed_socket_does_not_raise_sigpipe) {
    Pair pair;
    REQUIRE(pair.init());
    close(pair.fd[1]);
    pair.fd[1] = -1;
    CHECK_EQ(send(pair.fd[0], "x", 1, platform::kSendFlags), -1);
    CHECK_EQ(errno, EPIPE);
}

TEST(kqueue, registration_failure_and_cleanup) {
    Backend backend;
    REQUIRE(backend.init());
    auto& b = *backend.value;
    CHECK(!b.add_recv(-1, 0));
    Pair pair;
    REQUIRE(pair.init());
    b.shutdown();
    CHECK_EQ(b.kqueue_fd, -1);
    CHECK(!b.add_recv(pair.fd[0], 0));
}

TEST(kqueue, send_backpressure_preserves_independent_read_filter) {
    Backend backend;
    REQUIRE(backend.init());
    Pair pair;
    REQUIRE(pair.init());
    auto& b = *backend.value;
    Connection conn{};
    conn.reset();
    conn.id = 0;
    conn.fd = pair.fd[0];
    u8 input[32];
    conn.recv_buf.bind(input, sizeof(input));
    REQUIRE(b.add_recv(pair.fd[0], 0));
    int size = 4096;
    REQUIRE_EQ(setsockopt(pair.fd[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)), 0);
    static u8 bytes[256 * 1024];
    REQUIRE(b.add_send(pair.fd[0], 0, bytes, sizeof(bytes)));
    REQUIRE(b.send_state[0].remaining > 0);
    // Re-registering READ must not remove the outstanding WRITE filter.
    REQUIRE(b.add_recv(pair.fd[0], 0));
    REQUIRE_EQ(write(pair.fd[1], "abc", 3), 3);
    u32 received = 0;
    bool sent = false, read = false;
    const u64 deadline = now_ns() + 2'000'000'000ull;
    while ((!sent || !read) && now_ns() < deadline) {
        u8 buf[16384];
        ssize_t n;
        while ((n = ::read(pair.fd[1], buf, sizeof(buf))) > 0) received += static_cast<u32>(n);
        if (!ready(b, 10)) continue;
        IoEvent event;
        if (b.wait(&event, 1, &conn, 1) != 1) continue;
        if (event.type == IoEventType::Send) {
            CHECK_EQ(event.result, static_cast<i32>(sizeof(bytes)));
            sent = true;
        } else if (event.type == IoEventType::Recv) {
            CHECK_EQ(event.result, 3);
            read = true;
        }
    }
    CHECK(sent);
    CHECK(read);
    CHECK_EQ(b.send_state[0].remaining, 0u);
    u8 buf[16384];
    ssize_t n;
    while ((n = ::read(pair.fd[1], buf, sizeof(buf))) > 0) received += static_cast<u32>(n);
    CHECK_EQ(received, sizeof(bytes));
    b.cancel(pair.fd[0], 0);
    b.clear_send_state(0);
    CHECK_EQ(b.send_state[0].src, nullptr);
}

TEST(kqueue, upstream_episode_detach_and_reuse) {
    Backend backend;
    REQUIRE(backend.init());
    Pair pair;
    REQUIRE(pair.init());
    auto& b = *backend.value;
    Connection conn{};
    conn.reset();
    conn.id = 0;
    conn.upstream_fd = pair.fd[0];
    const u32 episode = conn.upstream_episode;
    REQUIRE(b.begin_upstream_episode(0, episode));
    REQUIRE(b.add_recv_upstream(pair.fd[0], 0, episode));
    REQUIRE_EQ(write(pair.fd[1], "x", 1), 1);
    REQUIRE(ready(b));
    int fd = -1;
    REQUIRE(b.detach_upstream(conn, &fd));
    CHECK_EQ(fd, pair.fd[0]);
    CHECK(!ready(b, 10));
    CHECK(!b.add_recv_upstream(fd, 0, episode));
    REQUIRE(b.begin_upstream_episode(0, conn.upstream_episode));
    REQUIRE(b.add_recv_upstream(fd, 0, conn.upstream_episode));
    u8 input[32];
    conn.upstream_recv_buf.bind(input, sizeof(input));
    REQUIRE(ready(b));
    IoEvent event;
    REQUIRE_EQ(b.wait(&event, 1, &conn, 1), 1u);
    CHECK_EQ(event.upstream_episode, conn.upstream_episode);
    CHECK_EQ(event.result, 1);
}

TEST(kqueue, failed_detach_closes_before_retiring_episode) {
    Backend backend;
    REQUIRE(backend.init());
    Pair pair;
    REQUIRE(pair.init());
    auto& b = *backend.value;
    Connection conn{};
    conn.reset();
    conn.id = 0;
    conn.upstream_fd = pair.fd[0];
    const u32 episode = conn.upstream_episode;
    REQUIRE(b.begin_upstream_episode(0, episode));
    REQUIRE(b.add_recv_upstream(pair.fd[0], 0, episode));
    // Leave the real queue alive while forcing both filter deletions to fail.
    const int queue = b.kqueue_fd;
    b.kqueue_fd = -1;
    int detached_fd = -1;
    const bool detached = b.detach_upstream(conn, &detached_fd);
    b.kqueue_fd = queue;
    CHECK(!detached);
    CHECK_EQ(detached_fd, -1);
    CHECK_EQ(fcntl(pair.fd[0], F_GETFD), -1);
    CHECK_EQ(errno, EBADF);
    pair.fd[0] = -1;  // The backend consumed the descriptor.
    CHECK_EQ(conn.upstream_fd, -1);
    CHECK_NE(conn.upstream_episode, episode);
    CHECK_EQ(b.active_upstream_episode[0], 0u);
    CHECK(b.begin_upstream_episode(0, conn.upstream_episode));
}

TEST(kqueue, failed_detach_and_close_quarantines_episode) {
    Backend backend;
    REQUIRE(backend.init());
    Pair pair;
    REQUIRE(pair.init());
    auto& b = *backend.value;
    Connection conn{};
    conn.reset();
    conn.id = 0;
    conn.upstream_fd = pair.fd[0];
    const u32 episode = conn.upstream_episode;
    REQUIRE(b.begin_upstream_episode(0, episode));
    REQUIRE(b.add_recv_upstream(pair.fd[0], 0, episode));
    REQUIRE_EQ(write(pair.fd[1], "x", 1), 1);
    REQUIRE(ready(b));
    auto fault = test_fault::io_fault_for_fd(pair.fd[0]);
    fault.close_errno = EINTR;
    fault.close_failures = 1;
    int detached_fd = -1;
    bool detached;
    {
        test_fault::ScopedIoFault scope(fault);
        const int queue = b.kqueue_fd;
        b.kqueue_fd = -1;
        detached = b.detach_upstream(conn, &detached_fd);
        b.kqueue_fd = queue;
    }
    CHECK(!detached);
    CHECK_EQ(detached_fd, -1);
    CHECK(fcntl(pair.fd[0], F_GETFD) >= 0);  // No retry after the injected close failure.
    CHECK_EQ(conn.upstream_fd, -1);
    CHECK_EQ(conn.upstream_episode, episode);
    CHECK_EQ(b.active_upstream_episode[0], KqueueBackend::kUpstreamEpisodeExhausted);
    CHECK(!b.detach_upstream(conn));  // A second, fd-less cleanup cannot clear quarantine.
    CHECK(!b.begin_upstream_episode(0, episode + 1));
    REQUIRE(ready(b));
    IoEvent event;
    CHECK_EQ(b.wait(&event, 1, &conn, 1), 0u);  // Reject the surviving kernel event.
    b.quarantine_upstream_episode_on_slot_release(0);
    CHECK_EQ(b.active_upstream_episode[0], KqueueBackend::kUpstreamEpisodeExhausted);
}

TEST(kqueue, eof_preserves_unread_bytes) {
    Backend backend;
    REQUIRE(backend.init());
    Pair pair;
    REQUIRE(pair.init());
    auto& b = *backend.value;
    Connection conn{};
    conn.reset();
    conn.id = 0;
    conn.fd = pair.fd[0];
    u8 input[32];
    conn.recv_buf.bind(input, sizeof(input));
    REQUIRE(b.add_recv(pair.fd[0], 0));
    REQUIRE_EQ(write(pair.fd[1], "last bytes", 10), 10);
    REQUIRE_EQ(shutdown(pair.fd[1], SHUT_WR), 0);
    REQUIRE(ready(b));
    IoEvent event;
    REQUIRE_EQ(b.wait(&event, 1, &conn, 1), 1u);
    CHECK_EQ(event.result, 10);
    CHECK_EQ(conn.recv_buf.len(), 10u);
    REQUIRE(ready(b));
    REQUIRE_EQ(b.wait(&event, 1, &conn, 1), 1u);
    CHECK_EQ(event.result, 0);
    // Peer SHUT_WR must not prevent the response from being sent back.
    REQUIRE(b.add_send(pair.fd[0], 0, reinterpret_cast<const u8*>("ok"), 2));
    REQUIRE_EQ(b.wait(&event, 1, &conn, 1), 1u);
    CHECK_EQ(event.type, IoEventType::Send);
    CHECK_EQ(event.result, 2);
}

TEST(kqueue, refused_connect_reports_error_and_retires_episode) {
    Backend backend;
    REQUIRE(backend.init());
    auto& b = *backend.value;
    // Obtain an unused loopback address, then close it before connecting.
    // Darwin can defer a connect while the destination is bound but not listening.
    int reserved = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(reserved >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE_EQ(bind(reserved, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    socklen_t length = sizeof(address);
    REQUIRE_EQ(getsockname(reserved, reinterpret_cast<sockaddr*>(&address), &length), 0);
    close(reserved);
    Connection conn{};
    conn.reset();
    conn.id = 0;
    conn.upstream_fd = platform::stream_socket();
    REQUIRE(conn.upstream_fd >= 0);
    REQUIRE(b.begin_upstream_episode(0, conn.upstream_episode));
    REQUIRE(b.add_connect(conn.upstream_fd, 0, &address, sizeof(address), conn.upstream_episode));
    REQUIRE(b.pending_count || ready(b));
    IoEvent event;
    REQUIRE_EQ(b.wait(&event, 1, &conn, 1), 1u);
    CHECK_EQ(event.type, IoEventType::UpstreamConnect);
    CHECK_EQ(event.result, -ECONNREFUSED);
    CHECK_EQ(event.upstream_episode, conn.upstream_episode);
    REQUIRE(b.detach_upstream(conn));
    CHECK_EQ(conn.upstream_fd, -1);
}

TEST(kqueue, full_proxy_buffer_waits_for_send_before_rearming_read) {
    Backend backend;
    REQUIRE(backend.init());
    Pair pair;
    REQUIRE(pair.init());
    auto& b = *backend.value;
    Connection conn{};
    conn.reset();
    conn.id = 0;
    conn.upstream_fd = pair.fd[0];
    u8 input[4];
    conn.upstream_recv_buf.bind(input, sizeof(input));
    conn.upstream_recv_buf.write(reinterpret_cast<const u8*>("held"), 4);
    conn.on_send = +[](void*, Connection&, IoEvent) {};
    REQUIRE(b.begin_upstream_episode(0, conn.upstream_episode));
    REQUIRE(b.add_recv_upstream(pair.fd[0], 0, conn.upstream_episode));
    REQUIRE_EQ(write(pair.fd[1], "next", 4), 4);
    REQUIRE(ready(b));
    IoEvent event;
    CHECK_EQ(b.wait(&event, 1, &conn, 1), 0u);
    CHECK_EQ(input[0], 'h');  // The in-flight send still owns the old bytes.
    CHECK(!ready(b, 10));
    conn.upstream_recv_buf.reset();
    conn.on_send = nullptr;
    REQUIRE(b.add_recv_upstream(pair.fd[0], 0, conn.upstream_episode));
    REQUIRE(ready(b));
    REQUIRE_EQ(b.wait(&event, 1, &conn, 1), 1u);
    CHECK_EQ(event.result, 4);
    CHECK_EQ(input[0], 'n');
    CHECK_EQ(b.failure_code(), 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
