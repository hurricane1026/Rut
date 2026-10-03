// Idle keep-alive buffer trim on the io_uring loop (IoUringEventLoop::sweep_idle_trim),
// which is driven from the timer wheel.
//
// Real-loop tests drive an actual IoUringEventLoop single-threaded against real
// loopback sockets: the test thread alternates client I/O with backend.wait() +
// dispatch_batch() (what run() does), and injects the 1 Hz Timeout tick directly
// with loop->dispatch() so no test sleeps for real seconds. The loop's own timerfd is
// slowed to 10 s so a stray real tick cannot perturb the tick arithmetic.

#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/slice_pool.h"
#include "test.h"
#include "test_helpers.h"
#include <iostream>
#include <string>

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

using namespace rut;

namespace {

// Fault injection for IoUringEventLoop's idle-trim page release (see
// detail::test_idle_trim_inject). Each knob defaults to "no fault".
i64 g_fail_point = -1;               // probe step (PidfdOpen / ProbeAdvise) that fails
i64 g_batch_allowed = -1;            // ranges process_madvise may take per call (-1: all)
const u8* g_fail_slice_a = nullptr;  // per-slice madvise fails for these two slices
const u8* g_fail_slice_b = nullptr;
// Once the retry budget proves that this process cannot create a ring, later
// test cases must skip immediately instead of repeating the same 10-second wait.
bool g_iouring_permanently_unavailable = false;

}  // namespace

namespace rut::detail {

i64 test_idle_trim_inject(u8 point, u64 arg) noexcept {
    switch (point) {
        case IdleTrimPidfdOpen:
        case IdleTrimProbeAdvise:
            return g_fail_point == point ? 0 : -1;
        case IdleTrimBatchAdvise:
            return g_batch_allowed;
        case IdleTrimSliceAdvise: {
            const u8* p = reinterpret_cast<const u8*>(arg);
            return (p == g_fail_slice_a || p == g_fail_slice_b) ? 0 : -1;
        }
        default:
            return -1;
    }
}

}  // namespace rut::detail

namespace {

// Restores every injection knob when a test ends, however it ends.
struct InjectGuard {
    ~InjectGuard() {
        g_fail_point = -1;
        g_batch_allowed = -1;
        g_fail_slice_a = nullptr;
        g_fail_slice_b = nullptr;
    }
};

u64 g_big_body_calls = 0;
constexpr u32 kBigBodyLen = 1u << 20;
char g_big_body[kBigBodyLen];

// ReturnStatus 200 with response body #1 (carried in upstream_id).
u64 big_body_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    ++g_big_body_calls;
    return jit::HandlerResult{jit::HandlerAction::ReturnStatus, 200, 1, 0, jit::YieldKind::HttpGet}
        .pack();
}

// Timer wait, then 204: a `wait(ms)` route — pending_handler_fn set while parked.
u64 waiting_handler(void*, jit::HandlerCtx* ctx, const u8*, u32, void*) {
    if (ctx != nullptr && ctx->state == 7) return jit::HandlerResult::make_status(204).pack();
    return jit::HandlerResult::make_yield_payload(7, jit::YieldKind::Timer, 400).pack();
}

u32 resident_pages(const u8* p, u32 len) {
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || reinterpret_cast<uintptr_t>(p) % static_cast<uintptr_t>(page_size) != 0)
        return 0xffffffffu;
    const u32 pages = (len + static_cast<u32>(page_size) - 1) / static_cast<u32>(page_size);
    unsigned char vec[16];
    if (pages > sizeof(vec)) return 0;
    if (mincore(const_cast<u8*>(p), len, vec) != 0) return 0xffffffffu;
    u32 n = 0;
    for (u32 i = 0; i < pages; i++) n += vec[i] & 1u;
    return n;
}

bool slice_pages_are_independent() {
    const long page_size = sysconf(_SC_PAGESIZE);
    return page_size > 0 && SlicePool::kSliceSize % static_cast<u32>(page_size) == 0;
}

void drain_client(i32 fd, std::string& out) {
    char buf[65536];
    for (;;) {
        const ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0) return;
        out.append(buf, static_cast<size_t>(n));
    }
}

// True once `data` holds `count` complete responses; sets `total` to the byte length
// of the first `count` (Content-Length framed; header-only when absent).
bool complete_responses(const std::string& data, u32 count, size_t* total) {
    size_t pos = 0;
    for (u32 i = 0; i < count; i++) {
        const size_t he = data.find("\r\n\r\n", pos);
        if (he == std::string::npos) return false;
        size_t body = 0;
        const size_t cl = data.find("Content-Length: ", pos);
        if (cl != std::string::npos && cl < he) body = strtoul(data.c_str() + cl + 16, nullptr, 10);
        pos = he + 4 + body;
        if (pos > data.size()) return false;
    }
    if (total != nullptr) *total = pos;
    return true;
}

struct TrimRig {
    void* storage = MAP_FAILED;
    IoUringEventLoop* loop = nullptr;
    RouteConfig cfg{};
    const RouteConfig* active = nullptr;
    i32 lfd = -1;
    u16 port = 0;
    bool listening = false;
    bool up = false;
    bool need_trim = true;  // fail init (tests SKIP) when process_madvise is unusable

    // capacity: slot count. server_sndbuf != 0 shrinks accepted sockets' send buffers.
    bool init(u32 capacity, bool listen_socket, u32 server_sndbuf = 0) {
        if (g_iouring_permanently_unavailable) return false;
        storage = mmap(nullptr,
                       sizeof(IoUringEventLoop),
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);
        if (storage == MAP_FAILED) return false;
        loop = new (storage) IoUringEventLoop();
        if (listen_socket) {
            auto l = create_listen_socket(0);
            if (!l.has_value()) return false;
            lfd = l.value();
            port = get_port(lfd);
            if (server_sndbuf != 0)
                setsockopt(lfd, SOL_SOCKET, SO_SNDBUF, &server_sndbuf, sizeof(server_sndbuf));
            listening = true;
        }
        // Rings are charged to the per-user RLIMIT_MEMLOCK, so concurrent test
        // processes can transiently exhaust it (ENOMEM): retry briefly before
        // treating io_uring as unavailable.
        bool inited = false;
        bool saw_enomem = false;
        for (u32 attempt = 0; attempt < 40 && !inited; attempt++) {
            if (attempt != 0) {
                usleep(250 * 1000);
                loop->~IoUringEventLoop();
                loop = new (storage) IoUringEventLoop();
            }
            auto r = loop->init(0, lfd, 0, capacity);
            inited = r.has_value();
            if (!inited && r.error().code != ENOMEM) break;
            if (!inited) saw_enomem = true;
        }
        if (!inited) {
            if (saw_enomem) g_iouring_permanently_unavailable = true;
            return false;
        }
        up = true;
        if (need_trim && loop->idle_trim_pidfd < 0) return false;
        loop->config_ptr = &active;
        active = &cfg;
        if (listening) {
            // Slow the loop's own 1 Hz timerfd so only injected ticks drive the test.
            itimerspec its{};
            its.it_interval.tv_sec = 10;
            its.it_value.tv_sec = 10;
            if (loop->backend.timer_fd >= 0)
                timerfd_settime(loop->backend.timer_fd, 0, &its, nullptr);
            loop->backend.add_accept();
        }
        return true;
    }

    ~TrimRig() {
        if (loop != nullptr) {
            if (up) {
                for (u32 i = 0; i < loop->slots_initialized; i++)
                    if (loop->conns[i].fd >= 0 && loop->conns[i].fd < 100000)
                        ::close(loop->conns[i].fd);
                loop->shutdown();
            }
            loop->~IoUringEventLoop();
        }
        if (lfd >= 0) ::close(lfd);
        if (storage != MAP_FAILED) munmap(storage, sizeof(IoUringEventLoop));
    }

    template <typename Pred>
    bool pump(Pred pred, i64 max_ms = 8000) {
        IoEvent events[kMaxEventsPerWait];
        const i64 deadline = test_mono_ms() + max_ms;
        while (!pred()) {
            if (test_mono_ms() > deadline) return false;
            const u32 n = loop->backend.wait(
                events, kMaxEventsPerWait, loop->conns, loop->connection_capacity);
            loop->dispatch_batch(events, n);
        }
        return true;
    }

    void tick(i32 n = 1) { loop->dispatch(make_ev(0, IoEventType::Timeout, n)); }

    Connection* live_conn() {
        // Slots at or past slots_initialized were never handed out (zero bytes).
        for (u32 i = 0; i < loop->slots_initialized; i++)
            if (loop->conns[i].fd >= 0) return &loop->conns[i];
        return nullptr;
    }

    i32 connect_client(u32 rcvbuf = 0) {
        const i32 fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        if (rcvbuf != 0) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = __builtin_bswap16(port);
        a.sin_addr.s_addr = __builtin_bswap32(0x7F000001);
        if (connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
            ::close(fd);
            return -1;
        }
        return fd;
    }

    // Send `req`, pump until `count` complete responses arrived; returns the bytes.
    bool exchange(i32 cli, const char* req, std::string& resp, u32 count = 1) {
        resp.clear();
        if (!send_all(cli, req, static_cast<u32>(strlen(req)))) return false;
        return pump([&] {
            drain_client(cli, resp);
            return complete_responses(resp, count, nullptr);
        });
    }

    bool wait_idle() {
        return pump([&] {
            Connection* c = live_conn();
            return c != nullptr && loop->idle_trim_eligible(*c);
        });
    }
};

// The contract under test (spelled out, not read from the loop's constant, so a change
// to the loop's minimum idle age cannot silently move the goalposts): nothing is trimmed
// before a connection has been idle this many wheel ticks.
constexpr u32 kMinIdleTicks = 5;

constexpr const char kReqA[] = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
constexpr const char kReqB[] = "GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
constexpr const char kReqBig[] = "GET /big HTTP/1.1\r\nHost: x\r\n\r\n";
constexpr const char kReqWait[] = "GET /wait HTTP/1.1\r\nHost: x\r\n\r\n";

// Register the routes every real-loop test uses.
bool add_routes(TrimRig& r) {
    for (u32 i = 0; i < kBigBodyLen; i++) g_big_body[i] = static_cast<char>('a' + (i % 23));
    return r.cfg.add_static("/a", kRouteMethodGet, 200) &&
           r.cfg.add_static("/b", kRouteMethodGet, 204) &&
           r.cfg.add_response_body_view(g_big_body, kBigBodyLen) == 1u &&
           r.cfg.add_jit_handler("/big", kRouteMethodGet, &big_body_handler) &&
           r.cfg.add_jit_handler("/wait", kRouteMethodGet, &waiting_handler);
}

}  // namespace

// ---------------------------------------------------------------------------
// SlicePool::bound_slice_valid
// ---------------------------------------------------------------------------

TEST(slice_pool_discard, returns_pages_of_a_bound_slice_and_keeps_it_bound) {
    if (!slice_pages_are_independent()) SKIP("host pages exceed SlicePool slices");
    const long page_size = sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 0);
    SlicePool pool;
    REQUIRE(pool.init(512).has_value());
    u8* s = pool.alloc();
    REQUIRE(s != nullptr);
    __builtin_memset(s, 0x5a, SlicePool::kSliceSize);
    const u32 expected_pages =
        (SlicePool::kSliceSize + static_cast<u32>(page_size) - 1) / static_cast<u32>(page_size);
    CHECK_EQ(resident_pages(s, SlicePool::kSliceSize), expected_pages);
    const u32 avail = pool.available();
    CHECK(pool.bound_slice_valid(s));
    CHECK_EQ(madvise(s, SlicePool::kSliceSize, MADV_DONTNEED), 0);
    CHECK_EQ(resident_pages(s, SlicePool::kSliceSize), 0u);
    for (u32 i = 0; i < SlicePool::kSliceSize; i += 509) CHECK_EQ(s[i], 0u);
    CHECK_EQ(pool.available(), avail);  // still bound: free stack untouched
    CHECK(pool.bound_slice_valid(s));
    // The slice stays fully usable and frees normally.
    s[7] = 1;
    pool.free(s);
    CHECK_EQ(pool.available(), avail + 1);
    u8* again = pool.alloc();
    CHECK(again == s);
    CHECK_EQ(again[7], 0u);  // the free path's zero-fill invariant still holds
    pool.free(again);
    pool.destroy();
}

TEST(slice_pool_discard, refuses_free_misaligned_foreign_and_bulk_pointers) {
    SlicePool pool;
    REQUIRE(pool.init(512, 0, SlicePool::kMaxCachedSlices, 4).has_value());
    u8* s = pool.alloc();
    REQUIRE(s != nullptr);
    __builtin_memset(s, 1, SlicePool::kSliceSize);
    CHECK(pool.bound_slice_valid(s));
    CHECK(!pool.bound_slice_valid(s + 16));  // not slice-aligned
    CHECK(!pool.bound_slice_valid(nullptr));
    u8 local[8];
    CHECK(!pool.bound_slice_valid(local));  // foreign
    pool.free(s);
    CHECK(!pool.bound_slice_valid(s));  // free slice: not bound
    u8* bulk = pool.alloc_bulk();
    REQUIRE(bulk != nullptr);
    CHECK(!pool.bound_slice_valid(bulk));
    pool.free(bulk);
    pool.destroy();
}

// ---------------------------------------------------------------------------
// Real loop: trim, reuse, activity, non-whitelisted states
// ---------------------------------------------------------------------------

TEST(iouring_idle_trim, idle_keepalive_trimmed_once_then_serves_next_request) {
    TrimRig r;
    if (!r.init(8, true)) SKIP("io_uring or process_madvise unavailable");
    REQUIRE(add_routes(r));
    const i32 cli = r.connect_client();
    REQUIRE_GE(cli, 0);
    std::string first;
    REQUIRE(r.exchange(cli, kReqA, first));
    REQUIRE(r.wait_idle());
    Connection* c = r.live_conn();
    REQUIRE(c != nullptr);
    u8* const recv_slice = c->recv_slice;
    u8* const send_slice = c->send_slice;
    // Serving a request dirtied pages in both bound slices.
    CHECK_GE(resident_pages(recv_slice, SlicePool::kSliceSize), 1u);
    CHECK_GE(resident_pages(send_slice, SlicePool::kSliceSize), 1u);

    // Not trimmed before the idle threshold, trimmed right after it.
    u32 ticks = 0;
    while (r.loop->idle_trim_conns == 0 && ticks < 20) {
        r.tick();
        ticks++;
    }
    CHECK_GE(ticks, kMinIdleTicks);
    CHECK_LE(ticks, kMinIdleTicks + 2);
    CHECK_EQ(r.loop->idle_trim_conns, 1u);
    CHECK_EQ(r.loop->idle_trim_madvise, 2u);
    CHECK_EQ(resident_pages(recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(send_slice, SlicePool::kSliceSize), 0u);
    // Bindings are untouched.
    CHECK(c->recv_slice == recv_slice && c->send_slice == send_slice);
    CHECK(c->recv_buf.data() == recv_slice && c->send_buf.data() == send_slice);
    CHECK_EQ(c->recv_buf.capacity(), SlicePool::kSliceSize);
    CHECK_EQ(c->send_buf.capacity(), SlicePool::kSliceSize);

    // At most once per idle period: many more idle ticks change nothing.
    for (u32 i = 0; i < 30; i++) r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, 1u);
    CHECK_EQ(r.loop->idle_trim_madvise, 2u);

    // The trimmed connection serves the next request byte-exactly.
    std::string again;
    REQUIRE(r.exchange(cli, kReqA, again));
    CHECK(again == first);
    std::string b;
    REQUIRE(r.exchange(cli, kReqB, b));
    CHECK(b.compare(0, 12, "HTTP/1.1 204") == 0);
    REQUIRE(r.wait_idle());

    // A new idle period after that activity is trimmed again (once).
    for (u32 i = 0; i < 30; i++) r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, 2u);
    CHECK_EQ(r.loop->idle_trim_madvise, 4u);
    ::close(cli);
}

TEST(iouring_idle_trim, connection_active_every_tick_is_never_trimmed) {
    TrimRig r;
    if (!r.init(8, true)) SKIP("io_uring or process_madvise unavailable");
    REQUIRE(add_routes(r));
    const i32 cli = r.connect_client();
    REQUIRE_GE(cli, 0);
    std::string resp;
    for (u32 i = 0; i < 4 * kMinIdleTicks; i++) {
        REQUIRE(r.exchange(cli, kReqA, resp));
        REQUIRE(r.wait_idle());
        r.tick();
    }
    CHECK_EQ(r.loop->idle_trim_conns, 0u);
    CHECK_EQ(r.loop->idle_trim_madvise, 0u);
    ::close(cli);
}

TEST(iouring_idle_trim, partial_request_bytes_are_never_trimmed) {
    TrimRig r;
    if (!r.init(8, true)) SKIP("io_uring or process_madvise unavailable");
    REQUIRE(add_routes(r));
    const i32 cli = r.connect_client();
    REQUIRE_GE(cli, 0);
    std::string baseline;
    REQUIRE(r.exchange(cli, kReqA, baseline));
    REQUIRE(r.wait_idle());

    const char part1[] = "GET /a HTTP/1.1\r\nHo";
    const u32 part1_len = sizeof(part1) - 1;
    REQUIRE(send_all(cli, part1, part1_len));
    Connection* c = r.live_conn();
    REQUIRE(c != nullptr);
    REQUIRE(r.pump([&] { return c->recv_buf.len() == part1_len; }));
    CHECK(!r.loop->idle_trim_eligible(*c));
    for (u32 i = 0; i < 30; i++) r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, 0u);
    CHECK_EQ(c->recv_buf.len(), part1_len);
    CHECK_EQ(memcmp(c->recv_buf.data(), part1, part1_len), 0);  // bytes intact

    std::string resp;
    const char part2[] = "st: x\r\n\r\n";
    REQUIRE(send_all(cli, part2, sizeof(part2) - 1));
    REQUIRE(r.pump([&] {
        drain_client(cli, resp);
        return complete_responses(resp, 1, nullptr);
    }));
    CHECK(resp == baseline);  // the split request parsed exactly
    ::close(cli);
}

TEST(iouring_idle_trim, slow_reader_with_pipelined_request_is_not_trimmed_until_drained) {
    TrimRig r;
    // Tiny send/receive buffers: the 1 MiB body cannot leave in one go, so the send
    // stays in flight (and the pipelined second request stays buffered) while the
    // client does not read.
    if (!r.init(8, true, 4096)) SKIP("io_uring or process_madvise unavailable");
    REQUIRE(add_routes(r));
    const i32 cli = r.connect_client(4096);
    REQUIRE_GE(cli, 0);
    std::string both;
    both += kReqBig;
    both += kReqA;
    REQUIRE(send_all(cli, both.c_str(), static_cast<u32>(both.size())));
    Connection* c = nullptr;
    REQUIRE(r.pump([&] {
        c = r.live_conn();
        return c != nullptr && g_big_body_calls > 0 && c->send_armed;
    }));
    const u64 calls_before = g_big_body_calls;
    CHECK(!r.loop->idle_trim_eligible(*c));
    for (u32 i = 0; i < 30; i++) r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, 0u);
    CHECK(c->send_armed || c->local_body_remaining != 0 || c->state == ConnState::Sending);
    CHECK_EQ(g_big_body_calls, calls_before);

    // Drain: both responses arrive complete and in order.
    std::string resp;
    REQUIRE(r.pump([&] {
        drain_client(cli, resp);
        return complete_responses(resp, 2, nullptr);
    }));
    size_t first_len = 0;
    REQUIRE(complete_responses(resp, 1, &first_len));
    CHECK_EQ(first_len, resp.find("\r\n\r\n") + 4 + kBigBodyLen);
    CHECK_EQ(memcmp(resp.data() + resp.find("\r\n\r\n") + 4, g_big_body, kBigBodyLen), 0);
    CHECK(resp.compare(first_len, 15, "HTTP/1.1 200 OK") == 0);

    // Once fully drained the connection is at rest and then does get trimmed.
    REQUIRE(r.wait_idle());
    for (u32 i = 0; i < 12; i++) r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, 1u);
    ::close(cli);
}

TEST(iouring_idle_trim, connection_parked_in_wait_handler_is_not_trimmed) {
    TrimRig r;
    if (!r.init(8, true)) SKIP("io_uring or process_madvise unavailable");
    REQUIRE(add_routes(r));
    const i32 cli = r.connect_client();
    REQUIRE_GE(cli, 0);
    REQUIRE(send_all(cli, kReqWait, sizeof(kReqWait) - 1));
    Connection* c = nullptr;
    REQUIRE(r.pump([&] {
        c = r.live_conn();
        return c != nullptr && c->pending_handler_fn != nullptr;
    }));
    CHECK(!r.loop->idle_trim_eligible(*c));
    for (u32 i = 0; i < 30; i++) r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, 0u);
    std::string resp;
    REQUIRE(r.pump([&] {
        drain_client(cli, resp);
        return complete_responses(resp, 1, nullptr);
    }));
    CHECK(resp.compare(0, 12, "HTTP/1.1 204") == 0);
    ::close(cli);
}

// ---------------------------------------------------------------------------
// Synthetic connections: wheel-driven budgets, exactly-once, eligibility table
// ---------------------------------------------------------------------------

namespace {

// Stage a slot as a plain idle keep-alive connection with dirty slice pages, armed
// in the wheel the way accept / the last response event arms it.
Connection* stage_idle(TrimRig& r, i32 fake_fd) {
    Connection* c = r.loop->alloc_conn();
    if (c == nullptr) return nullptr;
    c->fd = fake_fd;  // >= 100000: never a real descriptor, never closed
    c->state = ConnState::ReadingHeader;
    c->on_recv = &on_header_received<IoUringEventLoop>;
    c->recv_armed = true;
    c->pending_ops = 1;  // the multishot recv: all an idle connection has outstanding
    c->recv_slice[0] = 1;
    c->send_slice[0] = 1;
    r.loop->timer.add(c, r.loop->keepalive_timeout);
    return c;
}

// Sweep counters before/after one injected tick.
struct TickDelta {
    u64 examined;
    u64 trimmed;
    u64 madvise;
};

TickDelta tick_delta(TrimRig& r, i32 n = 1) {
    const u64 e = r.loop->idle_trim_examined;
    const u64 t = r.loop->idle_trim_conns;
    const u64 m = r.loop->idle_trim_madvise;
    r.tick(n);
    return {
        r.loop->idle_trim_examined - e, r.loop->idle_trim_conns - t, r.loop->idle_trim_madvise - m};
}

}  // namespace

TEST(iouring_idle_trim, burst_larger_than_budget_is_trimmed_exactly_once_over_later_ticks) {
    constexpr u32 kLive = 3000;
    static_assert(kLive > IoUringEventLoop::kIdleTrimMaxTrims);
    static_assert(kLive > IoUringEventLoop::kIdleTrimMaxExamined);
    TrimRig r;
    if (!r.init(kLive + 8, false)) SKIP("io_uring or process_madvise unavailable");
    r.loop->idle_trim_budget_ns = ~0ull >> 1;  // only the count caps apply
    Connection* sample = nullptr;
    for (u32 i = 0; i < kLive; i++) {
        Connection* c = stage_idle(r, 100000 + static_cast<i32>(i));
        REQUIRE(c != nullptr);
        if (i == 0) sample = c;
    }
    CHECK_EQ(resident_pages(sample->recv_slice, SlicePool::kSliceSize), 1u);

    u64 max_examined = 0;
    u64 max_trimmed = 0;
    u32 first_trim_tick = 0;
    u32 last_trim_tick = 0;
    for (u32 t = 1; t <= 30; t++) {
        const TickDelta d = tick_delta(r);
        if (d.examined > max_examined) max_examined = d.examined;
        if (d.trimmed > max_trimmed) max_trimmed = d.trimmed;
        if (d.trimmed != 0) {
            if (first_trim_tick == 0) first_trim_tick = t;
            last_trim_tick = t;
        }
        // Nothing is examined before the minimum idle age.
        if (t < kMinIdleTicks) CHECK_EQ(d.examined, 0u);
    }
    CHECK_EQ(first_trim_tick, kMinIdleTicks);
    CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(kLive));
    CHECK_EQ(r.loop->idle_trim_madvise, 2ull * kLive);
    // Each connection was examined exactly once, under both caps every tick.
    CHECK_EQ(r.loop->idle_trim_examined, static_cast<u64>(kLive));
    CHECK_EQ(max_trimmed, static_cast<u64>(IoUringEventLoop::kIdleTrimMaxTrims));
    CHECK_LE(max_examined, static_cast<u64>(IoUringEventLoop::kIdleTrimMaxExamined));
    CHECK_EQ(last_trim_tick,
             kMinIdleTicks +
                 (kLive + IoUringEventLoop::kIdleTrimMaxTrims - 1) /
                     IoUringEventLoop::kIdleTrimMaxTrims -
                 1);
    CHECK_EQ(resident_pages(sample->recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(sample->send_slice, SlicePool::kSliceSize), 0u);
    // Further ticks (well before the 60 s expiry) examine nothing at all.
    for (u32 t = 0; t < 20; t++) CHECK_EQ(tick_delta(r).examined, 0u);
}

TEST(iouring_idle_trim,
     time_budget_bounds_each_tick_and_a_burst_beyond_the_window_is_partly_trimmed) {
    // A wall-clock budget already spent after the first node: every tick still makes
    // progress (one node) but no more, so a burst larger than window * rate is only
    // partly trimmed in this idle period — the documented limit — and never over.
    constexpr u32 kLive = 100;
    TrimRig r;
    if (!r.init(kLive + 8, false)) SKIP("io_uring or process_madvise unavailable");
    r.loop->idle_trim_budget_ns = 1;
    for (u32 i = 0; i < kLive; i++) REQUIRE(stage_idle(r, 100000 + static_cast<i32>(i)) != nullptr);
    for (u32 t = 1; t <= 55; t++) {
        const TickDelta d = tick_delta(r);
        CHECK_EQ(d.examined,
                 t < kMinIdleTicks || t >= kMinIdleTicks + IoUringEventLoop::kIdleTrimAgeWindow
                     ? 0u
                     : 1u);
        CHECK_LE(d.trimmed, 1u);
    }
    CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(IoUringEventLoop::kIdleTrimAgeWindow));
}

TEST(iouring_idle_trim, capacity_does_not_change_when_or_what_the_sweep_touches) {
    constexpr u32 kBigCap = 100000;
    constexpr u32 kSmallCap = 64;
    constexpr u32 kLive = 10;
    u32 trim_tick[2] = {0, 0};
    const u32 caps[2] = {kSmallCap, kBigCap};
    for (u32 v = 0; v < 2; v++) {
        TrimRig r;
        if (!r.init(caps[v], false)) SKIP("io_uring or process_madvise unavailable");
        for (u32 i = 0; i < kLive; i++) REQUIRE(stage_idle(r, 100000 + static_cast<i32>(i)));
        // Bytes of never-allocated slots must be neither read (counted) nor written.
        const u32 kWatch = 32;
        // alloc_conn hands out ids in ascending order, so the slots past the
        // initialised prefix stay untouched.
        Connection* watch = &r.loop->conns[r.loop->slots_initialized];
        u8 snapshot[kWatch * sizeof(Connection)];
        memcpy(snapshot, static_cast<void*>(watch), sizeof(snapshot));
        for (u32 t = 1; t <= 30; t++) {
            r.tick();
            if (trim_tick[v] == 0 && r.loop->idle_trim_conns == kLive) trim_tick[v] = t;
        }
        CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(kLive));
        // Only the live aged connections were ever examined.
        CHECK_EQ(r.loop->idle_trim_examined, static_cast<u64>(kLive));
        CHECK_EQ(memcmp(snapshot, static_cast<void*>(watch), sizeof(snapshot)), 0);
    }
    CHECK_EQ(trim_tick[0], kMinIdleTicks);
    CHECK_EQ(trim_tick[1], trim_tick[0]);
}

TEST(iouring_idle_trim, rearm_gives_a_busy_connection_a_fresh_examination) {
    // Ineligible when its list is visited (a send still in flight), then idle: the
    // examination is not repeated under the same arming, but the completion that
    // ends the send re-arms the timer, and the new arming is examined at its own
    // age 5 — well inside the window.
    TrimRig r;
    if (!r.init(8, false)) SKIP("io_uring or process_madvise unavailable");
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    c->send_armed = true;
    for (u32 i = 0; i < 8; i++) r.tick();  // ages 1..8: examined (busy) at age 5
    CHECK_EQ(r.loop->idle_trim_examined, 1u);
    CHECK_EQ(r.loop->idle_trim_conns, 0u);
    c->send_armed = false;
    for (u32 i = 0; i < 10; i++) r.tick();  // same arming: not examined again
    CHECK_EQ(r.loop->idle_trim_examined, 1u);
    CHECK_EQ(r.loop->idle_trim_conns, 0u);
    r.loop->timer.refresh(c, r.loop->keepalive_timeout);  // the completion event
    for (u32 i = 0; i < kMinIdleTicks - 1; i++) r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, 0u);
    r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, 1u);
    CHECK_EQ(r.loop->idle_trim_examined, 2u);
}

TEST(iouring_idle_trim, stalled_loop_ticking_several_times_at_once_still_trims) {
    TrimRig r;
    if (!r.init(8, false)) SKIP("io_uring or process_madvise unavailable");
    Connection* a = stage_idle(r, 100000);  // armed now
    REQUIRE(a != nullptr);
    r.tick(3);  // a is 3 ticks old: too young
    CHECK_EQ(r.loop->idle_trim_examined, 0u);
    Connection* b = stage_idle(r, 100001);  // armed 3 ticks later than a
    REQUIRE(b != nullptr);
    r.tick(9);  // stall: a is 12, b is 9 old — both inside the window in one go
    CHECK_EQ(r.loop->idle_trim_conns, 2u);
    CHECK_EQ(resident_pages(a->recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(b->send_slice, SlicePool::kSliceSize), 0u);
    r.tick(20);
    CHECK_EQ(r.loop->idle_trim_examined, 2u);
}

TEST(iouring_idle_trim, wheel_cursor_wraps_and_each_idle_period_trims_once) {
    TrimRig r;
    if (!r.init(8, false)) SKIP("io_uring or process_madvise unavailable");
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    for (u32 period = 1; period <= 6; period++) {  // 6 x 40 ticks: several wheel laps
        for (u32 t = 0; t < 40; t++) r.tick();
        CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(period));
        CHECK_EQ(r.loop->idle_trim_madvise, 2ull * period);
        c->recv_slice[0] = 1;  // dirty again, as a served request would
        c->send_slice[0] = 1;
        r.loop->timer.refresh(c, r.loop->keepalive_timeout);  // ...and re-arm
    }
    CHECK_GT(r.loop->timer.cursor, 2 * TimerWheel::kSlots);
}

TEST(iouring_idle_trim, unusable_timeouts_make_the_sweep_a_no_op_and_small_ones_clip_the_ages) {
    TrimRig r;
    if (!r.init(8, false)) SKIP("io_uring or process_madvise unavailable");
    auto& loop = *r.loop;
    // Timeouts that leave no age >= the minimum (or would wrap the wheel): no work,
    // and nothing may be examined or trimmed.
    const u32 unusable[] = {0, 1, kMinIdleTicks, TimerWheel::kSlots, 1000};
    for (u32 v : unusable) {
        loop.keepalive_timeout = v;
        loop.upstream_timeout = v;
        Connection* c = stage_idle(r, 100000);
        REQUIRE(c != nullptr);
        for (u32 t = 0; t < 8; t++) loop.sweep_idle_trim();
        CHECK_EQ(loop.idle_trim_examined, 0u);
        loop.timer.remove(c);
        c->fd = -1;
        loop.free_conn(*c);
    }
    // A timeout only a little above the minimum: the one usable age is honoured.
    loop.keepalive_timeout = kMinIdleTicks + 2;
    loop.upstream_timeout = loop.keepalive_timeout;
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    for (u32 t = 0; t < kMinIdleTicks + 1; t++) r.tick();
    CHECK_EQ(loop.idle_trim_conns, 1u);
    loop.timer.remove(c);
    c->fd = -1;
    loop.free_conn(*c);
}

TEST(iouring_idle_trim, discard_failure_does_not_mark_or_count_the_connection) {
    TrimRig r;
    if (!r.init(4, false)) SKIP("io_uring or process_madvise unavailable");
    auto& loop = *r.loop;
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    // Rebind both buffers to memory the pool does not own: eligible (the binding is
    // consistent) but discard_bound() refuses every slice.
    alignas(4096) static u8 foreign[2][SlicePool::kSliceSize];
    u8* const real_recv = c->recv_slice;
    u8* const real_send = c->send_slice;
    c->recv_slice = foreign[0];
    c->send_slice = foreign[1];
    c->recv_buf.bind(foreign[0], SlicePool::kSliceSize);
    c->send_buf.bind(foreign[1], SlicePool::kSliceSize);
    REQUIRE(loop.idle_trim_eligible(*c));
    for (u32 t = 0; t < 8; t++) r.tick();
    CHECK_EQ(loop.idle_trim_examined, 1u);
    CHECK_EQ(loop.idle_trim_madvise, 0u);
    CHECK_EQ(loop.idle_trim_conns, 0u);  // not counted as trimmed
    c->recv_slice = real_recv;
    c->send_slice = real_send;
    c->recv_buf.bind(real_recv, SlicePool::kSliceSize);
    c->send_buf.bind(real_send, SlicePool::kSliceSize);
}

TEST(iouring_idle_trim, rotation_keeps_expiry_refresh_and_remove_working) {
    TrimRig r;
    if (!r.init(8, true)) SKIP("io_uring or process_madvise unavailable");
    REQUIRE(add_routes(r));
    i32 cli[4];
    std::string resp;
    for (u32 i = 0; i < 4; i++) {
        cli[i] = r.connect_client();
        REQUIRE_GE(cli[i], 0);
        REQUIRE(r.exchange(cli[i], kReqA, resp));
    }
    auto live = [&] {
        u32 n = 0;
        for (u32 i = 0; i < r.loop->slots_initialized; i++) n += r.loop->conns[i].fd >= 0;
        return n;
    };
    // All four were armed at the same cursor, so they share one wheel list.
    REQUIRE_EQ(live(), 4u);
    const u32 c0 = r.loop->timer.cursor;
    for (u32 t = 0; t < 8; t++) r.tick();  // rotates and trims all four
    CHECK_EQ(r.loop->idle_trim_conns, 4u);

    // Client 0 sends a request on its rotated node (timer.refresh), client 2 hangs
    // up (timer.remove through close_conn); 1 and 3 keep their original deadline.
    REQUIRE(r.exchange(cli[0], kReqA, resp));
    const u32 c0_refresh = r.loop->timer.cursor;
    ::close(cli[2]);
    REQUIRE(r.pump([&] { return live() == 3u; }));
    // 60 s keep-alive: alive through tick c0+59, expired by the tick that pops c0+60.
    while (r.loop->timer.cursor < c0 + r.loop->keepalive_timeout) {
        r.tick();
        CHECK_EQ(live(), 3u);
    }
    r.tick();  // pops list c0 + 60
    REQUIRE(r.pump([&] { return live() == 1u; }));
    // The refreshed connection expires on its own, later deadline, not before.
    while (r.loop->timer.cursor < c0_refresh + r.loop->keepalive_timeout) {
        r.tick();
        CHECK_EQ(live(), 1u);
    }
    r.tick();
    REQUIRE(r.pump([&] { return live() == 0u; }));
    for (u32 i = 0; i < 4; i++) ::close(cli[i]);
}

TEST(iouring_idle_trim, every_non_whitelisted_state_is_ineligible) {
    TrimRig r;
    if (!r.init(4, false)) SKIP("io_uring or process_madvise unavailable");
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    auto& loop = *r.loop;
    CHECK(loop.idle_trim_eligible(*c));
    static const u8 kByte = 0;

    struct Case {
        const char* name;
        void (*apply)(IoUringEventLoop&, Connection&);
        void (*undo)(IoUringEventLoop&, Connection&);
    };
    const Case cases[] = {
        {"closed", [](auto&, auto& c) { c.fd = -1; }, [](auto&, auto& c) { c.fd = 100000; }},
        {"proxying",
         [](auto&, auto& c) { c.state = ConnState::Proxying; },
         [](auto&, auto& c) { c.state = ConnState::ReadingHeader; }},
        {"sending",
         [](auto&, auto& c) { c.state = ConnState::Sending; },
         [](auto&, auto& c) { c.state = ConnState::ReadingHeader; }},
        {"recv cb other",
         [](auto&, auto& c) { c.on_recv = nullptr; },
         [](auto&, auto& c) { c.on_recv = &on_header_received<IoUringEventLoop>; }},
        {"send cb",
         [](auto&, auto& c) { c.on_send = &on_response_sent<IoUringEventLoop>; },
         [](auto&, auto& c) { c.on_send = nullptr; }},
        {"h2",
         [](auto&, auto& c) { c.protocol = ConnProtocol::Http2; },
         [](auto&, auto& c) { c.protocol = ConnProtocol::Http11; }},
        {"tls",
         [](auto&, auto& c) { c.tls_active = true; },
         [](auto&, auto& c) { c.tls_active = false; }},
        {"tls mid-handshake",
         [](auto&, auto& c) { c.tls_in_slice = const_cast<u8*>(&kByte); },
         [](auto&, auto& c) { c.tls_in_slice = nullptr; }},
        {"ws tunnel",
         [](auto&, auto& c) { c.is_ws_tunnel = true; },
         [](auto&, auto& c) { c.is_ws_tunnel = false; }},
        {"ws terminate",
         [](auto&, auto& c) { c.is_ws_terminate = true; },
         [](auto&, auto& c) { c.is_ws_terminate = false; }},
        {"partial request",
         [](auto&, auto& c) { c.recv_buf.write(&kByte, 1); },
         [](auto&, auto& c) { c.recv_buf.reset(); }},
        {"pipeline stash",
         [](auto&, auto& c) { c.pipeline_stash_len = 5; },
         [](auto&, auto& c) { c.pipeline_stash_len = 0; }},
        {"retry snapshot",
         [](auto&, auto& c) { c.retry_req_send_len = 5; },
         [](auto&, auto& c) { c.retry_req_send_len = 0; }},
        {"pipeline depth",
         [](auto&, auto& c) { c.pipeline_depth = 1; },
         [](auto&, auto& c) { c.pipeline_depth = 0; }},
        {"send in flight",
         [](auto&, auto& c) { c.send_armed = true; },
         [](auto&, auto& c) { c.send_armed = false; }},
        {"backend send pending",
         [](auto& l, auto& c) { l.backend.send_state[c.id].remaining = 9; },
         [](auto& l, auto& c) { l.backend.send_state[c.id].remaining = 0; }},
        {"local body",
         [](auto&, auto& c) { c.local_body_remaining = 9; },
         [](auto&, auto& c) { c.local_body_remaining = 0; }},
        {"recv not armed",
         [](auto&, auto& c) { c.recv_armed = false; },
         [](auto&, auto& c) { c.recv_armed = true; }},
        {"recv paused",
         [](auto&, auto& c) { c.recv_paused_for_send = true; },
         [](auto&, auto& c) { c.recv_paused_for_send = false; }},
        {"request in flight",
         [](auto&, auto& c) { c.req_start_us = 1; },
         [](auto&, auto& c) { c.req_start_us = 0; }},
        {"epoch held",
         [](auto&, auto& c) { c.epoch_held = true; },
         [](auto&, auto& c) { c.epoch_held = false; }},
        {"pending handler",
         [](auto&, auto& c) { c.pending_handler_fn = &waiting_handler; },
         [](auto&, auto& c) { c.pending_handler_fn = nullptr; }},
        {"yield armed",
         [](auto&, auto& c) { c.yield_armed = true; },
         [](auto&, auto& c) { c.yield_armed = false; }},
        {"throttled",
         [](auto&, auto& c) { c.throttle_paused = true; },
         [](auto&, auto& c) { c.throttle_paused = false; }},
        {"upstream fd",
         [](auto&, auto& c) { c.upstream_fd = 7; },
         [](auto&, auto& c) { c.upstream_fd = -1; }},
        {"upstream recv armed",
         [](auto&, auto& c) { c.upstream_recv_armed = true; },
         [](auto&, auto& c) { c.upstream_recv_armed = false; }},
        {"upstream send armed",
         [](auto&, auto& c) { c.upstream_send_armed = true; },
         [](auto&, auto& c) { c.upstream_send_armed = false; }},
        {"upstream recv paused",
         [](auto&, auto& c) { c.upstream_recv_paused_for_send = true; },
         [](auto&, auto& c) { c.upstream_recv_paused_for_send = false; }},
        {"upstream direct recv",
         [](auto&, auto& c) { c.upstream_recv_direct_armed = true; },
         [](auto&, auto& c) { c.upstream_recv_direct_armed = false; }},
        {"idle-return fd",
         [](auto&, auto& c) { c.idle_return_fd = 7; },
         [](auto&, auto& c) { c.idle_return_fd = -1; }},
        // Neutrality checks shared with submit_staged_local_response_impl: an upstream
        // send can outlive upstream_send_armed, so its ledgers must veto the trim.
        {"upstream send in backend",
         [](auto& l, auto& c) { l.backend.upstream_send_state[c.id].remaining = 9; },
         [](auto& l, auto& c) { l.backend.upstream_send_state[c.id].remaining = 0; }},
        {"unaccounted in-flight op",
         [](auto&, auto& c) { c.pending_ops = 2; },
         [](auto&, auto& c) { c.pending_ops = 1; }},
        {"upstream request incomplete",
         [](auto&, auto& c) { c.upstream_request_incomplete = true; },
         [](auto&, auto& c) { c.upstream_request_incomplete = false; }},
        {"response mutations snapshotted",
         [](auto&, auto& c) { c.response_mutations_snapshotted = true; },
         [](auto&, auto& c) { c.response_mutations_snapshotted = false; }},
        {"response-read deadline owner",
         [](auto&, auto& c) { c.response_read_deadline_send_close_generation = 1; },
         [](auto&, auto& c) { c.response_read_deadline_send_close_generation = 0; }},
        {"backend failed",
         [](auto& l, auto&) { l.backend.fatal_error.store(EPROTO); },
         [](auto& l, auto&) { l.backend.fatal_error.store(0); }},
    };
    for (const Case& k : cases) {
        k.apply(loop, *c);
        if (loop.idle_trim_eligible(*c)) {
            std::cerr << "eligible despite: " << k.name << "\n";
            CHECK(false);
        }
        k.undo(loop, *c);
        CHECK(loop.idle_trim_eligible(*c));
    }

    {
        auto view = c->recv_buf.release();  // a parsed-request view is live
        CHECK(!loop.idle_trim_eligible(*c));
    }
    CHECK(loop.idle_trim_eligible(*c));
}

TEST(iouring_idle_trim, upstream_recv_slice_is_trimmed_only_when_quiet) {
    TrimRig r;
    if (!r.init(4, false)) SKIP("io_uring or process_madvise unavailable");
    auto& loop = *r.loop;
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    u8* up = loop.pool.alloc();
    REQUIRE(up != nullptr);
    c->upstream_recv_slice = up;
    c->upstream_recv_buf.bind(up, SlicePool::kSliceSize);
    up[0] = 1;
    static const u8 kByte = 0;
    // One idle period: re-arm (as the last request event would), then age past 5.
    auto run_period = [&] {
        loop.timer.refresh(c, loop.keepalive_timeout);
        for (u32 i = 0; i < 8; i++) r.tick();
    };

    // Buffered upstream bytes: client slices still trim, the upstream slice is left alone.
    REQUIRE_EQ(c->upstream_recv_buf.write(&kByte, 1), 1u);
    run_period();
    CHECK_EQ(loop.idle_trim_conns, 1u);
    CHECK_EQ(loop.idle_trim_madvise, 2u);
    CHECK_EQ(resident_pages(up, SlicePool::kSliceSize), 1u);

    // Quiet upstream side: a later idle period trims it too.
    c->upstream_recv_buf.reset();
    run_period();
    CHECK_EQ(loop.idle_trim_conns, 2u);
    CHECK_EQ(loop.idle_trim_madvise, 5u);  // 2 + (recv, send, upstream)
    CHECK_EQ(resident_pages(up, SlicePool::kSliceSize), 0u);

    // upstream_send_len (a client send sourced from the upstream slice) is left
    // stale after proxied responses: it must not stop the client slices from being
    // trimmed, but it does keep the upstream slice itself.
    up[0] = 1;
    c->upstream_send_len = 266;
    run_period();
    CHECK_EQ(loop.idle_trim_conns, 3u);
    CHECK_EQ(loop.idle_trim_madvise, 7u);  // + (recv, send)
    CHECK_EQ(resident_pages(up, SlicePool::kSliceSize), 1u);
    c->upstream_send_len = 0;

    // An outstanding direct upstream recv (kernel writes the slice) blocks everything.
    up[0] = 1;
    c->upstream_recv_direct_armed = true;
    run_period();
    CHECK_EQ(loop.idle_trim_conns, 3u);
    CHECK_EQ(resident_pages(up, SlicePool::kSliceSize), 1u);
    c->upstream_recv_direct_armed = false;
    c->upstream_recv_buf.bind(nullptr, 0);
    c->upstream_recv_slice = nullptr;
    loop.pool.free(up);
}

TEST(iouring_idle_trim, non_empty_send_buffer_keeps_its_slice_untouched) {
    // A proxied request on a reused upstream socket leaves its retry-snapshot bytes in
    // send_buf (length kept, retry_req_send_len cleared) after completing. Those bytes
    // are never read again, but the trim does not assume that: it leaves that slice
    // alone and still returns the receive slice.
    TrimRig r;
    if (!r.init(4, false)) SKIP("io_uring or process_madvise unavailable");
    auto& loop = *r.loop;
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    static const u8 kStale[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    REQUIRE_EQ(c->send_buf.write(kStale, sizeof(kStale) - 1), sizeof(kStale) - 1);
    for (u32 i = 0; i < 12; i++) r.tick();
    CHECK_EQ(loop.idle_trim_conns, 1u);
    CHECK_EQ(loop.idle_trim_madvise, 1u);  // recv slice only
    CHECK_EQ(resident_pages(c->recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(c->send_slice, SlicePool::kSliceSize), 1u);
    CHECK_EQ(memcmp(c->send_buf.data(), kStale, sizeof(kStale) - 1), 0);
}

// ---------------------------------------------------------------------------
// Arming, batching, fallback, capability probe
// ---------------------------------------------------------------------------

namespace {

// stage_idle plus a bound upstream receive slice, so the connection contributes
// three ranges to the batch. The slice is owned by the loop's pool (released with it).
Connection* stage_idle_with_upstream(TrimRig& r, i32 fake_fd) {
    Connection* c = stage_idle(r, fake_fd);
    if (c == nullptr) return nullptr;
    u8* up = r.loop->pool.alloc();
    if (up == nullptr) return nullptr;
    c->upstream_recv_slice = up;
    c->upstream_recv_buf.bind(up, SlicePool::kSliceSize);
    up[0] = 1;
    return c;
}

// Ticks until the first trimming tick has happened (idle age 5), returning how many
// connections that single tick trimmed.
u64 tick_to_first_trim(TrimRig& r) {
    for (u32 t = 0; t < kMinIdleTicks + 2; t++) {
        const TickDelta d = tick_delta(r);
        if (d.examined != 0) return d.trimmed;
    }
    return 0;
}

}  // namespace

TEST(iouring_idle_trim, every_arm_clears_the_examined_mark_and_connection_stays_same_size) {
    TrimRig r;
    if (!r.init(4, false)) SKIP("io_uring or process_madvise unavailable");
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    CHECK(!c->idle_trim_examined);
    for (u32 i = 0; i < kMinIdleTicks + 1; i++) r.tick();
    CHECK(c->idle_trim_examined);  // examined once it aged
    r.loop->timer.refresh(c, 30);  // a re-arm with a different timeout
    CHECK(!c->idle_trim_examined);
    for (u32 i = 0; i < kMinIdleTicks + 1; i++) r.tick();
    CHECK(c->idle_trim_examined);
    r.loop->timer.remove(c);
    r.loop->timer.add(c, r.loop->keepalive_timeout);  // a bare add
    CHECK(!c->idle_trim_examined);
    // ChainDirectRecvOwner is a 32-byte immutable CQE target snapshot. Keep the
    // slot-size assertion explicit so future owner fields cannot grow the hot
    // connection layout unnoticed.
    CHECK_EQ(sizeof(Connection), 3648u);
}

TEST(iouring_idle_trim,
     rearm_with_a_different_timeout_onto_the_same_expiry_does_not_hide_later_nodes) {
    // A connection examined under keep-alive (60 s) and then re-armed with a 30 s
    // timeout 30 ticks later lands in the same wheel list again (same absolute
    // expiry) at its head. It must not stop later walks of that list from reaching
    // the nodes behind it that were never examined.
    constexpr u32 kLive = 100;
    TrimRig r;
    if (!r.init(kLive + 8, false)) SKIP("io_uring or process_madvise unavailable");
    r.loop->idle_trim_budget_ns = 1;  // one node per tick
    for (u32 i = 0; i < kLive; i++) REQUIRE(stage_idle(r, 100000 + static_cast<i32>(i)) != nullptr);
    for (u32 t = 0; t < 30; t++) r.tick();
    const u64 before = r.loop->idle_trim_examined;
    CHECK_EQ(before, 30u - kMinIdleTicks + 1);  // ticks 5..30, one node each
    Connection* examined = nullptr;
    for (u32 i = 0; i < r.loop->slots_initialized && examined == nullptr; i++)
        if (r.loop->conns[i].fd >= 0 && r.loop->conns[i].idle_trim_examined)
            examined = &r.loop->conns[i];
    REQUIRE(examined != nullptr);
    r.loop->timer.refresh(examined, 30);  // expiry = cursor + 30 = the same list
    for (u32 t = 0; t < 20; t++) r.tick();
    // The walk kept examining: window ages 5..44, one node per tick.
    CHECK_EQ(r.loop->idle_trim_examined, 40u);
    CHECK(examined->idle_trim_examined);  // and the re-armed node itself was re-examined
}

TEST(iouring_idle_trim, batched_tick_advises_everything_in_one_call_up_to_the_chunk_limit) {
    static_assert(IoUringEventLoop::kIdleTrimMaxRanges > IoUringEventLoop::kIdleTrimIovChunk,
                  "the cap must be able to exceed one process_madvise call");
    constexpr u32 kChunk = IoUringEventLoop::kIdleTrimIovChunk;
    // Exactly one chunk: kChunk / 2 connections with two ranges each.
    {
        constexpr u32 kConns = kChunk / 2;
        static_assert(kConns <= IoUringEventLoop::kIdleTrimMaxTrims);
        TrimRig r;
        if (!r.init(kConns + 8, false)) SKIP("io_uring or process_madvise unavailable");
        r.loop->idle_trim_budget_ns = ~0ull >> 1;
        Connection* first = nullptr;
        Connection* lastc = nullptr;
        for (u32 i = 0; i < kConns; i++) {
            lastc = stage_idle(r, 100000 + static_cast<i32>(i));
            REQUIRE(lastc != nullptr);
            if (first == nullptr) first = lastc;
        }
        CHECK_EQ(tick_to_first_trim(r), static_cast<u64>(kConns));
        CHECK_EQ(r.loop->idle_trim_batches, 1u);
        CHECK_EQ(r.loop->idle_trim_fallback, 0u);
        CHECK_EQ(r.loop->idle_trim_madvise, static_cast<u64>(kChunk));
        CHECK_EQ(resident_pages(first->recv_slice, SlicePool::kSliceSize), 0u);
        CHECK_EQ(resident_pages(lastc->send_slice, SlicePool::kSliceSize), 0u);
    }
    // The cap: every connection contributes three ranges, so the largest batch is
    // kIdleTrimMaxRanges = one full chunk plus a remainder, in two calls.
    {
        constexpr u32 kConns = IoUringEventLoop::kIdleTrimMaxTrims + 100;
        TrimRig r;
        if (!r.init(kConns + 8, false)) SKIP("io_uring or process_madvise unavailable");
        r.loop->idle_trim_budget_ns = ~0ull >> 1;
        Connection* c0 = nullptr;
        Connection* clast = nullptr;
        for (u32 i = 0; i < kConns; i++) {
            Connection* c = stage_idle_with_upstream(r, 100000 + static_cast<i32>(i));
            REQUIRE(c != nullptr);
            if (c0 == nullptr) c0 = c;
            clast = c;
        }
        CHECK_EQ(tick_to_first_trim(r), static_cast<u64>(IoUringEventLoop::kIdleTrimMaxTrims));
        CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(IoUringEventLoop::kIdleTrimMaxTrims));
        CHECK_EQ(r.loop->idle_trim_madvise, static_cast<u64>(IoUringEventLoop::kIdleTrimMaxRanges));
        CHECK_EQ(r.loop->idle_trim_batches,
                 (IoUringEventLoop::kIdleTrimMaxRanges + kChunk - 1) / kChunk);
        CHECK_EQ(r.loop->idle_trim_fallback, 0u);
        // Examined-but-not-trimmed nodes beyond the cap wait for the next tick, where
        // the remainder is trimmed too.
        r.tick();
        CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(kConns));
        // Pages of both ends of the array (first and last chunk) are really gone.
        CHECK_EQ(resident_pages(c0->recv_slice, SlicePool::kSliceSize), 0u);
        CHECK_EQ(resident_pages(c0->upstream_recv_slice, SlicePool::kSliceSize), 0u);
        CHECK_EQ(resident_pages(clast->send_slice, SlicePool::kSliceSize), 0u);
        CHECK_EQ(resident_pages(clast->upstream_recv_slice, SlicePool::kSliceSize), 0u);
    }
}

TEST(iouring_idle_trim, short_batch_return_falls_back_to_per_slice_for_the_remainder) {
    InjectGuard guard;
    constexpr u32 kConns = 300;                        // 600 ranges: one chunk
    for (i64 allowed : {i64{100}, i64{1}, i64{-2}}) {  // short at 100, after 1, soft failure
        TrimRig r;
        if (!r.init(kConns + 8, false)) SKIP("io_uring or process_madvise unavailable");
        r.loop->idle_trim_budget_ns = ~0ull >> 1;
        Connection* first = nullptr;
        Connection* lastc = nullptr;
        for (u32 i = 0; i < kConns; i++) {
            lastc = stage_idle(r, 100000 + static_cast<i32>(i));
            REQUIRE(lastc != nullptr);
            if (first == nullptr) first = lastc;
        }
        g_batch_allowed = allowed;
        CHECK_EQ(tick_to_first_trim(r), static_cast<u64>(kConns));
        // Everything was advised, the tail per slice; every connection counted once.
        CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(kConns));
        CHECK_EQ(r.loop->idle_trim_madvise, 2ull * kConns);
        CHECK_EQ(r.loop->idle_trim_fallback,
                 2ull * kConns - static_cast<u64>(allowed < 0 ? 0 : allowed));
        CHECK_EQ(r.loop->idle_trim_batches, 1u);  // attempted calls, injected or real
        CHECK(r.loop->idle_trim_pidfd >= 0);      // a soft failure keeps the feature on
        CHECK_EQ(resident_pages(first->recv_slice, SlicePool::kSliceSize), 0u);
        CHECK_EQ(resident_pages(lastc->send_slice, SlicePool::kSliceSize), 0u);
        g_batch_allowed = -1;
    }
}

TEST(iouring_idle_trim, short_return_inside_the_second_chunk_advises_the_tail_per_slice) {
    InjectGuard guard;
    constexpr u32 kConns = IoUringEventLoop::kIdleTrimMaxTrims;
    constexpr u32 kChunk = IoUringEventLoop::kIdleTrimIovChunk;
    constexpr u32 kTotal = kConns * IoUringEventLoop::kIdleTrimSlicesPerConn;
    static_assert(kTotal > kChunk + 10);
    TrimRig r;
    if (!r.init(kConns + 8, false)) SKIP("io_uring or process_madvise unavailable");
    r.loop->idle_trim_budget_ns = ~0ull >> 1;
    Connection* c0 = nullptr;
    Connection* clast = nullptr;
    for (u32 i = 0; i < kConns; i++) {
        clast = stage_idle_with_upstream(r, 100000 + static_cast<i32>(i));
        REQUIRE(clast != nullptr);
        if (c0 == nullptr) c0 = clast;
    }
    // Only 10 ranges of every chunk are accepted: the first chunk is short too, and
    // the second chunk's remainder starts at range kChunk + 10.
    g_batch_allowed = 10;
    CHECK_EQ(tick_to_first_trim(r), static_cast<u64>(kConns));
    CHECK_EQ(r.loop->idle_trim_batches, 2u);
    CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(kConns));
    CHECK_EQ(r.loop->idle_trim_madvise, static_cast<u64>(kTotal));
    CHECK_EQ(r.loop->idle_trim_fallback, static_cast<u64>(kTotal - 20));
    // The last connection's ranges are in the second chunk's per-slice remainder.
    CHECK_EQ(resident_pages(clast->recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(clast->send_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(clast->upstream_recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(c0->recv_slice, SlicePool::kSliceSize), 0u);
}

TEST(iouring_idle_trim, hard_batch_failure_finishes_the_tick_then_turns_the_feature_off) {
    InjectGuard guard;
    TrimRig r;
    constexpr u32 kConns = 8;
    if (!r.init(kConns + 8, false)) SKIP("io_uring or process_madvise unavailable");
    auto& loop = *r.loop;
    Connection* c[kConns];
    for (u32 i = 0; i < kConns; i++) {
        c[i] = stage_idle(r, 100000 + static_cast<i32>(i));
        REQUIRE(c[i] != nullptr);
    }
    g_batch_allowed = 0;  // process_madvise fails hard (EPERM)
    tick_to_first_trim(r);
    // That tick's queue was still released, per slice...
    CHECK_EQ(loop.idle_trim_conns, static_cast<u64>(kConns));
    CHECK_EQ(loop.idle_trim_madvise, 2ull * kConns);
    CHECK_EQ(loop.idle_trim_fallback, 2ull * kConns);
    CHECK_EQ(resident_pages(c[3]->recv_slice, SlicePool::kSliceSize), 0u);
    // ...and the feature is now off for good: nothing is examined or written again.
    CHECK_EQ(loop.idle_trim_pidfd, -1);
    g_batch_allowed = -1;
    const u64 batches = loop.idle_trim_batches;
    const u64 examined = loop.idle_trim_examined;
    loop.timer.refresh(c[0], loop.keepalive_timeout);
    c[0]->recv_slice[0] = 1;
    for (u32 t = 0; t < 12; t++) r.tick();
    CHECK_EQ(loop.idle_trim_examined, examined);
    CHECK_EQ(loop.idle_trim_batches, batches);
    CHECK(!c[0]->idle_trim_examined);
    CHECK_EQ(resident_pages(c[0]->recv_slice, SlicePool::kSliceSize), 1u);
    // A transient failure (EAGAIN) is retried on the next tick instead.
    TrimRig r2;
    if (!r2.init(kConns + 8, false)) SKIP("io_uring or process_madvise unavailable");
    Connection* d = stage_idle(r2, 100000);
    REQUIRE(d != nullptr);
    g_batch_allowed = -2;
    tick_to_first_trim(r2);
    CHECK(r2.loop->idle_trim_pidfd >= 0);
    g_batch_allowed = -1;
    r2.loop->timer.refresh(d, r2.loop->keepalive_timeout);
    d->recv_slice[0] = 1;
    const u64 b2 = r2.loop->idle_trim_batches;
    for (u32 t = 0; t < kMinIdleTicks + 1; t++) r2.tick();
    CHECK_EQ(r2.loop->idle_trim_batches, b2 + 1);
    CHECK_EQ(resident_pages(d->recv_slice, SlicePool::kSliceSize), 0u);
}

TEST(iouring_idle_trim, connection_counts_only_if_a_slice_was_really_advised) {
    InjectGuard guard;
    TrimRig r;
    constexpr u32 kConns = 6;
    if (!r.init(kConns + 8, false)) SKIP("io_uring or process_madvise unavailable");
    Connection* c[kConns];
    for (u32 i = 0; i < kConns; i++) {
        c[i] = stage_idle(r, 100000 + static_cast<i32>(i));
        REQUIRE(c[i] != nullptr);
    }
    // The batch fails softly; connection 1 loses both slices to a failing per-slice
    // madvise (not counted, its pages stay), connection 4 only its send slice (still
    // counted: one of its slices was advised).
    g_batch_allowed = -2;
    g_fail_slice_a = c[1]->recv_slice;
    g_fail_slice_b = c[1]->send_slice;
    tick_to_first_trim(r);
    CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(kConns - 1));
    CHECK_EQ(r.loop->idle_trim_madvise, 2ull * (kConns - 1));
    CHECK_EQ(resident_pages(c[1]->recv_slice, SlicePool::kSliceSize), 1u);
    CHECK_EQ(resident_pages(c[1]->send_slice, SlicePool::kSliceSize), 1u);
    CHECK_EQ(resident_pages(c[0]->recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(c[5]->send_slice, SlicePool::kSliceSize), 0u);
    g_fail_slice_a = c[4]->send_slice;
    g_fail_slice_b = nullptr;
    r.loop->timer.refresh(c[4], r.loop->keepalive_timeout);  // a fresh idle period
    c[4]->recv_slice[0] = 1;
    c[4]->send_slice[0] = 1;
    const u64 conns_before = r.loop->idle_trim_conns;
    const u64 madvise_before = r.loop->idle_trim_madvise;
    for (u32 t = 0; t < kMinIdleTicks + 1; t++) r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, conns_before + 1);
    CHECK_EQ(r.loop->idle_trim_madvise, madvise_before + 1);
    CHECK_EQ(resident_pages(c[4]->recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(c[4]->send_slice, SlicePool::kSliceSize), 1u);
}

TEST(iouring_idle_trim, probe_failure_turns_the_feature_off_entirely) {
    InjectGuard guard;
    for (i64 point : {i64{detail::IdleTrimPidfdOpen}, i64{detail::IdleTrimProbeAdvise}}) {
        TrimRig r;
        r.need_trim = false;
        if (!r.init(16, false)) SKIP("io_uring unavailable");
        auto& loop = *r.loop;
        g_fail_point = point;
        CHECK(!loop.probe_idle_trim());
        CHECK_EQ(loop.idle_trim_pidfd, -1);  // no fd left open either
        Connection* c = stage_idle(r, 100000);
        REQUIRE(c != nullptr);
        const u32 cursor = loop.timer.cursor;
        for (u32 t = 0; t < 30; t++) r.tick();
        CHECK_EQ(loop.timer.cursor, cursor + 30);  // ticks still run
        CHECK_EQ(loop.idle_trim_examined, 0u);
        CHECK_EQ(loop.idle_trim_conns, 0u);
        CHECK_EQ(loop.idle_trim_madvise, 0u);
        CHECK_EQ(loop.idle_trim_batches, 0u);
        CHECK(!c->idle_trim_examined);  // no connection field was written
        CHECK_EQ(resident_pages(c->recv_slice, SlicePool::kSliceSize), 1u);
        CHECK_EQ(resident_pages(c->send_slice, SlicePool::kSliceSize), 1u);
        // The probe can succeed later (capability restored): the feature comes back.
        g_fail_point = -1;
        const bool can = loop.probe_idle_trim();
        CHECK_EQ(can, loop.idle_trim_pidfd >= 0);
        if (can) {
            loop.timer.refresh(c, loop.keepalive_timeout);
            for (u32 t = 0; t < kMinIdleTicks + 1; t++) r.tick();
            CHECK_EQ(loop.idle_trim_conns, 1u);
        }
    }
}

TEST(iouring_idle_trim, init_probes_once_and_shutdown_closes_the_pidfd) {
    TrimRig r;
    r.need_trim = false;
    if (!r.init(8, false)) SKIP("io_uring unavailable");
    if (r.loop->idle_trim_pidfd < 0) SKIP("process_madvise unavailable");
    const i32 fd = r.loop->idle_trim_pidfd;
    CHECK_GE(fcntl(fd, F_GETFD), 0);
    CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK(r.loop->probe_idle_trim());  // re-probing replaces the descriptor, no leak
    CHECK_GE(r.loop->idle_trim_pidfd, 0);
    const i32 fd2 = r.loop->idle_trim_pidfd;
    r.loop->shutdown();
    r.up = false;
    CHECK_EQ(r.loop->idle_trim_pidfd, -1);
    CHECK_EQ(fcntl(fd2, F_GETFD), -1);
    CHECK_EQ(errno, EBADF);
}

namespace {

constexpr char kUpstreamBody[] = "proxied-body-0123456789-abcdefghijklmnopqrstuvwxyz";

// Minimal keep-alive HTTP upstream on its own thread: answers every request with a
// fixed body and counts the requests it saw.
struct TestUpstream {
    i32 lfd = -1;
    u16 port = 0;
    u32 requests = 0;
    bool stop = false;
    std::string request_buffers[8];
    pthread_t thread{};
    bool started = false;

    static void* run(void* arg) {
        auto* u = static_cast<TestUpstream*>(arg);
        i32 conns[8];
        u32 n = 0;
        static const char kResp[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 50\r\nConnection: keep-alive\r\n\r\n";
        static_assert(sizeof(kUpstreamBody) - 1 == 50);
        while (!__atomic_load_n(&u->stop, __ATOMIC_ACQUIRE)) {
            pollfd pfds[9];
            pfds[0] = {u->lfd, POLLIN, 0};
            for (u32 i = 0; i < n; i++) pfds[1 + i] = {conns[i], POLLIN, 0};
            const u32 polled = n;
            if (poll(pfds, 1 + polled, 50) <= 0) continue;
            // Service the connections that were polled (their revents are valid),
            // newest index first so dropping one does not shift an unserviced one.
            for (u32 i = polled; i-- != 0;) {
                bool drop = false;
                if ((pfds[1 + i].revents & (POLLIN | POLLHUP)) != 0) {
                    char buf[4096];
                    const ssize_t got = recv(conns[i], buf, sizeof(buf), MSG_DONTWAIT);
                    if (got <= 0) {
                        drop = true;
                    } else {
                        u->request_buffers[i].append(buf, static_cast<size_t>(got));
                        for (;;) {
                            const size_t end = u->request_buffers[i].find("\r\n\r\n");
                            if (end == std::string::npos) break;
                            u->request_buffers[i].erase(0, end + 4);
                            __atomic_add_fetch(&u->requests, 1u, __ATOMIC_SEQ_CST);
                            send(conns[i], kResp, sizeof(kResp) - 1, MSG_NOSIGNAL);
                            send(conns[i], kUpstreamBody, sizeof(kUpstreamBody) - 1, MSG_NOSIGNAL);
                        }
                    }
                }
                if (drop) {
                    ::close(conns[i]);
                    const u32 last = --n;
                    conns[i] = conns[last];
                    u->request_buffers[i].swap(u->request_buffers[last]);
                    u->request_buffers[last].clear();
                }
            }
            if ((pfds[0].revents & POLLIN) != 0 && n < 8) {
                const i32 c = accept(u->lfd, nullptr, nullptr);
                if (c >= 0) {
                    u->request_buffers[n].clear();
                    conns[n++] = c;
                }
            }
        }
        for (u32 i = 0; i < n; i++) ::close(conns[i]);
        return nullptr;
    }

    bool start() {
        auto l = create_listen_socket(0);
        if (!l.has_value()) return false;
        lfd = l.value();
        port = get_port(lfd);
        started = pthread_create(&thread, nullptr, &run, this) == 0;
        return started;
    }

    ~TestUpstream() {
        __atomic_store_n(&stop, true, __ATOMIC_RELEASE);
        if (started) pthread_join(thread, nullptr);
        if (lfd >= 0) ::close(lfd);
    }
};

}  // namespace

TEST(iouring_idle_trim, proxied_connection_is_trimmed_and_serves_the_next_proxied_request) {
    TestUpstream up;
    REQUIRE(up.start());
    TrimRig r;
    if (!r.init(8, true)) SKIP("io_uring or process_madvise unavailable");
    REQUIRE(add_routes(r));
    auto id = r.cfg.add_upstream("b", 0x7F000001, up.port);
    REQUIRE(id.has_value());
    REQUIRE(r.cfg.add_proxy("/p", 0, id.value()));
    const char kReqProxy[] = "GET /p HTTP/1.1\r\nHost: x\r\n\r\n";
    const i32 cli = r.connect_client();
    REQUIRE_GE(cli, 0);
    std::string first;
    REQUIRE(r.exchange(cli, kReqProxy, first));
    CHECK(first.compare(0, 12, "HTTP/1.1 200") == 0);
    CHECK_EQ(first.substr(first.size() - (sizeof(kUpstreamBody) - 1)), std::string(kUpstreamBody));
    CHECK_EQ(__atomic_load_n(&up.requests, __ATOMIC_ACQUIRE), 1u);
    REQUIRE(r.wait_idle());
    Connection* c = r.live_conn();
    REQUIRE(c != nullptr);
    u8* const recv_slice = c->recv_slice;
    u8* const send_slice = c->send_slice;
    CHECK_GE(resident_pages(recv_slice, SlicePool::kSliceSize), 1u);
    for (u32 t = 0; t < 12 && r.loop->idle_trim_conns == 0; t++) r.tick();
    CHECK_EQ(r.loop->idle_trim_conns, 1u);
    CHECK_EQ(resident_pages(recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(send_slice, SlicePool::kSliceSize), 0u);
    CHECK(c->recv_slice == recv_slice && c->send_slice == send_slice);  // still bound
    // The next proxied request on the same connection is served byte-exact, and the
    // upstream saw exactly one more request.
    std::string second;
    REQUIRE(r.exchange(cli, kReqProxy, second));
    CHECK(second == first);
    CHECK_EQ(__atomic_load_n(&up.requests, __ATOMIC_ACQUIRE), 2u);
    ::close(cli);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
