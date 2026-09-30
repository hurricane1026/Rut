// Idle keep-alive buffer trim on the io_uring loop (IoUringEventLoop::sweep_idle_trim).
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

#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

using namespace rut;

namespace {

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
    const u32 pages = len / 4096;
    unsigned char vec[16];
    if (pages > sizeof(vec)) return 0;
    if (mincore(const_cast<u8*>(p), len, vec) != 0) return 0xffffffffu;
    u32 n = 0;
    for (u32 i = 0; i < pages; i++) n += vec[i] & 1u;
    return n;
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

    // capacity: slot count. server_sndbuf != 0 shrinks accepted sockets' send buffers.
    bool init(u32 capacity, bool listen_socket, u32 server_sndbuf = 0) {
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
        for (u32 attempt = 0; attempt < 40 && !inited; attempt++) {
            if (attempt != 0) {
                usleep(250 * 1000);
                loop->~IoUringEventLoop();
                loop = new (storage) IoUringEventLoop();
            }
            auto r = loop->init(0, lfd, 0, capacity);
            inited = r.has_value();
            if (!inited && r.error().code != ENOMEM) break;
        }
        if (!inited) return false;
        up = true;
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
                for (u32 i = 0; i < loop->connection_capacity; i++)
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
        for (u32 i = 0; i < loop->connection_capacity; i++)
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
// SlicePool::discard_bound
// ---------------------------------------------------------------------------

TEST(slice_pool_discard, returns_pages_of_a_bound_slice_and_keeps_it_bound) {
    SlicePool pool;
    REQUIRE(pool.init(512).has_value());
    u8* s = pool.alloc();
    REQUIRE(s != nullptr);
    __builtin_memset(s, 0x5a, SlicePool::kSliceSize);
    CHECK_EQ(resident_pages(s, SlicePool::kSliceSize), 4u);
    const u32 avail = pool.available();
    CHECK(pool.discard_bound(s));
    CHECK_EQ(resident_pages(s, SlicePool::kSliceSize), 0u);
    for (u32 i = 0; i < SlicePool::kSliceSize; i += 509) CHECK_EQ(s[i], 0u);
    CHECK_EQ(pool.available(), avail);  // still bound: free stack untouched
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
    CHECK(!pool.discard_bound(s + 16));  // not slice-aligned
    CHECK(!pool.discard_bound(nullptr));
    u8 local[8];
    CHECK(!pool.discard_bound(local));  // foreign
    pool.free(s);
    CHECK(!pool.discard_bound(s));  // free slice: not bound
    u8* bulk = pool.alloc_bulk();
    REQUIRE(bulk != nullptr);
    CHECK(!pool.discard_bound(bulk));
    pool.free(bulk);
    pool.destroy();
}

// ---------------------------------------------------------------------------
// Real loop: trim, reuse, activity, non-whitelisted states
// ---------------------------------------------------------------------------

TEST(iouring_idle_trim, idle_keepalive_trimmed_once_then_serves_next_request) {
    TrimRig r;
    if (!r.init(8, true)) SKIP("io_uring unavailable");
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
    CHECK_GE(ticks, IoUringEventLoop::kIdleTrimMinIdleTicks);
    CHECK_LE(ticks, IoUringEventLoop::kIdleTrimMinIdleTicks + 2);
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
    if (!r.init(8, true)) SKIP("io_uring unavailable");
    REQUIRE(add_routes(r));
    const i32 cli = r.connect_client();
    REQUIRE_GE(cli, 0);
    std::string resp;
    for (u32 i = 0; i < 4 * IoUringEventLoop::kIdleTrimMinIdleTicks; i++) {
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
    if (!r.init(8, true)) SKIP("io_uring unavailable");
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
    if (!r.init(8, true, 4096)) SKIP("io_uring unavailable");
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
    if (!r.init(8, true)) SKIP("io_uring unavailable");
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
// Synthetic connections: per-tick bounds and the eligibility table
// ---------------------------------------------------------------------------

namespace {

// Stage a slot as a plain idle keep-alive connection with dirty slice pages.
Connection* stage_idle(TrimRig& r, i32 fake_fd) {
    Connection* c = r.loop->alloc_conn();
    if (c == nullptr) return nullptr;
    c->fd = fake_fd;  // >= 100000: never a real descriptor, never closed
    c->state = ConnState::ReadingHeader;
    c->on_recv = &on_header_received<IoUringEventLoop>;
    c->recv_armed = true;
    c->recv_slice[0] = 1;
    c->send_slice[0] = 1;
    return c;
}

}  // namespace

TEST(iouring_idle_trim, sweep_respects_per_tick_slot_and_trim_bounds) {
    constexpr u32 kCap = 3000;
    constexpr u32 kLive = 2000;
    static_assert(kLive > IoUringEventLoop::kIdleTrimMaxPerTick);
    static_assert(kCap > IoUringEventLoop::kIdleTrimSlotsPerTick);
    TrimRig r;
    if (!r.init(kCap, false)) SKIP("io_uring unavailable");
    Connection* sample = nullptr;
    for (u32 i = 0; i < kLive; i++) {
        Connection* c = stage_idle(r, 100000 + static_cast<i32>(i));
        REQUIRE(c != nullptr);
        if (i == 0) sample = c;
    }
    CHECK_EQ(resident_pages(sample->recv_slice, SlicePool::kSliceSize), 1u);

    u64 max_trimmed_per_tick = 0;
    u32 max_advance = 0;
    u32 sweeps = 0;
    for (; sweeps < 400 && r.loop->idle_trim_conns < kLive; sweeps++) {
        const u64 before = r.loop->idle_trim_conns;
        const u32 cursor_before = r.loop->idle_trim_cursor;
        r.loop->sweep_idle_trim(1);
        const u64 delta = r.loop->idle_trim_conns - before;
        if (delta > max_trimmed_per_tick) max_trimmed_per_tick = delta;
        const u32 advance = (r.loop->idle_trim_cursor + kCap - cursor_before) % kCap;
        if (advance > max_advance) max_advance = advance;
        // Nothing is trimmed on a first sighting, only after the idle threshold.
        if (sweeps < IoUringEventLoop::kIdleTrimMinIdleTicks) CHECK_EQ(delta, 0u);
    }
    CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(kLive));
    CHECK_EQ(r.loop->idle_trim_madvise, 2ull * kLive);
    CHECK_LE(max_trimmed_per_tick, static_cast<u64>(IoUringEventLoop::kIdleTrimMaxPerTick));
    CHECK_EQ(max_trimmed_per_tick, static_cast<u64>(IoUringEventLoop::kIdleTrimMaxPerTick));
    CHECK_LE(max_advance, IoUringEventLoop::kIdleTrimSlotsPerTick);
    CHECK_GE(sweeps, kLive / IoUringEventLoop::kIdleTrimMaxPerTick);
    CHECK_EQ(resident_pages(sample->recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(sample->send_slice, SlicePool::kSliceSize), 0u);

    // Every connection was trimmed exactly once; further sweeps do nothing.
    for (u32 i = 0; i < 100; i++) r.loop->sweep_idle_trim(1);
    CHECK_EQ(r.loop->idle_trim_conns, static_cast<u64>(kLive));
    CHECK_EQ(r.loop->idle_trim_madvise, 2ull * kLive);
}

TEST(iouring_idle_trim, every_non_whitelisted_state_is_ineligible) {
    TrimRig r;
    if (!r.init(4, false)) SKIP("io_uring unavailable");
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

    // An ineligible sighting forgets the candidate mark: the idle period restarts.
    loop.sweep_idle_trim(1);
    CHECK_EQ(c->idle_trim_phase, IoUringEventLoop::kIdleTrimCandidate);
    c->send_armed = true;
    loop.sweep_idle_trim(1);
    CHECK_EQ(c->idle_trim_phase, IoUringEventLoop::kIdleTrimNone);
    c->send_armed = false;
    for (u32 i = 0; i < 4; i++) loop.sweep_idle_trim(1);
    CHECK_EQ(loop.idle_trim_conns, 0u);  // threshold measured from the restart
    for (u32 i = 0; i < 4; i++) loop.sweep_idle_trim(1);
    CHECK_EQ(loop.idle_trim_conns, 1u);
    // A completed request since the trim re-arms it for a new idle period.
    c->handler_gen++;
    for (u32 i = 0; i < 12; i++) loop.sweep_idle_trim(1);
    CHECK_EQ(loop.idle_trim_conns, 2u);
}

TEST(iouring_idle_trim, upstream_recv_slice_is_trimmed_only_when_quiet) {
    TrimRig r;
    if (!r.init(4, false)) SKIP("io_uring unavailable");
    auto& loop = *r.loop;
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    u8* up = loop.pool.alloc();
    REQUIRE(up != nullptr);
    c->upstream_recv_slice = up;
    c->upstream_recv_buf.bind(up, SlicePool::kSliceSize);
    up[0] = 1;
    static const u8 kByte = 0;
    auto run_to_trim = [&] {
        for (u32 i = 0; i < 12; i++) loop.sweep_idle_trim(1);
    };

    // Buffered upstream bytes: client slices still trim, the upstream slice is left alone.
    REQUIRE_EQ(c->upstream_recv_buf.write(&kByte, 1), 1u);
    run_to_trim();
    CHECK_EQ(loop.idle_trim_conns, 1u);
    CHECK_EQ(loop.idle_trim_madvise, 2u);
    CHECK_EQ(resident_pages(up, SlicePool::kSliceSize), 1u);

    // Quiet upstream side: a later idle period trims it too.
    c->upstream_recv_buf.reset();
    c->handler_gen++;
    run_to_trim();
    CHECK_EQ(loop.idle_trim_conns, 2u);
    CHECK_EQ(loop.idle_trim_madvise, 5u);  // 2 + (recv, send, upstream)
    CHECK_EQ(resident_pages(up, SlicePool::kSliceSize), 0u);

    // An outstanding direct upstream recv (kernel writes the slice) blocks everything.
    up[0] = 1;
    c->upstream_recv_direct_armed = true;
    c->handler_gen++;
    run_to_trim();
    CHECK_EQ(loop.idle_trim_conns, 2u);
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
    if (!r.init(4, false)) SKIP("io_uring unavailable");
    auto& loop = *r.loop;
    Connection* c = stage_idle(r, 100000);
    REQUIRE(c != nullptr);
    static const u8 kStale[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    REQUIRE_EQ(c->send_buf.write(kStale, sizeof(kStale) - 1), sizeof(kStale) - 1);
    for (u32 i = 0; i < 12; i++) loop.sweep_idle_trim(1);
    CHECK_EQ(loop.idle_trim_conns, 1u);
    CHECK_EQ(loop.idle_trim_madvise, 1u);  // recv slice only
    CHECK_EQ(resident_pages(c->recv_slice, SlicePool::kSliceSize), 0u);
    CHECK_EQ(resident_pages(c->send_slice, SlicePool::kSliceSize), 1u);
    CHECK_EQ(memcmp(c->send_buf.data(), kStale, sizeof(kStale) - 1), 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
