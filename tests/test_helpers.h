#pragma once

// Shared test infrastructure — mock event loop, real socket helpers.

#include "mock_backend.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/event_loop.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/shard_control.h"
#include "rut/runtime/socket.h"
#include "rut/runtime/timer_wheel.h"
#include "rut/runtime/traffic_capture.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rut;

// ---- Mock event loop (64 conns, for unit tests) ----

struct SmallLoop : EventLoopCRTP<SmallLoop> {
    MockBackend backend;
    TimerWheel timer;
    u32 shard_id = 0;
    bool running = true;

    static constexpr u32 kMaxConns = 64;
    static constexpr u32 kBufSize = 4096;  // test buffer size per direction
    Connection conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top = 0;
    u32 keepalive_timeout = 60;
    bool draining = false;
    AccessLogRing* access_log = nullptr;
    struct CaptureRing* capture_ring = nullptr;
    ShardMetrics* metrics = nullptr;

    // Inline buffer storage for tests (no SlicePool dependency).
    u8 recv_storage[kMaxConns][kBufSize];
    u8 send_storage[kMaxConns][kBufSize];
    u8 upstream_recv_storage[kMaxConns][kBufSize];
    u8 response_header_storage[kMaxConns][kBufSize];
    u8 capture_storage[kMaxConns][CaptureEntry::kMaxHeaderLen];

    bool set_capture(CaptureRing* ring) {
        capture_ring = ring;
        if (!ring) return true;
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0 && !conns[i].capture_buf)
                conns[i].capture_buf = capture_storage[i];
        }
        return true;
    }

    bool is_draining() const { return draining; }

    // Per-shard control plane pointers (mirrors EventLoop for testing).
    const RouteConfig** config_ptr = nullptr;
    ShardControlBlock* control = nullptr;
    ShardEpoch* epoch = nullptr;
    void** jit_code_ptr = nullptr;

    // Epoch helpers — functional when epoch pointer is wired.
    void epoch_enter() {
        if (epoch)
            epoch->epoch.store(epoch->epoch.load(std::memory_order_relaxed) + 1,
                               std::memory_order_release);
    }
    void epoch_leave() {
        if (epoch)
            epoch->epoch.store(epoch->epoch.load(std::memory_order_relaxed) + 1,
                               std::memory_order_release);
    }

    // Poll the per-shard control block (mirrors EventLoop::poll_command).
    void poll_command() {
        if (!control) return;
        auto* cfg = control->pending_config.exchange(nullptr, std::memory_order_acq_rel);
        if (cfg && config_ptr) *config_ptr = cfg;
        auto* jit = control->pending_jit.exchange(nullptr, std::memory_order_acq_rel);
        if (jit && jit_code_ptr) *jit_code_ptr = jit;
        auto* cap = control->pending_capture.exchange(nullptr, std::memory_order_acq_rel);
        if (cap == kCaptureDisable)
            set_capture(nullptr);
        else if (cap)
            set_capture(cap);
    }

    void setup() {
        running = true;
        draining = false;
        access_log = nullptr;
        capture_ring = nullptr;
        metrics = nullptr;
        config_ptr = nullptr;
        control = nullptr;
        epoch = nullptr;
        jit_code_ptr = nullptr;
        keepalive_timeout = 60;
        free_top = kMaxConns;
        timer.init();
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i].reset();
            conns[i].id = i;
            free_stack[i] = i;
        }
        backend.init(0, -1);
    }

    void clear_upstream_fd(u32 /*conn_id*/) {}

    bool alloc_upstream_buf(ConnectionBase& c) {
        if (c.upstream_recv_slice) return true;
        u32 id = c.id;
        if (id >= kMaxConns) return false;
        c.upstream_recv_slice = upstream_recv_storage[id];
        c.upstream_recv_buf.bind(upstream_recv_storage[id], kBufSize);
        return true;
    }

    bool alloc_response_header_buf(ConnectionBase& c) {
        if (c.response_header_slice) return true;
        c.response_header_slice = response_header_storage[c.id];
        c.response_header_buf.bind(response_header_storage[c.id], kBufSize);
        return true;
    }

    Connection* alloc_conn_impl() {
        if (free_top == 0) return nullptr;
        u32 id = free_stack[--free_top];
        conns[id].reset();
        conns[id].id = id;
        conns[id].listener_context = this->listener_context;
        conns[id].recv_slice = recv_storage[id];
        conns[id].send_slice = send_storage[id];
        conns[id].recv_buf.bind(recv_storage[id], kBufSize);
        conns[id].send_buf.bind(send_storage[id], kBufSize);
        conns[id].response_header_slice = response_header_storage[id];
        conns[id].response_header_buf.bind(response_header_storage[id], kBufSize);
        if (capture_ring) conns[id].capture_buf = capture_storage[id];
        return &conns[id];
    }
    void free_conn_impl(Connection& c) {
        u32 cid = c.id;
        timer.remove(&c);
        // MockBackend::kAsyncIo == false: sync backend, free immediately.
        c.reset();
        free_stack[free_top++] = cid;
    }
    bool submit_recv_impl(Connection& c) { return backend.add_recv(c.fd, c.id); }
    bool submit_send_impl(Connection& c, const u8* buf, u32 len) {
        return backend.add_send(c.fd, c.id, buf, len);
    }
    bool submit_send_upstream_impl(Connection& c, const u8* buf, u32 len) {
        return backend.add_send_upstream(c.upstream_fd, c.id, buf, len);
    }
    bool submit_recv_upstream_impl(Connection& c) {
        return backend.add_recv_upstream(c.upstream_fd, c.id);
    }
    bool pause_recv(Connection& c) {
        backend.pause_recv(c.id);
        return true;
    }
    void pause_upstream_recv_impl(Connection& c) { backend.pause_upstream_recv(c.id); }
    bool submit_connect_impl(Connection& c, const void* addr, u32 addr_len) {
        return backend.add_connect(c.upstream_fd, c.id, addr, addr_len);
    }
    // Test shim: record the ms for assertions, fall back to 1s wheel so
    // pending_handler_fn is still re-entered when the test ticks.
    u32 last_yield_ms = 0;
    [[nodiscard]] bool schedule_yield_timer(Connection& c, u32 ms) {
        last_yield_ms = ms;
        u32 secs = timer_seconds_from_ms(ms);
        // Mirror real-loop wheel-fallback boundary: 64 slots × 1s, so
        // seconds >= kSlots would wrap mod-64. Fail the request so
        // tests exercising long waits under simulated SQ pressure
        // behave like the production loops.
        if (secs >= TimerWheel::kSlots) return false;
        if (secs == 0) secs = 1;
        // timer.add doesn't detach an existing entry — calling it twice
        // on the same connection would double-insert and corrupt the
        // intrusive list. Production loops remove first; mirror that
        // so keepalive-armed conns can yield safely.
        timer.remove(&c);
        c.yield_armed = true;
        timer.add(&c, secs);
        return true;
    }
    void close_conn_impl(Connection& c) {
        if (c.req_start_us != 0) epoch_leave();
        // Mirror real EventLoop: cancel in-flight I/O before freeing.
        if (c.fd >= 0) {
            backend.cancel(c.fd, c.id);
            c.fd = -1;
        }
        if (c.upstream_fd >= 0) {
            backend.cancel(c.upstream_fd, c.id);
            c.upstream_fd = -1;
        }
        if (metrics) {
            if (c.req_start_us != 0) {
                if (metrics->requests_active > 0) metrics->requests_active--;
            }
            metrics->on_close();
        }
        this->free_conn(c);
    }

    // Inject + dispatch convenience.
    // For Recv events with result>0, simulates what a real backend does:
    // append mock data into the connection's recv_buf (or upstream_recv_buf
    // for UpstreamRecv). Syncs ev.result to actual committed bytes, or
    // -ENOBUFS if buffer full.
    void inject_and_dispatch(IoEvent ev) {
        if ((ev.type == IoEventType::Recv || ev.type == IoEventType::UpstreamRecv) &&
            ev.result > 0 && ev.conn_id < kMaxConns) {
            auto& buf = (ev.type == IoEventType::UpstreamRecv) ? conns[ev.conn_id].upstream_recv_buf
                                                               : conns[ev.conn_id].recv_buf;
            u32 n = static_cast<u32>(ev.result);
            u32 avail = buf.write_avail();
            if (avail == 0) {
                ev.result = -ENOBUFS;
            } else {
                if (n > avail) n = avail;
                // Write deterministic mock bytes before commit so data()-based
                // tests see meaningful content (repeating 0x00..0xFF pattern).
                u8* dst = buf.write_ptr();
                for (u32 j = 0; j < n; j++) dst[j] = static_cast<u8>(j & 0xFF);
                buf.commit(n);
                ev.result = static_cast<i32>(n);
            }
        }
        backend.inject(ev);
        IoEvent events[8];
        u32 n = backend.wait(events, 8);
        for (u32 i = 0; i < n; i++) dispatch(events[i]);
    }

    void dispatch(const IoEvent& ev) {
        switch (ev.type) {
            case IoEventType::Accept: {
                if (ev.result < 0) return;
                Connection* c = this->alloc_conn();
                if (!c) return;
                c->fd = ev.result;
                c->state = ConnState::ReadingHeader;
                c->on_recv = &on_header_received<SmallLoop>;
                timer.add(c, keepalive_timeout);
                this->submit_recv(*c);
                break;
            }
            case IoEventType::Timeout:
                timer.tick([this](Connection* c) {
                    // Mirror EpollEventLoop/IoUringEventLoop: a tick can
                    // represent either keepalive expiry (close) or a JIT
                    // yield fallback (resume). schedule_yield_timer on
                    // this mock uses the wheel, so tests exercising
                    // wait(...) reach this branch.
                    if (c->pending_handler_fn &&
                        (c->pending_yield_kind == jit::YieldKind::Timer ||
                         (c->yield_armed &&
                          yield_kind_matches_event(c->pending_yield_kind, IoEventType::Timeout)))) {
                        c->yield_armed = false;
                        c->resume_event_kind = jit::YieldKind::Timer;
                        c->resume_event_result = 0;
                        resume_jit_handler<SmallLoop>(this, *c);
                    } else {
                        this->close_conn(*c);
                    }
                });
                break;
            case IoEventType::Recv:
            case IoEventType::Send:
            case IoEventType::UpstreamConnect:
            case IoEventType::UpstreamRecv:
            case IoEventType::UpstreamSend:
                if (ev.conn_id < kMaxConns) {
                    auto& conn = conns[ev.conn_id];
                    if (conn.on_recv || conn.on_send || conn.on_upstream_recv ||
                        conn.on_upstream_send) {
                        timer.refresh(&conn, keepalive_timeout);
                        this->dispatch_event(conn, ev);
                    } else if (conn.pending_handler_fn &&
                               yield_kind_matches_event(conn.pending_yield_kind, ev.type)) {
                        if (conn.yield_armed) {
                            conn.yield_armed = false;
                            timer.remove(&conn);
                        }
                        conn.resume_event_kind = yield_kind_from_event(ev.type);
                        conn.resume_event_result = ev.result;
                        resume_jit_handler<SmallLoop>(this, conn);
                    }
                }
                break;
            case IoEventType::HandlerTimer:
            case IoEventType::Count:
                break;
        }
    }

    // Find connection by fd
    Connection* find_fd(i32 fd) {
        for (u32 i = 0; i < kMaxConns; i++)
            if (conns[i].fd == fd) return &conns[i];
        return nullptr;
    }
};

inline IoEvent make_ev(u32 conn_id, IoEventType type, i32 result, u16 buf_id = 0, u8 has_buf = 0) {
    return {conn_id, result, buf_id, has_buf, type, 0};
}

inline IoEvent make_ev_more(u32 conn_id, IoEventType type, i32 result, u8 more) {
    return {conn_id, result, 0, 0, type, more};
}

// ---- Async mock backend (kAsyncIo = true) for io_uring-style tests ----

struct AsyncMockBackend {
    static constexpr bool kAsyncIo = true;

    static constexpr u32 kMaxOps = 256;
    MockOp ops[kMaxOps];
    u32 op_count = 0;
    i32 timer_fd = -1;
    bool fail_connect = false;
    bool fail_upstream_recv = false;
    bool fail_upstream_send = false;

    static constexpr u32 kMaxEvents = 256;
    IoEvent pending[kMaxEvents];
    u32 pending_count = 0;

    core::Expected<void, Error> init(u32 /*shard_id*/, i32 /*listen_fd*/) {
        op_count = 0;
        pending_count = 0;
        timer_fd = -1;
        fail_connect = false;
        fail_upstream_recv = false;
        fail_upstream_send = false;
        return {};
    }

    void add_accept() {
        if (op_count < kMaxOps) {
            ops[op_count++] = {MockOp::Accept, -1, 0, nullptr, 0};
        }
    }

    bool add_recv(i32 fd, u32 conn_id) {
        if (op_count < kMaxOps) {
            ops[op_count++] = {MockOp::Recv, fd, conn_id, nullptr, 0};
        }
        return true;
    }

    bool add_recv_upstream(i32 fd, u32 conn_id) {
        if (fail_upstream_recv) return false;
        return add_recv(fd, conn_id);
    }

    bool add_send(i32 fd, u32 conn_id, const u8* buf, u32 len) {
        if (op_count < kMaxOps) {
            ops[op_count++] = {MockOp::Send, fd, conn_id, buf, len};
        }
        return true;
    }

    bool add_send_upstream(i32 fd, u32 conn_id, const u8* buf, u32 len) {
        if (fail_upstream_send) return false;
        return add_send(fd, conn_id, buf, len);
    }

    bool add_connect(i32 fd, u32 conn_id, const void* /*addr*/, u32 /*len*/) {
        if (fail_connect) return false;
        if (op_count < kMaxOps) {
            ops[op_count++] = {MockOp::Connect, fd, conn_id, nullptr, 0};
        }
        return true;
    }

    u32 cancel(i32 fd,
               u32 conn_id,
               bool /*recv_armed*/ = false,
               bool /*send_armed*/ = false,
               bool /*upstream_recv_armed*/ = false,
               bool /*upstream_send_armed*/ = false,
               bool /*has_upstream*/ = false) {
        u32 n = 0;
        if (op_count < kMaxOps) {
            ops[op_count++] = {MockOp::Cancel, fd, conn_id, nullptr, 0};
            n++;
        }
        return n;
    }

    void cancel_accept() {}
    void shutdown() {}

    void inject(IoEvent ev) {
        if (pending_count < kMaxEvents) {
            pending[pending_count++] = ev;
        }
    }

    u32 wait(IoEvent* events, u32 max, Connection* /*conns*/ = nullptr, u32 /*max_conns*/ = 0) {
        u32 n = pending_count < max ? pending_count : max;
        for (u32 i = 0; i < n; i++) events[i] = pending[i];
        for (u32 i = n; i < pending_count; i++) pending[i - n] = pending[i];
        pending_count -= n;
        return n;
    }

    const MockOp* last_op(MockOp::Type type) const {
        for (i32 i = static_cast<i32>(op_count) - 1; i >= 0; i--) {
            if (ops[i].type == type) return &ops[i];
        }
        return nullptr;
    }

    u32 count_ops(MockOp::Type type) const {
        u32 n = 0;
        for (u32 i = 0; i < op_count; i++) {
            if (ops[i].type == type) n++;
        }
        return n;
    }

    void clear_ops() { op_count = 0; }
};

// Async mock backend that fails add_recv (returns false).
struct FailRecvAsyncMockBackend : AsyncMockBackend {
    bool add_recv(i32 /*fd*/, u32 /*conn_id*/) { return false; }
    bool add_recv_upstream(i32 fd, u32 conn_id) { return add_recv(fd, conn_id); }
};

// ---- Async mock event loop (64 conns, io_uring-style deferred reclaim) ----

struct AsyncSmallLoop : EventLoopCRTP<AsyncSmallLoop> {
    AsyncMockBackend backend;
    TimerWheel timer;
    u32 shard_id = 0;
    bool running = true;

    static constexpr u32 kMaxConns = 64;
    static constexpr u32 kBufSize = 4096;
    Connection conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top = 0;

    u32 pending_free[kMaxConns];
    u32 pending_free_count = 0;

    u32 keepalive_timeout = 60;
    bool draining = false;
    AccessLogRing* access_log = nullptr;
    struct CaptureRing* capture_ring = nullptr;
    ShardMetrics* metrics = nullptr;

    u8 recv_storage[kMaxConns][kBufSize];
    u8 send_storage[kMaxConns][kBufSize];
    u8 upstream_recv_storage[kMaxConns][kBufSize];
    u8 response_header_storage[kMaxConns][kBufSize];

    bool is_draining() const { return draining; }

    // Per-shard control plane pointers (mirrors EventLoop for testing).
    const RouteConfig** config_ptr = nullptr;
    ShardControlBlock* control = nullptr;
    ShardEpoch* epoch = nullptr;
    void** jit_code_ptr = nullptr;

    // Epoch helpers — functional when epoch pointer is wired.
    void epoch_enter() {
        if (epoch)
            epoch->epoch.store(epoch->epoch.load(std::memory_order_relaxed) + 1,
                               std::memory_order_release);
    }
    void epoch_leave() {
        if (epoch)
            epoch->epoch.store(epoch->epoch.load(std::memory_order_relaxed) + 1,
                               std::memory_order_release);
    }

    void clear_upstream_fd(u32 /*conn_id*/) {}

    bool alloc_upstream_buf(ConnectionBase& c) {
        if (c.upstream_recv_slice) return true;
        u32 id = c.id;
        if (id >= kMaxConns) return false;
        c.upstream_recv_slice = upstream_recv_storage[id];
        c.upstream_recv_buf.bind(upstream_recv_storage[id], kBufSize);
        return true;
    }

    bool alloc_response_header_buf(ConnectionBase& c) {
        if (c.response_header_slice) return true;
        c.response_header_slice = response_header_storage[c.id];
        c.response_header_buf.bind(response_header_storage[c.id], kBufSize);
        return true;
    }

    void setup() {
        running = true;
        draining = false;
        access_log = nullptr;
        capture_ring = nullptr;
        metrics = nullptr;
        config_ptr = nullptr;
        control = nullptr;
        epoch = nullptr;
        jit_code_ptr = nullptr;
        keepalive_timeout = 60;
        free_top = kMaxConns;
        pending_free_count = 0;
        timer.init();
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i].reset();
            conns[i].id = i;
            free_stack[i] = i;
        }
        backend.init(0, -1);
    }

    Connection* alloc_conn_impl() {
        if (free_top == 0) return nullptr;
        u32 id = free_stack[--free_top];
        conns[id].reset();
        conns[id].id = id;
        conns[id].recv_slice = recv_storage[id];
        conns[id].send_slice = send_storage[id];
        conns[id].recv_buf.bind(recv_storage[id], kBufSize);
        conns[id].send_buf.bind(send_storage[id], kBufSize);
        conns[id].response_header_slice = response_header_storage[id];
        conns[id].response_header_buf.bind(response_header_storage[id], kBufSize);
        return &conns[id];
    }

    void free_conn_impl(Connection& c) {
        u32 cid = c.id;
        timer.remove(&c);
        if (c.pending_ops == 0) {
            // No in-flight ops: reclaim immediately.
            c.reset();
            free_stack[free_top++] = cid;
        } else {
            // Defer until CQEs drain pending_ops to 0.
            u8* rs = c.recv_slice;
            u8* ss = c.send_slice;
            u8* us = c.upstream_recv_slice;
            u32 ops = c.pending_ops;
            c.reset();
            conns[cid].recv_slice = rs;
            conns[cid].send_slice = ss;
            conns[cid].upstream_recv_slice = us;
            conns[cid].pending_ops = ops;
            pending_free[pending_free_count++] = cid;
        }
    }

    bool submit_recv_impl(Connection& c) {
        if (c.recv_armed) return true;
        if (backend.add_recv(c.fd, c.id)) {
            c.pending_ops++;
            c.recv_armed = true;
            return true;
        }
        return false;
    }
    bool submit_send_impl(Connection& c, const u8* buf, u32 len) {
        if (backend.add_send(c.fd, c.id, buf, len)) {
            c.pending_ops++;
            c.send_armed = true;
            return true;
        }
        return false;
    }
    bool submit_send_upstream_impl(Connection& c, const u8* buf, u32 len) {
        if (backend.add_send_upstream(c.upstream_fd, c.id, buf, len)) {
            c.pending_ops++;
            c.upstream_send_armed = true;
            return true;
        }
        return false;
    }
    bool submit_recv_upstream_impl(Connection& c) {
        if (c.upstream_recv_armed) return true;
        if (backend.add_recv_upstream(c.upstream_fd, c.id)) {
            c.pending_ops++;
            c.upstream_recv_armed = true;
            return true;
        }
        return false;
    }
    bool submit_connect_impl(Connection& c, const void* addr, u32 addr_len) {
        if (backend.add_connect(c.upstream_fd, c.id, addr, addr_len)) {
            c.pending_ops++;
            return true;
        }
        return false;
    }

    // Test shim matching SmallLoop's: drive the legacy wheel so existing
    // 1-second tick tests continue to resume the handler.
    u32 last_yield_ms = 0;
    [[nodiscard]] bool schedule_yield_timer(Connection& c, u32 ms) {
        last_yield_ms = ms;
        u32 secs = timer_seconds_from_ms(ms);
        // Mirror real-loop wheel-fallback boundary: 64 slots × 1s, so
        // seconds >= kSlots would wrap mod-64. Fail the request so
        // tests exercising long waits under simulated SQ pressure
        // behave like the production loops.
        if (secs >= TimerWheel::kSlots) return false;
        if (secs == 0) secs = 1;
        // timer.add doesn't detach an existing entry — calling it twice
        // on the same connection would double-insert and corrupt the
        // intrusive list. Production loops remove first; mirror that
        // so keepalive-armed conns can yield safely.
        timer.remove(&c);
        c.yield_armed = true;
        timer.add(&c, secs);
        return true;
    }

    void close_conn_impl(Connection& c) {
        if (c.req_start_us != 0) epoch_leave();
        if (c.pending_ops > 0) {
            c.pending_ops += backend.cancel(c.fd,
                                            c.id,
                                            c.recv_armed,
                                            c.send_armed,
                                            c.upstream_recv_armed,
                                            c.upstream_send_armed,
                                            c.upstream_fd >= 0);
        }
        c.fd = -1;
        c.upstream_fd = -1;
        if (metrics) {
            if (c.req_start_us != 0) {
                if (metrics->requests_active > 0) metrics->requests_active--;
            }
            metrics->on_close();
        }
        this->free_conn(c);
    }

    void reclaim_slot(u32 cid) {
        // Inline reclaim from dispatch: push to free_stack, remove from pending_free.
        free_stack[free_top++] = cid;
        for (u32 i = 0; i < pending_free_count; i++) {
            if (pending_free[i] == cid) {
                pending_free[i] = pending_free[--pending_free_count];
                break;
            }
        }
    }

    void reclaim_pending() {
        u32 remaining = 0;
        for (u32 i = 0; i < pending_free_count; i++) {
            u32 cid = pending_free[i];
            if (conns[cid].pending_ops == 0) {
                free_stack[free_top++] = cid;
            } else {
                pending_free[remaining++] = cid;
            }
        }
        pending_free_count = remaining;
    }

    void dispatch(const IoEvent& ev) {
        switch (ev.type) {
            case IoEventType::Accept: {
                if (ev.result < 0) return;
                Connection* c = this->alloc_conn();
                if (!c) return;
                c->fd = ev.result;
                c->state = ConnState::ReadingHeader;
                c->on_recv = &on_header_received<AsyncSmallLoop>;
                timer.add(c, keepalive_timeout);
                this->submit_recv(*c);
                break;
            }
            case IoEventType::HandlerTimer:
                if (ev.conn_id < kMaxConns) {
                    auto& conn = conns[ev.conn_id];
                    if (conn.pending_ops > 0) conn.pending_ops--;
                    const bool matching_generation =
                        ev.result == static_cast<i32>(conn.yield_timer_gen);
                    const bool was_yield_armed = conn.yield_armed;
                    if (matching_generation) {
                        conn.yield_armed = false;
                        timer.remove(&conn);
                    }
                    if (conn.pending_handler_fn && matching_generation &&
                        (conn.pending_yield_kind == jit::YieldKind::Timer ||
                         (was_yield_armed &&
                          yield_kind_matches_event(conn.pending_yield_kind,
                                                   IoEventType::HandlerTimer)))) {
                        conn.resume_event_kind = jit::YieldKind::Timer;
                        conn.resume_event_result = 0;
                        resume_jit_handler<AsyncSmallLoop>(this, conn);
                    } else if (conn.pending_ops == 0 && !conn.pending_handler_fn && conn.fd < 0) {
                        reclaim_slot(ev.conn_id);
                    }
                }
                break;
            case IoEventType::Timeout:
                timer.tick([this](Connection* c) {
                    // See SmallLoop: a tick resumes yielded JIT handlers and
                    // otherwise closes on keepalive expiry.
                    if (c->pending_handler_fn &&
                        (c->pending_yield_kind == jit::YieldKind::Timer ||
                         (c->yield_armed &&
                          yield_kind_matches_event(c->pending_yield_kind, IoEventType::Timeout)))) {
                        c->yield_armed = false;
                        c->resume_event_kind = jit::YieldKind::Timer;
                        c->resume_event_result = 0;
                        resume_jit_handler<AsyncSmallLoop>(this, *c);
                    } else {
                        this->close_conn(*c);
                    }
                });
                break;
            case IoEventType::Recv:
            case IoEventType::Send:
            case IoEventType::UpstreamConnect:
            case IoEventType::UpstreamRecv:
            case IoEventType::UpstreamSend:
                if (ev.conn_id < kMaxConns) {
                    auto& conn = conns[ev.conn_id];
                    // Async CQE accounting: decrement pending_ops on final CQE.
                    if (!ev.more) {
                        if (conn.pending_ops > 0) conn.pending_ops--;
                        if (ev.type == IoEventType::Recv) conn.recv_armed = false;
                        if (ev.type == IoEventType::Send) conn.send_armed = false;
                        if (ev.type == IoEventType::UpstreamSend) conn.upstream_send_armed = false;
                        if (ev.type == IoEventType::UpstreamRecv) conn.upstream_recv_armed = false;
                    }
                    if (conn.on_recv || conn.on_send || conn.on_upstream_recv ||
                        conn.on_upstream_send) {
                        timer.refresh(&conn, keepalive_timeout);
                        this->dispatch_event(conn, ev);
                    } else if (conn.pending_handler_fn &&
                               yield_kind_matches_event(conn.pending_yield_kind, ev.type)) {
                        if (conn.yield_armed) {
                            conn.yield_armed = false;
                            timer.remove(&conn);
                        }
                        conn.resume_event_kind = yield_kind_from_event(ev.type);
                        conn.resume_event_result = ev.result;
                        resume_jit_handler<AsyncSmallLoop>(this, conn);
                    } else {
                        // Stale CQE: if all ops complete, reclaim immediately.
                        if (conn.pending_ops == 0) {
                            reclaim_slot(ev.conn_id);
                        }
                    }
                }
                break;
            case IoEventType::Count:
                break;
        }
    }

    // Inject + dispatch convenience (mirrors SmallLoop).
    void inject_and_dispatch(IoEvent ev) {
        if ((ev.type == IoEventType::Recv || ev.type == IoEventType::UpstreamRecv) &&
            ev.result > 0 && ev.conn_id < kMaxConns) {
            auto& buf = (ev.type == IoEventType::UpstreamRecv) ? conns[ev.conn_id].upstream_recv_buf
                                                               : conns[ev.conn_id].recv_buf;
            u32 n = static_cast<u32>(ev.result);
            u32 avail = buf.write_avail();
            if (avail == 0) {
                ev.result = -ENOBUFS;
            } else {
                if (n > avail) n = avail;
                u8* dst = buf.write_ptr();
                for (u32 j = 0; j < n; j++) dst[j] = static_cast<u8>(j & 0xFF);
                buf.commit(n);
                ev.result = static_cast<i32>(n);
            }
        }
        backend.inject(ev);
        IoEvent events[8];
        u32 n = backend.wait(events, 8);
        for (u32 i = 0; i < n; i++) dispatch(events[i]);
    }

    Connection* find_fd(i32 fd) {
        for (u32 i = 0; i < kMaxConns; i++)
            if (conns[i].fd == fd) return &conns[i];
        return nullptr;
    }
};

// ---- Async loop with failing recv backend ----

struct FailRecvAsyncSmallLoop : EventLoopCRTP<FailRecvAsyncSmallLoop> {
    FailRecvAsyncMockBackend backend;
    TimerWheel timer;
    u32 shard_id = 0;
    bool running = true;

    static constexpr u32 kMaxConns = 64;
    static constexpr u32 kBufSize = 4096;
    Connection conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top = 0;

    u32 keepalive_timeout = 60;
    bool draining = false;
    AccessLogRing* access_log = nullptr;
    struct CaptureRing* capture_ring = nullptr;
    ShardMetrics* metrics = nullptr;

    u8 recv_storage[kMaxConns][kBufSize];
    u8 send_storage[kMaxConns][kBufSize];
    u8 upstream_recv_storage[kMaxConns][kBufSize];
    u8 response_header_storage[kMaxConns][kBufSize];

    bool is_draining() const { return draining; }

    // Per-shard control plane pointers (mirrors EventLoop for testing).
    const RouteConfig** config_ptr = nullptr;
    ShardEpoch* epoch = nullptr;

    // Epoch helpers — functional when epoch pointer is wired.
    void epoch_enter() {
        if (epoch)
            epoch->epoch.store(epoch->epoch.load(std::memory_order_relaxed) + 1,
                               std::memory_order_release);
    }
    void epoch_leave() {
        if (epoch)
            epoch->epoch.store(epoch->epoch.load(std::memory_order_relaxed) + 1,
                               std::memory_order_release);
    }

    void clear_upstream_fd(u32 /*conn_id*/) {}

    bool alloc_upstream_buf(ConnectionBase& c) {
        if (c.upstream_recv_slice) return true;
        u32 id = c.id;
        if (id >= kMaxConns) return false;
        c.upstream_recv_slice = upstream_recv_storage[id];
        c.upstream_recv_buf.bind(upstream_recv_storage[id], kBufSize);
        return true;
    }

    bool alloc_response_header_buf(ConnectionBase& c) {
        if (c.response_header_slice) return true;
        c.response_header_slice = response_header_storage[c.id];
        c.response_header_buf.bind(response_header_storage[c.id], kBufSize);
        return true;
    }

    void setup() {
        running = true;
        draining = false;
        access_log = nullptr;
        metrics = nullptr;
        config_ptr = nullptr;
        epoch = nullptr;
        keepalive_timeout = 60;
        free_top = kMaxConns;
        timer.init();
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i].reset();
            conns[i].id = i;
            free_stack[i] = i;
        }
        backend.init(0, -1);
    }

    Connection* alloc_conn_impl() {
        if (free_top == 0) return nullptr;
        u32 id = free_stack[--free_top];
        conns[id].reset();
        conns[id].id = id;
        conns[id].recv_slice = recv_storage[id];
        conns[id].send_slice = send_storage[id];
        conns[id].recv_buf.bind(recv_storage[id], kBufSize);
        conns[id].send_buf.bind(send_storage[id], kBufSize);
        conns[id].response_header_slice = response_header_storage[id];
        conns[id].response_header_buf.bind(response_header_storage[id], kBufSize);
        return &conns[id];
    }

    void free_conn_impl(Connection& c) {
        u32 cid = c.id;
        timer.remove(&c);
        c.reset();
        free_stack[free_top++] = cid;
    }

    bool submit_recv_impl(Connection& c) {
        if (c.recv_armed) return true;
        if (backend.add_recv(c.fd, c.id)) {
            c.pending_ops++;
            c.recv_armed = true;
            return true;
        }
        return false;
    }
    bool submit_send_impl(Connection& c, const u8* buf, u32 len) {
        if (backend.add_send(c.fd, c.id, buf, len)) {
            c.pending_ops++;
            return true;
        }
        return false;
    }
    bool submit_send_upstream_impl(Connection& c, const u8* buf, u32 len) {
        if (backend.add_send_upstream(c.upstream_fd, c.id, buf, len)) {
            c.pending_ops++;
            return true;
        }
        return false;
    }
    bool submit_recv_upstream_impl(Connection& c) {
        if (c.upstream_recv_armed) return true;
        if (backend.add_recv_upstream(c.upstream_fd, c.id)) {
            c.pending_ops++;
            c.upstream_recv_armed = true;
            return true;
        }
        return false;
    }
    bool submit_connect_impl(Connection& c, const void* addr, u32 addr_len) {
        if (backend.add_connect(c.upstream_fd, c.id, addr, addr_len)) {
            c.pending_ops++;
            return true;
        }
        return false;
    }
    u32 last_yield_ms = 0;
    [[nodiscard]] bool schedule_yield_timer(Connection& c, u32 ms) {
        last_yield_ms = ms;
        u32 secs = timer_seconds_from_ms(ms);
        // Mirror real-loop wheel-fallback boundary: 64 slots × 1s, so
        // seconds >= kSlots would wrap mod-64. Fail the request so
        // tests exercising long waits under simulated SQ pressure
        // behave like the production loops.
        if (secs >= TimerWheel::kSlots) return false;
        if (secs == 0) secs = 1;
        // timer.add doesn't detach an existing entry — calling it twice
        // on the same connection would double-insert and corrupt the
        // intrusive list. Production loops remove first; mirror that
        // so keepalive-armed conns can yield safely.
        timer.remove(&c);
        c.yield_armed = true;
        timer.add(&c, secs);
        return true;
    }
    void close_conn_impl(Connection& c) {
        if (c.req_start_us != 0) epoch_leave();
        c.fd = -1;
        c.upstream_fd = -1;
        this->free_conn(c);
    }

    void dispatch(const IoEvent&) {}
};

// ---- Real socket helpers ----

using RealLoop = EpollEventLoop;

inline RealLoop* create_real_loop() {
    void* p =
        mmap(nullptr, sizeof(RealLoop), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return nullptr;
    return new (p) RealLoop();
}

inline void destroy_real_loop(RealLoop* l) {
    if (l) {
        l->~RealLoop();
        munmap(l, sizeof(RealLoop));
    }
}

inline u16 get_port(i32 fd) {
    struct sockaddr_in a;
    socklen_t l = sizeof(a);
    getsockname(fd, reinterpret_cast<struct sockaddr*>(&a), &l);
    return __builtin_bswap16(a.sin_port);
}

inline i32 connect_to(u16 port) {
    i32 fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = __builtin_bswap16(port);
    a.sin_addr.s_addr = __builtin_bswap32(0x7F000001);
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&a), sizeof(a)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

inline i32 create_bound_client_socket(u16 client_port, u16* out_bound_port = nullptr) {
    i32 fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = __builtin_bswap16(client_port);
    local_addr.sin_addr.s_addr = __builtin_bswap32(0x7F000001);
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
        close(fd);
        return -1;
    }
    if (out_bound_port != nullptr) {
        struct sockaddr_in bound_addr;
        memset(&bound_addr, 0, sizeof(bound_addr));
        socklen_t l = sizeof(bound_addr);
        if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&bound_addr), &l) < 0) {
            close(fd);
            return -1;
        }
        *out_bound_port = __builtin_bswap16(bound_addr.sin_port);
    }
    return fd;
}

inline bool connect_bound_client_socket(i32 fd, u16 server_port) {
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = __builtin_bswap16(server_port);
    remote_addr.sin_addr.s_addr = __builtin_bswap32(0x7F000001);
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&remote_addr), sizeof(remote_addr)) < 0) {
        close(fd);
        return false;
    }
    return true;
}

inline bool send_all(i32 fd, const char* d, u32 len) {
    u32 sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, d + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += static_cast<u32>(n);
    }
    return true;
}

inline i64 test_mono_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<i64>(ts.tv_sec) * 1000 + ts.tv_nsec / 1'000'000;
}

inline i32 recv_timeout(i32 fd, char* buf, u32 len, i32 ms) {
    // SO_RCVTIMEO makes recv() non-restartable (man 7 signal): a stop/cont
    // cycle on a loaded CI runner interrupts it with EINTR even though no
    // handler exists. Field evidence (PR #186 dump): step=recv-101-nothing
    // errno=4. Retry with the remaining budget instead of surfacing a
    // spurious failure; a genuinely expired budget still returns -EAGAIN.
    const i64 deadline = test_mono_ms() + ms;
    for (;;) {
        i64 left = deadline - test_mono_ms();
        if (left < 1) left = 1;
        struct timeval tv;
        tv.tv_sec = left / 1000;
        tv.tv_usec = static_cast<long>(left % 1000) * 1000L;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ssize_t n = recv(fd, buf, len, 0);
        if (n >= 0) return static_cast<i32>(n);
        if (errno != EINTR) return -errno;
        if (test_mono_ms() >= deadline) {
            // Leave errno matching the synthetic timeout: callers that
            // record errno (the ws-flake setup evidence) must see EAGAIN,
            // not the last EINTR this loop absorbed.
            errno = EAGAIN;
            return -EAGAIN;
        }
    }
}

inline bool has_200(const char* buf, i32 n) {
    for (i32 i = 0; i < n - 2; i++)
        if (buf[i] == '2' && buf[i + 1] == '0' && buf[i + 2] == '0') return true;
    return false;
}

// Byte-literal substring search over a fixed-length buffer. Returns true
// iff `[needle, needle+nlen)` appears anywhere in `[hay, hay+hlen)`.
// Handles nlen == 0 (always true) and nlen > hlen (always false).
inline bool buf_contains(const char* hay, u32 hlen, const char* needle, u32 nlen) {
    if (nlen > hlen) return false;
    for (u32 i = 0; i + nlen <= hlen; i++) {
        bool match = true;
        for (u32 j = 0; j < nlen; j++) {
            if (hay[i + j] != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

struct LoopThread {
    RealLoop* loop;
    pthread_t thread;
    i32 max_iters;
    // When set, the hang-guard bounds TIME instead of iteration count: the
    // loop serves until this many wall-clock milliseconds elapse (checked on
    // every wakeup), and max_iters is ignored. An LT-ready fd (e.g. an idle
    // EPOLLOUT registration) can make backend.wait return immediately every
    // call and burn max_iters in milliseconds, killing the loop under the
    // test's feet mid-scenario; conversely an idle loop only wakes on the
    // 1 Hz timerfd, so an iteration cap is also far too SLOW a guard there.
    // Tests whose client drives a multi-round-trip conversation should set
    // this to cover the whole conversation; stop() remains the normal exit.
    i64 max_run_ms = 0;
    static i64 mono_ms() {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<i64>(ts.tv_sec) * 1000 + ts.tv_nsec / 1'000'000;
    }
    static void* run(void* arg) {
        auto* lt = static_cast<LoopThread*>(arg);
        auto* lp = lt->loop;
        lp->backend.add_accept();
        IoEvent events[256];
        i32 iters = 0;
        const i64 deadline = lt->max_run_ms > 0 ? mono_ms() + lt->max_run_ms : 0;
        while (lp->is_running()) {
            u32 n = lp->backend.wait(events, 256, lp->conns, RealLoop::kMaxConns);
            for (u32 i = 0; i < n; i++) lp->dispatch(events[i]);
            if (deadline != 0) {
                if (mono_ms() >= deadline) break;
            } else if (++iters >= lt->max_iters) {
                break;
            }
        }
        return nullptr;
    }
    void start() { pthread_create(&thread, nullptr, run, this); }
    void stop() {
        loop->stop();
        pthread_join(thread, nullptr);
    }
};

struct TestServer {
    RealLoop* loop = nullptr;
    i32 listen_fd = -1;
    u16 port = 0;
    LoopThread lt{};

    bool setup(i32 iters) {
        loop = create_real_loop();
        if (!loop) return false;
        auto lfd_result = create_listen_socket(0);
        if (!lfd_result) {
            destroy_real_loop(loop);
            return false;
        }
        listen_fd = lfd_result.value();
        port = get_port(listen_fd);
        if (!loop->init(0, listen_fd)) {
            close(listen_fd);
            destroy_real_loop(loop);
            return false;
        }
        lt.loop = loop;
        lt.thread = {};
        lt.max_iters = iters;
        lt.start();
        return true;
    }
    void teardown() {
        lt.stop();
        loop->shutdown();
        close(listen_fd);
        destroy_real_loop(loop);
    }
};

// Valid HTTP response for proxy tests. Must be parseable by HttpResponseParser.
static const char kMockHttpResponse[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 2\r\n"
    "\r\n"
    "OK";
static constexpr u32 kMockHttpResponseLen = sizeof(kMockHttpResponse) - 1;

// Write a valid HTTP response into conn's upstream_recv_buf and dispatch UpstreamRecv.
// This replaces inject_and_dispatch for upstream response events so the
// response parser sees valid HTTP (inject_and_dispatch writes garbage bytes).
template <typename Loop>
static void inject_upstream_response(Loop& loop, Connection& conn) {
    conn.upstream_recv_buf.reset();
    u8* dst = conn.upstream_recv_buf.write_ptr();
    for (u32 j = 0; j < kMockHttpResponseLen; j++) dst[j] = static_cast<u8>(kMockHttpResponse[j]);
    conn.upstream_recv_buf.commit(kMockHttpResponseLen);
    IoEvent ev =
        make_ev(conn.id, IoEventType::UpstreamRecv, static_cast<i32>(kMockHttpResponseLen));
    // Inject directly without going through inject_and_dispatch (which would
    // overwrite our carefully crafted upstream_recv_buf with garbage bytes).
    loop.backend.inject(ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);
}

#define HTTP_REQ "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
#define HTTP_REQ_LEN 27
