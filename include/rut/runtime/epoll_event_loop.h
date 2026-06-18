#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/callbacks.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/drain.h"
#include "rut/runtime/epoll_backend.h"
#include "rut/runtime/error.h"
#include "rut/runtime/event_loop.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/io_backend.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/jit_dispatch.h"
#include "rut/runtime/metrics.h"
#include "rut/runtime/rate_limit.h"
#include "rut/runtime/shard_control.h"
#include "rut/runtime/slab_pool.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/timer_wheel.h"
#include "rut/runtime/tls.h"
#include "rut/runtime/upstream_concurrency.h"
#include <atomic>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

namespace rut {

namespace epoll_yield {

// Shared max-conn constant: both YieldHeap and EpollEventLoop derive
// their sizes from this single source so they can't drift.
static constexpr u32 kMaxConns = 16384;

inline u64 monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<u64>(ts.tv_sec) * 1'000'000'000ull + static_cast<u64>(ts.tv_nsec);
}

// Min-heap of pending JIT yield deadlines. The heap's top entry determines
// when backend.yield_timer_fd must fire next. Entries are tagged with the
// connection's handler_gen so stale entries (connection closed and
// reassigned to a different request) are filtered on pop. handler_gen is
// a monotonic per-connection counter — strictly unique across reuse even
// under μs-granularity close/reuse churn that could alias req_start_us.
//
// Capacity: one live entry per connection at most; handler chains (yield →
// resume → yield) push a new entry each time, but the prior entry has
// already been popped. Sized at kMaxConns + small slack for safety.
struct YieldHeap {
    struct Entry {
        u64 deadline_ns;
        u32 handler_gen;
        u32 conn_id;
    };
    // One live entry per connection at most, plus headroom for stale
    // entries that linger briefly between close and their deadline.
    // Derived from the shared epoll_yield::kMaxConns so the heap and
    // EpollEventLoop always agree on capacity.
    static constexpr u32 kCap = kMaxConns + 256;
    Entry entries[kCap];
    u32 size = 0;

    void clear() { size = 0; }
    bool empty() const { return size == 0; }
    const Entry& top() const { return entries[0]; }

    bool push(u64 deadline_ns, u32 handler_gen, u32 conn_id) {
        if (size >= kCap) return false;
        u32 i = size++;
        entries[i] = {deadline_ns, handler_gen, conn_id};
        sift_up(i);
        return true;
    }

    // Remove every entry with this conn_id. O(n) scan — expected to be
    // called at most once per close_conn, and n is bounded by the number
    // of concurrent yielded handlers (≤ kMaxConns). Restores the heap
    // invariant by sifting up/down the swapped-in tail entries. Returns
    // the number of entries removed.
    u32 remove_by_conn(u32 conn_id) {
        u32 removed = 0;
        u32 i = 0;
        while (i < size) {
            if (entries[i].conn_id != conn_id) {
                i++;
                continue;
            }
            entries[i] = entries[--size];
            removed++;
            // Sift the swapped entry up or down as needed. Only one of
            // the two branches can do work because the swapped entry
            // is either smaller than its parent (sift up) or larger
            // than one of its children (sift down), but not both.
            if (i < size) sift(i);
            // Don't advance i — the slot now holds the swapped tail,
            // which may itself match conn_id on chained yields (rare).
        }
        return removed;
    }

    void pop() {
        if (size == 0) return;
        entries[0] = entries[--size];
        sift_down(0);
    }

private:
    void sift_up(u32 i) {
        while (i > 0) {
            u32 parent = (i - 1) / 2;
            if (entries[parent].deadline_ns <= entries[i].deadline_ns) break;
            Entry tmp = entries[parent];
            entries[parent] = entries[i];
            entries[i] = tmp;
            i = parent;
        }
    }
    void sift_down(u32 i) {
        while (true) {
            u32 l = 2 * i + 1;
            u32 r = 2 * i + 2;
            u32 smallest = i;
            if (l < size && entries[l].deadline_ns < entries[smallest].deadline_ns) smallest = l;
            if (r < size && entries[r].deadline_ns < entries[smallest].deadline_ns) smallest = r;
            if (smallest == i) break;
            Entry tmp = entries[smallest];
            entries[smallest] = entries[i];
            entries[i] = tmp;
            i = smallest;
        }
    }
    void sift(u32 i) {
        // A swapped-in tail entry must sift in exactly one direction; try
        // both (each is a no-op when not applicable).
        sift_up(i);
        sift_down(i);
    }
};

}  // namespace epoll_yield

// EpollEventLoop — concrete, non-template event loop for epoll backend.
//
// Epoll is synchronous: the kernel is done with user buffers when
// recv/send returns. No deferred reclamation, no pending_ops tracking,
// no armed flags, no cancel SQEs.
struct EpollEventLoop : EventLoopCRTP<EpollEventLoop> {
    EpollBackend backend;
    TimerWheel timer;
    epoll_yield::YieldHeap yield_heap;
    // Absolute deadline currently programmed into backend.yield_timer_fd.
    // 0 means disarmed. Used to avoid redundant timerfd_settime syscalls
    // when a new push does not change the heap's top.
    u64 yield_timer_armed_ns = 0;
    u32 shard_id;
    // Shared cross-shard limiter for @rateLimit(scope: global) rules. Null ->
    // global rules degrade to per-shard. main.cc points every shard at one
    // shared instance.
    GlobalRateLimiter* global_rl = nullptr;
    // Shared per-upstream concurrency gauge for max-inflight limiting (null =
    // unlimited). main.cc points every shard at one shared instance.
    UpstreamConcurrency* upstream_cc = nullptr;
    bool upstream_acquire(u16 uid, u32 max) {
        return upstream_cc ? upstream_cc->try_acquire(uid, max) : true;
    }
    void upstream_release(u16 uid) {
        if (upstream_cc) upstream_cc->release(uid);
    }

private:
    std::atomic<bool> running_;
    std::atomic<bool> draining_;
    std::atomic<u64> drain_start_;
    std::atomic<u32> drain_period_;

public:
    static constexpr u32 kMaxConns = epoll_yield::kMaxConns;
    static constexpr u32 kDefaultKeepaliveTimeout = 60;
    // Deadline (seconds; coarse 1s timer-wheel resolution) for a connection in
    // the Proxying state. SCOPE: the post-connect phase only — from the upstream
    // connect completing, through request-send, until the upstream's first
    // response bytes. Firing before any response reached the client
    // (!proxy_resp_started) → 504; after streaming started → close (truncate).
    // Does NOT bound TCP connect establishment: the timer flips to this value
    // only on the first upstream I/O event (connect completion), so a *hung
    // connect* is still bounded by keepalive_timeout (ECONNREFUSED is immediate,
    // so this rarely matters). Idle keep-alive uses keepalive_timeout — a
    // separate knob. TODO: a dedicated connect-timeout if hung connects matter.
    static constexpr u32 kDefaultUpstreamTimeout = 30;
    SlicePool pool;
    // Per-shard HTTP/2 engine pool — lazily handed out when a connection
    // upgrades to h2. Bounded; over-cap upgrades fall back to closing the conn.
    static constexpr u32 kH2PoolCap = 2048;
    SlabPool<Http2Conn, kH2PoolCap> h2_pool;
    Connection conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top;

    u32 keepalive_timeout = kDefaultKeepaliveTimeout;
    u32 upstream_timeout = kDefaultUpstreamTimeout;
    i32 listen_fd = -1;
    TlsServerContext* tls_server = nullptr;

    AccessLogRing* access_log = nullptr;

    struct CaptureRing* capture_ring = nullptr;
    static constexpr u32 kCaptureSliceSize = 8192;
    u8* capture_region_ = nullptr;

    bool set_capture(CaptureRing* ring) {
        capture_ring = ring;
        if (!ring) return true;
        if (!capture_region_) {
            void* region = mmap(nullptr,
                                static_cast<u64>(kMaxConns) * kCaptureSliceSize,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS,
                                -1,
                                0);
            if (region == MAP_FAILED) {
                capture_ring = nullptr;
                return false;
            }
            capture_region_ = static_cast<u8*>(region);
        }
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0 && !conns[i].capture_buf)
                conns[i].capture_buf = capture_region_ + static_cast<u64>(i) * kCaptureSliceSize;
        }
        return true;
    }

    ShardMetrics* metrics = nullptr;
    // Registry of every shard's metrics, for the built-in /metrics endpoint to
    // aggregate across shards. Null → endpoint disabled (the default).
    ShardMetrics* const* all_shard_metrics = nullptr;
    u32 shard_metrics_count = 0;

    const RouteConfig** config_ptr = nullptr;
    ShardControlBlock* control = nullptr;
    ShardEpoch* epoch = nullptr;
    void** jit_code_ptr = nullptr;

    core::Expected<void, Error> init(u32 id, i32 lfd, u32 pool_prealloc = 0) {
        shard_id = id;
        listen_fd = lfd;
        running_.store(true, std::memory_order_relaxed);
        draining_.store(false, std::memory_order_relaxed);
        drain_start_.store(0, std::memory_order_relaxed);
        drain_period_.store(0, std::memory_order_relaxed);
        keepalive_timeout = kDefaultKeepaliveTimeout;
        upstream_timeout = kDefaultUpstreamTimeout;
        capture_ring = nullptr;
        capture_region_ = nullptr;
        config_ptr = nullptr;
        control = nullptr;
        epoch = nullptr;
        jit_code_ptr = nullptr;
        free_top = kMaxConns;
        timer.init();
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i].reset();
            conns[i].id = i;
            conns[i].shard_id = static_cast<u8>(id);
            free_stack[i] = i;
        }
        // 3 slices max per connection: recv + send + upstream_recv (lazy).
        TRY_VOID(pool.init(kMaxConns * 3, pool_prealloc));
        auto h2p = h2_pool.init();
        if (!h2p) {
            pool.destroy();
            return core::make_unexpected(h2p.error());
        }
        auto be = backend.init(id, lfd);
        if (!be) {
            h2_pool.destroy();
            pool.destroy();
            return core::make_unexpected(be.error());
        }
        return {};
    }

    void run() {
        backend.add_accept();
        IoEvent events[kMaxEventsPerWait];

        while (is_running()) {
            u32 n = backend.wait(events, kMaxEventsPerWait, conns, kMaxConns);
            for (u32 i = 0; i < n; i++) {
                dispatch(events[i]);
            }
            poll_command();
            if (draining_.load(std::memory_order_acquire)) {
                close_listen();
                u64 start = drain_start_.load(std::memory_order_relaxed);
                u32 period = drain_period_.load(std::memory_order_relaxed);
                if (active_count() == 0) {
                    running_.store(false, std::memory_order_relaxed);
                } else if (monotonic_secs() >= start + period) {
                    force_close_all();
                    running_.store(false, std::memory_order_relaxed);
                }
            }
        }
    }

    void stop() { running_.store(false, std::memory_order_release); }
    bool is_running() const { return running_.load(std::memory_order_acquire); }
    bool is_draining() const { return draining_.load(std::memory_order_acquire); }

    void poll_command() {
        if (!control) return;
        auto* cfg = control->pending_config.exchange(nullptr, std::memory_order_acq_rel);
        if (cfg && config_ptr) *config_ptr = cfg;
        auto* jit = control->pending_jit.exchange(nullptr, std::memory_order_acq_rel);
        if (jit && jit_code_ptr) *jit_code_ptr = jit;
        auto* cap = control->pending_capture.exchange(nullptr, std::memory_order_acq_rel);
        if (cap == kCaptureDisable) {
            set_capture(nullptr);
        } else if (cap) {
            if (!set_capture(cap)) control->pending_capture.store(cap, std::memory_order_release);
        }
    }

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

    void shutdown() {
        backend.shutdown();
        h2_pool.destroy();
        pool.destroy();
        if (capture_region_) {
            munmap(capture_region_, static_cast<u64>(kMaxConns) * kCaptureSliceSize);
            capture_region_ = nullptr;
        }
    }

    void drain(u32 period_secs) {
        drain_period_.store(period_secs, std::memory_order_relaxed);
        drain_start_.store(monotonic_secs(), std::memory_order_relaxed);
        draining_.store(true, std::memory_order_release);
        if (backend.timer_fd >= 0) {
            struct itimerspec wake = {};
            wake.it_value.tv_nsec = 1;
            wake.it_interval.tv_sec = 1;
            timerfd_settime(backend.timer_fd, 0, &wake, nullptr);
        }
    }

    u32 active_count() const { return kMaxConns - free_top; }

    // Lazy-allocate upstream recv buffer for proxy connections.
    // Only called when a connection starts proxying — non-proxy connections
    // never pay the cost. Returns false if SlicePool is exhausted.
    // Clear upstream fd mapping (call when upstream_fd is closed on keep-alive).
    void clear_upstream_fd(u32 conn_id) {
        if (conn_id < EpollBackend::kMaxFdMap) backend.upstream_fd_map[conn_id] = -1;
    }

    // Stop polling the upstream fd without closing it (close_conn still ::closes
    // it). epoll is level-triggered and delivers EPOLLHUP/EPOLLERR even with the
    // interest mask zeroed, so a backend that closes during the pre-tunnel 101
    // drain to a slow client would otherwise spin the loop redelivering the EOF.
    // io_uring needs no equivalent (a cancelled recv does not re-fire), so this
    // method is epoll-only and the WS callback reaches it via a requires-guard.
    void ws_unpoll_upstream(Connection& c) {
        if (c.upstream_fd >= 0) backend.quiesce_recv(c.id, /*upstream=*/true);
    }

    // Symmetric to ws_unpoll_upstream for the downstream (client) fd: stop epoll
    // from redelivering a client half-close (EPOLLRDHUP) while a tunnel close is
    // deferred behind a still-draining client→upstream send. close_conn ::closes
    // the fd later.
    void ws_unpoll_client(Connection& c) {
        if (c.fd >= 0) backend.quiesce_recv(c.id, /*upstream=*/false);
    }

    bool alloc_upstream_buf(ConnectionBase& c) {
        if (c.upstream_recv_slice) return true;  // already allocated
        u8* s = pool.alloc();
        if (!s) return false;
        c.upstream_recv_slice = s;
        c.upstream_recv_buf.bind(s, SlicePool::kSliceSize);
        return true;
    }

    // --- CRTP implementations (no if constexpr — epoll only) ---

    Connection* alloc_conn_impl() {
        if (free_top == 0) return nullptr;
        u8* rs = pool.alloc();
        u8* ss = pool.alloc();
        if (!rs || !ss) {
            if (rs) pool.free(rs);
            if (ss) pool.free(ss);
            return nullptr;
        }
        u32 id = free_stack[--free_top];
        conns[id].reset();
        conns[id].id = id;
        conns[id].shard_id = static_cast<u8>(shard_id);
        conns[id].recv_slice = rs;
        conns[id].send_slice = ss;
        conns[id].recv_buf.bind(rs, SlicePool::kSliceSize);
        conns[id].send_buf.bind(ss, SlicePool::kSliceSize);
        if (capture_region_)
            conns[id].capture_buf = capture_region_ + static_cast<u64>(id) * kCaptureSliceSize;
        return &conns[id];
    }

    bool alloc_h2_impl(Connection& c) {
        if (c.h2) return true;  // already attached
        Http2Conn* h = h2_pool.alloc();
        if (!h) return false;
        c.h2 = h;
        return true;
    }

    void free_conn_impl(Connection& c) {
        u32 cid = c.id;
        timer.remove(&c);
        // Sync backend: kernel is done with buffers. Free immediately.
        if (c.recv_slice) pool.free(c.recv_slice);
        if (c.send_slice) pool.free(c.send_slice);
        if (c.upstream_recv_slice) pool.free(c.upstream_recv_slice);
        if (c.h2) h2_pool.free(c.h2);
        c.reset();
        free_stack[free_top++] = cid;
    }

    bool submit_recv_impl(Connection& c) { return backend.add_recv(c.fd, c.id); }

    bool submit_send_impl(Connection& c, const u8* buf, u32 len) {
        if (c.tls_active) {
            return backend.add_send_tls(c, buf, len);
        }
        return backend.add_send(c.fd, c.id, buf, len);
    }

    bool submit_connect_impl(Connection& c, const void* addr, u32 addr_len) {
        return backend.add_connect(c.upstream_fd, c.id, addr, addr_len);
    }

    bool submit_send_upstream_impl(Connection& c, const u8* buf, u32 len) {
        return backend.add_send_upstream(c.upstream_fd, c.id, buf, len);
    }

    bool submit_recv_upstream_impl(Connection& c) {
        return backend.add_recv_upstream(c.upstream_fd, c.id);
    }

    void pause_upstream_recv_impl(Connection& c) {
        backend.pause_upstream_recv(c.id, c.ws_client_send_pending);
    }

    void close_conn_impl(Connection& c) {
        if (c.req_start_us != 0) epoch_leave();
        // Release any held upstream concurrency slot (catch-all for failure /
        // non-keep-alive completion; the held flag makes a prior release a no-op).
        if (c.upstream_slot_held) {
            upstream_release(c.upstream_slot_uid);
            c.upstream_slot_held = false;
        }
        // If a yield is scheduled, drop its heap entry now so a long wait
        // doesn't keep an unused heap slot occupied until its deadline.
        // Only the pending_handler_fn path can have an entry; no-op
        // otherwise. Rearm in case this conn owned the heap's top.
        if (c.pending_handler_fn) {
            if (yield_heap.remove_by_conn(c.id) > 0) rearm_yield_timerfd();
        }
        if (c.fd >= 0) {
            ::close(c.fd);
            c.fd = -1;
        }
        if (c.tls_active && c.tls) {
            destroy_tls_server_ssl(c.tls);
            c.tls = nullptr;
            c.tls_active = false;
            c.tls_handshake_complete = false;
        }
        if (c.upstream_fd >= 0) {
            ::close(c.upstream_fd);
            c.upstream_fd = -1;
        }
        // Clear upstream fd map to prevent stale fd matching after reuse.
        if (c.id < EpollBackend::kMaxFdMap) backend.upstream_fd_map[c.id] = -1;
        if (c.id < EpollBackend::kMaxFdMap) backend.downstream_fd_map[c.id] = -1;
        // Drop any in-flight partial-send bookkeeping so a reused conn_id+fd
        // cannot resurrect a stale send (see EpollBackend::clear_send_state).
        backend.clear_send_state(c.id);
        if (metrics) {
            if (c.req_start_us != 0) {
                if (metrics->requests_active > 0) metrics->requests_active--;
            }
            metrics->on_close();
        }
        this->free_conn(c);
    }

    // --- Yield timer (ms precision via one-shot timerfd + min-heap) ---

    // Schedule a JIT handler yield wake-up in `ms` milliseconds. Unlike
    // timer.add (1-second resolution, slotted wheel), this pushes an
    // absolute CLOCK_MONOTONIC deadline onto yield_heap and re-arms
    // backend.yield_timer_fd when the heap's top deadline moves earlier.
    // Slots should be cleared before calling — no recv/send in flight.
    //
    // Takes the conn off the keepalive wheel while the precise timer
    // owns its wakeup — otherwise waits longer than keepalive_timeout
    // get resumed early by the wheel's 1-second tick. Keepalive gets
    // re-armed automatically by dispatch()'s timer.refresh when the
    // handler resumes and submits its next I/O.
    //
    // Returns false if the request can't be scheduled faithfully —
    // yield_heap is full AND the wait exceeds what the 1-second wheel
    // fallback can represent (~63s). Caller fails the request.
    [[nodiscard]] bool schedule_yield_timer(Connection& conn, u32 ms) {
        timer.remove(&conn);
        // Epoll is level-triggered: with all callback slots null during
        // yield, an adversarial peer sending bytes while recv_buf is
        // full would keep waking us on EPOLLIN for no work. Suspend
        // recv interest until the next submit_recv rearms it.
        backend.pause_recv(conn.id);
        u64 now = epoll_yield::monotonic_ns();
        u64 deadline = now + static_cast<u64>(ms) * 1'000'000ull;
        if (yield_heap.push(deadline, conn.handler_gen, conn.id)) {
            conn.yield_armed = true;
            rearm_yield_timerfd();
            return true;
        }
        // Heap full — fall back to 1-second timer wheel, but only if
        // the wait fits. 64 slots × 1s: seconds in [1, 63] land
        // faithfully; 64+ would wrap mod-64. Fail the request
        // rather than silently shorten the wait.
        u32 secs = timer_seconds_from_ms(ms);
        if (secs >= TimerWheel::kSlots) return false;
        // Minimum 1 second: wait(0) on the wheel would land in the
        // current slot, which the ongoing tick has already drained —
        // the entry would then sit idle until the wheel wraps (~64s).
        // analyze rejects wait(0) upstream, so this is defence-in-depth.
        if (secs == 0) secs = 1;
        conn.yield_armed = true;
        timer.add(&conn, secs);
        return true;
    }

    // (Re-)arm backend.yield_timer_fd for the current heap top. Called after
    // every push and after every drain. Uses yield_timer_armed_ns to skip
    // redundant timerfd_settime calls.
    void rearm_yield_timerfd() {
        if (yield_heap.empty()) {
            if (yield_timer_armed_ns != 0) {
                backend.arm_yield_timerfd(0);
                yield_timer_armed_ns = 0;
            }
            return;
        }
        u64 top = yield_heap.top().deadline_ns;
        if (top == yield_timer_armed_ns) return;
        backend.arm_yield_timerfd(top);
        yield_timer_armed_ns = top;
    }

    void disarm_yield_timer(Connection& conn) {
        if (!conn.yield_armed) return;
        conn.yield_armed = false;
        conn.yield_timer_gen++;
        timer.remove(&conn);
        if (yield_heap.remove_by_conn(conn.id) > 0) rearm_yield_timerfd();
    }

    // Park a @throttle-paused proxy connection on the precise (sub-second) yield
    // timer for `delay_ns`, reusing the per-shard yield_heap. Tagged with
    // handler_gen so a close+reuse before it fires is filtered as stale on drain.
    // Returns false if the heap is full — the caller falls back to the keepalive
    // wheel (throttle_resume re-checks the budget, so a coarse wake is safe).
    [[nodiscard]] bool arm_throttle_timer(Connection& conn, u64 delay_ns) {
        timer.remove(&conn);  // precise timer owns the wakeup; off the keepalive wheel
        u64 deadline = epoll_yield::monotonic_ns() + delay_ns;
        if (yield_heap.push(deadline, conn.handler_gen, conn.id)) {
            rearm_yield_timerfd();
            return true;
        }
        return false;
    }

    // Drain all heap entries whose deadline has passed. An entry resumes either a
    // @throttle-paused proxy pump or a pending JIT handler (skipping stale entries
    // whose handler_gen no longer matches — the slot was closed and reused before
    // the timer fired).
    void drain_yield_heap() {
        u64 now = epoll_yield::monotonic_ns();
        while (!yield_heap.empty() && yield_heap.top().deadline_ns <= now) {
            auto entry = yield_heap.top();
            yield_heap.pop();
            if (entry.conn_id >= kMaxConns) continue;
            auto& c = conns[entry.conn_id];
            if (c.handler_gen != entry.handler_gen) continue;  // stale
            if (c.throttle_paused) {
                throttle_resume<EpollEventLoop>(this, c);
                continue;
            }
            if (!c.pending_handler_fn) continue;
            if (c.pending_yield_kind != jit::YieldKind::Timer &&
                !yield_kind_matches_event(c.pending_yield_kind, IoEventType::HandlerTimer))
                continue;
            c.yield_armed = false;
            c.resume_event_kind = jit::YieldKind::Timer;
            c.resume_event_result = 0;
            resume_jit_handler<EpollEventLoop>(this, c);
        }
        rearm_yield_timerfd();
    }

    // --- Dispatch ---

    void dispatch(const IoEvent& ev) {
        switch (ev.type) {
            case IoEventType::Accept:
                on_accept(ev);
                break;
            case IoEventType::HandlerTimer:
                // yield_timer_fd expired; drain all entries at/past the
                // current clock.
                drain_yield_heap();
                break;
            case IoEventType::Timeout: {
                i32 ticks = ev.result > 0 ? ev.result : 1;
                const i32 max_ticks = static_cast<i32>(TimerWheel::kSlots);
                if (ticks > max_ticks) ticks = max_ticks;
                for (i32 t = 0; t < ticks; t++) {
                    timer.tick([this](Connection* c) {
                        // A timer can now expire for two reasons:
                        //   (1) keepalive — close the connection (existing).
                        //   (2) a JIT handler yielded with wait(ms), or wait-any
                        //       chose timeout as its completion event.
                        if (c->pending_handler_fn &&
                            (c->pending_yield_kind == jit::YieldKind::Timer ||
                             (c->yield_armed && yield_kind_matches_event(c->pending_yield_kind,
                                                                         IoEventType::Timeout)))) {
                            c->yield_armed = false;
                            c->resume_event_kind = jit::YieldKind::Timer;
                            c->resume_event_result = 0;
                            resume_jit_handler<EpollEventLoop>(this, *c);
                        } else if (c->state == ConnState::Proxying && !c->proxy_resp_started) {
                            // Upstream stalled before responding → 504.
                            respond_upstream_timeout<EpollEventLoop>(this, *c);
                        } else if (c->throttle_paused) {
                            // @throttle: a new byte-rate window has opened — resume
                            // the parked client send.
                            throttle_resume<EpollEventLoop>(this, *c);
#if RUT_ENABLE_WEBSOCKET
                        } else if (c->is_ws_tunnel) {
                            // WebSocket tunnel: no idle keepalive timeout (no-op).
#endif
                        } else {
                            this->close_conn(*c);
                        }
                    });
                }
                if (draining_.load(std::memory_order_acquire)) {
                    u64 start = drain_start_.load(std::memory_order_relaxed);
                    u32 period = drain_period_.load(std::memory_order_relaxed);
                    u64 now = monotonic_secs();
                    for (u32 i = 0; i < kMaxConns; i++) {
                        if (conns[i].fd >= 0 && conns[i].state == ConnState::ReadingHeader &&
                            should_drain_close(i, start, now, period)) {
                            this->close_conn(conns[i]);
                        }
                    }
                }
                break;
            }
            case IoEventType::Recv:
            case IoEventType::Send:
            case IoEventType::UpstreamConnect:
            case IoEventType::UpstreamRecv:
            case IoEventType::UpstreamSend:
                if (ev.conn_id < kMaxConns) {
                    auto& conn = conns[ev.conn_id];
                    if (conn.on_recv || conn.on_send || conn.on_upstream_recv ||
                        conn.on_upstream_send) {
                        // A @throttle-paused connection's timer is owned by the
                        // byte-rate window (refresh(&conn, 1) in the pump gate);
                        // don't let stray events (e.g. a stale -ENOBUFS on the
                        // upstream fd) bump it back to the keepalive timeout, which
                        // would strand the parked pump until keepalive expiry.
                        if (!conn.throttle_paused)
                            timer.refresh(&conn,
                                          conn.state == ConnState::Proxying ? upstream_timeout
                                                                            : keepalive_timeout);
                        this->dispatch_event(conn, ev);
                    } else if (conn.pending_handler_fn) {
                        if (yield_kind_matches_event(conn.pending_yield_kind, ev.type)) {
                            disarm_yield_timer(conn);
                            conn.resume_event_kind = yield_kind_from_event(ev.type);
                            conn.resume_event_result = ev.result;
                            resume_jit_handler<EpollEventLoop>(this, conn);
                            break;
                        }
                        // Mid-yield (all callback slots null while the yield timer
                        // owns the wakeup). Close on terminal recv (peer FIN / RST /
                        // hang-up) so a client disconnect during wait(ms) can't
                        // keep the slot allocated until the deadline fires.
                        // close_conn takes the yield timer down via yield_heap
                        // remove_by_conn in close_conn_impl.
                        if (ev.type == IoEventType::Recv && ev.result <= 0) {
                            this->close_conn(conn);
                        }
                    }
                }
                break;
            case IoEventType::Count:
                break;
        }
    }

private:
    using Self = EpollEventLoop;

    void on_accept(const IoEvent& ev) {
        if (ev.result < 0) return;
        Connection* c = this->alloc_conn();
        if (!c) {
            ::close(ev.result);
            return;
        }
        c->fd = ev.result;
        struct sockaddr_in peer = {};
        socklen_t peer_len = sizeof(peer);
        if (::getpeername(c->fd, reinterpret_cast<struct sockaddr*>(&peer), &peer_len) == 0 &&
            peer.sin_family == AF_INET) {
            c->peer_addr = peer.sin_addr.s_addr;
            c->peer_port = ntohs(peer.sin_port);
        }
        if (tls_server) {
            auto tls_result = create_tls_server_ssl(tls_server, c->fd);
            if (!tls_result) {
                ::close(c->fd);
                c->fd = -1;
                this->free_conn(*c);
                return;
            }
            c->tls_active = true;
            c->tls_handshake_complete = false;
            c->tls = tls_result.value();
        }
        c->state = ConnState::ReadingHeader;
        c->keep_alive = !draining_.load(std::memory_order_relaxed);
        c->on_recv = &on_header_received<Self>;
        timer.add(c, keepalive_timeout);
        if (metrics) metrics->on_accept();
        this->submit_recv(*c);
    }

    void close_listen() {
        if (listen_fd >= 0) {
            backend.cancel_accept();
            ::close(listen_fd);
            listen_fd = -1;
        }
    }

    void force_close_all() {
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0) {
                this->close_conn(conns[i]);
            }
        }
    }
};

}  // namespace rut
