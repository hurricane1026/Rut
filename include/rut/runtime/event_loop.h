#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/callbacks.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/drain.h"
#include "rut/runtime/error.h"
#include "rut/runtime/io_backend.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/metrics.h"
#include "rut/runtime/rate_limit.h"
#include "rut/runtime/shard_control.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/timer_wheel.h"
#include "rut/runtime/tls.h"
#include "rut/runtime/upstream_concurrency.h"
#include <atomic>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/timerfd.h>  // timerfd_settime
#include <unistd.h>       // close()

namespace rut {

// CRTP base — provides submit/close/alloc methods via static dispatch.
// No virtual functions, no vtable, no RTTI. The compiler inlines everything.
//
// Derived must implement:
//   bool submit_recv_impl(Connection& c)
//   bool submit_send_impl(Connection& c, const u8* buf, u32 len)
//   bool submit_connect_impl(Connection& c, const void* addr, u32 addr_len)
//   bool submit_send_upstream_impl(Connection& c, const u8* buf, u32 len)
//   bool submit_recv_upstream_impl(Connection& c)
//   void close_conn_impl(Connection& c)
//   Connection* alloc_conn_impl()
//   void free_conn_impl(Connection& c)

template <typename Derived>
class EventLoopCRTP {
    friend Derived;
    EventLoopCRTP() = default;

    Derived& self() { return static_cast<Derived&>(*this); }

public:
    bool submit_recv(Connection& c) { return self().submit_recv_impl(c); }
    bool submit_send(Connection& c, const u8* buf, u32 len) {
        return self().submit_send_impl(c, buf, len);
    }
    bool submit_connect(Connection& c, const void* addr, u32 addr_len) {
        return self().submit_connect_impl(c, addr, addr_len);
    }
    void close_conn(Connection& c) { self().close_conn_impl(c); }
    Connection* alloc_conn() { return self().alloc_conn_impl(); }
    void free_conn(Connection& c) { self().free_conn_impl(c); }

    // Lazily attach a pooled HTTP/2 engine to a connection (idempotent).
    // Returns false if the per-shard h2 pool is exhausted.
    bool alloc_h2(Connection& c) { return self().alloc_h2_impl(c); }

    // Default: HTTP/2 unsupported (no pool). Concrete loops that serve h2
    // (EpollEventLoop, IoUringEventLoop) hide this with a real implementation;
    // test/mocks and the legacy loop inherit the refusal and fall back to close.
    bool alloc_h2_impl(Connection& /*c*/) { return false; }

    // Upstream I/O: send/recv on upstream_fd instead of fd.
    bool submit_send_upstream(Connection& c, const u8* buf, u32 len) {
        return self().submit_send_upstream_impl(c, buf, len);
    }
    bool submit_recv_upstream(Connection& c) { return self().submit_recv_upstream_impl(c); }

    // Stop watching the upstream fd for readability (used by @throttle to park the
    // proxy body pump between byte-rate windows). On backends with a persistent
    // level-triggered registration (epoll) this disarms EPOLLIN so pending
    // upstream data can't drive the pipeline past the pause; on submission-based
    // backends (io_uring) simply not re-arming the recv is enough, so this is a
    // no-op there. submit_recv_upstream re-arms on resume.
    void pause_upstream_recv(Connection& c) {
        if constexpr (requires { self().pause_upstream_recv_impl(c); }) {
            self().pause_upstream_recv_impl(c);
        }
    }

    // Per-event-type dispatch: route to typed slot.
    // Called from each concrete EventLoop's dispatch() after timer refresh.
    // Centralizes all "unexpected event" handling in one place.
    void dispatch_event(Connection& conn, const IoEvent& ev) {
        switch (ev.type) {
            case IoEventType::Recv:
                if (conn.on_recv) {
                    conn.on_recv(&self(), conn, ev);
                } else {
                    handle_unhandled_recv(conn, ev);
                }
                break;
            case IoEventType::Send:
                if (conn.on_send) conn.on_send(&self(), conn, ev);
                break;
            case IoEventType::UpstreamRecv:
                if (conn.on_upstream_recv) {
                    conn.on_upstream_recv(&self(), conn, ev);
                } else if (ev.result < 0 && conn.state != ConnState::ReadingHeader &&
                           !conn.upstream_abandoned) {
                    // -ENOBUFS: upstream_recv_buf full, close to prevent hot-loop.
                    // Once keep-alive has returned to ReadingHeader, negative
                    // UpstreamRecv CQEs can be stale completions from a just-
                    // closed upstream fd and must not kill the client. Likewise
                    // once we've abandoned the upstream (timeout → 504): the
                    // client send is in flight and stale upstream CQEs are benign.
                    self().close_conn(conn);
                }
                // null + result >= 0: data in upstream_recv_buf, safely ignored.
                break;
            case IoEventType::UpstreamSend:
            case IoEventType::UpstreamConnect:
                if (conn.on_upstream_send) conn.on_upstream_send(&self(), conn, ev);
                break;
            case IoEventType::Accept:
            case IoEventType::Timeout:
            case IoEventType::HandlerTimer:
            case IoEventType::Count:
                break;
        }
    }

    // Handle client Recv when no on_recv handler is set.
    // Centralizes drain/EOF/ENOBUFS logic — written once, correct everywhere.
    void handle_unhandled_recv(Connection& conn, const IoEvent& ev) {
        if (ev.result > 0) {
            if (!conn.keep_alive) conn.recv_buf.reset();
            // Re-arm only when io_uring multishot terminated (!recv_armed).
            // On epoll, recv_armed is always false but EPOLLIN is already
            // armed via EPOLLIN|EPOLLOUT from add_send — calling submit_recv
            // would EPOLL_CTL_MOD to EPOLLIN only, dropping EPOLLOUT and
            // stalling backpressured sends. Check on_send to guard.
            if (!conn.recv_armed && !conn.on_send) self().submit_recv(conn);
            return;
        }
        if (ev.result < 0) {
            self().close_conn(conn);  // -ENOBUFS: prevent busy-loop
            return;
        }
        // EOF: tolerate half-close
    }
};

template <typename Backend>
struct EventLoop : EventLoopCRTP<EventLoop<Backend>> {
    Backend backend;
    TimerWheel timer;
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
    // Cross-thread state — main thread writes (stop/drain), shard thread reads.
    // All access via std::atomic for portability (ARM weak memory model).
    // draining_ is the release/acquire gate: drain_start_/drain_period_ are
    // written with relaxed ordering before draining_ is stored with release,
    // so the shard thread sees consistent values after acquiring draining_.
    std::atomic<bool> running_;
    std::atomic<bool> draining_;
    std::atomic<u64> drain_start_;   // monotonic seconds when drain began
    std::atomic<u32> drain_period_;  // seconds until force-close

public:
    static constexpr u32 kMaxConns = 16384;
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
    static constexpr bool kSupportsEventYieldResume = false;
    SlicePool
        pool;  // per-shard buffer pool (3 slices max per connection: recv + send + upstream_recv)
    Connection conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top;

    // Pending-free list: slots closed during the current dispatch batch.
    // Moved to free_stack (and deferred slices returned to pool) after the
    // next wait() cycle, which submits cancel SQEs and harvests CQEs so
    // the kernel no longer references the buffers.
    u32 pending_free[kMaxConns];
    u32 pending_free_count;

    // Deferred accepts: accepted fds that couldn't be allocated during
    // dispatch because all slots were in pending_free. Retried after the
    // batch finishes and reclaim_pending() frees slots.
    static constexpr u32 kMaxDeferredAccepts = 64;
    i32 deferred_accepts[kMaxDeferredAccepts];
    u32 deferred_accept_addrs[kMaxDeferredAccepts];
    u16 deferred_accept_ports[kMaxDeferredAccepts];
    u32 deferred_accept_count;

    u32 keepalive_timeout = kDefaultKeepaliveTimeout;
    u32 upstream_timeout = kDefaultUpstreamTimeout;
    i32 listen_fd = -1;  // stored for drain: close to stop kernel routing new connections
    TlsServerContext* tls_server = nullptr;

    // Per-shard access log ring. Set by Shard before run(). Null = no logging.
    AccessLogRing* access_log = nullptr;

    // Per-shard traffic capture ring. Use set_capture() to change.
    struct CaptureRing* capture_ring = nullptr;
    static constexpr u32 kCaptureSliceSize = 8192;  // must match CaptureEntry::kMaxHeaderLen
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

    // Per-shard metrics. Set by Shard before run(). Null = no metrics.
    ShardMetrics* metrics = nullptr;

    // Per-shard control plane pointers. Set by Shard::init(), read by
    // poll_command() / epoch_enter() / epoch_leave() on the shard thread.
    // Null = no control plane (standalone EventLoop in tests).
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
        pending_free_count = 0;
        deferred_accept_count = 0;
        timer.init();
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i].reset();
            conns[i].id = i;
            conns[i].shard_id = static_cast<u8>(id);
            free_stack[i] = i;
        }
        // 3 slices max per connection: recv + send + upstream_recv (lazy).
        TRY_VOID(pool.init(kMaxConns * 3, pool_prealloc));
        auto be = backend.init(id, lfd);
        if (!be) {
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
            // Async backend: reclaim closed slots whose CQEs have all been
            // harvested. Runs AFTER dispatch so stale CQEs decrement
            // pending_ops before we check. Then retry any deferred accepts.
            if constexpr (Backend::kAsyncIo) {
                reclaim_pending();
                retry_deferred_accepts();
            }
            poll_command();
            // Close listen fd after dispatching the current batch so any
            // already-queued accepts (epoll backlog) get a proper response
            // with Connection: close, rather than being dropped/reset.
            // Idempotent — only effective on the first drain iteration.
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

    // Poll the per-shard control block. Independent config + JIT slots.
    // Zero-cost when neither flag is set (two atomic loads, both predicted
    // not-taken).
    void poll_command() {
        if (!control) return;
        // Single atomic exchange per slot: read + clear in one op.
        // nullptr = no update; non-null = apply.
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

    // RCU monotonic epoch. Both enter and leave increment, so the control
    // plane can snapshot before a swap and wait for advancement.
    // Zero-cost when epoch pointer is null (no control plane wired).
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
        if constexpr (Backend::kAsyncIo) reclaim_pending();
        backend.shutdown();
        pool.destroy();
        if (capture_region_) {
            munmap(capture_region_, static_cast<u64>(kMaxConns) * kCaptureSliceSize);
            capture_region_ = nullptr;
        }
    }

    // Reclaim a single slot from pending_free by conn_id. Frees slices,
    // pushes to free_stack, and removes from the pending_free array.
    // Called inline from dispatch() when a stale CQE completes reclamation,
    // so a later Accept in the same batch can reuse the slot immediately.
    void reclaim_slot(u32 cid) {
        if (conns[cid].recv_slice) {
            pool.free(conns[cid].recv_slice);
            conns[cid].recv_slice = nullptr;
        }
        if (conns[cid].send_slice) {
            pool.free(conns[cid].send_slice);
            conns[cid].send_slice = nullptr;
        }
        if (conns[cid].upstream_recv_slice) {
            pool.free(conns[cid].upstream_recv_slice);
            conns[cid].upstream_recv_slice = nullptr;
        }
        free_stack[free_top++] = cid;
        // Remove from pending_free (swap with last element).
        for (u32 i = 0; i < pending_free_count; i++) {
            if (pending_free[i] == cid) {
                pending_free[i] = pending_free[--pending_free_count];
                break;
            }
        }
    }

    // CQE-driven reclamation: only reclaim slots whose in-flight I/O has
    // fully completed (pending_ops == 0). Slots still waiting for CQEs
    // remain in pending_free until a future dispatch() decrements their
    // pending_ops to 0.
    void reclaim_pending() {
        u32 remaining = 0;
        for (u32 i = 0; i < pending_free_count; i++) {
            u32 cid = pending_free[i];
            if (conns[cid].pending_ops == 0) {
                if (conns[cid].recv_slice) {
                    pool.free(conns[cid].recv_slice);
                    conns[cid].recv_slice = nullptr;
                }
                if (conns[cid].send_slice) {
                    pool.free(conns[cid].send_slice);
                    conns[cid].send_slice = nullptr;
                }
                if (conns[cid].upstream_recv_slice) {
                    pool.free(conns[cid].upstream_recv_slice);
                    conns[cid].upstream_recv_slice = nullptr;
                }
                free_stack[free_top++] = cid;
            } else {
                pending_free[remaining++] = cid;
            }
        }
        pending_free_count = remaining;
    }

    // Begin graceful drain. New requests get Connection: close.
    // Idle connections are probabilistically closed on each timer tick.
    // After period_secs, force-close all remaining.
    //
    // Called from main thread. Relaxed stores for period/start, then
    // release store on draining_ — shard thread's acquire load on
    // draining_ guarantees it sees consistent period/start values.
    void drain(u32 period_secs) {
        drain_period_.store(period_secs, std::memory_order_relaxed);
        drain_start_.store(monotonic_secs(), std::memory_order_relaxed);
        draining_.store(true, std::memory_order_release);

        // Wake the shard thread if it's blocked in backend.wait().
        // timerfd_settime is async-signal-safe and thread-safe (POSIX).
        // Setting a 1ns expiry fires immediately, causing wait() to return
        // a Timeout event so the run loop can observe draining_ and close_listen().
        if (backend.timer_fd >= 0) {
            struct itimerspec wake = {};
            wake.it_value.tv_nsec = 1;    // fire immediately
            wake.it_interval.tv_sec = 1;  // preserve 1-second periodic tick
            timerfd_settime(backend.timer_fd, 0, &wake, nullptr);
        }
    }

    // Lazy-allocate upstream recv buffer for proxy connections.
    // Only called when a connection starts proxying — non-proxy connections
    // never pay the cost. Returns false if SlicePool is exhausted.
    bool alloc_upstream_buf(ConnectionBase& c) {
        if (c.upstream_recv_slice) return true;  // already allocated
        u8* s = pool.alloc();
        if (!s) return false;
        c.upstream_recv_slice = s;
        c.upstream_recv_buf.bind(s, SlicePool::kSliceSize);
        return true;
    }

    // Clear upstream fd mapping (no-op for legacy template — epoll/iouring
    // concrete loops handle their own fd maps).
    void clear_upstream_fd(u32 /*conn_id*/) {}

    // Number of connections not yet fully reclaimed.
    // Includes pending_free slots: they're closed but still waiting for
    // CQEs, so drain must keep running until they're reclaimed too.
    u32 active_count() const { return kMaxConns - free_top; }

    // --- CRTP implementations ---

    Connection* alloc_conn_impl() {
        if (free_top == 0) return nullptr;
        // Allocate buffer slices from pool before committing the conn slot.
        u8* rs = pool.alloc();
        u8* ss = pool.alloc();
        if (!rs || !ss) {
            if (rs) pool.free(rs);
            if (ss) pool.free(ss);
            return nullptr;  // pool exhausted — back-pressure
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

    void free_conn_impl(Connection& c) {
        u32 cid = c.id;
        timer.remove(&c);
        if constexpr (Backend::kAsyncIo) {
            // Async backend (io_uring): if no ops are in flight (the close
            // was triggered by the final CQE), reclaim immediately — no
            // need to defer. This avoids blocking alloc_conn at saturation
            // when a close and accept arrive in the same dispatch batch.
            if (c.pending_ops == 0) {
                if (c.recv_slice) pool.free(c.recv_slice);
                if (c.send_slice) pool.free(c.send_slice);
                if (c.upstream_recv_slice) pool.free(c.upstream_recv_slice);
                c.reset();
                free_stack[free_top++] = cid;
                return;
            }
            // Ops still in flight: defer until CQEs arrive and pending_ops
            // reaches 0 in reclaim_pending().
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
        } else {
            // Sync backend (epoll): kernel is done with buffers when
            // read/write returns. Return slices to pool immediately.
            if (c.recv_slice) pool.free(c.recv_slice);
            if (c.send_slice) pool.free(c.send_slice);
            if (c.upstream_recv_slice) pool.free(c.upstream_recv_slice);
            c.reset();
            free_stack[free_top++] = cid;
        }
    }

    bool submit_recv_impl(Connection& c) {
        if constexpr (Backend::kAsyncIo) {
            // Multishot recv stays armed across keep-alive cycles.
            // Skip re-submit to avoid inflating pending_ops.
            if (c.recv_armed) return true;
        }
        if (backend.add_recv(c.fd, c.id)) {
            if constexpr (Backend::kAsyncIo) {
                c.pending_ops++;
                c.recv_armed = true;
            }
            return true;
        }
        return false;
    }
    bool submit_send_impl(Connection& c, const u8* buf, u32 len) {
        if constexpr (requires(Backend& be, Connection& conn, const u8* ptr, u32 n) {
                          be.add_send_tls(conn, ptr, n);
                      }) {
            if (c.tls_active) {
                if (backend.add_send_tls(c, buf, len)) return true;
            }
        }
        if (backend.add_send(c.fd, c.id, buf, len)) {
            if constexpr (Backend::kAsyncIo) {
                c.pending_ops++;
                c.send_armed = true;
            }
            return true;
        }
        return false;
    }
    bool submit_connect_impl(Connection& c, const void* addr, u32 addr_len) {
        if (backend.add_connect(c.upstream_fd, c.id, addr, addr_len)) {
            if constexpr (Backend::kAsyncIo) c.pending_ops++;
            return true;
        }
        return false;
    }
    bool submit_send_upstream_impl(Connection& c, const u8* buf, u32 len) {
        if (backend.add_send_upstream(c.upstream_fd, c.id, buf, len)) {
            if constexpr (Backend::kAsyncIo) {
                c.pending_ops++;
                c.upstream_send_armed = true;
            }
            return true;
        }
        return false;
    }
    void pause_upstream_recv_impl(Connection& c) {
        if constexpr (requires { backend.pause_upstream_recv(c.id); }) {
            backend.pause_upstream_recv(c.id);
        }
        if constexpr (Backend::kAsyncIo) c.upstream_recv_armed = false;
    }
    bool submit_recv_upstream_impl(Connection& c) {
        if constexpr (Backend::kAsyncIo) {
            if (c.upstream_recv_armed) return true;
        }
        if (backend.add_recv_upstream(c.upstream_fd, c.id)) {
            if constexpr (Backend::kAsyncIo) {
                c.pending_ops++;
                c.upstream_recv_armed = true;
            }
            return true;
        }
        return false;
    }

    void close_conn_impl(Connection& c) {
        // If a request was in flight (epoch_enter called), leave the epoch
        // before closing. This covers timer wheel timeouts, force_close_all
        // during drain, and any other path that bypasses normal callbacks.
        if (c.req_start_us != 0) epoch_leave();
        // Release any held upstream concurrency slot (catch-all; idempotent via
        // the held flag).
        if (c.upstream_slot_held) {
            upstream_release(c.upstream_slot_uid);
            c.upstream_slot_held = false;
        }
        if constexpr (Backend::kAsyncIo) {
            // Only cancel when ops are in flight. If pending_ops == 0,
            // the slot is freed immediately — no cancels needed.
            // Add cancel count to pending_ops so the slot isn't reclaimed
            // until all cancel CQEs have been processed.
            if (c.pending_ops > 0) {
                c.pending_ops += backend.cancel(c.fd,
                                                c.id,
                                                c.recv_armed,
                                                c.send_armed,
                                                c.upstream_recv_armed,
                                                c.upstream_send_armed,
                                                c.upstream_fd >= 0);
            }
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
        if (metrics) {
            // If a request was in flight (started but not completed),
            // decrement requests_active to avoid a permanent leak.
            if (c.req_start_us != 0) {
                if (metrics->requests_active > 0) metrics->requests_active--;
            }
            metrics->on_close();
        }
        this->free_conn(c);
    }

    // --- Dispatch ---

    void dispatch(const IoEvent& ev) {
        switch (ev.type) {
            case IoEventType::Accept:
                // During drain: still accept queued connections so they get a
                // proper response with Connection: close, rather than a TCP RST.
                // on_accept() sets keep_alive=false when draining_ is true.
                on_accept(ev);
                break;
            case IoEventType::Timeout: {
                // ev.result carries timerfd tick count — may be >1 if loop stalled.
                // Advance timer wheel once per accumulated tick to avoid skipping expirations.
                i32 ticks = ev.result > 0 ? ev.result : 1;
                const i32 max_ticks = static_cast<i32>(TimerWheel::kSlots);
                if (ticks > max_ticks) ticks = max_ticks;  // clamp to wheel size
                for (i32 t = 0; t < ticks; t++) {
                    timer.tick([this](Connection* c) {
                        if (c->state == ConnState::Proxying && !c->proxy_resp_started) {
                            respond_upstream_timeout(this, *c);  // upstream stalled → 504
                        } else if (c->throttle_paused) {
                            throttle_resume(this, *c);  // @throttle: resume next window
                        } else {
                            this->close_conn(*c);
                        }
                    });
                }

                // During drain: probabilistically close idle connections.
                // ReadingHeader = waiting for next request on keep-alive (effectively idle).
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
            case IoEventType::HandlerTimer:
                if (ev.conn_id < kMaxConns) {
                    auto& conn = conns[ev.conn_id];
                    if constexpr (Backend::kAsyncIo) {
                        // Decrement pending_ops only on the final CQE for this op.
                        // Multishot recv (IORING_RECV_MULTISHOT) sets ev.more on
                        // intermediate CQEs — the SQE stays armed, so the op is
                        // still in-flight and must not be counted as complete.
                        if (!ev.more) {
                            if (conn.pending_ops > 0) conn.pending_ops--;
                            // Multishot recv ended — clear the armed flag using
                            // event type (not state) to distinguish client vs upstream.
                            if (ev.type == IoEventType::Recv) conn.recv_armed = false;
                            if (ev.type == IoEventType::Send) conn.send_armed = false;
                            if (ev.type == IoEventType::UpstreamSend)
                                conn.upstream_send_armed = false;
                            if (ev.type == IoEventType::UpstreamRecv)
                                conn.upstream_recv_armed = false;
                        }
                    }
                    if (conn.on_recv || conn.on_send || conn.on_upstream_recv ||
                        conn.on_upstream_send) {
                        // See EpollEventLoop: don't let stray events bump a
                        // @throttle-paused connection's byte-rate-window timer back
                        // to the keepalive timeout.
                        if (!conn.throttle_paused) timer.refresh(&conn, conn.state == ConnState::Proxying ? upstream_timeout
                                                            : keepalive_timeout);
                        this->dispatch_event(conn, ev);
                    } else if constexpr (Backend::kAsyncIo) {
                        // Stale CQE for a closed connection. If all ops are now
                        // complete, reclaim the slot immediately so a later Accept
                        // in the same batch can reuse it (avoids dropping connections
                        // at saturation).
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

    // Legacy EventLoop<Backend> predates the JIT-yield primitive; it lacks
    // the HandlerTimer dispatch path that EpollEventLoop / IoUringEventLoop
    // implement. Returning false from schedule_yield_timer makes
    // handle_jit_outcome::TimerYield respond 500 instead of hanging.
    // Remove this stub if/when the legacy loop gains real yield support.
    [[nodiscard]] bool schedule_yield_timer(Connection& /*conn*/, u32 /*ms*/) { return false; }

private:
    using Self = EventLoop<Backend>;

    void on_accept(const IoEvent& ev) {
        if (ev.result < 0) return;
        i32 fd = ev.result;
        u32 peer_addr = 0;
        u16 peer_port = 0;
        struct sockaddr_in peer = {};
        socklen_t peer_len = sizeof(peer);
        if (::getpeername(fd, reinterpret_cast<struct sockaddr*>(&peer), &peer_len) == 0 &&
            peer.sin_family == AF_INET) {
            peer_addr = peer.sin_addr.s_addr;
            peer_port = ntohs(peer.sin_port);
        }
        Connection* c = this->alloc_conn();
        if (!c) {
            if constexpr (Backend::kAsyncIo) {
                // Try reclaiming slots from stale CQEs earlier in this batch.
                reclaim_pending();
                c = this->alloc_conn();
                if (!c) {
                    // Still no slot — a later CQE in this batch may free one.
                    // Defer the accept fd and retry after the batch finishes.
                    if (deferred_accept_count < kMaxDeferredAccepts) {
                        deferred_accepts[deferred_accept_count] = fd;
                        deferred_accept_addrs[deferred_accept_count] = peer_addr;
                        deferred_accept_ports[deferred_accept_count] = peer_port;
                        deferred_accept_count++;
                    } else {
                        ::close(fd);
                    }
                    return;
                }
            } else {
                ::close(fd);
                return;
            }
        }
        c->fd = fd;
        c->peer_addr = peer_addr;
        c->peer_port = peer_port;
        if (tls_server) {
            auto tls_result = create_tls_server_ssl(tls_server, fd);
            if (!tls_result) {
                ::close(fd);
                this->free_conn(*c);
                return;
            }
            c->tls_active = true;
            c->tls_handshake_complete = false;
            c->tls = tls_result.value();
        }
        c->state = ConnState::ReadingHeader;
        // During drain: mark new connections for close after first response.
        c->keep_alive = !draining_.load(std::memory_order_relaxed);
        c->on_recv = &on_header_received<Self>;
        timer.add(c, keepalive_timeout);
        if (metrics) metrics->on_accept();
        this->submit_recv(*c);
    }

    // Retry accepts that were deferred because no slot was available
    // during the dispatch batch. Now that reclaim_pending() has run,
    // slots may have become available.
    void retry_deferred_accepts() {
        for (u32 i = 0; i < deferred_accept_count; i++) {
            i32 fd = deferred_accepts[i];
            Connection* c = this->alloc_conn();
            if (!c) {
                ::close(fd);
                continue;
            }
            c->fd = fd;
            c->peer_addr = deferred_accept_addrs[i];
            c->peer_port = deferred_accept_ports[i];
            if (tls_server) {
                auto tls_result = create_tls_server_ssl(tls_server, fd);
                if (!tls_result) {
                    ::close(fd);
                    c->fd = -1;
                    this->free_conn(*c);
                    continue;
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
        deferred_accept_count = 0;
    }

    // Stop accepting new connections: cancel the backend's accept request
    // (required for io_uring multishot) then close the listen socket.
    void close_listen() {
        if (listen_fd >= 0) {
            backend.cancel_accept();
            ::close(listen_fd);
            listen_fd = -1;
        }
    }

    // Force-close all active connections (drain deadline exceeded).
    void force_close_all() {
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0) {
                this->close_conn(conns[i]);
            }
        }
    }
};

}  // namespace rut
