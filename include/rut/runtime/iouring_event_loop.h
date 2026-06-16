#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/callbacks.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/drain.h"
#include "rut/runtime/error.h"
#include "rut/runtime/event_loop.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/io_backend.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/io_uring_backend.h"
#include "rut/runtime/jit_dispatch.h"
#include "rut/runtime/metrics.h"
#include "rut/runtime/shard_control.h"
#include "rut/runtime/slab_pool.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/timer_wheel.h"
#include <atomic>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace rut {

// IoUringEventLoop — concrete, non-template event loop for io_uring backend.
//
// io_uring is asynchronous: the kernel may still reference user buffers
// between SQE submission and CQE completion. This loop tracks pending_ops
// per connection and defers slice reclamation until all in-flight CQEs
// have been harvested. Includes armed flag management, cancel SQE tracking,
// deferred accepts, and reclaim_pending/reclaim_slot machinery.
struct IoUringEventLoop : EventLoopCRTP<IoUringEventLoop> {
    IoUringBackend backend;
    TimerWheel timer;
    u32 shard_id;
    // Total shards in this process (1 in tests). Used to scale a Global-scope
    // rate limit to a per-shard share (ceil(max / shard_count)).
    u32 shard_count = 1;

private:
    std::atomic<bool> running_;
    std::atomic<bool> draining_;
    std::atomic<u64> drain_start_;
    std::atomic<u32> drain_period_;

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
    SlicePool pool;
    // Per-shard HTTP/2 engine pool (see EpollEventLoop). Lazily handed out on
    // h2 upgrade; bounded, over-cap upgrades close the connection.
    static constexpr u32 kH2PoolCap = 2048;
    SlabPool<Http2Conn, kH2PoolCap> h2_pool;
    Connection conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top;

    // Pending-free list: slots closed during the current dispatch batch.
    u32 pending_free[kMaxConns];
    u32 pending_free_count;

    // Deferred accepts: accepted fds that couldn't be allocated during
    // dispatch because all slots were in pending_free.
    static constexpr u32 kMaxDeferredAccepts = 64;
    i32 deferred_accepts[kMaxDeferredAccepts];
    u32 deferred_accept_count;

    u32 keepalive_timeout = kDefaultKeepaliveTimeout;
    u32 upstream_timeout = kDefaultUpstreamTimeout;
    i32 listen_fd = -1;

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
            reclaim_pending();
            retry_deferred_accepts();
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
        reclaim_pending();
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
    // No-op for io_uring (no fd_map to clear).
    void clear_upstream_fd(u32 /*conn_id*/) {}

    // never pay the cost. Returns false if SlicePool is exhausted.
    bool alloc_upstream_buf(ConnectionBase& c) {
        if (c.upstream_recv_slice) return true;  // already allocated
        u8* s = pool.alloc();
        if (!s) return false;
        c.upstream_recv_slice = s;
        c.upstream_recv_buf.bind(s, SlicePool::kSliceSize);
        return true;
    }

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

    // --- CRTP implementations (io_uring: async, with armed/pending_ops) ---

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
        // The h2 engine is a pool object, not a kernel buffer — safe to reclaim
        // now even with ops in flight (unlike the recv/send slices below).
        if (c.h2) {
            h2_pool.free(c.h2);
            c.h2 = nullptr;
        }
        // If no ops are in flight, reclaim immediately.
        if (c.pending_ops == 0) {
            if (c.recv_slice) pool.free(c.recv_slice);
            if (c.send_slice) pool.free(c.send_slice);
            if (c.upstream_recv_slice) pool.free(c.upstream_recv_slice);
            c.reset();
            free_stack[free_top++] = cid;
            return;
        }
        // Ops still in flight: defer until CQEs arrive.
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

    bool submit_recv_impl(Connection& c) {
        if (c.recv_paused_for_send) {
            c.recv_pause_rearm_pending = true;
            return true;
        }
        if (c.recv_armed) {
            if (c.recv_pause_cancel_pending) c.recv_pause_rearm_pending = true;
            return true;
        }
        if (backend.add_recv(c.fd, c.id)) {
            c.pending_ops++;
            c.recv_armed = true;
            c.recv_pause_rearm_pending = false;
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

    bool submit_connect_impl(Connection& c, const void* addr, u32 addr_len) {
        if (backend.add_connect(c.upstream_fd, c.id, addr, addr_len)) {
            c.pending_ops++;
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

    // io_uring only recvs when an SQE is submitted, so not re-arming the recv
    // (which throttle_pause_before_pump achieves by returning early) is enough to
    // backpressure the upstream. Just ensure the armed flag is clear so resume
    // re-submits the recv. No in-flight recv exists at a pump point.
    void pause_upstream_recv_impl(Connection& c) { c.upstream_recv_armed = false; }

    bool pause_recv(Connection& c) {
        c.recv_paused_for_send = true;
        c.recv_pause_cancel_pending = true;
        if (!c.recv_armed) return true;
        return backend.pause_recv(c.fd, c.id);
    }

    void close_conn_impl(Connection& c) {
        if (c.req_start_us != 0) epoch_leave();
        // Only cancel when ops are in flight.
        if (c.pending_ops > 0) {
            c.pending_ops += backend.cancel(c.fd,
                                            c.id,
                                            c.recv_armed,
                                            c.send_armed,
                                            c.upstream_recv_armed,
                                            c.upstream_send_armed,
                                            c.upstream_fd >= 0,
                                            c.yield_timeout_armed,
                                            c.yield_timer_gen);
        }
        if (c.fd >= 0) {
            ::close(c.fd);
            c.fd = -1;
        }
        if (c.upstream_fd >= 0) {
            ::close(c.upstream_fd);
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

    // --- Dispatch ---

    // Schedule a JIT handler yield timer via IORING_OP_TIMEOUT. ms
    // precision — kernel drives the timer, CQE arrives as IoEvent with
    // type=HandlerTimer carrying conn_id. Slots should already be
    // cleared before calling (no recv/send in flight while waiting).
    //
    // Takes the conn off the keepalive wheel while the precise timer
    // owns its wakeup — otherwise waits longer than keepalive_timeout
    // get resumed early by the wheel's 1-second tick.
    //
    // Falls back to the 1-second wheel if the SQ is full; the wheel
    // tick callback checks pending_handler_fn and resumes from there,
    // degrading precision but preserving liveness.
    //
    // On success, increments pending_ops and sets yield_armed so
    // close_conn_impl will submit a cancel SQE — keeping the slot
    // pinned until the timer's CQE is harvested, so a late stale
    // HandlerTimer can't resume a handler on a reused slot.
    //
    // Returns false if no timer could be scheduled faithfully: under
    // catastrophic SQ pressure (IORING_OP_TIMEOUT fails even after
    // flush+retry) AND the requested wait exceeds what the 1-second
    // wheel fallback can represent (~63s). Caller fails the request.
    [[nodiscard]] bool schedule_yield_timer(Connection& conn, u32 ms) {
        timer.remove(&conn);
        // Ensure a recv is in flight so peer disconnect during wait(ms)
        // produces a CQE the mid-yield dispatch branch can close on.
        // submit_recv is idempotent (checks recv_armed), so this is a
        // no-op when multishot is still running. It matters when the
        // prior multishot terminated with !ev.more before this yield
        // (e.g., buffer-ring edge case) and would otherwise leave no
        // in-flight recv to surface a silent client FIN.
        this->submit_recv(conn);
        // submit_recv silently no-ops under SQ pressure (add_recv fails
        // with no retry). If recv still isn't armed, we'd sleep without
        // a disconnect detector — fail the request instead of leaking
        // the slot until the yield deadline expires.
        if (!conn.recv_armed) return false;
        // NOTE: we deliberately do NOT cancel the multishot recv here.
        // A cancel SQE would make the canceled target's -ECANCELED CQE
        // arrive after the handler resumes and re-sets on_recv, where
        // it would be interpreted as a peer close and kill the
        // connection (or break keep-alive). The dispatch-level
        // pending_handler_fn branch closes on any mid-yield recv CQE,
        // so an adversarial peer can't exhaust buffers or silently
        // inject data.
        if (backend.add_yield_timeout(conn.id, conn, ms)) {
            conn.yield_armed = true;
            conn.yield_timeout_armed = true;
            conn.pending_ops++;
            return true;
        }
        // Catastrophic SQ pressure — add_yield_timeout already did one
        // flush+retry. Fall back to the 1-second wheel, but only if
        // the wait actually fits: 64 slots × 1s, so seconds in
        // [1, 63] land faithfully; seconds 64+ would wrap mod-64 and
        // fire far too early. Fail the request rather than shorten.
        u32 secs = timer_seconds_from_ms(ms);
        if (secs >= TimerWheel::kSlots) return false;
        // Minimum 1 second: wait(0) on the wheel would land in the
        // current slot, which the ongoing tick has already drained —
        // the entry would then sit idle until the wheel wraps (~64s).
        // analyze rejects wait(0) upstream, so this is defence-in-depth.
        if (secs == 0) secs = 1;
        conn.yield_armed = true;
        conn.yield_timeout_armed = false;
        timer.add(&conn, secs);
        return true;
    }

    void disarm_yield_timer(Connection& conn) {
        if (!conn.yield_armed) return;
        const u32 old_gen = conn.yield_timer_gen;
        const bool timeout_armed = conn.yield_timeout_armed;
        conn.yield_armed = false;
        conn.yield_timeout_armed = false;
        conn.yield_timer_gen++;
        timer.remove(&conn);
        if (timeout_armed) (void)backend.cancel_yield_timeout(conn.id, old_gen);
    }

    void dispatch(const IoEvent& ev) {
        switch (ev.type) {
            case IoEventType::Accept:
                on_accept(ev);
                break;
            case IoEventType::HandlerTimer:
                // JIT handler yield timer fired (or was cancelled — same
                // resume path; any error bubbles through the handler).
                //
                // Decrement pending_ops unconditionally: IORING_OP_TIMEOUT
                // never sets CQE_F_MORE, and the cancel SQE submitted in
                // close_conn_impl shares this user_data — both CQEs route
                // here and must each decrement. yield_armed can't gate this
                // because free_conn_impl::reset() clears the flag when a
                // close lands while the timer is in flight.
                if (ev.conn_id < kMaxConns) {
                    auto& c = conns[ev.conn_id];
                    if (c.pending_ops > 0) c.pending_ops--;
                    const bool matching_generation =
                        ev.result == static_cast<i32>(c.yield_timer_gen);
                    const bool was_yield_armed = c.yield_armed;
                    if (matching_generation) {
                        c.yield_armed = false;
                        c.yield_timeout_armed = false;
                    }
                    if (c.pending_handler_fn && matching_generation &&
                        (c.pending_yield_kind == jit::YieldKind::Timer ||
                         (was_yield_armed &&
                          yield_kind_matches_event(c.pending_yield_kind,
                                                   IoEventType::HandlerTimer)))) {
                        c.resume_event_kind = jit::YieldKind::Timer;
                        c.resume_event_result = 0;
                        resume_jit_handler<IoUringEventLoop>(this, c);
                    } else if (c.pending_ops == 0 && !c.pending_handler_fn && c.fd < 0) {
                        // Stale CQE for an already-closed slot; safe to
                        // reclaim now that the last in-flight op has drained.
                        reclaim_slot(ev.conn_id);
                    }
                }
                break;
            case IoEventType::Timeout: {
                i32 ticks = ev.result > 0 ? ev.result : 1;
                const i32 max_ticks = static_cast<i32>(TimerWheel::kSlots);
                if (ticks > max_ticks) ticks = max_ticks;
                for (i32 t = 0; t < ticks; t++) {
                    timer.tick([this](Connection* c) {
                        // See epoll_event_loop.h: timer fires for keepalive,
                        // wait(ms), or wait-any timeout completion.
                        if (c->pending_handler_fn &&
                            (c->pending_yield_kind == jit::YieldKind::Timer ||
                             (c->yield_armed && yield_kind_matches_event(c->pending_yield_kind,
                                                                         IoEventType::Timeout)))) {
                            c->yield_armed = false;
                            c->yield_timeout_armed = false;
                            c->resume_event_kind = jit::YieldKind::Timer;
                            c->resume_event_result = 0;
                            resume_jit_handler<IoUringEventLoop>(this, *c);
                        } else if (c->state == ConnState::Proxying && !c->proxy_resp_started) {
                            // Upstream stalled before responding → 504.
                            respond_upstream_timeout<IoUringEventLoop>(this, *c);
                        } else if (c->throttle_paused) {
                            throttle_resume<IoUringEventLoop>(this, *c);
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
                    // Send-wait recv pause: pause_recv() cancels the multishot
                    // recv before a non-empty wait(downstream.send()). Only the
                    // terminal -ECANCELED CQE is special-cased here (flag reset
                    // + optional rearm). A *positive* recv CQE that was already
                    // harvested into recv_buf before the cancel took effect is
                    // deliberately NOT suppressed: those bytes are always past
                    // the current request's framing (needs_req_body buffers the
                    // full Content-Length body before the handler can yield, and
                    // chunked bodies are rejected with 400), so they are the
                    // next pipelined request. Every request accessor re-parses
                    // req_data and bounds its output to the first request
                    // (rut_helper_req_body caps at content_length, path/method/
                    // header to the first request's line/block), so the larger
                    // req_len is inert — no route value can observe the raced
                    // bytes. Dropping them would instead corrupt HTTP/1.1
                    // pipelining, and would diverge from the timer/upstream wait
                    // contract that intentionally keeps such bytes (see the
                    // mid-yield stray-CQE handling below). The pause is thus
                    // best-effort liveness/buffer-pressure defence, not a hard
                    // data barrier the residual in-flight CQE could breach.
                    if (ev.type == IoEventType::Recv && ev.result == -ECANCELED &&
                        conn.recv_pause_cancel_pending) {
                        const bool needs_recv_rearm = conn.recv_pause_rearm_pending;
                        conn.recv_pause_rearm_pending = false;
                        conn.recv_pause_cancel_pending = false;
                        conn.recv_armed = false;
                        if (conn.pending_ops > 0) conn.pending_ops--;
                        if (needs_recv_rearm && !conn.recv_paused_for_send) {
                            if (!this->submit_recv_impl(conn)) {
                                this->close_conn(conn);
                                break;
                            }
                        }
                        break;
                    }
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
                        // See EpollEventLoop: don't let stray events bump a
                        // @throttle-paused connection's byte-rate-window timer back
                        // to the keepalive timeout.
                        if (!conn.throttle_paused) timer.refresh(&conn, conn.state == ConnState::Proxying ? upstream_timeout
                                                            : keepalive_timeout);
                        if (ev.type == IoEventType::Send) conn.recv_paused_for_send = false;
                        this->dispatch_event(conn, ev);
                    } else if (conn.pending_handler_fn) {
                        if (yield_kind_matches_event(conn.pending_yield_kind, ev.type)) {
                            if (ev.type == IoEventType::Send) conn.recv_paused_for_send = false;
                            disarm_yield_timer(conn);
                            conn.resume_event_kind = yield_kind_from_event(ev.type);
                            conn.resume_event_result = ev.result;
                            resume_jit_handler<IoUringEventLoop>(this, conn);
                            break;
                        }
                        // Stray CQE for a conn that's mid-yield (all slots null
                        // while the timer owns the wakeup). Provided-buffer
                        // lifetime is already handled inside
                        // IoUringBackend::wait(); this branch only decides
                        // whether the stray completion should terminate the
                        // connection.
                        //
                        // Rules:
                        //   - ev.result > 0                 → keep alive. Bytes
                        //     the peer sends during wait(ms) — segmented body,
                        //     pipelined next request — are contractually noise
                        //     for slice 0 (analyze rejects the patterns where
                        //     they'd be meaningful). Killing here would punish
                        //     legitimate clients.
                        //   - ev.result == 0 && !ev.more    → peer FIN. Close.
                        //   - ev.result < 0 (non-CANCEL)    → recv error,
                        //     including -ENOBUFS when recv_buf fills. On older
                        //     kernels -ENOBUFS can arrive with ev.more still set,
                        //     so relying on !ev.more here would let the loop
                        //     hot-spin on repeated error CQEs until the yield
                        //     deadline fires. Close unconditionally.
                        const bool kRecvError = (ev.type == IoEventType::Recv && ev.result < 0 &&
                                                 ev.result != -ECANCELED);
                        const bool kPeerClose =
                            (ev.type == IoEventType::Recv && !ev.more && ev.result == 0);
                        if (kRecvError || kPeerClose) {
                            this->close_conn(conn);
                        } else if (ev.type == IoEventType::Recv && !ev.more && ev.result > 0) {
                            // Positive-data terminal CQE: multishot ended (the
                            // generic accounting above cleared recv_armed).
                            // Re-arm so a subsequent peer disconnect during the
                            // remaining wait(ms) still produces a CQE and
                            // reaches the close_conn branch — otherwise the
                            // slot would sit occupied until the yield deadline.
                            this->submit_recv(conn);
                        }
                    } else if (conn.pending_ops == 0) {
                        // Stale CQE for a genuinely closed connection.
                        reclaim_slot(ev.conn_id);
                    }
                }
                break;
            case IoEventType::Count:
                break;
        }
    }

private:
    using Self = IoUringEventLoop;

    void on_accept(const IoEvent& ev) {
        if (ev.result < 0) return;
        Connection* c = this->alloc_conn();
        if (!c) {
            // Try reclaiming slots from stale CQEs.
            reclaim_pending();
            c = this->alloc_conn();
            if (!c) {
                // Defer the accept fd and retry after the batch finishes.
                if (deferred_accept_count < kMaxDeferredAccepts) {
                    deferred_accepts[deferred_accept_count++] = ev.result;
                } else {
                    ::close(ev.result);
                }
                return;
            }
        }
        c->fd = ev.result;
        struct sockaddr_in peer = {};
        socklen_t peer_len = sizeof(peer);
        if (::getpeername(c->fd, reinterpret_cast<struct sockaddr*>(&peer), &peer_len) == 0 &&
            peer.sin_family == AF_INET) {
            c->peer_addr = peer.sin_addr.s_addr;
            c->peer_port = ntohs(peer.sin_port);
        }
        c->state = ConnState::ReadingHeader;
        c->keep_alive = !draining_.load(std::memory_order_relaxed);
        c->on_recv = &on_header_received<Self>;
        timer.add(c, keepalive_timeout);
        if (metrics) metrics->on_accept();
        this->submit_recv(*c);
    }

    void retry_deferred_accepts() {
        for (u32 i = 0; i < deferred_accept_count; i++) {
            i32 fd = deferred_accepts[i];
            Connection* c = this->alloc_conn();
            if (!c) {
                ::close(fd);
                continue;
            }
            c->fd = fd;
            struct sockaddr_in peer = {};
            socklen_t peer_len = sizeof(peer);
            if (::getpeername(c->fd, reinterpret_cast<struct sockaddr*>(&peer), &peer_len) == 0 &&
                peer.sin_family == AF_INET) {
                c->peer_addr = peer.sin_addr.s_addr;
                c->peer_port = ntohs(peer.sin_port);
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
