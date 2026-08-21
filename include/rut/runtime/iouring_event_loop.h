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
#include "rut/runtime/rate_limit.h"
#include "rut/runtime/shard_control.h"
#include "rut/runtime/slab_pool.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/timer_wheel.h"
#include "rut/runtime/tls.h"
#include "rut/runtime/tls_iouring.h"
#include "rut/runtime/upstream_concurrency.h"
#include "rut/runtime/upstream_pool.h"
#include <atomic>

#include <netinet/in.h>
#include <sys/mman.h>
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
    u32 shard_id = 0;
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
    static constexpr u32 kMaxConns = 16384;
    // Active health-check probing requires synchronous probe teardown; the
    // io_uring loop doesn't support that yet, so sweep_health_probes only re-arms
    // deadlines here and issues no connects (epoll-only this slice).
    static constexpr bool kSupportsHealthProbe = false;
    static constexpr u32 kTlsInputSize = SlicePool::kSliceSize + 1024;
    // Owned ciphertext output buffer + watermark backpressure for proxy-over-TLS
    // streaming on io_uring. See docs/iouring-tls-output-buffer.md.
    static constexpr u32 kTlsRecordMax =
        SlicePool::kSliceSize + 256;  // 1 chunk's worst-case ciphertext
    static constexpr u32 kTlsOutBufCap =
        4 * SlicePool::kSliceSize;  // 64 KiB — bounded throughput knob
    static constexpr u32 kTlsOutHigh =
        kTlsOutBufCap - kTlsRecordMax;                    // pause upstream recv above this
    static constexpr u32 kTlsOutLow = kTlsOutBufCap / 4;  // resume below this
    static constexpr u32 kTlsDrainChunk =
        SlicePool::kSliceSize;  // a raw send submits ≤ this at once
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
    // TLS server context (cert/key/ALPN). When set, accepted connections
    // terminate TLS via the event-loop TlsEngine (see tls_iouring.h). Null =
    // plaintext. Mirrors EpollEventLoop::tls_server.
    TlsServerContext* tls_server = nullptr;
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
    // Normally zero. A strict retirement cancel that could not acquire an SQE
    // is retried before the next blocking wait; the count avoids scanning the
    // full connection table on the ordinary hot path.
    u32 upstream_retirement_retry_count;
    // Set only when exact rendezvous owners make at least one parked HTTP/1
    // boundary eligible. The ordinary hot path avoids a connection-table scan;
    // the run loop consumes this after the complete wait batch.
    bool http1_boundary_ready_pending;

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
    // Per-shard idle upstream connection pool (HTTP/1 keep-alive reuse). Wired by
    // the shard; null in tests/mocks that don't exercise reuse.
    UpstreamPool* upstream = nullptr;

    const RouteConfig** config_ptr = nullptr;
    ShardControlBlock* control = nullptr;
    ShardEpoch* epoch = nullptr;
    void** jit_code_ptr = nullptr;

    core::Expected<void, Error> init(u32 id, i32 lfd, u32 pool_prealloc = 0) {
        shard_id = id;
        listen_fd = lfd;
        this->listener_context = {};
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
        upstream_retirement_retry_count = 0;
        http1_boundary_ready_pending = false;
        deferred_accept_count = 0;
        timer.init();
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i].reset();
            conns[i].id = i;
            conns[i].shard_id = static_cast<u8>(id);
            free_stack[i] = i;
        }
        // Plaintext needs recv + send + lazy upstream_recv. TLS termination adds
        // one long-lived ciphertext output slice per connection. TLS input uses
        // a slightly larger mmap buffer so one full ciphertext record fits.
        // tls_server is wired after init(), so reserve for the TLS-capable case.
        TRY_VOID(pool.init(kMaxConns * 6, pool_prealloc));
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
        // Arm timer deadlines from activation (config is installed before run()),
        // so `every: D` measures from here rather than from the first 1s tick.
        this->fire_due_timers();
        // Reset/arm active-health state at activation (#161 F4). io_uring issues
        // no probes this slice, but the reset still clears stale numeric-slot
        // verdicts that routing reads.
        this->arm_health_on_config_change();
        IoEvent events[kMaxEventsPerWait];

        while (is_running()) {
            retry_strict_upstream_retirement_cancels();
            u32 n = backend.wait(events, kMaxEventsPerWait, conns, kMaxConns);
            if (backend.failure_code() != 0) {
                // A zero-event wait is valid; a sticky backend error is not. Stop
                // this shard so an io_uring_enter failure cannot become a silent
                // request stall or an endless busy loop.
                running_.store(false, std::memory_order_release);
                break;
            }
            for (u32 i = 0; i < n; i++) {
                dispatch(events[i]);
            }
            // Retirement/header rendezvous owners publish only readiness during
            // dispatch. Admit parked HTTP/1 request boundaries after every CQE
            // in this wait batch, before reclamation or accept reuse.
            resume_deferred_http1_boundaries();
            reclaim_pending();
            retry_deferred_accepts();
            poll_command();
            // Re-arm timers after a possible hot reload (see EpollEventLoop::run).
            this->fire_due_timers();
            // Reset/arm active-health state on hot reload (#161 F4). No-op when
            // unchanged; advances health_armed_config so the later sweep doesn't
            // double-reset.
            this->arm_health_on_config_change();
            if (draining_.load(std::memory_order_acquire)) {
                close_listen();
                // Drain the idle upstream pool on the shard thread (NOT in drain(),
                // which runs on the control thread and would race pool access here).
                // Idempotent (no-op once empty); drain-time completions close-not-pool,
                // so the pool stays empty and the shard exits with no open pooled fds.
                if (upstream) upstream->drain();
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
        if (cfg && config_ptr) {
            *config_ptr = cfg;
            // A reload may repoint an upstream endpoint under the same
            // (upstream_id, backend_idx); drop idle sockets parked under the old
            // config so post-reload requests don't reuse a stale connection.
            if (upstream) upstream->drain();
        }
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
        close_deferred_idle_return_fds();
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
        // NOTE: do NOT drain the share-nothing UpstreamPool here — drain() runs on the
        // control thread (Shard::drain) while the shard's event-loop thread may be in
        // take_idle/put_idle/sweep. The pool is drained on the shard thread instead,
        // the first time run() observes draining_ (the timerfd kick below wakes it).
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

    static bool strict_upstream_retirement_blocks_reclaim(const Connection& c) {
        return c.upstream_retirement_active || c.upstream_retirement_target_owned != 0 ||
               c.upstream_retirement_cancel_owned != 0 || c.upstream_retirement_cancel_retry != 0 ||
               c.upstream_close_target_owned != 0 || c.upstream_close_cancel_owned != 0 ||
               c.upstream_close_pause_cancel_owned;
    }

    static constexpr u8 upstream_op_for_event(IoEventType type) {
        if (type == IoEventType::UpstreamConnect) return kUpstreamOpConnect;
        if (type == IoEventType::UpstreamRecv) return kUpstreamOpRecv;
        if (type == IoEventType::UpstreamSend) return kUpstreamOpSend;
        return 0;
    }

    static constexpr IoEventType upstream_event_for_op(u8 op) {
        if (op == kUpstreamOpConnect) return IoEventType::UpstreamConnect;
        if (op == kUpstreamOpRecv) return IoEventType::UpstreamRecv;
        if (op == kUpstreamOpSend) return IoEventType::UpstreamSend;
        return IoEventType::Count;
    }

    static constexpr u32 upstream_op_count(u8 mask) {
        return static_cast<u32>((mask & kUpstreamOpConnect) != 0) +
               static_cast<u32>((mask & kUpstreamOpRecv) != 0) +
               static_cast<u32>((mask & kUpstreamOpSend) != 0);
    }

    // Park only the post-response request-boundary tail. Every request-1 side
    // effect (metrics/log/epoch/upstream release) has already completed before
    // this hook is called from on_proxy_response_sent.
    [[nodiscard]] bool defer_http1_request_boundary(Connection& c) {
        // Exhausting the episode space quarantines the slot even when C1 had
        // no recv owner to drain. Never admit request 2 under an invalid token.
        if (c.upstream_episode_quarantined || !valid_upstream_episode(c.upstream_episode)) {
            close_conn(c);
            return true;
        }
        if (!strict_upstream_retirement_blocks_reclaim(c)) return false;
        if (c.http1_boundary_deferred || c.http1_boundary_ready) {
            // A duplicate rendezvous cannot be resumed safely. Keep it parked;
            // the normal close path will clear it.
            close_conn(c);
            return true;
        }
        c.http1_boundary_deferred = true;
        c.http1_boundary_ready = false;
        c.http1_boundary_successor_episode = c.upstream_episode;
        return true;
    }

    static bool current_successor_event_is_valid(const Connection& c, const IoEvent& ev) {
        if (!io_event_is_upstream(ev.type) || !valid_upstream_episode(ev.upstream_episode) ||
            ev.upstream_episode != c.upstream_episode)
            return false;
        if (ev.aux == kPauseCancelAux)
            return ev.type == IoEventType::UpstreamRecv && c.upstream_recv_pause_cancel_pending &&
                   c.pending_ops > 0;
        if (ev.aux == kLocalSubmitFailureAux) {
            if (c.pending_ops == 0) return false;
            if (ev.type == IoEventType::UpstreamConnect)
                return c.on_upstream_send != nullptr && c.upstream_connect_armed;
            if (ev.type == IoEventType::UpstreamSend)
                return c.on_upstream_send != nullptr && c.upstream_send_armed;
            // A local recv-registration failure is the completion of the new
            // submitted target itself; unlike an old terminal racing a pause,
            // cancel_inflight alone is not ownership of this synthetic record.
            return ev.type == IoEventType::UpstreamRecv && c.on_upstream_recv != nullptr &&
                   c.upstream_recv_armed;
        }
        if (ev.aux != 0 || c.pending_ops == 0) return false;
        if (ev.type == IoEventType::UpstreamConnect)
            return c.on_upstream_send != nullptr && c.upstream_connect_armed;
        if (ev.type == IoEventType::UpstreamSend)
            return c.on_upstream_send != nullptr && c.upstream_send_armed;
        // A pause/body-completion path may clear armed before the old recv
        // target terminal drains, but cancel_inflight still proves its exact
        // current ownership and must reach the stale-data branch.
        return ev.type == IoEventType::UpstreamRecv &&
               (c.upstream_recv_armed || c.upstream_recv_cancel_inflight);
    }

private:
    static bool prebuilt_http1_header_is_complete(const Connection& c) {
        const u32 len = c.response_header_buf.len();
        const u8* data = c.response_header_buf.data();
        if (data == nullptr || len < 16u || __builtin_memcmp(data, "HTTP/1.1 ", 9) != 0 ||
            data[9] < '1' || data[9] > '5' || data[10] < '0' || data[10] > '9' || data[11] < '0' ||
            data[11] > '9' || data[12] != ' ' || data[len - 4] != '\r' || data[len - 3] != '\n' ||
            data[len - 2] != '\r' || data[len - 1] != '\n')
            return false;
        const u16 status =
            static_cast<u16>((data[9] - '0') * 100u + (data[10] - '0') * 10u + (data[11] - '0'));
        return status == c.resp_status;
    }

    bool prebuilt_http1_layout_is_valid(const Connection& c,
                                        u8 selected_targets,
                                        Http1RequestBufferDisposition disposition,
                                        u32 request_prefix_len) const {
        const bool retiring_connect = (selected_targets & kUpstreamOpConnect) != 0;
        const bool retiring_send = (selected_targets & kUpstreamOpSend) != 0;
        const auto& send = backend.upstream_send_state[c.id];
        auto exact_send_source = [&](const u8* expected, u32 total) {
            return !retiring_send ||
                   (expected != nullptr && send.src == expected && send.offset <= total &&
                    send.remaining == total - send.offset && send.fd == c.upstream_fd &&
                    send.type == IoEventType::UpstreamSend &&
                    send.upstream_episode == c.upstream_episode);
        };

        switch (disposition) {
            case Http1RequestBufferDisposition::PrefixInRecv:
                // Before the initial upload completes, request 1 is still the
                // exact prefix of recv_buf. The only possible transport phases
                // are connect establishment or a fresh send sourced from that
                // prefix; a recv-only/owner-free handoff cannot prove this
                // layout.
                return !c.request_upload_complete && !c.upstream_request_incomplete &&
                       (retiring_connect || retiring_send) &&
                       (!retiring_connect || selected_targets == kUpstreamOpConnect) &&
                       request_prefix_len != 0 && request_prefix_len == c.req_initial_send_len &&
                       request_prefix_len <= c.recv_buf.len() && c.retry_req_send_len == 0 &&
                       c.pipeline_stash_len == 0 &&
                       exact_send_source(c.recv_buf.data(), request_prefix_len);
            case Http1RequestBufferDisposition::RetrySendBuf:
                // A retry snapshot is meaningful only while its exact replay
                // send is live and sourced from send_buf. Connect ownership is
                // not evidence that this snapshot is the active request.
                return !c.request_upload_complete && !c.upstream_request_incomplete &&
                       !retiring_connect && retiring_send && request_prefix_len != 0 &&
                       request_prefix_len == c.retry_req_send_len && c.pipeline_stash_len == 0 &&
                       request_prefix_len <= c.send_buf.len() &&
                       exact_send_source(c.send_buf.data(), request_prefix_len);
            case Http1RequestBufferDisposition::ExistingPipeline: {
                // The upload callback has already removed request 1 from
                // recv_buf. recv_buf therefore starts at the next-request
                // boundary, while any retry snapshot/pipeline stash remains in
                // send_buf until both rendezvous owners drain. A live Send has
                // not reached that callback and belongs to RetrySendBuf instead.
                const u32 stored =
                    static_cast<u32>(c.retry_req_send_len) + static_cast<u32>(c.pipeline_stash_len);
                return c.request_upload_complete && !c.upstream_request_incomplete &&
                       !retiring_connect && !retiring_send &&
                       request_prefix_len == c.retry_req_send_len && stored <= c.send_buf.len();
            }
            case Http1RequestBufferDisposition::None:
                return false;
        }
        return false;
    }

    void publish_prebuilt_http1_ready(Connection& c) {
        if (c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None ||
            c.http1_prebuilt_wait != 0 || !c.http1_boundary_deferred || c.http1_boundary_ready)
            return;
        c.http1_boundary_ready = true;
        http1_boundary_ready_pending = true;
    }

    bool normalize_prebuilt_http1_request_buffer(Connection& c) {
        const u32 prefix = c.http1_prebuilt_request_prefix_len;
        switch (c.http1_prebuilt_disposition) {
            case Http1RequestBufferDisposition::PrefixInRecv: {
                if (prefix == 0 || prefix != c.req_initial_send_len || prefix > c.recv_buf.len() ||
                    c.retry_req_send_len != 0 || c.pipeline_stash_len != 0)
                    return false;
                const u32 late = c.recv_buf.len() - prefix;
                if (late != 0) __builtin_memmove(c.recv_slice, c.recv_buf.data() + prefix, late);
                c.recv_buf.set_len(late);
                return true;
            }
            case Http1RequestBufferDisposition::RetrySendBuf:
                if (prefix == 0 || prefix != c.retry_req_send_len || c.pipeline_stash_len != 0 ||
                    prefix > c.send_buf.len())
                    return false;
                c.retry_req_send_len = 0;
                c.send_buf.reset();
                return true;
            case Http1RequestBufferDisposition::ExistingPipeline:
                return prefix == c.retry_req_send_len &&
                       static_cast<u32>(c.retry_req_send_len) +
                               static_cast<u32>(c.pipeline_stash_len) <=
                           c.send_buf.len();
            case Http1RequestBufferDisposition::None:
                return false;
        }
        return false;
    }

    [[nodiscard]] bool begin_upstream_retirement_impl(Connection& c,
                                                      u8 selected_targets,
                                                      bool detached_recv_callback,
                                                      bool transfer_live_state) {
        constexpr u8 kAllUpstreamOps = kUpstreamOpConnect | kUpstreamOpRecv | kUpstreamOpSend;
        const u32 previous_tombstone = c.upstream_retiring_episode;
        const bool replaceable_tombstone =
            previous_tombstone == 0 ||
            (valid_upstream_episode(previous_tombstone) &&
             previous_tombstone < c.upstream_episode && !c.upstream_retirement_active &&
             c.upstream_retirement_target_owned == 0 && c.upstream_retirement_cancel_owned == 0 &&
             c.upstream_retirement_cancel_retry == 0);
        if (c.id >= kMaxConns || c.upstream_episode_quarantined ||
            !valid_upstream_episode(c.upstream_episode) || !replaceable_tombstone ||
            (selected_targets & static_cast<u8>(~kAllUpstreamOps)) != 0 ||
            ((selected_targets & kUpstreamOpConnect) != 0 &&
             (selected_targets & kUpstreamOpSend) != 0) ||
            c.upstream_retirement_active || c.upstream_retirement_target_owned != 0 ||
            c.upstream_retirement_cancel_owned != 0 || c.upstream_retirement_cancel_retry != 0 ||
            c.upstream_close_episode != 0 || c.upstream_close_target_owned != 0 ||
            c.upstream_close_cancel_owned != 0 || c.upstream_close_pause_cancel_owned ||
            c.http1_boundary_deferred || c.http1_boundary_ready || c.http1_prebuilt_wait != 0 ||
            c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None ||
            c.http1_prebuilt_request_prefix_len != 0 || c.http1_boundary_successor_episode != 0 ||
            c.upstream_fd < 0 || c.send_armed || c.yield_armed || c.yield_timeout_armed ||
            c.recv_paused_for_send || c.recv_pause_cancel_pending || c.recv_pause_rearm_pending ||
            c.upstream_recv_paused_for_send || c.upstream_recv_pause_cancel_pending ||
            c.upstream_recv_pause_rearm_pending || c.upstream_recv_cancel_inflight ||
            c.upstream_recv_terminal_stale)
            return false;

        const auto& downstream_send = backend.send_state[c.id];
        const auto& upstream_send = backend.upstream_send_state[c.id];
        if (downstream_send.remaining != 0) return false;

        u8 actual_targets = 0;
        if (c.upstream_connect_armed) actual_targets |= kUpstreamOpConnect;
        if (c.upstream_recv_armed) actual_targets |= kUpstreamOpRecv;
        if (c.upstream_send_armed) actual_targets |= kUpstreamOpSend;
        if (actual_targets != selected_targets) return false;
        if ((selected_targets & (kUpstreamOpConnect | kUpstreamOpSend)) != 0 &&
            c.on_upstream_send == nullptr)
            return false;
        if ((selected_targets & kUpstreamOpRecv) != 0 && !detached_recv_callback &&
            c.on_upstream_recv == nullptr)
            return false;

        if ((selected_targets & kUpstreamOpSend) != 0) {
            if (upstream_send.src == nullptr || upstream_send.fd != c.upstream_fd ||
                upstream_send.remaining == 0 || upstream_send.type != IoEventType::UpstreamSend ||
                upstream_send.upstream_episode != c.upstream_episode)
                return false;
        } else if (upstream_send.remaining != 0) {
            return false;
        }

        // Exact equality excludes every unrepresented target or cancel CQE.
        const u32 expected_pending =
            static_cast<u32>(c.recv_armed) + upstream_op_count(selected_targets);
        if (c.pending_ops != expected_pending) return false;

        // Replace a fully-drained older tombstone directly with the exact
        // current token. Never clear it through zero: from this assignment on,
        // every older episode remains default-denied by the latest-retirement
        // consumer while this exact episode owns the new recv/cancel finals.
        const u32 retiring_episode = c.upstream_episode;
        c.upstream_retiring_episode = retiring_episode;
        c.upstream_retirement_active = selected_targets != 0;
        c.upstream_retirement_target_owned = selected_targets;
        c.upstream_retirement_cancel_owned = 0;
        c.upstream_retirement_cancel_retry = 0;

        // The generic entry moves ownership atomically into the retirement
        // ledger. Leaving an old armed flag behind would let a synchronous
        // downstream close misclassify that old target as a successor op. The
        // legacy strict wrapper preserves its existing enclosing handoff: its
        // callback was already detached and abandon_strict_upstream clears the
        // recv flag synchronously before returning to the event loop.
        if (transfer_live_state) {
            if ((selected_targets & kUpstreamOpConnect) != 0) c.upstream_connect_armed = false;
            if ((selected_targets & kUpstreamOpRecv) != 0) {
                c.upstream_recv_armed = false;
                c.on_upstream_recv = nullptr;
            }
            if ((selected_targets & kUpstreamOpSend) != 0) c.upstream_send_armed = false;
            if ((selected_targets & (kUpstreamOpConnect | kUpstreamOpSend)) != 0)
                c.on_upstream_send = nullptr;
        }

        // Publish a different current token before another backend wait can
        // inspect a provided-buffer CQE. At exhaustion, use an unrepresentable
        // current token and permanently quarantine the allocator slot.
        if (!c.next_upstream_episode()) {
            c.upstream_episode = kInvalidUpstreamEventEpisode;
            c.upstream_episode_quarantined = true;
        }

        if (selected_targets == 0) {
            c.upstream_retirement_active = false;
            return true;
        }

        for (u8 op : {kUpstreamOpConnect, kUpstreamOpSend, kUpstreamOpRecv}) {
            if ((selected_targets & op) == 0) continue;
            if (backend.cancel_retiring_upstream(
                    c.id, upstream_event_for_op(op), retiring_episode)) {
                c.upstream_retirement_cancel_owned |= op;
                c.pending_ops++;
            } else {
                c.upstream_retirement_cancel_retry |= op;
                upstream_retirement_retry_count++;
            }
        }
        return true;
    }

public:
    // Establish exact transport ownership for a bounded upstream episode. This
    // is foundation only: Connect/Send callers may not publish an HTTP/1
    // request boundary until #265's later epoch/header rendezvous exists.
    [[nodiscard]] bool begin_upstream_retirement(Connection& c, u8 selected_targets) {
        if (selected_targets == 0) return false;
        return begin_upstream_retirement_impl(c, selected_targets, false, true);
    }

    // Advance an exact, owner-free episode into the persistent tombstone. This
    // is for callbacks that observe a terminal upstream record after normal CQE
    // accounting has already cleared the final target; it never fabricates an
    // operation or pending count.
    [[nodiscard]] bool advance_upstream_retirement_tombstone(Connection& c) {
        return begin_upstream_retirement_impl(c, 0, false, true);
    }

    // Internal D2 seam. The complete header is already owned by
    // response_header_buf; this method proves transport and request-buffer
    // ownership before advancing the episode or submitting any downstream byte.
    // No production policy path calls it in this slice.
    [[nodiscard]] bool begin_prebuilt_http1_response(Connection& c,
                                                     u8 selected_targets,
                                                     Http1RequestBufferDisposition disposition,
                                                     u32 request_prefix_len) {
        constexpr u8 kAllowed = kUpstreamOpConnect | kUpstreamOpSend | kUpstreamOpRecv;
        if (c.id >= kMaxConns || c.fd < 0 || c.upstream_fd < 0 ||
            c.protocol != ConnProtocol::Http11 || c.tls_active || c.state != ConnState::Proxying ||
            !c.keep_alive || !c.req_client_keep_alive || c.req_start_us == 0 || c.epoch_held ||
            c.resp_body_mode != BodyMode::None || c.resp_body_remaining != 0 ||
            c.req_body_mode != BodyMode::None || c.req_body_remaining != 0 || c.req_body_streamed ||
            c.send_armed || c.on_send != nullptr || c.http1_boundary_deferred ||
            c.http1_boundary_ready || c.http1_boundary_successor_episode != 0 ||
            c.http1_prebuilt_wait != 0 ||
            c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None ||
            c.http1_prebuilt_request_prefix_len != 0 ||
            (selected_targets & static_cast<u8>(~kAllowed)) != 0 ||
            ((selected_targets & kUpstreamOpConnect) != 0 &&
             (selected_targets & kUpstreamOpSend) != 0) ||
            !prebuilt_http1_header_is_complete(c) ||
            !prebuilt_http1_layout_is_valid(c, selected_targets, disposition, request_prefix_len))
            return false;

        const bool advanced = selected_targets == 0
                                  ? advance_upstream_retirement_tombstone(c)
                                  : begin_upstream_retirement(c, selected_targets);
        if (!advanced) return false;
        if (c.upstream_episode_quarantined || !valid_upstream_episode(c.upstream_episode)) {
            close_conn(c);
            return false;
        }

        c.http1_prebuilt_wait = kHttp1WaitHeaderSend;
        if (c.upstream_retirement_active) c.http1_prebuilt_wait |= kHttp1WaitUpstreamRetirement;
        c.http1_prebuilt_disposition = disposition;
        c.http1_prebuilt_request_prefix_len = request_prefix_len;
        c.http1_boundary_successor_episode = c.upstream_episode;
        c.upstream_abandoned = true;
        c.upstream_keep_alive = false;
        c.upstream_start_us = 0;
        c.proxy_resp_started = true;
        c.on_upstream_recv = nullptr;
        c.on_upstream_send = nullptr;
        ::close(c.upstream_fd);
        c.upstream_fd = -1;
        if (c.upstream_slot_held) {
            upstream_release(c.upstream_slot_uid);
            c.upstream_slot_held = false;
        }
        c.resp_body_sent = c.response_header_buf.len();
        c.transition_to_sending(&on_prebuilt_http1_header_sent<IoUringEventLoop>);
        if (!submit_send(c, c.response_header_buf.data(), c.response_header_buf.len())) {
            close_conn(c);
            return false;
        }
        return true;
    }

    [[nodiscard]] bool complete_prebuilt_http1_header_send(Connection& c) {
        if (c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None ||
            (c.http1_prebuilt_wait != kHttp1WaitHeaderSend &&
             c.http1_prebuilt_wait != (kHttp1WaitHeaderSend | kHttp1WaitUpstreamRetirement)) ||
            c.http1_boundary_deferred || c.http1_boundary_ready ||
            c.http1_boundary_successor_episode != c.upstream_episode)
            return false;
        c.http1_prebuilt_wait &= static_cast<u8>(~kHttp1WaitHeaderSend);
        c.http1_boundary_deferred = true;
        publish_prebuilt_http1_ready(c);
        return true;
    }

    bool prebuilt_http1_header_send_completion_is_valid(const Connection& c,
                                                        const IoEvent& ev) const {
        if (c.id >= kMaxConns || ev.conn_id != c.id || ev.type != IoEventType::Send || ev.more ||
            ev.aux != 0 || ev.result <= 0 ||
            static_cast<u32>(ev.result) != c.response_header_buf.len() ||
            c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None ||
            (c.http1_prebuilt_wait & kHttp1WaitHeaderSend) == 0 || c.state != ConnState::Sending ||
            c.send_armed || c.req_start_us == 0 || c.epoch_held ||
            c.on_send != &on_prebuilt_http1_header_sent<IoUringEventLoop>)
            return false;
        const auto& send = backend.send_state[c.id];
        return send.src == c.response_header_buf.data() && send.fd == c.fd &&
               send.offset == c.response_header_buf.len() && send.remaining == 0 &&
               send.type == IoEventType::Send;
    }

    // Fence D2's one downstream HeaderSend target before generic Send
    // accounting. The first exact full completion continues through the normal
    // proactor accounting and dedicated callback. Once that owner is cleared,
    // every duplicate/late Send is swallowed while the two-party rendezvous is
    // still active and cannot steal the long-lived downstream recv count.
    bool consume_prebuilt_http1_header_send_event(Connection& c, const IoEvent& ev) {
        if (ev.type != IoEventType::Send ||
            c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None)
            return false;
        if ((c.http1_prebuilt_wait & kHttp1WaitHeaderSend) == 0) return true;

        const auto& send = backend.send_state[c.id];
        const bool exact_owner = c.id < kMaxConns && c.state == ConnState::Sending &&
                                 c.send_armed && c.req_start_us != 0 && !c.epoch_held &&
                                 c.on_send == &on_prebuilt_http1_header_sent<IoUringEventLoop> &&
                                 send.src == c.response_header_buf.data() && send.fd == c.fd &&
                                 send.type == IoEventType::Send;
        if (!exact_owner || ev.conn_id != c.id || ev.aux != 0 || ev.more) {
            close_conn(c);
            return true;
        }

        const bool full = ev.result > 0 &&
                          static_cast<u32>(ev.result) == c.response_header_buf.len() &&
                          send.offset == c.response_header_buf.len() && send.remaining == 0;
        if (full) return false;

        // A terminal error/invalid short record terminates exactly the owned
        // HeaderSend target. Retire that one count before close; never let the
        // generic branch consume a recv or retirement owner. F_MORE above is
        // non-terminal and remains armed for close-ledger cancellation.
        if (c.pending_ops == 0) {
            c.upstream_episode = kInvalidUpstreamEventEpisode;
            c.upstream_episode_quarantined = true;
            backend.fatal_error.store(EPROTO, std::memory_order_release);
            running_.store(false, std::memory_order_release);
        } else {
            c.pending_ops--;
            c.send_armed = false;
            backend.send_state[c.id] = {};
        }
        close_conn(c);
        return true;
    }

    // Existing production C1 caller: its callback has already been detached,
    // and the proven strict point owns at most one upstream recv target.
    [[nodiscard]] bool begin_strict_upstream_retirement(Connection& c) {
        const u8 selected = c.upstream_recv_armed ? kUpstreamOpRecv : 0;
        return begin_upstream_retirement_impl(c, selected, true, false);
    }

    // Safe retry point: called before backend.wait submits/blocks. A full SQ
    // necessarily has work for wait() to advance; a sticky enter failure stops
    // the shard through the existing explicit fatal path.
    void retry_strict_upstream_retirement_cancels() {
        if (upstream_retirement_retry_count == 0) return;
        for (u32 id = 0; id < kMaxConns && upstream_retirement_retry_count != 0; id++) {
            Connection& c = conns[id];
            if (!c.upstream_retirement_cancel_retry) continue;
            if (!c.upstream_retirement_active ||
                (c.upstream_retirement_cancel_owned & c.upstream_retirement_cancel_retry) != 0 ||
                (c.upstream_retirement_cancel_retry &
                 static_cast<u8>(~c.upstream_retirement_target_owned)) != 0 ||
                !valid_upstream_episode(c.upstream_retiring_episode)) {
                // Corrupt retirement ownership cannot be repaired safely.
                backend.fatal_error.store(EPROTO, std::memory_order_release);
                running_.store(false, std::memory_order_release);
                return;
            }
            for (u8 op : {kUpstreamOpConnect, kUpstreamOpSend, kUpstreamOpRecv}) {
                if ((c.upstream_retirement_cancel_retry & op) == 0) continue;
                if (!backend.cancel_retiring_upstream(
                        c.id, upstream_event_for_op(op), c.upstream_retiring_episode))
                    continue;
                c.upstream_retirement_cancel_retry &= static_cast<u8>(~op);
                c.upstream_retirement_cancel_owned |= op;
                c.pending_ops++;
                upstream_retirement_retry_count--;
            }
        }
    }

    // Route strict-retirement CQEs before generic stale accounting. Returning
    // true means the event was consumed without entering callbacks, timer
    // refresh, armed-flag changes, send state, or current request buffers.
    bool consume_strict_upstream_retirement_event(Connection& c, const IoEvent& ev) {
        if (!io_event_is_upstream(ev.type)) return false;

        const u8 retirement_op = upstream_op_for_event(ev.type);
        const bool matching_retirement = retirement_op != 0 && c.upstream_retiring_episode != 0 &&
                                         ev.upstream_episode == c.upstream_retiring_episode;
        if (matching_retirement) {
            // Keep the token as a tombstone after completion: matching
            // duplicates remain consumed and cannot steal generic accounting.
            if (!c.upstream_retirement_active) return true;

            u8* owned = nullptr;
            if (ev.aux == 0)
                owned = &c.upstream_retirement_target_owned;
            else if (ev.aux == kUpstreamRetirementCancelAux)
                owned = &c.upstream_retirement_cancel_owned;
            if (owned == nullptr || (*owned & retirement_op) == 0 || ev.more) return true;

            // Ownership is counted when the target was armed or after the
            // cancel SQE was queued. A zero aggregate here is corrupt state;
            // fail the shard explicitly without inventing a decrement.
            if (c.pending_ops == 0) {
                c.upstream_episode = kInvalidUpstreamEventEpisode;
                c.upstream_episode_quarantined = true;
                backend.fatal_error.store(EPROTO, std::memory_order_release);
                running_.store(false, std::memory_order_release);
                return true;
            }
            *owned &= static_cast<u8>(~retirement_op);
            if (ev.aux == 0 && retirement_op == kUpstreamOpSend)
                backend.upstream_send_state[c.id] = {};
            c.pending_ops--;
            if (ev.aux == 0 && (c.upstream_retirement_cancel_retry & retirement_op) != 0) {
                // The target reached its terminal CQE before an initially-full
                // SQ could accept the cancel. No kernel recv remains to cancel,
                // so retire the retry obligation synchronously and keep the
                // loop-level scan count exact.
                if (upstream_retirement_retry_count == 0) {
                    c.upstream_episode = kInvalidUpstreamEventEpisode;
                    c.upstream_episode_quarantined = true;
                    backend.fatal_error.store(EPROTO, std::memory_order_release);
                    running_.store(false, std::memory_order_release);
                    return true;
                }
                c.upstream_retirement_cancel_retry &= static_cast<u8>(~retirement_op);
                upstream_retirement_retry_count--;
            }
            if (c.upstream_retirement_target_owned == 0 &&
                c.upstream_retirement_cancel_owned == 0 &&
                c.upstream_retirement_cancel_retry == 0) {
                c.upstream_retirement_active = false;
                if (c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None) {
                    if ((c.http1_prebuilt_wait & kHttp1WaitUpstreamRetirement) == 0) {
                        c.upstream_episode = kInvalidUpstreamEventEpisode;
                        c.upstream_episode_quarantined = true;
                        backend.fatal_error.store(EPROTO, std::memory_order_release);
                        running_.store(false, std::memory_order_release);
                        return true;
                    }
                    c.http1_prebuilt_wait &= static_cast<u8>(~kHttp1WaitUpstreamRetirement);
                    publish_prebuilt_http1_ready(c);
                } else if (c.http1_boundary_deferred && !c.http1_boundary_ready) {
                    c.http1_boundary_ready = true;
                    http1_boundary_ready_pending = true;
                }
                if (c.fd < 0 && c.pending_ops == 0) reclaim_slot(c.id);
            }
            return true;
        }

        // A live successor can have an operation and its close-path cancel in
        // flight concurrently. Both were counted independently, so route only
        // the exact episode/type/aux owner and leave duplicates or forged
        // records unable to decrement aggregate pending_ops.
        if (c.upstream_close_episode != 0 && ev.upstream_episode == c.upstream_close_episode) {
            const u8 op = upstream_op_for_event(ev.type);

            bool owned = false;
            if (ev.aux == 0) {
                owned = (c.upstream_close_target_owned & op) != 0;
                if (owned && !ev.more) c.upstream_close_target_owned &= static_cast<u8>(~op);
            } else if (ev.aux == kUpstreamCloseCancelAux) {
                owned = (c.upstream_close_cancel_owned & op) != 0;
                if (owned && !ev.more) c.upstream_close_cancel_owned &= static_cast<u8>(~op);
            } else if (ev.aux == kPauseCancelAux && op == kUpstreamOpRecv) {
                owned = c.upstream_close_pause_cancel_owned;
                if (owned && !ev.more) c.upstream_close_pause_cancel_owned = false;
            }
            if (!owned || ev.more) return true;
            if (c.pending_ops == 0) {
                c.upstream_episode = kInvalidUpstreamEventEpisode;
                c.upstream_episode_quarantined = true;
                backend.fatal_error.store(EPROTO, std::memory_order_release);
                running_.store(false, std::memory_order_release);
                return true;
            }
            c.pending_ops--;
            if (c.fd < 0 && c.pending_ops == 0 && !strict_upstream_retirement_blocks_reclaim(c))
                reclaim_slot(c.id);
            return true;
        }

        // The strict begin precondition proves there is no other upstream
        // operation while retirement is active. Once inactive, retain the
        // latest token as a tombstone but admit documented production
        // completions carrying the exact current successor token. Retirement-
        // only, unknown, malformed, and older records own no aggregate
        // accounting and remain swallowed.
        if (c.upstream_retiring_episode == 0) return false;
        if (c.upstream_retirement_active) return true;
        return !current_successor_event_is_valid(c, ev);
    }

    // Consume every ready marker before invoking the factored continuation.
    // Called only after all CQEs returned by the current backend.wait batch.
    // Public for focused production-dispatch tests; run() is the only runtime
    // scheduler.
    void resume_deferred_http1_boundaries() {
        if (!http1_boundary_ready_pending) return;
        http1_boundary_ready_pending = false;
        for (u32 id = 0; id < kMaxConns; id++) {
            Connection& c = conns[id];
            if (!c.http1_boundary_ready) continue;

            c.http1_boundary_ready = false;
            if (!c.http1_boundary_deferred) continue;
            const u32 expected_episode = c.http1_boundary_successor_episode;

            if (c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None) {
                const bool has_request_callback =
                    c.on_send || c.on_upstream_recv || c.on_upstream_send ||
                    (c.uses_iouring_tls() ? c.tls_pending_on_recv != nullptr
                                          : c.on_recv != nullptr);
                const bool valid =
                    c.id == id && c.fd >= 0 && !is_draining() && !c.upstream_episode_quarantined &&
                    c.http1_prebuilt_wait == 0 && !strict_upstream_retirement_blocks_reclaim(c) &&
                    c.upstream_close_episode == 0 && c.upstream_close_target_owned == 0 &&
                    c.upstream_close_cancel_owned == 0 && !c.upstream_close_pause_cancel_owned &&
                    valid_upstream_episode(expected_episode) &&
                    c.upstream_episode == expected_episode && c.upstream_fd < 0 &&
                    !c.upstream_slot_held && c.state == ConnState::Sending && !c.send_armed &&
                    c.req_start_us == 0 && c.epoch_held && !c.upstream_connect_armed &&
                    !c.upstream_send_armed && !c.upstream_recv_armed && !has_request_callback;
                if (!valid || !normalize_prebuilt_http1_request_buffer(c)) {
                    if (c.fd >= 0) close_conn(c);
                    continue;
                }

                c.http1_boundary_deferred = false;
                c.http1_boundary_successor_episode = 0;
                c.http1_prebuilt_wait = 0;
                c.http1_prebuilt_disposition = Http1RequestBufferDisposition::None;
                c.http1_prebuilt_request_prefix_len = 0;
                epoch_leave();
                c.epoch_held = false;
                continue_http1_request_boundary<IoUringEventLoop>(this, c);
                continue;
            }

            c.http1_boundary_deferred = false;
            c.http1_boundary_successor_episode = 0;

            const bool has_request_callback =
                c.on_send || c.on_upstream_recv || c.on_upstream_send ||
                (c.uses_iouring_tls() ? c.tls_pending_on_recv != nullptr : c.on_recv != nullptr);
            const bool valid =
                c.id == id && c.fd >= 0 && !is_draining() && !c.upstream_episode_quarantined &&
                !strict_upstream_retirement_blocks_reclaim(c) &&
                valid_upstream_episode(expected_episode) &&
                c.upstream_episode == expected_episode && c.state == ConnState::Sending &&
                !c.send_armed && c.req_start_us == 0 && !has_request_callback;
            if (!valid) {
                if (c.fd >= 0) close_conn(c);
                continue;
            }
            continue_http1_request_boundary<IoUringEventLoop>(this, c);
        }
    }

    // --- HTTP/1 idle upstream connection reuse (per-shard pool) ---

    // Borrow a live idle socket to (upstream_id, backend_idx) from the pool,
    // skipping the TCP connect. io_uring routes upstream completions by conn_id
    // user_data (no fd map), so installing the fd is all that's needed; the next
    // submit_send_upstream arms a send SQE tagged with this conn. Returns false
    // (no live idle socket) → caller connects fresh.
    bool reuse_idle_upstream(Connection& c, u16 upstream_id, u8 backend_idx) {
        if (!upstream) return false;
        const i32 fd = upstream->take_idle(upstream_id, backend_idx);
        if (fd < 0) return false;
        c.upstream_fd = fd;
        return true;
    }

    // Return conn.upstream_fd to the idle pool at proxy completion. Unlike epoll's
    // synchronous detach, the multishot upstream recv (IORING_RECV_MULTISHOT) is
    // still armed here, so the fd can't be handed out until that recv stops — a new
    // borrower's recv would otherwise race the old one on the same socket. We cancel
    // the recv and DEFER the pool-return (idle_return_fd) until its terminal CQE
    // drains; try_deferred_upstream_rearm parks it then. If no recv is armed we park
    // immediately. The fd is detached from the conn (upstream_fd = -1) either way,
    // so release_upstream_conn's close is skipped; close_conn closes idle_return_fd
    // if the conn tears down before the drain.
    void return_idle_upstream(Connection& c, u16 upstream_id, u8 backend_idx) {
        if (c.upstream_fd < 0 || !upstream) return;  // caller closes
        const bool kRecvPending = c.upstream_recv_armed || c.upstream_recv_cancel_inflight ||
                                  c.upstream_recv_pause_cancel_pending;
        if (!kRecvPending) {
            const i32 fd = c.upstream_fd;
            c.upstream_fd = -1;
            c.upstream_send_armed = false;
            if (!upstream->put_idle(fd, upstream_id, backend_idx, monotonic_secs())) ::close(fd);
            return;
        }
        // The recv being drained belongs to the just-completed upstream fd, not to
        // any pipelined/follow-up request that may reuse this Connection slot. Any
        // terminal or positive CQE from it must be quarantined and dropped.
        c.upstream_recv_terminal_stale = true;
        c.upstream_recv_idle_stale_bytes = false;
        // Cancel the armed multishot recv; if the cancel SQE can't be queued, leave
        // the fd closed/detached but keep the old recv as an in-flight stale terminal
        // barrier; otherwise a later CQE can be delivered to the next request.
        if (c.upstream_recv_armed && !pause_upstream_recv_impl(c)) {
            ::close(c.upstream_fd);
            c.upstream_fd = -1;
            c.upstream_send_armed = false;
            c.upstream_recv_cancel_inflight = true;
            return;
        }
        c.idle_return_fd = c.upstream_fd;
        c.idle_return_uid = upstream_id;
        c.idle_return_bidx = backend_idx;
        // Pin the config this fd is parked under. If a reload swaps it before the
        // recv drains, the deferred put_idle would slip a stale-config socket past
        // poll_command's pool drain — try_deferred_upstream_rearm closes on mismatch.
        c.idle_return_config = config_ptr ? *config_ptr : nullptr;
        c.upstream_fd = -1;
        c.upstream_send_armed = false;
    }

    // never pay the cost. Returns false if SlicePool is exhausted.
    bool alloc_upstream_buf(ConnectionBase& c) {
        if (c.upstream_recv_slice) return true;  // already allocated
        u8* s = pool.alloc();
        if (!s) return false;
        c.upstream_recv_slice = s;
        c.upstream_recv_buf.bind(s, SlicePool::kSliceSize);
        return true;
    }

    bool alloc_response_header_buf(ConnectionBase& c) {
        if (c.response_header_slice) return true;
        u8* s = pool.alloc();
        if (!s) return false;
        c.response_header_slice = s;
        c.response_header_buf.bind(s, SlicePool::kSliceSize);
        return true;
    }

    // Two WebSocket terminate-mode reassembly slices (one per direction). All-or-nothing.
    bool alloc_ws_terminate_bufs(ConnectionBase& c) {
        if (c.ws_c2u_msg) return true;  // already allocated
        u8* a = pool.alloc();
        u8* b = pool.alloc();
        if (!a || !b) {
            if (a) pool.free(a);
            if (b) pool.free(b);
            return false;
        }
        c.ws_c2u_msg = a;
        c.ws_u2c_msg = b;
        return true;
    }

    // Initialize TLS termination on a freshly accepted connection: create the
    // engine, allocate the ciphertext in/out slices, and point on_recv at the
    // TLS driver. Returns false (and rolls back) if the engine or pool fails.
    bool tls_setup(Connection& c) {
        if (!tls_engine_init(c.tls_engine, tls_server)) return false;
        void* in_region = mmap(
            nullptr, kTlsInputSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (in_region == MAP_FAILED) {
            tls_engine_free(c.tls_engine);
            return false;
        }
        u8* in = static_cast<u8*>(in_region);
        // Owned ciphertext output buffer (kTlsOutBufCap, mmap like tls_in) — see
        // docs/iouring-tls-output-buffer.md. tls_out_slice holds the mmap base
        // for teardown; tls_out_buf is the Buffer view used for staging+draining.
        void* out_region = mmap(
            nullptr, kTlsOutBufCap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (out_region == MAP_FAILED) {
            munmap(in, kTlsInputSize);
            tls_engine_free(c.tls_engine);
            return false;
        }
        u8* out = static_cast<u8*>(out_region);
        c.tls_in_slice = in;
        c.tls_in_buf.bind(in, kTlsInputSize);
        c.tls_out_slice = out;
        c.tls_out_buf.bind(out, kTlsOutBufCap);
        c.tls_active = true;
        c.tls_handshake_complete = false;
        c.tls_pending_on_recv = &on_header_received<Self>;
        c.on_recv = &tls_recv<Self>;
        return true;
    }

    void free_tls_in_buf(ConnectionBase& c) {
        if (!c.tls_in_slice) return;
        munmap(c.tls_in_slice, kTlsInputSize);
        c.tls_in_slice = nullptr;
        c.tls_in_buf.bind(nullptr, 0);
    }

    void free_tls_out_buf(ConnectionBase& c) {
        if (!c.tls_out_slice) return;  // tls_out_slice is the mmap base (see tls_setup)
        munmap(c.tls_out_slice, kTlsOutBufCap);
        c.tls_out_slice = nullptr;
        c.tls_out_buf.bind(nullptr, 0);
    }

    void reclaim_slot(u32 cid) {
        if (cid >= kMaxConns || strict_upstream_retirement_blocks_reclaim(conns[cid])) return;
        bool was_pending = false;
        for (u32 i = 0; i < pending_free_count; i++) {
            if (pending_free[i] == cid) {
                pending_free[i] = pending_free[--pending_free_count];
                was_pending = true;
                break;
            }
        }
        // Every deferred slot enters pending_free in free_conn_impl. Refusing
        // an unowned reclaim makes duplicate finals idempotent.
        if (!was_pending) return;
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
        if (conns[cid].response_header_slice) {
            pool.free(conns[cid].response_header_slice);
            conns[cid].response_header_slice = nullptr;
        }
        free_tls_in_buf(conns[cid]);
        free_tls_out_buf(conns[cid]);
        if (!conns[cid].upstream_episode_quarantined) free_stack[free_top++] = cid;
    }

    void reclaim_pending() {
        u32 remaining = 0;
        for (u32 i = 0; i < pending_free_count; i++) {
            u32 cid = pending_free[i];
            if (conns[cid].pending_ops == 0 &&
                !strict_upstream_retirement_blocks_reclaim(conns[cid])) {
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
                if (conns[cid].response_header_slice) {
                    pool.free(conns[cid].response_header_slice);
                    conns[cid].response_header_slice = nullptr;
                }
                free_tls_in_buf(conns[cid]);
                free_tls_out_buf(conns[cid]);
                if (!conns[cid].upstream_episode_quarantined) free_stack[free_top++] = cid;
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
        conns[id].listener_context = this->listener_context;
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
        // The TlsEngine owns only the SSL object (+ its custom BIO), never the
        // io_uring-referenced slices — safe to free now even with ops in flight.
        if (c.tls_engine.ssl) tls_engine_free(c.tls_engine);
        // WebSocket terminate reassembly slices are CPU-only scratch (never handed to a
        // kernel op — the re-framed output goes in place in the recv slices), so reclaim
        // them now too, regardless of in-flight ops.
        if (c.ws_c2u_msg) {
            pool.free(c.ws_c2u_msg);
            c.ws_c2u_msg = nullptr;
        }
        if (c.ws_u2c_msg) {
            pool.free(c.ws_u2c_msg);
            c.ws_u2c_msg = nullptr;
        }
        // If no ops are in flight, reclaim immediately.
        if (c.pending_ops == 0 && !strict_upstream_retirement_blocks_reclaim(c)) {
            if (c.recv_slice) pool.free(c.recv_slice);
            if (c.send_slice) pool.free(c.send_slice);
            if (c.upstream_recv_slice) pool.free(c.upstream_recv_slice);
            if (c.response_header_slice) pool.free(c.response_header_slice);
            free_tls_in_buf(c);
            free_tls_out_buf(c);
            c.reset();
            if (!c.upstream_episode_quarantined) free_stack[free_top++] = cid;
            return;
        }
        // Ops still in flight: defer until CQEs arrive.
        u8* rs = c.recv_slice;
        u8* ss = c.send_slice;
        u8* us = c.upstream_recv_slice;
        u8* hs = c.response_header_slice;
        u8* tin = c.tls_in_slice;
        u8* tout = c.tls_out_slice;
        u32 ops = c.pending_ops;
        const u8 allocated_shard = c.shard_id;
        const u32 retiring_episode = c.upstream_retiring_episode;
        const bool retirement_active = c.upstream_retirement_active;
        const u8 retirement_target_owned = c.upstream_retirement_target_owned;
        const u8 retirement_cancel_owned = c.upstream_retirement_cancel_owned;
        const u8 retirement_cancel_retry = c.upstream_retirement_cancel_retry;
        const u32 close_episode = c.upstream_close_episode;
        const u8 close_target_owned = c.upstream_close_target_owned;
        const u8 close_cancel_owned = c.upstream_close_cancel_owned;
        const bool close_pause_cancel_owned = c.upstream_close_pause_cancel_owned;
        c.reset();
        conns[cid].id = cid;
        conns[cid].shard_id = allocated_shard;
        conns[cid].recv_slice = rs;
        conns[cid].send_slice = ss;
        conns[cid].upstream_recv_slice = us;
        conns[cid].response_header_slice = hs;
        conns[cid].tls_in_slice = tin;
        conns[cid].tls_out_slice = tout;
        conns[cid].pending_ops = ops;
        conns[cid].upstream_retiring_episode = retiring_episode;
        conns[cid].upstream_retirement_active = retirement_active;
        conns[cid].upstream_retirement_target_owned = retirement_target_owned;
        conns[cid].upstream_retirement_cancel_owned = retirement_cancel_owned;
        conns[cid].upstream_retirement_cancel_retry = retirement_cancel_retry;
        conns[cid].upstream_close_episode = close_episode;
        conns[cid].upstream_close_target_owned = close_target_owned;
        conns[cid].upstream_close_cancel_owned = close_cancel_owned;
        conns[cid].upstream_close_pause_cancel_owned = close_pause_cancel_owned;
        pending_free[pending_free_count++] = cid;
    }

    bool submit_recv_impl(Connection& c) {
        const bool tls_send_needs_recv =
            c.uses_iouring_tls() && c.tls_pending_on_recv == &tls_resume_pending_send_recv<Self>;
        if (c.recv_paused_for_send && !tls_send_needs_recv) {
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

    // Raw client send — bytes go to the wire as-is (plaintext, or already-
    // encrypted ciphertext from the TLS layer).
    bool submit_send_raw(Connection& c, const u8* buf, u32 len) {
        if (backend.add_send(c.fd, c.id, buf, len)) {
            c.pending_ops++;
            c.send_armed = true;
            return true;
        }
        return false;
    }

    bool submit_send_impl(Connection& c, const u8* buf, u32 len) {
        if (c.tls_active) {
            // A previous single-shot send still mid-encryption (its plaintext
            // didn't fit tls_out_buf in one shot) must not be overwritten or its
            // remainder is lost. The upper layer serializes client sends via
            // pause/resume; phase 3 decouples proxy streaming. Fail safe (caller
            // closes) rather than corrupt.
            if (c.tls_send_src && c.tls_send_off < c.tls_send_len) {
                close_conn(c);
                return false;
            }
            // Encrypt into the owned tls_out_buf; ciphertext drains via
            // tls_on_out_drain, which fires this continuation once fully sent.
            c.tls_pending_on_send = c.on_send;
            c.tls_send_src = buf;
            c.tls_send_len = len;
            c.tls_send_off = 0;
            u32 consumed = 0;
            const TlsFill kFs = tls_fill_output<Self>(this, c, buf, len, consumed);
            c.tls_send_off = consumed;
            if (kFs == TlsFill::Fatal) {
                c.tls_pending_on_send = nullptr;
                c.tls_send_src = nullptr;
                c.tls_send_len = 0;
                c.tls_send_off = 0;
                return false;  // caller closes
            }
            if (kFs == TlsFill::NeedRead) {
                c.tls_pending_on_recv = &tls_resume_pending_send_recv<Self>;
                // SSL_write needs peer input to retry. If no recv is armed and one
                // can't be queued (SQ pressure), nothing will ever deliver that
                // input — fail closed rather than hang until the idle timeout
                // (mirrors the resume/drain WANT_READ paths).
                if (!c.recv_armed && !submit_recv(c)) {
                    c.tls_pending_on_recv = nullptr;
                    c.tls_pending_on_send = nullptr;
                    c.tls_send_src = nullptr;
                    c.tls_send_len = 0;
                    c.tls_send_off = 0;
                    return false;  // caller closes
                }
            }
            // Done / NeedRoom: the upper-layer continuation fires from
            // tls_on_out_drain once the whole plaintext is encrypted and sent.
            return true;
        }
        return submit_send_raw(c, buf, len);
    }

    bool submit_connect_impl(Connection& c, const void* addr, u32 addr_len) {
        if (backend.add_connect(c.upstream_fd, c.id, addr, addr_len, c.upstream_episode)) {
            c.pending_ops++;
            c.upstream_connect_armed = true;
            return true;
        }
        return false;
    }

    bool submit_send_upstream_impl(Connection& c, const u8* buf, u32 len) {
        if (backend.add_send_upstream(c.upstream_fd, c.id, buf, len, c.upstream_episode)) {
            c.pending_ops++;
            c.upstream_send_armed = true;
            return true;
        }
        return false;
    }

    bool submit_recv_upstream_impl(Connection& c) {
        if (c.upstream_recv_paused_for_send) {
            c.upstream_recv_pause_rearm_pending = true;
            return true;
        }
        if (c.upstream_recv_armed) {
            // armed can be a DOOMED recv: after a pause cancel, the in-flight recv is
            // being cancelled (its -ECANCELED is pending) even though armed is still set.
            // If either the cancel or that recv terminal is still in flight, this isn't a
            // live recv we can rely on — remember the re-arm so it fires once both drain.
            if (c.upstream_recv_pause_cancel_pending || c.upstream_recv_cancel_inflight)
                c.upstream_recv_pause_rearm_pending = true;
            return true;
        }
        // Defer-until-drains: a prior pause's cancel SQE and/or the cancelled recv are
        // still in flight even though upstream_recv_armed is clear (proxy_stream_complete
        // clears it at the keep-alive boundary while both are still pending). Arming a new
        // multishot recv now would give it the same (conn_id, UpstreamRecv) user_data the
        // stale cancel matches, OR let the stale recv terminal clobber the fresh recv's
        // armed flag. Wait: the cancel CQE clears cancel_pending and the recv terminal
        // clears cancel_inflight; try_deferred_upstream_rearm re-arms once both are clear.
        // (epoll's pause is synchronous and never sets these, so this is io_uring-only.)
        if (c.upstream_recv_pause_cancel_pending || c.upstream_recv_cancel_inflight) {
            c.upstream_recv_pause_rearm_pending = true;
            return true;
        }
        if (backend.add_recv_upstream(c.upstream_fd, c.id, c.upstream_episode)) {
            c.pending_ops++;
            c.upstream_recv_armed = true;
            c.upstream_recv_pause_rearm_pending = false;
            return true;
        }
        return false;
    }

    bool pause_upstream_recv_impl(Connection& c) {
        if (!c.upstream_recv_armed) return true;  // nothing armed — no cancel, no CQE
        if (c.upstream_recv_pause_cancel_pending) {
            // A cancel is already in flight (e.g. a mid-body watermark pause). If the body
            // has SINCE completed — a parked/buffered tail finished it and re-paused here
            // with resp_fully_buffered set — upgrade the stale marker so the in-flight
            // recv's terminal/data is still treated as stale post-body data. The early
            // return must not leave terminal_stale at its mid-body value of false.
            c.upstream_recv_terminal_stale =
                c.upstream_recv_terminal_stale || c.resp_fully_buffered;
            return true;
        }
        // Cancel the multishot recv by user_data — recv-only, so a concurrent upstream
        // send (WS tunnel, overlapping body upload) is never touched. The cancel is
        // COUNTED in pending_ops and its own completion (tagged kPauseCancelAux) is what
        // re-arms the recv (see try_deferred_upstream_rearm): the recv is re-armed only
        // after the cancel drains, so the in-flight cancel can never match a freshly-
        // armed recv on the reused conn_id, and the slot can't be reclaimed until then.
        if (!backend.pause_upstream_recv(c.upstream_fd, c.id, c.upstream_episode)) return false;
        c.upstream_recv_pause_cancel_pending = true;
        // The armed recv will now produce a terminal CQE (-ECANCELED, or a normal
        // completion that beat the cancel). Track it independently of upstream_recv_armed
        // so the re-arm waits for it even after proxy_stream_complete clears armed.
        c.upstream_recv_cancel_inflight = true;
        // Capture whether the body was already complete: if so, the cancelled recv's
        // terminal is stale post-body data to suppress. Captured now because
        // proxy_stream_complete clears resp_fully_buffered before that terminal drains.
        c.upstream_recv_terminal_stale = c.upstream_recv_terminal_stale || c.resp_fully_buffered;
        c.pending_ops++;
        return true;
    }

    // Re-arm an upstream recv that a pause deferred, but ONLY once BOTH the old recv and
    // its pause cancel have drained — armed cleared by the recv's CQE, cancel_pending
    // cleared by the cancel's own CQE (kPauseCancelAux). Re-arming before the cancel
    // drains would let it match the fresh recv on the reused conn_id. The recv and
    // cancel CQEs can arrive in either order, so both terminal branches call this; it
    // fires from whichever lands second. No-op unless a re-arm was actually deferred.
    // Returns false only if the re-arm failed under SQ pressure (caller must close).
    bool try_deferred_upstream_rearm(Connection& c) {
        // Deferred idle-pool return (return_idle_upstream): the cancelled multishot
        // recv has now fully drained (both the cancel and the recv terminal cleared
        // their flags), so the fd parked in idle_return_fd is safe to hand to the
        // pool — no recv can fire on it anymore. Runs at every recv-terminal drain
        // site (all call this) so whichever CQE lands last triggers it. Closes the
        // fd if the pool is full / gone.
        const bool kUpstreamRecvDrained = !c.upstream_recv_pause_cancel_pending &&
                                          !c.upstream_recv_cancel_inflight &&
                                          !c.upstream_recv_armed;
        if (c.idle_return_fd >= 0 && kUpstreamRecvDrained) {
            const i32 fd = c.idle_return_fd;
            c.idle_return_fd = -1;
            // A reload landed while the cancel drained: the pinned config no longer
            // matches the live one, so poll_command's pool drain already ran and this
            // fd's (uid, bidx) may now map to a different backend — close, don't pool.
            const bool kConfigStale = !config_ptr || *config_ptr != c.idle_return_config;
            // Stale bytes the backend wrote after the framed response were copied into
            // upstream_recv_buf while the cancel drained (on_upstream_recv was cleared,
            // so they were silently consumed off the socket). take_idle's MSG_PEEK can't
            // see them anymore, so the next reuse would parse them as an early response —
            // close rather than pool a desynced socket.
            const bool kStaleBytes =
                c.upstream_recv_buf.len() != 0 || c.upstream_recv_idle_stale_bytes;
            const bool kDraining = is_draining();
            if (kStaleBytes) c.upstream_recv_buf.reset();
            c.upstream_recv_idle_stale_bytes = false;
            if (kConfigStale || kStaleBytes || kDraining || !upstream ||
                !upstream->put_idle(fd, c.idle_return_uid, c.idle_return_bidx, monotonic_secs()))
                ::close(fd);
        }
        // Deferred close: close_conn_impl tore the conn down (e.g. Connection: close)
        // while the deferred pool-return was still draining, leaving the slot allocated
        // so these recv-terminal CQEs would route here. The fd is now pooled (above) and
        // the recv has fully drained, so finish the slot-free that close_conn skipped.
        // free_conn defers reclamation itself if client-side cancel CQEs are still in
        // flight (parks the conn in pending_free until pending_ops hits 0).
        if (c.close_after_idle_return && kUpstreamRecvDrained) {
            c.close_after_idle_return = false;
            this->free_conn(c);
            return true;
        }
        if (c.upstream_recv_pause_cancel_pending || c.upstream_recv_cancel_inflight ||
            c.upstream_recv_armed || !c.upstream_recv_pause_rearm_pending ||
            c.upstream_recv_paused_for_send || c.upstream_fd < 0) {
            // upstream_fd < 0 ⇒ the connection is being torn down (close_conn closed the
            // upstream) — don't re-arm a recv on a dead fd. A live deferred re-arm always
            // has upstream_fd >= 0, since rearm_pending is only set by a submit_recv_-
            // upstream call, which happens only once the upstream is connected.
            return true;
        }
        c.upstream_recv_pause_rearm_pending = false;
        return submit_recv_upstream_impl(c);
    }

    [[nodiscard]] bool pause_upstream_recv_for_send(Connection& c) {
        c.upstream_recv_paused_for_send = true;
        return pause_upstream_recv_impl(c);
    }

    [[nodiscard]] bool pause_recv(Connection& c) {
        c.recv_paused_for_send = true;
        if (c.uses_iouring_tls() && c.tls_pending_on_recv == &tls_resume_pending_send_recv<Self>)
            return true;
        c.recv_pause_cancel_pending = true;
        if (!c.recv_armed) return true;
        return backend.pause_recv(c.fd, c.id);
    }

    void close_conn_impl(Connection& c) {
        // A close is terminal for a parked request boundary. Readiness may have
        // been published earlier in the same CQE batch; batch-end scans must see
        // cleared state and never repeat request-1 completion on a dead slot.
        c.http1_boundary_deferred = false;
        c.http1_boundary_ready = false;
        c.http1_boundary_successor_episode = 0;
        c.http1_prebuilt_wait = 0;
        c.http1_prebuilt_disposition = Http1RequestBufferDisposition::None;
        c.http1_prebuilt_request_prefix_len = 0;
        // epoch_held covers a suspended continuation pinning the config epoch
        // after its ordinary req_start_us ownership has ended (or an HTTP/2
        // async stream which never used h1 request timing).
        if (c.req_start_us != 0 || c.epoch_held) epoch_leave();
        c.epoch_held = false;
        // Release any held upstream concurrency slot (catch-all; held flag makes a
        // prior release at completion a no-op).
        if (c.upstream_slot_held) {
            upstream_release(c.upstream_slot_uid);
            c.upstream_slot_held = false;
        }
        const bool idle_return_recv_draining =
            c.idle_return_fd >= 0 && (c.upstream_recv_armed || c.upstream_recv_cancel_inflight ||
                                      c.upstream_recv_pause_cancel_pending);
        // Preserve exact live-successor ownership across free_conn::reset().
        // The old C1 token remains in its separate tombstone; this ledger is
        // only for operations submitted under the current successor token.
        const bool successor_close_already_owned = c.upstream_close_target_owned != 0 ||
                                                   c.upstream_close_cancel_owned != 0 ||
                                                   c.upstream_close_pause_cancel_owned;
        if (!idle_return_recv_draining && !successor_close_already_owned &&
            valid_upstream_episode(c.upstream_episode)) {
            u8 targets = 0;
            if (c.upstream_connect_armed) targets |= kUpstreamOpConnect;
            if (c.upstream_recv_armed || c.upstream_recv_cancel_inflight)
                targets |= kUpstreamOpRecv;
            if (c.upstream_send_armed) targets |= kUpstreamOpSend;
            if (targets != 0 || c.upstream_recv_pause_cancel_pending) {
                c.upstream_close_episode = c.upstream_episode;
                c.upstream_close_target_owned = targets;
                c.upstream_close_pause_cancel_owned = c.upstream_recv_pause_cancel_pending;
            }
        }
        // Only cancel when ops are in flight.
        if (c.pending_ops > 0) {
            // If an idle upstream fd is parked waiting for its old multishot recv to
            // drain, do not submit another close-path UpstreamRecv cancel for a newer
            // upstream_fd on the same conn_id. The parked recv/cancel pair owns these
            // flags until try_deferred_upstream_rearm observes both CQEs.
            const bool cancel_upstream_recv = c.upstream_recv_armed &&
                                              !c.upstream_recv_pause_cancel_pending &&
                                              !idle_return_recv_draining;
            u8 close_cancel_mask = 0;
            const u32 submitted = backend.cancel(c.fd,
                                                 c.id,
                                                 c.recv_armed,
                                                 c.send_armed,
                                                 c.upstream_connect_armed,
                                                 cancel_upstream_recv,
                                                 c.upstream_send_armed,
                                                 c.upstream_fd >= 0,
                                                 c.upstream_episode,
                                                 c.yield_timeout_armed,
                                                 c.yield_timer_gen,
                                                 &close_cancel_mask);
            c.upstream_close_cancel_owned |= close_cancel_mask;
            c.pending_ops += submitted;
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
        // A deferred idle-pool return (return_idle_upstream parked a still-reusable
        // upstream fd in idle_return_fd) whose cancelled multishot recv has NOT yet
        // drained. Don't discard the reusable fd or free the slot: keep the conn
        // allocated so the in-flight cancel + recv-terminal CQEs still route here by
        // conn_id. try_deferred_upstream_rearm then pools the fd AND performs this
        // deferred free once the recv drains. Quiesce the client side (timer + I/O
        // callbacks) so a stray client terminal CQE can't dispatch on the now-closed
        // connection; the upstream-recv terminal branches key off the recv flags (left
        // intact here), not these callbacks, so the drain still completes. epoch / slot
        // / metrics above have already run exactly once — the deferred free_conn does
        // none of them, so there is no double release.
        if (idle_return_recv_draining) {
            c.close_after_idle_return = true;
            timer.remove(&c);
            c.on_recv = nullptr;
            c.on_send = nullptr;
            c.on_upstream_recv = nullptr;
            c.on_upstream_send = nullptr;
            c.pending_handler_fn = nullptr;
            return;
        }
        // idle_return_fd set but already drained (no recv still racing it): the fd is
        // reusable, so pool it rather than discard. In practice the synchronous close
        // right after return_idle_upstream always leaves the cancel in flight, so this
        // pools only if the recv happened to drain before close_conn ran — either way a
        // reusable fd must not be leaked/closed.
        if (c.idle_return_fd >= 0) {
            const i32 fd = c.idle_return_fd;
            c.idle_return_fd = -1;
            // Same refusals as the deferred drain in try_deferred_upstream_rearm: a
            // config swap (poll_command drained the pool) or surplus bytes copied into
            // upstream_recv_buf both desync reuse — close rather than pool.
            const bool kConfigStale = !config_ptr || *config_ptr != c.idle_return_config;
            const bool kStaleBytes =
                c.upstream_recv_buf.len() != 0 || c.upstream_recv_idle_stale_bytes;
            const bool kDraining = is_draining();
            if (kStaleBytes) c.upstream_recv_buf.reset();
            c.upstream_recv_idle_stale_bytes = false;
            if (kConfigStale || kStaleBytes || kDraining || !upstream ||
                !upstream->put_idle(fd, c.idle_return_uid, c.idle_return_bidx, monotonic_secs()))
                ::close(fd);
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

    // Park a @throttle-paused proxy connection for `delay_ns` via an io_uring
    // TIMEOUT SQE (ms granularity — fine for byte pacing; throttle_resume
    // re-checks the budget so rounding/early wake is safe). Reuses the JIT yield
    // timeout machinery; the HandlerTimer CQE routes back to throttle_resume when
    // the connection is throttle_paused. Returns false on SQ pressure → caller
    // falls back to the keepalive wheel.
    [[nodiscard]] bool arm_throttle_timer(Connection& conn, u64 delay_ns) {
        timer.remove(&conn);
        u32 ms = static_cast<u32>((delay_ns + 999'999ull) / 1'000'000ull);
        if (ms == 0) ms = 1;
        if (backend.add_yield_timeout(conn.id, conn, ms)) {
            conn.yield_armed = true;
            conn.yield_timeout_armed = true;
            conn.pending_ops++;
            return true;
        }
        return false;
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
                    if (c.throttle_paused && matching_generation) {
                        // @throttle pacing timer fired — resume the parked proxy
                        // pump (re-checks the byte budget; may re-park).
                        throttle_resume<IoUringEventLoop>(this, c);
                    } else if (c.pending_handler_fn && matching_generation &&
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
                            // Upstream stalled before responding → 504. A genuine
                            // in-flight h2 proxy stream reframes as h2 (raw h1 504
                            // bytes would corrupt the stream); anything else uses
                            // the HTTP/1 path.
                            if (c->protocol == ConnProtocol::Http2 && c->h2 != nullptr &&
                                c->h2->async_stream != 0)
                                h2_proxy_fail<IoUringEventLoop>(this, *c, 504);
                            else
                                respond_upstream_timeout<IoUringEventLoop>(this, *c);
                        } else if (c->throttle_paused) {
                            throttle_resume<IoUringEventLoop>(this, *c);
#if RUT_ENABLE_WEBSOCKET
                        } else if (c->is_ws_tunnel || c->is_ws_terminate) {
                            // WebSocket tunnel/terminate: long-lived sessions
                            // have no idle keepalive timeout — a quiet-but-
                            // healthy WebSocket must not be reaped at the HTTP
                            // keep-alive deadline (RFC 6455 liveness is
                            // ping/pong, not idle close).
#endif
                        } else {
                            this->close_conn(*c);
                        }
                    });
                }
                this->fire_due_timers();
                // io_uring: sweep re-arms health-probe deadlines but issues no
                // probes (kSupportsHealthProbe == false). EPOLL-only this slice.
                this->sweep_health_probes();
                // Evict idle pooled upstream sockets past the keepalive deadline
                // (1s-granular) — bounds dead-socket accumulation for endpoints that
                // never get another request to trigger take_idle's probe.
                if (upstream)
                    upstream->sweep(static_cast<u32>(monotonic_secs()), keepalive_timeout);
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
                    if (consume_strict_upstream_retirement_event(conn, ev)) break;
                    if (consume_prebuilt_http1_header_send_event(conn, ev)) break;
                    const bool stale_tagged_upstream =
                        io_event_is_tagged_stale(ev, conn.upstream_episode);
                    if (stale_tagged_upstream) {
                        // The backend has already returned any provided buffer.
                        // Retire only this completion's lifetime accounting; do
                        // not touch current callbacks, armed flags, timers, or
                        // handler state.
                        if (!ev.more && conn.pending_ops > 0) conn.pending_ops--;
                        if (conn.fd < 0 && conn.pending_ops == 0) reclaim_slot(conn.id);
                        break;
                    }
                    // A strict-retirement boundary may coexist with the
                    // long-lived downstream multishot recv. wait() has already
                    // copied positive provided-buffer bytes into recv_buf; keep
                    // them byte-exact but do not parse, route, refresh timers,
                    // invoke callbacks, or alter request state until batch-end
                    // retirement handoff. Terminal-positive rearms only this
                    // buffering recv target. EOF/error/cancel fails closed and
                    // cancels the marker without repeating request completion.
                    if (ev.type == IoEventType::Recv &&
                        (conn.http1_boundary_deferred ||
                         conn.http1_prebuilt_disposition != Http1RequestBufferDisposition::None)) {
                        if (!ev.more) {
                            if (conn.pending_ops > 0) conn.pending_ops--;
                            conn.recv_armed = false;
                        }
                        if (ev.result <= 0) {
                            this->close_conn(conn);
                            break;
                        }
                        if (!ev.more && !this->submit_recv_impl(conn)) {
                            this->close_conn(conn);
                        }
                        break;
                    }
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
                    // The pause cancel's OWN completion (real conn_id + kPauseCancelAux,
                    // counted in pending_ops). The cancel has fully drained, so a freshly-
                    // armed recv on this conn_id can no longer be matched by it — re-arm
                    // now if the recv side has also drained. Carries no data.
                    if (ev.type == IoEventType::UpstreamRecv && ev.aux == kPauseCancelAux) {
                        if (conn.pending_ops > 0) conn.pending_ops--;
                        conn.upstream_recv_pause_cancel_pending = false;
                        if (conn.fd < 0) {
                            // Connection already closed — this is a stale/close-path cancel
                            // completion. The early break below skips the generic
                            // pending_ops==0 reclaim, so reclaim here if it was the last op,
                            // or the slot leaks and proxy churn exhausts the table. A deferred
                            // close (close_after_idle_return) routes through the rearm helper
                            // instead: it pools idle_return_fd once the recv fully drains and
                            // then performs the slot-free close_conn postponed.
                            if (conn.close_after_idle_return)
                                this->try_deferred_upstream_rearm(conn);
                            else if (conn.pending_ops == 0)
                                this->reclaim_slot(conn.id);
                            break;
                        }
                        if (!this->try_deferred_upstream_rearm(conn)) this->close_conn(conn);
                        break;
                    }
                    if (ev.type == IoEventType::UpstreamRecv && ev.result == -ECANCELED) {
                        // The recv was cancelled (cancel won the race). Don't clear
                        // cancel_pending or re-arm here — the cancel's own CQE owns that,
                        // and may not have drained yet. Account the recv and mark its
                        // terminal drained; re-arm fires from whichever of {recv, cancel}
                        // CQE lands second.
                        conn.upstream_recv_armed = false;
                        conn.upstream_recv_cancel_inflight = false;
                        conn.upstream_recv_terminal_stale = false;
                        // A torn-down h2-proxy episode's recv terminal has now drained,
                        // so the next episode may safely arm its own recv — but first
                        // discard any stale positive bytes wait() copied into the buffer
                        // before this terminal, or the next stream would parse them as its
                        // own response. Gated on the flag so the normal recv path (which
                        // delivers the real bytes below) is untouched.
                        if (conn.h2_proxy_recv_draining) {
                            conn.h2_proxy_recv_draining = false;
                            conn.upstream_recv_buf.reset();
                        }
                        if (conn.pending_ops > 0) conn.pending_ops--;
                        if (conn.fd < 0) {
                            // Closed conn (e.g. the close-path cancel of an armed upstream
                            // recv): reclaim the slot if this drained the last op, since the
                            // break skips the generic reclaim below. A deferred close pools
                            // idle_return_fd + performs its postponed slot-free via the rearm
                            // helper once the recv has fully drained.
                            if (conn.close_after_idle_return)
                                this->try_deferred_upstream_rearm(conn);
                            else if (conn.pending_ops == 0)
                                this->reclaim_slot(conn.id);
                            break;
                        }
                        if (!this->try_deferred_upstream_rearm(conn)) this->close_conn(conn);
                        break;
                    }
                    // Stale post-body recv data/terminal. A body-done pause cancelled this
                    // recv (cancel_inflight) at the keep-alive boundary, but its already-
                    // harvested multishot CQEs — both F_MORE data and the final terminal —
                    // still arrive, and wait() has already appended their bytes to
                    // upstream_recv_buf. Roll those bytes back and NEVER deliver: once
                    // proxy_stream_complete repoints the slot to the next pipelined request,
                    // delivering or leaving stale bytes would corrupt/close it. (The next
                    // request's recv can't have produced data yet — it re-arms only after
                    // THIS recv drains.) Only the final CQE accounts/drains the recv.
                    if (ev.type == IoEventType::UpstreamRecv &&
                        conn.upstream_recv_cancel_inflight && conn.upstream_recv_terminal_stale) {
                        if (ev.result > 0) {
                            if (conn.idle_return_fd >= 0)
                                conn.upstream_recv_idle_stale_bytes = true;
                            const u32 stale = static_cast<u32>(ev.result);
                            if (conn.upstream_recv_buf.len() >= stale)
                                conn.upstream_recv_buf.set_len(conn.upstream_recv_buf.len() -
                                                               stale);
                        }
                        if (!ev.more) {
                            conn.upstream_recv_armed = false;
                            conn.upstream_recv_cancel_inflight = false;
                            conn.upstream_recv_terminal_stale = false;
                            if (conn.pending_ops > 0) conn.pending_ops--;
                            if (conn.fd < 0) {
                                // A deferred close pools idle_return_fd + performs its
                                // postponed slot-free via the rearm helper once the recv has
                                // fully drained; otherwise reclaim if this was the last op.
                                if (conn.close_after_idle_return)
                                    this->try_deferred_upstream_rearm(conn);
                                else if (conn.pending_ops == 0)
                                    this->reclaim_slot(conn.id);
                                break;
                            }
                            if (!this->try_deferred_upstream_rearm(conn)) this->close_conn(conn);
                        }
                        break;
                    }
                    // Async CQE accounting: decrement pending_ops on final CQE.
                    if (!ev.more) {
                        if (conn.pending_ops > 0) conn.pending_ops--;
                        if (ev.type == IoEventType::Recv) conn.recv_armed = false;
                        if (ev.type == IoEventType::Send) conn.send_armed = false;
                        if (ev.type == IoEventType::UpstreamConnect)
                            conn.upstream_connect_armed = false;
                        if (ev.type == IoEventType::UpstreamSend) {
                            conn.upstream_send_armed = false;
                            // A torn-down h2-proxy episode's request send has now drained, so
                            // pending_synth is free again — lift the reuse quarantine.
                            conn.h2_proxy_synth_quarantined = false;
                        }
                        if (ev.type == IoEventType::UpstreamRecv) {
                            // Recv ended normally and is NOT stale (the stale case is handled
                            // and dropped above). If a pause cancel lost the race its own CQE
                            // still clears cancel_pending and owns the re-arm; here just
                            // account, mark the recv terminal drained, and re-arm if both
                            // sides drained, then fall through to deliver the real bytes.
                            conn.upstream_recv_armed = false;
                            conn.upstream_recv_cancel_inflight = false;
                            conn.upstream_recv_terminal_stale = false;
                            // A torn-down h2-proxy episode's recv terminal has now drained;
                            // discard any stale positive bytes it left so the next stream
                            // can't parse them as its response. Gated on the flag so the
                            // normal recv (delivered via dispatch_event below) is untouched
                            // — for the draining case on_upstream_recv is null, so the
                            // fall-through delivery is suppressed by the abandoned guard.
                            if (conn.h2_proxy_recv_draining) {
                                conn.h2_proxy_recv_draining = false;
                                conn.upstream_recv_buf.reset();
                            }
                            if (conn.fd < 0) {
                                // Closed conn: reclaim if this was the last op (the break
                                // below skips the generic pending_ops==0 reclaim). A deferred
                                // close pools idle_return_fd + performs its postponed slot-free
                                // via the rearm helper once the recv has fully drained.
                                if (conn.close_after_idle_return)
                                    this->try_deferred_upstream_rearm(conn);
                                else if (conn.pending_ops == 0)
                                    this->reclaim_slot(conn.id);
                                break;
                            }
                            if (!this->try_deferred_upstream_rearm(conn)) {
                                this->close_conn(conn);
                                break;
                            }
                        }
                    }
                    const bool has_recv_slot =
                        conn.on_recv && (!conn.uses_iouring_tls() || conn.tls_pending_on_recv);
                    if (has_recv_slot || conn.on_send || conn.on_upstream_recv ||
                        conn.on_upstream_send) {
                        // See EpollEventLoop: don't let stray events bump a
                        // @throttle-paused connection's byte-rate-window timer back
                        // to the keepalive timeout.
                        if (!conn.throttle_paused)
                            timer.refresh(&conn,
                                          conn.state == ConnState::Proxying ? upstream_timeout
                                                                            : keepalive_timeout);
                        if (ev.type == IoEventType::Send) conn.recv_paused_for_send = false;
                        this->dispatch_event(conn, ev);
                    } else if (conn.pending_handler_fn) {
                        if (yield_kind_matches_event(conn.pending_yield_kind, ev.type)) {
                            if (conn.uses_iouring_tls() && ev.type == IoEventType::Recv) {
                                conn.tls_pending_on_recv =
                                    &tls_resume_pending_handler_recv<IoUringEventLoop>;
                                tls_recv<IoUringEventLoop>(this, conn, ev);
                                if (conn.tls_active && conn.pending_handler_fn)
                                    conn.tls_pending_on_recv = nullptr;
                                break;
                            }
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

    // Forced drain-deadline shutdown: close every live client, then close any
    // upstream fd still parked for a deferred idle-pool return. Public so the
    // deferred-fd close path is unit-testable. Called only from run().
    void force_close_all() {
        close_live_clients();
        close_deferred_idle_return_fds();
    }

private:
    using Self = IoUringEventLoop;

    void close_live_clients() {
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0) {
                // A LIVE keep-alive client can also hold a parked idle_return_fd while
                // its upstream recv cancel drains. close_conn takes the deferred path
                // here (keeps the conn allocated, leaves idle_return_fd for a future
                // CQE) — so the fd survives below and is closed there.
                this->close_conn(conns[i]);
            }
        }
    }

    void close_deferred_idle_return_fds() {
        for (u32 i = 0; i < kMaxConns; i++) {
            // A reusable upstream fd is parked in idle_return_fd awaiting a recv-cancel
            // drain that this forced shutdown will never deliver — close it directly so
            // it can't leak. Covers both a slot whose client fd was already closed
            // (deferred-close) and a live client just torn down above whose close_conn
            // took the deferred path. close_conn's synchronous path already pooled/closed
            // and set idle_return_fd = -1, so the guard prevents a double-close.
            if (conns[i].idle_return_fd >= 0) {
                ::close(conns[i].idle_return_fd);
                conns[i].idle_return_fd = -1;
            }
        }
    }

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
        if (tls_server) {
            if (!tls_setup(*c)) {
                ::close(c->fd);
                c->fd = -1;
                this->free_conn(*c);
                return;
            }
        } else {
            c->on_recv = &on_header_received<Self>;
        }
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
            if (tls_server) {
                if (!tls_setup(*c)) {
                    ::close(c->fd);
                    c->fd = -1;
                    this->free_conn(*c);
                    continue;
                }
            } else {
                c->on_recv = &on_header_received<Self>;
            }
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
};

}  // namespace rut
