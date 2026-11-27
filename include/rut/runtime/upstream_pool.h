#pragma once

#include "rut/common/checked_arithmetic.h"
#include "rut/common/types.h"
#include "rut/platform/socket.h"
#include "rut/runtime/route_table.h"
#include <atomic>

#include <errno.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

namespace rut {

// Per-shard idle upstream connection pool (HTTP/1 keep-alive reuse).
//
// Holds connected, currently-unused upstream sockets so a later proxy request to
// the same endpoint can skip the TCP connect. Each shard owns one UpstreamPool;
// fd slots remain shard-local, while idle_count is atomic so tests/metrics can
// observe progress without racing the owner thread. An idle entry is keyed by the
// endpoint it connects to: (upstream_id, backend_idx) — multi-backend upstreams keep a
// separate reusable socket per backend address.
//
// Lifecycle: the proxy completion path calls put_idle() to hand a live fd over
// (detached from its Connection); a new proxy request calls take_idle() to borrow
// one back. The pool never owns a Connection — only the raw fd.

struct UpstreamConn {
    i32 fd = -1;
    u16 upstream_id = 0;
    u8 backend_idx = 0;      // which backend endpoint of the upstream this connects to
    bool idle = false;       // true = parked, available for reuse
    bool allocated = false;  // true = slot in use
    i32 completed_requests = 0;
    // Seconds in legacy mode; microseconds when an explicit positive timeout is set.
    u64 parked_time = 0;
};

struct UpstreamPool {
    static constexpr u32 kMaxConns = 4096;

    static constexpr u32 kNoSlot = 0xFFFFFFFFu;

    UpstreamConn conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top = 0;
    bool idle_timeout_configured = false;
    u32 idle_timeout_sec = 0;
    u32 endpoint_capacity = kMaxConns;
    i32 max_requests = 0;
    u16 endpoint_counts[RouteConfig::kMaxUpstreams][UpstreamTarget::kMaxBackends]{};
    // Parked slots form an intrusive list, most recently parked first, so
    // take_idle() and sweep() visit only idle entries instead of every slot.
    u32 idle_prev[kMaxConns];
    u32 idle_next[kMaxConns];
    u32 idle_head = kNoSlot;
    // live idle entries — lets take_idle() skip the scan when cold. Atomic only for
    // cross-thread observation; pool slot ownership remains single-threaded.
    std::atomic<u32> idle_count{0};

    void init(u32 capacity = kMaxConns) {
        endpoint_capacity = capacity <= kMaxConns ? capacity : kMaxConns;
        reset_endpoint_counts();
        free_top = kMaxConns;
        idle_count.store(0, std::memory_order_relaxed);
        reset_idle_list();
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i] = UpstreamConn{};
            free_stack[i] = i;
        }
    }

    // Park a connected, idle upstream fd for reuse by a later request to the same
    // (upstream_id, backend_idx) endpoint. Returns false when the endpoint quota
    // or pool is full, reuse is disabled, or the key is invalid. The caller must
    // close a rejected fd. The fd must have no I/O armed on it. `completed`
    // counts earlier clean requests on this socket, before the current response.
    bool put_idle(i32 fd, u16 upstream_id, u8 backend_idx, u32 now_sec, i32 completed = 0) {
        return put_idle_at(fd,
                           upstream_id,
                           backend_idx,
                           now_sec,
                           idle_timeout_configured && idle_timeout_sec ? clock_us() : 0,
                           completed);
    }

    bool put_idle_at(
        i32 fd, u16 upstream_id, u8 backend_idx, u32 now_sec, u64 now_us, i32 completed = 0) {
        u32 idx;
        // The active socket has completed one more clean request at this boundary.
        i32 completed_after = 0;
        if (completed < 0 || max_requests < 0 ||
            (max_requests && (__builtin_add_overflow(completed, 1, &completed_after) ||
                              completed_after >= max_requests)))
            return false;
        if (fd < 0 || upstream_id >= RouteConfig::kMaxUpstreams ||
            backend_idx >= UpstreamTarget::kMaxBackends ||
            endpoint_counts[upstream_id][backend_idx] >= endpoint_capacity || !pop_free_slot(idx))
            return false;
        ++endpoint_counts[upstream_id][backend_idx];
        conns[idx] = {fd,
                      upstream_id,
                      backend_idx,
                      /*idle=*/true,
                      /*allocated=*/true,
                      completed_after,
                      idle_timeout_configured && idle_timeout_sec ? now_us : now_sec};
        link_idle(idx);
        idle_count.fetch_add(1, std::memory_order_release);
        return true;
    }

    // Close parked sockets idle for at least max_idle_sec — bounds resource use for
    // sockets a backend silently closes while parked (no event watches an idle fd;
    // take_idle's probe only fires for endpoints that receive another request, so a
    // low-traffic or removed endpoint could otherwise hold dead fds until reload).
    // Driven by the per-shard 1s timer tick. No-op when the pool is empty.
    void sweep(u32 now_sec, u32 max_idle_sec) {
        if (idle_timeout_configured) max_idle_sec = idle_timeout_sec;
        if ((idle_timeout_configured && max_idle_sec == 0) ||
            idle_count.load(std::memory_order_acquire) == 0)
            return;
        const u64 now_us = idle_timeout_configured ? clock_us() : 0;
        sweep_at(now_sec, max_idle_sec, now_us);
    }

    void sweep_at(u32 now_sec, u32 max_idle_sec, u64 now_us) {
        for (u32 i = idle_head; i != kNoSlot;) {
            const u32 next = idle_next[i];
            UpstreamConn& c = conns[i];
            const u32 idle = wrapping_sub(now_sec, static_cast<u32>(c.parked_time));
            u64 idle_us = 0;
            if (idle_timeout_configured
                    ? !sub_overflow(now_us, c.parked_time, &idle_us) &&
                          idle_us >= static_cast<u64>(max_idle_sec) * 1000000u
                    : idle >= max_idle_sec) {
                ::close(c.fd);
                release_slot(i);
            }
            i = next;
        }
    }

    // Borrow a reusable idle fd for the given endpoint, or -1 if none is live.
    // Each candidate is liveness-probed with a non-blocking MSG_PEEK: a socket the
    // backend already closed (EOF) or errored is closed and skipped, and one with
    // unexpected pending bytes (a desynced/half-pipelined socket) is discarded too
    // — only an EAGAIN (nothing buffered, still open) socket is handed back. This
    // catches the common idle-timeout race before any request bytes are sent; the
    // residual probe-vs-send race is handled by the caller's idempotent resend.
    // Candidates are tried most recently parked first (the likeliest to be live).
    i32 take_idle(u16 upstream_id, u8 backend_idx, i32* completed = nullptr) {
        if (idle_count.load(std::memory_order_acquire) == 0) return -1;
        return take_idle_at(upstream_id,
                            backend_idx,
                            idle_timeout_configured && idle_timeout_sec ? clock_us() : 0,
                            completed);
    }

    i32 take_idle_at(u16 upstream_id, u8 backend_idx, u64 now_us, i32* completed = nullptr) {
        for (u32 i = idle_head; i != kNoSlot;) {
            const u32 next = idle_next[i];
            const UpstreamConn& c = conns[i];
            if (c.upstream_id != upstream_id || c.backend_idx != backend_idx) {
                i = next;
                continue;
            }
            const i32 fd = c.fd;
            const i32 prior_completed = c.completed_requests;
            u64 idle_us = 0;
            const bool expired = idle_timeout_configured && idle_timeout_sec != 0 &&
                                 !__builtin_sub_overflow(now_us, c.parked_time, &idle_us) &&
                                 idle_us >= static_cast<u64>(idle_timeout_sec) * 1000000u;
            release_slot(i);
            if (expired) {
                ::close(fd);
                i = next;
                continue;
            }
            char probe;
            const ssize_t n = ::recv(fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (completed) *completed = prior_completed;
                return fd;
            }
            ::close(fd);  // EOF / unexpected data / hard error → not reusable
            i = next;
        }
        return -1;
    }

    // Close every parked socket and return to the empty (but usable) state. Called
    // on config reload: a hot reload can repoint an upstream endpoint while keeping
    // the same (upstream_id, backend_idx), so idle sockets parked under the old
    // config must not be handed out for the new endpoint. No-op when already empty.
    void drain() {
        if (idle_count.load(std::memory_order_acquire) == 0) return;
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0) ::close(conns[i].fd);
            conns[i] = UpstreamConn{};
        }
        free_top = kMaxConns;
        idle_count.store(0, std::memory_order_release);
        reset_idle_list();
        reset_endpoint_counts();
        for (u32 i = 0; i < kMaxConns; i++) free_stack[i] = i;
    }

    // Close every parked socket and reset to the initial all-free state.
    void shutdown() {
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0) ::close(conns[i].fd);
            conns[i] = UpstreamConn{};
        }
        free_top = kMaxConns;
        idle_count.store(0, std::memory_order_release);
        reset_idle_list();
        reset_endpoint_counts();
        for (u32 i = 0; i < kMaxConns; i++) free_stack[i] = i;
    }

    // Create a non-blocking upstream socket. Returns fd on success, -1 on failure.
    static i32 create_socket() { return platform::stream_socket(); }

private:
    static u64 clock_us() {
        timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        u64 now_us = static_cast<u64>(ts.tv_sec) * 1000000u;
        (void)__builtin_add_overflow(now_us, static_cast<u64>(ts.tv_nsec) / 1000u, &now_us);
        return now_us;
    }

    void reset_endpoint_counts() {
        for (u32 i = 0; i < RouteConfig::kMaxUpstreams; ++i)
            for (u32 j = 0; j < UpstreamTarget::kMaxBackends; ++j) endpoint_counts[i][j] = 0;
    }

    bool pop_free_slot(u32& slot) {
        if (free_top == 0) return false;
        slot = free_stack[--free_top];
        return true;
    }

    void push_free_slot(u32 slot) {
        if (free_top < kMaxConns) free_stack[free_top++] = slot;
    }

    void reset_idle_list() {
        idle_head = kNoSlot;
        for (u32 i = 0; i < kMaxConns; i++) idle_prev[i] = idle_next[i] = kNoSlot;
    }

    void link_idle(u32 i) {
        idle_prev[i] = kNoSlot;
        idle_next[i] = idle_head;
        if (idle_head != kNoSlot) idle_prev[idle_head] = i;
        idle_head = i;
    }

    void unlink_idle(u32 i) {
        const u32 prev = idle_prev[i];
        const u32 next = idle_next[i];
        if (prev != kNoSlot)
            idle_next[prev] = next;
        else
            idle_head = next;
        if (next != kNoSlot) idle_prev[next] = prev;
        idle_prev[i] = idle_next[i] = kNoSlot;
    }

    void release_slot(u32 i) {
        unlink_idle(i);
        --endpoint_counts[conns[i].upstream_id][conns[i].backend_idx];
        conns[i] = UpstreamConn{};
        push_free_slot(i);
        u32 count = idle_count.load(std::memory_order_relaxed);
        while (count > 0 &&
               !idle_count.compare_exchange_weak(count,
                                                 static_cast<u32>(static_cast<i64>(count) - 1),
                                                 std::memory_order_release,
                                                 std::memory_order_relaxed)) {
        }
    }
};

}  // namespace rut
