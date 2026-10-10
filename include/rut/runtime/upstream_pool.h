#pragma once

#include "rut/common/types.h"
#include "rut/platform/socket.h"
#include <atomic>

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
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
    u32 parked_sec = 0;      // monotonic seconds when parked (idle-timeout sweep)
};

struct UpstreamPool {
    static constexpr u32 kMaxConns = 4096;

    static constexpr u32 kNoSlot = 0xFFFFFFFFu;

    UpstreamConn conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top = 0;
    // Parked slots form an intrusive list, most recently parked first, so
    // take_idle() and sweep() visit only idle entries instead of every slot.
    u32 idle_prev[kMaxConns];
    u32 idle_next[kMaxConns];
    u32 idle_head = kNoSlot;
    // live idle entries — lets take_idle() skip the scan when cold. Atomic only for
    // cross-thread observation; pool slot ownership remains single-threaded.
    std::atomic<u32> idle_count{0};
    void* idle_close_ctx = nullptr;
    void (*before_idle_close)(void*, i32) = nullptr;
    bool (*idle_reuse_probe_required)(void*, i32, u32) = nullptr;

    void close_idle_fd(i32 fd) {
        if (before_idle_close != nullptr) before_idle_close(idle_close_ctx, fd);
        ::close(fd);
    }

    void init() {
        free_top = kMaxConns;
        idle_count.store(0, std::memory_order_relaxed);
        reset_idle_list();
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i] = UpstreamConn{};
            free_stack[i] = i;
        }
    }

    // Park a connected, idle upstream fd for reuse by a later request to the same
    // (upstream_id, backend_idx) endpoint. Returns false if the pool is full (the
    // caller must close the fd itself). The fd must have no I/O armed on it.
    bool put_idle(
        i32 fd, u16 upstream_id, u8 backend_idx, u32 now_sec, u32* parked_slot = nullptr) {
        if (parked_slot != nullptr) *parked_slot = kNoSlot;
        if (fd < 0 || free_top == 0) return false;
        const u32 idx = free_stack[--free_top];
        conns[idx] = {fd, upstream_id, backend_idx, /*idle=*/true, /*allocated=*/true, now_sec};
        link_idle(idx);
        idle_count.fetch_add(1, std::memory_order_release);
        if (parked_slot != nullptr) *parked_slot = idx;
        return true;
    }

    // An idle watcher must prove the slot still owns this exact descriptor.
    // A harvested event may outlive borrow, sweep, reload or slot reuse.
    bool discard_idle(u32 slot, i32 fd) {
        if (slot >= kMaxConns || !conns[slot].allocated || !conns[slot].idle ||
            conns[slot].fd != fd)
            return false;
        close_idle_fd(fd);
        release_slot(slot);
        return true;
    }

    // Close parked sockets idle for at least max_idle_sec — bounds resource use for
    // sockets a backend silently closes while parked (no event watches an idle fd;
    // take_idle's probe only fires for endpoints that receive another request, so a
    // low-traffic or removed endpoint could otherwise hold dead fds until reload).
    // Driven by the per-shard 1s timer tick. No-op when the pool is empty.
    void sweep(u32 now_sec, u32 max_idle_sec) {
        if (idle_count.load(std::memory_order_acquire) == 0) return;
        for (u32 i = idle_head; i != kNoSlot;) {
            const u32 next = idle_next[i];
            UpstreamConn& c = conns[i];
            if (now_sec - c.parked_sec >= max_idle_sec) {
                close_idle_fd(c.fd);
                release_slot(i);
            }
            i = next;
        }
    }

    // Borrow a reusable idle fd for the given endpoint, or -1 if none is live.
    // Without an idle event watcher, candidates are checked with MSG_PEEK: a socket the
    // backend already closed (EOF) or errored is closed and skipped, and one with
    // unexpected pending bytes (a desynced/half-pipelined socket) is discarded too
    // — only an EAGAIN (nothing buffered, still open) socket is handed back. This
    // catches the common idle-timeout race before any request bytes are sent; the
    // residual probe-vs-send race is handled by the caller's idempotent resend.
    // An idle watcher may eagerly invalidate known readiness, but every borrow
    // still probes the socket. Userspace readiness state cannot prove that the
    // kernel had no new bytes after parking and before this borrow.
    // Candidates are tried most recently parked first (the likeliest to be live).
    i32 take_idle(u16 upstream_id, u8 backend_idx) {
        if (idle_count.load(std::memory_order_acquire) == 0) return -1;
        for (u32 i = idle_head; i != kNoSlot;) {
            const u32 next = idle_next[i];
            const UpstreamConn& c = conns[i];
            if (c.upstream_id != upstream_id || c.backend_idx != backend_idx) {
                i = next;
                continue;
            }
            const i32 fd = c.fd;
            // The callback remains responsible for watcher-side ownership fencing
            // and stale-event invalidation. It cannot suppress this probe: bytes
            // may arrive after the last harvested event and before take_idle().
            (void)(idle_reuse_probe_required == nullptr ||
                   idle_reuse_probe_required(idle_close_ctx, fd, i));
            release_slot(i);
            char probe;
            const ssize_t n = ::recv(fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return fd;  // healthy
            close_idle_fd(fd);  // EOF / unexpected data / hard error → not reusable
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
            if (conns[i].fd >= 0) close_idle_fd(conns[i].fd);
            conns[i] = UpstreamConn{};
        }
        free_top = kMaxConns;
        idle_count.store(0, std::memory_order_release);
        reset_idle_list();
        for (u32 i = 0; i < kMaxConns; i++) free_stack[i] = i;
    }

    // Close every parked socket and reset to the initial all-free state.
    void shutdown() {
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0) close_idle_fd(conns[i].fd);
            conns[i] = UpstreamConn{};
        }
        free_top = kMaxConns;
        idle_count.store(0, std::memory_order_release);
        reset_idle_list();
        for (u32 i = 0; i < kMaxConns; i++) free_stack[i] = i;
    }

    // Create a non-blocking upstream socket. Returns fd on success, -1 on failure.
    inline static std::atomic<bool> study_tcp_nodelay{false};
    static i32 create_socket() {
        const i32 kFd = platform::stream_socket();
        if (kFd >= 0 && study_tcp_nodelay.load(std::memory_order_relaxed)) {
            const int kOne = 1;
            const int kSavedErrno = errno;
            (void)::setsockopt(kFd, IPPROTO_TCP, TCP_NODELAY, &kOne, sizeof(kOne));
            errno = kSavedErrno;
        }
        return kFd;
    }

private:
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
        conns[i] = UpstreamConn{};
        if (free_top < kMaxConns) free_stack[free_top++] = i;
        u32 count = idle_count.load(std::memory_order_relaxed);
        while (count > 0 &&
               !idle_count.compare_exchange_weak(
                   count, count - 1, std::memory_order_release, std::memory_order_relaxed)) {
        }
    }
};

}  // namespace rut
