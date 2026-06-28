#pragma once

#include "rut/common/types.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rut {

// Per-shard idle upstream connection pool (HTTP/1 keep-alive reuse).
//
// Holds connected, currently-unused upstream sockets so a later proxy request to
// the same endpoint can skip the TCP connect. Each shard owns one UpstreamPool —
// no cross-shard sharing, so no atomics. An idle entry is keyed by the endpoint it
// connects to: (upstream_id, backend_idx) — multi-backend upstreams keep a
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
};

struct UpstreamPool {
    static constexpr u32 kMaxConns = 4096;

    UpstreamConn conns[kMaxConns];
    u32 free_stack[kMaxConns];
    u32 free_top = 0;
    u32 idle_count = 0;  // live idle entries — lets take_idle() skip the scan when cold

    void init() {
        free_top = kMaxConns;
        idle_count = 0;
        for (u32 i = 0; i < kMaxConns; i++) {
            conns[i] = UpstreamConn{};
            free_stack[i] = i;
        }
    }

    // Park a connected, idle upstream fd for reuse by a later request to the same
    // (upstream_id, backend_idx) endpoint. Returns false if the pool is full (the
    // caller must close the fd itself). The fd must have no I/O armed on it.
    bool put_idle(i32 fd, u16 upstream_id, u8 backend_idx) {
        if (fd < 0 || free_top == 0) return false;
        const u32 idx = free_stack[--free_top];
        conns[idx] = {fd, upstream_id, backend_idx, /*idle=*/true, /*allocated=*/true};
        idle_count++;
        return true;
    }

    // Borrow a reusable idle fd for the given endpoint, or -1 if none is live.
    // Each candidate is liveness-probed with a non-blocking MSG_PEEK: a socket the
    // backend already closed (EOF) or errored is closed and skipped, and one with
    // unexpected pending bytes (a desynced/half-pipelined socket) is discarded too
    // — only an EAGAIN (nothing buffered, still open) socket is handed back. This
    // catches the common idle-timeout race before any request bytes are sent; the
    // residual probe-vs-send race is handled by the caller's idempotent resend.
    i32 take_idle(u16 upstream_id, u8 backend_idx) {
        if (idle_count == 0) return -1;
        for (u32 i = 0; i < kMaxConns; i++) {
            UpstreamConn& c = conns[i];
            if (!c.idle || !c.allocated || c.fd < 0) continue;
            if (c.upstream_id != upstream_id || c.backend_idx != backend_idx) continue;
            const i32 fd = c.fd;
            release_slot(i);
            char probe;
            const ssize_t n = ::recv(fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return fd;  // healthy
            ::close(fd);  // EOF / unexpected data / hard error → not reusable
        }
        return -1;
    }

    // Close every parked socket and return to the empty (but usable) state. Called
    // on config reload: a hot reload can repoint an upstream endpoint while keeping
    // the same (upstream_id, backend_idx), so idle sockets parked under the old
    // config must not be handed out for the new endpoint. No-op when already empty.
    void drain() {
        if (idle_count == 0) return;
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0) ::close(conns[i].fd);
            conns[i] = UpstreamConn{};
        }
        free_top = kMaxConns;
        idle_count = 0;
        for (u32 i = 0; i < kMaxConns; i++) free_stack[i] = i;
    }

    // Close every parked socket and reset to the initial all-free state.
    void shutdown() {
        for (u32 i = 0; i < kMaxConns; i++) {
            if (conns[i].fd >= 0) ::close(conns[i].fd);
            conns[i] = UpstreamConn{};
        }
        free_top = kMaxConns;
        idle_count = 0;
        for (u32 i = 0; i < kMaxConns; i++) free_stack[i] = i;
    }

    // Create a non-blocking upstream socket. Returns fd on success, -1 on failure.
    static i32 create_socket() {
        return socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    }

private:
    void release_slot(u32 i) {
        conns[i] = UpstreamConn{};
        if (free_top < kMaxConns) free_stack[free_top++] = i;
        if (idle_count > 0) idle_count--;
    }
};

}  // namespace rut
