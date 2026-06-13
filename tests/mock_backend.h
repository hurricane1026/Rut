#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"
#include "rut/runtime/io_event.h"

namespace rut {

struct ConnectionBase;              // forward declaration for wait() signature
using Connection = ConnectionBase;  // alias (matches connection.h)

// Mock I/O backend for unit testing.
// Records all submitted operations, lets tests inject completions.
// No real sockets, no syscalls, fully deterministic.

struct MockOp {
    enum Type : u8 { Accept, Recv, Send, Connect, Cancel, PauseRecv };
    Type type;
    i32 fd;
    u32 conn_id;
    const u8* send_buf;
    u32 send_len;
};

struct MockBackend {
    // Mock backend: synchronous like epoll (no deferred reclamation).
    static constexpr bool kAsyncIo = false;

    // Recorded operations (submitted by event loop / callbacks)
    static constexpr u32 kMaxOps = 256;
    MockOp ops[kMaxOps];
    u32 op_count = 0;
    i32 timer_fd = -1;
    bool fail_connect = false;
    bool fail_upstream_recv = false;
    bool fail_upstream_send = false;

    // Injected completions (fed back to event loop)
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

    void cancel_accept() {}

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

    bool add_send_upstream(i32 fd, u32 conn_id, const u8* buf, u32 len) {
        if (fail_upstream_send) return false;
        return add_send(fd, conn_id, buf, len);
    }

    bool add_send(i32 fd, u32 conn_id, const u8* buf, u32 len) {
        if (op_count < kMaxOps) {
            ops[op_count++] = {MockOp::Send, fd, conn_id, buf, len};
        }
        return true;
    }

    bool add_connect(i32 fd, u32 conn_id, const void* /*addr*/, u32 /*len*/) {
        if (fail_connect) return false;
        if (op_count < kMaxOps) {
            ops[op_count++] = {MockOp::Connect, fd, conn_id, nullptr, 0};
        }
        return true;
    }

    void pause_recv(u32 conn_id, bool /*preserve_send_interest*/ = false) {
        if (op_count < kMaxOps) {
            ops[op_count++] = {MockOp::PauseRecv, -1, conn_id, nullptr, 0};
        }
    }

    u32 cancel(i32 fd,
               u32 conn_id,
               bool /*recv_armed*/ = false,
               bool /*send_armed*/ = false,
               bool /*upstream_recv_armed*/ = false,
               bool /*upstream_send_armed*/ = false,
               bool /*has_upstream*/ = false) {
        if (op_count < kMaxOps) {
            ops[op_count++] = {MockOp::Cancel, fd, conn_id, nullptr, 0};
        }
        return 0;  // sync backend: no cancel CQEs to track
    }

    void shutdown() {}

    // --- Test helpers ---

    // Inject a completion event. Will be returned by next wait().
    void inject(IoEvent ev) {
        if (pending_count < kMaxEvents) {
            pending[pending_count++] = ev;
        }
    }

    // Return injected events, then clear.
    // conns/max_conns match backend concept but unused in mock (no real recv).
    u32 wait(IoEvent* events, u32 max, Connection* /*conns*/ = nullptr, u32 /*max_conns*/ = 0) {
        u32 n = pending_count < max ? pending_count : max;
        for (u32 i = 0; i < n; i++) events[i] = pending[i];
        // Shift remaining
        for (u32 i = n; i < pending_count; i++) pending[i - n] = pending[i];
        pending_count -= n;
        return n;
    }

    // Find last op of given type.
    const MockOp* last_op(MockOp::Type type) const {
        for (i32 i = static_cast<i32>(op_count) - 1; i >= 0; i--) {
            if (ops[i].type == type) return &ops[i];
        }
        return nullptr;
    }

    // Count ops of given type.
    u32 count_ops(MockOp::Type type) const {
        u32 n = 0;
        for (u32 i = 0; i < op_count; i++) {
            if (ops[i].type == type) n++;
        }
        return n;
    }

    void clear_ops() { op_count = 0; }
};

}  // namespace rut
