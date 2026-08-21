#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/error.h"
#include "rut/runtime/io_backend.h"

#include <sys/epoll.h>
#include <sys/timerfd.h>

namespace rut {

// epoll backend — reactor internally, proactor API externally.
// "Reactor disguised as proactor": wait() does the recv/send
// and emits IoEvent completions, identical to io_uring's output.
//
// Fallback for Linux < 6.0 (epoll available since 3.9+ with SO_REUSEPORT).
//
// Key differences from io_uring:
//   - No provided buffer ring: allocate slice on EPOLLIN readiness
//   - No multishot: accept loop inside wait()
//   - Two syscalls per I/O (epoll_wait + recv/send) vs one batched
//   - No zero-copy send
//
struct EpollBackend {
    // epoll uses synchronous read/write: the kernel is done with user
    // buffers when the syscall returns. No deferred reclamation needed.
    static constexpr bool kAsyncIo = false;

    i32 epoll_fd = -1;
    i32 timer_fd = -1;
    // One-shot timerfd for JIT handler yield precision. EpollEventLoop
    // maintains a min-heap of pending yield deadlines and re-arms this
    // fd via arm_yield_timerfd() whenever the heap's top entry changes.
    i32 yield_timer_fd = -1;
    i32 listen_fd = -1;

    // conn_id → fd mappings. Separate maps for client and upstream so that
    // proxy connections with both fds registered don't overwrite each other.
    static constexpr u32 kMaxFdMap = 16384;
    i32 downstream_fd_map[kMaxFdMap];  // downstream (client) fd per conn_id
    i32 upstream_fd_map[kMaxFdMap];    // upstream (origin) fd per conn_id

    // Pending synthetic completion events (from immediate sends). FIXED LIFO
    // stack. Scoped producers preflight this capacity before their synchronous
    // syscall; they are single-threaded and non-reentrant, so one entry check
    // reserves the only completion slot that operation can need.
    static constexpr u32 kPendingCap = 64;
    IoEvent pending_completions[kPendingCap];
    u32 pending_count = 0;

    // Outstanding partial-send state per connection.
    // When add_send() can't complete immediately (partial write or EAGAIN),
    // it records the source pointer, fd, and remaining bytes here.
    // wait() resumes the send on EPOLLOUT using this state directly,
    // not conns[conn_id].send_buf — because the source may be recv_buf (proxy).
    // remaining == 0 means no outstanding send for this conn_id.
    struct SendState {
        const u8* src;  // original buffer pointer passed to add_send
        i32 fd;         // fd to send on (may differ from fd_map for upstream)
        u32 offset;
        u32 remaining;
        IoEventType type;
        bool tls;
        u32 tls_wait_events;
    };
    SendState send_state[kMaxFdMap];
    SendState upstream_send_state[kMaxFdMap];

    // --- Interface methods ---

    // Initialize epoll and timerfd for this shard.
    core::Expected<void, Error> init(u32 shard_id, i32 listen_fd);

    // Register listen socket for accept events.
    void add_accept();

    // Register fd for EPOLLIN — actual recv happens inside wait().
    bool add_recv(i32 fd, u32 conn_id);
    bool add_recv_upstream(i32 fd, u32 conn_id);

    // Suspend EPOLLIN on the downstream fd for conn_id. Used when a JIT
    // handler yields so client bytes arriving mid-wait don't spin the
    // event loop (epoll is level-triggered, so a full recv_buf + unread
    // kernel data would keep firing). The next submit_recv re-arms
    // EPOLLIN via add_recv's set_fd_interest path. No-op if the conn_id
    // has no registered downstream fd.
    void pause_recv(u32 conn_id, bool preserve_send_interest = false);

    // Suspend EPOLLIN on the upstream fd for conn_id. Used by @throttle to park
    // the proxy body pump between byte-rate windows: epoll is level-triggered, so
    // pending upstream data would otherwise keep firing UpstreamRecv and drive the
    // pipeline past the pause. submit_recv_upstream re-arms EPOLLIN on resume.
    // No-op if the conn_id has no registered upstream fd.
    void pause_upstream_recv(u32 conn_id, bool preserve_send_interest = false);

    // Stop polling a tunnel fd's READ side (drop EPOLLIN/EPOLLRDHUP so a
    // level-triggered half-close can't re-fire) while PRESERVING any in-flight
    // send on that fd (keep its EPOLLOUT so it still drains). If no send is
    // pending the fd is removed from the epoll set entirely. Used by the
    // nginx-style drain-then-close path. upstream selects the upstream fd /
    // upstream_send_state; otherwise the downstream fd / send_state.
    void quiesce_recv(u32 conn_id, bool upstream);

    // Drop any partial-send bookkeeping for conn_id. MUST be called on close so
    // a leftover send_state entry (a partial send that was still in flight when
    // the connection closed) cannot be misread as live after the conn_id and fd
    // number are reused: pause_recv/add_recv preserve a pending send's EPOLLOUT
    // keyed on (remaining > 0 && ss.fd == fd), and would otherwise arm EPOLLOUT
    // and send from the stale ss.src pointer into the new connection's fd.
    void clear_send_state(u32 conn_id);

    // Try immediate send. If partial/EAGAIN, register EPOLLOUT.
    bool add_send(i32 fd, u32 conn_id, const u8* buf, u32 len);
    bool add_send_upstream(i32 fd, u32 conn_id, const u8* buf, u32 len);
    bool add_send_tls(Connection& c, const u8* buf, u32 len);

    // Register fd for connect completion (EPOLLOUT).
    bool add_connect(i32 fd, u32 conn_id, const void* addr, u32 addr_len);

    // Remove fd from epoll.
    u32 cancel(i32 fd,
               u32 conn_id,
               bool recv_armed = false,
               bool send_armed = false,
               bool upstream_recv_armed = false,
               bool upstream_send_armed = false,
               bool has_upstream = false);

    // Remove listen socket from epoll. For epoll this is sufficient to stop
    // accepting — no multishot to cancel (unlike io_uring).
    void cancel_accept();

    // Wait for events, perform I/O, return completion events.
    // conns + max_conns: connection table for recv into Connection::recv_buf.
    u32 wait(IoEvent* events, u32 max_events, Connection* conns, u32 max_conns);

    // Shutdown and close fds.
    void shutdown();

    // Arm yield_timer_fd for a one-shot deadline `deadline_ns` in the
    // CLOCK_MONOTONIC epoch. Call with 0 to disarm. Used by
    // EpollEventLoop when its yield-timer heap changes its top deadline.
    void arm_yield_timerfd(u64 deadline_ns);

private:
    // Encode conn_id + type into epoll_event.data.u64
    static u64 encode_data(u32 conn_id, IoEventType type);
    static void decode_data(u64 data, u32& conn_id, IoEventType& type);
};

}  // namespace rut
