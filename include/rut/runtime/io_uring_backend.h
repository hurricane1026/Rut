#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"
#include "rut/runtime/io_backend.h"
#include <atomic>

#include <errno.h>
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rut {

struct ConnectionBase;              // forward declaration for wait() signature
using Connection = ConnectionBase;  // alias (matches connection.h)

// Direct io_uring backend — no liburing dependency.
// Uses raw syscalls for full control (~300 lines per DESIGN.md).
//
// io_uring features (Linux 6.0+). Currently enabled marked with [*]:
//   [*] IORING_ACCEPT_MULTISHOT   — one SQE continuously accepts
//   [*] IORING_RECV_MULTISHOT     — one SQE continuously receives per connection
//   [*] IOSQE_BUFFER_SELECT       — kernel picks buffer from provided ring
//   [ ] IORING_SETUP_SQPOLL       — kernel-side SQ polling (needs CAP_SYS_NICE)
//   [ ] IORING_OP_SEND_ZC         — zero-copy send (future optimization)
//   [*] IORING_SETUP_COOP_TASKRUN — cooperative task running
// Ring setup runs before the shard thread starts, so SINGLE_ISSUER is intentionally
// not used: submissions and enters may come from the spawned shard thread.
//
struct IoUringBackend {
    // io_uring is async: the kernel may still access user buffers between
    // SQE submission and CQE completion. EventLoop uses this trait to
    // enable CQE-driven deferred slice reclamation (pending_ops tracking).
    static constexpr bool kAsyncIo = true;

    // Ring file descriptor
    i32 ring_fd = -1;

    // SQ ring mapped memory
    u32* sq_head = nullptr;
    u32* sq_tail = nullptr;
    u32* sq_ring_mask = nullptr;
    u32* sq_array = nullptr;
    io_uring_sqe* sq_entries = nullptr;
    u32 sq_ring_entries = 0;

    // CQ ring mapped memory
    u32* cq_head = nullptr;
    u32* cq_tail = nullptr;
    u32* cq_ring_mask = nullptr;
    io_uring_cqe* cq_entries = nullptr;
    u32 cq_ring_entries = 0;

    // Mapped regions (for cleanup)
    void* sq_ring_ptr = nullptr;
    u64 sq_ring_sz = 0;
    void* cq_ring_ptr = nullptr;
    u64 cq_ring_sz = 0;
    void* sqes_ptr = nullptr;
    u64 sqes_sz = 0;

    // Provided buffer ring
    io_uring_buf_ring* buf_ring = nullptr;
    u8* buf_base = nullptr;  // kProvidedBufCount * kProvidedBufSize bytes

    // Listen socket
    i32 listen_fd = -1;

    // Timer fd for 1-second ticks (drives timer wheel, same as epoll backend)
    i32 timer_fd = -1;
    u64 timer_ticks_buf = 0;        // read target for IORING_OP_READ on timer_fd
    bool timer_read_armed = false;  // true if a timer read SQE is in-flight

    // Outstanding partial-send state per connection.
    // When IORING_OP_SEND completes partially, wait() re-submits the remainder.
    // Only emits Send completion when all bytes are sent (or error).
    static constexpr u32 kMaxSendState = 16384;
    struct SendState {
        const u8* src;
        i32 fd;
        u32 offset;
        u32 remaining;
        IoEventType type;
        u32 upstream_episode;
        u32 generation = 0;
    };
    SendState send_state[kMaxSendState];
    SendState upstream_send_state[kMaxSendState];

    // Pending SQE count (for submission)
    u32 pending = 0;

    // Sticky fatal error from io_uring_enter. A zero-event wait is otherwise a
    // legitimate result, so the event loop/control plane must inspect this
    // separately. The worker writes it; the control thread polls it.
    std::atomic<i32> fatal_error{0};

    // --- Interface methods ---

    // Initialize the io_uring instance for this shard.
    core::Expected<void, Error> init(u32 shard_id, i32 listen_fd);

    // Submit a multishot accept on the listen socket.
    void add_accept();

    // Submit a multishot recv with provided buffer selection.
    // No user buffer needed — kernel picks from provided ring.
    // Returns false if SQ is full (no SQE submitted).
    bool add_recv(i32 fd, u32 conn_id);

    // Same as add_recv but encodes UpstreamRecv in user_data so dispatch
    // can distinguish upstream vs client recv CQEs.
    bool add_recv_upstream(i32 fd, u32 conn_id, u32 upstream_episode = 1);
    // Dedicated single submission point for the bounded explicit
    // first-response deadline.  It intentionally does not inherit the ordinary
    // recv path's idempotent/deferred-rearm semantics.
    bool add_first_response_recv(i32 fd, u32 conn_id, u32 upstream_episode);

    // Pause downstream recv while a send wait is pending.
    // Uses a silent cancel CQE so the event loop does not have to special-case it.
    bool pause_recv(i32 fd, u32 conn_id);
    // Cancel the multishot upstream recv by user_data (recv-only). The cancel's own
    // completion is tagged kPauseCancelAux so dispatch re-arms only once it drains.
    bool pause_upstream_recv(i32 fd, u32 conn_id, u32 upstream_episode = 1);
    // Exact-token cancel used by bounded upstream-episode retirement. The
    // cancel's own CQE retains the selected operation type and is tagged
    // separately from pause/rearm cancellation. Returns true only after the
    // cancel SQE has actually been queued.
    bool cancel_retiring_upstream(u32 conn_id, IoEventType type, u32 upstream_episode);
    bool cancel_retiring_upstream_recv(u32 conn_id, u32 upstream_episode) {
        return cancel_retiring_upstream(conn_id, IoEventType::UpstreamRecv, upstream_episode);
    }

    // Submit a send (or zero-copy send).
    // Returns false if SQ is full (no SQE submitted).
    bool add_send(i32 fd, u32 conn_id, const u8* buf, u32 len, u32 generation = 0);

    // Same as add_send but encodes UpstreamSend in user_data.
    bool add_send_upstream(i32 fd, u32 conn_id, const u8* buf, u32 len, u32 upstream_episode = 1);

    // Submit a connect to upstream.
    // Returns false if SQ is full (no SQE submitted).
    bool add_connect(i32 fd, u32 conn_id, const void* addr, u32 addr_len, u32 upstream_episode = 1);

    // Submit IORING_OP_TIMEOUT for a JIT handler yield. ms granularity —
    // the timespec storage lives on the Connection because the kernel
    // reads it asynchronously. CQE completes with res == -ETIME under
    // normal expiry; the wait() path emits IoEvent{HandlerTimer, conn_id}
    // with IoEvent::result set to the connection's yield_timer_gen so
    // the dispatcher can reject stale timeout CQEs.
    bool add_yield_timeout(u32 conn_id, Connection& conn, u32 ms);

    // Cancel outstanding operations for a connection (by user_data match).
    // Only submits cancel SQEs for op types actually in flight.
    // Returns the number of cancel SQEs submitted (for pending_ops tracking).
    u32 cancel(i32 fd,
               u32 conn_id,
               bool recv_armed,
               bool send_armed,
               bool upstream_connect_armed,
               bool upstream_recv_armed,
               bool upstream_send_armed,
               bool has_upstream,
               u32 upstream_episode = 1,
               bool yield_armed = false,
               u32 yield_timer_gen = 0,
               u8* upstream_cancel_mask = nullptr,
               bool* send_cancel_owned = nullptr);

    bool cancel_yield_timeout(u32 conn_id, u32 yield_timer_gen);

    // Cancel the multishot accept request. Must be called before closing
    // listen_fd during drain to stop io_uring from accepting new connections.
    void cancel_accept();

    // Wait for completions. Returns number of events filled.
    // Calls io_uring_enter to submit pending SQEs and wait for CQEs.
    // conns: connection table — recv completions using provided buffers are
    // copied into conns[conn_id].recv_buf. max_conns: table size for bounds checking.
    u32 wait(IoEvent* events, u32 max_events, Connection* conns, u32 max_conns);

    i32 failure_code() const { return fatal_error.load(std::memory_order_acquire); }

    // Shutdown and unmap all resources.
    void shutdown();

    // Return a provided buffer back to the ring after processing.
    void return_buffer(u16 buf_id);

#ifdef RUT_TESTING
public:
#else
private:
#endif
    // Encode/decode SQE user_data. Production callers should continue using the
    // typed submit/cancel helpers.
    static u64 encode_user_data(u32 conn_id, IoEventType type);
    static u64 encode_user_data(u32 conn_id, IoEventType type, u32 aux);
    static u64 encode_upstream_user_data(u32 conn_id,
                                         IoEventType type,
                                         u32 upstream_episode,
                                         u8 aux = 0);
    static void decode_user_data(u64 data, u32& conn_id, IoEventType& type);
    static void decode_user_data(u64 data, u32& conn_id, IoEventType& type, u32& aux);
    static void decode_user_data(
        u64 data, u32& conn_id, IoEventType& type, u32& aux, u32& upstream_episode);

private:
    // Submit a cancel SQE matching a specific user_data value.
    // conn_id/type/aux are encoded in the cancel CQE's user_data. Pass the real
    // conn_id for tracked close-path cancels, or kCancelConnId for fire-and-
    // forget cancels that should be consumed silently.
    bool cancel_by_user_data(
        u64 target, u32 conn_id, IoEventType type, u32 aux = 0, u32 upstream_episode = 0);

    // Get next available SQE. Returns nullptr if SQ is full.
    io_uring_sqe* get_sqe();

    // Setup provided buffer ring via io_uring_register.
    core::Expected<void, Error> setup_buf_ring();

    // Submit IORING_OP_READ on timer_fd to receive next tick.
    void submit_timer_read();

    void record_enter_error(i32 result) {
        if (result < 0 && result != -EINTR) fatal_error.store(-result, std::memory_order_release);
    }
};

}  // namespace rut
