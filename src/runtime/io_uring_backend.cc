#include "rut/runtime/io_uring_backend.h"

#include "core/expected.h"
#include "rut/runtime/callbacks.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/error.h"
#include "rut/runtime/response_read_deadline.h"

#include <errno.h>
#include <linux/io_uring.h>
#include <string.h>  // memset
#include <sys/mman.h>
#include <sys/socket.h>  // SOCK_NONBLOCK, SOCK_CLOEXEC
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

// IORING_OP_CANCEL may not be defined on older kernel headers
#ifndef IORING_OP_ASYNC_CANCEL
#define IORING_OP_ASYNC_CANCEL 14
#endif

#ifndef IORING_ASYNC_CANCEL_ALL
#define IORING_ASYNC_CANCEL_ALL (1U << 0)
#endif

namespace rut {

static bool response_deadline_copy_owner(const Connection& conn, u32 upstream_episode, u32 aux) {
    const bool post_commit =
        conn.response_read_deadline_post_commit_phase != ResponseReadDeadlinePostCommitPhase::None;
    return aux == 0 && conn.fd >= 0 && conn.upstream_fd >= 0 &&
           (conn.state == ConnState::Proxying ||
            (post_commit && conn.state == ConnState::Sending)) &&
           conn.protocol == ConnProtocol::Http11 && !conn.tls_active && conn.h2 == nullptr &&
           (conn.response_read_deadline_state == ResponseReadDeadlineState::Armed ||
            (post_commit &&
             conn.response_read_deadline_state == ResponseReadDeadlineState::BodyComplete)) &&
           conn.response_read_deadline_owner_generation != 0 &&
           conn.response_read_deadline_owner_generation == conn.response_read_deadline_generation &&
           response_read_deadline_owner_is_stable(conn,
                                                  &on_upstream_response<IoUringEventLoop>,
                                                  ResponseReadDeadlineOwnerPhase::ArmedForCopy) &&
           conn.response_read_deadline_upstream_episode == upstream_episode &&
           conn.upstream_episode == upstream_episode && valid_upstream_episode(upstream_episode) &&
           conn.upstream_recv_armed &&
           (conn.on_upstream_recv == &on_upstream_response<IoUringEventLoop> ||
            (post_commit && conn.on_upstream_recv == nullptr)) &&
           !conn.upstream_recv_paused_for_send && !conn.upstream_recv_pause_cancel_pending &&
           !conn.upstream_recv_pause_rearm_pending && !conn.upstream_recv_cancel_inflight &&
           !conn.upstream_retirement_active && conn.upstream_retirement_target_owned == 0 &&
           conn.upstream_retirement_cancel_owned == 0 &&
           conn.upstream_retirement_cancel_retry == 0 && conn.upstream_close_episode == 0 &&
           conn.upstream_close_target_owned == 0 && conn.upstream_close_cancel_owned == 0 &&
           !conn.upstream_close_pause_cancel_owned && conn.idle_return_fd < 0 &&
           conn.idle_return_config == nullptr && !conn.close_after_idle_return &&
           !conn.h2_proxy_recv_draining && !conn.h2_proxy_synth_quarantined;
}

// Sentinel conn_id for timer events (same value as epoll backend)
static constexpr u32 kTimerConnId = 0xFFFFFE;
// Sentinel conn_id for cancel completions (must not collide with real conn_ids or timer)
static constexpr u32 kCancelConnId = 0xFFFFFD;
// kPauseCancelAux (the pause-cancel completion tag) is defined in io_event.h so the
// event loop can recognize it on IoEvent::aux.

// --- Syscall wrappers (no liburing) ---

static i32 io_uring_setup(u32 entries, struct io_uring_params* p) {
    i32 ret = static_cast<i32>(syscall(__NR_io_uring_setup, entries, p));
    return ret >= 0 ? ret : -errno;
}

static i32 io_uring_enter(i32 fd, u32 to_submit, u32 min_complete, u32 flags) {
    i32 ret = static_cast<i32>(
        syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, nullptr, 0));
    return ret >= 0 ? ret : -errno;
}

static i32 io_uring_register(i32 fd, u32 opcode, const void* arg, u32 nr_args) {
    i32 ret = static_cast<i32>(syscall(__NR_io_uring_register, fd, opcode, arg, nr_args));
    return ret >= 0 ? ret : -errno;
}

// --- user_data encoding ---
// Layout: [63:32] = auxiliary generation, [31:8] = 24-bit conn_id/sentinel,
// [7:0] = IoEventType. conn_id is still decoded as u32; 24 bits covers every
// live connection id and the io_uring sentinel ids while preserving the full
// u32 HandlerTimer generation used to reject stale timeout CQEs.

u64 IoUringBackend::encode_user_data(u32 conn_id, IoEventType type) {
    return encode_user_data(conn_id, type, 0);
}

u64 IoUringBackend::encode_user_data(u32 conn_id, IoEventType type, u32 aux) {
    return (static_cast<u64>(aux) << 32) | ((static_cast<u64>(conn_id) & 0xFFFFFFu) << 8) |
           static_cast<u64>(type);
}

u64 IoUringBackend::encode_upstream_user_data(u32 conn_id,
                                              IoEventType type,
                                              u32 upstream_episode,
                                              u8 aux) {
    return encode_upstream_event_token({conn_id, type, upstream_episode, aux});
}

void IoUringBackend::decode_user_data(u64 data, u32& conn_id, IoEventType& type) {
    u32 aux = 0;
    decode_user_data(data, conn_id, type, aux);
}

void IoUringBackend::decode_user_data(u64 data, u32& conn_id, IoEventType& type, u32& aux) {
    type = static_cast<IoEventType>(data & 0xFF);
    conn_id = static_cast<u32>((data >> 8) & 0xFFFFFFu);
    aux = static_cast<u32>(data >> 32);
}

void IoUringBackend::decode_user_data(
    u64 data, u32& conn_id, IoEventType& type, u32& aux, u32& upstream_episode) {
    type = static_cast<IoEventType>(data & 0xFFu);
    if (io_event_is_upstream(type)) {
        conn_id = static_cast<u32>((data >> 8) & kIoUserDataMaxConnId);
        aux = static_cast<u8>(data >> 56);
        upstream_episode = static_cast<u32>((data >> 32) & kIoUserDataMaxUpstreamEpisode);
        UpstreamEventToken token;
        if (decode_upstream_event_token(data, &token)) {
            return;
        }
        // Preserve the upstream type/connection identity, but make malformed
        // tokens unambiguously stale. In particular, do not let episode zero
        // fall through to the legacy decoder and invoke a current callback.
        upstream_episode = kInvalidUpstreamEventEpisode;
        return;
    }
    decode_user_data(data, conn_id, type, aux);
    upstream_episode = 0;
}

// --- SQE helpers ---

io_uring_sqe* IoUringBackend::get_sqe() {
    u32 tail = __atomic_load_n(sq_tail, __ATOMIC_RELAXED);
    u32 head = __atomic_load_n(sq_head, __ATOMIC_ACQUIRE);
    u32 mask = *sq_ring_mask;

    if (tail - head >= sq_ring_entries) {
        return nullptr;  // SQ is full
    }

    io_uring_sqe* sqe = &sq_entries[tail & mask];
    sq_array[tail & mask] = tail & mask;
    return sqe;
}

static void sqe_advance_tail(u32* sq_tail) {
    u32 tail = __atomic_load_n(sq_tail, __ATOMIC_RELAXED);
    __atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);
}

// --- Init ---

core::Expected<void, Error> IoUringBackend::init(u32 /*shard_id*/, i32 lfd) {
    listen_fd = lfd;
    // Explicitly init fds to -1: mmap-zeroed memory skips default member initializers,
    // so timer_fd/ring_fd could be 0. If init fails early and calls shutdown(), closing
    // fd 0 (stdin) would be catastrophic.
    ring_fd = -1;
    timer_fd = -1;
    timer_read_armed = false;
    fatal_error.store(0, std::memory_order_relaxed);
    for (u32 i = 0; i < kMaxSendState; i++) {
        send_state[i] = {nullptr, -1, 0, 0, IoEventType::Send, 0, 0};
        upstream_send_state[i] = {nullptr, -1, 0, 0, IoEventType::UpstreamSend, 0, 0};
    }

    // Setup io_uring with desired flags
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_COOP_TASKRUN;
    // Note: SQPOLL requires CAP_SYS_NICE or io_uring_register credentials.
    // Omit for now, add as optimization later.

    constexpr u32 kRingEntries = 16384;
    ring_fd = io_uring_setup(kRingEntries, &params);
    if (ring_fd < 0) return core::make_unexpected(Error::make(-ring_fd, Error::Source::IoUring));

    sq_ring_entries = params.sq_entries;
    cq_ring_entries = params.cq_entries;

    // Map SQ ring
    sq_ring_sz = params.sq_off.array + params.sq_entries * sizeof(u32);
    sq_ring_ptr = mmap(nullptr,
                       sq_ring_sz,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE,
                       ring_fd,
                       IORING_OFF_SQ_RING);
    if (sq_ring_ptr == MAP_FAILED) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Mmap));
    }

    auto* sq_base = static_cast<u8*>(sq_ring_ptr);
    sq_head = reinterpret_cast<u32*>(sq_base + params.sq_off.head);
    sq_tail = reinterpret_cast<u32*>(sq_base + params.sq_off.tail);
    sq_ring_mask = reinterpret_cast<u32*>(sq_base + params.sq_off.ring_mask);
    sq_array = reinterpret_cast<u32*>(sq_base + params.sq_off.array);

    // Map SQEs
    sqes_sz = params.sq_entries * sizeof(io_uring_sqe);
    sqes_ptr = mmap(nullptr,
                    sqes_sz,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE,
                    ring_fd,
                    IORING_OFF_SQES);
    if (sqes_ptr == MAP_FAILED) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Mmap));
    }
    sq_entries = static_cast<io_uring_sqe*>(sqes_ptr);

    // Map CQ ring
    cq_ring_sz = params.cq_off.cqes + params.cq_entries * sizeof(io_uring_cqe);
    cq_ring_ptr = mmap(nullptr,
                       cq_ring_sz,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE,
                       ring_fd,
                       IORING_OFF_CQ_RING);
    if (cq_ring_ptr == MAP_FAILED) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Mmap));
    }

    auto* cq_base = static_cast<u8*>(cq_ring_ptr);
    cq_head = reinterpret_cast<u32*>(cq_base + params.cq_off.head);
    cq_tail = reinterpret_cast<u32*>(cq_base + params.cq_off.tail);
    cq_ring_mask = reinterpret_cast<u32*>(cq_base + params.cq_off.ring_mask);
    cq_entries = reinterpret_cast<io_uring_cqe*>(cq_base + params.cq_off.cqes);

    // Setup provided buffer ring for zero-copy recv
    TRY_VOID(setup_buf_ring());

    // Create timerfd for 1-second ticks (drives timer wheel)
    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Timerfd));
    }
    struct itimerspec ts;
    memset(&ts, 0, sizeof(ts));
    ts.it_interval.tv_sec = 1;
    ts.it_value.tv_sec = 1;
    if (timerfd_settime(timer_fd, 0, &ts, nullptr) < 0) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Timerfd));
    }

    // Submit initial read on timerfd
    submit_timer_read();

    return {};
}

// --- Provided buffer ring ---

core::Expected<void, Error> IoUringBackend::setup_buf_ring() {
    // Allocate buffer memory: kProvidedBufCount * kProvidedBufSize
    u64 total_buf_sz = static_cast<u64>(kProvidedBufCount) * kProvidedBufSize;
    buf_base = static_cast<u8*>(mmap(nullptr,
                                     total_buf_sz,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                                     -1,
                                     0));
    if (buf_base == MAP_FAILED) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Mmap));
    }

    // Allocate the buf_ring structure itself
    u64 ring_sz = sizeof(io_uring_buf_ring) + kProvidedBufCount * sizeof(io_uring_buf);
    void* ring_mem = mmap(nullptr,
                          ring_sz,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                          -1,
                          0);
    if (ring_mem == MAP_FAILED) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Mmap));
    }
    buf_ring = static_cast<io_uring_buf_ring*>(ring_mem);

    // Register the buffer ring with io_uring
    struct io_uring_buf_reg reg;
    memset(&reg, 0, sizeof(reg));
    reg.ring_addr = reinterpret_cast<u64>(buf_ring);
    reg.ring_entries = kProvidedBufCount;
    reg.bgid = kBufGroupId;

    i32 rc = io_uring_register(ring_fd, IORING_REGISTER_PBUF_RING, &reg, 1);
    if (rc < 0) {
        shutdown();
        return core::make_unexpected(Error::make(-rc, Error::Source::IoUring));
    }

    // Fill the ring with buffer entries
    for (u32 i = 0; i < kProvidedBufCount; i++) {
        io_uring_buf* buf = &buf_ring->bufs[i];
        buf->addr = reinterpret_cast<u64>(buf_base + static_cast<u64>(i) * kProvidedBufSize);
        buf->len = kProvidedBufSize;
        buf->bid = static_cast<u16>(i);
    }
    // Advance the ring tail to make all buffers available
    __atomic_store_n(&buf_ring->tail, static_cast<u16>(kProvidedBufCount), __ATOMIC_RELEASE);

    return {};
}

void IoUringBackend::return_buffer(u16 buf_id) {
    // Add buffer back to the provided ring
    u16 tail = __atomic_load_n(&buf_ring->tail, __ATOMIC_RELAXED);
    u16 mask = kProvidedBufCount - 1;  // power of 2

    io_uring_buf* buf = &buf_ring->bufs[tail & mask];
    buf->addr = reinterpret_cast<u64>(buf_base + static_cast<u64>(buf_id) * kProvidedBufSize);
    buf->len = kProvidedBufSize;
    buf->bid = buf_id;

    __atomic_store_n(&buf_ring->tail, static_cast<u16>(tail + 1), __ATOMIC_RELEASE);
}

void IoUringBackend::submit_timer_read() {
    if (timer_read_armed) return;  // already in-flight
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;  // SQ full — will retry on next wait()

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_READ;
    sqe->fd = timer_fd;
    sqe->addr = reinterpret_cast<u64>(&timer_ticks_buf);
    sqe->len = sizeof(timer_ticks_buf);
    sqe->user_data = encode_user_data(kTimerConnId, IoEventType::Timeout);

    sqe_advance_tail(sq_tail);
    pending++;
    timer_read_armed = true;
}

// --- Operations ---

void IoUringBackend::add_accept() {
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_ACCEPT;
    sqe->fd = listen_fd;
    sqe->accept_flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
    sqe->ioprio = IORING_ACCEPT_MULTISHOT;  // multishot: one SQE, continuous accept
    sqe->user_data = encode_user_data(0, IoEventType::Accept);

    sqe_advance_tail(sq_tail);
    pending++;
}

bool IoUringBackend::add_recv(i32 fd, u32 conn_id) {
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_RECV;
    sqe->fd = fd;
    sqe->len = kProvidedBufSize;  // max bytes to read from provided buffer
    sqe->buf_group = kBufGroupId;
    sqe->flags = IOSQE_BUFFER_SELECT;
    sqe->ioprio = IORING_RECV_MULTISHOT;  // multishot: continuous recv
    sqe->user_data = encode_user_data(conn_id, IoEventType::Recv);

    sqe_advance_tail(sq_tail);
    pending++;
    return true;
}

bool IoUringBackend::add_recv_upstream(i32 fd, u32 conn_id, u32 upstream_episode) {
    if (conn_id >= kMaxSendState || !valid_upstream_episode(upstream_episode)) return false;
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_RECV;
    sqe->fd = fd;
    sqe->len = kProvidedBufSize;
    sqe->buf_group = kBufGroupId;
    sqe->flags = IOSQE_BUFFER_SELECT;
    sqe->ioprio = IORING_RECV_MULTISHOT;
    sqe->user_data =
        encode_upstream_user_data(conn_id, IoEventType::UpstreamRecv, upstream_episode);

    sqe_advance_tail(sq_tail);
    pending++;
    return true;
}

bool IoUringBackend::add_recv_upstream_once(i32 fd, u32 conn_id, u32 upstream_episode) {
    if (conn_id >= kMaxSendState || !valid_upstream_episode(upstream_episode)) return false;
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_RECV;
    sqe->fd = fd;
    sqe->len = kProvidedBufSize;
    sqe->buf_group = kBufGroupId;
    sqe->flags = IOSQE_BUFFER_SELECT;
    sqe->user_data =
        encode_upstream_user_data(conn_id, IoEventType::UpstreamRecv, upstream_episode);

    sqe_advance_tail(sq_tail);
    pending++;
    return true;
}

bool IoUringBackend::add_first_response_recv(i32 fd, u32 conn_id, u32 upstream_episode) {
    if (fd < 0 || conn_id >= kMaxSendState || !valid_upstream_episode(upstream_episode))
        return false;
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_RECV;
    sqe->fd = fd;
    sqe->len = kProvidedBufSize;
    sqe->buf_group = kBufGroupId;
    sqe->flags = IOSQE_BUFFER_SELECT;
    sqe->ioprio = IORING_RECV_MULTISHOT;
    sqe->user_data =
        encode_upstream_user_data(conn_id, IoEventType::UpstreamRecv, upstream_episode);

    sqe_advance_tail(sq_tail);
    pending++;
    return true;
}

bool IoUringBackend::pause_recv(i32 fd, u32 conn_id) {
    if (fd < 0 || conn_id >= kMaxSendState) return false;
    return cancel_by_user_data(
        encode_user_data(conn_id, IoEventType::Recv), kCancelConnId, IoEventType::Recv);
}

// Pause the multishot upstream recv by cancelling it by user_data (recv-only — it
// never touches a concurrent upstream send, unlike a cancel-by-fd). The cancel's OWN
// completion is tagged with the real conn_id + kPauseCancelAux, so it routes to the
// connection rather than being silently dropped: the loop counts it in pending_ops
// (pinning the slot until it drains) and re-arms the recv only once it arrives — so
// the in-flight cancel can never match a freshly-armed recv on the reused conn_id.
bool IoUringBackend::pause_upstream_recv(i32 fd, u32 conn_id, u32 upstream_episode) {
    if (fd < 0 || conn_id >= kMaxSendState || !valid_upstream_episode(upstream_episode))
        return false;
    return cancel_by_user_data(
        encode_upstream_user_data(conn_id, IoEventType::UpstreamRecv, upstream_episode),
        conn_id,
        IoEventType::UpstreamRecv,
        kPauseCancelAux,
        upstream_episode);
}

bool IoUringBackend::cancel_retiring_upstream(u32 conn_id, IoEventType type, u32 upstream_episode) {
    if (conn_id >= kMaxSendState || !io_event_is_upstream(type) ||
        !valid_upstream_episode(upstream_episode))
        return false;
    return cancel_by_user_data(encode_upstream_user_data(conn_id, type, upstream_episode),
                               conn_id,
                               type,
                               kUpstreamRetirementCancelAux,
                               upstream_episode);
}

bool IoUringBackend::add_send(i32 fd, u32 conn_id, const u8* buf, u32 len, u32 generation) {
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;  // SQ full — don't record send_state without a submitted SQE

    // Record send state only after acquiring SQE — if kernel returns partial,
    // wait() re-submits the remainder.
    if (conn_id < kMaxSendState) {
        send_state[conn_id] = {buf, fd, 0, len, IoEventType::Send, 0, generation};
    }

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_SEND;
    sqe->fd = fd;
    sqe->addr = reinterpret_cast<u64>(buf);
    sqe->len = len;
    sqe->user_data = encode_user_data(conn_id, IoEventType::Send, generation);

    sqe_advance_tail(sq_tail);
    pending++;
    return true;
}

bool IoUringBackend::flush_pending_nonblocking() {
    return flush_pending_nonblocking_impl([](i32 fd, u32 to_submit, u32 min_complete, u32 flags) {
        return io_uring_enter(fd, to_submit, min_complete, flags);
    });
}

bool IoUringBackend::add_send_upstream(
    i32 fd, u32 conn_id, const u8* buf, u32 len, u32 upstream_episode) {
    if (conn_id >= kMaxSendState || !valid_upstream_episode(upstream_episode)) return false;
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    if (conn_id < kMaxSendState) {
        upstream_send_state[conn_id] = {
            buf, fd, 0, len, IoEventType::UpstreamSend, upstream_episode, 0};
    }

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_SEND;
    sqe->fd = fd;
    sqe->addr = reinterpret_cast<u64>(buf);
    sqe->len = len;
    sqe->user_data =
        encode_upstream_user_data(conn_id, IoEventType::UpstreamSend, upstream_episode);

    sqe_advance_tail(sq_tail);
    pending++;
    return true;
}

bool IoUringBackend::add_connect(
    i32 fd, u32 conn_id, const void* addr, u32 addr_len, u32 upstream_episode) {
    if (conn_id >= kMaxSendState || !valid_upstream_episode(upstream_episode)) return false;
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return false;

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_CONNECT;
    sqe->fd = fd;
    sqe->addr = reinterpret_cast<u64>(addr);
    sqe->off = addr_len;  // connect uses off field for addrlen
    sqe->user_data =
        encode_upstream_user_data(conn_id, IoEventType::UpstreamConnect, upstream_episode);

    sqe_advance_tail(sq_tail);
    pending++;
    return true;
}

bool IoUringBackend::add_yield_timeout(u32 conn_id, Connection& conn, u32 ms) {
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) {
        // SQ full — flush pending SQEs to make room, then retry once.
        // Mirrors cancel_by_user_data's pattern. wait(ms) semantics
        // require the timer to actually be scheduled; failing here would
        // force the caller into the wheel fallback, which caps precision
        // AND (for ms > 63000) wraps the deadline mod 64 seconds.
        if (pending > 0) {
            i32 flushed = io_uring_enter(ring_fd, pending, 0, IORING_ENTER_SQ_WAKEUP);
            if (flushed > 0)
                pending -= static_cast<u32>(flushed);
            else if (flushed < 0)
                record_enter_error(flushed);
        }
        sqe = get_sqe();
        if (!sqe) return false;
    }

    // Relative timeout; kernel reads &conn.yield_timespec asynchronously
    // so the storage must live on the Connection (not on the stack).
    conn.yield_timespec.tv_sec = ms / 1000;
    conn.yield_timespec.tv_nsec = static_cast<long long>(ms % 1000) * 1'000'000LL;

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_TIMEOUT;
    sqe->fd = -1;  // unused for IORING_OP_TIMEOUT
    sqe->addr = reinterpret_cast<u64>(&conn.yield_timespec);
    sqe->len = 1;  // one timespec
    sqe->off = 0;  // count=0 → plain relative timeout (no "wait for N events" semantics)
    conn.yield_timer_gen++;
    sqe->user_data = encode_user_data(conn_id, IoEventType::HandlerTimer, conn.yield_timer_gen);

    sqe_advance_tail(sq_tail);
    pending++;
    return true;
}

void IoUringBackend::cancel_accept() {
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) return;

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_ASYNC_CANCEL;
    sqe->fd = listen_fd;
    // Cancel by user_data — matches the multishot accept SQE.
    sqe->addr = encode_user_data(0, IoEventType::Accept);
    sqe->cancel_flags = IORING_ASYNC_CANCEL_ALL;
    sqe->user_data = encode_user_data(kCancelConnId, IoEventType::Accept);

    sqe_advance_tail(sq_tail);
    pending++;

    // Submit immediately so the cancel takes effect before close_listen()
    // closes the fd. Without this, the cancel SQE sits in the SQ until
    // the next wait(), by which time the fd may already be closed/reused.
    if (pending > 0) {
        i32 ret = io_uring_enter(ring_fd, pending, 0, IORING_ENTER_SQ_WAKEUP);
        if (ret > 0)
            pending -= static_cast<u32>(ret);
        else if (ret < 0)
            record_enter_error(ret);
    }
}

// Submit a cancel SQE matching a specific user_data value.
// Returns true if the SQE was queued, false if SQ is full.
bool IoUringBackend::cancel_by_user_data(
    u64 target, u32 conn_id, IoEventType type, u32 aux, u32 upstream_episode) {
    if (io_event_is_upstream(type) &&
        (conn_id >= kMaxSendState || !valid_upstream_episode(upstream_episode)))
        return false;
    io_uring_sqe* sqe = get_sqe();
    if (!sqe) {
        // SQ ring full — flush pending SQEs to make room, then retry.
        if (pending > 0) {
            i32 flushed = io_uring_enter(ring_fd, pending, 0, IORING_ENTER_SQ_WAKEUP);
            if (flushed > 0)
                pending -= static_cast<u32>(flushed);
            else if (flushed < 0)
                record_enter_error(flushed);
        }
        sqe = get_sqe();
        if (!sqe) return false;
    }

    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_ASYNC_CANCEL;
    // Cancel by user_data match (not fd) — safe across fd reuse after close().
    sqe->addr = target;
    sqe->cancel_flags = IORING_ASYNC_CANCEL_ALL;
    // Encode the caller-provided conn_id/type/aux in the cancel CQE. Close-path
    // cancels use the real conn_id so dispatch can account pending_ops; mid-wait
    // timeout disarms use kCancelConnId so the cancel CQE is consumed silently.
    sqe->user_data =
        io_event_is_upstream(type)
            ? encode_upstream_user_data(conn_id, type, upstream_episode, static_cast<u8>(aux))
            : encode_user_data(conn_id, type, aux);

    sqe_advance_tail(sq_tail);
    pending++;
    return true;
}

bool IoUringBackend::cancel_yield_timeout(u32 conn_id, u32 yield_timer_gen) {
    return cancel_by_user_data(
        encode_user_data(conn_id, IoEventType::HandlerTimer, yield_timer_gen),
        kCancelConnId,
        IoEventType::HandlerTimer,
        yield_timer_gen);
}

u32 IoUringBackend::cancel(i32 /*fd*/,
                           u32 conn_id,
                           bool recv_armed,
                           bool send_armed,
                           bool upstream_connect_armed,
                           bool upstream_recv_armed,
                           bool upstream_send_armed,
                           bool has_upstream,
                           u32 upstream_episode,
                           bool yield_armed,
                           u32 yield_timer_gen,
                           u8* upstream_cancel_mask,
                           bool* send_cancel_owned) {
    if (upstream_cancel_mask) *upstream_cancel_mask = 0;
    if (send_cancel_owned) *send_cancel_owned = false;
    if ((has_upstream || upstream_connect_armed || upstream_recv_armed || upstream_send_armed) &&
        !valid_upstream_episode(upstream_episode))
        return 0;
    // Only cancel op types that are actually in flight to avoid wasting
    // SQ/CQ capacity with no-op cancels that produce -ENOENT completions.
    u32 submitted = 0;
    if (recv_armed) {
        if (cancel_by_user_data(
                encode_user_data(conn_id, IoEventType::Recv), conn_id, IoEventType::Recv))
            submitted++;
    }
    if (send_armed) {
        const u32 generation = conn_id < kMaxSendState ? send_state[conn_id].generation : 0;
        if (cancel_by_user_data(encode_user_data(conn_id, IoEventType::Send, generation),
                                conn_id,
                                IoEventType::Send,
                                generation == 0 ? 0 : generation | kNonUpstreamSendCancelBit)) {
            submitted++;
            if (send_cancel_owned) *send_cancel_owned = generation != 0;
        }
    }
    // Upstream ops only if the connection was proxying.
    if (has_upstream) {
        if (upstream_recv_armed) {
            if (cancel_by_user_data(
                    encode_upstream_user_data(conn_id, IoEventType::UpstreamRecv, upstream_episode),
                    conn_id,
                    IoEventType::UpstreamRecv,
                    kUpstreamCloseCancelAux,
                    upstream_episode)) {
                submitted++;
                if (upstream_cancel_mask) *upstream_cancel_mask |= kUpstreamOpRecv;
            }
        }
        if (upstream_send_armed) {
            if (cancel_by_user_data(
                    encode_upstream_user_data(conn_id, IoEventType::UpstreamSend, upstream_episode),
                    conn_id,
                    IoEventType::UpstreamSend,
                    kUpstreamCloseCancelAux,
                    upstream_episode)) {
                submitted++;
                if (upstream_cancel_mask) *upstream_cancel_mask |= kUpstreamOpSend;
            }
        }
        if (upstream_connect_armed &&
            cancel_by_user_data(
                encode_upstream_user_data(conn_id, IoEventType::UpstreamConnect, upstream_episode),
                conn_id,
                IoEventType::UpstreamConnect,
                kUpstreamCloseCancelAux,
                upstream_episode)) {
            submitted++;
            if (upstream_cancel_mask) *upstream_cancel_mask |= kUpstreamOpConnect;
        }
    }
    // JIT handler yield timer (IORING_OP_TIMEOUT) — cancel pins the slot
    // until the target CQE arrives, preventing stale HandlerTimer events
    // from resuming a handler on a reused slot.
    if (yield_armed) {
        if (cancel_by_user_data(
                encode_user_data(conn_id, IoEventType::HandlerTimer, yield_timer_gen),
                conn_id,
                IoEventType::HandlerTimer,
                yield_timer_gen))
            submitted++;
    }

    // Submit immediately so cancels take effect before close_conn_impl()
    // closes the fd. Retry on EINTR; subtract actually submitted count.
    for (;;) {
        i32 ret = io_uring_enter(ring_fd, pending, 0, IORING_ENTER_SQ_WAKEUP);
        if (ret >= 0) {
            pending -= static_cast<u32>(ret);
            break;
        }
        if (ret == -EINTR) continue;
        record_enter_error(ret);
        break;  // other error — event loop will stop instead of retrying forever
    }
    return submitted;
}

// --- Wait (submit + harvest) ---

u32 IoUringBackend::wait(IoEvent* events, u32 max_events, Connection* conns, u32 max_conns) {
    if (failure_code() != 0) return 0;
    // Retry timer read if previous submit_timer_read() failed (SQ was full)
    if (timer_fd >= 0 && !timer_read_armed) submit_timer_read();

    // Submit pending SQEs and wait for at least 1 CQE
    u32 flags = IORING_ENTER_GETEVENTS;
    i32 ret;
    for (;;) {
        if (pending > 0) {
            ret = io_uring_enter(ring_fd, pending, 1, flags);
            if (ret >= 0) pending -= static_cast<u32>(ret);
        } else {
            ret = io_uring_enter(ring_fd, 0, 1, flags);
        }
        if (ret >= 0) break;
        if (ret == -EINTR) continue;
        record_enter_error(ret);
        return 0;
    }

    // Harvest CQEs
    u32 head = __atomic_load_n(cq_head, __ATOMIC_ACQUIRE);
    u32 tail = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    u32 mask = *cq_ring_mask;
    u32 count = 0;

    while (head != tail && count < max_events) {
        io_uring_cqe* cqe = &cq_entries[head & mask];

        // The destination array is reused across waits.  Clear the complete
        // slot before decoding so metadata from a prior CQE can never become
        // evidence for the current one.
        events[count] = {};

        u32 conn_id;
        IoEventType type;
        u32 aux = 0;
        u32 upstream_episode = 0;
        decode_user_data(cqe->user_data, conn_id, type, aux, upstream_episode);

        // Cancel CQEs — silently consume, don't emit event
        if (conn_id == kCancelConnId) {
            head++;
            continue;
        }

        // --- #3: Timer tick handling ---
        if (conn_id == kTimerConnId && type == IoEventType::Timeout) {
            timer_read_armed = false;
            if (cqe->res == static_cast<i32>(sizeof(timer_ticks_buf))) {
                // Clamp tick count to avoid i32 overflow after long stalls
                i32 ticks =
                    (timer_ticks_buf > 0x7FFFFFFF) ? 0x7FFFFFFF : static_cast<i32>(timer_ticks_buf);
                events[count].conn_id = 0;
                events[count].type = IoEventType::Timeout;
                events[count].result = ticks;
                events[count].buf_id = 0;
                events[count].has_buf = 0;
                events[count].more = 0;
                events[count].aux = 0;
                events[count].upstream_episode = 0;
                count++;
            }
            // Re-submit read on timerfd for next tick
            submit_timer_read();
            head++;
            continue;
        }

        // --- #4: Provided buffer handling ---
        // MUST return the buffer to the ring regardless of result or conn_id validity,
        // otherwise the provided buffer ring drains and recv stalls.
        if (cqe->flags & IORING_CQE_F_BUFFER) {
            u16 buf_id = static_cast<u16>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);

            // Append data into the appropriate recv buffer only on success + valid conn.
            // UpstreamRecv → upstream_recv_buf; Recv → recv_buf.
            // Buffer is NOT reset here — callback resets when it consumes data.
            i32 buf_result = cqe->res;
            bool stale_upstream = false;
            bool deadline_active = false;
            bool deadline_owner = false;
            if (type == IoEventType::UpstreamRecv && conns != nullptr && conn_id < max_conns) {
                const auto& conn = conns[conn_id];
                deadline_active =
                    (conn.response_read_deadline_state == ResponseReadDeadlineState::Armed ||
                     conn.response_read_deadline_state ==
                         ResponseReadDeadlineState::BodyComplete) &&
                    conn.response_read_deadline_owner_generation != 0 &&
                    conn.response_read_deadline_owner_generation ==
                        conn.response_read_deadline_generation;
            }
            if (io_event_is_upstream(type)) {
                stale_upstream = conns == nullptr || conn_id >= max_conns ||
                                 upstream_episode == 0 ||
                                 upstream_episode != conns[conn_id].upstream_episode;
                if (!stale_upstream && type == IoEventType::UpstreamRecv) {
                    const auto& conn = conns[conn_id];
                    deadline_owner =
                        (conn.response_read_deadline_state == ResponseReadDeadlineState::Armed ||
                         conn.response_read_deadline_state ==
                             ResponseReadDeadlineState::BodyComplete) &&
                        conn.response_read_deadline_upstream_episode == upstream_episode &&
                        conn.response_read_deadline_owner_generation != 0 &&
                        conn.response_read_deadline_owner_generation ==
                            conn.response_read_deadline_generation;
                    // Episode equality alone is not ownership: a forged or
                    // duplicate aux-0 CQE must not mutate the live recv buffer,
                    // and a closed successor's target must drain accounting
                    // without copying bytes into reset storage.
                    stale_upstream =
                        aux != 0 || conn.fd < 0 ||
                        (!conn.upstream_recv_armed && !conn.upstream_recv_cancel_inflight);
                }
            }
            const bool valid_buffer_id = buf_id < kProvidedBufCount;
            if (cqe->res > 0 && conn_id < max_conns && !stale_upstream && valid_buffer_id) {
                u32 nbytes = static_cast<u32>(cqe->res);
                // TLS client connections receive ciphertext: land it in
                // tls_in_buf so the event-loop TLS layer can decrypt into
                // recv_buf (plaintext). Upstream + plaintext use their buffers.
                auto& target_buf = (type == IoEventType::UpstreamRecv)
                                       ? conns[conn_id].upstream_recv_buf
                                   : conns[conn_id].tls_active ? conns[conn_id].tls_in_buf
                                                               : conns[conn_id].recv_buf;
                const u8* src = buf_base + static_cast<u64>(buf_id) * kProvidedBufSize;
                u32 avail = target_buf.write_avail();
                const bool deadline_copy_eligible =
                    type == IoEventType::UpstreamRecv && deadline_owner &&
                    nbytes <= kProvidedBufSize && nbytes <= avail &&
                    response_deadline_copy_owner(conns[conn_id], upstream_episode, aux);
                // A matching explicit-deadline owner never enters the legacy
                // partial-copy path.  Its provided-buffer payload is one
                // indivisible witness: exact and fully eligible, or zero bytes.
                u32 to_copy = deadline_owner ? (deadline_copy_eligible ? nbytes : 0)
                                             : (nbytes < avail ? nbytes : avail);
                const u32 copy_begin = target_buf.len();
                if (to_copy > 0) {
                    __builtin_memcpy(target_buf.write_ptr(), src, to_copy);
                    target_buf.commit(to_copy);
                }
                // Report actual bytes copied, not kernel bytes (may differ if buf full)
                buf_result = (to_copy < nbytes) ? -ENOBUFS : static_cast<i32>(to_copy);
                if (deadline_owner) {
                    events[count].copy_witness = deadline_copy_eligible && to_copy == nbytes
                                                     ? IoEventCopyWitness::Full
                                                     : IoEventCopyWitness::Invalid;
                    events[count].copy_deadline_generation =
                        conns[conn_id].response_read_deadline_generation;
                    events[count].copy_deadline_profile =
                        static_cast<u8>(conns[conn_id].response_read_deadline_profile);
                    events[count].copy_deadline_method =
                        conns[conn_id].response_read_deadline_method;
                    if (events[count].copy_witness == IoEventCopyWitness::Full) {
                        events[count].copy_begin = copy_begin;
                        events[count].copy_end = target_buf.len();
                    }
                }
            } else if (cqe->res > 0 && deadline_active) {
                events[count].copy_witness = IoEventCopyWitness::Invalid;
                events[count].copy_deadline_generation =
                    conns[conn_id].response_read_deadline_generation;
                events[count].copy_deadline_profile =
                    static_cast<u8>(conns[conn_id].response_read_deadline_profile);
                events[count].copy_deadline_method = conns[conn_id].response_read_deadline_method;
                if (!stale_upstream) buf_result = -ENOBUFS;
            } else if (cqe->res > 0 && !valid_buffer_id) {
                buf_result = -ENOBUFS;
            }
            if (deadline_active && (stale_upstream || cqe->res == -ECANCELED || aux != 0)) {
                events[count].copy_witness = IoEventCopyWitness::Invalid;
                events[count].copy_deadline_generation =
                    conns[conn_id].response_read_deadline_generation;
                events[count].copy_deadline_profile =
                    static_cast<u8>(conns[conn_id].response_read_deadline_profile);
                events[count].copy_deadline_method = conns[conn_id].response_read_deadline_method;
            }

            // Always return the buffer, even on error
            if (valid_buffer_id) return_buffer(buf_id);

            // Emit event (buffer already returned, clear has_buf)
            events[count].conn_id = conn_id;
            events[count].type = type;
            events[count].result = buf_result;
            events[count].buf_id = 0;
            events[count].has_buf = 0;
            events[count].more = (cqe->flags & IORING_CQE_F_MORE) ? 1 : 0;
            events[count].aux = static_cast<u8>(aux);  // 0 for recv data
            events[count].upstream_episode = upstream_episode;
            head++;
            count++;
            continue;
        }

        // --- Send completion: enforce full-send proactor semantics ---
        // If IORING_OP_SEND returned partial, re-submit the remainder.
        // Only emit completion when all bytes sent (or error).
        if ((type == IoEventType::Send || (type == IoEventType::UpstreamSend && aux == 0)) &&
            conn_id < kMaxSendState) {
            auto& ss = (type == IoEventType::UpstreamSend) ? upstream_send_state[conn_id]
                                                           : send_state[conn_id];
            const bool live_upstream_send_owned =
                type != IoEventType::UpstreamSend ||
                (valid_upstream_episode(upstream_episode) &&
                 ss.upstream_episode == upstream_episode &&
                 (conns == nullptr || (conn_id < max_conns && conns[conn_id].fd >= 0 &&
                                       conns[conn_id].upstream_episode == upstream_episode &&
                                       conns[conn_id].upstream_send_armed)));
            if (!live_upstream_send_owned) {
                // This CQE belongs to a previous upstream episode (or is
                // malformed). Never apply its byte count to the state now
                // installed for this connection ID and never resubmit it.
                // Emit a tagged terminal event so the common async pending-op
                // accounting can retire the old operation.
                if (cqe->res > 0 && ss.remaining > 0) {
                    events[count].conn_id = conn_id;
                    events[count].type = type;
                    events[count].result = -ESTALE;
                    events[count].buf_id = 0;
                    events[count].has_buf = 0;
                    events[count].more = 0;
                    events[count].aux = static_cast<u8>(aux);
                    events[count].upstream_episode = upstream_episode;
                    events[count].non_upstream_generation =
                        type == IoEventType::Send ? ss.generation : 0;
                    head++;
                    count++;
                    continue;
                }
            }
            if (cqe->res > 0 && ss.remaining > 0) {
                u32 nw = static_cast<u32>(cqe->res);
                if (nw > ss.remaining || ss.offset > UINT32_MAX - nw) {
                    // A completion may never claim bytes outside the submitted
                    // range.  Clear the state and emit one terminal failure;
                    // wrapping remaining would otherwise manufacture a complete
                    // fixed request upload (and can also address past src).
                    ss.remaining = 0;
                    events[count].conn_id = conn_id;
                    events[count].type = type;
                    events[count].result = -EOVERFLOW;
                    events[count].buf_id = 0;
                    events[count].has_buf = 0;
                    events[count].more = 0;
                    events[count].aux = static_cast<u8>(aux);
                    events[count].upstream_episode = upstream_episode;
                    events[count].non_upstream_generation =
                        type == IoEventType::Send ? ss.generation : 0;
                    head++;
                    count++;
                    continue;
                }
                ss.offset += nw;
                ss.remaining -= nw;
                if (ss.remaining > 0) {
                    // Partial — re-submit remaining bytes
                    io_uring_sqe* sqe = get_sqe();
                    if (sqe) {
                        memset(sqe, 0, sizeof(*sqe));
                        sqe->opcode = IORING_OP_SEND;
                        sqe->fd = ss.fd;
                        sqe->addr = reinterpret_cast<u64>(ss.src + ss.offset);
                        sqe->len = ss.remaining;
                        sqe->user_data =
                            type == IoEventType::UpstreamSend
                                ? encode_upstream_user_data(conn_id, type, ss.upstream_episode)
                                : encode_user_data(conn_id, type, ss.generation);
                        sqe_advance_tail(sq_tail);
                        pending++;
                        head++;
                        continue;  // don't emit event yet
                    }
                    // SQ full — can't re-submit. Emit error to prevent deadlock.
                    ss.remaining = 0;
                    events[count].conn_id = conn_id;
                    events[count].type = type;
                    events[count].result = -ENOSPC;
                    events[count].buf_id = 0;
                    events[count].has_buf = 0;
                    events[count].more = 0;
                    events[count].aux = 0;
                    events[count].upstream_episode = upstream_episode;
                    events[count].non_upstream_generation =
                        type == IoEventType::Send ? ss.generation : 0;
                    head++;
                    count++;
                    continue;
                }
                // All bytes sent — emit completion with total
                events[count].conn_id = conn_id;
                events[count].type = type;
                events[count].result = static_cast<i32>(ss.offset);
                events[count].buf_id = 0;
                events[count].has_buf = 0;
                events[count].more = 0;
                events[count].aux = 0;
                events[count].upstream_episode = upstream_episode;
                events[count].non_upstream_generation =
                    type == IoEventType::Send ? ss.generation : 0;
                head++;
                count++;
                continue;
            }
            // Error or no send_state — fall through to default emit
        }

        // --- Default: non-buffer events (Accept, Connect, error Send/Recv) ---
        events[count].conn_id = conn_id;
        events[count].type = type;
        events[count].result = type == IoEventType::HandlerTimer ? static_cast<i32>(aux) : cqe->res;
        events[count].buf_id = 0;
        events[count].has_buf = 0;
        events[count].more = (cqe->flags & IORING_CQE_F_MORE) ? 1 : 0;
        // Forward the decoded aux so dispatch can recognize a pause cancel's own
        // completion (UpstreamRecv + kPauseCancelAux); 0 for every normal op.
        events[count].aux = type == IoEventType::Send ? 0 : static_cast<u8>(aux);
        events[count].upstream_episode = upstream_episode;
        events[count].non_upstream_generation = type == IoEventType::Send ? aux : 0;
        if (type == IoEventType::UpstreamRecv && conns != nullptr && conn_id < max_conns &&
            conns[conn_id].response_read_deadline_state == ResponseReadDeadlineState::Armed &&
            conns[conn_id].response_read_deadline_owner_generation != 0 &&
            conns[conn_id].response_read_deadline_owner_generation ==
                conns[conn_id].response_read_deadline_generation &&
            (cqe->res > 0 || cqe->res == -ECANCELED || aux != 0)) {
            events[count].copy_witness = IoEventCopyWitness::Invalid;
            events[count].copy_deadline_generation =
                conns[conn_id].response_read_deadline_generation;
            events[count].copy_deadline_profile =
                static_cast<u8>(conns[conn_id].response_read_deadline_profile);
            events[count].copy_deadline_method = conns[conn_id].response_read_deadline_method;
            if (cqe->res > 0 && upstream_episode == conns[conn_id].upstream_episode)
                events[count].result = -ENOBUFS;
        }

        head++;
        count++;
    }

    __atomic_store_n(cq_head, head, __ATOMIC_RELEASE);
    return count;
}

// --- Shutdown ---

void IoUringBackend::shutdown() {
    if (timer_fd >= 0) {
        close(timer_fd);
        timer_fd = -1;
    }
    if (buf_base != nullptr) {
        munmap(buf_base, static_cast<u64>(kProvidedBufCount) * kProvidedBufSize);
        buf_base = nullptr;
    }
    if (buf_ring != nullptr) {
        u64 ring_sz = sizeof(io_uring_buf_ring) + kProvidedBufCount * sizeof(io_uring_buf);
        munmap(buf_ring, ring_sz);
        buf_ring = nullptr;
    }
    if (sqes_ptr != nullptr) {
        munmap(sqes_ptr, sqes_sz);
        sqes_ptr = nullptr;
    }
    if (cq_ring_ptr != nullptr) {
        munmap(cq_ring_ptr, cq_ring_sz);
        cq_ring_ptr = nullptr;
    }
    if (sq_ring_ptr != nullptr) {
        munmap(sq_ring_ptr, sq_ring_sz);
        sq_ring_ptr = nullptr;
    }
    if (ring_fd >= 0) {
        close(ring_fd);
        ring_fd = -1;
    }
}

}  // namespace rut
