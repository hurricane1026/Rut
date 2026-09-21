#pragma once

#include "core/expected.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/error.h"
#include "rut/runtime/io_backend.h"
#include <atomic>

#include <sys/event.h>

namespace rut {

// macOS development backend. Independent EVFILT_READ / EVFILT_WRITE filters
// perform synchronous nonblocking I/O and produce the runtime's IoEvent stream.
// No epoll emulation, extra library, asynchronous buffer ownership or CPU pinning.
struct KqueueBackend {
    static constexpr bool kAsyncIo = false;
    static constexpr u32 kMaxFdMap = 16384;
    static constexpr u32 kPendingCap = 64;
    static constexpr u32 kPendingBurstQuota = 8;
    static constexpr u32 kUpstreamEpisodeExhausted = kInvalidUpstreamEventEpisode;

    u32 pending_count = 0;  // Capacity inspected by the shared health-probe scheduler.
    i32 kqueue_fd = -1;
    i32 listen_fd = -1;
    i32 downstream_fd_map[kMaxFdMap];
    i32 upstream_fd_map[kMaxFdMap];
    u32 active_upstream_episode[kMaxFdMap];

    struct SendState {
        const u8* src = nullptr;
        i32 fd = -1;
        u32 offset = 0;
        u32 remaining = 0;
        IoEventType type = IoEventType::Send;
        bool tls = false;
        i16 tls_wait_filter = 0;
        u32 upstream_episode = 0;
    };
    SendState send_state[kMaxFdMap];
    SendState upstream_send_state[kMaxFdMap];

    core::Expected<void, Error> init(u32 shard_id, i32 listener);
    void shutdown();
    void add_accept();
    void cancel_accept();
    bool add_recv(i32 fd, u32 conn_id);
    bool add_recv_upstream(i32 fd, u32 conn_id, u32 episode);
    void pause_recv(u32 conn_id, bool preserve_send_interest = false);
    void pause_upstream_recv(u32 conn_id, u32 episode, bool preserve_send_interest = false);
    void quiesce_recv(u32 conn_id, bool upstream, u32 episode);
    void clear_send_state(u32 conn_id);
    bool add_send(i32 fd, u32 conn_id, const u8* buf, u32 len);
    bool add_send_upstream(i32 fd, u32 conn_id, const u8* buf, u32 len, u32 episode);
    bool add_send_tls(Connection& conn, const u8* buf, u32 len);
    bool add_connect(i32 fd, u32 conn_id, const void* addr, u32 addr_len, u32 episode);
    u32 cancel(
        i32 fd, u32 conn_id, bool = false, bool = false, bool = false, bool = false, bool = false);
    bool begin_upstream_episode(u32 conn_id, u32 episode);
    bool retire_upstream_episode_after_detach(Connection& conn, u32 episode);
    bool detach_upstream(Connection& conn, i32* detached_fd = nullptr);
    void quarantine_upstream_episode_on_slot_release(u32 conn_id);
    void arm_yield_timer(u64 deadline_ns);
    void wake();
    i32 failure_code() const { return failure_.load(std::memory_order_acquire); }
    u32 wait(IoEvent* events, u32 max_events, Connection* conns, u32 max_conns);

private:
    // Paused downstream reads retain EOF detection without spinning on data.
    enum class ReadMode : u8 { Disabled, Active, EofOnly };
    ReadMode downstream_read_[kMaxFdMap];
    ReadMode upstream_read_[kMaxFdMap];
    SSL* downstream_tls_[kMaxFdMap];
    i16 tls_recv_filter_[kMaxFdMap];
    u32 tls_read_hint_ = kMaxFdMap;
    IoEvent pending_[kPendingCap];
    u32 pending_streak_ = 0;
    std::atomic<i32> failure_{0};

    void fail(i32 error);
    bool valid_owner(u32 conn_id, u32 episode) const;
    bool register_read(u32 conn_id, bool upstream);
    bool arm_send(u32 conn_id, SendState& state);
    bool queue(u32 conn_id, IoEventType type, i32 result, u32 episode = 0, u8 aux = 0);
    u32 pop_pending(IoEvent* event, Connection* conns, u32 max_conns);
    bool start_send(i32 fd, u32 conn_id, const u8* buf, u32 len, bool upstream, u32 episode);
    i32 flush_send(SendState& state, SSL* ssl);
    bool finish_send(u32 conn_id, SendState& state, SSL* ssl, IoEvent& event);
    bool receive(Connection& conn, bool upstream, IoEvent& event);
};

}  // namespace rut
