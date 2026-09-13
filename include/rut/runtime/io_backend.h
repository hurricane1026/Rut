#pragma once

#include "rut/common/types.h"
#include "rut/runtime/io_event.h"

namespace rut {

// I/O backend concept — satisfied by both IoUringBackend and EpollBackend.
// Selected at compile time via template parameter — no virtual dispatch.
//
// Required interface:
//   i32  init(u32 shard_id, i32 listen_fd);  // returns 0 on success, -errno on failure
//   static constexpr bool kAsyncIo;  // true for io_uring, false for epoll
//   void add_accept();
//   bool add_recv(i32 fd, u32 conn_id);          // false if SQ full (io_uring)
//   bool add_recv_upstream(i32 fd, u32 conn_id, u32 upstream_episode);
//                                                // upstream recv (UpstreamRecv)
//   bool add_send(i32 fd, u32 conn_id, const u8* buf, u32 len);
//   bool add_send_upstream(i32 fd, u32 conn_id, const u8* buf, u32 len,
//                          u32 upstream_episode); // UpstreamSend
//   bool add_connect(i32 fd, u32 conn_id, const void* addr, u32 addr_len,
//                    u32 upstream_episode);
//   void cancel(i32 fd, u32 conn_id);
//   u32  wait(IoEvent* events, u32 max_events, Connection* conns, u32 max_conns);
//
// Proactor model: wait() returns completed I/O events.
// - io_uring: native proactor, I/O is already done when CQE arrives
// - epoll: reactor internally, but wait() does recv/send and emits completions
//
// Error convention: IoEvent.result < 0 means -errno.
// Upstream producers require a valid nonzero episode; downstream and other
// synthetic/test events use the neutral episode. This is an internal CRTP
// contract, not a public IoEvent ABI change.

// Max events per wait call
static constexpr u32 kMaxEventsPerWait = 256;

// Provided buffer ring size (io_uring)
static constexpr u32 kProvidedBufCount = 2048;
static constexpr u32 kProvidedBufSize = 4096;  // 4KB per buffer

// Buffer group ID for provided buffer ring
static constexpr u16 kBufGroupId = 0;

}  // namespace rut
