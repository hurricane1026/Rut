#pragma once

#include "rut/common/types.h"
#include "rut/runtime/io_event.h"

namespace rut {

// I/O backend concept — IoUringBackend/EpollBackend on Linux, KqueueBackend on macOS.
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
// - epoll/kqueue: reactor internally, but wait() does recv/send and emits completions
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

// Dedicated provided buffer ring for bounded one-shot upstream recvs. Each
// buffer matches one upstream receive slice, so a response body moves in
// slice-sized steps instead of 4 KiB steps. Buffer ids continue after the
// ordinary ring's ids: a CQE's buffer id alone identifies the owning ring.
static constexpr u32 kLargeProvidedBufCount = 1024;
static constexpr u32 kLargeProvidedBufSize = 16384;
static constexpr u16 kLargeBufGroupId = 1;
static constexpr u32 kLargeProvidedBufIdBase = kProvidedBufCount;
static_assert((kLargeProvidedBufCount & (kLargeProvidedBufCount - 1)) == 0,
              "provided buffer ring entries must be a power of two");
static_assert(kLargeProvidedBufIdBase + kLargeProvidedBufCount <= 0x10000u,
              "provided buffer ids must fit the CQE's 16-bit buffer id");

// Bulk provided buffer ring for upstream body relays that switched to bulk
// relay buffers (SlicePool::kBulkSliceSize). A bulk relay moves the body in
// 256 KiB steps instead of 16 KiB ones, which cuts the per-chunk completion
// round trips of a large proxied body by 16x. The ring holds one buffer per
// bulk relay buffer, so the at most kBulkSlices / 2 bulk relays (each with a
// single armed one-shot recv) can never drain it.
static constexpr u32 kBulkProvidedBufCount = 64;
static constexpr u32 kBulkProvidedBufSize = 256 * 1024;
static constexpr u16 kBulkBufGroupId = 2;
static constexpr u32 kBulkProvidedBufIdBase = kLargeProvidedBufIdBase + kLargeProvidedBufCount;
static_assert((kBulkProvidedBufCount & (kBulkProvidedBufCount - 1)) == 0,
              "provided buffer ring entries must be a power of two");
static_assert(kBulkProvidedBufIdBase + kBulkProvidedBufCount <= 0x10000u,
              "provided buffer ids must fit the CQE's 16-bit buffer id");

}  // namespace rut
