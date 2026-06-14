/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

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
//   bool add_recv_upstream(i32 fd, u32 conn_id); // upstream recv (UpstreamRecv type)
//   bool add_send(i32 fd, u32 conn_id, const u8* buf, u32 len);
//   bool add_send_upstream(i32 fd, u32 conn_id, const u8* buf, u32 len); // UpstreamSend
//   bool add_connect(i32 fd, u32 conn_id, const void* addr, u32 addr_len);
//   void cancel(i32 fd, u32 conn_id);
//   u32  wait(IoEvent* events, u32 max_events, Connection* conns, u32 max_conns);
//
// Proactor model: wait() returns completed I/O events.
// - io_uring: native proactor, I/O is already done when CQE arrives
// - epoll: reactor internally, but wait() does recv/send and emits completions
//
// Error convention: IoEvent.result < 0 means -errno.

// Max events per wait call
static constexpr u32 kMaxEventsPerWait = 256;

// Provided buffer ring size (io_uring)
static constexpr u32 kProvidedBufCount = 2048;
static constexpr u32 kProvidedBufSize = 4096;  // 4KB per buffer

// Buffer group ID for provided buffer ring
static constexpr u16 kBufGroupId = 0;

}  // namespace rut
