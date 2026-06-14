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

namespace rut {

// I/O event types — shared by both io_uring and epoll backends
enum class IoEventType : u8 {
    Accept,
    Recv,
    Send,
    UpstreamConnect,
    UpstreamRecv,
    UpstreamSend,
    Timeout,       // 1-second TimerWheel tick (keepalive driver)
    HandlerTimer,  // JIT handler yield timer expired. Precise to ms.
                   // io_uring: IORING_OP_TIMEOUT — conn_id identifies the
                   //   target connection whose pending_handler_fn resumes.
                   // epoll:   shared one-shot timerfd — event is a global
                   //   notification; conn_id is unused, the event loop
                   //   drains its min-heap to find which conns to resume.
    Count,
};

static_assert(static_cast<u8>(IoEventType::Count) == 8u,
              "IoEventType should keep all runtime event tags and remain small");

// Unified completion event — field order optimized for minimal padding.
struct IoEvent {
    u32 conn_id;
    i32 result;  // bytes transferred or error code
    u16 buf_id;  // provided buffer id (io_uring only; valid iff has_buf != 0)
    u8 has_buf;  // non-zero if this event owns a provided buffer in buf_id
    IoEventType type;
    u8 more;  // non-zero if the SQE will produce more CQEs (multishot recv)
};

}  // namespace rut
