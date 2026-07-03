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

// user_data aux tag marking a pause cancel's OWN completion (vs the recv CQE it
// cancels, aux 0). Shared by the io_uring backend (sets it) and the event loop
// (recognizes it via IoEvent::aux to re-arm only after the cancel has drained).
inline constexpr u8 kPauseCancelAux = 1;
// Local backend submission/registration failure. The completion is synthetic: real
// proxy paths fail closed, while health probes drop it without recording backend health.
inline constexpr u8 kLocalSubmitFailureAux = 2;

// Unified completion event — field order optimized for minimal padding.
struct IoEvent {
    u32 conn_id;
    i32 result;  // bytes transferred or error code
    u16 buf_id;  // provided buffer id (io_uring only; valid iff has_buf != 0)
    u8 has_buf;  // non-zero if this event owns a provided buffer in buf_id
    IoEventType type;
    u8 more;     // non-zero if the SQE will produce more CQEs (multishot recv)
    u8 aux = 0;  // decoded user_data aux tag; kPauseCancelAux marks a pause cancel's
                 // own completion (distinct from the recv CQE it cancels)
};

}  // namespace rut
