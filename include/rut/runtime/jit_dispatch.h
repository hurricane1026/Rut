#pragma once

#include "rut/common/types.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/io_event.h"

namespace rut {

// ── Outcome of a JIT handler invocation ────────────────────────────
//
// Decouples the handler ABI (packed u64) from the event-loop wiring.
// Callers (epoll_event_loop, iouring_event_loop, simulate_engine) invoke
// the handler via `invoke_jit_handler()` and then dispatch on `kind`:
//
//   - ReturnStatus: send HTTP response with `status_code` and finish.
//   - Forward:     proxy to upstream #`upstream_id`.
//   - TimerYield:  schedule a wake `timer_ms` from now and resume the
//                   same handler with `ctx.state = next_state`. The
//                   handler was paused at a `wait(ms)` (or later
//                   `any(wait(h, ms))`) boundary; the event loop picks
//                   the timer mechanism and precision — for example,
//                   consuming `timer_ms` directly via IORING_OP_TIMEOUT
//                   or a min-heap + one-shot timerfd, or bucketing via
//                   the 1-second TimerWheel.
//   - Error:       handler returned an unsupported action — event loop
//                   should close the connection with 500.

struct JitDispatchOutcome {
    enum class Kind : u8 {
        ReturnStatus,
        Forward,
        TimerYield,
        EventYield,
        Error,
    };

    Kind kind = Kind::Error;
    u16 status_code = 0;
    u16 upstream_id = 0;
    u16 next_state = 0;
    jit::YieldKind yield_kind = jit::YieldKind::Timer;
    u32 timer_ms = 0;  // raw ms payload; callers pick their own precision
    // 1-based index into RouteConfig::response_bodies for
    // Kind::ReturnStatus; 0 = no custom body. Decoded from the
    // upstream_id slot per handler ABI.
    //
    // Meaning of body_idx == 0 depends on response_headers_idx:
    //   body_idx == 0, headers_idx == 0: "no custom body" → dispatch
    //       falls back to format_static_response. For status codes
    //       that allow a body, that emits the reason-phrase as body;
    //       for codes that must have no body (1xx / 204 / 304) the
    //       formatter correctly emits Content-Length: 0 and no body
    //       bytes.
    //   body_idx == 0, headers_idx != 0: "headers-only response" (the
    //       user wrote `response(301, headers: {...})`) → empty body,
    //       Content-Length: 0, custom headers emitted on the wire.
    //   body_idx > 0 but out-of-range: config mismatch; dispatch falls
    //       back to the reason-phrase body (subject to the same
    //       no-body-code rule above). Preserved in both the
    //       no-headers and headers paths.
    u16 response_body_idx = 0;
    const char* dynamic_response_body = nullptr;
    u32 dynamic_response_body_len = 0;
    const jit::HandlerCtx* response_ctx = nullptr;
    // 1-based index into RouteConfig::response_header_sets for
    // Kind::ReturnStatus; 0 = no custom headers. Decoded from the
    // next_state slot per handler ABI (reused while action is
    // ReturnStatus — next_state has no resumption meaning there).
    u16 response_headers_idx = 0;
};

inline constexpr bool response_status_forbids_body(u16 status) {
    return status < 200 || status == 204 || status == 205 || status == 304;
}

// Round-up conversion from ms to seconds. Callers using a 1-second
// TimerWheel (legacy keepalive mechanism) can use this to bucket timer_ms.
// Native ms-precision paths (IORING_OP_TIMEOUT / epoll min-heap) should
// consume outcome.timer_ms directly.
inline u32 timer_seconds_from_ms(u32 ms) {
    if (ms == 0) return 0;
    const u64 secs = (static_cast<u64>(ms) + 999u) / 1000u;
    return secs > 0xFFFFFFFFu ? 0xFFFFFFFFu : static_cast<u32>(secs);
}

inline bool yield_kind_matches_event(jit::YieldKind kind, IoEventType type) {
    switch (kind) {
        case jit::YieldKind::Any:
            return type == IoEventType::Recv || type == IoEventType::Timeout ||
                   type == IoEventType::HandlerTimer;
        case jit::YieldKind::Recv:
            return type == IoEventType::Recv;
        case jit::YieldKind::Send:
            return type == IoEventType::Send;
        case jit::YieldKind::UpstreamConnect:
            return type == IoEventType::UpstreamConnect;
        case jit::YieldKind::UpstreamRecv:
            return type == IoEventType::UpstreamRecv;
        case jit::YieldKind::UpstreamSend:
            return type == IoEventType::UpstreamSend;
        case jit::YieldKind::HttpGet:
        case jit::YieldKind::HttpPost:
        case jit::YieldKind::Forward:
        case jit::YieldKind::Timer:
            return false;
    }
    return false;
}

inline jit::YieldKind yield_kind_from_event(IoEventType type) {
    switch (type) {
        case IoEventType::Recv:
            return jit::YieldKind::Recv;
        case IoEventType::Send:
            return jit::YieldKind::Send;
        case IoEventType::UpstreamConnect:
            return jit::YieldKind::UpstreamConnect;
        case IoEventType::UpstreamRecv:
            return jit::YieldKind::UpstreamRecv;
        case IoEventType::UpstreamSend:
            return jit::YieldKind::UpstreamSend;
        case IoEventType::Timeout:
        case IoEventType::HandlerTimer:
            return jit::YieldKind::Timer;
        case IoEventType::Accept:
        case IoEventType::Count:
            return jit::YieldKind::HttpGet;
    }
    return jit::YieldKind::Timer;
}

// Invoke a JIT-compiled handler once and translate the packed result
// into an event-loop-facing outcome. Does NOT loop: a Yield returns either
// TimerYield or EventYield, and the caller is expected to resume by setting
// `ctx.state = out.next_state` and calling this function again after the
// requested timer or event fires.
//
// Caller owns storage for `ctx`. If the handler reads wait result fields after
// a resume, `ctx` must include the 8-byte-aligned frame slots advertised by
// `slot_count`, and the same 8-byte-aligned storage must be reused across
// resumes. The entry call must set `ctx.state = 0`.
inline JitDispatchOutcome invoke_jit_handler(jit::HandlerFn fn,
                                             void* conn,
                                             jit::HandlerCtx& ctx,
                                             const u8* req_data,
                                             u32 req_len,
                                             void* arena) {
    JitDispatchOutcome out{};
    if (fn == nullptr) return out;  // Kind::Error by default

    const u64 packed = fn(conn, &ctx, req_data, req_len, arena);
    const auto r = jit::HandlerResult::unpack(packed);

    switch (r.action) {
        case jit::HandlerAction::ReturnStatus:
            out.kind = JitDispatchOutcome::Kind::ReturnStatus;
            out.status_code = r.status_code;
            out.response_ctx = &ctx;
            // ABI: upstream_id carries a 1-based response-body index
            // and next_state a 1-based response-header-set index for
            // ReturnStatus (0 = no custom body / no custom headers;
            // dispatch behaviour when idx == 0 — reason-phrase fallback
            // vs. headers-only empty body — is documented on the
            // response_body_idx field above).
            if (r.upstream_id == jit::HandlerResult::kDynamicResponseBody) {
                // A failed/overflowed serializer is a server error, never a
                // partial JSON response. The helper clears valid before work.
                if ((ctx.response_body_valid == 0 || ctx.response_body_data == nullptr) &&
                    !response_status_forbids_body(out.status_code)) {
                    out.status_code = 500;
                } else if (ctx.response_body_valid != 0 && ctx.response_body_data != nullptr) {
                    out.dynamic_response_body = ctx.response_body_data;
                    out.dynamic_response_body_len = ctx.response_body_len;
                }
            } else {
                out.response_body_idx = r.upstream_id;
            }
            out.response_headers_idx = r.next_state;
            return out;
        case jit::HandlerAction::Forward:
            out.kind = JitDispatchOutcome::Kind::Forward;
            out.upstream_id = r.upstream_id;
            return out;
        case jit::HandlerAction::Yield:
            out.next_state = r.next_state;
            out.yield_kind = r.yield_kind;
            switch (r.yield_kind) {
                case jit::YieldKind::Timer:
                    out.kind = JitDispatchOutcome::Kind::TimerYield;
                    out.timer_ms = r.yield_payload_u32();
                    return out;
                case jit::YieldKind::Any:
                case jit::YieldKind::Recv:
                case jit::YieldKind::Send:
                case jit::YieldKind::UpstreamConnect:
                case jit::YieldKind::UpstreamRecv:
                case jit::YieldKind::UpstreamSend:
                    out.kind = JitDispatchOutcome::Kind::EventYield;
                    out.timer_ms = r.yield_payload_u32();
                    return out;
                case jit::YieldKind::HttpGet:
                case jit::YieldKind::HttpPost:
                case jit::YieldKind::Forward:
                    return out;
            }
            return out;
    }
    return out;  // unreachable; leaves Kind::Error
}

}  // namespace rut
