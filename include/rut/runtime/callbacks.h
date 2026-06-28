#pragma once

#include "rut/common/types.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/traffic_capture.h"

namespace rut {

enum class HttpMethod : u8;

struct EpollEventLoop;
struct IoUringEventLoop;

// Verify capture slice size constants match the authoritative CaptureEntry::kMaxHeaderLen.
// These are defined separately in each EventLoop type to avoid circular includes.
static_assert(CaptureEntry::kMaxHeaderLen == 8192,
              "Update kCaptureSliceSize in all EventLoop types if this changes");

// HTTP status codes used in callbacks.
static constexpr u16 kStatusOK = 200;
static constexpr u16 kStatusInternalServerError = 500;
static constexpr u16 kStatusBadGateway = 502;

// Minimum bytes for a valid HTTP response status line ("HTTP/1.x NNN").
static constexpr u32 kMinResponseLen = 12;

// Length of "Connection: close\r\n".
static constexpr u32 kConnCloseLen = 19;

// Length of the header terminator "\r\n\r\n".
static constexpr u32 kHeaderEndLen = 4;

static constexpr u32 kResponse200Len = sizeof(
                                           "HTTP/1.1 200 OK\r\n"
                                           "Content-Length: 2\r\n"
                                           "Connection: keep-alive\r\n"
                                           "\r\n"
                                           "OK") -
                                       1;

static constexpr u32 kResponse200CloseLen = sizeof(
                                                "HTTP/1.1 200 OK\r\n"
                                                "Content-Length: 2\r\n"
                                                "Connection: close\r\n"
                                                "\r\n"
                                                "OK") -
                                            1;

// Callbacks are template functions parameterized on the concrete EventLoop type.
// Each is assigned to a per-event-type slot (on_recv, on_send, on_upstream_recv,
// on_upstream_send). dispatch_event routes events to the correct slot —
// callbacks only receive their expected event type. Zero virtual dispatch.

template <typename Loop>
void on_header_received(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_response_sent(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_jit_wait_send_sent(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_upstream_connected(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_upstream_request_sent(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_upstream_response(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_proxy_response_sent(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_response_header_sent(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_response_body_recvd(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_response_body_sent(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_request_body_sent(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_request_body_recvd(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_jit_request_body_recvd(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_early_upstream_recvd(void* lp, Connection& conn, IoEvent ev);

// JIT handler dispatch — invoked from timer.tick when pending_handler_fn
// is set (distinguishes resume from keepalive expiry). Defined in
// callbacks_impl.h alongside the rest of the handler-chain logic.
template <typename Loop>
void resume_jit_handler(Loop* loop, Connection& conn);

// Emit 504 Gateway Timeout for a proxying connection whose upstream stalled
// before responding — invoked from timer.tick. Defined in callbacks_impl.h.
template <typename Loop>
void respond_upstream_timeout(Loop* loop, Connection& conn);

// Answer a suspended HTTP/2 proxy stream with a synthetic status (e.g. 504 on
// upstream timeout from the timer tick, 502 on failure) and tear down the
// upstream side. Defined in callbacks_impl.h.
template <typename Loop>
void h2_proxy_fail(Loop* loop, Connection& conn, u16 status);

// Resume a throttled (@throttle) client send parked for the next byte-rate
// window — invoked from the per-shard timer tick. Defined in callbacks_impl.h.
template <typename Loop>
void throttle_resume(Loop* loop, Connection& conn);

template <typename Loop>
void on_early_upstream_recvd_send_inflight(void* lp, Connection& conn, IoEvent ev);

template <typename Loop>
void on_body_send_with_early_response(void* lp, Connection& conn, IoEvent ev);

extern template void on_header_received<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_response_sent<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_jit_wait_send_sent<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_upstream_connected<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_upstream_request_sent<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_upstream_response<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_proxy_response_sent<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_response_header_sent<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_response_body_recvd<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_response_body_sent<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_request_body_sent<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_request_body_recvd<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_jit_request_body_recvd<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_early_upstream_recvd<EpollEventLoop>(void*, Connection&, IoEvent);
extern template void on_early_upstream_recvd_send_inflight<EpollEventLoop>(void*,
                                                                           Connection&,
                                                                           IoEvent);
extern template void on_body_send_with_early_response<EpollEventLoop>(void*, Connection&, IoEvent);

extern template void on_header_received<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_response_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_jit_wait_send_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_upstream_connected<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_upstream_request_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_upstream_response<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_proxy_response_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_response_header_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_response_body_recvd<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_response_body_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_request_body_sent<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_request_body_recvd<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_jit_request_body_recvd<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_early_upstream_recvd<IoUringEventLoop>(void*, Connection&, IoEvent);
extern template void on_early_upstream_recvd_send_inflight<IoUringEventLoop>(void*,
                                                                             Connection&,
                                                                             IoEvent);
extern template void on_body_send_with_early_response<IoUringEventLoop>(void*,
                                                                        Connection&,
                                                                        IoEvent);

inline u8 ascii_lower(u8 c) {
    if (c >= 'A' && c <= 'Z') return static_cast<u8>(c + ('a' - 'A'));
    return c;
}

inline bool ascii_ci_eq(const u8* data, const char* lit, u32 len) {
    for (u32 i = 0; i < len; i++) {
        if (ascii_lower(data[i]) != ascii_lower(static_cast<u8>(lit[i]))) return false;
    }
    return true;
}

}  // namespace rut
