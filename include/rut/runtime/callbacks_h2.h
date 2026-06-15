#pragma once

// HTTP/2 serving path, shared by both backends (templated on Loop). Drives the
// per-connection Http2Conn engine: feed inbound bytes, run dispatch for each
// completed request, serialize responses as HEADERS(+DATA), and flush.
//
// First serving cut: static (return-status) routes + the default 200. JIT
// handlers and proxy over h2 answer 503 for now (they need request-byte
// synthesis / async-yield-over-h2 wiring — tracked as follow-ups). HTTP/1 is
// untouched: this path is only entered when conn.protocol == Http2 (ALPN) or
// the cleartext h2c preface is detected.

#include "rut/runtime/connection.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/route_method.h"
#include "rut/runtime/route_params.h"
#include "rut/runtime/route_table.h"

#include <string.h>  // memmove

namespace rut {

// Per-process() dispatch context, pointed at by Http2Conn::cb_ctx for the
// duration of one process() call. Response frames produced by the on_headers
// callback accumulate in `resp`.
template <typename Loop>
struct H2Dispatch {
    Loop* loop;
    Connection* conn;
    u8* resp;
    u32 resp_cap;
    u32 resp_len;
    bool overflow;
};

// Append a status-only response (HEADERS with :status, END_STREAM) for a stream.
template <typename Loop>
void h2_emit_status(H2Dispatch<Loop>& d, u32 stream_id, u16 status) {
    char sbuf[3];
    sbuf[0] = static_cast<char>('0' + (status / 100) % 10);
    sbuf[1] = static_cast<char>('0' + (status / 10) % 10);
    sbuf[2] = static_cast<char>('0' + status % 10);
    const hpack::Header kHs[] = {{{":status", 7}, {sbuf, 3}}};
    const u32 kN = http2_write_headers(d.resp + d.resp_len,
                                       d.resp_cap - d.resp_len,
                                       stream_id,
                                       kHs,
                                       1,
                                       /*end_stream=*/true);
    if (kN == 0)
        d.overflow = true;
    else
        d.resp_len += kN;
}

// Resolve a completed h2 request to a status and emit the response.
template <typename Loop>
void h2_dispatch_request(H2Dispatch<Loop>& d,
                         u32 stream_id,
                         const hpack::Header* headers,
                         u32 nheaders) {
    ParsedRequest req;
    if (!h2_headers_to_request(headers, nheaders, &req)) {
        h2_emit_status(d, stream_id, 400);
        return;
    }

    const RouteConfig* config = d.conn->request_config;
    if (!config) {
        h2_emit_status(d, stream_id, 200);  // route-less fallback (matches HTTP/1)
        return;
    }

    const u8 kMethodKey = route_method_key(req.method);
    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    const RouteEntry* route =
        config->match_canonical(req.path_canon, kMethodKey, params, &param_count, kMaxRouteParams);

    if (!route) {
        h2_emit_status(d, stream_id, 200);  // default (matches HTTP/1 catchall)
        return;
    }
    switch (route->action) {
        case RouteAction::Static:
            h2_emit_status(d, stream_id, route->status_code);
            return;
        case RouteAction::Proxy:
        case RouteAction::JitHandler:
        default:
            // TODO(h2): proxy and JIT handlers over HTTP/2 — proxy needs the
            // upstream state machine driven per stream; JIT needs request-byte
            // synthesis (handlers prime their parse cache from HTTP/1 bytes) and
            // async-yield-over-h2. Until then, fail closed.
            h2_emit_status(d, stream_id, 503);
            return;
    }
}

template <typename Loop>
void h2_on_headers_cb(
    void* ctx, Http2Conn& /*c*/, u32 stream_id, const hpack::Header* hs, u32 n, bool /*end*/) {
    auto* d = static_cast<H2Dispatch<Loop>*>(ctx);
    h2_dispatch_request(*d, stream_id, hs, n);
}

// Forward declaration: defined below; on_h2_data re-arms via this on send done.
template <typename Loop>
void on_h2_data(void* lp, Connection& conn, IoEvent ev);

// Send-completion callback for the h2 path (partial-send aware, mirrors
// on_response_sent). On completion: close if the engine asked to, else go back
// to reading frames.
template <typename Loop>
void on_h2_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    const u32 kSendLen = conn.send_buf.len();
    if (ev.result < 0) {
        loop->close_conn(conn);
        return;
    }
    const u32 kResult = static_cast<u32>(ev.result);
    if (conn.send_progress > kSendLen || kResult > (kSendLen - conn.send_progress)) {
        loop->close_conn(conn);
        return;
    }
    conn.send_progress += kResult;
    if (conn.send_progress < kSendLen) {
        if (kResult == 0u) {
            loop->close_conn(conn);
            return;
        }
        const u32 kRemaining = kSendLen - conn.send_progress;
        conn.transition_to_sending(&on_h2_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data() + conn.send_progress, kRemaining);
        return;
    }

    conn.send_progress = 0;
    conn.send_buf.reset();
    if (!conn.keep_alive) {  // engine signalled GOAWAY / connection error
        loop->close_conn(conn);
        return;
    }
    // Keep serving frames on this connection.
    conn.transition_to_reading_header(&on_h2_data<Loop>);
    loop->submit_recv(conn);
}

// Recv callback for an h2 connection: feed bytes to the engine, run dispatch,
// flush control + response frames.
template <typename Loop>
void on_h2_data(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    conn.send_progress = 0;
    if (ev.result <= 0 || !conn.h2) {
        loop->close_conn(conn);
        return;
    }

    // Control frames the engine emits (SETTINGS/ACK/WINDOW_UPDATE/PING/GOAWAY).
    u8 ctrl[8192];
    // Response frames produced by the dispatch callback.
    static constexpr u32 kRespCap = 8192;
    u8 resp[kRespCap];
    H2Dispatch<Loop> d{loop, &conn, resp, kRespCap, 0, false};

    conn.h2->cb_ctx = &d;
    conn.h2->on_headers = &h2_on_headers_cb<Loop>;
    conn.h2->on_data = nullptr;  // body ignored for static routes (flow control still runs)
    conn.h2->on_reset = nullptr;
    conn.request_config = loop->config_ptr ? *loop->config_ptr : nullptr;

    u32 ctrl_len = 0;
    Http2Result r =
        conn.h2->process(conn.recv_buf.data(), conn.recv_buf.len(), ctrl, sizeof(ctrl), &ctrl_len);

    // Compact unconsumed bytes (a partial trailing frame) to the front so the
    // next recv appends after them.
    const u32 kLen = conn.recv_buf.len();
    const u32 kRemaining = kLen - r.consumed;
    if (kRemaining > 0 && r.consumed > 0)
        memmove(conn.recv_slice, conn.recv_slice + r.consumed, kRemaining);
    conn.recv_buf.reset();
    if (kRemaining > 0) conn.recv_buf.commit(kRemaining);

    const bool kClose = r.close || d.overflow;

    // No output and a partial frame that fills the whole recv buffer => the peer
    // sent a frame larger than we can buffer. Fail closed.
    if (ctrl_len == 0 && d.resp_len == 0) {
        if (kClose || conn.recv_buf.write_avail() == 0) {
            loop->close_conn(conn);
            return;
        }
        conn.transition_to_reading_header(&on_h2_data<Loop>);
        loop->submit_recv(conn);
        return;
    }

    // Combine control + response frames into the send buffer and flush.
    conn.send_buf.reset();
    conn.send_buf.write(ctrl, ctrl_len);
    conn.send_buf.write(resp, d.resp_len);
    conn.keep_alive = !kClose;  // on_h2_sent closes the connection when false
    conn.transition_to_sending(&on_h2_sent<Loop>);
    loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
}

// Switch a connection to HTTP/2 and process whatever bytes already arrived.
// Lazily allocates + initializes the engine once.
template <typename Loop>
void enter_h2(Loop* loop, Connection& conn, IoEvent ev) {
    if (!conn.h2) {
        if (!loop->alloc_h2(conn)) {
            loop->close_conn(conn);
            return;
        }
        conn.h2->cb_ctx = nullptr;
        conn.h2->on_headers = nullptr;
        conn.h2->on_data = nullptr;
        conn.h2->on_reset = nullptr;
        conn.h2->init();
    }
    conn.transition_to_reading_header(&on_h2_data<Loop>);
    on_h2_data<Loop>(static_cast<void*>(loop), conn, ev);
}

}  // namespace rut
