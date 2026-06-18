#pragma once

// HTTP/2 serving path, shared by both backends (templated on Loop). Drives the
// per-connection Http2Conn engine: feed inbound bytes, run dispatch for each
// completed request, serialize responses as HEADERS(+DATA), and flush.
//
// Serves: static (return-status) routes, the default 200, and synchronous JIT
// handlers (those that return a status — with an optional body/headers — without
// yielding and without reading the request body). Proxy routes, body-reading or
// yielding JIT handlers answer 503 for now (async-over-h2 / per-stream upstream
// are follow-ups). HTTP/1 is untouched: this path is only entered when
// conn.protocol == Http2 (ALPN) or the cleartext h2c preface is detected.

#include "rut/runtime/connection.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/http_parser.h"  // http_method_str
#include "rut/runtime/jit_dispatch.h"
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

// Append a response (HEADERS + optional DATA body) for a stream, encoded with
// the connection's dynamic-indexing encoder. `hdrs[0..nhdrs)` are extra
// response headers (after :status, before content-length).
template <typename Loop>
void h2_emit_response(H2Dispatch<Loop>& d,
                      u32 stream_id,
                      u16 status,
                      const hpack::Header* hdrs,
                      u32 nhdrs,
                      const u8* body,
                      u32 body_len) {
    auto enc = d.conn->h2->hpack_enc;
    const u32 kN = http2_write_response(d.resp + d.resp_len,
                                        d.resp_cap - d.resp_len,
                                        enc,
                                        stream_id,
                                        status,
                                        hdrs,
                                        nhdrs,
                                        body,
                                        body_len);
    if (kN == 0) {
        enc = d.conn->h2->hpack_enc;
        const u32 kFallback = http2_write_response(d.resp + d.resp_len,
                                                   d.resp_cap - d.resp_len,
                                                   enc,
                                                   stream_id,
                                                   500,
                                                   nullptr,
                                                   0,
                                                   nullptr,
                                                   0);
        if (kFallback == 0)
            d.overflow = true;
        else {
            d.conn->h2->hpack_enc = enc;
            d.resp_len += kFallback;
        }
    } else {
        d.conn->h2->hpack_enc = enc;
        d.resp_len += kN;
    }
}

// Append a status-only response (HEADERS with :status, END_STREAM).
template <typename Loop>
void h2_emit_status(H2Dispatch<Loop>& d, u32 stream_id, u16 status) {
    h2_emit_response(d, stream_id, status, nullptr, 0, nullptr, 0);
}

// Synthesize a minimal HTTP/1 request from decoded h2 headers into out, so a JIT
// handler's parse-cache prime (which parses raw HTTP/1 bytes) sees the request.
// Returns the byte length, or 0 on missing pseudo-headers / overflow.
inline u32 h2_synth_h1_request(const hpack::Header* hs, u32 n, u8* out, u32 cap) {
    Str method{nullptr, 0};
    Str path{nullptr, 0};
    Str authority{nullptr, 0};
    for (u32 i = 0; i < n; i++) {
        if (hs[i].name.eq(Str{":method", 7}))
            method = hs[i].value;
        else if (hs[i].name.eq(Str{":path", 5}))
            path = hs[i].value;
        else if (hs[i].name.eq(Str{":authority", 10}))
            authority = hs[i].value;
    }
    if (method.len == 0 || path.len == 0) return 0;

    u32 o = 0;
    auto put = [&](const char* s, u32 len) -> bool {
        if (o + len > cap) return false;
        for (u32 i = 0; i < len; i++) out[o++] = static_cast<u8>(s[i]);
        return true;
    };
    if (!put(method.ptr, method.len) || !put(" ", 1) || !put(path.ptr, path.len) ||
        !put(" HTTP/1.1\r\n", 11))
        return 0;
    if (authority.len > 0 &&
        (!put("host: ", 6) || !put(authority.ptr, authority.len) || !put("\r\n", 2)))
        return 0;
    for (u32 i = 0; i < n; i++) {
        if (hs[i].name.len > 0 && hs[i].name.ptr[0] == ':') continue;  // pseudo-headers
        if (!put(hs[i].name.ptr, hs[i].name.len) || !put(": ", 2) ||
            !put(hs[i].value.ptr, hs[i].value.len) || !put("\r\n", 2))
            return 0;
    }
    if (!put("\r\n", 2)) return 0;
    return o;
}

inline u32 h2_dec_len(u32 v) {
    u32 n = 1;
    while (v >= 10) {
        v /= 10;
        n++;
    }
    return n;
}

inline void h2_write_dec(u8* out, u32 v) {
    const u32 n = h2_dec_len(v);
    for (u32 i = 0; i < n; i++) {
        out[n - 1 - i] = static_cast<u8>('0' + (v % 10));
        v /= 10;
    }
}

inline bool h2_header_name_eq(const u8* p, u32 len, const char* s) {
    u32 sl = 0;
    while (s[sl]) sl++;
    if (len != sl) return false;
    for (u32 i = 0; i < len; i++)
        if (p[i] != static_cast<u8>(s[i])) return false;
    return true;
}

// The existing JIT parser consumes an HTTP/1-shaped request and uses
// Content-Length to expose req.body. HTTP/2 DATA frames do not require a
// content-length header, so synthesize one at END_STREAM when absent and reject
// mismatches when present. pending_body_start points just after the synthesized
// CRLFCRLF; DATA bytes follow there.
inline bool h2_finalize_synth_body(Http2Conn& h2) {
    if (h2.pending_body_start < 4 || h2.pending_body_start > h2.pending_synth_len) return false;
    const u32 body_len = h2.pending_synth_len - h2.pending_body_start;
    u32 line = 0;
    while (line + 1 < h2.pending_body_start) {
        u32 end = line;
        while (end + 1 < h2.pending_body_start &&
               !(h2.pending_synth[end] == '\r' && h2.pending_synth[end + 1] == '\n'))
            end++;
        if (end == line) break;
        u32 colon = line;
        while (colon < end && h2.pending_synth[colon] != ':') colon++;
        if (colon < end &&
            h2_header_name_eq(h2.pending_synth + line, colon - line, "content-length")) {
            u32 p = colon + 1;
            while (p < end && h2.pending_synth[p] == ' ') p++;
            u32 got = 0;
            if (p == end) return false;
            while (p < end) {
                const u8 ch = h2.pending_synth[p++];
                if (ch < '0' || ch > '9') return false;
                got = got * 10 + static_cast<u32>(ch - '0');
            }
            return got == body_len;
        }
        line = end + 2;
    }

    static constexpr char kPrefix[] = "content-length: ";
    static constexpr u32 kPrefixLen = sizeof(kPrefix) - 1;
    const u32 add_len = kPrefixLen + h2_dec_len(body_len) + 2;
    if (h2.pending_synth_len + add_len > Http2Conn::kBodySynthCap) return false;
    const u32 insert = h2.pending_body_start - 2;
    for (u32 i = h2.pending_synth_len; i > insert; i--)
        h2.pending_synth[i + add_len - 1] = h2.pending_synth[i - 1];
    for (u32 i = 0; i < kPrefixLen; i++) h2.pending_synth[insert + i] = kPrefix[i];
    h2_write_dec(h2.pending_synth + insert + kPrefixLen, body_len);
    h2.pending_synth[insert + kPrefixLen + h2_dec_len(body_len)] = '\r';
    h2.pending_synth[insert + kPrefixLen + h2_dec_len(body_len) + 1] = '\n';
    h2.pending_synth_len += add_len;
    h2.pending_body_start += add_len;
    return true;
}

// Invoke a synchronous JIT handler given the assembled HTTP/1 request bytes
// (headers, plus body for POST), then serialize its response. Yielding /
// forwarding handlers are not supported over h2 yet → 503.
template <typename Loop>
void h2_invoke_emit(H2Dispatch<Loop>& d,
                    u32 stream_id,
                    const RouteEntry* route,
                    const RouteParam* params,
                    u32 param_count,
                    const u8* synth,
                    u32 synth_len) {
    auto* ctx = d.conn->reset_jit_ctx();
    ctx->state = 0;
    ctx->resume_event_kind = static_cast<u32>(jit::YieldKind::Timer);
    ctx->resume_event_result = 0;
    ctx->route_param_count = param_count;
    for (u32 i = 0; i < param_count; i++) ctx->route_params[i] = params[i];

    const JitDispatchOutcome kOutcome = invoke_jit_handler(
        route->fn, static_cast<void*>(d.conn), *ctx, synth, synth_len, /*arena=*/nullptr);
    if (kOutcome.kind != JitDispatchOutcome::Kind::ReturnStatus) {
        h2_emit_status(d, stream_id, 503);  // forward/yield over h2 not wired yet
        return;
    }
    const RouteConfig* cfg = d.conn->request_config;
    const u8* body = nullptr;
    u32 body_len = 0;
    if (kOutcome.response_body_idx != 0 && cfg != nullptr &&
        kOutcome.response_body_idx <= cfg->response_body_count) {
        const auto& b = cfg->response_bodies[kOutcome.response_body_idx - 1];
        body = reinterpret_cast<const u8*>(b.data);
        body_len = b.len;
    }
    hpack::Header hdrs[RouteConfig::kMaxHeadersPerSet];
    u32 nhdrs = 0;
    if (kOutcome.response_headers_idx != 0 && cfg != nullptr &&
        kOutcome.response_headers_idx <= cfg->response_header_set_count) {
        const auto& ref = cfg->response_header_sets[kOutcome.response_headers_idx - 1];
        for (u16 i = 0; i < ref.count; i++) {
            hdrs[nhdrs].name = {cfg->header_keys[ref.offset + i].data,
                                cfg->header_keys[ref.offset + i].len};
            hdrs[nhdrs].value = {cfg->header_values[ref.offset + i].data,
                                 cfg->header_values[ref.offset + i].len};
            nhdrs++;
        }
    }
    h2_emit_response(d, stream_id, kOutcome.status_code, hdrs, nhdrs, body, body_len);
}

// A body-reading handler has its full request (headers + accumulated body) in
// the connection's pending_synth. Re-parse it to route, then invoke + serialize.
template <typename Loop>
void h2_finish_body(H2Dispatch<Loop>& d, u32 stream_id) {
    Http2Conn* h2 = d.conn->h2;
    const bool kOverflow = h2->pending_overflow;
    const u8* synth = h2->pending_synth;
    if (kOverflow) {
        h2->pending_stream = 0;
        h2->pending_synth_len = 0;
        h2->pending_body_start = 0;
        h2->pending_overflow = false;
        h2_emit_status(d, stream_id, 413);  // body exceeded our buffer
        return;
    }
    if (!h2_finalize_synth_body(*h2)) {
        h2->pending_stream = 0;
        h2->pending_synth_len = 0;
        h2->pending_body_start = 0;
        h2->pending_overflow = false;
        h2_emit_status(d, stream_id, 400);
        return;
    }
    const u32 kLen = h2->pending_synth_len;
    h2->pending_stream = 0;  // clear before responding
    h2->pending_synth_len = 0;
    h2->pending_body_start = 0;
    h2->pending_overflow = false;
    HttpParser parser;
    parser.reset();
    ParsedRequest req;
    if (parser.parse(synth, kLen, &req) != ParseStatus::Complete) {
        h2_emit_status(d, stream_id, 400);
        return;
    }
    const RouteConfig* cfg = d.conn->request_config;
    if (!cfg) {
        h2_emit_status(d, stream_id, 200);
        return;
    }
    RouteParam params[kMaxRouteParams]{};
    u32 pc = 0;
    const RouteEntry* route = cfg->match_canonical(
        req.path_canon, route_method_key(req.method), params, &pc, kMaxRouteParams);
    if (!route || route->action != RouteAction::JitHandler || !route->fn) {
        h2_emit_status(d, stream_id, route ? 503 : 200);
        return;
    }
    h2_invoke_emit(d, stream_id, route, params, pc, synth, kLen);
}

// Resolve a completed header block (END_HEADERS) to a response. end_stream is
// the HEADERS frame's flag — false means a request body (DATA frames) follows.
template <typename Loop>
void h2_dispatch_request(H2Dispatch<Loop>& d,
                         u32 stream_id,
                         const hpack::Header* headers,
                         u32 nheaders,
                         bool end_stream) {
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
        case RouteAction::JitHandler: {
            if (!route->fn) {
                h2_emit_status(d, stream_id, 500);
                return;
            }
            u8 synth[8192];
            const u32 kSynthLen = h2_synth_h1_request(headers, nheaders, synth, sizeof(synth));
            if (kSynthLen == 0) {
                h2_emit_status(d, stream_id, 400);
                return;
            }
            if (!route->needs_req_body || end_stream) {
                // No request body to wait for — invoke now.
                h2_invoke_emit(d, stream_id, route, params, param_count, synth, kSynthLen);
                return;
            }
            // Body follows: stash the synthesized headers and accumulate DATA.
            // One body upload at a time per connection.
            Http2Conn* h2 = d.conn->h2;
            if (h2->pending_stream != 0 || kSynthLen > Http2Conn::kBodySynthCap) {
                h2_emit_status(d, stream_id, 503);
                return;
            }
            for (u32 i = 0; i < kSynthLen; i++) h2->pending_synth[i] = synth[i];
            h2->pending_body_start = kSynthLen;
            h2->pending_synth_len = kSynthLen;
            h2->pending_overflow = false;
            h2->pending_stream = stream_id;
            return;
        }
        case RouteAction::Proxy:
        default:
            // TODO(h2): proxy over HTTP/2 needs the upstream state machine
            // driven per stream. Until then, fail closed.
            h2_emit_status(d, stream_id, 503);
            return;
    }
}

template <typename Loop>
void h2_on_headers_cb(
    void* ctx, Http2Conn& /*c*/, u32 stream_id, const hpack::Header* hs, u32 n, bool end) {
    auto* d = static_cast<H2Dispatch<Loop>*>(ctx);
    h2_dispatch_request(*d, stream_id, hs, n, end);
}

// DATA frames for a body-reading request: append to pending_synth, finalize at
// END_STREAM. DATA for any other stream is ignored (flow control already ran).
template <typename Loop>
void h2_on_data_cb(
    void* ctx, Http2Conn& c, u32 stream_id, const u8* data, u32 len, bool end_stream) {
    auto* d = static_cast<H2Dispatch<Loop>*>(ctx);
    if (c.pending_stream != stream_id) return;
    if (c.pending_synth_len + len > Http2Conn::kBodySynthCap) {
        c.pending_overflow = true;
    } else {
        for (u32 i = 0; i < len; i++) c.pending_synth[c.pending_synth_len + i] = data[i];
        c.pending_synth_len += len;
    }
    if (end_stream) h2_finish_body(*d, stream_id);
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
    conn.h2->on_data = &h2_on_data_cb<Loop>;  // accumulates request bodies
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
