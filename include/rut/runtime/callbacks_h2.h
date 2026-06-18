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
    if (kN == 0 && d.resp_len != 0) {
        d.overflow = true;
    } else if (kN == 0 && d.resp_len == 0) {
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

inline void h2_clear_pending(Http2Conn& h2) {
    h2.pending_stream = 0;
    h2.pending_body_start = 0;
    h2.pending_synth_len = 0;
    h2.pending_body_len = 0;
    h2.pending_content_length = 0;
    h2.pending_has_content_length = false;
    h2.pending_buffer_body = false;
    h2.pending_overflow = false;
    h2.pending_route_config = nullptr;
    h2.pending_route = nullptr;
    h2.pending_route_action = RouteAction::Static;
    h2.pending_static_status = 200;
    h2.pending_jit_fn = nullptr;
    h2.pending_route_param_count = 0;
    for (u32 i = 0; i < kMaxRouteParams; i++) {
        h2.pending_route_params[i] = {};
    }
}

// pending_body_start points just after the synthesized CRLFCRLF; DATA bytes are
// appended there only when the matched handler actually reads req.body.
inline bool h2_finalize_synth_body(Http2Conn& h2) {
    if (h2.pending_body_start < 4 || h2.pending_body_start > h2.pending_synth_len) return false;
    return !h2.pending_has_content_length || h2.pending_content_length == h2.pending_body_len;
}

// Insert "content-length: <body_len>\r\n" immediately before the blank-line
// terminator of a synthesized HTTP/1 request, shifting any buffered body to the
// right. `body_start` points just past the "\r\n\r\n" terminator. Returns false
// (leaving the buffer untouched) if the result would exceed cap. Used to expose
// HTTP/2 DATA-only bodies (no client content-length) through the HTTP/1-shaped
// JIT body parser, which keys off content-length.
inline bool h2_inject_content_length(u8* buf, u32* len, u32 body_start, u32 body_len, u32 cap) {
    if (body_start < 4 || body_start > *len) return false;
    char digits[10];
    u32 nd = 0;
    if (body_len == 0) {
        digits[nd++] = '0';
    } else {
        char tmp[10];
        u32 t = 0;
        for (u32 v = body_len; v > 0; v /= 10) tmp[t++] = static_cast<char>('0' + (v % 10));
        while (t > 0) digits[nd++] = tmp[--t];
    }
    static const char kKey[] = "content-length: ";
    const u32 kKeyLen = 16;             // strlen("content-length: ")
    const u32 kIns = kKeyLen + nd + 2;  // header line + CRLF
    if (*len + kIns > cap) return false;
    const u32 kAt = body_start - 2;  // before the blank-line CRLF
    for (u32 i = *len; i > kAt; i--) buf[i - 1 + kIns] = buf[i - 1];
    u32 o = kAt;
    for (u32 i = 0; i < kKeyLen; i++) buf[o++] = static_cast<u8>(kKey[i]);
    for (u32 i = 0; i < nd; i++) buf[o++] = static_cast<u8>(digits[i]);
    buf[o++] = '\r';
    buf[o++] = '\n';
    *len += kIns;
    return true;
}

template <typename Loop>
bool h2_defer_until_data_end(H2Dispatch<Loop>& d,
                             u32 stream_id,
                             const hpack::Header* headers,
                             u32 nheaders,
                             const ParsedRequest& req,
                             bool buffer_body,
                             RouteAction action,
                             const RouteConfig* route_config,
                             const RouteEntry* route,
                             const RouteParam* params,
                             u32 param_count,
                             u16 static_status) {
    Http2Conn* h2 = d.conn->h2;
    if (h2->pending_stream != 0) {
        h2_emit_status(d, stream_id, 503);  // one body upload at a time
        return false;
    }
    // Only JIT handlers consume the synthesized HTTP/1 request. Static / proxy /
    // default deferrals just count DATA octets and validate Content-Length, so
    // they never serialize the header list — that avoids a spurious 400 when a
    // large-but-legal h2 header block exceeds the HTTP/1 synth cap.
    u32 synth_len = 0;
    if (action == RouteAction::JitHandler) {
        synth_len =
            h2_synth_h1_request(headers, nheaders, h2->pending_synth, Http2Conn::kBodySynthCap);
        if (synth_len == 0) {
            h2_emit_status(d, stream_id, 400);
            return false;
        }
    }
    h2->pending_body_start = synth_len;
    h2->pending_synth_len = synth_len;
    h2->pending_body_len = 0;
    h2->pending_content_length = req.content_length;
    h2->pending_has_content_length = req.has_content_length;
    h2->pending_buffer_body = buffer_body;
    h2->pending_overflow = false;
    h2->pending_route_config = route_config;
    h2->pending_route = route;
    h2->pending_route_action = action;
    h2->pending_static_status = static_status;
    h2->pending_jit_fn = route ? route->fn : nullptr;
    // Snapshot route params for the deferred handler. Only JIT handlers consume
    // params, and only they build the synthesized request; re-anchor each param
    // value into pending_synth (stable) rather than the matcher's hdr_scratch
    // source, which the next decoded header block reuses. Param values are
    // substrings of the raw :path, which h2_synth_h1_request copied verbatim into
    // pending_synth right after "METHOD ".
    u32 stored = 0;
    if (action == RouteAction::JitHandler) {
        Str method{nullptr, 0};
        Str path{nullptr, 0};
        for (u32 i = 0; i < nheaders; i++) {
            if (headers[i].name.eq(Str{":method", 7}))
                method = headers[i].value;
            else if (headers[i].name.eq(Str{":path", 5}))
                path = headers[i].value;
        }
        const u32 kCapped = param_count > kMaxRouteParams ? kMaxRouteParams : param_count;
        const u32 kPathStart = method.len + 1;  // path follows "METHOD " in synth
        for (u32 i = 0; i < kCapped; i++) {
            const RouteParam& p = params[i];
            // Defensive: a trie-matched value is always within the raw path, so
            // this skip is unreachable in practice (no silent truncation).
            if (path.ptr == nullptr || p.value < path.ptr ||
                p.value + p.value_len > path.ptr + path.len)
                continue;
            const u32 kOff = kPathStart + static_cast<u32>(p.value - path.ptr);
            h2->pending_route_params[stored++] = {
                p.name,
                p.name_len,
                reinterpret_cast<const char*>(h2->pending_synth + kOff),
                p.value_len};
        }
    }
    h2->pending_route_param_count = stored;
    h2->pending_stream = stream_id;
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
                    const RouteConfig* cfg,
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

// A deferred stream is complete. If the matched handler reads req.body,
// pending_synth holds headers plus DATA; otherwise it holds only headers and
// pending_body_len is used for Content-Length validation.
template <typename Loop>
void h2_finish_body(H2Dispatch<Loop>& d, u32 stream_id) {
    Http2Conn* h2 = d.conn->h2;
    if (h2->pending_overflow) {
        const bool kBuffered = h2->pending_buffer_body;
        h2_clear_pending(*h2);
        h2_emit_status(d, stream_id, kBuffered ? 413 : 400);
        return;
    }
    // A client-supplied Content-Length must equal the actual DATA octet count,
    // for every deferred action — not just body-reading handlers.
    if (h2->pending_has_content_length && h2->pending_content_length != h2->pending_body_len) {
        h2_clear_pending(*h2);
        h2_emit_status(d, stream_id, 400);
        return;
    }

    const RouteAction kAction = h2->pending_route_action;
    if (kAction != RouteAction::JitHandler) {
        // Static / default / proxy: respond from the decision made at HEADERS
        // time. No synthesized request was built for these.
        const u16 kStatus = (kAction == RouteAction::Proxy) ? 503 : h2->pending_static_status;
        h2_clear_pending(*h2);
        h2_emit_status(d, stream_id, kStatus);
        return;
    }

    // Body-reading handler whose client omitted Content-Length: inject the
    // observed body length so the HTTP/1-shaped parse exposes the DATA bytes.
    if (h2->pending_buffer_body && !h2->pending_has_content_length &&
        !h2_inject_content_length(h2->pending_synth,
                                  &h2->pending_synth_len,
                                  h2->pending_body_start,
                                  h2->pending_body_len,
                                  Http2Conn::kBodySynthCap)) {
        h2_clear_pending(*h2);
        h2_emit_status(d, stream_id, 413);
        return;
    }

    const u32 kLen = h2->pending_synth_len;
    const u8* synth = h2->pending_synth;
    const RouteConfig* cfg = h2->pending_route_config;
    const RouteEntry* route = h2->pending_route;
    const jit::HandlerFn kJitFn = h2->pending_jit_fn;
    const u32 kRouteParamCount = h2->pending_route_param_count;
    RouteParam route_params[kMaxRouteParams];
    for (u32 i = 0; i < kRouteParamCount; i++) {
        const H2RouteParam& p = h2->pending_route_params[i];
        route_params[i] = {p.name, p.name_len, p.value, p.value_len};
    }

    h2_clear_pending(*h2);  // clear before responding
    if (route == nullptr || kJitFn == nullptr) {
        h2_emit_status(d, stream_id, 500);
        return;
    }
    h2_invoke_emit(d, stream_id, route, route_params, kRouteParamCount, cfg, synth, kLen);
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
    if (end_stream && req.has_content_length && req.content_length != 0) {
        h2_emit_status(d, stream_id, 400);
        return;
    }

    const RouteConfig* config = d.conn->request_config;
    if (!config) {
        if (!end_stream && req.has_content_length) {
            h2_defer_until_data_end(d,
                                    stream_id,
                                    headers,
                                    nheaders,
                                    req,
                                    /*buffer_body=*/false,
                                    RouteAction::Static,
                                    /*route_config=*/nullptr,
                                    /*route=*/nullptr,
                                    /*params=*/nullptr,
                                    /*param_count=*/0,
                                    /*static_status=*/200);
            return;
        }
        h2_emit_status(d, stream_id, 200);  // route-less fallback (matches HTTP/1)
        return;
    }

    const u8 kMethodKey = route_method_key(req.method);
    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    const RouteEntry* route =
        config->match_canonical(req.path_canon, kMethodKey, params, &param_count, kMaxRouteParams);

    if (!route) {
        if (!end_stream && req.has_content_length) {
            h2_defer_until_data_end(d,
                                    stream_id,
                                    headers,
                                    nheaders,
                                    req,
                                    /*buffer_body=*/false,
                                    RouteAction::Static,
                                    config,
                                    /*route=*/nullptr,
                                    /*params=*/nullptr,
                                    /*param_count=*/0,
                                    /*static_status=*/200);
            return;
        }
        h2_emit_status(d, stream_id, 200);  // default (matches HTTP/1 catchall)
        return;
    }
    switch (route->action) {
        case RouteAction::Static:
            if (!end_stream && req.has_content_length) {
                h2_defer_until_data_end(d,
                                        stream_id,
                                        headers,
                                        nheaders,
                                        req,
                                        /*buffer_body=*/false,
                                        RouteAction::Static,
                                        config,
                                        route,
                                        params,
                                        param_count,
                                        route->status_code);
                return;
            }
            h2_emit_status(d, stream_id, route->status_code);
            return;
        case RouteAction::JitHandler: {
            if (!route->fn) {
                h2_emit_status(d, stream_id, 500);
                return;
            }
            // Defer when a body still follows: needs_req_body handlers wait to
            // read it; others wait only to consume / validate a declared
            // Content-Length. buffer_body decides whether DATA is accumulated.
            if (!end_stream && (route->needs_req_body || req.has_content_length)) {
                h2_defer_until_data_end(d,
                                        stream_id,
                                        headers,
                                        nheaders,
                                        req,
                                        /*buffer_body=*/route->needs_req_body,
                                        RouteAction::JitHandler,
                                        config,
                                        route,
                                        params,
                                        param_count,
                                        200);
                return;
            }
            // No request body to wait for — invoke now.
            u8 synth[Http2Conn::kBodySynthCap];
            const u32 kSynthLen = h2_synth_h1_request(headers, nheaders, synth, sizeof(synth));
            if (kSynthLen == 0) {
                h2_emit_status(d, stream_id, 400);
                return;
            }
            h2_invoke_emit(d, stream_id, route, params, param_count, config, synth, kSynthLen);
            return;
        }
        case RouteAction::Proxy:
        default:
            if (!end_stream && req.has_content_length) {
                h2_defer_until_data_end(d,
                                        stream_id,
                                        headers,
                                        nheaders,
                                        req,
                                        /*buffer_body=*/false,
                                        RouteAction::Proxy,
                                        config,
                                        route,
                                        params,
                                        param_count,
                                        200);
                return;
            }
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

// DATA frames for a deferred request: count every body octet, append only when
// the matched handler reads req.body, and finalize at END_STREAM. DATA for any
// other stream is ignored (flow control already ran).
template <typename Loop>
void h2_on_data_cb(
    void* ctx, Http2Conn& c, u32 stream_id, const u8* data, u32 len, bool end_stream) {
    auto* d = static_cast<H2Dispatch<Loop>*>(ctx);
    if (c.pending_stream != stream_id) return;
    if (c.pending_body_len > 0xffffffffu - len) {
        c.pending_overflow = true;
    } else {
        c.pending_body_len += len;
    }
    if (c.pending_buffer_body && c.pending_synth_len + len > Http2Conn::kBodySynthCap) {
        c.pending_overflow = true;
    } else if (c.pending_buffer_body) {
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
