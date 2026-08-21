#pragma once

// HTTP/2 serving path, shared by both backends (templated on Loop). Drives the
// per-connection Http2Conn engine: feed inbound bytes, run dispatch for each
// completed request, serialize responses as HEADERS(+DATA), and flush.
//
// Serves: static (return-status) routes, the default 200, synchronous JIT
// handlers (status + optional body/headers + request bodies), timer-yielding JIT
// handlers (wait(ms) — suspended on the async slot, resumed via the yield timer),
// and no-body proxy/JIT-forward routes (forwarded to the h1 upstream, response
// buffered and re-framed). One suspended stream per connection (others queue).
// Still 503: event-yield JIT handlers and proxy/JIT-forward outcomes carrying a
// request body. HTTP/1 is untouched: this path is only entered when
// conn.protocol == Http2 (ALPN) or the cleartext h2c preface is detected.

#include "rut/runtime/access_log.h"  // monotonic_us
#include "rut/runtime/connection.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/http_parser.h"  // http_method_str
#include "rut/runtime/jit_dispatch.h"
#include "rut/runtime/rate_limit_enforce.h"
#include "rut/runtime/route_method.h"
#include "rut/runtime/route_params.h"
#include "rut/runtime/route_table.h"

#include <string.h>  // memmove

namespace rut {

// Implemented in callbacks.cc using the HTTP/1 override helpers. The h2
// forwarding path temporarily presents its synthesized HTTP/1 request through
// Connection::recv_buf so both protocols share the same validation and rewrite
// semantics without making this standalone header depend on callbacks_impl.h.
bool h2_apply_forward_request_overrides(Connection& conn);

inline void h2_reset_request_mutations(Connection& conn) {
    conn.req_path_overridden = false;
    conn.req_path_override = {nullptr, 0};
    conn.target_transform_id = 0;
    conn.target_transform_recorded = false;
    conn.req_header_override_count = 0;
    conn.req_header_append_mask = 0;
    conn.req_header_override_overflow = false;
    conn.resp_header_mutation_pending_count = 0;
    conn.resp_header_mutation_pending_overflow = false;
    conn.resp_header_mutation_count = 0;
    conn.resp_header_mutation_overflow = false;
    if (conn.response_header_buf.valid()) conn.response_header_buf.reset();
}

inline bool h2_prepare_forward_request(
    Connection& conn, const u8* synth, u32 synth_len, u8* out, u32 out_cap, u32* out_len) {
    if (synth_len > out_cap) return false;
    __builtin_memmove(out, synth, synth_len);
    u32 header_end = 0;
    for (u32 i = 0; i + 3 < synth_len; i++) {
        if (out[i] == '\r' && out[i + 1] == '\n' && out[i + 2] == '\r' && out[i + 3] == '\n') {
            header_end = i + 4;
            break;
        }
    }
    if (header_end == 0) return false;

    u8* saved_slice = conn.recv_slice;
    Buffer saved_buf = static_cast<Buffer&&>(conn.recv_buf);
    const u32 saved_header_end = conn.req_header_end;
    const u32 saved_initial_send_len = conn.req_initial_send_len;
    conn.recv_slice = out;
    conn.recv_buf.bind(out, out_cap);
    conn.recv_buf.commit(synth_len);
    conn.req_header_end = header_end;
    conn.req_initial_send_len = synth_len;
    const bool ok = h2_apply_forward_request_overrides(conn);
    if (ok) *out_len = conn.recv_buf.len();
    conn.recv_buf = static_cast<Buffer&&>(saved_buf);
    conn.recv_slice = saved_slice;
    conn.req_header_end = saved_header_end;
    conn.req_initial_send_len = saved_initial_send_len;
    return ok;
}

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

// Mark a stream Closed once its final (END_STREAM) response has been serialized.
// http2_write_response always sets END_STREAM on the last frame, so every emitted
// response completes the stream from our side. Without this the Http2Stream stays
// in the live table forever (the serving layer writes frames directly, bypassing
// the engine's stream state), and after kMaxStreams slots have ever been used
// alloc_stream — which only reuses Closed slots — starts refusing new streams on a
// long-lived keep-alive connection even though none are active.
inline void h2_close_stream(Http2Conn* h2, u32 stream_id) {
    if (Http2Stream* s = h2->find_stream(stream_id)) {
        // We've serialized our END_STREAM response. If the peer already finished
        // its side (HalfClosedRemote), the stream is fully closed and its slot is
        // reusable. If the peer is still sending (Open) — e.g. a request without
        // END_STREAM to a route that ignores the body — move to half-closed(local):
        // keep the slot live so the engine accepts and discards the peer's trailing
        // DATA instead of mistaking the still-open remote side for a closed stream
        // and replying with a spurious RST_STREAM.
        s->state = (s->state == Http2StreamState::HalfClosedRemote)
                       ? Http2StreamState::Closed
                       : Http2StreamState::HalfClosedLocal;
    }
}

// Connection-specific (hop-by-hop) header names that MUST NOT appear in an HTTP/2
// response (RFC 7540 §8.1.2.2). validate_response_header already blocks Connection
// / Transfer-Encoding / Content-Length, but a route's response(headers:) set can
// still carry keep-alive / proxy-connection / upgrade / te — drop those on the h2
// path so a compliant client doesn't reject the response as malformed.
inline bool h2_is_prohibited_response_header(const char* name, u32 len) {
    return http_header_name_eq_ci(name, len, "connection", 10) ||
           http_header_name_eq_ci(name, len, "keep-alive", 10) ||
           http_header_name_eq_ci(name, len, "proxy-connection", 16) ||
           http_header_name_eq_ci(name, len, "transfer-encoding", 17) ||
           http_header_name_eq_ci(name, len, "upgrade", 7) ||
           http_header_name_eq_ci(name, len, "te", 2);
}

template <typename Loop>
void h2_emit_response(H2Dispatch<Loop>& d,
                      u32 stream_id,
                      u16 status,
                      const hpack::Header* hdrs,
                      u32 nhdrs,
                      const u8* body,
                      u32 body_len,
                      bool allow_fallback = true) {
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
    if (kN != 0) {
        d.conn->h2->hpack_enc = enc;
        d.resp_len += kN;
        h2_close_stream(d.conn->h2, stream_id);
        return;
    }
    // The response didn't fit. If it isn't the first frame in the batch, or the
    // caller opted out of the generic fallback (e.g. the proxy wants its own 502),
    // just flag overflow so the caller decides.
    if (d.resp_len != 0 || !allow_fallback) {
        d.overflow = true;
        return;
    }
    // First frame, fallback allowed: a tiny synthetic 500 always fits.
    enc = d.conn->h2->hpack_enc;
    const u32 kFallback = http2_write_response(
        d.resp + d.resp_len, d.resp_cap - d.resp_len, enc, stream_id, 500, nullptr, 0, nullptr, 0);
    if (kFallback == 0)
        d.overflow = true;
    else {
        d.conn->h2->hpack_enc = enc;
        d.resp_len += kFallback;
        h2_close_stream(d.conn->h2, stream_id);
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
        if (hs[i].name.eq(Str{"cookie", 6})) continue;                 // combined below
        // When :authority is present it already produced the Host line above; drop
        // a regular `host` field so the synthesized request (and any upstream we
        // proxy it to) doesn't carry two conflicting Host headers (:authority is
        // authoritative — it's what Rut routed/authorized against). RFC 7540 §8.1.2.3.
        if (authority.len > 0 && hs[i].name.eq(Str{"host", 4})) continue;
        if (!put(hs[i].name.ptr, hs[i].name.len) || !put(": ", 2) ||
            !put(hs[i].value.ptr, hs[i].value.len) || !put("\r\n", 2))
            return 0;
    }
    // HTTP/2 may split Cookie into multiple `cookie` fields (RFC 7540 §8.1.2.5).
    // Join them into one HTTP/1 `cookie:` header (RFC 6265 form) so everything
    // downstream — routing, handler parsing, cookie rate-limit keys — sees the
    // full value instead of just the first field. Emitted after the other headers
    // (a second pass) so an interleaved header can't split the cookie line.
    bool cookie_open = false;
    for (u32 i = 0; i < n; i++) {
        if (!hs[i].name.eq(Str{"cookie", 6})) continue;
        if (!put(cookie_open ? "; " : "cookie: ", cookie_open ? 2 : 8) ||
            !put(hs[i].value.ptr, hs[i].value.len))
            return 0;
        cookie_open = true;
    }
    if (cookie_open && !put("\r\n", 2)) return 0;
    if (!put("\r\n", 2)) return 0;
    return o;
}

// Route-match values point into the HPACK decoder scratch, while JIT execution
// may suspend and outlive that scratch. The synthesized h1 request contains the
// raw :path verbatim after "METHOD "; point immediate-dispatch params at that
// copy so h2_stash_synth can re-anchor them when a handler yields.
inline u32 h2_reanchor_route_params(const hpack::Header* headers,
                                    u32 nheaders,
                                    const RouteParam* params,
                                    u32 param_count,
                                    const u8* synth,
                                    RouteParam* out) {
    Str method{nullptr, 0};
    Str path{nullptr, 0};
    for (u32 i = 0; i < nheaders; i++) {
        if (headers[i].name.eq(Str{":method", 7}))
            method = headers[i].value;
        else if (headers[i].name.eq(Str{":path", 5}))
            path = headers[i].value;
    }
    const u32 kCapped = param_count > kMaxRouteParams ? kMaxRouteParams : param_count;
    const u32 kPathStart = method.len + 1;
    u32 stored = 0;
    for (u32 i = 0; i < kCapped; i++) {
        const RouteParam& p = params[i];
        if (path.ptr == nullptr || p.value < path.ptr ||
            p.value + p.value_len > path.ptr + path.len)
            continue;
        const u32 kOff = kPathStart + static_cast<u32>(p.value - path.ptr);
        out[stored++] = {
            p.name, p.name_len, reinterpret_cast<const char*>(synth + kOff), p.value_len};
    }
    return stored;
}

// Extra validation for an h2 request about to be forwarded upstream as HTTP/1.1.
// h2_headers_to_request already enforced the core pseudo-header rules, but two
// hazards are harmless for a local handler yet corrupt a *forwarded* HTTP/1.1
// request, so gate them only on the proxy path:
//   1. Missing :scheme — RFC 7540 §8.1.2.3 makes it mandatory for non-CONNECT
//      requests; h2_headers_to_request tracks but doesn't require it (CONNECT and
//      synthetic local requests legitimately omit it), so a scheme-less proxy
//      request would otherwise reach the upstream.
//   2. Missing/ambiguous Host — without a usable :authority, exactly one
//      non-empty regular `host` field is required. Otherwise the synthesized
//      HTTP/1.1 request has no Host or duplicate Host fields. (When a non-empty
//      :authority is present h2_synth_h1_request drops every regular host.)
// Returns false to reject (→ 400) before opening the upstream.
inline bool h2_proxy_request_forwardable(const hpack::Header* hs, u32 n) {
    bool have_scheme = false;
    bool have_authority = false;
    u32 host_fields = 0;
    bool have_usable_host = false;
    for (u32 i = 0; i < n; i++) {
        if (hs[i].name.eq(Str{":scheme", 7}))
            have_scheme = hs[i].value.len != 0;
        else if (hs[i].name.eq(Str{":authority", 10}))
            have_authority = hs[i].value.len != 0;
        else if (hs[i].name.len > 0 && hs[i].name.ptr[0] != ':' && hs[i].name.eq(Str{"host", 4})) {
            host_fields++;
            have_usable_host = hs[i].value.len != 0;
        }
    }
    if (!have_scheme) return false;
    if (!have_authority && (host_fields != 1 || !have_usable_host)) return false;
    return true;
}

inline void h2_clear_pending(Http2Conn& h2) {
    h2.pending_stream = 0;
    h2.pending_body_start = 0;
    h2.pending_synth_len = 0;
    h2.pending_body_len = 0;
    h2.pending_content_length = 0;
    h2.pending_has_content_length = false;
    h2.pending_buffer_body = false;
    h2.pending_request_forwardable = false;
    h2.pending_prepared_forward = false;
    h2.pending_overflow = false;
    h2.pending_route_config = nullptr;
    h2.pending_route = nullptr;
    h2.pending_route_action = RouteAction::Static;
    h2.pending_static_status = 200;
    h2.pending_forward_upstream_id = 0;
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
    // One deferred request at a time, AND none while a wait/proxy stream is
    // suspended: both reuse pending_synth, so a second would corrupt the first.
    // Also refuse while pending_synth is quarantined (a torn-down proxy episode's
    // io_uring upstream send still sources it until its CQE drains).
    if (h2->pending_stream != 0 || h2->async_stream != 0 || d.conn->h2_proxy_synth_quarantined) {
        h2_emit_status(d, stream_id, 503);
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
    h2->pending_request_forwardable =
        action == RouteAction::JitHandler && h2_proxy_request_forwardable(headers, nheaders);
    h2->pending_prepared_forward = false;
    h2->pending_overflow = false;
    h2->pending_route_config = route_config;
    h2->pending_route = route;
    h2->pending_route_action = action;
    h2->pending_static_status = static_status;
    h2->pending_forward_upstream_id = 0;
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

// A body-agnostic handler has already run and selected Forward, but the peer
// left its request stream open. Preserve the prepared request and drain/count
// DATA exactly once: a non-empty body is rejected, while an empty END_STREAM can
// still use the existing no-body proxy path without invoking the handler twice.
template <typename Loop>
bool h2_defer_prepared_forward(H2Dispatch<Loop>& d,
                               u32 stream_id,
                               const ParsedRequest& req,
                               const RouteConfig* cfg,
                               u16 upstream_id,
                               const u8* synth,
                               u32 synth_len,
                               bool replace_owned_async = false) {
    Http2Conn* h2 = d.conn->h2;
    const bool async_conflict =
        h2->async_stream != 0 && (!replace_owned_async || h2->async_stream != stream_id);
    if (h2->pending_stream != 0 || async_conflict || d.conn->h2_proxy_synth_quarantined ||
        synth_len > Http2Conn::kBodySynthCap)
        return false;
    for (u32 i = 0; i < synth_len; i++) h2->pending_synth[i] = synth[i];
    h2->pending_stream = stream_id;
    h2->pending_body_start = synth_len;
    h2->pending_synth_len = synth_len;
    h2->pending_body_len = 0;
    h2->pending_content_length = req.content_length;
    h2->pending_has_content_length = req.has_content_length;
    h2->pending_buffer_body = false;
    h2->pending_request_forwardable = true;
    h2->pending_prepared_forward = true;
    h2->pending_overflow = false;
    h2->pending_route_config = cfg;
    h2->pending_route = nullptr;
    h2->pending_route_action = RouteAction::JitHandler;
    h2->pending_static_status = 200;
    h2->pending_forward_upstream_id = upstream_id;
    h2->pending_jit_fn = nullptr;
    h2->pending_route_param_count = 0;
    return true;
}

// Serialize a handler's ReturnStatus outcome — status, plus an optional body and
// custom header set materialized from the route config — as the stream's HTTP/2
// response. Shared by the immediate and async-resume paths.
template <typename Loop>
void h2_emit_outcome(H2Dispatch<Loop>& d,
                     u32 stream_id,
                     const JitDispatchOutcome& o,
                     const RouteConfig* cfg) {
    const u8* body = nullptr;
    u32 body_len = 0;
    if (o.response_body_idx != 0 && cfg != nullptr &&
        o.response_body_idx <= cfg->response_body_count) {
        const auto& b = cfg->response_bodies[o.response_body_idx - 1];
        body = reinterpret_cast<const u8*>(b.data);
        body_len = b.len;
    }
    constexpr u32 kMaxEffectiveHeaders =
        RouteConfig::kMaxHeadersPerSet + Connection::kMaxRespHeaderMutations;
    hpack::Header hdrs[kMaxEffectiveHeaders];
    u32 nhdrs = 0;
    if (o.response_headers_idx != 0 && cfg != nullptr &&
        o.response_headers_idx <= cfg->response_header_set_count) {
        const auto& ref = cfg->response_header_sets[o.response_headers_idx - 1];
        for (u16 i = 0; i < ref.count; i++) {
            const char* kn = cfg->header_keys[ref.offset + i].data;
            const u32 kl = cfg->header_keys[ref.offset + i].len;
            // Connection-specific fields are prohibited in HTTP/2 (RFC 7540
            // §8.1.2.2) and make compliant clients treat the response as malformed.
            // validate_response_header only reserves Connection/Transfer-Encoding/
            // Content-Length, so keep-alive/proxy-connection/upgrade/te can still
            // reach here from a route's response(headers:) set — drop them.
            if (h2_is_prohibited_response_header(kn, kl)) continue;
            hdrs[nhdrs].name = {kn, kl};
            hdrs[nhdrs].value = {cfg->header_values[ref.offset + i].data,
                                 cfg->header_values[ref.offset + i].len};
            nhdrs++;
        }
    }
    if (d.conn->resp_header_mutation_overflow) {
        h2_emit_status(d, stream_id, 500);
        return;
    }
    for (u32 mi = 0; mi < d.conn->resp_header_mutation_count; mi++) {
        const auto& mutation = d.conn->resp_header_mutations[mi];
        const bool remove = mutation.mode == Connection::RespHeaderMutationMode::Remove;
        if (validate_response_header(mutation.name.ptr,
                                     mutation.name.len,
                                     remove ? "" : mutation.value.ptr,
                                     remove ? 0 : mutation.value.len) != HttpHeaderValidation::Ok) {
            h2_emit_status(d, stream_id, 500);
            return;
        }
        if (mutation.mode != Connection::RespHeaderMutationMode::Add) {
            for (u32 i = 0; i < nhdrs;) {
                if (!http_header_name_eq_ci(
                        hdrs[i].name.ptr, hdrs[i].name.len, mutation.name.ptr, mutation.name.len)) {
                    i++;
                    continue;
                }
                for (u32 move = i + 1; move < nhdrs; move++) hdrs[move - 1] = hdrs[move];
                nhdrs--;
            }
        }
        if (!remove && !h2_is_prohibited_response_header(mutation.name.ptr, mutation.name.len)) {
            if (nhdrs >= kMaxEffectiveHeaders) {
                h2_emit_status(d, stream_id, 500);
                return;
            }
            hdrs[nhdrs].name = mutation.name;
            hdrs[nhdrs].value = mutation.value;
            nhdrs++;
        }
    }
    h2_emit_response(d, stream_id, o.status_code, hdrs, nhdrs, body, body_len);
}

// An h2 stream going async (wait/proxy) must pin the RCU config epoch the same
// way the HTTP/1 request path does — otherwise a config hot-reload during the
// wait can free the RouteConfig/RouteEntry pinned in the async slot before the
// stream resumes. epoch_held is the "in epoch" marker close_conn also checks, so
// the pair stays balanced even on an abnormal close. A dedicated flag (not
// req_start_us) keeps the metrics requests_active count correct — the h2 path
// never called on_request_start, so it must not trigger the close-time
// decrement. Idempotent.
template <typename Loop>
void h2_async_epoch_enter(Loop* loop, Connection& conn) {
    if (!conn.epoch_held) {
        loop->epoch_enter();
        conn.epoch_held = true;
    }
}
template <typename Loop>
void h2_async_epoch_leave(Loop* loop, Connection& conn) {
    if (conn.epoch_held) {
        loop->epoch_leave();
        conn.epoch_held = false;
    }
}

// Release the single async-suspend slot.
inline void h2_clear_async(Http2Conn& h2) {
    h2.async_stream = 0;
    h2.async_kind = H2AsyncKind::None;
    h2.async_cfg = nullptr;
    h2.async_synth_len = 0;
    h2.async_synth_sent = 0;
    h2.async_request_body_followed = false;
    h2.async_request_stream_open = false;
    h2.async_request_forwardable = false;
    h2.async_request_has_content_length = false;
    h2.async_request_content_length = 0;
    h2.async_timer_ms = 0;
    h2.async_fn = nullptr;
    h2.async_state = 0;
    h2.async_upstream_id = 0;
    h2.async_resp_len = 0;
}

// Copy a synthesized h1 request into pending_synth (the per-connection stable
// buffer) so it survives a suspension. Clamps to the buffer; a no-op when the
// source already is pending_synth (the deferred-body path). Returns the length.
inline u32 h2_stash_synth(Http2Conn& h2, const u8* synth, u32 synth_len) {
    const u32 kN = synth_len <= Http2Conn::kBodySynthCap ? synth_len : Http2Conn::kBodySynthCap;
    if (synth != h2.pending_synth)
        for (u32 i = 0; i < kN; i++) h2.pending_synth[i] = synth[i];
    return kN;
}

// Park a timer-yielding handler's resume point on the connection's single async
// slot (the request bytes are copied into pending_synth so they survive the
// sleep). The precise yield timer is armed later by h2_arm_async_timer, after
// this batch's queued frames flush. Returns false when a stream is already
// suspended — one async wait at a time, mirroring pending_stream — so the caller
// answers 503.
template <typename Loop>
bool h2_suspend_timer(H2Dispatch<Loop>& d,
                      u32 stream_id,
                      jit::HandlerFn fn,
                      const JitDispatchOutcome& o,
                      const RouteConfig* cfg,
                      const u8* synth,
                      u32 synth_len,
                      bool request_body_followed,
                      bool request_forwardable,
                      const ParsedRequest* open_request = nullptr) {
    Http2Conn* h2 = d.conn->h2;
    // Refuse if a stream is already suspended OR a body-reading request is deferred
    // — both reuse pending_synth, so a second would corrupt the first's bytes — OR
    // while pending_synth is quarantined behind a draining io_uring upstream send.
    if (h2->async_stream != 0 || h2->pending_stream != 0 || d.conn->h2_proxy_synth_quarantined)
        return false;
    // Pin the config epoch BEFORE storing cfg/route — a backpressured flush of the
    // suspending batch could otherwise let a hot reload reclaim them while parked.
    h2_async_epoch_enter(d.loop, *d.conn);
    h2->async_synth_len = h2_stash_synth(*h2, synth, synth_len);
    // Immediate dispatch uses a stack synth. Preserve every request-backed
    // pointer retained across the yield, not just the raw request bytes.
    d.conn->reanchor_request_overrides(synth, synth_len, h2->pending_synth);
    d.conn->reanchor_response_mutations(synth, synth_len, h2->pending_synth);
    auto* ctx = d.conn->jit_ctx();
    for (u32 i = 0; i < ctx->route_param_count; i++) {
        auto& value = ctx->route_params[i].value;
        if (value == nullptr) continue;
        const auto* ptr = reinterpret_cast<const u8*>(value);
        if (ptr < synth || ptr + ctx->route_params[i].value_len > synth + synth_len) continue;
        value = reinterpret_cast<const char*>(h2->pending_synth + (ptr - synth));
    }
    h2->async_stream = stream_id;
    h2->async_kind = H2AsyncKind::Timer;
    h2->async_cfg = cfg;
    h2->async_request_body_followed = request_body_followed;
    h2->async_request_stream_open = open_request != nullptr;
    h2->async_request_forwardable = request_forwardable;
    h2->async_request_has_content_length =
        open_request != nullptr && open_request->has_content_length;
    h2->async_request_content_length = open_request != nullptr ? open_request->content_length : 0;
    h2->async_timer_ms = o.timer_ms;
    h2->async_fn = fn;
    h2->async_state = static_cast<u16>(o.next_state);
    return true;
}

// Park a proxy stream on the async slot: the synthesized h1 request is stashed in
// pending_synth to be forwarded upstream (then reused to accumulate the upstream
// response). The upstream connect is started later by h2_proxy_begin, after this
// batch flushes. Returns false when a stream is already suspended → caller 503s.
template <typename Loop>
bool h2_suspend_proxy(H2Dispatch<Loop>& d,
                      u32 stream_id,
                      const RouteConfig* cfg,
                      u16 upstream_id,
                      const u8* synth,
                      u32 synth_len) {
    Http2Conn* h2 = d.conn->h2;
    // Refuse while another stream is suspended OR a body-reading request is
    // deferred — both reuse pending_synth (see h2_suspend_timer) — OR while
    // pending_synth is quarantined behind a draining io_uring upstream send.
    if (h2->async_stream != 0 || h2->pending_stream != 0 || d.conn->h2_proxy_synth_quarantined)
        return false;
    // Pin the config epoch before storing cfg/route (see h2_suspend_timer).
    h2_async_epoch_enter(d.loop, *d.conn);
    h2->async_synth_len = h2_stash_synth(*h2, synth, synth_len);
    h2->async_stream = stream_id;
    h2->async_kind = H2AsyncKind::Proxy;
    h2->async_cfg = cfg;
    h2->async_upstream_id = upstream_id;
    h2->async_resp_len = 0;
    return true;
}

// Invoke a JIT handler given the assembled HTTP/1 request bytes (headers, plus
// body for POST), then serialize its response. A timer yield (wait(ms)) or
// forwarding outcome parks the stream for async continuation; event yields are
// not supported over h2 yet → 503.
template <typename Loop>
void h2_invoke_emit(H2Dispatch<Loop>& d,
                    u32 stream_id,
                    const RouteEntry* route,
                    const RouteParam* params,
                    u32 param_count,
                    const RouteConfig* cfg,
                    const u8* synth,
                    u32 synth_len,
                    bool request_body_followed,
                    bool request_forwardable,
                    const ParsedRequest* open_request = nullptr) {
    auto* ctx = d.conn->reset_jit_ctx();
    d.conn->resp_header_mutation_pending_count = 0;
    d.conn->resp_header_mutation_pending_overflow = false;
    d.conn->resp_header_mutation_count = 0;
    d.conn->resp_header_mutation_overflow = false;
    if (d.conn->response_header_buf.valid()) d.conn->response_header_buf.reset();
    ctx->state = 0;
    ctx->resume_event_kind = static_cast<u32>(jit::YieldKind::Timer);
    ctx->resume_event_result = 0;
    ctx->route_param_count = param_count;
    for (u32 i = 0; i < param_count; i++) ctx->route_params[i] = params[i];

    const JitDispatchOutcome kOutcome = invoke_jit_handler(
        route->fn, static_cast<void*>(d.conn), *ctx, synth, synth_len, /*arena=*/nullptr);
    if (d.conn->target_transform_recorded) {
        h2_emit_status(d, stream_id, 400);
        return;
    }
    if (kOutcome.kind == JitDispatchOutcome::Kind::Redirect) {
        // Redirect serialization is deliberately unavailable in this
        // increment. Validate the pinned table reference, then reject before
        // creating any H2 proxy/async state or upstream work.
        if (cfg == nullptr || !cfg->redirect_policy_id_is_valid(kOutcome.redirect_policy_id)) {
            h2_emit_status(d, stream_id, 400);
            return;
        }
        h2_emit_status(d, stream_id, 400);
        return;
    }
    if (kOutcome.kind == JitDispatchOutcome::Kind::TimerYield) {
        if (!h2_suspend_timer(d,
                              stream_id,
                              route->fn,
                              kOutcome,
                              cfg,
                              synth,
                              synth_len,
                              request_body_followed,
                              request_forwardable,
                              open_request))
            h2_emit_status(d, stream_id, 503);  // a stream is already suspended
        return;
    }
    if (kOutcome.kind == JitDispatchOutcome::Kind::Forward) {
        // Failure-policy serialization is not implemented in the H2 path;
        // never reinterpret a bundle as transparent forwarding.
        if (kOutcome.policy_bundle_id != 0) {
            h2_emit_status(d, stream_id, 400);
            return;
        }
        if (kOutcome.response_policy_id != 0 &&
            (cfg == nullptr || !cfg->response_policy_id_is_valid(kOutcome.response_policy_id) ||
             d.conn->resp_header_mutation_count != 0 ||
             d.conn->resp_header_mutation_pending_count != 0 ||
             d.conn->resp_header_mutation_pending_overflow ||
             d.conn->resp_header_mutation_overflow)) {
            h2_emit_status(d, stream_id, 400);
            return;
        }
        // Response serialization is not implemented yet. Never silently
        // downgrade a valid non-zero policy to transparent forwarding.
        if (kOutcome.response_policy_id != 0) {
            h2_emit_status(d, stream_id, 400);
            return;
        }
        if (kOutcome.request_policy_id != 0) {
            h2_emit_status(d, stream_id, 400);
            return;
        }
        if (request_body_followed && open_request == nullptr) {
            h2_emit_status(d, stream_id, 503);
            return;
        }
        if (!request_forwardable) {
            h2_emit_status(d, stream_id, 400);
            return;
        }
        const bool stable = d.conn->resp_header_mutation_count == 0 ||
                            (d.loop->alloc_response_header_buf(*d.conn) &&
                             d.conn->stabilize_response_mutations(synth, synth_len));
        u8 forward_synth[Http2Conn::kBodySynthCap];
        u32 forward_len = 0;
        const bool prepared =
            stable &&
            h2_prepare_forward_request(
                *d.conn, synth, synth_len, forward_synth, sizeof(forward_synth), &forward_len);
        if (!prepared) {
            h2_emit_status(d, stream_id, 500);
            return;
        }
        if (cfg == nullptr || kOutcome.upstream_id >= cfg->upstream_count) {
            h2_emit_status(d, stream_id, 503);
            return;
        }
        const bool parked = open_request != nullptr
                                ? h2_defer_prepared_forward(d,
                                                            stream_id,
                                                            *open_request,
                                                            cfg,
                                                            static_cast<u16>(kOutcome.upstream_id),
                                                            forward_synth,
                                                            forward_len)
                                : h2_suspend_proxy(d,
                                                   stream_id,
                                                   cfg,
                                                   static_cast<u16>(kOutcome.upstream_id),
                                                   forward_synth,
                                                   forward_len);
        if (!parked) h2_emit_status(d, stream_id, 503);
        return;
    }
    if (kOutcome.kind != JitDispatchOutcome::Kind::ReturnStatus) {
        h2_emit_status(d, stream_id, 503);  // forward/event-yield over h2: follow-up
        return;
    }
    h2_emit_outcome(d, stream_id, kOutcome, cfg);
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

    if (h2->pending_prepared_forward) {
        const u32 kBodyLen = h2->pending_body_len;
        const u32 kSynthLen = h2->pending_synth_len;
        const RouteConfig* cfg = h2->pending_route_config;
        const u16 kUpstreamId = h2->pending_forward_upstream_id;
        const u8* synth = h2->pending_synth;
        h2_clear_pending(*h2);
        if (kBodyLen != 0) {
            h2_emit_status(d, stream_id, 503);
            return;
        }
        if (!h2_suspend_proxy(d, stream_id, cfg, kUpstreamId, synth, kSynthLen))
            h2_emit_status(d, stream_id, 503);
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
    const bool kRequestBodyFollowed = h2->pending_body_len != 0;
    const bool kRequestForwardable = h2->pending_request_forwardable;
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
    // No rate-limit charge here: #131 pins the matched route/config at HEADERS
    // time (h2->pending_route*), so the deferred body dispatches to exactly the
    // route metered at HEADERS time — h2_dispatch_request charges body routes
    // there (a reload can't swap the route out from under the pinned dispatch).
    h2_invoke_emit(d,
                   stream_id,
                   route,
                   route_params,
                   kRouteParamCount,
                   cfg,
                   synth,
                   kLen,
                   kRequestBodyFollowed,
                   kRequestForwardable);
}

// Resolve a completed header block (END_HEADERS) to a response. end_stream is
// the HEADERS frame's flag — false means a request body (DATA frames) follows.
template <typename Loop>
void h2_dispatch_request(H2Dispatch<Loop>& d,
                         u32 stream_id,
                         const hpack::Header* headers,
                         u32 nheaders,
                         bool end_stream) {
    // A prepared Forward waiting to learn whether its open request stream is
    // actually empty owns both pending_synth and the connection mutation log.
    if (d.conn->h2->pending_prepared_forward) {
        h2_emit_status(d, stream_id, 503);
        return;
    }
    // The mutation logs are connection-owned. Clear them at every new request
    // boundary once no suspended proxy owns them; a later plain proxy stream must
    // never inherit a completed JIT stream's mutations.
    if (d.conn->h2->async_stream == 0) h2_reset_request_mutations(*d.conn);
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
    // Firewall gate — mirrors the HTTP/1 path (callbacks_impl.h checks
    // firewall_allows_peer before route matching and 403s). Without this an h2
    // client bypasses a deny/default-deny rule and can reach a protected upstream
    // via the proxy route; enforce it here for every h2 route, before dispatch.
    if (config && !config->firewall_allows_peer(d.conn->peer_addr, d.conn->peer_port)) {
        h2_emit_status(d, stream_id, 403);
        return;
    }
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

    // Enforce @rateLimit before dispatch — the same per-shard buckets as HTTP/1
    // (see rate_limit_enforce.h), so a route can't be called unmetered over h2.
    // Build an HTTP/1-shaped view so header/query/cookie key components extract
    // identically; IP and route-param keys work regardless of the synth.
    // Body-reading handlers defer dispatch to h2_finish_body (after the DATA
    // frames), but #131 pins the matched route/config at HEADERS time
    // (h2->pending_route*), so the deferred body runs against exactly this route.
    // Meter HERE for every route (including deferred-body ones) — a config reload
    // can't swap the route out from under the pinned dispatch, and finish_body
    // does not re-charge, so each request is metered exactly once.
    if (route->rate_limit.count > 0) {
        u8 rl_synth[8192];
        const u32 kRlLen = h2_synth_h1_request(headers, nheaders, rl_synth, sizeof(rl_synth));
        if (kRlLen == 0 && rate_limit_needs_req_buf(route->rate_limit)) {
            // The HTTP/1 synthesis overflowed the scratch buffer (header block too
            // large), so a header/cookie key would extract empty and collapse
            // distinct callers into one bucket — a padded request could then throttle
            // unrelated keys. Reject instead of metering an empty key. (IP/param keys
            // don't read the buffer, and query keys fall back to :path below, so they
            // are not gated here.)
            h2_emit_status(d, stream_id, 431);  // Request Header Fields Too Large
            return;
        }
        RateLimitKeyInput key_in;
        key_in.peer_addr = d.conn->peer_addr;
        key_in.req_buf = kRlLen ? rl_synth : nullptr;
        key_in.req_header_end = kRlLen;
        key_in.path = req.path.ptr;  // :path fallback for query keys on overflow
        key_in.path_len = req.path.len;
        key_in.params = params;
        key_in.param_count = param_count;
        const u32 kRouteIdx = static_cast<u32>(route - config->routes);
        if (rate_limit_exceeded(d.loop, route->rate_limit, kRouteIdx, key_in, monotonic_us())) {
            h2_emit_status(d, stream_id, 429);
            return;
        }
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
            // A declared Content-Length must be validated at END_STREAM even
            // when the handler does not read req.body. Such handlers still
            // avoid buffering DATA; requests without a declared length retain
            // the immediate body-agnostic dispatch path below.
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
            // No body dependency to wait for — invoke now.
            u8 synth[Http2Conn::kBodySynthCap];
            const u32 kSynthLen = h2_synth_h1_request(headers, nheaders, synth, sizeof(synth));
            if (kSynthLen == 0) {
                h2_emit_status(d, stream_id, 400);
                return;
            }
            RouteParam stable_params[kMaxRouteParams];
            const u32 kStableParamCount = h2_reanchor_route_params(
                headers, nheaders, params, param_count, synth, stable_params);
            h2_invoke_emit(d,
                           stream_id,
                           route,
                           stable_params,
                           kStableParamCount,
                           config,
                           synth,
                           kSynthLen,
                           !end_stream,
                           h2_proxy_request_forwardable(headers, nheaders),
                           end_stream ? nullptr : &req);
            return;
        }
        case RouteAction::Proxy:
        default:
            // Any request body (DATA frames follow) blocks proxying: we'd forward
            // the synthesized headers immediately and silently drop the body
            // (it's never tied to pending_stream). Gate on end_stream, NOT just a
            // declared content-length — an h2 POST can stream a body with no
            // content-length. Defer to drain DATA, then 503 (forwarding request
            // bodies over h2 is a follow-up); see h2_finish_body's Proxy branch.
            if (!end_stream) {
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
            // No-body proxy: park the stream and forward to the h1 upstream,
            // re-framing its response into h2 (h2_proxy_begin, after flush).
            {
                // Reject requests that would forward a malformed/ambiguous HTTP/1.1
                // request upstream (missing :scheme, duplicate Host) before opening it.
                if (!h2_proxy_request_forwardable(headers, nheaders)) {
                    h2_emit_status(d, stream_id, 400);
                    return;
                }
                u8 synth[Http2Conn::kBodySynthCap];
                const u32 kSynthLen = h2_synth_h1_request(headers, nheaders, synth, sizeof(synth));
                if (kSynthLen == 0) {
                    h2_emit_status(d, stream_id, 400);
                    return;
                }
                if (!h2_suspend_proxy(d, stream_id, config, route->upstream_id, synth, kSynthLen))
                    h2_emit_status(d, stream_id, 503);  // a stream is already suspended
            }
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

// A peer RST_STREAM. If it cancels the stream currently parked on the async slot
// (a wait/proxy that the client coalesced HEADERS + RST_STREAM for in one packet),
// abandon the parked work: clear the slot so this batch neither arms the yield
// timer nor opens the upstream nor sends a response for a stream the client already
// cancelled. The timer/upstream are armed only AFTER process() returns, so at RST
// time there is no in-flight I/O to undo; the config epoch pinned for the suspend
// is released by the post-process path once async_stream is clear.
inline void h2_on_reset_cb(void* /*ctx*/, Http2Conn& c, u32 stream_id, Http2Error /*err*/) {
    if (c.async_stream != 0 && c.async_stream == stream_id) h2_clear_async(c);
}

// Forward declaration: defined below; on_h2_data re-arms via this on send done.
template <typename Loop>
void on_h2_data(void* lp, Connection& conn, IoEvent ev);

// Transfer the parked async resume point (Http2Conn async_*) onto the Connection
// and arm the precise yield timer — atomically leaving the keepalive wheel, the
// same sequence the HTTP/1 TimerYield path uses. Done only once the suspended
// stream's batch has flushed, so conn.pending_handler_fn is never set while the
// connection is still on the keepalive wheel (which would let a keepalive tick
// resume or close it early). Returns schedule_yield_timer's verdict; false means
// the wait couldn't be scheduled faithfully → caller fails the connection.
template <typename Loop>
[[nodiscard]] bool h2_arm_async_timer(Loop* loop, Connection& conn) {
    Http2Conn* h2 = conn.h2;
    conn.pending_handler_fn = h2->async_fn;
    conn.handler_state = h2->async_state;
    conn.pending_yield_kind = jit::YieldKind::Timer;
    conn.transition_to_exec_handler_wait();
    return loop->schedule_yield_timer(conn, h2->async_timer_ms);
}

// Defined in callbacks_impl.h (needs the upstream helpers): open the upstream
// connection for a proxy-suspended stream and forward the request.
template <typename Loop>
void h2_proxy_begin(Loop* loop, Connection& conn);

// Once a suspended stream's batch has flushed, start whatever it is waiting on:
// arm the resume timer (Timer) or open the upstream connection (Proxy). Pins the
// RCU config epoch first so a hot-reload during the wait can't free the config
// pinned in the async slot (released when the stream completes).
template <typename Loop>
void h2_begin_suspended_io(Loop* loop, Connection& conn) {
    h2_async_epoch_enter(loop, conn);
    if (conn.h2->async_kind == H2AsyncKind::Proxy) {
        h2_proxy_begin<Loop>(loop, conn);
        return;
    }
    if (!h2_arm_async_timer<Loop>(loop, conn)) loop->close_conn(conn);
}

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
    // A stream is suspended (wait() or proxy): now that its batch has flushed,
    // start what it waits on — arm the resume timer, or open the upstream
    // connection — instead of reading more frames (one suspended stream at a
    // time, others queue until it resumes).
    if (conn.h2 && conn.h2->async_stream != 0) {
        h2_begin_suspended_io<Loop>(loop, conn);
        return;
    }
    // Keep serving frames on this connection.
    conn.transition_to_reading_header(&on_h2_data<Loop>);
    // A just-resumed stream may have left coalesced frames buffered (process()
    // stops consuming once a stream parks). Drain them now rather than blocking
    // on a socket read the client may never make — they were already received.
    if (conn.h2 && conn.recv_buf.len() > 0) {
        IoEvent synth{conn.id, static_cast<i32>(conn.recv_buf.len()), 0, 0, IoEventType::Recv, 0};
        on_h2_data<Loop>(static_cast<void*>(loop), conn, synth);
        return;
    }
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
    conn.h2->on_reset = &h2_on_reset_cb;      // cancels a parked stream on RST_STREAM
    // Pin the RCU config epoch BEFORE snapshotting and matching the config, so a
    // hot reload (poll_command runs once per loop iteration, after this dispatch
    // batch) can't reclaim a RouteConfig/RouteEntry that a stream parks on —
    // whether it suspends on wait/proxy or defers its body to a later DATA batch.
    // Released at the bottom of this batch when nothing stays parked; held across
    // batches otherwise (and dropped on resume or close_conn).
    h2_async_epoch_enter(loop, conn);
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

    // A handler suspended on wait() during this batch. Flush whatever queued
    // (control frames + any synchronously-completed streams' responses); the
    // resume timer is armed afterward — in on_h2_sent if there's output to send,
    // or right here if there isn't. Not entered on kClose: a closing connection
    // abandons the suspended handler rather than parking it.
    if (conn.h2->async_stream != 0 && !kClose) {
        if (ctrl_len == 0 && d.resp_len == 0) {
            h2_begin_suspended_io<Loop>(loop, conn);
            return;
        }
        conn.send_buf.reset();
        conn.send_buf.write(ctrl, ctrl_len);
        conn.send_buf.write(resp, d.resp_len);
        conn.keep_alive = true;
        conn.transition_to_sending(&on_h2_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
        return;
    }

    // Past the suspend path: no wait/proxy stream parked this batch. Release the
    // config epoch pinned at the top — unless a body-defer still holds cfg/route
    // for a later DATA batch (keep it then), or a parked stream rides a close
    // (close_conn releases it). The leave is idempotent, so a later close_conn is
    // a harmless no-op.
    if (conn.h2->async_stream == 0 && conn.h2->pending_stream == 0)
        h2_async_epoch_leave(loop, conn);

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

// Resume a timer-suspended HTTP/2 stream. Called from resume_jit_handler when the
// connection is HTTP/2 (the timer drains in both backends funnel through there).
// Re-invokes the handler from the parked request bytes; on ReturnStatus
// serializes the stream's response and flushes (after which on_h2_sent re-arms
// recv since the async slot is cleared); on another wait() re-arms without
// flushing; on Forward converts the occupied timer slot into a proxy slot and
// starts the upstream directly. Event yields over h2 are not supported yet.
template <typename Loop>
void h2_resume_jit_handler(Loop* loop, Connection& conn) {
    Http2Conn* h2 = conn.h2;
    if (h2 == nullptr || h2->async_stream == 0) {
        loop->close_conn(conn);
        return;
    }
    // schedule_yield_timer took the connection off the keepalive wheel; put it
    // back before we re-enter Sending, so a client that stops reading the
    // resumed response can't strand the connection with no timer to reap it
    // (mirrors the HTTP/1 resume_jit_handler).
    loop->timer.refresh(&conn, loop->keepalive_timeout);
    const u32 kStreamId = h2->async_stream;
    auto* ctx = conn.jit_ctx();
    ctx->state = conn.handler_state;
    ctx->resume_event_kind = static_cast<u32>(conn.resume_event_kind);
    ctx->resume_event_result = conn.resume_event_result;
    const JitDispatchOutcome kOutcome = invoke_jit_handler(conn.pending_handler_fn,
                                                           static_cast<void*>(&conn),
                                                           *ctx,
                                                           h2->pending_synth,
                                                           h2->async_synth_len,
                                                           /*arena=*/nullptr);

    if (conn.target_transform_recorded) {
        u8 resp[8192];
        H2Dispatch<Loop> d{loop, &conn, resp, sizeof(resp), 0, false};
        h2_emit_status(d, kStreamId, 400);
        conn.pending_handler_fn = nullptr;
        h2_clear_async(*h2);
        h2_async_epoch_leave(loop, conn);
        if (d.resp_len == 0 || d.overflow) {
            loop->close_conn(conn);
            return;
        }
        conn.send_progress = 0;
        conn.send_buf.reset();
        conn.send_buf.write(resp, d.resp_len);
        conn.keep_alive = true;
        conn.transition_to_sending(&on_h2_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
        return;
    }

    // Another wait(): keep the stream parked and re-arm without flushing.
    if (kOutcome.kind == JitDispatchOutcome::Kind::TimerYield) {
        h2->async_timer_ms = kOutcome.timer_ms;
        h2->async_state = static_cast<u16>(kOutcome.next_state);
        if (!h2_arm_async_timer<Loop>(loop, conn)) loop->close_conn(conn);
        return;
    }

    if (kOutcome.kind == JitDispatchOutcome::Kind::Redirect) {
        // The timer owns the async slot and config epoch. Reject the
        // foundation-only action and release both before sending status.
        u8 resp[8192];
        H2Dispatch<Loop> d{loop, &conn, resp, sizeof(resp), 0, false};
        // Resolve the pinned id even though both valid and invalid ids are
        // rejected until H2 serialization exists.
        const bool valid = h2->async_cfg != nullptr &&
                           h2->async_cfg->redirect_policy_id_is_valid(kOutcome.redirect_policy_id);
        (void)valid;
        h2_emit_status(d, kStreamId, 400);
        conn.pending_handler_fn = nullptr;
        h2_clear_async(*h2);
        h2_async_epoch_leave(loop, conn);
        if (d.resp_len == 0 || d.overflow) {
            loop->close_conn(conn);
            return;
        }
        conn.send_progress = 0;
        conn.send_buf.reset();
        conn.send_buf.write(resp, d.resp_len);
        conn.keep_alive = true;
        conn.transition_to_sending(&on_h2_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
        return;
    }

    if (kOutcome.kind == JitDispatchOutcome::Kind::Forward) {
        u16 failure_status = 0;
        if (kOutcome.policy_bundle_id != 0) failure_status = 400;
        if (kOutcome.response_policy_id != 0 &&
            (h2->async_cfg == nullptr ||
             !h2->async_cfg->response_policy_id_is_valid(kOutcome.response_policy_id) ||
             conn.resp_header_mutation_count != 0 || conn.resp_header_mutation_pending_count != 0 ||
             conn.resp_header_mutation_pending_overflow || conn.resp_header_mutation_overflow))
            failure_status = 400;
        if (failure_status == 0 && kOutcome.response_policy_id != 0) failure_status = 400;
        if (kOutcome.request_policy_id != 0) failure_status = 400;
        if (failure_status == 0 && h2->async_request_body_followed &&
            !h2->async_request_stream_open) {
            failure_status = 503;
        } else if (!h2->async_request_forwardable) {
            failure_status = 400;
        }
        if (failure_status == 0 &&
            (h2->async_cfg == nullptr || kOutcome.upstream_id >= h2->async_cfg->upstream_count)) {
            failure_status = 503;
        }

        u8 forward_synth[Http2Conn::kBodySynthCap];
        u32 forward_len = 0;
        if (failure_status == 0) {
            const bool stable =
                conn.resp_header_mutation_count == 0 ||
                (loop->alloc_response_header_buf(conn) &&
                 conn.stabilize_response_mutations(h2->pending_synth, h2->async_synth_len));
            if (!stable || !h2_prepare_forward_request(conn,
                                                       h2->pending_synth,
                                                       h2->async_synth_len,
                                                       forward_synth,
                                                       sizeof(forward_synth),
                                                       &forward_len))
                failure_status = 500;
        }

        if (failure_status == 0 && h2->async_request_stream_open) {
            ParsedRequest open_request;
            open_request.reset();
            open_request.has_content_length = h2->async_request_has_content_length;
            open_request.content_length = h2->async_request_content_length;
            u8 resp[8192];
            H2Dispatch<Loop> d{loop, &conn, resp, sizeof(resp), 0, false};
            if (!h2_defer_prepared_forward(d,
                                           kStreamId,
                                           open_request,
                                           h2->async_cfg,
                                           static_cast<u16>(kOutcome.upstream_id),
                                           forward_synth,
                                           forward_len,
                                           /*replace_owned_async=*/true)) {
                failure_status = 503;
            } else {
                conn.pending_handler_fn = nullptr;
                h2_clear_async(*h2);
                conn.transition_to_reading_header(&on_h2_data<Loop>);
                if (conn.recv_buf.len() > 0) {
                    IoEvent synth{
                        conn.id, static_cast<i32>(conn.recv_buf.len()), 0, 0, IoEventType::Recv, 0};
                    on_h2_data<Loop>(static_cast<void*>(loop), conn, synth);
                } else {
                    loop->submit_recv(conn);
                }
                return;
            }
        }

        if (failure_status == 0) {
            // The timer already owns the single async slot and its config epoch.
            // Convert it in place instead of calling h2_suspend_proxy (which
            // correctly refuses an occupied slot).
            h2->async_synth_len = h2_stash_synth(*h2, forward_synth, forward_len);
            h2->async_synth_sent = 0;
            h2->async_kind = H2AsyncKind::Proxy;
            h2->async_upstream_id = static_cast<u16>(kOutcome.upstream_id);
            h2->async_resp_len = 0;
            h2->async_timer_ms = 0;
            h2->async_fn = nullptr;
            h2->async_state = 0;
            conn.pending_handler_fn = nullptr;
            h2_proxy_begin<Loop>(loop, conn);
            return;
        }

        u8 resp[8192];
        H2Dispatch<Loop> d{loop, &conn, resp, sizeof(resp), 0, false};
        h2_emit_status(d, kStreamId, failure_status);
        conn.pending_handler_fn = nullptr;
        h2_clear_async(*h2);
        h2_async_epoch_leave(loop, conn);
        if (d.resp_len == 0 || d.overflow) {
            loop->close_conn(conn);
            return;
        }
        conn.send_progress = 0;
        conn.send_buf.reset();
        conn.send_buf.write(resp, d.resp_len);
        conn.keep_alive = true;
        conn.transition_to_sending(&on_h2_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
        return;
    }

    u8 resp[8192];
    H2Dispatch<Loop> d{loop, &conn, resp, sizeof(resp), 0, false};
    if (kOutcome.kind == JitDispatchOutcome::Kind::ReturnStatus) {
        h2_emit_outcome(d, kStreamId, kOutcome, h2->async_cfg);
    } else {
        h2_emit_status(d, kStreamId, 503);  // forward / event-yield over h2: follow-up
    }

    // Clear the suspension before responding so the flush's on_h2_sent re-arms
    // recv (async_stream == 0) rather than the timer. The async episode is over —
    // release the config epoch pinned at park time.
    conn.pending_handler_fn = nullptr;
    h2_clear_async(*h2);
    h2_async_epoch_leave(loop, conn);

    if (d.resp_len == 0 || d.overflow) {
        loop->close_conn(conn);
        return;
    }
    conn.send_progress = 0;
    conn.send_buf.reset();
    conn.send_buf.write(resp, d.resp_len);
    conn.keep_alive = true;
    conn.transition_to_sending(&on_h2_sent<Loop>);
    loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
}

}  // namespace rut
