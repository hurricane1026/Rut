#pragma once

// HTTP/2 serving path, shared by both backends (templated on Loop). Drives the
// per-connection Http2Conn engine: feed inbound bytes, run dispatch for each
// completed request, serialize responses as HEADERS(+DATA), and flush.
//
// Serves: static (return-status) routes, the default 200, synchronous JIT
// handlers (status + optional body/headers + request bodies), timer-yielding JIT
// handlers (wait(ms) — suspended on the async slot, resumed via the yield timer),
// and no-body proxy routes (forwarded to the h1 upstream, response buffered and
// re-framed). One suspended stream per connection (others queue). Still 503:
// forwarding/event-yield JIT handlers, and proxy with a request body. HTTP/1 is
// untouched: this path is only entered when conn.protocol == Http2 (ALPN) or the
// cleartext h2c preface is detected.

#include "rut/runtime/access_log.h"  // monotonic_us
#include "rut/runtime/connection.h"
#include "rut/runtime/control_plane_snapshot.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/http_parser.h"  // http_method_str
#include "rut/runtime/jit_dispatch.h"
#include "rut/runtime/metrics.h"
#include "rut/runtime/rate_limit_enforce.h"
#include "rut/runtime/response_body_storage.h"
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

template <typename Loop>
inline void h2_mark_request_metrics_pending(H2Dispatch<Loop>& d, u32 stream_id) {
    Http2Stream* stream = d.conn->h2->find_stream(stream_id);
    if (stream == nullptr || !stream->metrics_started) return;
    stream->metrics_pending_send = true;
}

inline void h2_complete_sent_request_metrics(Http2Conn& h2) {
    for (u32 i = 0; i < h2.nstreams; i++) {
        auto& stream = h2.streams[i];
        if (!stream.metrics_started || !stream.metrics_pending_send) continue;
        if (h2.metrics != nullptr) {
            const u64 now = monotonic_us();
            const u64 elapsed = now >= stream.request_start_us ? now - stream.request_start_us : 0;
            h2.metrics->on_request_complete(elapsed > 0xffffffffu ? 0xffffffffu
                                                                  : static_cast<u32>(elapsed));
        }
        stream.metrics_started = false;
        stream.metrics_pending_send = false;
        stream.request_start_us = 0;
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
        h2_mark_request_metrics_pending(d, stream_id);
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
        h2_mark_request_metrics_pending(d, stream_id);
        h2_close_stream(d.conn->h2, stream_id);
    }
}

// Append a status-only response (HEADERS with :status, END_STREAM).
template <typename Loop>
void h2_emit_status(H2Dispatch<Loop>& d, u32 stream_id, u16 status) {
    h2_emit_response(d, stream_id, status, nullptr, 0, nullptr, 0);
}

// Append an informational HEADERS block without closing the stream. This is
// used for Expect: 100-continue before a selected buffered forward waits for
// DATA, so a client that gates its upload on the acknowledgement can proceed.
template <typename Loop>
void h2_emit_continue(H2Dispatch<Loop>& d, u32 stream_id) {
    const hpack::Header status{{":status", 7}, {"100", 3}};
    const u32 n = http2_write_headers(
        d.resp + d.resp_len, d.resp_cap - d.resp_len, stream_id, &status, 1, false);
    if (n == 0)
        d.overflow = true;
    else
        d.resp_len += n;
}

inline bool h2_expects_continue(const hpack::Header* headers, u32 nheaders) {
    for (u32 i = 0; i < nheaders; i++)
        if (headers[i].name.eq(Str{"expect", 6}) &&
            http_header_name_eq_ci(headers[i].value.ptr, headers[i].value.len, "100-continue", 12))
            return true;
    return false;
}

inline bool h2_response_status_forbids_body(u16 status) {
    return status < 200 || status == 204 || status == 205 || status == 304;
}

inline u32 h2_u32_to_dec(u32 value, char* out) {
    char reversed[10];
    u32 len = 0;
    do {
        reversed[len++] = static_cast<char>('0' + value % 10);
        value /= 10;
    } while (value != 0);
    for (u32 i = 0; i < len; i++) out[i] = reversed[len - i - 1];
    return len;
}

inline bool h2_synth_request_is_head(const u8* synth, u32 synth_len) {
    return synth != nullptr && synth_len >= 5 && synth[0] == 'H' && synth[1] == 'E' &&
           synth[2] == 'A' && synth[3] == 'D' && synth[4] == ' ';
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

// Extra validation for an h2 request about to be forwarded upstream as HTTP/1.1.
// h2_headers_to_request already enforced the core pseudo-header rules, but two
// hazards are harmless for a local handler yet corrupt a *forwarded* HTTP/1.1
// request, so gate them only on the proxy path:
//   1. Missing :scheme — RFC 7540 §8.1.2.3 makes it mandatory for non-CONNECT
//      requests; h2_headers_to_request tracks but doesn't require it (CONNECT and
//      synthetic local requests legitimately omit it), so a scheme-less proxy
//      request would otherwise reach the upstream.
//   2. Ambiguous Host — with no :authority, two regular `host` fields would
//      synthesize duplicate Host headers upstream. (When :authority is present
//      h2_synth_h1_request drops every regular host, so that case is already safe.)
// Returns false to reject (→ 400) before opening the upstream.
inline bool h2_proxy_request_forwardable(const hpack::Header* hs, u32 n) {
    bool have_scheme = false;
    bool have_authority = false;
    u32 host_fields = 0;
    for (u32 i = 0; i < n; i++) {
        if (hs[i].name.eq(Str{":scheme", 7}))
            have_scheme = true;
        else if (hs[i].name.eq(Str{":authority", 10}))
            have_authority = hs[i].value.len != 0;
        else if (hs[i].name.len > 0 && hs[i].name.ptr[0] != ':' && hs[i].name.eq(Str{"host", 4}))
            host_fields++;
    }
    if (!have_scheme) return false;
    if (!have_authority && host_fields != 1) return false;
    return true;
}

inline void h2_clear_pending(Http2Conn& h2) {
    if (h2.pending_preinvoked_forward || h2.pending_preinvoked_timer)
        rut_helper_resp_release_body_storage(static_cast<void*>(h2.async_jit_ctx()));
    h2.pending_stream = 0;
    h2.pending_body_start = 0;
    h2.pending_synth_len = 0;
    h2.pending_body_len = 0;
    h2.pending_content_length = 0;
    h2.pending_has_content_length = false;
    h2.pending_buffer_body = false;
    h2.pending_request_forwardable = false;
    h2.pending_overflow = false;
    h2.pending_preinvoked_forward = false;
    h2.pending_preinvoked_timer = false;
    h2.pending_forward_upstream_id = 0;
    h2.pending_timer_state = 0;
    h2.pending_timer_ms = 0;
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
    h2->pending_request_forwardable = h2_proxy_request_forwardable(headers, nheaders);
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
    if (h2_expects_continue(headers, nheaders)) h2_emit_continue(d, stream_id);
    return true;
}

// Serialize a handler's ReturnStatus outcome — status, plus an optional body and
// custom header set materialized from the route config — as the stream's HTTP/2
// response. Shared by the immediate and async-resume paths.
template <typename Loop>
void h2_emit_outcome(H2Dispatch<Loop>& d,
                     u32 stream_id,
                     const JitDispatchOutcome& o,
                     const RouteConfig* cfg,
                     bool head_request) {
    jit::ScopedResponseBodyMutationStorageRelease release_body_storage(o.response_ctx);
    const u8* body = nullptr;
    u32 body_len = 0;
    if (o.dynamic_response_body != nullptr) {
        body = reinterpret_cast<const u8*>(o.dynamic_response_body);
        body_len = o.dynamic_response_body_len;
    } else if (o.response_body_idx != 0 && cfg != nullptr &&
               o.response_body_idx <= cfg->response_body_count) {
        const auto& b = cfg->response_bodies[o.response_body_idx - 1];
        body = reinterpret_cast<const u8*>(b.data);
        body_len = b.len;
    }
    constexpr u32 kMaxEffectiveHeaders = RouteConfig::kMaxHeadersPerSet +
                                         jit::kMaxCapturedResponseHeaders +
                                         jit::kMaxResponseHeaderMutations + 2;
    hpack::Header hdrs[kMaxEffectiveHeaders];
    // Header values are non-owning Str views and are encoded only after the
    // list is complete, so storage synthesized below must span the emit call.
    char content_length[10];
    u32 nhdrs = 0;
    if (o.uses_captured_response && o.response_ctx != nullptr &&
        o.response_ctx->captured_response_valid) {
        for (u32 i = 0; i < o.response_ctx->captured_response_header_count; i++) {
            const auto& header = o.response_ctx->captured_response_headers[i];
            if ((o.status_code < 200 || o.status_code == 204) &&
                http_header_name_eq_ci(
                    header.name.ptr, header.name.len, "content-length", 14))
                continue;
            if (h2_is_prohibited_response_header(header.name.ptr, header.name.len)) continue;
            hdrs[nhdrs].name = header.name;
            hdrs[nhdrs].value = header.value;
            nhdrs++;
        }
    }
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
    if (o.response_ctx != nullptr && o.response_ctx->response_header_overflow) {
        h2_emit_status(d, stream_id, 500);
        return;
    }
    const u32 mutation_count =
        o.response_ctx != nullptr ? o.response_ctx->response_header_count : 0;
    for (u32 mi = 0; mi < mutation_count; mi++) {
        const auto& mutation = o.response_ctx->response_header_mutations[mi];
        const bool remove = mutation.mode == jit::ResponseHeaderMutationMode::Remove;
        if (validate_response_header(mutation.name.ptr,
                                     mutation.name.len,
                                     remove ? "" : mutation.value.ptr,
                                     remove ? 0 : mutation.value.len) != HttpHeaderValidation::Ok) {
            h2_emit_status(d, stream_id, 500);
            return;
        }
        if (mutation.mode != jit::ResponseHeaderMutationMode::Add) {
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
    const bool status_forbids_body = h2_response_status_forbids_body(o.status_code);
    if (o.dynamic_response_body != nullptr && !status_forbids_body) {
        bool has_content_type = false;
        for (u32 i = 0; i < nhdrs; i++) {
            if (http_header_name_eq_ci(hdrs[i].name.ptr, hdrs[i].name.len, "content-type", 12)) {
                has_content_type = true;
                break;
            }
        }
        if (!has_content_type) {
            hdrs[nhdrs].name = {"content-type", 12};
            hdrs[nhdrs].value = {"text/plain; charset=utf-8", 25};
            nhdrs++;
        }
    }
    // HEAD suppresses DATA while retaining the representation metadata that the
    // equivalent GET would emit. http2_write_response normally derives
    // content-length from body_len, so preserve it explicitly before clearing
    // the payload passed to the writer.
    if (head_request && body_len != 0 && !status_forbids_body) {
        const u32 content_length_len = h2_u32_to_dec(body_len, content_length);
        hdrs[nhdrs].name = {"content-length", 14};
        hdrs[nhdrs].value = {content_length, content_length_len};
        nhdrs++;
    }
    // Informational, 204, 205, and 304 responses never carry a message body.
    if (head_request || status_forbids_body) {
        body = nullptr;
        body_len = 0;
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
    if (h2.async_stream != 0 && (h2.async_kind == H2AsyncKind::Timer ||
                                 h2.async_apply_response_mutations || h2.async_capture_response))
        rut_helper_resp_release_body_storage(static_cast<void*>(h2.async_jit_ctx()));
    h2.async_stream = 0;
    h2.async_kind = H2AsyncKind::None;
    h2.async_cfg = nullptr;
    h2.async_synth_len = 0;
    h2.async_body_start = 0;
    h2.async_body_len = 0;
    h2.async_inject_content_length_on_forward = false;
    h2.async_wait_for_body_on_forward = false;
    h2.async_timer_ms = 0;
    h2.async_fn = nullptr;
    h2.async_state = 0;
    h2.async_route = nullptr;
    h2.async_upstream_id = 0;
    h2.async_apply_response_mutations = false;
    h2.async_request_forwardable = false;
    h2.async_capture_response = false;
    h2.async_resp_len = 0;
}

// A HEADERS-time timer resumed into ForwardBuffered while the request stream is
// still open. Move the stable request bytes and parked HandlerCtx into the
// pending-body episode; setting async_stream to zero before clearing prevents
// the old Timer owner from releasing the context's mutation storage.
inline void h2_transfer_timer_to_pending_forward(Http2Conn& h2, u32 stream_id, u16 upstream_id) {
    h2.pending_stream = stream_id;
    h2.pending_body_start = h2.async_body_start;
    h2.pending_synth_len = h2.async_synth_len;
    h2.pending_body_len = 0;
    h2.pending_content_length = 0;
    h2.pending_has_content_length = false;
    h2.pending_buffer_body = true;
    h2.pending_request_forwardable = true;
    h2.pending_overflow = false;
    h2.pending_preinvoked_forward = true;
    h2.pending_preinvoked_timer = false;
    h2.pending_forward_upstream_id = upstream_id;
    h2.pending_route_config = h2.async_cfg;
    h2.pending_route = h2.async_route;
    h2.pending_route_action = RouteAction::JitHandler;
    h2.pending_jit_fn = h2.async_fn;
    h2.pending_route_param_count = 0;

    h2.async_stream = 0;
    h2_clear_async(h2);
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

inline void h2_rebase_synth_view(Str& view,
                                 const u8* old_synth,
                                 const u8* new_synth,
                                 u32 synth_len) {
    if (view.ptr == nullptr || old_synth == new_synth) return;
    const auto kOld = reinterpret_cast<uintptr_t>(old_synth);
    const auto kPtr = reinterpret_cast<uintptr_t>(view.ptr);
    if (kPtr < kOld || kPtr - kOld > synth_len || view.len > synth_len - (kPtr - kOld)) return;
    view.ptr = reinterpret_cast<const char*>(new_synth + (kPtr - kOld));
}

inline bool h2_snapshot_async_jit_ctx(Http2Conn& h2,
                                      jit::HandlerCtx& live,
                                      const u8* old_synth,
                                      u32 synth_len) {
    if (live.slot_count > kMaxJitHandlerSlots ||
        live.response_header_pending_count > jit::kMaxResponseHeaderMutations ||
        live.route_param_count > kMaxRouteParams)
        return false;
    const size_t kBytes = sizeof(jit::HandlerCtx) + static_cast<size_t>(live.slot_count) * 8;
    auto* parked = h2.async_jit_ctx();
    __builtin_memcpy(parked, &live, kBytes);

    // The parked frame now owns the lazily allocated mutation buffer. Clear the
    // connection scratch copy so another H2 stream can reset it without freeing
    // bytes still needed by this suspended stream.
    live.response_body_mutation_storage = nullptr;
    live.response_body_snapshot_storage = nullptr;

    const u32 kMutationCount = parked->response_header_pending_count;
    for (u32 i = 0; i < kMutationCount; i++) {
        h2_rebase_synth_view(
            parked->response_header_mutations[i].name, old_synth, h2.pending_synth, synth_len);
        h2_rebase_synth_view(
            parked->response_header_mutations[i].value, old_synth, h2.pending_synth, synth_len);
    }
    const u32 kParamCount = parked->route_param_count;
    for (u32 i = 0; i < kParamCount; i++) {
        Str value{parked->route_params[i].value, parked->route_params[i].value_len};
        h2_rebase_synth_view(value, old_synth, h2.pending_synth, synth_len);
        parked->route_params[i].value = value.ptr;
    }
    return true;
}

inline bool h2_reanchor_route_params(const RouteParam* params,
                                     u32 param_count,
                                     Str raw_path,
                                     const u8* synth,
                                     u32 synth_len,
                                     RouteParam* anchored) {
    if (param_count > kMaxRouteParams || (param_count != 0 && raw_path.ptr == nullptr))
        return false;
    u32 path_start = 0;
    while (path_start < synth_len && synth[path_start] != ' ') path_start++;
    if (path_start == synth_len) return false;
    path_start++;
    if (raw_path.len > synth_len - path_start) return false;

    const auto kPath = reinterpret_cast<uintptr_t>(raw_path.ptr);
    for (u32 i = 0; i < param_count; i++) {
        const auto kValue = reinterpret_cast<uintptr_t>(params[i].value);
        if (kValue < kPath || kValue - kPath > raw_path.len ||
            params[i].value_len > raw_path.len - (kValue - kPath))
            return false;
        anchored[i] = params[i];
        anchored[i].value = reinterpret_cast<const char*>(synth + path_start + (kValue - kPath));
    }
    return true;
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
                      jit::HandlerCtx& live_ctx,
                      const JitDispatchOutcome& o,
                      const RouteConfig* cfg,
                      const u8* synth,
                      u32 synth_len,
                      bool request_forwardable,
                      u32 body_start,
                      u32 body_len,
                      bool inject_content_length_on_forward,
                      bool ctx_already_parked = false) {
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
    h2->async_body_start = body_start;
    h2->async_body_len = body_len;
    h2->async_inject_content_length_on_forward = inject_content_length_on_forward;
    if (!ctx_already_parked &&
        !h2_snapshot_async_jit_ctx(*h2, live_ctx, synth, h2->async_synth_len)) {
        h2_async_epoch_leave(d.loop, *d.conn);
        return false;
    }
    h2->async_stream = stream_id;
    h2->async_kind = H2AsyncKind::Timer;
    h2->async_cfg = cfg;
    h2->async_timer_ms = o.timer_ms;
    h2->async_fn = fn;
    h2->async_state = static_cast<u16>(o.next_state);
    h2->async_request_forwardable = request_forwardable;
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
                      const RouteEntry* route,
                      u16 upstream_id,
                      bool apply_response_mutations,
                      bool capture_response,
                      jit::HandlerCtx* live_ctx,
                      const u8* synth,
                      u32 synth_len,
                      bool ctx_already_parked = false) {
    Http2Conn* h2 = d.conn->h2;
    // Refuse while another stream is suspended OR a body-reading request is
    // deferred — both reuse pending_synth (see h2_suspend_timer) — OR while
    // pending_synth is quarantined behind a draining io_uring upstream send.
    if (h2->async_stream != 0 || h2->pending_stream != 0 || d.conn->h2_proxy_synth_quarantined)
        return false;
    // Pin the config epoch before storing cfg/route (see h2_suspend_timer).
    h2_async_epoch_enter(d.loop, *d.conn);
    h2->async_synth_len = h2_stash_synth(*h2, synth, synth_len);
    if ((apply_response_mutations || capture_response) && !ctx_already_parked &&
        (live_ctx == nullptr ||
         !h2_snapshot_async_jit_ctx(*h2, *live_ctx, synth, h2->async_synth_len))) {
        h2_async_epoch_leave(d.loop, *d.conn);
        return false;
    }
    h2->async_stream = stream_id;
    h2->async_kind = H2AsyncKind::Proxy;
    h2->async_cfg = cfg;
    h2->async_route = route;
    h2->async_upstream_id = upstream_id;
    h2->async_apply_response_mutations = apply_response_mutations;
    h2->async_capture_response = capture_response;
    h2->async_resp_len = 0;
    return true;
}

// Invoke a JIT handler given the assembled HTTP/1 request bytes (headers, plus
// body for POST), then serialize its response. A timer yield (wait(ms)) parks the
// stream for async resume; forwarding / event-yield handlers are not supported
// over h2 yet → 503.
template <typename Loop>
void h2_invoke_emit(H2Dispatch<Loop>& d,
                    u32 stream_id,
                    const RouteEntry* route,
                    const RouteParam* params,
                    u32 param_count,
                    const RouteConfig* cfg,
                    const u8* synth,
                    u32 synth_len,
                    bool request_forwardable,
                    u32 body_start = 0,
                    u32 body_len = 0,
                    bool inject_content_length_on_forward = false) {
    auto* ctx = d.conn->reset_jit_ctx();
    if (route->needs_control_plane_snapshot) latch_control_plane_snapshot(d.loop, ctx);
    ctx->state = 0;
    ctx->resume_event_kind = static_cast<u32>(jit::YieldKind::Timer);
    ctx->resume_event_result = 0;
    ctx->route_param_count = param_count;
    for (u32 i = 0; i < param_count; i++) ctx->route_params[i] = params[i];

    const JitDispatchOutcome kOutcome = invoke_jit_handler(
        route->fn, static_cast<void*>(d.conn), *ctx, synth, synth_len, /*arena=*/nullptr);
    if (kOutcome.kind == JitDispatchOutcome::Kind::TimerYield) {
        if (!h2_suspend_timer(d,
                              stream_id,
                              route->fn,
                              *ctx,
                              kOutcome,
                              cfg,
                              synth,
                              synth_len,
                              request_forwardable,
                              body_start,
                              body_len,
                              inject_content_length_on_forward)) {
            jit::release_response_body_mutation_storage(ctx);
            h2_emit_status(d, stream_id, 503);  // a stream is already suspended
        }
        return;
    }
    if (kOutcome.kind == JitDispatchOutcome::Kind::ForwardBuffered ||
        kOutcome.kind == JitDispatchOutcome::Kind::ForwardCapture) {
        if (!request_forwardable) {
            jit::release_response_body_mutation_storage(ctx);
            h2_emit_status(d, stream_id, 400);
            return;
        }
        const bool capture = kOutcome.kind == JitDispatchOutcome::Kind::ForwardCapture;
        u32 forward_len = synth_len;
        if (inject_content_length_on_forward &&
            !h2_inject_content_length(const_cast<u8*>(synth),
                                      &forward_len,
                                      body_start,
                                      body_len,
                                      Http2Conn::kBodySynthCap)) {
            jit::release_response_body_mutation_storage(ctx);
            h2_emit_status(d, stream_id, 413);
            return;
        }
        if (!h2_suspend_proxy(d,
                              stream_id,
                              cfg,
                              route,
                              kOutcome.upstream_id,
                              !capture,
                              capture,
                              ctx,
                              synth,
                              forward_len)) {
            jit::release_response_body_mutation_storage(ctx);
            h2_emit_status(d, stream_id, 503);
        } else if (capture) {
            d.conn->h2->async_fn = route->fn;
            d.conn->h2->async_state = kOutcome.next_state;
        }
        return;
    }
    if (kOutcome.kind != JitDispatchOutcome::Kind::ReturnStatus) {
        jit::release_response_body_mutation_storage(ctx);
        h2_emit_status(d, stream_id, 503);  // forward/event-yield over h2: follow-up
        return;
    }
    h2_emit_outcome(d, stream_id, kOutcome, cfg, h2_synth_request_is_head(synth, synth_len));
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

    if (h2->pending_preinvoked_forward || h2->pending_preinvoked_timer) {
        const RouteConfig* cfg = h2->pending_route_config;
        const RouteEntry* route = h2->pending_route;
        const u16 upstream_id = h2->pending_forward_upstream_id;
        const bool preinvoked_timer = h2->pending_preinvoked_timer;
        if (route == nullptr || (!preinvoked_timer && !h2->pending_request_forwardable)) {
            const u16 status = route == nullptr ? 500 : 400;
            h2_clear_pending(*h2);
            h2_emit_status(d, stream_id, status);
            return;
        }
        if (!preinvoked_timer && !h2->pending_has_content_length &&
            !h2_inject_content_length(h2->pending_synth,
                                      &h2->pending_synth_len,
                                      h2->pending_body_start,
                                      h2->pending_body_len,
                                      Http2Conn::kBodySynthCap)) {
            h2_clear_pending(*h2);
            h2_emit_status(d, stream_id, 413);
            return;
        }
        const u32 synth_len = h2->pending_synth_len;
        const u32 body_start = h2->pending_body_start;
        const u32 body_len = h2->pending_body_len;
        const bool request_forwardable = h2->pending_request_forwardable;
        const bool inject_content_length_on_forward = !h2->pending_has_content_length;
        h2->pending_stream = 0;  // transfer the shared synth/context to async
        bool suspended = false;
        if (preinvoked_timer) {
            JitDispatchOutcome outcome{};
            outcome.kind = JitDispatchOutcome::Kind::TimerYield;
            outcome.next_state = h2->pending_timer_state;
            outcome.timer_ms = h2->pending_timer_ms;
            suspended = h2_suspend_timer(d,
                                         stream_id,
                                         route->fn,
                                         *h2->async_jit_ctx(),
                                         outcome,
                                         cfg,
                                         h2->pending_synth,
                                         synth_len,
                                         request_forwardable,
                                         body_start,
                                         body_len,
                                         inject_content_length_on_forward,
                                         /*ctx_already_parked=*/true);
        } else {
            suspended = h2_suspend_proxy(d,
                                         stream_id,
                                         cfg,
                                         route,
                                         upstream_id,
                                         true,
                                         h2->async_jit_ctx(),
                                         h2->pending_synth,
                                         synth_len,
                                         /*ctx_already_parked=*/true);
        }
        if (!suspended) {
            h2_clear_pending(*h2);
            h2_emit_status(d, stream_id, 503);
            return;
        }
        h2->pending_preinvoked_forward = false;  // ownership moved to async
        h2->pending_preinvoked_timer = false;
        h2_clear_pending(*h2);
        return;
    }

    const RouteEntry* pending_route = h2->pending_route;
    const bool inject_for_handler = h2->pending_buffer_body && !h2->pending_has_content_length &&
                                    pending_route != nullptr && pending_route->needs_req_body;
    // A body-reading handler still needs the derived length for the HTTP/1-
    // shaped body parser. A route that only may buffered-forward must observe
    // the original header set; its derived length is injected after that
    // outcome is selected below.
    if (inject_for_handler && !h2_inject_content_length(h2->pending_synth,
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
    const u32 kBodyStart = h2->pending_body_start;
    const u32 kBodyLen = h2->pending_body_len;
    const bool kInjectContentLengthOnForward =
        h2->pending_buffer_body && !h2->pending_has_content_length && !inject_for_handler;
    const RouteConfig* cfg = h2->pending_route_config;
    const RouteEntry* route = pending_route;
    const jit::HandlerFn kJitFn = h2->pending_jit_fn;
    const u32 kRouteParamCount = h2->pending_route_param_count;
    const bool kRequestForwardable = h2->pending_request_forwardable;
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
                   kRequestForwardable,
                   kBodyStart,
                   kBodyLen,
                   kInjectContentLengthOnForward);
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
            // A route may contain a buffered-forward terminator without reading
            // req.body. Run it from the HEADERS view first: local responses and
            // waits must not inherit the 16 KiB forwarding-body cap merely
            // because some other branch can forward. Only the selected buffered
            // forward parks and accumulates DATA. Preserve its already-produced
            // mutation context so the handler is not invoked a second time.
            if (!end_stream && !req.has_content_length && !route->needs_req_body &&
                route->can_forward_buffered) {
                Http2Conn* h2 = d.conn->h2;
                if (h2->pending_stream != 0 || h2->async_stream != 0 ||
                    d.conn->h2_proxy_synth_quarantined) {
                    h2_emit_status(d, stream_id, 503);
                    return;
                }
                u8 synth[Http2Conn::kBodySynthCap];
                const u32 kSynthLen = h2_synth_h1_request(headers, nheaders, synth, sizeof(synth));
                if (kSynthLen == 0) {
                    h2_emit_status(d, stream_id, 400);
                    return;
                }
                RouteParam anchored_params[kMaxRouteParams];
                if (!h2_reanchor_route_params(
                        params, param_count, req.path, synth, kSynthLen, anchored_params)) {
                    h2_emit_status(d, stream_id, 500);
                    return;
                }
                auto* ctx = d.conn->reset_jit_ctx();
                ctx->state = 0;
                ctx->resume_event_kind = static_cast<u32>(jit::YieldKind::Timer);
                ctx->resume_event_result = 0;
                ctx->route_param_count = param_count;
                for (u32 i = 0; i < param_count; i++) ctx->route_params[i] = anchored_params[i];
                const JitDispatchOutcome kOutcome = invoke_jit_handler(
                    route->fn, static_cast<void*>(d.conn), *ctx, synth, kSynthLen, nullptr);

                if (kOutcome.kind == JitDispatchOutcome::Kind::ForwardBuffered) {
                    if (!h2_proxy_request_forwardable(headers, nheaders)) {
                        jit::release_response_body_mutation_storage(ctx);
                        h2_emit_status(d, stream_id, 400);
                        return;
                    }
                    if (!h2_defer_until_data_end(d,
                                                 stream_id,
                                                 headers,
                                                 nheaders,
                                                 req,
                                                 /*buffer_body=*/true,
                                                 RouteAction::JitHandler,
                                                 config,
                                                 route,
                                                 params,
                                                 param_count,
                                                 200)) {
                        jit::release_response_body_mutation_storage(ctx);
                        return;
                    }
                    if (!h2_snapshot_async_jit_ctx(*h2, *ctx, synth, kSynthLen)) {
                        h2_clear_pending(*h2);
                        jit::release_response_body_mutation_storage(ctx);
                        h2_emit_status(d, stream_id, 500);
                        return;
                    }
                    h2->pending_preinvoked_forward = true;
                    h2->pending_forward_upstream_id = kOutcome.upstream_id;
                    return;
                }
                if (kOutcome.kind == JitDispatchOutcome::Kind::TimerYield) {
                    if (!h2_suspend_timer(d,
                                          stream_id,
                                          route->fn,
                                          *ctx,
                                          kOutcome,
                                          config,
                                          synth,
                                          kSynthLen,
                                          h2_proxy_request_forwardable(headers, nheaders),
                                          kSynthLen,
                                          0,
                                          true)) {
                        jit::release_response_body_mutation_storage(ctx);
                        h2_emit_status(d, stream_id, 503);
                        return;
                    }
                    h2->async_route = route;
                    h2->async_wait_for_body_on_forward = true;
                    if (h2_expects_continue(headers, nheaders)) h2_emit_continue(d, stream_id);
                    return;
                }
                if (kOutcome.kind == JitDispatchOutcome::Kind::ReturnStatus) {
                    h2_emit_outcome(
                        d, stream_id, kOutcome, config, h2_synth_request_is_head(synth, kSynthLen));
                    return;
                }
                jit::release_response_body_mutation_storage(ctx);
                h2_emit_status(d, stream_id, 503);
                return;
            }
            // Routes that inspect the body or may buffered-forward need the
            // DATA bytes themselves. A declared length also defers dispatch so
            // framing can be validated, while ordinary body-ignoring handlers
            // remain able to respond immediately to open-ended uploads.
            if (!end_stream &&
                (route->needs_req_body || route->can_forward_buffered || req.has_content_length)) {
                h2_defer_until_data_end(
                    d,
                    stream_id,
                    headers,
                    nheaders,
                    req,
                    /*buffer_body=*/route->needs_req_body || route->can_forward_buffered,
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
            RouteParam anchored_params[kMaxRouteParams];
            if (!h2_reanchor_route_params(
                    params, param_count, req.path, synth, kSynthLen, anchored_params)) {
                h2_emit_status(d, stream_id, 500);
                return;
            }
            h2_invoke_emit(d,
                           stream_id,
                           route,
                           anchored_params,
                           param_count,
                           config,
                           synth,
                           kSynthLen,
                           h2_proxy_request_forwardable(headers, nheaders));
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
                if (!h2_suspend_proxy(d,
                                      stream_id,
                                      config,
                                      route,
                                      route->upstream_id,
                                      false,
                                      false,
                                      nullptr,
                                      synth,
                                      kSynthLen))
                    h2_emit_status(d, stream_id, 503);  // a stream is already suspended
            }
            return;
    }
}

template <typename Loop>
void h2_on_headers_cb(
    void* ctx, Http2Conn& c, u32 stream_id, const hpack::Header* hs, u32 n, bool end) {
    auto* d = static_cast<H2Dispatch<Loop>*>(ctx);
    if constexpr (requires { d->loop->metrics; }) c.metrics = d->loop->metrics;
    if (Http2Stream* stream = c.find_stream(stream_id);
        stream != nullptr && !stream->metrics_started && c.metrics != nullptr) {
        stream->metrics_started = true;
        stream->request_start_us = monotonic_us();
        c.metrics->on_request_start();
    }
    h2_dispatch_request(*d, stream_id, hs, n, end);
}

// DATA frames for a deferred request: count every body octet and append when the
// matched JIT route may need to expose or forward it, then finalize at END_STREAM.
// DATA for any other stream is ignored (flow control already ran).
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
    Http2Stream* reset_stream = nullptr;
    for (u32 i = 0; i < c.nstreams; i++) {
        if (c.streams[i].id == stream_id) {
            reset_stream = &c.streams[i];
            break;
        }
    }
    if (reset_stream != nullptr && reset_stream->metrics_started) {
        if (c.metrics != nullptr) c.metrics->on_request_cancel();
        reset_stream->metrics_started = false;
        reset_stream->metrics_pending_send = false;
        reset_stream->request_start_us = 0;
    }
    if (c.async_stream != 0 && c.async_stream == stream_id) h2_clear_async(c);
    if (c.pending_stream != 0 && c.pending_stream == stream_id) h2_clear_pending(c);
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
    auto* parked_ctx = h2->async_jit_ctx();
    // Other streams in the same decoded batch may have reused the connection
    // scratch context after this stream was parked. Release any lazy body
    // buffer they acquired before replacing the scratch owner with the parked
    // frame; otherwise that allocation becomes unreachable.
    if (conn.handler_ctx != nullptr && conn.handler_ctx != parked_ctx)
        rut_helper_resp_release_body_storage(conn.handler_ctx);
    conn.pending_handler_fn = h2->async_fn;
    conn.handler_state = h2->async_state;
    conn.handler_ctx = parked_ctx;
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
        if (conn.h2->async_apply_response_mutations || conn.h2->async_capture_response)
            conn.handler_ctx = conn.h2->async_jit_ctx();
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
    if (conn.h2) h2_complete_sent_request_metrics(*conn.h2);
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
// flushing; forward / event-yield over h2 are not supported yet → 503.
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
    const bool kHeadRequest = h2_synth_request_is_head(h2->pending_synth, h2->async_synth_len);
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

    // Another wait(): keep the stream parked and re-arm without flushing.
    if (kOutcome.kind == JitDispatchOutcome::Kind::TimerYield) {
        h2->async_timer_ms = kOutcome.timer_ms;
        h2->async_state = static_cast<u16>(kOutcome.next_state);
        if (!h2_arm_async_timer<Loop>(loop, conn)) loop->close_conn(conn);
        return;
    }
    if (kOutcome.kind == JitDispatchOutcome::Kind::ForwardBuffered &&
        h2->async_request_forwardable && h2->async_wait_for_body_on_forward) {
        // This timer began at HEADERS time while the peer side remained open.
        // Only now that the resumed branch actually selected buffered forwarding
        // do we collect DATA and apply the forwarding cap. Transfer ownership of
        // the parked mutation context to the pending-body episode without
        // releasing it; h2_finish_body will move it into the proxy episode.
        conn.pending_handler_fn = nullptr;
        conn.handler_ctx = nullptr;
        h2_transfer_timer_to_pending_forward(*h2, kStreamId, kOutcome.upstream_id);
        conn.transition_to_reading_header(&on_h2_data<Loop>);
        loop->submit_recv(conn);
        return;
    }
    if ((kOutcome.kind == JitDispatchOutcome::Kind::ForwardBuffered ||
         kOutcome.kind == JitDispatchOutcome::Kind::ForwardCapture) &&
        h2->async_request_forwardable) {
        if (h2->async_inject_content_length_on_forward &&
            !h2_inject_content_length(h2->pending_synth,
                                      &h2->async_synth_len,
                                      h2->async_body_start,
                                      h2->async_body_len,
                                      Http2Conn::kBodySynthCap)) {
            u8 resp[8192];
            H2Dispatch<Loop> d{loop, &conn, resp, sizeof(resp), 0, false};
            h2_emit_status(d, kStreamId, 413);
            conn.pending_handler_fn = nullptr;
            conn.handler_ctx = nullptr;
            h2_clear_async(*h2);
            h2_async_epoch_leave(loop, conn);
            if (d.resp_len == 0 || d.overflow) {
                loop->close_conn(conn);
                return;
            }
            conn.send_progress = 0;
            conn.send_buf.reset();
            conn.send_buf.write(resp, d.resp_len);
            conn.transition_to_sending(&on_h2_sent<Loop>);
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
        const bool capture = kOutcome.kind == JitDispatchOutcome::Kind::ForwardCapture;
        h2->async_kind = H2AsyncKind::Proxy;
        h2->async_upstream_id = kOutcome.upstream_id;
        h2->async_apply_response_mutations = !capture;
        h2->async_capture_response = capture;
        if (capture) {
            h2->async_fn = conn.pending_handler_fn;
            h2->async_state = kOutcome.next_state;
        }
        conn.pending_handler_fn = nullptr;
        h2_proxy_begin<Loop>(loop, conn);
        return;
    }

    u8 resp[Http2Conn::kBodySynthCap];
    H2Dispatch<Loop> d{loop, &conn, resp, sizeof(resp), 0, false};
    if (kOutcome.kind == JitDispatchOutcome::Kind::ReturnStatus) {
        h2_emit_outcome(d, kStreamId, kOutcome, h2->async_cfg, kHeadRequest);
    } else if (kOutcome.kind == JitDispatchOutcome::Kind::ForwardBuffered ||
               kOutcome.kind == JitDispatchOutcome::Kind::ForwardCapture) {
        h2_emit_status(d, kStreamId, 400);
    } else {
        h2_emit_status(d, kStreamId, 503);  // forward / event-yield over h2: follow-up
    }
    if (conn.response_capture_slice != nullptr) {
        if constexpr (requires { loop->pool.free(conn.response_capture_slice); })
            loop->pool.free(conn.response_capture_slice);
        conn.response_capture_slice = nullptr;
    }

    // Clear the suspension before responding so the flush's on_h2_sent re-arms
    // recv (async_stream == 0) rather than the timer. The async episode is over —
    // release the config epoch pinned at park time.
    conn.pending_handler_fn = nullptr;
    conn.handler_ctx = nullptr;
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
