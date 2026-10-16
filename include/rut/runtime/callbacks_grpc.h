#pragma once

// Included after callbacks_h2.h. All sends copy into the Connection's owned
// send slice: retiring an RPC never frees memory referenced by an async SQE.
#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/grpc_protocol.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/upstream_pool.h"

namespace rut {
inline u32 select_backend(u16 upstream_id, u32 backend_count, u64 now_us);
inline void record_backend_result(u16 upstream_id, u32 backend_idx, bool success, u64 now_us);

template <typename Loop>
void grpc_refresh_timer(Loop*, Connection&);
template <typename Loop>
void grpc_drive_upstream(Loop*, Connection&);
template <typename Loop>
void grpc_kick_downstream(Loop*, Connection&);
template <typename Loop>
void grpc_deadline_fired(Loop*, Connection&);
template <typename Loop>
void grpc_on_upstream_data(void*, Connection&, IoEvent);
template <typename Loop>
void grpc_on_upstream_sent(void*, Connection&, IoEvent);

inline GrpcExchange* grpc_find(Http2Conn& h, u32 id) {
    for (auto* x : h.grpc.streams)
        if (x && (h.grpc.upstream ? x->upstream_stream : x->downstream_stream) == id) return x;
    return nullptr;
}
inline bool grpc_attach(Http2Conn& h, GrpcExchange* x) {
    for (auto& entry : h.grpc.streams) {
        if (entry) continue;
        entry = x;
        h.grpc.active++;
        return true;
    }
    return false;
}
inline void grpc_queue_cancel(Http2Conn& h, u32 stream_id) {
    auto& g = h.grpc;
    if (g.control_len + 13 <= sizeof(g.control)) {
        g.control_len += write_rst_stream(g.control + g.control_len, stream_id, Http2Error::Cancel);
        return;
    }
    for (u32 i = 0; i < g.pending_cancel_count; i++)
        if (g.pending_cancels[i] == stream_id) return;
    if (g.pending_cancel_count < 64) g.pending_cancels[g.pending_cancel_count++] = stream_id;
}
inline void grpc_flush_pending_cancels(Http2Conn& h) {
    auto& g = h.grpc;
    while (g.pending_cancel_count && sizeof(g.control) - g.control_len >= 13) {
        const u32 stream_id = g.pending_cancels[--g.pending_cancel_count];
        g.control_len += write_rst_stream(g.control + g.control_len, stream_id, Http2Error::Cancel);
    }
}
inline void grpc_detach(Http2Conn& h, GrpcExchange* x) {
    for (auto& entry : h.grpc.streams) {
        if (entry != x) continue;
        entry = nullptr;
        h.grpc.active--;
        if (!h.grpc.active) h.grpc.idle_since_us = monotonic_us();
        return;
    }
}
inline void grpc_pop(u8* buf, u32& len, u32 n) {
    len -= n;
    if (len) __builtin_memmove(buf, buf + n, len);
}
inline bool grpc_timeout(Str value, u64* micros) {
    if (value.len < 2 || value.len > 9) return false;
    u64 n = 0;
    for (u32 i = 0; i + 1 < value.len; i++) {
        if (value.ptr[i] < '0' || value.ptr[i] > '9') return false;
        n = n * 10 + static_cast<u32>(value.ptr[i] - '0');
    }
    switch (value.ptr[value.len - 1]) {
        case 'H':
            n *= 3600000000ull;
            break;
        case 'M':
            n *= 60000000ull;
            break;
        case 'S':
            n *= 1000000ull;
            break;
        case 'm':
            n *= 1000;
            break;
        case 'u':
            break;
        case 'n':
            n = (n + 999) / 1000;
            break;
        default:
            return false;
    }
    *micros = n;
    return true;
}
inline u32 grpc_error_headers(u8* out, u32 cap, u32 sid, u8 code, bool started) {
    char status[2] = {static_cast<char>('0' + code / 10), static_cast<char>('0' + code % 10)};
    const Str value = code >= 10 ? Str{status, 2} : Str{status + 1, 1};
    const hpack::Header hs[] = {{{":status", 7}, {"200", 3}},
                                {{"content-type", 12}, {"application/grpc", 16}},
                                {{"grpc-status", 11}, value}};
    return http2_write_headers(out, cap, sid, hs + (started ? 2 : 0), started ? 1 : 3, true);
}

// Return all buffered credit on retirement (including cancellation), so one
// cancelled RPC cannot exhaust the connection window for unrelated RPCs.
template <typename Loop>
void grpc_release(Loop* loop, GrpcExchange* x, bool cancel) {
    Connection* down = x->downstream;
    Connection* up = x->upstream;
    if (down && down->h2) {
        down->h2->consume_data(x->downstream_stream, x->upload_len);
        if (auto* stream = down->h2->find_stream(x->downstream_stream))
            stream->manual_window = false;
        grpc_detach(*down->h2, x);
        if (!down->h2->grpc.busy) grpc_refresh_timer(loop, *down);
    }
    if (up && up->h2) {
        auto& h = *up->h2;
        h.consume_data(x->upstream_stream, x->download_len);
        if (auto* s = h.find_stream(x->upstream_stream)) {
            if (cancel && x->request_headers_sent) grpc_queue_cancel(h, x->upstream_stream);
            s->state = Http2StreamState::Closed;
        }
        grpc_detach(h, x);
    }
    if (x->slot_held) loop->upstream_release(x->upstream_id);
    loop->pool.free(reinterpret_cast<u8*>(x));
    if (up && up->h2 && !up->h2->grpc.busy) grpc_drive_upstream(loop, *up);
}

template <typename Loop>
void grpc_connection_closed(void* lp, Connection& conn) {
    auto* loop = static_cast<Loop*>(lp);
    if (!conn.h2) return;
    auto& g = conn.h2->grpc;
    g.busy = true;
    if (g.timer_deadline_us) {
        if constexpr (requires { loop->disarm_yield_timer(conn); }) loop->disarm_yield_timer(conn);
    }
    // During connect the descriptor is also held in upstream_fd for the
    // backend's connect operation. The ordinary close path must close it once.
    if (g.connecting && conn.fd == conn.upstream_fd) conn.fd = -1;
    if (g.upstream) {
        Connection** link = &loop->grpc_upstreams;
        while (*link && *link != &conn) link = &(*link)->h2->grpc.pool_next;
        if (*link) *link = g.pool_next;
        for (auto*& x : g.streams) {
            if (!x) continue;
            x->upstream = nullptr;
            if (!x->response_end) x->failure = 14;
            x->response_end = true;
            Connection* down = x->downstream;
            x = nullptr;
            if (down) grpc_kick_downstream(loop, *down);
        }
        g.active = 0;
    } else {
        for (auto*& x : g.streams) {
            if (!x) continue;
            Connection* up = x->upstream;
            grpc_release(loop, x, true);
            if (up && up->h2 && !up->h2->grpc.busy) grpc_drive_upstream(loop, *up);
        }
    }
}

template <typename Loop>
bool grpc_grow_recv(Loop* loop, Connection& conn) {
    if (conn.recv_buf.capacity() >= kDefaultMaxFrameSize + kFrameHeaderSize) return true;
    u8* storage = loop->pool.alloc_bulk();
    if (!storage) return false;
    const u32 n = conn.recv_buf.len();
    __builtin_memcpy(storage, conn.recv_buf.data(), n);
    loop->pool.free(conn.recv_slice);
    conn.bind_request_receive_buffer(storage, SlicePool::kBulkSliceSize);
    conn.recv_buf.commit(n);
    return true;
}

// Client session callbacks only stage owned bytes. They never close a session
// while Http2Conn::process still has it on its stack.
template <typename Loop>
struct GrpcClientDispatch {
    Loop* loop;
    Connection* conn;
};

inline bool grpc_has_status(const hpack::Header* hs, u32 n) {
    for (u32 i = 0; i < n; i++)
        if (hs[i].name.eq({"grpc-status", 11})) return true;
    return false;
}
inline bool grpc_request_header_allowed(const hpack::Header& h) {
    if (h.name.eq({"connection", 10}) || h.name.eq({"keep-alive", 10}) ||
        h.name.eq({"proxy-connection", 16}) || h.name.eq({"transfer-encoding", 17}) ||
        h.name.eq({"upgrade", 7}))
        return false;
    if (h.name.eq({"te", 2}) && !h.value.eq({"trailers", 8})) return false;
    return true;
}
inline bool grpc_response_header_allowed(const hpack::Header& h) {
    return !h.name.eq({"content-length", 14});
}
inline bool grpc_rejected_by_goaway(const Http2Conn& h, const GrpcExchange& x) {
    return h.peer_goaway && (!x.request_headers_sent || x.upstream_stream > h.peer_last_stream);
}
inline void grpc_begin_handshake(GrpcProxyState& g, u64 now_us) {
    if (!g.connected_at_us) g.connected_at_us = now_us;
}
inline void grpc_record_connect_result(const Connection& conn, bool success, u64 now_us) {
    record_backend_result(conn.upstream_idx, conn.upstream_backend_idx, success, now_us);
}
inline void grpc_record_handshake_result(Connection& conn, bool success, u64 now_us) {
    if (conn.h2 == nullptr || conn.h2->grpc.handshake_health_recorded) return;
    conn.h2->grpc.handshake_health_recorded = true;
    grpc_record_connect_result(conn, success, now_us);
}
inline bool grpc_idle_upstream_should_close(
    const GrpcProxyState& g, bool peer_goaway, bool draining, u64 now_us, u64 keepalive_us) {
    return g.active == 0 && (draining || peer_goaway || now_us - g.idle_since_us >= keepalive_us);
}
template <typename Loop>
void grpc_response_headers(
    void* ctx, Http2Conn& h, u32 sid, const hpack::Header* hs, u32 n, bool end) {
    (void)ctx;
    auto* x = grpc_find(h, sid);
    if (!x) return;
    bool status = false;
    u32 http_status = 0;
    bool content_type = false;
    for (u32 i = 0; i < n; i++) {
        if (hs[i].name.eq({":status", 7})) {
            if (hs[i].value.len == 3 && hs[i].value.ptr[0] == '1') return;
            status = hs[i].value.eq({"200", 3});
            if (hs[i].value.len == 3)
                http_status =
                    static_cast<u32>((hs[i].value.ptr[0] - '0') * 100 +
                                     (hs[i].value.ptr[1] - '0') * 10 + hs[i].value.ptr[2] - '0');
        }
        if (hs[i].name.eq({"content-type", 12})) content_type = grpc_content_type(hs[i].value);
    }
    if (!status || !content_type) {
        switch (http_status) {
            case 400:
                x->failure = 13;
                break;
            case 401:
                x->failure = 16;
                break;
            case 403:
                x->failure = 7;
                break;
            case 404:
                x->failure = 12;
                break;
            case 429:
            case 502:
            case 503:
            case 504:
                x->failure = 14;
                break;
            default:
                x->failure = 2;
                break;
        }
        x->response_end = true;
        return;
    }
    hpack::Header filtered[Http2Conn::kMaxHeadersPerReq];
    u32 filtered_n = 0;
    for (u32 i = 0; i < n; i++) {
        if (!grpc_response_header_allowed(hs[i])) continue;
        if (filtered_n < Http2Conn::kMaxHeadersPerReq) filtered[filtered_n++] = hs[i];
    }
    x->response_headers_len = http2_write_headers(x->response_headers,
                                                  sizeof(x->response_headers),
                                                  x->downstream_stream,
                                                  filtered,
                                                  filtered_n,
                                                  end && grpc_has_status(filtered, filtered_n));
    if (!x->response_headers_len) x->failure = 8;
    x->response_end = end;
    if (end && !grpc_has_status(hs, n)) x->failure = 2;
}
template <typename Loop>
void grpc_response_trailers(void*, Http2Conn& h, u32 sid, const hpack::Header* hs, u32 n, bool) {
    auto* x = grpc_find(h, sid);
    if (!x) return;
    hpack::Header filtered[Http2Conn::kMaxHeadersPerReq];
    u32 filtered_n = 0;
    for (u32 i = 0; i < n; i++) {
        if (!grpc_response_header_allowed(hs[i])) continue;
        if (filtered_n < Http2Conn::kMaxHeadersPerReq) filtered[filtered_n++] = hs[i];
    }
    x->response_trailers_len = http2_write_headers(x->response_trailers,
                                                   sizeof(x->response_trailers),
                                                   x->downstream_stream,
                                                   filtered,
                                                   filtered_n,
                                                   true);
    if (!x->response_trailers_len) x->failure = 8;
    if (!grpc_has_status(hs, n)) x->failure = 2;
    x->response_end = true;
}
template <typename Loop>
void grpc_response_data(void*, Http2Conn& h, u32 sid, const u8* data, u32 len, bool end) {
    auto* x = grpc_find(h, sid);
    if (!x) {
        h.consume_data(sid, len);
        return;
    }
    if (len > sizeof(x->download) - x->download_len) {
        x->failure = 8;
        return;
    }
    if (len) __builtin_memcpy(x->download + x->download_len, data, len);
    x->download_len += len;
    if (end) {
        x->failure = 2;
        x->response_end = true;
    }  // gRPC requires status trailers.
}
template <typename Loop>
void grpc_response_reset(void*, Http2Conn& h, u32 sid, Http2Error error) {
    if (auto* x = grpc_find(h, sid); x && !x->response_end) {
        switch (static_cast<u32>(error)) {
            case static_cast<u32>(Http2Error::Cancel):
                x->failure = 1;
                break;
            case static_cast<u32>(Http2Error::RefusedStream):
                x->failure = 14;
                break;
            case static_cast<u32>(Http2Error::EnhanceYourCalm):
                x->failure = 8;
                break;
            case static_cast<u32>(Http2Error::InadequateSecurity):
                x->failure = 7;
                break;
            default:
                x->failure = 13;
                break;
        }
        x->response_end = true;
    }
}

template <typename Loop>
void grpc_on_upstream_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result <= 0 || static_cast<u32>(ev.result) > conn.send_buf.len() - conn.send_progress) {
        loop->close_conn(conn);
        return;
    }
    conn.send_progress += static_cast<u32>(ev.result);
    if (conn.send_progress < conn.send_buf.len()) {
        if (!loop->submit_send(conn,
                               conn.send_buf.data() + conn.send_progress,
                               conn.send_buf.len() - conn.send_progress))
            loop->close_conn(conn);
        return;
    }
    conn.send_progress = 0;
    conn.send_buf.reset();
    conn.on_send = nullptr;
    grpc_on_upstream_data<Loop>(lp, conn, {conn.id, 1, 0, 0, IoEventType::Recv, 0});
}

template <typename Loop>
void grpc_drive_upstream(Loop* loop, Connection& conn) {
    auto& h = *conn.h2;
    auto& g = h.grpc;
    if (g.connecting || conn.on_send || g.busy) return;
    g.busy = true;
    grpc_flush_pending_cancels(h);
    if (h.conn_recv_credit && sizeof(g.control) - g.control_len >= 26) {
        u32 written = 0;
        h.process(
            nullptr, 0, g.control + g.control_len, sizeof(g.control) - g.control_len, &written);
        g.control_len += written;
    }
    u8* out = conn.send_buf.write_ptr();
    u32 n = 0;
    if (!g.preface_sent) {
        __builtin_memcpy(out, kClientPreface, kClientPrefaceLen);
        n = kClientPrefaceLen + write_settings_frame(out + kClientPrefaceLen, h.our_settings);
        g.preface_sent = true;
    } else if (g.control_len) {
        n = g.control_len;
        __builtin_memcpy(out, g.control, n);
        g.control_len = 0;
    } else {
        u32 opened = 0;
        u32 next_header = 0x7fffffffu;
        for (auto* x : g.streams) {
            if (!x || x->failure || x->response_end) continue;
            if (x->request_headers_sent)
                opened++;
            else if (x->upstream_stream < next_header)
                next_header = x->upstream_stream;
        }
        for (u32 step = 0; step < 64; step++) {
            const u32 i = (g.cursor + step) % 64;
            auto* x = g.streams[i];
            if (!x || x->failure || x->response_end) continue;
            auto* stream = h.find_stream(x->upstream_stream);
            if (!stream) continue;
            if (!x->request_headers_sent) {
                // Stream creation is ordered even when DATA is round-robin.
                if (x->upstream_stream != next_header) continue;
                if (!h.peer_settings_seen || (h.peer_settings.has_max_concurrent_streams &&
                                              opened >= h.peer_settings.max_concurrent_streams))
                    continue;
                n = x->request_headers_len;
                __builtin_memcpy(out, x->request_headers, n);
                x->request_headers_sent = true;
            } else if (x->upload_len && stream->send_window > 0 && h.conn_send_window > 0) {
                u32 amount = x->upload_len;
                const u32 cap = conn.send_buf.write_avail() - kFrameHeaderSize;
                if (amount > cap) amount = cap;
                if (amount > h.peer_settings.max_frame_size)
                    amount = h.peer_settings.max_frame_size;
                if (amount > static_cast<u32>(stream->send_window)) amount = stream->send_window;
                if (amount > static_cast<u64>(h.conn_send_window)) amount = h.conn_send_window;
                n = http2_write_data(out, x->upstream_stream, x->upload, amount, false);
                grpc_pop(x->upload, x->upload_len, amount);
                stream->send_window -= static_cast<i32>(amount);
                h.conn_send_window -= amount;
                x->downstream->h2->consume_data(x->downstream_stream, amount);
            } else if (!x->upload_len && x->request_end && !x->request_end_sent) {
                if (x->request_trailers_len) {
                    n = x->request_trailers_len;
                    __builtin_memcpy(out, x->request_trailers, n);
                } else
                    n = http2_write_data(out, x->upstream_stream, nullptr, 0, true);
                x->request_end_sent = true;
                stream->state = stream->state == Http2StreamState::HalfClosedRemote
                                    ? Http2StreamState::Closed
                                    : Http2StreamState::HalfClosedLocal;
            }
            if (n) {
                g.cursor = (i + 1) % 64;
                break;
            }
        }
    }
    if (n) {
        conn.send_buf.commit(n);
        conn.on_send = &grpc_on_upstream_sent<Loop>;
        if (!loop->submit_send(conn, conn.send_buf.data(), n)) {
            loop->close_conn(conn);
            return;
        }
    }
    // Window credit may have become available for any downstream session.
    for (auto* x : g.streams)
        if (x && x->downstream) grpc_kick_downstream(loop, *x->downstream);
    g.busy = false;
}

template <typename Loop>
void grpc_on_upstream_data(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result <= 0 || !conn.h2) {
        if (conn.h2 && !conn.h2->peer_settings_seen)
            grpc_record_handshake_result(conn, false, monotonic_us());
        loop->close_conn(conn);
        return;
    }
    auto& h = *conn.h2;
    auto& g = h.grpc;
    if (g.connecting) return;
    GrpcClientDispatch<Loop> dispatch{loop, &conn};
    h.cb_ctx = &dispatch;
    h.on_headers = &grpc_response_headers<Loop>;
    h.on_trailers = &grpc_response_trailers<Loop>;
    h.on_data = &grpc_response_data<Loop>;
    h.on_reset = &grpc_response_reset<Loop>;
    const bool settings_seen_before = h.peer_settings_seen;
    g.busy = true;
    u32 written = 0;
    const auto result = h.process(conn.recv_buf.data(),
                                  conn.recv_buf.len(),
                                  g.control + g.control_len,
                                  sizeof(g.control) - g.control_len,
                                  &written);
    g.control_len += written;
    grpc_flush_pending_cancels(h);
    const u32 remaining = conn.recv_buf.len() - result.consumed;
    if (remaining) __builtin_memmove(conn.recv_slice, conn.recv_slice + result.consumed, remaining);
    conn.reset_request_receive_buffer();
    conn.recv_buf.commit(remaining);
    if (result.close) {
        grpc_record_handshake_result(conn, false, monotonic_us());
        g.busy = false;
        loop->close_conn(conn);
        return;
    }
    if (!settings_seen_before && h.peer_settings_seen)
        grpc_record_handshake_result(conn, true, monotonic_us());
    for (auto* x : g.streams) {
        if (!x) continue;
        if (grpc_rejected_by_goaway(h, *x)) x->failure = 14;
        grpc_kick_downstream(loop, *x->downstream);
    }
    // RST/GOAWAY callbacks run while the H2 parser is busy, so the first kick
    // above is intentionally suppressed. Snapshot downstream connections
    // before releasing busy: the refresh/kick can retire and free exchanges.
    Connection* downstreams[64];
    u32 downstream_count = 0;
    for (auto* x : g.streams) {
        if (!x || !x->downstream) continue;
        bool seen = false;
        for (u32 i = 0; i < downstream_count; i++)
            if (downstreams[i] == x->downstream) seen = true;
        if (!seen) downstreams[downstream_count++] = x->downstream;
    }
    g.busy = false;
    // A timer-arm failure can leave a downstream error parked indefinitely.
    for (u32 i = 0; i < downstream_count; i++) {
        grpc_refresh_timer(loop, *downstreams[i]);
        grpc_kick_downstream(loop, *downstreams[i]);
    }
    grpc_drive_upstream(loop, conn);
    if (conn.h2 && !loop->submit_recv(conn)) loop->close_conn(conn);
}

template <typename Loop>
void grpc_connected(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result < 0) {
        grpc_record_connect_result(conn, false, monotonic_us());
        loop->close_conn(conn);
        return;
    }
    // Transfer the connected socket from the backend's connect registration to
    // ordinary full-duplex I/O on this dedicated upstream Connection slot.
    if constexpr (requires { loop->backend.detach_upstream(conn, &conn.fd); }) {
        i32 fd = -1;
        if (!loop->backend.detach_upstream(conn, &fd)) {
            conn.fd = -1;
            loop->close_conn(conn);
            return;
        }
        conn.fd = fd;
    } else
        conn.upstream_fd = -1;
    conn.h2->grpc.connecting = false;
    conn.set_slots(&grpc_on_upstream_data<Loop>, nullptr, nullptr, nullptr);
    grpc_drive_upstream(loop, conn);
    if (conn.h2 && !loop->submit_recv(conn)) loop->close_conn(conn);
}

inline bool grpc_upstream_reusable(const Connection& conn,
                                   const RouteConfig* cfg,
                                   u16 upstream_id,
                                   u32 backend_idx) {
    return conn.h2 && conn.request_config == cfg && conn.upstream_idx == upstream_id &&
           conn.upstream_backend_idx == backend_idx && !conn.h2->peer_goaway &&
           conn.h2->grpc.active < 64 && conn.h2->last_stream_id < 0x7ffffffdu;
}

template <typename Loop>
bool grpc_start_impl(Loop* loop,
                     Connection& down,
                     u32 sid,
                     const RouteConfig* cfg,
                     u16 uid,
                     const hpack::Header* hs,
                     u32 nh,
                     const ParsedRequest& req,
                     bool end) {
    if (!cfg || uid >= cfg->upstream_count || !cfg->upstreams[uid].http2 ||
        req.method != HttpMethod::POST || !grpc_request(req) || down.h2->grpc.active >= 64)
        return false;
    const auto& target = cfg->upstreams[uid];
    if (!target.addr_count) return false;
    const u64 now = monotonic_us();
    u64 deadline_base = now;
    if (down.h2 && down.h2->async_stream == sid && down.h2->async_headers_received_us)
        deadline_base = down.h2->async_headers_received_us;
    else if (auto* stream = down.h2->find_stream(sid); stream && stream->headers_received_us)
        deadline_base = stream->headers_received_us;
    u64 deadline = 0;
    for (u32 i = 0; i < nh; i++) {
        if (!hs[i].name.eq({"grpc-timeout", 12})) continue;
        u64 timeout = 0;
        if (deadline || !grpc_timeout(hs[i].value, &timeout)) return false;
        deadline = deadline_base + timeout;
    }
    const u32 backend = select_backend(uid, target.addr_count, now);
    Connection* up = nullptr;
    for (auto* c = loop->grpc_upstreams; c; c = c->h2->grpc.pool_next) {
        if (grpc_upstream_reusable(*c, cfg, uid, backend)) {
            up = c;
            break;
        }
    }
    auto* x = reinterpret_cast<GrpcExchange*>(loop->pool.alloc_bulk());
    if (!x) return false;
    static_assert(sizeof(GrpcExchange) <= SlicePool::kBulkSliceSize);
    x->init();
    if (end && req.has_content_length && req.content_length != 0) x->failure = 13;
    bool fresh = false;
    if (!up) {
        up = loop->alloc_conn();
        if (!up) {
            loop->pool.free(reinterpret_cast<u8*>(x));
            return false;
        }
        up->set_metrics_client(false);
        if (!loop->alloc_h2(*up) || !grpc_grow_recv(loop, *up)) {
            loop->close_conn(*up);
            loop->pool.free(reinterpret_cast<u8*>(x));
            return false;
        }
        up->h2->init_client();
        up->protocol = ConnProtocol::Http2;
        up->state = ConnState::ReadingBody;
        up->keep_alive = true;
        up->request_config = cfg;
        up->upstream_idx = uid;
        up->upstream_backend_idx = static_cast<u8>(backend);
        up->h2->grpc.upstream = true;
        up->h2->grpc.connecting = true;
        grpc_begin_handshake(up->h2->grpc, now);
        up->h2->grpc.pool_next = loop->grpc_upstreams;
        loop->grpc_upstreams = up;
        up->on_close = &grpc_connection_closed<Loop>;
        h2_async_epoch_enter(loop, *up);
        fresh = true;
    }
    const u32 usid = up->h2->last_stream_id + 2 - (up->h2->last_stream_id == 0 ? 1 : 0);
    auto* stream = up->h2->open_stream(usid);
    auto* down_stream = down.h2->find_stream(sid);
    if (!stream || !down_stream) {
        loop->pool.free(reinterpret_cast<u8*>(x));
        if (fresh) loop->close_conn(*up);
        return false;
    }
    hpack::Header filtered[Http2Conn::kMaxHeadersPerReq];
    u32 filtered_n = 0;
    for (u32 i = 0; i < nh; i++)
        if (grpc_request_header_allowed(hs[i]) && filtered_n < Http2Conn::kMaxHeadersPerReq)
            filtered[filtered_n++] = hs[i];
    x->request_headers_len = http2_write_headers(
        x->request_headers, sizeof(x->request_headers), usid, filtered, filtered_n, false);
    if (!x->request_headers_len) {
        stream->state = Http2StreamState::Closed;
        loop->pool.free(reinterpret_cast<u8*>(x));
        if (fresh) loop->close_conn(*up);
        return false;
    }
    x->downstream = &down;
    x->upstream = up;
    x->downstream_stream = sid;
    x->upstream_stream = usid;
    x->deadline_us = deadline;
    x->has_request_length = req.has_content_length;
    x->expected_request_bytes = req.content_length;
    x->request_end = end;
    x->upstream_id = uid;
    if (target.max_inflight) {
        if (!loop->upstream_acquire(uid, target.max_inflight)) {
            stream->state = Http2StreamState::Closed;
            loop->pool.free(reinterpret_cast<u8*>(x));
            if (fresh) loop->close_conn(*up);
            return false;
        }
        x->slot_held = true;
    }
    grpc_attach(*down.h2, x);
    grpc_attach(*up->h2, x);
    stream->manual_window = down_stream->manual_window = true;
    down.on_close = &grpc_connection_closed<Loop>;
    if (deadline && monotonic_us() >= deadline) {
        grpc_deadline_fired(loop, down);
        if (fresh) loop->close_conn(*up);
        return true;
    }
    if (fresh) {
        up->fd = up->upstream_fd = UpstreamPool::create_socket();
        up->set_slots(nullptr, nullptr, nullptr, &grpc_connected<Loop>);
        if (up->fd < 0 ||
            !loop->submit_connect(*up, &target.addrs[backend], sizeof(target.addrs[backend]))) {
            record_backend_result(uid, backend, /*success=*/false, monotonic_us());
            loop->close_conn(*up);
            return true;
        }
    } else
        grpc_drive_upstream(loop, *up);
    loop->timer.refresh(up, 1);
    loop->timer.refresh(&down, 1);
    grpc_refresh_timer(loop, down);
    return true;
}

template <typename Loop>
bool grpc_start(Loop* loop,
                Connection& down,
                u32 sid,
                const RouteConfig* cfg,
                u16 uid,
                const hpack::Header* hs,
                u32 nh,
                const ParsedRequest& req,
                bool end) {
    if constexpr (requires {
                      loop->grpc_upstreams;
                      loop->pool.alloc_bulk();
                      loop->alloc_conn();
                  })
        return grpc_start_impl(loop, down, sid, cfg, uid, hs, nh, req, end);
    else
        return false;
}

// Called from the ordinary H2 serving pump, with the downstream send slice idle.
template <typename Loop>
u32 grpc_pump_downstream(Loop* loop, Connection& down, u8* out, u32 cap) {
    if constexpr (!(requires {
                      loop->grpc_upstreams;
                      loop->pool.alloc_bulk();
                  }))
        return 0;
    else {
        auto& h = *down.h2;
        u32 total = 0;
        for (u32 step = 0; step < 64; step++) {
            const u32 i = (h.grpc.cursor + step) % 64;
            auto* x = h.grpc.streams[i];
            if (!x) continue;
            auto* stream = h.find_stream(x->downstream_stream);
            if (!stream) {
                grpc_release(loop, x, true);
                continue;
            }
            u32 n = 0;
            bool done = false;
            if (x->failure) {
                n = grpc_error_headers(out + total,
                                       cap - total,
                                       x->downstream_stream,
                                       x->failure,
                                       x->response_headers_sent);
                done = n != 0;
            } else if (!x->response_headers_sent && x->response_headers_len) {
                if (x->response_headers_len > cap - total) continue;
                n = x->response_headers_len;
                __builtin_memcpy(out + total, x->response_headers, n);
                x->response_headers_sent = true;
                done = x->response_end && !x->download_len && !x->response_trailers_len;
            } else if (x->response_headers_sent && x->download_len && stream->send_window > 0 &&
                       h.conn_send_window > 0 && cap - total > 9) {
                u32 amount = x->download_len;
                if (amount > cap - total - 9) amount = cap - total - 9;
                if (amount > h.peer_settings.max_frame_size)
                    amount = h.peer_settings.max_frame_size;
                if (amount > static_cast<u32>(stream->send_window)) amount = stream->send_window;
                if (amount > static_cast<u64>(h.conn_send_window)) amount = h.conn_send_window;
                n = http2_write_data(out + total, x->downstream_stream, x->download, amount, false);
                grpc_pop(x->download, x->download_len, amount);
                stream->send_window -= static_cast<i32>(amount);
                h.conn_send_window -= amount;
                if (x->upstream) x->upstream->h2->consume_data(x->upstream_stream, amount);
            } else if (x->response_headers_sent && !x->download_len && x->response_trailers_len) {
                if (x->response_trailers_len > cap - total) continue;
                n = x->response_trailers_len;
                __builtin_memcpy(out + total, x->response_trailers, n);
                done = true;
            }
            total += n;
            Connection* up = x->upstream;
            if (done) {
                h2_close_stream(&h, x->downstream_stream);
                grpc_release(loop, x, x->failure || !x->request_end_sent);
            }
            if (up && up->h2 && !up->h2->grpc.busy && !up->h2->grpc.connecting) {
                // Produce the returned response-window credit before the next read.
                grpc_on_upstream_data<Loop>(
                    static_cast<void*>(loop), *up, {up->id, 1, 0, 0, IoEventType::Recv, 0});
            }
            if (n) {
                h.grpc.cursor = (i + 1) % 64;
                break;
            }
        }
        return total;
    }
}

template <typename Loop>
void grpc_kick_downstream(Loop* loop, Connection& down) {
    if (!down.h2 || down.h2->grpc.busy || down.on_send || down.h2->async_stream) return;
    on_h2_data<Loop>(static_cast<void*>(loop), down, {down.id, 1, 0, 0, IoEventType::Recv, 0});
}

template <typename Loop>
void grpc_request_data(
    Loop* loop, Connection& down, GrpcExchange& x, const u8* data, u32 len, bool end) {
    if (x.failure || !x.upstream) {
        down.h2->consume_data(x.downstream_stream, len);
        return;
    }
    x.request_bytes += len;
    if (len > sizeof(x.upload) - x.upload_len ||
        (x.has_request_length && (x.request_bytes > x.expected_request_bytes ||
                                  (end && x.request_bytes != x.expected_request_bytes)))) {
        down.h2->consume_data(x.downstream_stream, len);
        x.failure = 13;
        return;
    }
    if (len) __builtin_memcpy(x.upload + x.upload_len, data, len);
    x.upload_len += len;
    x.request_end = end;
    grpc_drive_upstream(loop, *x.upstream);
}

template <typename Loop>
void grpc_request_trailers(void* ctx, Http2Conn& h, u32 sid, const hpack::Header* hs, u32 n, bool) {
    auto* d = static_cast<H2Dispatch<Loop>*>(ctx);
    if constexpr (requires {
                      d->loop->grpc_upstreams;
                      d->loop->pool.alloc_bulk();
                  }) {
        auto* x = grpc_find(h, sid);
        if (!x || !x->upstream) return;
        x->request_trailers_len = http2_write_headers(
            x->request_trailers, sizeof(x->request_trailers), x->upstream_stream, hs, n, true);
        if (!x->request_trailers_len) x->failure = 8;
        grpc_request_data(d->loop, *d->conn, *x, nullptr, 0, true);
    }
}

template <typename Loop>
void grpc_refresh_timer(Loop* loop, Connection& conn) {
    auto& g = conn.h2->grpc;
    if (g.upstream) return;
    u64 earliest = 0;
    for (auto* x : g.streams)
        if (x && !x->failure && x->deadline_us && (!earliest || x->deadline_us < earliest))
            earliest = x->deadline_us;
    if (earliest == g.timer_deadline_us) return;
    if (g.timer_deadline_us) {
        if constexpr (requires { loop->disarm_yield_timer(conn); }) loop->disarm_yield_timer(conn);
    }
    g.timer_deadline_us = earliest;
    if (!earliest) return;
    const u64 now = monotonic_us();
    u64 delay = earliest > now ? earliest - now : 1;
    if (delay > 3600000000ull) delay = 3600000000ull;
    if constexpr (!(requires { loop->arm_throttle_timer(conn, delay * 1000); })) {
        g.timer_deadline_us = 0;
        return;
    } else if (!loop->arm_throttle_timer(conn, delay * 1000)) {
        g.timer_deadline_us = 0;
        for (auto* x : g.streams) {
            if (!x || !x->deadline_us) continue;
            x->failure = 8;
            Connection* up = x->upstream;
            if (!up || !up->h2) continue;
            auto& uh = *up->h2;
            uh.consume_data(x->upstream_stream, x->download_len);
            if (auto* stream = uh.find_stream(x->upstream_stream)) {
                if (x->request_headers_sent) grpc_queue_cancel(uh, x->upstream_stream);
                stream->state = Http2StreamState::Closed;
            }
            grpc_detach(uh, x);
            x->upstream = nullptr;
            if (x->slot_held) {
                loop->upstream_release(x->upstream_id);
                x->slot_held = false;
            }
            if (!uh.grpc.busy) grpc_drive_upstream(loop, *up);
        }
        Connection* downstreams[64];
        u32 downstream_count = 0;
        for (auto* x : g.streams) {
            if (!x || !x->downstream) continue;
            bool seen = false;
            for (u32 i = 0; i < downstream_count; i++)
                if (downstreams[i] == x->downstream) seen = true;
            if (!seen) downstreams[downstream_count++] = x->downstream;
        }
        for (u32 i = 0; i < downstream_count; i++) grpc_kick_downstream(loop, *downstreams[i]);
        return;
    }
    conn.yield_armed = true;
}

template <typename Loop>
void grpc_deadline_fired(Loop* loop, Connection& conn) {
    conn.yield_armed = false;
    conn.h2->grpc.timer_deadline_us = 0;
    const u64 now = monotonic_us();
    for (auto* x : conn.h2->grpc.streams) {
        if (!x || !x->deadline_us || now < x->deadline_us) continue;
        x->failure = 4;
        Connection* up = x->upstream;
        if (!up || !up->h2) continue;
        auto& uh = *up->h2;
        uh.consume_data(x->upstream_stream, x->download_len);
        if (auto* stream = uh.find_stream(x->upstream_stream)) {
            if (x->request_headers_sent) grpc_queue_cancel(uh, x->upstream_stream);
            stream->state = Http2StreamState::Closed;
        }
        grpc_detach(uh, x);
        x->upstream = nullptr;
        if (x->slot_held) {
            loop->upstream_release(x->upstream_id);
            x->slot_held = false;
        }
        if (!uh.grpc.busy) grpc_drive_upstream(loop, *up);
    }
    grpc_refresh_timer(loop, conn);
    grpc_kick_downstream(loop, conn);
}

template <typename Loop>
void grpc_tick(Loop* loop, Connection& conn) {
    auto& h = *conn.h2;
    const u64 now = monotonic_us();
    if (h.grpc.upstream) {
        if (((h.grpc.connecting || !h.peer_settings_seen) &&
             now - h.grpc.connected_at_us >= static_cast<u64>(loop->upstream_timeout) * 1000000) ||
            grpc_idle_upstream_should_close(h.grpc,
                                            h.peer_goaway,
                                            loop->is_draining(),
                                            now,
                                            static_cast<u64>(loop->keepalive_timeout) * 1000000)) {
            if (!h.peer_settings_seen) grpc_record_handshake_result(conn, false, now);
            loop->close_conn(conn);
            return;
        }
    } else {
        for (auto* x : h.grpc.streams)
            if (x && x->deadline_us && now >= x->deadline_us) x->failure = 4;
        grpc_kick_downstream(loop, conn);
    }
    if (conn.h2) loop->timer.refresh(&conn, 1);
}
template <typename Loop>
bool grpc_start_synth(H2Dispatch<Loop>& d,
                      u32 sid,
                      const RouteConfig* cfg,
                      u16 uid,
                      const u8* synth,
                      u32 len,
                      bool end) {
    ParsedRequest req;
    HttpParser parser;
    if (parser.parse(synth, len, &req) != ParseStatus::Complete) return false;
    hpack::Header hs[Http2Conn::kMaxHeadersPerReq];
    u8 names[Http2Conn::kHeaderScratchCap];
    u32 used = 0;
    Str host{nullptr, 0};
    for (u32 i = 0; i < req.header_count; i++)
        if (grpc_header_name(req.headers[i].name, {"host", 4})) host = req.headers[i].value;
    if (!host.len) return false;
    hs[0] = {{":method", 7}, {"POST", 4}};
    hs[1] = {{":path", 5}, req.path};
    hs[2] = {{":scheme", 7}, {"http", 4}};
    hs[3] = {{":authority", 10}, host};
    hs[4] = {{"te", 2}, {"trailers", 8}};
    u32 n = 5;
    for (u32 i = 0; i < req.header_count; i++) {
        const auto& header = req.headers[i];
        if (grpc_header_name(header.name, {"host", 4}) ||
            grpc_header_name(header.name, {"te", 2}) ||
            grpc_header_name(header.name, {"connection", 10}))
            continue;
        if (n >= Http2Conn::kMaxHeadersPerReq || header.name.len > sizeof(names) - used)
            return false;
        for (u32 j = 0; j < header.name.len; j++) {
            char c = header.name.ptr[j];
            names[used + j] = c >= 'A' && c <= 'Z' ? c + 'a' - 'A' : c;
        }
        hs[n++] = {{reinterpret_cast<const char*>(names + used), header.name.len}, header.value};
        used += header.name.len;
    }
    return grpc_start(d.loop, *d.conn, sid, cfg, uid, hs, n, req, end);
}

}  // namespace rut
