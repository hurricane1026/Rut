#pragma once

// Included after callbacks_h2.h. All sends copy into the Connection's owned
// send slice: retiring an RPC never frees memory referenced by an async SQE.
#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/grpc_protocol.h"
#include "rut/runtime/receive_headroom.h"
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

inline void grpc_log_target(AccessLogEntry& entry, Str path) {
    entry.target_length = static_cast<u16>(path.len);
    entry.target_state = path.len > kAccessLogCompleteTargetMax ? AccessLogTargetState::OverLimit
                                                                : AccessLogTargetState::Complete;
    if (!path.len || path.ptr[0] != '/' || path.len > kAccessLogObservedStrictH1TargetMax)
        entry.target_state = AccessLogTargetState::Invalid;
    for (u32 j = 0; j < path.len; j++) {
        const u8 kByte = static_cast<u8>(path.ptr[j]);
        if (kByte <= 32 || kByte == 127) entry.target_state = AccessLogTargetState::Invalid;
    }
    if (entry.target_state == AccessLogTargetState::Complete)
        __builtin_memcpy(entry.path, path.ptr, path.len);
}

// Record exactly once when the exchange retires. Completion means the final
// trailers were staged into downstream-owned output, not acknowledged by peer.
template <typename Loop>
void grpc_observe(Loop* loop, GrpcExchange& x) {
    if (!x.observed) return;
    x.observed = false;
    const u64 kElapsed = monotonic_us() - x.started_us;
    const bool web_failure_terminated =
        x.web_failure_prepared && x.web_response_invalid && x.failure;
    const u8 kStatus =
        web_failure_terminated
            ? x.failure
            : (x.response_end_sent ? (x.failure ? x.failure : x.response_status) : 1);
    if (loop->metrics) loop->metrics->on_grpc_complete(kStatus, kElapsed);
    auto& entry = x.log_entry;
    entry.timestamp_us = realtime_us();
    entry.duration_us = kElapsed > 0xffffffffull ? 0xffffffffu : static_cast<u32>(kElapsed);
    // No separate upstream latency sample: lifetime includes downstream backpressure.
    entry.req_size =
        x.request_bytes > 0xffffffffull ? 0xffffffffu : static_cast<u32>(x.request_bytes);
    entry.resp_size = x.staged_response_bytes > 0xffffffffull
                          ? 0xffffffffu
                          : static_cast<u32>(x.staged_response_bytes);
    entry.grpc_status_plus_one = kStatus + 1;
    if (x.skip_rpc_log) return;
    if (loop->access_log && loop->live_access_log)
        loop->live_access_log->fail_protocol(EINVAL);
    else if (loop->live_access_log)
        (void)loop->live_access_log->publish(entry);
    else if (loop->access_log)
        (void)loop->access_log->push(entry);
}

// Return all buffered credit on retirement (including cancellation), so one
// cancelled RPC cannot exhaust the connection window for unrelated RPCs.
template <typename Loop>
void grpc_release(Loop* loop, GrpcExchange* x, bool cancel) {
    grpc_observe(loop, *x);
    Connection* down = x->downstream;
    Connection* up = x->upstream;
    if (down && down->h2) {
        if (!x->web_h1) {
            if (x->web_mode == GrpcWebContentType::Text)
                down->h2->consume_data(x->downstream_stream, x->upload_raw_credit);
            else
                down->h2->consume_data(x->downstream_stream, x->upload_len);
        }
        x->upload_raw_credit = 0;
        x->upload_len = 0;
        if (auto* stream = down->h2->find_stream(x->downstream_stream))
            stream->manual_window = false;
        grpc_detach(*down->h2, x);
        if (!down->h2->grpc.busy) {
            grpc_refresh_timer(loop, *down);
            if (!down->h2->grpc.active && !down->h2->grpc.timer_deadline_us) {
                if constexpr (requires { loop->timer.refresh(down, loop->keepalive_timeout); })
                    loop->timer.refresh(down, loop->keepalive_timeout);
            }
        }
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
        // BIO methods belong to this session context and must outlive its SSL.
        if (g.client_tls.ssl_ctx) {
            if (conn.tls_engine.ssl) tls_engine_free(conn.tls_engine);
            if (conn.tls) {
                destroy_tls_server_ssl(conn.tls);
                conn.tls = nullptr;
            }
            destroy_tls_client_context(g.client_tls);
        }
        Connection** link = &loop->grpc_upstreams;
        while (*link && *link != &conn) link = &(*link)->h2->grpc.pool_next;
        if (*link) *link = g.pool_next;
        for (auto*& x : g.streams) {
            if (!x) continue;
            x->upstream = nullptr;
            if (!x->response_end) x->failure = 14;
            x->response_end = true;
            Connection* down = x->downstream;
            if (x->slot_held) {
                loop->upstream_release(x->upstream_id);
                x->slot_held = false;
            }
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
    return reserve_request_receive_headroom(
        loop->pool, conn, kDefaultMaxFrameSize + kFrameHeaderSize);
}

// Client session callbacks only stage owned bytes. They never close a session
// while Http2Conn::process still has it on its stack.
template <typename Loop>
struct GrpcClientDispatch {
    Loop* loop;
    Connection* conn;
};

inline bool grpc_snapshot_response_mutations(const Connection& down, GrpcExchange& x) {
    if (down.resp_header_mutation_overflow ||
        down.resp_header_mutation_count > GrpcExchange::kMaxResponseMutations)
        return false;
    x.response_mutation_count = down.resp_header_mutation_count;
    x.response_mutation_bytes = 0;
    for (u32 i = 0; i < x.response_mutation_count; i++) {
        const auto& source = down.resp_header_mutations[i];
        const u32 needed = source.name.len + source.value.len;
        if (needed > GrpcExchange::kHeaders - x.response_mutation_bytes) {
            x.response_mutation_overflow = true;
            return false;
        }
        auto& target = x.response_mutations[i];
        target.name_offset = static_cast<u16>(x.response_mutation_bytes);
        target.name_len = static_cast<u16>(source.name.len);
        for (u32 j = 0; j < source.name.len; j++) {
            char c = source.name.ptr[j];
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            x.response_mutation_storage[x.response_mutation_bytes + j] = static_cast<u8>(c);
        }
        x.response_mutation_bytes += source.name.len;
        target.value_offset = static_cast<u16>(x.response_mutation_bytes);
        target.value_len = static_cast<u16>(source.value.len);
        if (source.value.len)
            __builtin_memcpy(x.response_mutation_storage + x.response_mutation_bytes,
                             source.value.ptr,
                             source.value.len);
        x.response_mutation_bytes += source.value.len;
        target.mode = static_cast<u8>(source.mode);
    }
    return true;
}

inline bool grpc_apply_response_mutations(GrpcExchange& x,
                                          hpack::Header* headers,
                                          u32* count,
                                          u32 capacity) {
    for (u32 mi = 0; mi < x.response_mutation_count; mi++) {
        const auto& mutation = x.response_mutations[mi];
        const char* name =
            reinterpret_cast<const char*>(x.response_mutation_storage + mutation.name_offset);
        const char* value =
            reinterpret_cast<const char*>(x.response_mutation_storage + mutation.value_offset);
        const bool remove =
            mutation.mode == static_cast<u8>(Connection::RespHeaderMutationMode::Remove);
        if (validate_response_header(
                name, mutation.name_len, remove ? "" : value, remove ? 0 : mutation.value_len) !=
            HttpHeaderValidation::Ok)
            return false;
        if (mutation.mode != static_cast<u8>(Connection::RespHeaderMutationMode::Add)) {
            for (u32 i = 0; i < *count;) {
                if (!http_header_name_eq_ci(
                        headers[i].name.ptr, headers[i].name.len, name, mutation.name_len)) {
                    i++;
                    continue;
                }
                for (u32 move = i + 1; move < *count; move++) headers[move - 1] = headers[move];
                (*count)--;
            }
        }
        if (!remove && !h2_is_prohibited_response_header(name, mutation.name_len)) {
            if (*count >= capacity) return false;
            headers[*count].name = {name, mutation.name_len};
            headers[*count].value = {value, mutation.value_len};
            (*count)++;
        }
    }
    return true;
}

inline bool grpc_has_status(const hpack::Header* hs, u32 n) {
    for (u32 i = 0; i < n; i++)
        if (hs[i].name.eq({"grpc-status", 11})) return true;
    return false;
}
// Invalid or duplicate status metadata is reported as UNKNOWN in telemetry;
// forwarding remains opaque and does not rewrite backend trailers.
inline u8 grpc_observed_status(const hpack::Header* hs, u32 n) {
    bool seen = false;
    u8 status = 2;
    for (u32 i = 0; i < n; i++) {
        if (!hs[i].name.eq({"grpc-status", 11})) continue;
        if (seen) return 2;
        seen = true;
        const Str kValue = hs[i].value;
        if (!kValue.len) return 2;
        u32 parsed = 0;
        for (u32 j = 0; j < kValue.len; j++) {
            if (kValue.ptr[j] < '0' || kValue.ptr[j] > '9') return 2;
            parsed = parsed * 10 + static_cast<u32>(kValue.ptr[j] - '0');
            if (parsed > 16) return 2;
        }
        status = static_cast<u8>(parsed);
    }
    return status;
}
inline bool grpc_web_trailer_metadata(const hpack::Header& h) {
    return !h.name.eq({":status", 7}) && !h.name.eq({"content-type", 12}) &&
           !h.name.eq({"content-length", 14});
}
inline bool grpc_web_queue_trailers(GrpcExchange& x, const hpack::Header* hs, u32 n) {
    GrpcWebTrailer trailers[Http2Conn::kMaxHeadersPerReq];
    u32 count = 0;
    for (u32 i = 0; i < n; i++) {
        if (!grpc_web_trailer_metadata(hs[i])) continue;
        if (count >= Http2Conn::kMaxHeadersPerReq) return false;
        trailers[count++] = {hs[i].name, hs[i].value};
    }
    if (!grpc_web_encode_trailer_envelope(trailers,
                                          count,
                                          x.response_trailers,
                                          sizeof(x.response_trailers),
                                          x.response_trailers_len))
        return false;
    x.response_trailers_offset = 0;
    x.web_trailer_queued = true;
    x.web_body_flushed = false;
    x.web_trailer_flushed = false;
    return true;
}
inline bool grpc_web_queue_status_trailer(GrpcExchange& x, u8 code) {
    char digits[2] = {static_cast<char>('0' + code / 10), static_cast<char>('0' + code % 10)};
    const Str value = code >= 10 ? Str{digits, 2} : Str{digits + 1, 1};
    const hpack::Header status{{"grpc-status", 11}, value};
    return grpc_web_queue_trailers(x, &status, 1);
}
template <typename Loop>
inline void grpc_web_kick_h1(Loop* loop, GrpcExchange& x) {
    if (x.web_h1 && x.web_h1_kick && x.downstream)
        x.web_h1_kick(loop, static_cast<ConnectionBase&>(*x.downstream));
}
inline bool grpc_web_force_content_type(GrpcExchange& x,
                                        hpack::Header* headers,
                                        u32* count,
                                        u32 capacity) {
    const Str value = x.web_mode == GrpcWebContentType::Text ? Str{"application/grpc-web-text", 25}
                                                             : Str{"application/grpc-web", 20};
    bool found = false;
    for (u32 i = 0; i < *count;) {
        if (headers[i].name.eq({"content-length", 14})) {
            for (u32 move = i + 1; move < *count; move++) headers[move - 1] = headers[move];
            (*count)--;
            continue;
        }
        if (!headers[i].name.eq({"content-type", 12})) {
            i++;
            continue;
        }
        if (!found) {
            headers[i].value = value;
            found = true;
            i++;
        } else {
            for (u32 move = i + 1; move < *count; move++) headers[move - 1] = headers[move];
            (*count)--;
        }
    }
    if (found) return true;
    if (*count >= capacity) return false;
    headers[*count] = {{"content-type", 12}, value};
    (*count)++;
    return true;
}
inline bool grpc_web_is_trailer_only(const hpack::Header& h) {
    return h.name.eq({"grpc-status", 11}) || h.name.eq({"grpc-message", 12}) ||
           h.name.eq({"grpc-status-details-bin", 23});
}
inline bool grpc_web_response_boundary(const GrpcExchange& x) {
    if (x.staged_response_message.header_bytes || x.staged_response_message.remaining) return false;
    return x.web_mode != GrpcWebContentType::Text || !x.web_pending_output_offset ||
           x.web_pending_output_offset == x.web_pending_output_len;
}
inline u32 grpc_web_drop_unstaged_response(GrpcExchange& x) {
    const u32 dropped = x.download_len;
    x.download_len = 0;
    x.response_trailers_len = x.response_trailers_offset = 0;
    x.web_trailer_queued = false;
    x.web_trailer_encoding = false;
    x.web_trailer_wire_started = false;
    if (x.web_mode == GrpcWebContentType::Text) {
        x.response_base64.init();
        x.web_encoded_message.init(0xffffffffu);
        x.web_encode_boundary_pending = false;
        x.web_pending_output_offset = x.web_pending_output_len = 0;
        x.web_pending_native_len = 0;
        x.web_pending_output_is_trailer = false;
        x.web_body_flushed = false;
    }
    return dropped;
}
inline u32 grpc_web_prepare_failure(GrpcExchange& x) {
    if (!x.failure || x.web_failure_prepared) return 0;
    x.web_failure_prepared = true;
    x.web_response_invalid =
        x.web_response_invalid || x.web_trailer_wire_started || !grpc_web_response_boundary(x);
    if (x.web_response_invalid) return 0;
    x.response_end = true;
    const u32 dropped = grpc_web_drop_unstaged_response(x);
    if (!grpc_web_queue_status_trailer(x, x.failure)) x.web_response_invalid = true;
    return dropped;
}
inline bool grpc_web_queue_h1_headers(GrpcExchange& x,
                                      const hpack::Header* headers,
                                      u32 count,
                                      bool seed_error,
                                      bool mutations_applied = false) {
    hpack::Header filtered[Http2Conn::kMaxHeadersPerReq];
    u32 filtered_count = 0;
    if (seed_error) {
        filtered[filtered_count++] = {{":status", 7}, {"200", 3}};
        filtered[filtered_count++] = {{"content-type", 12}, {"application/grpc", 16}};
    } else {
        for (u32 i = 0; i < count; i++) {
            if (!headers[i].name.len || headers[i].name.ptr[0] == ':' ||
                headers[i].name.eq({"content-length", 14}) ||
                headers[i].name.eq({"transfer-encoding", 17}) ||
                headers[i].name.eq({"connection", 10}))
                continue;
            if (filtered_count >= Http2Conn::kMaxHeadersPerReq) return false;
            filtered[filtered_count++] = headers[i];
        }
    }
    if ((!mutations_applied && !grpc_apply_response_mutations(
                                   x, filtered, &filtered_count, Http2Conn::kMaxHeadersPerReq)) ||
        !grpc_web_force_content_type(x, filtered, &filtered_count, Http2Conn::kMaxHeadersPerReq))
        return false;
    u32 offset = 0;
    for (u32 i = 0; i < filtered_count; i++) {
        const auto& header = filtered[i];
        if (!header.name.len || header.name.ptr[0] == ':' ||
            header.name.eq({"content-length", 14}) || header.name.eq({"transfer-encoding", 17}) ||
            header.name.eq({"connection", 10}))
            continue;
        const u32 needed = header.name.len + 2 + header.value.len + 2;
        if (needed > sizeof(x.response_headers) - offset) return false;
        __builtin_memcpy(x.response_headers + offset, header.name.ptr, header.name.len);
        offset += header.name.len;
        x.response_headers[offset++] = ':';
        x.response_headers[offset++] = ' ';
        if (header.value.len)
            __builtin_memcpy(x.response_headers + offset, header.value.ptr, header.value.len);
        offset += header.value.len;
        x.response_headers[offset++] = '\r';
        x.response_headers[offset++] = '\n';
    }
    x.response_headers_len = offset;
    return true;
}
template <typename Loop>
inline void grpc_release_slot(Loop* loop, GrpcExchange& x) {
    if (!x.slot_held) return;
    loop->upstream_release(x.upstream_id);
    x.slot_held = false;
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
template <typename Loop>
inline void grpc_record_connect_result(Loop* loop,
                                       const Connection& conn,
                                       bool success,
                                       u64 now_us) {
    const RouteConfig* current = loop->config_ptr ? *loop->config_ptr : nullptr;
    if (current != conn.request_config) return;
    grpc_record_connect_result(conn, success, now_us);
}
template <typename Loop>
inline void grpc_record_session_failure(Loop* loop, Connection& conn, u64 now_us) {
    if (!conn.h2 || conn.h2->grpc.session_failure_recorded) return;
    auto& h = *conn.h2;
    if (h.peer_settings_seen) {
        bool accepted_unfinished = false;
        for (auto* x : h.grpc.streams) {
            if (x && x->request_headers_sent && !x->response_end &&
                !grpc_rejected_by_goaway(h, *x)) {
                accepted_unfinished = true;
                break;
            }
        }
        if (!accepted_unfinished) return;
    }
    grpc_record_handshake_result(loop, conn, false, now_us);
}
template <typename Loop>
inline void grpc_record_rpc_success(Loop* loop, Connection& conn, u64 now_us) {
    if (!conn.h2) return;
    const RouteConfig* current = loop->config_ptr ? *loop->config_ptr : nullptr;
    if (current != conn.request_config) return;
    grpc_record_connect_result(conn, true, now_us);
}
inline bool grpc_parse_content_length(Str value, u32* out) {
    if (value.len == 0) return false;
    u32 parsed = 0;
    for (u32 i = 0; i < value.len; i++) {
        if (value.ptr[i] < '0' || value.ptr[i] > '9') return false;
        const u32 digit = static_cast<u32>(value.ptr[i] - '0');
        if (parsed > (0xffffffffu - digit) / 10u) return false;
        parsed = parsed * 10u + digit;
    }
    *out = parsed;
    return true;
}
template <typename Loop>
inline void grpc_detach_upstream_exchange(Loop* loop, Http2Conn& h, GrpcExchange& x) {
    h.consume_data(x.upstream_stream, x.download_len);
    if (x.request_headers_sent) grpc_queue_cancel(h, x.upstream_stream);
    if (auto* stream = h.find_stream(x.upstream_stream)) stream->state = Http2StreamState::Closed;
    grpc_detach(h, &x);
    x.upstream = nullptr;
    grpc_release_slot(loop, x);
}
inline bool grpc_idle_upstream_should_close(
    const GrpcProxyState& g, bool peer_goaway, bool draining, u64 now_us, u64 keepalive_us) {
    return g.active == 0 && (draining || peer_goaway || now_us - g.idle_since_us >= keepalive_us);
}
template <typename Loop>
void grpc_response_headers(
    void* ctx, Http2Conn& h, u32 sid, const hpack::Header* hs, u32 n, bool end) {
    auto* dispatch = static_cast<GrpcClientDispatch<Loop>*>(ctx);
    auto* x = grpc_find(h, sid);
    if (!x) return;
    bool status = false;
    u32 http_status = 0;
    bool content_type = false;
    u32 content_type_count = 0;
    bool invalid_content_length = false;
    const bool web_response =
        x->web_mode == GrpcWebContentType::Binary || x->web_mode == GrpcWebContentType::Text;
    for (u32 i = 0; i < n; i++) {
        if (hs[i].name.eq({":status", 7})) {
            if (hs[i].value.len == 3 && hs[i].value.ptr[0] == '1') return;
            status = hs[i].value.eq({"200", 3});
            if (hs[i].value.len == 3)
                http_status =
                    static_cast<u32>((hs[i].value.ptr[0] - '0') * 100 +
                                     (hs[i].value.ptr[1] - '0') * 10 + hs[i].value.ptr[2] - '0');
        }
        if (hs[i].name.eq({"content-type", 12})) {
            content_type_count++;
            content_type = web_response ? grpc_web_native_proto_content_type(hs[i].value)
                                        : grpc_content_type(hs[i].value);
        }
        if (hs[i].name.eq({"content-length", 14})) {
            u32 length = 0;
            if (x->has_response_length || !grpc_parse_content_length(hs[i].value, &length))
                invalid_content_length = true;
            else {
                x->has_response_length = true;
                x->expected_response_bytes = length;
            }
        }
    }
    if (web_response && content_type_count != 1) content_type = false;
    if (!status || !content_type || invalid_content_length) {
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
        if (invalid_content_length || (web_response && status && !content_type)) x->failure = 13;
        grpc_detach_upstream_exchange(dispatch->loop, h, *x);
        return;
    }
    hpack::Header filtered[Http2Conn::kMaxHeadersPerReq];
    u32 filtered_n = 0;
    const bool backend_terminal = end && grpc_has_status(hs, n);
    for (u32 i = 0; i < n; i++) {
        if (!grpc_response_header_allowed(hs[i])) continue;
        if (filtered_n < Http2Conn::kMaxHeadersPerReq) filtered[filtered_n++] = hs[i];
    }
    if (!grpc_apply_response_mutations(*x, filtered, &filtered_n, Http2Conn::kMaxHeadersPerReq)) {
        x->failure = 8;
        x->response_end = true;
        grpc_detach_upstream_exchange(dispatch->loop, h, *x);
        return;
    }
    const bool web =
        x->web_mode == GrpcWebContentType::Binary || x->web_mode == GrpcWebContentType::Text;
    if (web && backend_terminal) {
        if (const u8 framing_status = x->response_message.feed(nullptr, 0, true)) {
            x->failure = framing_status;
            x->web_response_invalid = !grpc_web_response_boundary(*x);
        }
    }
    if (web) {
        if (backend_terminal && !grpc_web_queue_trailers(*x, filtered, filtered_n)) {
            x->failure = 13;
            x->web_response_invalid = !grpc_web_response_boundary(*x);
        }
        if (!grpc_web_force_content_type(*x, filtered, &filtered_n, Http2Conn::kMaxHeadersPerReq)) {
            x->failure = 8;
        }
    }
    const bool filtered_has_status = grpc_has_status(filtered, filtered_n);
    const u8 observed_status = end ? grpc_observed_status(filtered, filtered_n) : 2;
    if (web && backend_terminal) {
        for (u32 i = 0; i < filtered_n;) {
            if (!grpc_web_is_trailer_only(filtered[i])) {
                i++;
                continue;
            }
            for (u32 move = i + 1; move < filtered_n; move++) filtered[move - 1] = filtered[move];
            filtered_n--;
        }
    }
    if (x->web_h1 && web) {
        if (!grpc_web_queue_h1_headers(*x, filtered, filtered_n, false, true)) x->failure = 8;
    } else {
        x->response_headers_len = http2_write_headers(x->response_headers,
                                                      sizeof(x->response_headers),
                                                      x->downstream_stream,
                                                      filtered,
                                                      filtered_n,
                                                      web ? false : backend_terminal);
    }
    if (!x->response_headers_len) {
        x->failure = 8;
        x->response_end = true;
        grpc_detach_upstream_exchange(dispatch->loop, h, *x);
        return;
    }
    x->response_end = end;
    // END_STREAM on the initial headers is a trailers-only response. Response
    // mutations apply to those headers, so telemetry must observe the same
    // filtered grpc-status that the downstream receives.
    if (end) x->response_status = observed_status;
    if (end && (!grpc_has_status(hs, n) || !filtered_has_status)) x->failure = 2;
    if (web && end && !backend_terminal && !x->failure) x->failure = 2;
    if (end && x->has_response_length && x->expected_response_bytes != x->response_bytes)
        x->failure = 13;
    if (x->response_end && !x->failure && x->upstream && grpc_has_status(hs, n))
        grpc_record_rpc_success(dispatch->loop, *x->upstream, monotonic_us());
    if (x->response_end) grpc_release_slot(dispatch->loop, *x);
    grpc_web_kick_h1(dispatch->loop, *x);
}
template <typename Loop>
void grpc_response_trailers(
    void* ctx, Http2Conn& h, u32 sid, const hpack::Header* hs, u32 n, bool) {
    auto* dispatch = static_cast<GrpcClientDispatch<Loop>*>(ctx);
    auto* x = grpc_find(h, sid);
    if (!x) return;
    const bool web =
        x->web_mode == GrpcWebContentType::Binary || x->web_mode == GrpcWebContentType::Text;
    if (web) {
        for (u32 i = 0; i < n; i++)
            if (hs[i].name.eq({"content-length", 14})) x->failure = 13;
        if (!grpc_has_status(hs, n)) x->failure = 2;
        if (const u8 framing_status = x->response_message.feed(nullptr, 0, true)) {
            x->failure = framing_status;
            x->web_response_invalid = !grpc_web_response_boundary(*x);
        }
        if (x->has_response_length && x->expected_response_bytes != x->response_bytes)
            x->failure = 13;
        x->response_status = grpc_observed_status(hs, n);
        if (!x->failure && !grpc_web_queue_trailers(*x, hs, n)) {
            x->failure = 13;
            x->web_response_invalid = !grpc_web_response_boundary(*x);
        }
        x->response_end = true;
        if (!x->failure && x->upstream && grpc_has_status(hs, n))
            grpc_record_rpc_success(dispatch->loop, *x->upstream, monotonic_us());
        grpc_release_slot(dispatch->loop, *x);
        grpc_web_kick_h1(dispatch->loop, *x);
        return;
    }
    hpack::Header filtered[Http2Conn::kMaxHeadersPerReq];
    u32 filtered_n = 0;
    for (u32 i = 0; i < n; i++) {
        if (hs[i].name.eq({"content-length", 14})) {
            x->failure = 13;
        }
        if (!grpc_response_header_allowed(hs[i])) continue;
        if (filtered_n < Http2Conn::kMaxHeadersPerReq) filtered[filtered_n++] = hs[i];
    }
    x->response_trailers_len = http2_write_headers(x->response_trailers,
                                                   sizeof(x->response_trailers),
                                                   x->downstream_stream,
                                                   filtered,
                                                   filtered_n,
                                                   true);
    if (!x->response_trailers_len) {
        x->failure = 8;
        x->response_end = true;
        grpc_detach_upstream_exchange(dispatch->loop, h, *x);
        return;
    }
    if (!grpc_has_status(hs, n)) x->failure = 2;
    if (const u8 framing_status = x->response_message.feed(nullptr, 0, true))
        x->failure = framing_status;
    if (x->has_response_length && x->expected_response_bytes != x->response_bytes) x->failure = 13;
    x->response_status = grpc_observed_status(hs, n);
    x->response_end = true;
    if (!x->failure && x->upstream && grpc_has_status(hs, n))
        grpc_record_rpc_success(dispatch->loop, *x->upstream, monotonic_us());
    grpc_release_slot(dispatch->loop, *x);
}
template <typename Loop>
void grpc_response_data(void* ctx, Http2Conn& h, u32 sid, const u8* data, u32 len, bool end) {
    auto* dispatch = static_cast<GrpcClientDispatch<Loop>*>(ctx);
    auto* x = grpc_find(h, sid);
    if (!x) {
        h.consume_data(sid, len);
        return;
    }
    const bool web =
        x->web_mode == GrpcWebContentType::Binary || x->web_mode == GrpcWebContentType::Text;
    const u8 framing_status = x->response_message.feed(data, len, end);
    if (framing_status) {
        x->failure = framing_status;
        if (web) x->web_response_invalid = !grpc_web_response_boundary(*x);
        x->response_end = true;
        h.consume_data(sid, len);
        grpc_detach_upstream_exchange(dispatch->loop, h, *x);
        return;
    }
    if (len > sizeof(x->download) - x->download_len) {
        x->failure = 8;
        x->response_end = true;
        if (web) x->web_response_invalid = !grpc_web_response_boundary(*x);
        h.consume_data(sid, len);
        grpc_detach_upstream_exchange(dispatch->loop, h, *x);
        return;
    }
    if (len) __builtin_memcpy(x->download + x->download_len, data, len);
    x->download_len += len;
    x->response_bytes += len;
    if (x->has_response_length && x->response_bytes > x->expected_response_bytes) x->failure = 13;
    if (x->failure == 13) {
        x->response_end = true;
        if (web) x->web_response_invalid = !grpc_web_response_boundary(*x);
        grpc_detach_upstream_exchange(dispatch->loop, h, *x);
        return;
    }
    if (end) {
        if (x->has_response_length && x->expected_response_bytes != x->response_bytes)
            x->failure = 13;
        else if (!x->failure)
            x->failure = 2;
        x->response_end = true;
        if (web && x->failure) x->web_response_invalid = !grpc_web_response_boundary(*x);
        grpc_release_slot(dispatch->loop, *x);
    }  // gRPC requires status trailers.
    grpc_web_kick_h1(dispatch->loop, *x);
}
template <typename Loop>
void grpc_response_reset(void* ctx, Http2Conn& h, u32 sid, Http2Error error) {
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
        if (x->web_mode == GrpcWebContentType::Binary || x->web_mode == GrpcWebContentType::Text) {
            const u32 outstanding = x->download_len;
            (void)grpc_web_prepare_failure(*x);
            x->response_end = true;
            h.consume_data(x->upstream_stream, outstanding);
        } else {
            x->response_end = true;
            h.consume_data(x->upstream_stream, x->download_len);
        }
        auto* d = static_cast<GrpcClientDispatch<Loop>*>(ctx);
        Connection* down = x->downstream;
        if (auto* stream = h.find_stream(x->upstream_stream))
            stream->state = Http2StreamState::Closed;
        grpc_detach(h, x);
        x->upstream = nullptr;
        grpc_release_slot(d->loop, *x);
        if (down) grpc_kick_downstream(d->loop, *down);
    }
}

template <typename Loop>
void grpc_on_upstream_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result <= 0 || static_cast<u32>(ev.result) > conn.send_buf.len() - conn.send_progress) {
        if (conn.h2) grpc_record_session_failure(loop, conn, monotonic_us());
        loop->close_conn(conn);
        return;
    }
    if (conn.h2->grpc.client_tls.ssl_ctx && !conn.h2->grpc.tls_verified) {
        SSL* ssl = conn.tls_engine.ssl ? conn.tls_engine.ssl : conn.tls;
        if (!tls_client_peer_valid(ssl)) {
            grpc_record_handshake_result(loop, conn, false, monotonic_us());
            loop->close_conn(conn);
            return;
        }
        conn.h2->grpc.tls_verified = true;
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
    // Readiness backends bootstrap SSL_connect through the preface write;
    // never send an RPC header until peer identity and h2 ALPN are verified.
    if (g.client_tls.ssl_ctx && !g.tls_verified && g.preface_sent) return;
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
            if (!x) continue;
            auto* stream = h.find_stream(x->upstream_stream);
            if (x->request_headers_sent) {
                if (stream && stream->state != Http2StreamState::Closed) opened++;
                continue;
            }
            if (x->failure || x->response_end) continue;
            if (x->upstream_stream < next_header) next_header = x->upstream_stream;
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
                if (x->web_mode == GrpcWebContentType::Text) {
                    if (!x->web_h1 && !x->upload_len && x->upload_raw_credit) {
                        x->downstream->h2->consume_data(x->downstream_stream, x->upload_raw_credit);
                        x->upload_raw_credit = 0;
                    }
                } else if (!x->web_h1)
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
void grpc_tls_ready(Loop* loop, Connection& conn) {
    conn.h2->grpc.tls_verified = true;
    conn.h2->grpc.connecting = false;
    grpc_drive_upstream(loop, conn);
}

template <typename Loop>
void grpc_on_upstream_data(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result <= 0 || !conn.h2) {
        if (conn.h2) {
            if (conn.h2->grpc.client_tls.ssl_ctx && !conn.h2->grpc.tls_verified)
                grpc_record_handshake_result(loop, conn, false, monotonic_us());
            else
                grpc_record_session_failure(loop, conn, monotonic_us());
        }
        loop->close_conn(conn);
        return;
    }
    auto& h = *conn.h2;
    auto& g = h.grpc;
    if (g.connecting) return;
    if (g.client_tls.ssl_ctx && !g.tls_verified) {
        SSL* ssl = conn.tls_engine.ssl ? conn.tls_engine.ssl : conn.tls;
        // Downstream window-credit pumps may call this without a network read.
        // An in-progress client handshake has not produced a peer verdict yet.
        if (ssl && !tls_handshake_finished(ssl)) return;
        if (!tls_client_peer_valid(ssl)) {
            grpc_record_handshake_result(loop, conn, false, monotonic_us());
            loop->close_conn(conn);
            return;
        }
        g.tls_verified = true;
    }
    GrpcClientDispatch<Loop> dispatch{loop, &conn};
    h.cb_ctx = &dispatch;
    h.on_headers = &grpc_response_headers<Loop>;
    h.on_trailers = &grpc_response_trailers<Loop>;
    h.on_data = &grpc_response_data<Loop>;
    h.on_reset = &grpc_response_reset<Loop>;
    const bool settings_seen_before = h.peer_settings_seen;
    g.busy = true;
    u32 written = 0;
    struct DownstreamSnapshot {
        Connection* conn;
        Http2Conn* h2;
        u32 handler_gen;
    } downstreams[64];
    u32 downstream_count = 0;
    for (auto* x : g.streams) {
        if (!x || !x->downstream) continue;
        bool seen = false;
        for (u32 i = 0; i < downstream_count; i++)
            if (downstreams[i].conn == x->downstream) seen = true;
        if (!seen)
            downstreams[downstream_count++] = {
                x->downstream, x->downstream->h2, x->downstream->handler_gen};
    }
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
        grpc_record_session_failure(loop, conn, monotonic_us());
        g.busy = false;
        loop->close_conn(conn);
        return;
    }
    if (!settings_seen_before && h.peer_settings_seen)
        grpc_record_handshake_result(loop, conn, true, monotonic_us());
    for (u32 i = 0; i < 64; i++) {
        auto* x = g.streams[i];
        if (!x) continue;
        if (grpc_rejected_by_goaway(h, *x)) {
            x->failure = 14;
            x->response_end = true;
            grpc_detach_upstream_exchange(loop, h, *x);
        }
    }
    // RST/GOAWAY callbacks run while the H2 parser is busy. Snapshot
    // downstream connections before parsing because callbacks may detach the
    // exchange, then kick each connection once after releasing busy.
    g.busy = false;
    // A timer-arm failure can leave a downstream error parked indefinitely.
    for (u32 i = 0; i < downstream_count; i++) {
        auto& snapshot = downstreams[i];
        if (!snapshot.conn || snapshot.conn->h2 != snapshot.h2 ||
            snapshot.conn->handler_gen != snapshot.handler_gen)
            continue;
        grpc_refresh_timer(loop, *snapshot.conn);
        grpc_kick_downstream(loop, *snapshot.conn);
    }
    grpc_drive_upstream(loop, conn);
    if (conn.h2 && !loop->submit_recv(conn)) loop->close_conn(conn);
}

template <typename Loop>
void grpc_connected(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result < 0) {
        grpc_record_connect_result(loop, conn, false, monotonic_us());
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
    const auto& target = conn.request_config->upstreams[conn.upstream_idx];
    if (target.tls.enabled) {
        auto& context = conn.h2->grpc.client_tls;
        if (!init_tls_client_context(context, target.tls)) {
            grpc_record_handshake_result(loop, conn, false, monotonic_us());
            loop->close_conn(conn);
            return;
        }
        if constexpr (requires { loop->tls_setup(conn, &context, target.tls.server_name); }) {
            if (!loop->tls_setup(conn, &context, target.tls.server_name) ||
                !loop->grow_h2_tls_input(conn)) {
                grpc_record_handshake_result(loop, conn, false, monotonic_us());
                loop->close_conn(conn);
                return;
            }
            conn.tls_pending_on_recv = &grpc_on_upstream_data<Loop>;
            tls_process(loop, conn);
            return;
        } else {
            auto ssl = create_tls_client_ssl(context, conn.fd, target.tls.server_name);
            if (!ssl) {
                grpc_record_handshake_result(loop, conn, false, monotonic_us());
                loop->close_conn(conn);
                return;
            }
            conn.tls = ssl.value();
            conn.tls_active = true;
            conn.tls_handshake_complete = false;
        }
    }
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
    const GrpcWebContentType web_mode = grpc_request_mode(req);
    if (!cfg || uid >= cfg->upstream_count || !cfg->upstreams[uid].http2 ||
        req.method != HttpMethod::POST ||
        (web_mode != GrpcWebContentType::Native && web_mode != GrpcWebContentType::Binary &&
         web_mode != GrpcWebContentType::Text) ||
        down.h2->grpc.active >= 64)
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
    x->web_h1 = down.h2->grpc.web_h1_kick != nullptr;
    x->web_h1_kick = down.h2->grpc.web_h1_kick;
    x->web_mode = web_mode;
    constexpr u32 kWebFramingLimit = 0xffffffffu;
    const u32 request_message_limit =
        target.max_request_message_bytes
            ? target.max_request_message_bytes
            : (web_mode == GrpcWebContentType::Native ? 0 : kWebFramingLimit);
    const u32 response_message_limit =
        target.max_response_message_bytes
            ? target.max_response_message_bytes
            : (web_mode == GrpcWebContentType::Native ? 0 : kWebFramingLimit);
    x->request_message.init(request_message_limit);
    x->response_message.init(response_message_limit);
    if (!grpc_snapshot_response_mutations(down, *x)) {
        loop->pool.free(reinterpret_cast<u8*>(x));
        return false;
    }
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
    for (u32 i = 0; i < nh; i++) {
        if (!grpc_request_header_allowed(hs[i]) || filtered_n >= Http2Conn::kMaxHeadersPerReq)
            continue;
        if (web_mode == GrpcWebContentType::Text && hs[i].name.eq({"content-length", 14})) continue;
        filtered[filtered_n] = hs[i];
        if (hs[i].name.eq({":scheme", 7}))
            filtered[filtered_n].value = target.tls.enabled ? Str{"https", 5} : Str{"http", 4};
        if (web_mode != GrpcWebContentType::Native && hs[i].name.eq({"content-type", 12}))
            filtered[filtered_n].value = {"application/grpc", 16};
        filtered_n++;
    }
    if (web_mode != GrpcWebContentType::Native) {
        for (u32 i = 0; i < filtered_n;) {
            if (!filtered[i].name.eq({"te", 2})) {
                i++;
                continue;
            }
            for (u32 move = i + 1; move < filtered_n; move++) filtered[move - 1] = filtered[move];
            filtered_n--;
        }
        if (filtered_n >= Http2Conn::kMaxHeadersPerReq) {
            stream->state = Http2StreamState::Closed;
            loop->pool.free(reinterpret_cast<u8*>(x));
            if (fresh) loop->close_conn(*up);
            return false;
        }
        filtered[filtered_n++] = {{"te", 2}, {"trailers", 8}};
    }
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
    x->started_us = now;
    x->observed = true;
    if (loop->metrics) loop->metrics->on_grpc_start();
    auto& entry = x->log_entry;
    entry.status = 200;
    entry.method = static_cast<u8>(LogHttpMethod::Post);
    entry.shard_id = down.shard_id;
    entry.addr = down.peer_addr;
    entry.target_state = AccessLogTargetState::Unavailable;
    for (u32 i = 0; i < nh; i++) {
        if (!hs[i].name.eq({":path", 5})) continue;
        const Str kPath = hs[i].value;
        grpc_log_target(entry, kPath);
        break;
    }
    for (u32 i = 0; i + 1 < sizeof(entry.upstream) && i < sizeof(target.name); i++) {
        entry.upstream[i] = target.name[i];
        if (!target.name[i]) break;
    }
    grpc_attach(*down.h2, x);
    grpc_attach(*up->h2, x);
    stream->manual_window = down_stream->manual_window = true;
    down.on_close = &grpc_connection_closed<Loop>;
    if (x->failure) {
        x->response_end = true;
        grpc_detach_upstream_exchange(loop, *up->h2, *x);
        grpc_refresh_timer(loop, down);
        grpc_kick_downstream(loop, down);
        if (fresh) loop->close_conn(*up);
        return true;
    }
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
                      loop->disarm_yield_timer(down);
                      loop->arm_throttle_timer(down, u64{1});
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
            const bool web = x->web_mode == GrpcWebContentType::Binary ||
                             x->web_mode == GrpcWebContentType::Text;
            if (web && x->failure && !x->web_failure_prepared) {
                const u32 dropped = grpc_web_prepare_failure(*x);
                if (dropped && x->upstream)
                    x->upstream->h2->consume_data(x->upstream_stream, dropped);
            }
            if (web && x->failure && !x->web_response_invalid && !x->response_headers_len &&
                !x->response_headers_sent) {
                hpack::Header error_headers[Http2Conn::kMaxHeadersPerReq];
                u32 error_count = 2;
                error_headers[0] = {{":status", 7}, {"200", 3}};
                error_headers[1] = {{"content-type", 12}, {"application/grpc", 16}};
                if (!grpc_apply_response_mutations(
                        *x, error_headers, &error_count, Http2Conn::kMaxHeadersPerReq) ||
                    !grpc_web_force_content_type(
                        *x, error_headers, &error_count, Http2Conn::kMaxHeadersPerReq)) {
                    x->web_response_invalid = true;
                } else {
                    x->response_headers_len = http2_write_headers(x->response_headers,
                                                                  sizeof(x->response_headers),
                                                                  x->downstream_stream,
                                                                  error_headers,
                                                                  error_count,
                                                                  false);
                }
            }
            u32 n = 0;
            bool done = false;
            if (x->failure && (!web || x->web_response_invalid)) {
                if (web && cap - total < 13) continue;
                if (web) {
                    n = write_rst_stream(
                        out + total, x->downstream_stream, Http2Error::InternalError);
                    done = n != 0;
                } else {
                    n = grpc_error_headers(out + total,
                                           cap - total,
                                           x->downstream_stream,
                                           x->failure,
                                           x->response_headers_sent);
                    done = n != 0;
                }
            } else if (!x->response_headers_sent && x->response_headers_len) {
                if (x->response_headers_len > cap - total) continue;
                n = x->response_headers_len;
                __builtin_memcpy(out + total, x->response_headers, n);
                x->response_headers_sent = true;
                done = x->response_end && !x->download_len && !x->response_trailers_len;
            } else if (x->response_headers_sent && (x->web_mode == GrpcWebContentType::Binary ||
                                                    x->web_mode == GrpcWebContentType::Text)) {
                const bool text = x->web_mode == GrpcWebContentType::Text;
                const u32 window = stream->send_window > 0 && h.conn_send_window > 0
                                       ? (stream->send_window < static_cast<i32>(h.conn_send_window)
                                              ? static_cast<u32>(stream->send_window)
                                              : static_cast<u32>(h.conn_send_window))
                                       : 0;
                if (cap - total <= 9 || !window) continue;
                u32 amount = 0;
                const u8* payload = nullptr;
                bool final = false;
                bool consume_download = false;
                if (!text) {
                    if (x->download_len) {
                        amount = x->download_len;
                        if (amount > cap - total - 9) amount = cap - total - 9;
                        if (amount > h.peer_settings.max_frame_size)
                            amount = h.peer_settings.max_frame_size;
                        if (amount > window) amount = window;
                        payload = x->download;
                        consume_download = true;
                    } else if (x->response_trailers_offset < x->response_trailers_len) {
                        amount = x->response_trailers_len - x->response_trailers_offset;
                        if (amount > cap - total - 9) amount = cap - total - 9;
                        if (amount > h.peer_settings.max_frame_size)
                            amount = h.peer_settings.max_frame_size;
                        if (amount > window) amount = window;
                        payload = x->response_trailers + x->response_trailers_offset;
                        x->response_trailers_offset += amount;
                        x->web_trailer_wire_started = true;
                    } else if (x->response_end) {
                        final = true;
                    }
                    if (!amount && !final) continue;
                    n = http2_write_data(out + total, x->downstream_stream, payload, amount, final);
                    if (amount) {
                        if (consume_download) {
                            (void)x->staged_response_message.feed(payload, amount, false);
                            grpc_pop(x->download, x->download_len, amount);
                            if (x->upstream)
                                x->upstream->h2->consume_data(x->upstream_stream, amount);
                        }
                        x->staged_response_bytes += amount;
                        stream->send_window -= static_cast<i32>(amount);
                        h.conn_send_window -= amount;
                    }
                    if (final) done = true;
                } else {
                    // Assemble one DATA payload in owned output. The small pending
                    // quartet only retains bytes across a flow-control/window tail.
                    u32 budget = cap - total - kFrameHeaderSize;
                    if (budget > window) budget = window;
                    if (budget > h.peer_settings.max_frame_size)
                        budget = h.peer_settings.max_frame_size;
                    u32 batched = 0;
                    u32 download_consumed = 0;
                    while (batched < budget) {
                        bool progressed = false;
                        if (x->web_pending_output_offset == x->web_pending_output_len) {
                            x->web_pending_output_offset = x->web_pending_output_len = 0;
                            x->web_pending_output_is_trailer = false;
                            const bool had_boundary = x->web_encode_boundary_pending;
                            const bool was_flushed = x->web_body_flushed;
                            u32 consumed = 0, written = 0;
                            if (x->web_encode_boundary_pending) {
                                const u8 native_len = x->response_base64.pending_len;
                                for (u8 i = 0; i < native_len; i++)
                                    x->web_pending_native[i] = x->response_base64.pending[i];
                                (void)x->response_base64.flush(
                                    x->web_pending_output, sizeof(x->web_pending_output), written);
                                if (written == 4) x->web_pending_native_len = native_len;
                                x->web_encode_boundary_pending = false;
                            } else if (x->download_len > download_consumed ||
                                       (!x->web_trailer_encoding &&
                                        x->response_base64.pending_len == 3)) {
                                const u8 previous_len = x->response_base64.pending_len;
                                u8 native[3]{};
                                for (u8 i = 0; i < previous_len; i++)
                                    native[i] = x->response_base64.pending[i];
                                const u32 needed = previous_len < 3 ? 3u - previous_len : 0u;
                                for (u32 i = 0;
                                     i < needed && i < x->download_len - download_consumed;
                                     i++)
                                    native[previous_len + i] = x->download[download_consumed + i];
                                const u32 source_len = x->web_encoded_message.next_span(
                                    x->download_len - download_consumed);
                                (void)x->response_base64.feed(x->download + download_consumed,
                                                              source_len,
                                                              consumed,
                                                              x->web_pending_output,
                                                              sizeof(x->web_pending_output),
                                                              written);
                                if (consumed) {
                                    (void)x->web_encoded_message.feed(
                                        x->download + download_consumed, consumed, false);
                                    if (!x->web_encoded_message.header_bytes &&
                                        !x->web_encoded_message.remaining)
                                        x->web_encode_boundary_pending = true;
                                }
                                if (written == 4) {
                                    __builtin_memcpy(x->web_pending_native, native, 3);
                                    x->web_pending_native_len = 3;
                                }
                                download_consumed += consumed;
                            } else if (x->response_trailers_offset < x->response_trailers_len ||
                                       (x->web_trailer_encoding &&
                                        x->response_base64.pending_len == 3)) {
                                const u32 left =
                                    x->response_trailers_len - x->response_trailers_offset;
                                if (!x->web_trailer_encoding) {
                                    x->web_pending_native_len = x->response_base64.pending_len;
                                    for (u8 i = 0; i < x->web_pending_native_len; i++)
                                        x->web_pending_native[i] = x->response_base64.pending[i];
                                }
                                (void)x->response_base64.feed(
                                    x->response_trailers + x->response_trailers_offset,
                                    left,
                                    consumed,
                                    x->web_pending_output,
                                    sizeof(x->web_pending_output),
                                    written);
                                x->response_trailers_offset += consumed;
                                if (consumed || written) x->web_trailer_encoding = true;
                                if (written) x->web_pending_output_is_trailer = true;
                            } else if (x->response_end) {
                                const u8 native_len =
                                    x->web_trailer_encoding ? 0 : x->response_base64.pending_len;
                                for (u8 i = 0; i < native_len; i++)
                                    x->web_pending_native[i] = x->response_base64.pending[i];
                                (void)x->response_base64.flush(
                                    x->web_pending_output, sizeof(x->web_pending_output), written);
                                if (written == 4) x->web_pending_native_len = native_len;
                                x->web_pending_output_is_trailer = x->web_trailer_encoding;
                                x->web_body_flushed = true;
                            }
                            x->web_pending_output_len = static_cast<u8>(written);
                            progressed = consumed || written || had_boundary ||
                                         was_flushed != x->web_body_flushed;
                        }
                        if (x->web_pending_output_offset < x->web_pending_output_len) {
                            u32 chunk = x->web_pending_output_len - x->web_pending_output_offset;
                            if (chunk > budget - batched) chunk = budget - batched;
                            __builtin_memcpy(out + total + kFrameHeaderSize + batched,
                                             x->web_pending_output + x->web_pending_output_offset,
                                             chunk);
                            x->web_pending_output_offset += static_cast<u8>(chunk);
                            batched += chunk;
                            if (x->web_pending_output_is_trailer)
                                x->web_trailer_wire_started = true;
                            if (x->web_pending_output_offset == x->web_pending_output_len &&
                                x->web_pending_native_len) {
                                (void)x->staged_response_message.feed(
                                    x->web_pending_native, x->web_pending_native_len, false);
                                x->web_pending_native_len = 0;
                            }
                            if (x->web_pending_output_offset == x->web_pending_output_len)
                                x->web_pending_output_is_trailer = false;
                        } else if (x->response_end && x->web_body_flushed) {
                            final = true;
                            break;
                        } else if (!progressed) {
                            break;
                        }
                    }
                    // Compact once per DATA batch, rather than moving the queue
                    // after every three input bytes.
                    if (download_consumed) {
                        grpc_pop(x->download, x->download_len, download_consumed);
                        if (x->upstream)
                            x->upstream->h2->consume_data(x->upstream_stream, download_consumed);
                    }
                    if (x->response_end && x->web_body_flushed &&
                        x->web_pending_output_offset == x->web_pending_output_len)
                        final = true;
                    if (!batched && !final) continue;
                    const Http2FrameHeader header{batched,
                                                  x->downstream_stream,
                                                  static_cast<u8>(Http2FrameType::Data),
                                                  final ? http2_flag::kEndStream : u8{0}};
                    n = write_frame_header(out + total, header) + batched;
                    x->staged_response_bytes += batched;
                    stream->send_window -= static_cast<i32>(batched);
                    h.conn_send_window -= batched;
                    if (final) done = true;
                }
            } else if (x->response_headers_sent && x->download_len && stream->send_window > 0 &&
                       h.conn_send_window > 0 && cap - total > 9) {
                u32 amount = x->download_len;
                if (amount > cap - total - 9) amount = cap - total - 9;
                if (amount > h.peer_settings.max_frame_size)
                    amount = h.peer_settings.max_frame_size;
                if (amount > static_cast<u32>(stream->send_window)) amount = stream->send_window;
                if (amount > static_cast<u64>(h.conn_send_window)) amount = h.conn_send_window;
                n = http2_write_data(out + total, x->downstream_stream, x->download, amount, false);
                x->staged_response_bytes += amount;
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
                x->response_end_sent = true;
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
    if (!down.h2) return;
    if (down.h2->grpc.web_h1_kick) {
        down.h2->grpc.web_h1_kick(loop, static_cast<ConnectionBase&>(down));
        return;
    }
    if (down.h2->grpc.busy || down.on_send || down.h2->async_stream) return;
    on_h2_data<Loop>(static_cast<void*>(loop), down, {down.id, 1, 0, 0, IoEventType::Recv, 0});
}

template <typename Loop>
void grpc_request_data(
    Loop* loop, Connection& down, GrpcExchange& x, const u8* data, u32 len, bool end) {
    x.request_bytes += len;
    if (x.failure || !x.upstream) {
        if (!x.web_h1) down.h2->consume_data(x.downstream_stream, len);
        return;
    }
    const u32 upload_before = x.upload_len;
    const u8* upload_data = data;
    u32 upload_len = len;
    if (x.web_mode == GrpcWebContentType::Text) {
        if (!x.web_h1 && len > UINT32_MAX - x.upload_raw_credit) {
            if (!x.web_h1) {
                down.h2->consume_data(x.downstream_stream, x.upload_raw_credit);
                down.h2->consume_data(x.downstream_stream, len);
            }
            x.upload_raw_credit = 0;
            x.upload_len = 0;
            x.failure = 8;
            grpc_detach_upstream_exchange(loop, *x.upstream->h2, x);
            return;
        }
        if (!x.web_h1) x.upload_raw_credit += len;
        u32 consumed = 0;
        const auto status = x.request_base64.feed(data,
                                                  len,
                                                  consumed,
                                                  x.upload + x.upload_len,
                                                  sizeof(x.upload) - x.upload_len,
                                                  upload_len);
        if (status == GrpcWebCodecStatus::Invalid || consumed != len) {
            if (!x.web_h1) down.h2->consume_data(x.downstream_stream, x.upload_raw_credit);
            x.upload_raw_credit = 0;
            x.upload_len = 0;
            x.failure = status == GrpcWebCodecStatus::Invalid ? 13 : 8;
            grpc_detach_upstream_exchange(loop, *x.upstream->h2, x);
            return;
        }
        if (end && x.request_base64.finish() != GrpcWebCodecStatus::Ok) {
            if (!x.web_h1) down.h2->consume_data(x.downstream_stream, x.upload_raw_credit);
            x.upload_raw_credit = 0;
            x.upload_len = 0;
            x.failure = 13;
            grpc_detach_upstream_exchange(loop, *x.upstream->h2, x);
            return;
        }
        upload_data = x.upload + upload_before;
    }
    const u8 framing_status = x.request_message.feed(upload_data, upload_len, end);
    if (framing_status) {
        if (!x.web_h1)
            down.h2->consume_data(
                x.downstream_stream,
                x.web_mode == GrpcWebContentType::Text ? x.upload_raw_credit : len);
        x.upload_raw_credit = 0;
        if (x.web_mode == GrpcWebContentType::Text) x.upload_len = 0;
        x.failure = framing_status;
        grpc_detach_upstream_exchange(loop, *x.upstream->h2, x);
        return;
    }
    if ((x.web_mode != GrpcWebContentType::Text && len > sizeof(x.upload) - x.upload_len) ||
        (x.has_request_length && (x.request_bytes > x.expected_request_bytes ||
                                  (end && x.request_bytes != x.expected_request_bytes)))) {
        if (!x.web_h1)
            down.h2->consume_data(
                x.downstream_stream,
                x.web_mode == GrpcWebContentType::Text ? x.upload_raw_credit : len);
        x.upload_raw_credit = 0;
        if (x.web_mode == GrpcWebContentType::Text) x.upload_len = 0;
        x.failure = 13;
        grpc_detach_upstream_exchange(loop, *x.upstream->h2, x);
        return;
    }
    if (x.web_mode != GrpcWebContentType::Text && len)
        __builtin_memcpy(x.upload + x.upload_len, data, len);
    x.upload_len += upload_len;
    x.request_end = end;
    if (x.web_mode == GrpcWebContentType::Text && !x.upload_len && x.upload_raw_credit) {
        if (!x.web_h1) down.h2->consume_data(x.downstream_stream, x.upload_raw_credit);
        x.upload_raw_credit = 0;
    }
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
        if (!x->request_trailers_len) {
            x->failure = 8;
            grpc_detach_upstream_exchange(d->loop, *x->upstream->h2, *x);
            return;
        }
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
        struct UpstreamSnapshot {
            Connection* conn;
            Http2Conn* h2;
            u32 handler_gen;
        } upstreams[64];
        u32 upstream_count = 0;
        struct DownstreamSnapshot {
            Connection* conn;
            Http2Conn* h2;
            u32 handler_gen;
        } downstreams[64];
        u32 downstream_count = 0;
        for (auto* x : g.streams) {
            if (!x || !x->downstream) continue;
            bool seen = false;
            for (u32 i = 0; i < downstream_count; i++)
                if (downstreams[i].conn == x->downstream) seen = true;
            if (!seen)
                downstreams[downstream_count++] = {
                    x->downstream, x->downstream->h2, x->downstream->handler_gen};
        }
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
            bool seen_upstream = false;
            for (u32 i = 0; i < upstream_count; i++)
                if (upstreams[i].conn == up) seen_upstream = true;
            if (!seen_upstream) upstreams[upstream_count++] = {up, &uh, up->handler_gen};
        }
        for (u32 i = 0; i < upstream_count; i++) {
            auto& snapshot = upstreams[i];
            if (snapshot.conn->h2 != snapshot.h2 ||
                snapshot.conn->handler_gen != snapshot.handler_gen || snapshot.h2->grpc.busy)
                continue;
            grpc_drive_upstream(loop, *snapshot.conn);
        }
        for (u32 i = 0; i < downstream_count; i++) {
            auto& snapshot = downstreams[i];
            if (snapshot.conn->h2 != snapshot.h2 ||
                snapshot.conn->handler_gen != snapshot.handler_gen)
                continue;
            grpc_kick_downstream(loop, *snapshot.conn);
        }
        return;
    }
    conn.yield_armed = true;
}

template <typename Loop>
void grpc_deadline_fired(Loop* loop, Connection& conn) {
    conn.yield_armed = false;
    conn.h2->grpc.timer_deadline_us = 0;
    const u64 now = monotonic_us();
    Http2Conn* downstream_h2 = conn.h2;
    const u32 downstream_handler_gen = conn.handler_gen;
    struct UpstreamSnapshot {
        Connection* conn;
        Http2Conn* h2;
        u32 handler_gen;
    } upstreams[64];
    u32 upstream_count = 0;
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
        bool seen_upstream = false;
        for (u32 i = 0; i < upstream_count; i++)
            if (upstreams[i].conn == up) seen_upstream = true;
        if (!seen_upstream) upstreams[upstream_count++] = {up, &uh, up->handler_gen};
    }
    for (u32 i = 0; i < upstream_count; i++) {
        auto& snapshot = upstreams[i];
        if (snapshot.conn->h2 != snapshot.h2 ||
            snapshot.conn->handler_gen != snapshot.handler_gen || snapshot.h2->grpc.busy)
            continue;
        grpc_drive_upstream(loop, *snapshot.conn);
    }
    if (conn.h2 != downstream_h2 || conn.handler_gen != downstream_handler_gen) return;
    grpc_refresh_timer(loop, conn);
    if (conn.h2 == downstream_h2 && conn.handler_gen == downstream_handler_gen)
        grpc_kick_downstream(loop, conn);
}

// Conservative active-session probes: no idle pool traffic, no probes during
// handshake or GOAWAY drain. The caller flushes the queued control frame.
inline bool grpc_keepalive_tick(Http2Conn& h, u64 now, u64 timeout_us, bool writable) {
    auto& g = h.grpc;
    if (h.ping_pending) return now - g.last_ping_us >= timeout_us;
    constexpr u64 interval_us = 300000000;  // five minutes; avoid server ping strikes
    const u64 since = g.last_ping_us ? g.last_ping_us : g.connected_at_us;
    if (!g.active || g.connecting || !h.peer_settings_seen || h.peer_goaway) {
        g.keepalive_due_us = 0;
        return false;
    }
    if (!g.keepalive_due_us) {
        if (now - since < interval_us) return false;
        // Start the timeout when this tick observes the overdue probe, so a
        // delayed timer does not close a session before it gets a probe chance.
        g.keepalive_due_us = now;
    }
    // A blocked transport must not keep an active session alive forever by
    // preventing the probe from entering the control buffer.
    if (now >= g.keepalive_due_us && now - g.keepalive_due_us >= timeout_us) return true;
    if (!writable || sizeof(g.control) - g.control_len < kFrameHeaderSize + 8) return false;
    g.control_len +=
        h.write_ping(g.control + g.control_len, sizeof(g.control) - g.control_len, now);
    g.last_ping_us = now;
    g.keepalive_due_us = 0;
    return false;
}

template <typename Loop>
void grpc_tick(Loop* loop, Connection& conn) {
    auto& h = *conn.h2;
    const u64 now = monotonic_us();
    if (h.grpc.upstream) {
        const u32 control_before = h.grpc.control_len;
        const bool stale_config =
            h.grpc.active == 0 && loop->config_ptr && *loop->config_ptr != conn.request_config;
        if (((h.grpc.connecting || !h.peer_settings_seen) &&
             now - h.grpc.connected_at_us >= static_cast<u64>(loop->upstream_timeout) * 1000000) ||
            stale_config ||
            grpc_keepalive_tick(h,
                                now,
                                static_cast<u64>(loop->upstream_timeout) * 1000000,
                                !conn.on_send && !h.grpc.busy &&
                                    (!h.grpc.client_tls.ssl_ctx || h.grpc.tls_verified)) ||
            grpc_idle_upstream_should_close(h.grpc,
                                            h.peer_goaway,
                                            loop->is_draining(),
                                            now,
                                            static_cast<u64>(loop->keepalive_timeout) * 1000000)) {
            grpc_record_session_failure(loop, conn, now);
            loop->close_conn(conn);
            return;
        }
        if (h.grpc.control_len > control_before) grpc_drive_upstream(loop, conn);
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
