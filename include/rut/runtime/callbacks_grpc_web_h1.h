#pragma once

#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/grpc_protocol.h"
#include "rut/runtime/io_backend.h"

namespace rut {

inline bool snapshot_response_mutations_before_request_rewrite(Connection& conn);

enum class GrpcWebH1Start : u8 { NotWeb, Started, Rejected };

inline bool grpc_web_h1_has_unsupported_expect(const ParsedRequest& req) {
    const bool body_bearing = req.chunked || (req.has_content_length && req.content_length != 0);
    if (!body_bearing) return false;
    for (u32 i = 0; i < req.header_count; i++) {
        const auto& header = req.headers[i];
        if (http_header_name_eq_ci(header.name.ptr, header.name.len, "expect", 6) &&
            header.value.len != 0)
            return true;
    }
    return false;
}

template <typename Loop>
void grpc_web_h1_on_recv(void* lp, Connection& conn, IoEvent ev);
template <typename Loop>
void grpc_web_h1_on_sent(void* lp, Connection& conn, IoEvent ev);
template <typename Loop>
void grpc_web_h1_kick(void* lp, Connection& conn);
template <typename Loop>
void grpc_web_h1_kick_thunk(void* lp, ConnectionBase& base) {
    grpc_web_h1_kick<Loop>(lp, static_cast<Connection&>(base));
}
template <typename Loop>
void grpc_web_h1_pump_response(Loop* loop, Connection& conn, GrpcExchange& x);
template <typename Loop>
void grpc_web_h1_resume_upload(Loop* loop, Connection& conn);

// Convert the parser's borrowed HTTP/1 view into bounded lowercase HPACK
// headers while the request receive slice is still stable, then start the same
// pooled native HTTP/2 exchange used by the HTTP/2 downstream path.
template <typename Loop>
GrpcWebH1Start grpc_web_h1_start(
    Loop* loop, Connection& conn, const RouteConfig* cfg, u16 upstream_id, bool policy_free) {
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    req.reset();
    if (parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &req) != ParseStatus::Complete) {
        return GrpcWebH1Start::NotWeb;
    }
    bool ambiguous_web_type = false;
    const GrpcWebContentType mode = grpc_request_mode(req, &ambiguous_web_type);
    if (ambiguous_web_type) return GrpcWebH1Start::Rejected;
    if (mode != GrpcWebContentType::Binary && mode != GrpcWebContentType::Text) {
        return GrpcWebH1Start::NotWeb;
    }
    if (grpc_web_h1_has_unsupported_expect(req)) return GrpcWebH1Start::Rejected;
    if (!policy_free) {
        return GrpcWebH1Start::Rejected;
    }
    // The bridge's response path is selected from the original Web media type.
    // Allowing forward(set_header:) to rewrite Content-Type could make the
    // synthetic H2 exchange produce native gRPC headers which the H1 writer
    // would then serialize as HTTP/1 text. Reject the override before mutating
    // the request, even when its replacement happens to classify as Web too.
    for (u32 i = 0; i < conn.req_header_override_count; i++) {
        const Str name = conn.req_header_overrides[i].name;
        if (http_header_name_eq_ci(name.ptr, name.len, "content-type", 12))
            return GrpcWebH1Start::Rejected;
    }
    // HTTP/1's normal upstream path snapshots response mutations before
    // applying DSL path/header rewrites. Keep the same ownership order before
    // converting the request headers into the synthetic H2 stream.
    if (!snapshot_response_mutations_before_request_rewrite(conn) ||
        !h2_apply_forward_request_overrides(conn)) {
        return GrpcWebH1Start::Rejected;
    }
    parser.reset();
    req.reset();
    if (parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &req) != ParseStatus::Complete) {
        return GrpcWebH1Start::Rejected;
    }
    ambiguous_web_type = false;
    if (grpc_request_mode(req, &ambiguous_web_type) != mode || ambiguous_web_type ||
        grpc_web_h1_has_unsupported_expect(req)) {
        return GrpcWebH1Start::Rejected;
    }
    if (req.method != HttpMethod::POST || req.version != HttpVersion::Http11 ||
        req.transfer_encoding == RequestTransferEncoding::Unsupported ||
        req.transfer_encoding == RequestTransferEncoding::Unparsed ||
        (req.chunked && req.has_content_length)) {
        return GrpcWebH1Start::Rejected;
    }
    if (req.chunked) {
        u32 transfer_encoding_count = 0;
        for (u32 i = 0; i < req.header_count; i++) {
            const auto& h = req.headers[i];
            if (!http_header_name_eq_ci(h.name.ptr, h.name.len, "transfer-encoding", 17)) continue;
            transfer_encoding_count++;
            if (!http_header_name_eq_ci(h.value.ptr, h.value.len, "chunked", 7))
                return GrpcWebH1Start::Rejected;
        }
        if (req.transfer_encoding != RequestTransferEncoding::FinalChunked ||
            transfer_encoding_count != 1)
            return GrpcWebH1Start::Rejected;
    } else if (req.transfer_encoding != RequestTransferEncoding::None) {
        return GrpcWebH1Start::Rejected;
    }

    if (!conn.h2) {
        if (!loop->alloc_h2(conn)) return GrpcWebH1Start::Rejected;
        conn.h2->init_client();
    }
    conn.h2->grpc.web_h1_kick = &grpc_web_h1_kick_thunk<Loop>;
    if (conn.h2->grpc.active != 0) return GrpcWebH1Start::Rejected;
    auto* stream = conn.h2->open_stream(1);
    if (!stream) return GrpcWebH1Start::Rejected;
    stream->headers_received_us = conn.req_start_us;

    hpack::Header hs[Http2Conn::kMaxHeadersPerReq]{};
    u8 name_storage[Http2Conn::kHeaderBlockCap];
    u32 name_used = 0;
    u32 nh = 0;
    auto add = [&](Str name, Str value) {
        if (nh >= Http2Conn::kMaxHeadersPerReq) return false;
        hs[nh++] = {name, value};
        return true;
    };
    Str authority{nullptr, 0};
    Str nominated_hop_headers[kMaxHeaders];
    u32 nominated_hop_count = 0;
    for (u32 i = 0; i < req.header_count; i++) {
        const auto& h = req.headers[i];
        if (http_header_name_eq_ci(h.name.ptr, h.name.len, "host", 4)) {
            if (authority.ptr) return GrpcWebH1Start::Rejected;
            authority = h.value;
        }
        if (!http_header_name_eq_ci(h.name.ptr, h.name.len, "connection", 10)) continue;
        u32 start = 0;
        while (start < h.value.len) {
            while (start < h.value.len && (h.value.ptr[start] == ' ' || h.value.ptr[start] == '\t'))
                start++;
            const u32 token_start = start;
            while (start < h.value.len && h.value.ptr[start] != ',') start++;
            u32 token_end = start;
            while (token_end > token_start &&
                   (h.value.ptr[token_end - 1] == ' ' || h.value.ptr[token_end - 1] == '\t'))
                token_end--;
            if (token_end == token_start || nominated_hop_count >= kMaxHeaders)
                return GrpcWebH1Start::Rejected;
            for (u32 j = token_start; j < token_end; j++) {
                const char c = h.value.ptr[j];
                const bool token_char = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                                        (c >= 'a' && c <= 'z') || c == '!' || c == '#' ||
                                        c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
                                        c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
                                        c == '`' || c == '|' || c == '~';
                if (!token_char) return GrpcWebH1Start::Rejected;
            }
            nominated_hop_headers[nominated_hop_count++] = {h.value.ptr + token_start,
                                                            token_end - token_start};
            if (start < h.value.len) start++;
        }
    }
    if (!authority.ptr || !authority.len || !add({":method", 7}, {"POST", 4}) ||
        !add({":path", 5}, req.path) ||
        !add({":scheme", 7}, conn.tls_active ? Str{"https", 5} : Str{"http", 4}) ||
        !add({":authority", 10}, authority))
        return GrpcWebH1Start::Rejected;
    for (u32 i = 0; i < req.header_count; i++) {
        const auto& h = req.headers[i];
        if (http_header_name_eq_ci(h.name.ptr, h.name.len, "host", 4) ||
            http_header_name_eq_ci(h.name.ptr, h.name.len, "connection", 10))
            continue;
        bool nominated = false;
        for (u32 j = 0; j < nominated_hop_count; j++) {
            if (!http_header_name_eq_ci(h.name.ptr,
                                        h.name.len,
                                        nominated_hop_headers[j].ptr,
                                        nominated_hop_headers[j].len))
                continue;
            if (http_header_name_eq_ci(h.name.ptr, h.name.len, "content-type", 12) ||
                http_header_name_eq_ci(h.name.ptr, h.name.len, "content-length", 14) ||
                http_header_name_eq_ci(h.name.ptr, h.name.len, "host", 4) ||
                http_header_name_eq_ci(h.name.ptr, h.name.len, "te", 2) ||
                http_header_name_eq_ci(h.name.ptr, h.name.len, "grpc-timeout", 12) ||
                http_header_name_eq_ci(h.name.ptr, h.name.len, "grpc-encoding", 13))
                return GrpcWebH1Start::Rejected;
            nominated = true;
            break;
        }
        if (nominated) continue;
        if (h.name.len > sizeof(name_storage) - name_used) return GrpcWebH1Start::Rejected;
        const u32 start = name_used;
        for (u32 j = 0; j < h.name.len; j++) {
            char c = h.name.ptr[j];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            name_storage[name_used++] = static_cast<u8>(c);
        }
        if (!add({reinterpret_cast<const char*>(name_storage + start), h.name.len}, h.value))
            return GrpcWebH1Start::Rejected;
    }
    const bool end = !req.chunked && (!req.has_content_length || req.content_length == 0);
    conn.keep_alive = false;
    conn.req_body_streamed = false;  // suppress the synchronous start kick until headers retire
    if (!grpc_start(loop, conn, 1, cfg, upstream_id, hs, nh, req, end)) {
        return GrpcWebH1Start::Rejected;
    }

    // parse_request_metadata may already have advanced the connection's body
    // framing parser over bytes coalesced with the headers. The bridge starts
    // its own bounded pump from the still-owned raw receive bytes, so restore
    // fresh framing state and count only body bytes as they enter gRPC.
    conn.req_body_mode =
        req.chunked ? BodyMode::Chunked
                    : (req.has_content_length && req.content_length ? BodyMode::ContentLength
                                                                    : BodyMode::None);
    conn.req_body_remaining = req.has_content_length ? req.content_length : 0;
    conn.req_chunk_parser.reset();
    conn.downstream_req_size = 0;
    conn.req_size = 0;
    conn.request_upload_complete = end;
    conn.state = ConnState::ReadingBody;
    conn.req_body_streamed = true;
    conn.set_slots(&grpc_web_h1_on_recv<Loop>, nullptr, nullptr, nullptr);
    if (conn.req_header_end > conn.recv_buf.len()) return GrpcWebH1Start::Rejected;
    conn.consume_request_receive_buffer(conn.req_header_end);
    grpc_web_h1_resume_upload(loop, conn);
    grpc_web_h1_kick<Loop>(static_cast<void*>(loop), conn);
    return GrpcWebH1Start::Started;
}

inline u32 grpc_web_h1_raw_budget(const GrpcExchange& x) {
    const u32 free = sizeof(x.upload) - x.upload_len;
    if (x.web_mode != GrpcWebContentType::Text) return free;
    if (free < 3) return 0;
    const u32 budget = (free / 3) * 4;
    return budget > x.request_base64.quartet_len ? budget - x.request_base64.quartet_len : 0;
}

template <typename Loop>
inline bool grpc_web_h1_pause_recv(Loop* loop, Connection& conn) {
    if constexpr (requires { loop->pause_recv(conn); }) {
        if (conn.recv_armed && !conn.recv_pause_cancel_pending && !loop->pause_recv(conn))
            return false;
    } else if constexpr (requires { loop->backend.pause_recv(conn.id, true); }) {
        loop->backend.pause_recv(conn.id, conn.on_send != nullptr);
    }
    return true;
}

template <typename Loop>
void grpc_web_h1_resume_upload(Loop* loop, Connection& conn) {
    if (!conn.h2 || !conn.req_body_streamed) return;
    GrpcExchange* x = grpc_find(*conn.h2, 1);
    if (!x || x->web_h1 == false) return;
    const int down_fd = conn.fd;
    Http2Conn* const down_h2 = conn.h2;
    const u32 down_epoch = conn.req_metadata_episode;
    if (conn.request_upload_complete) return;
    if (conn.req_body_mode == BodyMode::None) {
        // grpc_start received end=true for an empty HTTP body and already
        // finalized the request envelope.
        conn.request_upload_complete = true;
        grpc_web_h1_pause_recv(loop, conn);
        return;
    }

    for (u32 step = 0; step < 32; step++) {
        const u32 budget = grpc_web_h1_raw_budget(*x);
        if (budget == 0) {
            // io_uring may still deliver one positive CQE for a receive that
            // was already in flight when the pause was requested. Keep room
            // for that provided-buffer-sized completion before pausing.
            if (conn.recv_buf.write_avail() < kProvidedBufSize &&
                !reserve_request_receive_headroom(loop->pool, conn, kProvidedBufSize)) {
                loop->close_conn(conn);
                return;
            }
            if (!grpc_web_h1_pause_recv(loop, conn)) loop->close_conn(conn);
            return;
        }
        const u32 available = conn.recv_buf.len();
        if (!available) break;
        if (conn.req_body_mode == BodyMode::ContentLength) {
            const u32 amount =
                available < conn.req_body_remaining
                    ? (available < budget ? available : budget)
                    : (conn.req_body_remaining < budget ? conn.req_body_remaining : budget);
            if (!amount) break;
            const bool end = amount == conn.req_body_remaining;
            Connection* up = x->upstream;
            const int up_fd = up ? up->fd : -1;
            Http2Conn* up_h2 = up ? up->h2 : nullptr;
            const bool was_busy = up_h2 && up_h2->grpc.busy;
            if (up_h2) up_h2->grpc.busy = true;
            grpc_request_data(loop, conn, *x, conn.recv_buf.data(), amount, end);
            conn.consume_request_receive_buffer(amount);
            conn.req_body_remaining -= amount;
            conn.downstream_req_size += amount;
            conn.req_size += amount;
            if (up && up->fd == up_fd && up->h2 == up_h2 && up_h2) {
                up_h2->grpc.busy = was_busy;
                if (!was_busy) grpc_drive_upstream(loop, *up);
            }
            if (conn.fd != down_fd || conn.h2 != down_h2 ||
                conn.req_metadata_episode != down_epoch || grpc_find(*down_h2, 1) != x)
                return;
            if (end) {
                conn.request_upload_complete = true;
                grpc_web_h1_pause_recv(loop, conn);
                return;
            }
        } else if (conn.req_body_mode == BodyMode::Chunked) {
            const u32 input_len = available < budget ? available : budget;
            u32 consumed = 0, out_start = 0, out_len = 0;
            const ChunkStatus status = conn.req_chunk_parser.feed(
                conn.recv_buf.data(), input_len, &consumed, &out_start, &out_len);
            if (status == ChunkStatus::Error || consumed > available || out_start > consumed ||
                out_len > consumed - out_start) {
                x->failure = 13;
                x->response_end = true;
                if (x->upstream && x->upstream->h2)
                    grpc_detach_upstream_exchange(loop, *x->upstream->h2, *x);
                conn.request_upload_complete = true;
                grpc_web_h1_kick<Loop>(static_cast<void*>(loop), conn);
                return;
            }
            if (consumed == 0 && status != ChunkStatus::Done) break;
            Connection* up = x->upstream;
            const int up_fd = up ? up->fd : -1;
            Http2Conn* up_h2 = up ? up->h2 : nullptr;
            const bool was_busy = up_h2 && up_h2->grpc.busy;
            if (up_h2) up_h2->grpc.busy = true;
            if (out_len)
                grpc_request_data(loop, conn, *x, conn.recv_buf.data() + out_start, out_len, false);
            conn.consume_request_receive_buffer(consumed);
            conn.downstream_req_size += consumed;
            conn.req_size += consumed;
            if (up && up->fd == up_fd && up->h2 == up_h2 && up_h2) {
                up_h2->grpc.busy = was_busy;
                if (!was_busy) grpc_drive_upstream(loop, *up);
            }
            if (conn.fd != down_fd || conn.h2 != down_h2 ||
                conn.req_metadata_episode != down_epoch || grpc_find(*down_h2, 1) != x)
                return;
            if (status == ChunkStatus::Done) {
                const bool end_was_busy = up_h2 && up_h2->grpc.busy;
                if (up_h2) up_h2->grpc.busy = true;
                grpc_request_data(loop, conn, *x, nullptr, 0, true);
                if (up && up->fd == up_fd && up->h2 == up_h2 && up_h2) {
                    up_h2->grpc.busy = end_was_busy;
                    if (!end_was_busy) grpc_drive_upstream(loop, *up);
                }
                if (conn.fd != down_fd || conn.h2 != down_h2 ||
                    conn.req_metadata_episode != down_epoch || grpc_find(*down_h2, 1) != x)
                    return;
                conn.request_upload_complete = true;
                grpc_web_h1_pause_recv(loop, conn);
                return;
            }
            if (status == ChunkStatus::NeedMore) break;
        } else {
            x->failure = 13;
            x->response_end = true;
            grpc_web_h1_kick<Loop>(static_cast<void*>(loop), conn);
            return;
        }
    }

    if (!conn.request_upload_complete) {
        if (conn.recv_buf.write_avail() < kProvidedBufSize) {
            if constexpr (requires { loop->pool.alloc_bulk(); }) {
                if (!reserve_request_receive_headroom(loop->pool, conn, kProvidedBufSize)) {
                    loop->close_conn(conn);
                    return;
                }
            }
        }
        if (!conn.recv_armed && !conn.recv_pause_cancel_pending && !loop->submit_recv(conn))
            loop->close_conn(conn);
    }
}

template <typename Loop>
void grpc_web_h1_on_recv(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result == 0 && conn.request_upload_complete) return;
    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }
    grpc_web_h1_resume_upload(loop, conn);
}

template <typename Loop>
void grpc_web_h1_finish_response(Loop* loop, Connection& conn, GrpcExchange& x) {
    const u8 status = x.failure ? x.failure : x.response_status;
    const u32 response_size = x.staged_response_bytes > UINT32_MAX
                                  ? UINT32_MAX
                                  : static_cast<u32>(x.staged_response_bytes);
    const u32 request_size =
        x.request_bytes > UINT32_MAX ? UINT32_MAX : static_cast<u32>(x.request_bytes);
    conn.resp_status = 200;
    on_request_complete_with_grpc_status(
        loop, conn, 200, response_size, static_cast<u8>(status + 1), request_size);
    x.skip_rpc_log = true;
    if (conn.h2) grpc_release(loop, &x, x.failure || !x.request_end_sent);
    loop->epoch_leave();
    close_conn_after_complete_response(loop, conn);
}

template <typename Loop>
bool grpc_web_h1_prepare_failure(Loop* loop, Connection& conn, GrpcExchange& x) {
    if (x.failure && !x.web_failure_prepared) {
        const u32 dropped = grpc_web_prepare_failure(x);
        if (dropped && x.upstream && x.upstream->h2)
            x.upstream->h2->consume_data(x.upstream_stream, dropped);
    }
    if (!x.web_response_invalid) return true;
    loop->close_conn(conn);
    return false;
}

template <typename Loop>
void grpc_web_h1_kick(void* lp, Connection& conn) {
    auto* loop = static_cast<Loop*>(lp);
    if (!conn.h2 || !conn.req_body_streamed || conn.fd < 0) return;
    GrpcExchange* x = grpc_find(*conn.h2, 1);
    if (!x || !x->web_h1) return;
    if (!grpc_web_h1_prepare_failure(loop, conn, *x)) return;
    if (x->failure) {
        if (conn.on_send) return;
        grpc_web_h1_pump_response(loop, conn, *x);
        return;
    }
    const int down_fd = conn.fd;
    Http2Conn* const down_h2 = conn.h2;
    const u32 down_epoch = conn.req_metadata_episode;
    grpc_web_h1_resume_upload(loop, conn);
    if (conn.fd != down_fd || conn.fd < 0 || conn.h2 != down_h2 ||
        conn.req_metadata_episode != down_epoch || !conn.req_body_streamed)
        return;
    x = grpc_find(*down_h2, 1);
    if (!x || !x->web_h1 || conn.on_send) return;
    grpc_web_h1_pump_response(loop, conn, *x);
}

template <typename Loop>
void grpc_web_h1_pump_response(Loop* loop, Connection& conn, GrpcExchange& x) {
    if (conn.on_send || conn.fd < 0) return;
    if (x.failure && !x.web_failure_prepared) {
        const u32 dropped = grpc_web_prepare_failure(x);
        if (dropped && x.upstream && x.upstream->h2)
            x.upstream->h2->consume_data(x.upstream_stream, dropped);
    }
    if (x.web_response_invalid) {
        loop->close_conn(conn);
        return;
    }
    Connection* credit_upstream = nullptr;
    int credit_upstream_fd = -1;
    Http2Conn* credit_upstream_h2 = nullptr;
    u32 credit_upstream_stream = 0;
    conn.send_buf.reset();
    auto put = [&](const void* p, u32 n) {
        return n == 0 || conn.send_buf.write(static_cast<const u8*>(p), n) == n;
    };
    if (!x.response_headers_sent) {
        if (!x.response_headers_len) {
            if (!x.response_end) return;
            if (!grpc_web_queue_h1_headers(x, nullptr, 0, true)) {
                loop->close_conn(conn);
                return;
            }
        }
        static constexpr char kPrefix[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n";
        static constexpr char kBinaryContentType[] = "Content-Type: application/grpc-web\r\n";
        static constexpr char kTextContentType[] = "Content-Type: application/grpc-web-text\r\n";
        if (!put(kPrefix, sizeof(kPrefix) - 1) ||
            (!x.response_headers_len &&
             !(x.web_mode == GrpcWebContentType::Text
                   ? put(kTextContentType, sizeof(kTextContentType) - 1)
                   : put(kBinaryContentType, sizeof(kBinaryContentType) - 1))) ||
            !put(x.response_headers, x.response_headers_len) || !put("\r\n", 2)) {
            loop->close_conn(conn);
            return;
        }
        x.response_headers_sent = true;
    } else if (x.download_len ||
               (x.web_mode == GrpcWebContentType::Text && x.web_encode_boundary_pending) ||
               (x.web_mode == GrpcWebContentType::Text && !x.web_trailer_encoding &&
                x.response_base64.pending_len == 3)) {
        u32 amount = x.download_len;
        u32 wire_amount = 0;
        if (x.web_mode == GrpcWebContentType::Text) {
            u32 consumed = 0, written = 0;
            if (x.web_encode_boundary_pending) {
                const u8 native_len = x.response_base64.pending_len;
                if (native_len) {
                    for (u8 i = 0; i < native_len; i++)
                        x.web_pending_native[i] = x.response_base64.pending[i];
                    const auto status = x.response_base64.flush(
                        conn.send_buf.write_ptr(), conn.send_buf.write_avail(), written);
                    if (status != GrpcWebCodecStatus::Ok || !written) {
                        loop->close_conn(conn);
                        return;
                    }
                    conn.send_buf.commit(written);
                    if (x.staged_response_message.feed(x.web_pending_native, native_len, false)) {
                        loop->close_conn(conn);
                        return;
                    }
                    wire_amount = written;
                }
                x.web_pending_native_len = 0;
                x.web_encode_boundary_pending = false;
                x.web_pending_output_is_trailer = false;
            } else {
                const u8 previous_len = x.response_base64.pending_len;
                u8 previous_native[3]{};
                for (u8 i = 0; i < previous_len; i++)
                    previous_native[i] = x.response_base64.pending[i];
                const u32 source_len = x.web_encoded_message.next_span(amount);
                const auto status = x.response_base64.feed(x.download,
                                                           source_len,
                                                           consumed,
                                                           conn.send_buf.write_ptr(),
                                                           conn.send_buf.write_avail(),
                                                           written);
                if (status == GrpcWebCodecStatus::Invalid || (!consumed && !written)) {
                    loop->close_conn(conn);
                    return;
                }
                if (consumed && x.web_encoded_message.feed(x.download, consumed, false)) {
                    loop->close_conn(conn);
                    return;
                }
                if (!x.web_encoded_message.header_bytes && !x.web_encoded_message.remaining)
                    x.web_encode_boundary_pending = true;
                conn.send_buf.commit(written);
                const u32 native_staged = (written / 4) * 3;
                const u32 previous_staged =
                    native_staged < previous_len ? native_staged : previous_len;
                if (previous_staged &&
                    x.staged_response_message.feed(previous_native, previous_staged, false)) {
                    loop->close_conn(conn);
                    return;
                }
                const u32 input_staged = native_staged - previous_staged;
                if (input_staged &&
                    x.staged_response_message.feed(x.download, input_staged, false)) {
                    loop->close_conn(conn);
                    return;
                }
                const u32 pending = previous_len + consumed - native_staged;
                if (pending > sizeof(x.web_pending_native)) {
                    loop->close_conn(conn);
                    return;
                }
                u32 copied = 0;
                if (previous_len > native_staged) {
                    copied = previous_len - native_staged;
                    __builtin_memcpy(x.web_pending_native, previous_native + native_staged, copied);
                }
                const u32 input_pending = pending - copied;
                if (input_pending)
                    __builtin_memcpy(
                        x.web_pending_native + copied, x.download + input_staged, input_pending);
                x.web_pending_native_len = static_cast<u8>(pending);
                grpc_pop(x.download, x.download_len, consumed);
                amount = consumed;
                wire_amount = written;
            }
        } else {
            if (amount > conn.send_buf.write_avail()) amount = conn.send_buf.write_avail();
            if (amount == 0 || !put(x.download, amount)) return;
            if (x.staged_response_message.feed(x.download, amount, false)) {
                loop->close_conn(conn);
                return;
            }
            grpc_pop(x.download, x.download_len, amount);
            wire_amount = amount;
        }
        x.staged_response_bytes += wire_amount;
        if (amount && x.upstream && x.upstream->h2) {
            x.upstream->h2->consume_data(x.upstream_stream, amount);
            credit_upstream = x.upstream;
            credit_upstream_fd = credit_upstream->fd;
            credit_upstream_h2 = credit_upstream->h2;
            credit_upstream_stream = x.upstream_stream;
        }
    } else if (x.response_end) {
        // For text mode the trailer envelope continues the same base64 stream
        // as message data. Flush padding only after the envelope is encoded.
        if (x.web_mode == GrpcWebContentType::Text) x.web_body_flushed = true;
        if (conn.send_buf.len() == 0 && !x.web_trailer_flushed) {
            if (!x.response_trailers_len) {
                const u8 status_code = x.failure ? x.failure : x.response_status;
                char status[2] = {static_cast<char>('0' + status_code / 10),
                                  static_cast<char>('0' + status_code % 10)};
                const Str value = status_code >= 10 ? Str{status, 2} : Str{status + 1, 1};
                const GrpcWebTrailer trailer{{"grpc-status", 11}, value};
                u32 written = 0;
                if (!grpc_web_encode_trailer_envelope(
                        &trailer, 1, x.response_trailers, sizeof(x.response_trailers), written)) {
                    loop->close_conn(conn);
                    return;
                }
                x.response_trailers_len = written;
            }
            if (x.web_mode == GrpcWebContentType::Text) {
                x.web_trailer_encoding = true;
                while (conn.send_buf.write_avail()) {
                    if (x.response_trailers_offset < x.response_trailers_len ||
                        x.response_base64.pending_len == 3) {
                        u32 consumed = 0, written = 0;
                        const auto status = x.response_base64.feed(
                            x.response_trailers + x.response_trailers_offset,
                            x.response_trailers_len - x.response_trailers_offset,
                            consumed,
                            conn.send_buf.write_ptr(),
                            conn.send_buf.write_avail(),
                            written);
                        if (status == GrpcWebCodecStatus::Invalid || (!consumed && !written)) {
                            loop->close_conn(conn);
                            return;
                        }
                        x.response_trailers_offset += consumed;
                        if (written) {
                            x.web_pending_output_is_trailer = true;
                            x.web_trailer_wire_started = true;
                        }
                        conn.send_buf.commit(written);
                        if (written) break;
                    } else {
                        u32 written = 0;
                        const auto status = x.response_base64.flush(
                            conn.send_buf.write_ptr(), conn.send_buf.write_avail(), written);
                        if (status != GrpcWebCodecStatus::Ok) {
                            loop->close_conn(conn);
                            return;
                        }
                        conn.send_buf.commit(written);
                        if (written) {
                            x.web_pending_output_is_trailer = true;
                            x.web_trailer_wire_started = true;
                        }
                        x.web_trailer_flushed = true;
                        break;
                    }
                }
            } else {
                u32 amount = x.response_trailers_len - x.response_trailers_offset;
                if (amount > conn.send_buf.write_avail()) amount = conn.send_buf.write_avail();
                if (!amount || !put(x.response_trailers + x.response_trailers_offset, amount)) {
                    loop->close_conn(conn);
                    return;
                }
                x.response_trailers_offset += amount;
                x.web_trailer_wire_started = true;
                x.web_trailer_flushed = x.response_trailers_offset == x.response_trailers_len;
            }
            x.staged_response_bytes += conn.send_buf.len();
        }
        if (x.web_trailer_flushed) x.response_end_sent = true;
    } else {
        return;
    }
    if (!conn.send_buf.len()) {
        if (x.response_end_sent) {
            grpc_web_h1_finish_response(loop, conn, x);
            return;
        }
        if (x.download_len || x.web_encode_boundary_pending ||
            (x.response_end && x.web_mode == GrpcWebContentType::Text && !x.web_body_flushed))
            grpc_web_h1_pump_response(loop, conn, x);
        return;
    }
    conn.send_progress = 0;
    conn.state = ConnState::Sending;
    conn.set_slots(&grpc_web_h1_on_recv<Loop>, &grpc_web_h1_on_sent<Loop>, nullptr, nullptr);
    if (!loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len())) {
        loop->close_conn(conn);
        return;
    }
    // Parsing the upstream receive buffer may kick this H1 exchange again.
    // The response bytes are now owned by an in-flight send, and the H1 kick
    // checks on_send before touching send_buf, so that reentry is safe.
    if (credit_upstream && credit_upstream->fd == credit_upstream_fd &&
        credit_upstream->h2 == credit_upstream_h2 && credit_upstream_h2 &&
        !credit_upstream_h2->grpc.busy && !credit_upstream_h2->grpc.connecting)
        grpc_on_upstream_data<Loop>(static_cast<void*>(loop),
                                    *credit_upstream,
                                    {credit_upstream->id,
                                     static_cast<i32>(credit_upstream_stream),
                                     0,
                                     0,
                                     IoEventType::Recv,
                                     0});
}

template <typename Loop>
void grpc_web_h1_on_sent(void* lp, Connection& conn, IoEvent ev) {
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
    GrpcExchange* x = conn.h2 ? grpc_find(*conn.h2, 1) : nullptr;
    if (!x) {
        loop->close_conn(conn);
        return;
    }
    if (!grpc_web_h1_prepare_failure(loop, conn, *x)) return;
    if (x->response_end_sent) {
        grpc_web_h1_finish_response(loop, conn, *x);
        return;
    }
    grpc_web_h1_kick<Loop>(lp, conn);
}

}  // namespace rut
