#pragma once

#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/grpc_protocol.h"

namespace rut {

inline bool snapshot_response_mutations_before_request_rewrite(Connection& conn);

enum class GrpcWebH1Start : u8 { NotWeb, Started, Rejected };

template <typename Loop>
void grpc_web_h1_on_recv(void* lp, Connection& conn, IoEvent ev);
template <typename Loop>
void grpc_web_h1_on_sent(void* lp, Connection& conn, IoEvent ev);
template <typename Loop>
void grpc_web_h1_kick(void* lp, Connection& conn);
template <typename Loop>
void grpc_web_h1_kick_thunk(void* lp, ConnectionBase& base) {
    grpc_web_h1_kick(lp, static_cast<Connection&>(base));
}
template <typename Loop>
void grpc_web_h1_pump_response(Loop* loop, Connection& conn, GrpcExchange& x);
template <typename Loop>
void grpc_web_h1_resume_upload(Loop* loop, Connection& conn);

// Convert the parser's borrowed HTTP/1 view into bounded lowercase HPACK
// headers while the request receive slice is still stable, then start the same
// pooled native HTTP/2 exchange used by the HTTP/2 downstream path.
template <typename Loop>
GrpcWebH1Start grpc_web_h1_start(Loop* loop,
                                 Connection& conn,
                                 const RouteConfig* cfg,
                                 u16 upstream_id) {
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    req.reset();
    if (parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &req) != ParseStatus::Complete)
        return GrpcWebH1Start::NotWeb;
    const GrpcWebContentType mode = grpc_request_mode(req);
    if (mode != GrpcWebContentType::Binary && mode != GrpcWebContentType::Text)
        return GrpcWebH1Start::NotWeb;
    // HTTP/1's normal upstream path snapshots response mutations before
    // applying DSL path/header rewrites. Keep the same ownership order before
    // converting the request headers into the synthetic H2 stream.
    if (!snapshot_response_mutations_before_request_rewrite(conn) ||
        !h2_apply_forward_request_overrides(conn))
        return GrpcWebH1Start::Rejected;
    parser.reset();
    req.reset();
    if (parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &req) != ParseStatus::Complete)
        return GrpcWebH1Start::Rejected;
    if (req.method != HttpMethod::POST || req.version != HttpVersion::Http11 ||
        req.transfer_encoding == RequestTransferEncoding::Unsupported ||
        req.transfer_encoding == RequestTransferEncoding::Unparsed ||
        (req.chunked && req.has_content_length))
        return GrpcWebH1Start::Rejected;

    if (!conn.h2) {
        if (!loop->alloc_h2(conn)) return GrpcWebH1Start::Rejected;
        conn.h2->init();
    }
    conn.h2->grpc.web_h1_kick = &grpc_web_h1_kick_thunk<Loop>;
    if (conn.h2->grpc.active != 0) return GrpcWebH1Start::Rejected;
    auto* stream = conn.h2->open_stream(1);
    if (!stream) return GrpcWebH1Start::Rejected;

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
    for (u32 i = 0; i < req.header_count; i++) {
        const auto& h = req.headers[i];
        if (http_header_name_eq_ci(h.name.ptr, h.name.len, "host", 4)) {
            if (authority.ptr) return GrpcWebH1Start::Rejected;
            authority = h.value;
        }
    }
    if (!authority.ptr || !authority.len || !add({":method", 7}, {"POST", 4}) ||
        !add({":path", 5}, req.path) ||
        !add({":scheme", 7}, conn.tls_active ? Str{"https", 5} : Str{"http", 4}) ||
        !add({":authority", 10}, authority))
        return GrpcWebH1Start::Rejected;
    for (u32 i = 0; i < req.header_count; i++) {
        const auto& h = req.headers[i];
        if (http_header_name_eq_ci(h.name.ptr, h.name.len, "host", 4)) continue;
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
    if (!grpc_start(loop, conn, 1, cfg, upstream_id, hs, nh, req, end))
        return GrpcWebH1Start::Rejected;

    // parse_request_metadata may already have advanced the connection's body
    // framing parser over bytes coalesced with the headers. The bridge starts
    // its own bounded pump from the still-owned raw receive bytes, so restore
    // fresh framing state and count only body bytes as they enter gRPC.
    conn.req_body_mode = req.chunked ? BodyMode::Chunked
                                     : (req.has_content_length && req.content_length
                                            ? BodyMode::ContentLength
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
    grpc_web_h1_kick(static_cast<void*>(loop), conn);
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
                grpc_web_h1_kick(static_cast<void*>(loop), conn);
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
            grpc_web_h1_kick(static_cast<void*>(loop), conn);
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
void grpc_web_h1_kick(void* lp, Connection& conn) {
    auto* loop = static_cast<Loop*>(lp);
    if (!conn.h2 || !conn.req_body_streamed || conn.fd < 0 || conn.on_send) return;
    GrpcExchange* x = grpc_find(*conn.h2, 1);
    if (!x || !x->web_h1) return;
    grpc_web_h1_resume_upload(loop, conn);
    if (conn.fd < 0 || conn.on_send) return;
    grpc_web_h1_pump_response(loop, conn, *x);
}

template <typename Loop>
void grpc_web_h1_pump_response(Loop* loop, Connection& conn, GrpcExchange& x) {
    if (conn.on_send || conn.fd < 0) return;
    Connection* credit_upstream = nullptr;
    int credit_upstream_fd = -1;
    Http2Conn* credit_upstream_h2 = nullptr;
    u32 credit_upstream_stream = 0;
    conn.send_buf.reset();
    auto put = [&](const void* p, u32 n) {
        return n == 0 || conn.send_buf.write(static_cast<const u8*>(p), n) == n;
    };
    if (!x.response_headers_sent) {
        if (!x.response_headers_len && !x.response_end) return;
        static constexpr char kPrefix[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n";
        static constexpr char kBinaryContentType[] = "Content-Type: application/grpc-web\r\n";
        static constexpr char kTextContentType[] =
            "Content-Type: application/grpc-web-text\r\n";
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
    } else if (x.download_len) {
        u32 amount = x.download_len;
        u32 wire_amount = 0;
        if (x.web_mode == GrpcWebContentType::Text) {
            u32 consumed = 0, written = 0;
            const auto status = x.response_base64.feed(x.download,
                                                       amount,
                                                       consumed,
                                                       conn.send_buf.write_ptr(),
                                                       conn.send_buf.write_avail(),
                                                       written);
            if (status == GrpcWebCodecStatus::Invalid || consumed == 0) {
                loop->close_conn(conn);
                return;
            }
            conn.send_buf.commit(written);
            grpc_pop(x.download, x.download_len, consumed);
            amount = consumed;
            wire_amount = written;
        } else {
            if (amount > conn.send_buf.write_avail()) amount = conn.send_buf.write_avail();
            if (amount == 0 || !put(x.download, amount)) return;
            grpc_pop(x.download, x.download_len, amount);
            wire_amount = amount;
        }
        x.staged_response_bytes += wire_amount;
        if (x.upstream && x.upstream->h2) {
            x.upstream->h2->consume_data(x.upstream_stream, amount);
            credit_upstream = x.upstream;
            credit_upstream_fd = credit_upstream->fd;
            credit_upstream_h2 = credit_upstream->h2;
            credit_upstream_stream = x.upstream_stream;
        }
    } else if (x.response_end) {
        if (x.web_mode == GrpcWebContentType::Text && !x.web_body_flushed) {
            u32 written = 0;
            const auto status = x.response_base64.flush(
                conn.send_buf.write_ptr(), conn.send_buf.write_avail(), written);
            if (status != GrpcWebCodecStatus::Ok) {
                loop->close_conn(conn);
                return;
            }
            conn.send_buf.commit(written);
            x.staged_response_bytes += written;
            x.web_body_flushed = true;
        }
        if (conn.send_buf.len() == 0 && !x.web_trailer_flushed) {
            if (!x.response_trailers_len) {
                char status[2] = {static_cast<char>('0' + x.response_status / 10),
                                  static_cast<char>('0' + x.response_status % 10)};
                const Str value = x.response_status >= 10 ? Str{status, 2} : Str{status + 1, 1};
                const GrpcWebTrailer trailer{{"grpc-status", 11}, value};
                u32 written = 0;
                if (!grpc_web_encode_trailer_envelope(
                        &trailer, 1, x.response_trailers, sizeof(x.response_trailers), written)) {
                    loop->close_conn(conn);
                    return;
                }
                x.response_trailers_len = written;
            }
            const u8* trailer = x.response_trailers;
            u32 trailer_len = x.response_trailers_len;
            if (x.web_mode == GrpcWebContentType::Text) {
                if constexpr (requires { x.response_trailers_base64; }) {
                    trailer = x.response_trailers_base64;
                    trailer_len = x.response_trailers_base64_len;
                } else {
                    loop->close_conn(conn);
                    return;
                }
            }
            u32 amount = trailer_len - x.response_trailers_offset;
            if (amount > conn.send_buf.write_avail()) amount = conn.send_buf.write_avail();
            if (!amount || !put(trailer + x.response_trailers_offset, amount)) {
                loop->close_conn(conn);
                return;
            }
            x.response_trailers_offset += amount;
            x.web_trailer_flushed = x.response_trailers_offset == trailer_len;
            x.staged_response_bytes += amount;
        }
        if (x.web_trailer_flushed) x.response_end_sent = true;
    } else {
        return;
    }
    if (!conn.send_buf.len()) {
        if (x.response_end &&
            (x.download_len || (x.web_mode == GrpcWebContentType::Text && !x.web_body_flushed)))
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
    if (x->response_end_sent) {
        const u8 status = x->failure ? x->failure : x->response_status;
        const u32 response_size = x->staged_response_bytes > UINT32_MAX
                                      ? UINT32_MAX
                                      : static_cast<u32>(x->staged_response_bytes);
        const u32 request_size =
            x->request_bytes > UINT32_MAX ? UINT32_MAX : static_cast<u32>(x->request_bytes);
        conn.resp_status = 200;
        on_request_complete_with_grpc_status(
            loop, conn, 200, response_size, static_cast<u8>(status + 1), request_size);
        x->skip_rpc_log = true;
        if (conn.h2) grpc_release(loop, x, x->failure || !x->request_end_sent);
        loop->epoch_leave();
        close_conn_after_complete_response(loop, conn);
        return;
    }
    grpc_web_h1_kick(lp, conn);
}

}  // namespace rut
