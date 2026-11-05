#pragma once

// HTTP/2 WebSocket transport adapters. Included after the shared bounded
// exchange pump. HTTP/1 upstreams own a dedicated Connection and its ordinary
// send slice, so cancellation never frees bytes referenced by kernel I/O.
#include "rut/runtime/chunked_parser.h"

#include <sys/socket.h>

namespace rut {

template <typename Loop>
void h2ws_open_sessions(Loop* loop, Connection& down) {
    if constexpr (requires {
                      loop->grpc_upstreams;
                      loop->pool.alloc_bulk();
                  }) {
        if (!down.h2 || down.h2->grpc.upstream) return;
        auto& g = down.h2->grpc;
        const bool kBusy = g.busy;
        g.busy = true;
        for (auto* x : g.streams) {
            if (!x || !x->ws || !x->ws_accepted || !x->response_headers_sent || x->failure)
                continue;
            ws_h2_sent(*x, false);
            if (!ws_h2_open(*x) || !ws_h2_process(*x, true) || !ws_h2_process(*x, false))
                x->failure = 13;
            if (x->upstream) grpc_drive_upstream(loop, *x->upstream);
        }
        g.busy = kBusy;
        grpc_refresh_timer(loop, down);
    }
}

template <typename Loop>
bool h2ws_h1_pause(Loop* loop, Connection& c) {
    if constexpr (requires { loop->pause_recv(c); })
        return loop->pause_recv(c);
    else if constexpr (requires {
                           loop->backend.pause_recv(c.id, true);
                           loop->backend.pause_recv(c.id);
                       })
        loop->backend.pause_recv(c.id, true);
    c.recv_paused_for_send = true;
    return true;
}

template <typename Loop>
bool h2ws_h1_tls_finished(Loop* loop, Connection& c) {
    c.ws_tls_shutdown_pending = c.ws_tls_shutdown_need_read = false;
    c.ws_upstream_send_pending = false;
    c.on_send = nullptr;
    if (::shutdown(c.fd, SHUT_WR) != 0) return false;
    if (auto* x = grpc_find(*c.h2, 1)) x->request_end_sent = true;
    c.ws_client_write_shutdown = true;
    (void)loop;
    return true;
}

template <typename Loop>
void h2ws_h1_tls_sent(void* lp, Connection& c, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result <= 0 || !h2ws_h1_tls_finished(loop, c)) {
        loop->close_conn(c);
        return;
    }
    h2ws_h1_drive(loop, c);
}

template <typename Loop>
void h2ws_h1_drive(Loop* loop, Connection& c) {
    if (!c.h2) return;
    auto& g = c.h2->grpc;
    if (g.busy) return;
    auto* x = grpc_find(*c.h2, 1);
    if (!x) {
        loop->close_conn(c);
        return;
    }
    if (g.connecting || c.on_send) return;
    if (g.client_tls.ssl_ctx && !g.tls_verified) {
        SSL* ssl = c.tls_engine.ssl ? c.tls_engine.ssl : c.tls;
        // Readiness TLS bootstraps SSL_connect through the opening send.
        if (x->request_headers_sent && !tls_client_peer_valid(ssl, false)) return;
    }
    g.busy = true;
    u32 n = 0;
    c.send_buf.reset();
    u32 output_len = 0;
    const u8* output = grpc_output(*x, true, &output_len);
    if (!x->request_headers_sent) {
        n = x->request_headers_len;
        if (n > c.send_buf.capacity()) {
            g.busy = false;
            loop->close_conn(c);
            return;
        }
        c.send_buf.write(x->request_headers, n);
        x->request_headers_sent = true;
    } else if (x->ws_accepted && output_len) {
        n = output_len < c.send_buf.capacity() ? output_len : c.send_buf.capacity();
        c.send_buf.write(output, n);
        grpc_consume_output(*x, true, n);
    } else if (x->ws_accepted && !x->upload_len && x->request_end && !x->request_end_sent) {
        if (c.tls_active) {
            if constexpr (requires { loop->submit_ws_tls_shutdown(c); }) {
                c.ws_closing = c.ws_tls_shutdown_pending = c.ws_upstream_send_pending = true;
                c.on_send = &h2ws_h1_tls_sent<Loop>;
                g.busy = false;
                if (!loop->submit_ws_tls_shutdown(c)) loop->close_conn(c);
                return;
            }
            g.busy = false;
            loop->close_conn(c);
            return;
        }
        if (::shutdown(c.fd, SHUT_WR) != 0) {
            g.busy = false;
            loop->close_conn(c);
            return;
        }
        x->request_end_sent = true;
    }
    Connection* down = x->downstream;
    if (n) {
        c.on_send = &grpc_on_upstream_sent<Loop>;
        c.send_progress = 0;
        if (!loop->submit_send(c, c.send_buf.data(), n)) {
            g.busy = false;
            loop->close_conn(c);
            return;
        }
    }
    g.busy = false;
    if (down) grpc_kick_downstream(loop, *down);
}

inline bool h2ws_h1_response_headers(Connection& c,
                                     GrpcExchange& x,
                                     const ParsedResponse& response,
                                     hpack::Header* headers,
                                     u32* count,
                                     char* names,
                                     u32 capacity) {
    if (response.headers_truncated || response.content_length_count > 1 ||
        (response.chunked && response.has_content_length))
        return false;
    const bool kUpgraded = response.status_code == 101;
    if (kUpgraded &&
        !ws_handshake_response_matches(response, x.ws_offers, x.ws_offers_len, {}, nullptr, true))
        return false;
    if (!kUpgraded && response.status_code >= 200 && response.status_code < 300) return false;
    c.resp_status = kUpgraded ? 200 : response.status_code;
    char* status = names;
    if (capacity < 3) return false;
    status[0] = static_cast<char>('0' + c.resp_status / 100);
    status[1] = static_cast<char>('0' + (c.resp_status / 10) % 10);
    status[2] = static_cast<char>('0' + c.resp_status % 10);
    headers[0] = {{":status", 7}, {status, 3}};
    *count = 1;
    u32 used = 3;
    for (u32 i = 0; i < response.header_count; ++i) {
        const auto& h = response.headers[i];
        if (h2_is_prohibited_response_header(h.name.ptr, h.name.len) ||
            http_header_name_eq_ci(h.name.ptr, h.name.len, "sec-websocket-accept", 20) ||
            http_header_name_eq_ci(h.name.ptr, h.name.len, "content-length", 14))
            continue;
        bool nominated = false;
        for (u32 j = 0; j < response.header_count; ++j) {
            const auto& connection = response.headers[j];
            if (!http_header_name_eq_ci(connection.name.ptr, connection.name.len, "connection", 10))
                continue;
            u32 start = 0;
            while (start < connection.value.len) {
                while (start < connection.value.len &&
                       (connection.value.ptr[start] == ' ' || connection.value.ptr[start] == '\t' ||
                        connection.value.ptr[start] == ','))
                    ++start;
                u32 end = start;
                while (end < connection.value.len && connection.value.ptr[end] != ',') ++end;
                u32 last = end;
                while (last > start && (connection.value.ptr[last - 1] == ' ' ||
                                        connection.value.ptr[last - 1] == '\t'))
                    --last;
                nominated |= http_header_name_eq_ci(
                    h.name.ptr, h.name.len, connection.value.ptr + start, last - start);
                start = end + 1;
            }
        }
        if (nominated && kUpgraded &&
            (http_header_name_eq_ci(h.name.ptr, h.name.len, "sec-websocket-protocol", 22) ||
             http_header_name_eq_ci(h.name.ptr, h.name.len, "sec-websocket-extensions", 24)))
            return false;
        if (nominated) continue;
        if (*count >= Http2Conn::kMaxHeadersPerReq || h.name.len > capacity - used) return false;
        for (u32 j = 0; j < h.name.len; ++j) {
            const char kCh = h.name.ptr[j];
            names[used + j] = kCh >= 'A' && kCh <= 'Z' ? static_cast<char>(kCh + 'a' - 'A') : kCh;
        }
        headers[(*count)++] = {{names + used, h.name.len}, h.value};
        used += h.name.len;
    }
    if (!kUpgraded) {
        c.resp_body_mode = response.status_code == 304   ? BodyMode::None
                           : response.chunked            ? BodyMode::Chunked
                           : response.has_content_length ? BodyMode::ContentLength
                                                         : BodyMode::UntilClose;
        c.resp_body_remaining = response.content_length;
        c.resp_chunk_parser.reset();
    }
    return true;
}

template <typename Loop>
void h2ws_h1_received(void* lp, Connection& c, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (!c.h2) return;
    auto& g = c.h2->grpc;
    if (g.connecting || g.busy) return;
    auto* x = grpc_find(*c.h2, 1);
    if (!x) {
        loop->close_conn(c);
        return;
    }
    if (ev.result < 0) {
        loop->close_conn(c);
        return;
    }
    if (ev.result == 0) g.websocket_http1_eof = true;
    if (g.client_tls.ssl_ctx && !g.tls_verified) {
        SSL* ssl = c.tls_engine.ssl ? c.tls_engine.ssl : c.tls;
        if (!tls_handshake_finished(ssl)) return;
        if (!tls_client_peer_valid(ssl, false)) {
            loop->close_conn(c);
            return;
        }
        g.tls_verified = true;
    }
    g.busy = true;
    while (!g.websocket_http1_headers) {
        HttpResponseParser parser{};
        ParsedResponse response{};
        const auto kStatus = parser.parse(c.recv_buf.data(), c.recv_buf.len(), &response);
        if (kStatus == ParseStatus::Incomplete && !g.websocket_http1_eof &&
            c.recv_buf.len() < GrpcExchange::kHeaders)
            break;
        if (kStatus != ParseStatus::Complete || parser.header_end > GrpcExchange::kHeaders) {
            x->failure = 13;
            x->response_end = true;
            g.busy = false;
            loop->close_conn(c);
            return;
        }
        if (response.status_code < 200 && response.status_code != 101) {
            c.consume_request_receive_buffer(parser.header_end);
            continue;
        }
        hpack::Header headers[Http2Conn::kMaxHeadersPerReq];
        char names[Http2Conn::kHeaderScratchCap];
        u32 count = 0;
        if (!h2ws_h1_response_headers(c, *x, response, headers, &count, names, sizeof(names))) {
            x->failure = 13;
            x->response_end = true;
            g.busy = false;
            loop->close_conn(c);
            return;
        }
        const bool kEnd =
            response.status_code != 101 &&
            (c.resp_body_mode == BodyMode::None ||
             (c.resp_body_mode == BodyMode::ContentLength && c.resp_body_remaining == 0));
        GrpcClientDispatch<Loop> dispatch{loop, &c};
        grpc_response_headers<Loop>(&dispatch, *c.h2, 1, headers, count, kEnd);
        if (x->failure) {
            // Header validation may already have detached this exchange from
            // the upstream, so its close callback can no longer wake the client.
            Connection* down = x->downstream;
            g.busy = false;
            loop->close_conn(c);
            if (down && down->h2) {
                grpc_refresh_timer(loop, *down);
                grpc_kick_downstream(loop, *down);
            }
            return;
        }
        g.websocket_http1_headers = true;
        c.is_ws_tunnel = x->ws_accepted;
        c.consume_request_receive_buffer(parser.header_end);
    }
    while (g.websocket_http1_headers && !x->response_end && c.recv_buf.len() &&
           x->download_len < sizeof(x->download)) {
        u32 n = sizeof(x->download) - x->download_len;
        if (n > c.recv_buf.len()) n = c.recv_buf.len();
        u32 consumed = n, start = 0, produced = n;
        if (!x->ws_accepted) {
            if (c.resp_body_mode == BodyMode::ContentLength) {
                if (n > c.resp_body_remaining) n = c.resp_body_remaining;
                consumed = produced = n;
                c.resp_body_remaining -= n;
            } else if (c.resp_body_mode == BodyMode::Chunked) {
                const auto kResult =
                    c.resp_chunk_parser.feed(c.recv_buf.data(), n, &consumed, &start, &produced);
                if (kResult == ChunkStatus::Error) {
                    x->failure = 13;
                    break;
                }
                if (kResult != ChunkStatus::Data) produced = 0;
                if (kResult == ChunkStatus::Done) x->response_end = true;
            } else if (c.resp_body_mode == BodyMode::None) {
                x->response_end = true;
                break;
            }
        }
        if (produced)
            __builtin_memcpy(x->download + x->download_len, c.recv_buf.data() + start, produced);
        x->download_len += produced;
        if (x->ws && x->ws_accepted && !ws_h2_process(*x, false)) x->failure = 13;
        c.consume_request_receive_buffer(consumed);
        if (!x->ws_accepted && c.resp_body_mode == BodyMode::ContentLength &&
            !c.resp_body_remaining)
            x->response_end = true;
        if (!consumed) break;
    }
    if (g.websocket_http1_eof && c.recv_buf.len() == 0) {
        if (!g.websocket_http1_headers ||
            (!x->ws_accepted &&
             ((c.resp_body_mode == BodyMode::ContentLength && c.resp_body_remaining) ||
              (c.resp_body_mode == BodyMode::Chunked &&
               c.resp_chunk_parser.state != ChunkedParser::State::Complete))))
            x->failure = 13;
        if (x->ws && x->ws_accepted)
            ws_h2_eof(*x, false);
        else
            x->response_end = true;
    }
    Connection* down = x->downstream;
    if (g.websocket_http1_eof || c.recv_buf.len() || x->response_end ||
        x->download_len == sizeof(x->download)) {
        if (!h2ws_h1_pause(loop, c)) {
            g.busy = false;
            loop->close_conn(c);
            return;
        }
    } else {
        c.recv_paused_for_send = false;
        if (!loop->submit_recv(c)) {
            g.busy = false;
            loop->close_conn(c);
            return;
        }
    }
    g.busy = false;
    h2ws_h1_drive(loop, c);
    if (down && down->h2) {
        grpc_refresh_timer(loop, *down);
        grpc_kick_downstream(loop, *down);
    }
}

}  // namespace rut
