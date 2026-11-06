#pragma once

// Included after the bounded exchange pumps. An H1 downstream has one virtual
// stream in its metadata owner; the physical socket remains an H1/TLS socket.
#include "rut/runtime/callbacks.h"

namespace rut {
template <typename Loop>
bool ws_prepare_handshake_before_forward(Loop*, Connection&);
template <typename Loop>
void h1ws_h2_drive(Loop*, Connection&);

inline u32 h1ws_h2_response(Connection& c,
                            const hpack::Header* headers,
                            u32 count,
                            bool accepted,
                            u8* output,
                            u32 capacity) {
    u32 used = 0;
    auto put = [&](Str value) {
        if (value.len > capacity - used) return false;
        __builtin_memcpy(output + used, value.ptr, value.len);
        used += value.len;
        return true;
    };
    Str status{};
    for (u32 i = 0; i < count; ++i)
        if (headers[i].name.eq(lit_str(":status"))) status = headers[i].value;
    if (status.len == 3)
        c.resp_status = static_cast<u16>((status.ptr[0] - '0') * 100 + (status.ptr[1] - '0') * 10 +
                                         status.ptr[2] - '0');
    if (accepted) {
        if (!c.ws_handshake_slice ||
            !put(lit_str("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "
                         "websocket\r\nSec-WebSocket-Accept: ")) ||
            !put({reinterpret_cast<const char*>(c.ws_handshake_slice), kWsHandshakeAcceptLength}) ||
            !put(lit_str("\r\n")))
            return 0;
    } else if (!status.len || !put(lit_str("HTTP/1.1 ")) || !put(status) ||
               !put(lit_str(" Upstream Response\r\nConnection: close\r\n")))
        return 0;
    for (u32 i = 0; i < count; ++i) {
        const auto& h = headers[i];
        if (!h.name.len || h.name.ptr[0] == ':' ||
            h2_is_prohibited_response_header(h.name.ptr, h.name.len) ||
            http_header_name_eq_ci(h.name.ptr, h.name.len, "content-length", 14))
            continue;
        if (!put(h.name) || !put(lit_str(": ")) || !put(h.value) || !put(lit_str("\r\n"))) return 0;
    }
    return put(lit_str("\r\n")) ? used : 0;
}

template <typename Loop>
void h1ws_h2_complete_http(Loop* loop, Connection& c, GrpcExchange& x) {
    if constexpr (requires { loop->capture_ring; }) {
        if (!c.req_start_us) return;
        c.downstream_req_size = c.req_size =
            c.ws_client_header_len ? c.ws_client_header_len : c.req_header_end;
        const u64 kBytes = x.response_headers_len + x.staged_response_bytes;
        on_request_complete(
            loop, c, c.resp_status, kBytes > 0xffffffffu ? 0xffffffffu : static_cast<u32>(kBytes));
    }
}

template <typename Loop>
void h1ws_h2_sent(void* lp, Connection& c, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result <= 0 || static_cast<u32>(ev.result) > c.send_buf.len() - c.send_progress) {
        loop->close_conn(c);
        return;
    }
    c.send_progress += static_cast<u32>(ev.result);
    if (c.send_progress < c.send_buf.len()) {
        if (!client_send(
                loop, c, c.send_buf.data() + c.send_progress, c.send_buf.len() - c.send_progress))
            loop->close_conn(c);
        return;
    }
    c.on_send = nullptr;
    c.send_progress = 0;
    c.send_buf.reset();
    auto* x = grpc_find(*c.h2, 1);
    if (x && x->ws_accepted && !x->failure) {
        c.is_ws_tunnel = true;
        c.resp_status = 101;
        h1ws_h2_complete_http(loop, c, *x);
        if (x->ws) {
            ws_h2_sent(*x, false);
            if (!ws_h2_open(*x)) x->failure = 13;
        }
    } else if (x && x->failure)
        h1ws_h2_complete_http(loop, c, *x);
    h1ws_h2_received<Loop>(lp, c, {c.id, 1, 0, 0, IoEventType::Recv, 0});
}

template <typename Loop>
void h1ws_h2_tls_sent(void* lp, Connection& c, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result <= 0 || !h2ws_h1_tls_finished(loop, c)) {
        loop->close_conn(c);
        return;
    }
    h1ws_h2_received<Loop>(lp, c, {c.id, 1, 0, 0, IoEventType::Recv, 0});
}

template <typename Loop>
void h1ws_h2_drive(Loop* loop, Connection& c) {
    if (!c.h2 || c.h2->grpc.busy || c.on_send) return;
    auto* x = grpc_find(*c.h2, 1);
    if (!x || (x->failure && x->response_headers_sent)) {
        loop->close_conn(c);
        return;
    }
    auto& g = c.h2->grpc;
    if (x->response_end_sent && x->request_end_sent) {
        g.busy = true;
        grpc_release(loop, x, false);
        g.busy = false;
        loop->close_conn(c);
        return;
    }
    g.busy = true;
    c.send_buf.reset();
    if (!x->response_headers_sent) {
        if (x->failure) {
            const Str kStatus = x->failure == 4    ? lit_str("504")
                                : x->failure == 14 ? lit_str("503")
                                                   : lit_str("502");
            const hpack::Header kError{lit_str(":status"), kStatus};
            x->response_headers_len = h1ws_h2_response(
                c, &kError, 1, false, x->response_headers, sizeof(x->response_headers));
        }
        if (x->response_headers_len) {
            if (x->response_headers_len > c.send_buf.capacity()) {
                g.busy = false;
                loop->close_conn(c);
                return;
            }
            c.send_buf.write(x->response_headers, x->response_headers_len);
            x->response_headers_sent = true;
        }
    } else {
        u32 length = 0;
        const u8* output = grpc_output(*x, false, &length);
        if (length) {
            const u32 kAmount = length < c.send_buf.capacity() ? length : c.send_buf.capacity();
            c.send_buf.write(output, kAmount);
            grpc_consume_output(*x, false, kAmount);
            x->staged_response_bytes += kAmount;
        } else if (!x->download_len && x->response_end && !x->response_end_sent) {
            if (!x->ws_accepted) {
                h1ws_h2_complete_http(loop, c, *x);
                g.busy = false;
                loop->close_conn(c);
                return;
            }
            if (c.tls_active) {
                if constexpr (requires { loop->submit_ws_tls_shutdown(c); }) {
                    c.ws_closing = c.ws_tls_shutdown_pending = c.ws_upstream_send_pending = true;
                    c.on_send = &h1ws_h2_tls_sent<Loop>;
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
            x->response_end_sent = true;
        }
    }
    if (x->upstream) grpc_drive_upstream(loop, *x->upstream);
    if (c.send_buf.len()) {
        c.on_send = &h1ws_h2_sent<Loop>;
        if (!client_send(loop, c, c.send_buf.data(), c.send_buf.len())) {
            g.busy = false;
            loop->close_conn(c);
            return;
        }
    }
    g.busy = false;
    if (!c.on_send && x->response_end_sent && x->request_end_sent) {
        g.busy = true;
        grpc_release(loop, x, false);
        g.busy = false;
        loop->close_conn(c);
        return;
    }
    grpc_refresh_timer(loop, c);
}

template <typename Loop>
void h1ws_h2_received(void* lp, Connection& c, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (!c.h2) return;
    auto& g = c.h2->grpc;
    if (ev.result == 0) g.websocket_http1_eof = true;
    if (g.busy) return;
    auto* x = grpc_find(*c.h2, 1);
    if (!x || ev.result < 0) {
        loop->close_conn(c);
        return;
    }
    g.busy = true;
    u32 length = sizeof(x->upload) - x->upload_len;
    if (length > c.recv_buf.len()) length = c.recv_buf.len();
    if (length) {
        const bool kEnd = g.websocket_http1_eof && length == c.recv_buf.len();
        Http2Conn* const h2 = c.h2;
        const u32 handler_gen = c.handler_gen;
        grpc_request_data(loop, c, *x, c.recv_buf.data(), length, kEnd);
        // A timer-arm failure may synchronously close an H1 WebSocket bridge
        // with a response send pending. Its close callback releases the
        // exchange and clears c.h2, so do not touch either afterward.
        if (c.h2 != h2 || c.handler_gen != handler_gen) return;
        if (grpc_find(*h2, 1) != x) return;
        c.consume_request_receive_buffer(length);
    } else if (g.websocket_http1_eof && !c.recv_buf.len()) {
        if (x->ws)
            ws_h2_eof(*x, true);
        else
            x->request_end = true;
        if (x->upstream) grpc_drive_upstream(loop, *x->upstream);
    }
    if (g.websocket_http1_eof || c.recv_buf.len() || x->upload_len == sizeof(x->upload)) {
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
    h1ws_h2_drive(loop, c);
}

inline bool h1ws_h2_hop_header(const ParsedRequest& req, Str name) {
    if (h2_is_prohibited_response_header(name.ptr, name.len) ||
        http_header_name_eq_ci(name.ptr, name.len, "host", 4) ||
        http_header_name_eq_ci(name.ptr, name.len, "te", 2) ||
        http_header_name_eq_ci(name.ptr, name.len, "content-length", 14) ||
        http_header_name_eq_ci(name.ptr, name.len, "sec-websocket-key", 17) ||
        http_header_name_eq_ci(name.ptr, name.len, "sec-websocket-accept", 20))
        return true;
    for (u32 i = 0; i < req.header_count; ++i) {
        const auto& header = req.headers[i];
        if (!http_header_name_eq_ci(header.name.ptr, header.name.len, "connection", 10)) continue;
        u32 start = 0;
        while (start < header.value.len) {
            u32 end = start;
            while (end < header.value.len && header.value.ptr[end] != ',') ++end;
            Str token{header.value.ptr + start, end - start};
            while (token.len && (token.ptr[0] == ' ' || token.ptr[0] == '\t')) {
                ++token.ptr;
                --token.len;
            }
            while (token.len &&
                   (token.ptr[token.len - 1] == ' ' || token.ptr[token.len - 1] == '\t'))
                --token.len;
            if (http_header_name_eq_ci(name.ptr, name.len, token.ptr, token.len)) return true;
            start = end + 1;
        }
    }
    return false;
}

template <typename Loop>
bool h1ws_h2_start(Loop* loop, Connection& c, const RouteEntry* route, u16 uid) {
    if constexpr (!RUT_ENABLE_WEBSOCKET || !(requires {
                      loop->grpc_upstreams;
                      loop->pool.alloc_bulk();
                      loop->upstream_release(u16{});
                      loop->alloc_h2(c);
                  }))
        return false;
    else {
        const RouteConfig* cfg = c.request_config;
        if (!RUT_ENABLE_WEBSOCKET || !c.req_wants_upgrade || !cfg || uid >= cfg->upstream_count ||
            !cfg->upstreams[uid].http2)
            return false;
        auto reject = [&](u16 status) {
            hpack::Header header{lit_str(":status"), {}};
            char digits[] = {static_cast<char>('0' + status / 100),
                             static_cast<char>('0' + status / 10 % 10),
                             static_cast<char>('0' + status % 10)};
            header.value = {digits, 3};
            c.send_buf.reset();
            const u32 kN = h1ws_h2_response(
                c, &header, 1, false, c.send_buf.write_ptr(), c.send_buf.write_avail());
            c.send_buf.commit(kN);
            c.keep_alive = false;
            c.transition_to_sending(&on_response_sent<Loop>);
            if (!kN || !client_send(loop, c, c.send_buf.data(), kN)) loop->close_conn(c);
        };
        if (!h2_apply_forward_request_overrides(c)) {
            reject(400);
            return true;
        }
        ParsedRequest request{};
        HttpParser parser{};
        if (parser.parse(c.recv_buf.data(), c.recv_buf.len(), &request) != ParseStatus::Complete) {
            reject(400);
            return true;
        }
        if (!c.ws_handshake_slice) {
            const bool kWasTerminate = c.is_ws_terminate_route;
            c.is_ws_terminate_route = true;
            const bool kReady = ws_prepare_handshake_before_forward(loop, c);
            c.is_ws_terminate_route = kWasTerminate;
            if (!kReady) return true;
        }
        u32 offers = 0;
        const auto kValidation = ws_prepare_handshake(c.recv_buf.data(),
                                                      parser.header_end,
                                                      c.ws_handshake_slice,
                                                      SlicePool::kSliceSize,
                                                      &offers,
                                                      c.ws_subprotocol);
        if (kValidation != WsHandshakeRequestResult::Ready) {
            reject(kValidation == WsHandshakeRequestResult::InternalError ? 503 : 400);
            return true;
        }
        Str host{};
        for (u32 i = 0; i < request.header_count; ++i)
            if (http_header_name_eq_ci(
                    request.headers[i].name.ptr, request.headers[i].name.len, "host", 4))
                host = request.headers[i].value;
        hpack::Header hs[Http2Conn::kMaxHeadersPerReq];
        char names[Http2Conn::kHeaderScratchCap];
        u32 used = 0, n = 5;
        hs[0] = {lit_str(":method"), lit_str("CONNECT")};
        hs[1] = {lit_str(":protocol"), lit_str("websocket")};
        hs[2] = {lit_str(":scheme"),
                 cfg->upstreams[uid].tls.enabled ? lit_str("https") : lit_str("http")};
        hs[3] = {lit_str(":authority"), host};
        hs[4] = {lit_str(":path"), request.path};
        for (u32 i = 0; i < request.header_count; ++i) {
            const auto& h = request.headers[i];
            if (h1ws_h2_hop_header(request, h.name)) continue;
            if (n == Http2Conn::kMaxHeadersPerReq || h.name.len > sizeof(names) - used) {
                reject(400);
                return true;
            }
            for (u32 j = 0; j < h.name.len; ++j) {
                const char kCh = h.name.ptr[j];
                names[used + j] =
                    kCh >= 'A' && kCh <= 'Z' ? static_cast<char>(kCh + 'a' - 'A') : kCh;
            }
            hs[n++] = {{names + used, h.name.len}, h.value};
            used += h.name.len;
        }
        ParsedRequest translated{};
        Str protocol{};
        if (!host.len || !h2_headers_to_request(hs, n, &translated, &protocol) || c.h2) {
            reject(400);
            return true;
        }
        if (!loop->alloc_h2(c)) {
            reject(503);
            return true;
        }
        c.h2->init_client();
        c.h2->grpc.websocket_http1_downstream = true;
        c.h2->grpc.busy = true;
        auto* stream = c.h2->open_stream(1);
        stream->websocket = true;
        stream->headers_received_us = c.req_start_us;
        stream->websocket_route = route;
        c.upstream_idx = uid;
        const auto& target = cfg->upstreams[uid];
        const u32 kNameLength = target.name_len < sizeof(c.upstream_name) - 1
                                    ? target.name_len
                                    : static_cast<u32>(sizeof(c.upstream_name) - 1);
        __builtin_memcpy(c.upstream_name, target.name, kNameLength);
        c.upstream_name[kNameLength] = '\0';
        c.set_slots(&h1ws_h2_received<Loop>, nullptr, nullptr, nullptr);
        c.on_close = &grpc_connection_closed<Loop>;
        c.state = ConnState::ReadingBody;
        const bool kStarted = grpc_start(loop, c, 1, cfg, uid, hs, n, translated, false);
        stream->websocket_route = nullptr;
        stream->manual_window = false;
        c.h2->grpc.busy = false;
        if (!kStarted) {
            reject(stream->websocket_open_error ? stream->websocket_open_error : 503);
            return true;
        }
        // Only a started tunnel takes over the HTTP request epoch. A failed
        // start uses ordinary HTTP completion, which releases its own epoch.
        // Recording the 101 must keep callback code/configuration pinned.
        if (c.req_start_us)
            c.epoch_held = true;
        else
            h2_async_epoch_enter(loop, c);
        c.consume_request_receive_buffer(parser.header_end);
        h1ws_h2_received<Loop>(loop, c, {c.id, 1, 0, 0, IoEventType::Recv, 0});
        return true;
    }
}
}  // namespace rut
