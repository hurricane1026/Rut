#include "rut/runtime/ws_h2.h"

#include "core/placement_new.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/grpc_proxy_state.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_extensions.h"
#include "rut/runtime/ws_frame.h"
#include "rut/runtime/ws_terminate.h"

namespace rut {
namespace {
bool header_is(Str name, Str expected) {
    return http_header_name_eq_ci(name.ptr, name.len, expected.ptr, expected.len);
}
bool offered(const ParsedRequest& request, Str required) {
    if (!required.len) return true;
    for (u32 i = 0; i < request.header_count; ++i) {
        const auto& h = request.headers[i];
        if (!header_is(h.name, lit_str("sec-websocket-protocol"))) continue;
        u32 start = 0;
        while (start < h.value.len) {
            while (start < h.value.len && (h.value.ptr[start] == ' ' || h.value.ptr[start] == '\t'))
                ++start;
            u32 end = start;
            while (end < h.value.len && h.value.ptr[end] != ',') ++end;
            u32 last = end;
            while (last > start && (h.value.ptr[last - 1] == ' ' || h.value.ptr[last - 1] == '\t'))
                --last;
            if (Str{h.value.ptr + start, last - start}.eq(required)) return true;
            start = end + 1;
        }
    }
    return false;
}
bool begin_close(WsH2Session& session, u16 code, Str reason) {
    auto& c = session.callback;
    if (c.ws_closing) return true;
    if (!c.ws_close_payload.assign(code, reason)) return false;
    c.ws_closing = true;
    c.ws_close_client_need = c.ws_close_upstream_need = true;
    session.close_deadline_us = monotonic_us() + 5000000;
    return true;
}
bool fill_closes(WsH2Session& session) {
    auto& c = session.callback;
    for (u32 index = 0; index < 2; ++index) {
        bool& needed = index == 0 ? c.ws_close_upstream_need : c.ws_close_client_need;
        if (!needed || session.output_length[index]) continue;
        u8* output = index == 0 ? c.ws_c2u_out : c.ws_u2c_out;
        u64& rng = index == 0 ? c.ws_c2u.mask_rng : c.ws_u2c.mask_rng;
        const u32 kN = ws_emit_close_payload(
            output, c.ws_buffer_capacity(), index == 0, rng, c.ws_close_payload);
        if (!kN) return false;
        session.output_length[index] = kN;
        session.output_offset[index] = 0;
        session.output_close[index] = true;
        needed = false;
    }
    return true;
}
}  // namespace

WsH2Session* ws_h2_create(SlicePool& pool, const RouteEntry& route, const Connection& down) {
    if (!route.ws_terminate || !route.ws_frame_handler ||
        !ws_valid_message_capacity(route.ws_max_message_size))
        return nullptr;
    static_assert(sizeof(WsH2Session) <= SlicePool::kSliceSize);
    // Placement construction gives this pool slot a mutable session lifetime.
    // NOLINTNEXTLINE(misc-const-correctness)
    void* storage = pool.alloc();
    if (!storage) return nullptr;
    auto* session = ::new (storage) WsH2Session{};
    auto& c = session->callback;
    c.reset();
    c.peer_addr = down.peer_addr;
    c.peer_port = down.peer_port;
    c.shard_id = down.shard_id;
    c.tls_active = down.tls_active;
    c.request_config = down.request_config;
    c.json_arena.backend.pool = &pool;
    c.ws_handler = route.ws_frame_handler;
    c.ws_open_handler = route.ws_open_handler;
    c.ws_close_handler = route.ws_close_handler;
    c.ws_subprotocol = route.ws_subprotocol;
    c.ws_max_message_size = route.ws_max_message_size;
    c.ws_close_code = route.ws_close_code;
    c.ws_close_reason = route.ws_close_reason;
    c.ws_close_policies = route.ws_close_policies;
    c.ws_close_policy_count = route.ws_close_policy_count;
    c.ws_forward_text = route.ws_forward_text;
    c.ws_forward_texts = route.ws_forward_texts;
    c.ws_forward_text_count = route.ws_forward_text_count;
    return session;
}

void ws_h2_destroy(SlicePool& pool, WsH2Session* session) {
    if (!session) return;
    auto& c = session->callback;
    if (c.ws_session_started && !c.ws_session_close_notified) {
        c.ws_session_close_notified = true;
        if (c.ws_close_handler) (void)c.ws_close_handler(&c, WsOpcode::Text, nullptr, 0, true);
    }
    c.json_arena.destroy();
    c.free_ws_codecs(pool);
    if (c.ws_c2u_msg) pool.free(c.ws_c2u_msg);
    if (c.ws_u2c_msg) pool.free(c.ws_u2c_msg);
    if (c.ws_c2u_out) pool.free(c.ws_c2u_out);
    if (c.ws_u2c_out) pool.free(c.ws_u2c_out);
    if (c.response_header_slice) pool.free(c.response_header_slice);
    session->~WsH2Session();
    pool.free(reinterpret_cast<u8*>(session));
}

bool ws_h2_prepare_request(WsH2Session& session, const ParsedRequest& request, ParsedRequest* out) {
    auto& c = session.callback;
    if (!offered(request, c.ws_subprotocol) ||
        !ws_select_deflate_offer(request.headers, request.header_count, &c.ws_downstream_deflate))
        return false;
    *out = request;
    out->header_count = 0;
    for (u32 i = 0; i < request.header_count; ++i) {
        const auto& h = request.headers[i];
        if (header_is(h.name, lit_str("sec-websocket-extensions")) ||
            (c.ws_subprotocol.len && header_is(h.name, lit_str("sec-websocket-protocol"))))
            continue;
        out->headers[out->header_count++] = h;
    }
    if (out->header_count >= kMaxHeaders) return false;
    out->headers[out->header_count++] = {lit_str("sec-websocket-extensions"), kWsDeflateOffer, {}};
    if (c.ws_subprotocol.len) {
        if (out->header_count >= kMaxHeaders) return false;
        out->headers[out->header_count++] = {
            lit_str("sec-websocket-protocol"), c.ws_subprotocol, {}};
    }
    return true;
}

bool ws_h2_accept(WsH2Session& session, SlicePool& pool, const Header* headers, u32 count) {
    auto& c = session.callback;
    if (session.ready || !ws_accept_deflate_response(headers, count, &c.ws_upstream_deflate))
        return false;
    Str selected{};
    for (u32 i = 0; i < count; ++i)
        if (header_is(headers[i].name, lit_str("sec-websocket-protocol")))
            selected = headers[i].value;
    if (c.ws_subprotocol.len && !selected.eq(c.ws_subprotocol)) return false;
    if (selected.len) {
        if (selected.len > SlicePool::kSliceSize) return false;
        c.response_header_slice = pool.alloc();
        if (!c.response_header_slice) return false;
        __builtin_memcpy(c.response_header_slice, selected.ptr, selected.len);
        c.ws_negotiated_subprotocol = {reinterpret_cast<const char*>(c.response_header_slice),
                                       selected.len};
    }
    if (!c.alloc_ws_buffers(pool)) return false;
    auto configure = [&](WsInspector& inspector, bool from_client) {
        inspector.reset();
        inspector.masked = inspector.from_client = from_client;
        inspector.decoder = from_client ? c.ws_downstream_codec : c.ws_upstream_codec;
        inspector.encoder = from_client ? c.ws_upstream_codec : c.ws_downstream_codec;
        inspector.max_message_size = c.ws_max_message_size;
        inspector.dynamic_output = &c.ws_handler_output;
        inspector.forward_text = c.ws_forward_text;
        inspector.forward_texts = c.ws_forward_texts;
        inspector.forward_text_count = c.ws_forward_text_count;
        inspector.close_code = c.ws_close_code;
        inspector.close_reason = c.ws_close_reason;
        inspector.close_policies = c.ws_close_policies;
        inspector.close_policy_count = c.ws_close_policy_count;
    };
    configure(c.ws_c2u, true);
    configure(c.ws_u2c, false);
    c.is_ws_terminate = true;
    session.ready = true;
    return true;
}

void ws_h2_update_end(GrpcExchange& exchange) {
    auto& session = *exchange.ws;
    auto& c = session.callback;
    if (!c.ws_closing) return;
    exchange.deadline_us = session.close_deadline_us;
    if (c.ws_close_upstream_sent && (c.ws_close_upstream_received || c.ws_upstream_eof))
        exchange.request_end = true;
    if (c.ws_close_client_sent && (c.ws_close_client_received || c.ws_client_eof))
        exchange.response_end = true;
    c.ws_close_handshake_complete = c.ws_close_client_sent && c.ws_close_upstream_sent &&
                                    c.ws_close_client_received && c.ws_close_upstream_received;
}

bool ws_h2_open(GrpcExchange& exchange) {
    auto& session = *exchange.ws;
    auto& c = session.callback;
    if (!session.ready || c.ws_session_started) return session.ready;
    c.ws_session_started = true;
    exchange.deadline_us = 0;
    const auto kAction = c.ws_open_handler ? c.ws_open_handler(&c, WsOpcode::Text, nullptr, 0, true)
                                           : WsFrameAction::Drop;
    if (kAction == WsFrameAction::Close || kAction == WsFrameAction::CloseDynamic) {
        const auto& result = c.ws_handler_output;
        if (kAction == WsFrameAction::CloseDynamic &&
            (!result.ready || result.opcode != WsOpcode::Close))
            return false;
        if (!begin_close(
                session,
                kAction == WsFrameAction::CloseDynamic ? result.close_code : c.ws_close_code,
                kAction == WsFrameAction::CloseDynamic ? result.payload : c.ws_close_reason))
            return false;
    } else if (kAction != WsFrameAction::Drop && kAction != WsFrameAction::Forward)
        return false;
    if (!fill_closes(session)) return false;
    ws_h2_update_end(exchange);
    return true;
}

bool ws_h2_process(GrpcExchange& exchange, bool from_client) {
    auto& session = *exchange.ws;
    auto& c = session.callback;
    if (!c.ws_session_started) return true;
    const u32 kIndex = from_client ? 0 : 1;
    auto& length = from_client ? exchange.upload_len : exchange.download_len;
    u8* input = from_client ? exchange.upload : exchange.download;
    auto& inspector = from_client ? c.ws_c2u : c.ws_u2c;
    u32 consumed = 0;
    if (!c.ws_closing) {
        if (session.output_length[kIndex]) return true;
        u32 produced = 0;
        const auto kStatus = ws_inspect(inspector,
                                        input,
                                        length,
                                        from_client ? c.ws_c2u_out : c.ws_u2c_out,
                                        c.ws_buffer_capacity(),
                                        from_client ? c.ws_c2u_msg : c.ws_u2c_msg,
                                        c.ws_max_message_size,
                                        c.ws_handler,
                                        &c,
                                        &consumed,
                                        &produced);
        if (kStatus == WsInspectStatus::Error) return false;
        session.output_length[kIndex] = produced;
        session.output_offset[kIndex] = 0;
        if (inspector.received_close && !c.ws_record_peer_close(from_client, inspector))
            return false;
        if (kStatus == WsInspectStatus::Close) {
            if (!begin_close(session, inspector.echo_close_code, inspector.echo_close_reason()))
                return false;
            session.output_close[kIndex] = produced != 0;
            if (produced) (from_client ? c.ws_close_upstream_need : c.ws_close_client_need) = false;
        }
    } else if (length) {
        // Closing controls reply to their sender. Do not consume a Ping until
        // its owned reply slot is free; the fixed close deadline bounds stalls.
        const u32 kReply = 1 - kIndex;
        if (session.output_length[kReply]) return true;
        u8 ping[kWsMaxControlPayload];
        u32 ping_length = 0;
        const auto kStatus =
            ws_read_closing(inspector, input, length, ping, &ping_length, &consumed);
        if (kStatus == WsClosingRead::Error) return false;
        if (inspector.received_close && !c.ws_record_peer_close(from_client, inspector))
            return false;
        if (kStatus == WsClosingRead::Ping) {
            u64& rng = from_client ? c.ws_u2c.mask_rng : c.ws_c2u.mask_rng;
            const u32 kProduced = ws_emit_pong_frame(from_client ? c.ws_u2c_out : c.ws_c2u_out,
                                                     c.ws_buffer_capacity(),
                                                     !from_client,
                                                     rng,
                                                     ping,
                                                     ping_length);
            if (!kProduced) return false;
            session.output_length[kReply] = kProduced;
            session.output_offset[kReply] = 0;
        }
    }
    if (consumed) {
        length -= consumed;
        if (length) __builtin_memmove(input, input + consumed, length);
        Connection* owner = from_client ? exchange.downstream : exchange.upstream;
        if (owner && owner->h2 && !owner->h2->grpc.websocket_http1 &&
            !owner->h2->grpc.websocket_http1_downstream)
            owner->h2->consume_data(
                from_client ? exchange.downstream_stream : exchange.upstream_stream, consumed);
    }
    if (!c.ws_closing && !session.output_length[kIndex] &&
        (from_client ? c.ws_client_eof : c.ws_upstream_eof)) {
        // END_STREAM cannot complete a partial frame or fragmented message.
        // Waiting for bytes here would strand an accepted, deadline-free stream.
        if (length || inspector.partial_data_frame || inspector.assembler.in_fragmented)
            return false;
        if (!begin_close(session, 1001, {})) return false;
    }
    if (!fill_closes(session)) return false;
    ws_h2_update_end(exchange);
    return true;
}

void ws_h2_eof(GrpcExchange& exchange, bool from_client) {
    auto& session = *exchange.ws;
    auto& c = session.callback;
    (from_client ? c.ws_client_eof : c.ws_upstream_eof) = true;
    if (!c.ws_session_started) return;
    if (!ws_h2_process(exchange, from_client)) exchange.failure = 13;
}

const u8* ws_h2_output(GrpcExchange& exchange, bool from_client, u32* length) {
    auto& session = *exchange.ws;
    const u32 kIndex = from_client ? 0 : 1;
    *length = session.output_length[kIndex] - session.output_offset[kIndex];
    if (!*length) return nullptr;
    return (from_client ? session.callback.ws_c2u_out : session.callback.ws_u2c_out) +
           session.output_offset[kIndex];
}

bool ws_h2_consume_output(GrpcExchange& exchange, bool from_client, u32 length) {
    auto& session = *exchange.ws;
    const u32 kIndex = from_client ? 0 : 1;
    if (length > session.output_length[kIndex] - session.output_offset[kIndex]) return false;
    session.output_offset[kIndex] += length;
    if (session.output_offset[kIndex] == session.output_length[kIndex]) {
        session.output_length[kIndex] = session.output_offset[kIndex] = 0;
        if (session.output_close[kIndex]) {
            session.close_staged[kIndex] = true;
            session.output_close[kIndex] = false;
        }
    }
    if (!fill_closes(session)) return false;
    ws_h2_update_end(exchange);
    return true;
}

void ws_h2_sent(GrpcExchange& exchange, bool from_client) {
    auto& session = *exchange.ws;
    const u32 kIndex = from_client ? 0 : 1;
    if (!session.close_staged[kIndex]) return;
    session.close_staged[kIndex] = false;
    (from_client ? session.callback.ws_close_upstream_sent
                 : session.callback.ws_close_client_sent) = true;
    ws_h2_update_end(exchange);
}
}  // namespace rut
