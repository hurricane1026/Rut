// Focused tests for the active plaintext gRPC Health HTTP/2 probe builder and
// bounded response decoder. The integration path is exercised separately in
// test_integration.cc against a loopback HTTP/2 backend.
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/http2_frame.h"
#include "test.h"

using namespace rut;

namespace {
struct ProbeHarness {
    const RouteConfig** config_ptr = nullptr;
    u32 send_submits = 0;
    u32 recv_submits = 0;
    u32 frees = 0;
    const u8* last_send = nullptr;
    u32 last_send_len = 0;

    bool submit_send_upstream(Connection&, const u8* bytes, u32 len) {
        send_submits++;
        last_send = bytes;
        last_send_len = len;
        return true;
    }
    bool submit_recv_upstream(Connection&) {
        recv_submits++;
        return true;
    }
    void free_health_probe(Connection&) { frees++; }
};

u32 health_put_frame(
    u8* out, Http2FrameType type, u8 flags, u32 stream_id, const u8* payload, u32 payload_len) {
    Http2FrameHeader frame{};
    frame.type = static_cast<u8>(type);
    frame.flags = flags;
    frame.stream_id = stream_id;
    frame.length = payload_len;
    write_frame_header(out, frame);
    for (u32 i = 0; i < payload_len; ++i) out[kFrameHeaderSize + i] = payload[i];
    return kFrameHeaderSize + payload_len;
}

bool append_bytes(Buffer& buffer, const u8* bytes, u32 len) {
    return buffer.write(bytes, len) == len;
}

void prepare_probe_connection(Connection& conn,
                              Http2Conn& h2,
                              const RouteConfig& config,
                              u8* request_storage,
                              u32 request_capacity,
                              u8* send_storage,
                              u32 send_capacity,
                              u8* upstream_storage,
                              u32 upstream_capacity) {
    conn.reset();
    conn.bind_request_receive_buffer(request_storage, request_capacity);
    conn.send_buf.bind(send_storage, send_capacity);
    conn.upstream_recv_buf.bind(upstream_storage, upstream_capacity);
    conn.h2 = &h2;
    conn.is_health_probe = true;
    conn.request_config = &config;
    conn.upstream_idx = 0;
    conn.upstream_backend_idx = 0;
}
}  // namespace

TEST(grpc_health_probe, validates_serving_response_and_split_envelope) {
    Http2Conn h2{};
    h2.init_client();
    hpack::Header headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc+proto", 22}},
    };
    on_probe_h2_headers(nullptr, h2, 1, headers, 2, false);
    const u8 first[] = {0, 0};
    const u8 second[] = {0, 0, 4, 0x08, 0x01};
    const u8 unknown_field[] = {0x78, 0x07};  // unknown field 15, varint wire type
    on_probe_h2_data(nullptr, h2, 1, first, sizeof(first), false);
    on_probe_h2_data(nullptr, h2, 1, second, sizeof(second), false);
    on_probe_h2_data(nullptr, h2, 1, unknown_field, sizeof(unknown_field), false);
    hpack::Header trailer[] = {{{"grpc-status", 11}, {"0", 1}}};
    on_probe_h2_trailers(nullptr, h2, 1, trailer, 1, true);
    CHECK(health_probe_serving_response(h2));
}

TEST(grpc_health_probe, request_encodes_128_byte_service_length_as_varint) {
    RouteConfig cfg{};
    auto id = cfg.add_upstream("grpc", 0x7f000001, 50051);
    REQUIRE(id.has_value());
    UpstreamTarget& target = cfg.upstreams[id.value()];
    target.http2 = true;
    target.hc_service_len = 128;
    for (u32 i = 0; i < target.hc_service_len; ++i) target.hc_service[i] = 's';
    u8 storage[SlicePool::kSliceSize];
    Connection conn{};
    conn.reset();
    conn.bind_request_receive_buffer(storage, sizeof(storage));
    Http2Conn h2{};
    conn.h2 = &h2;
    REQUIRE(build_grpc_health_probe_request(conn, target, 0));

    u32 pos = kClientPrefaceLen;
    bool service_found = false;
    while (pos + kFrameHeaderSize <= conn.recv_buf.len()) {
        Http2FrameHeader frame{};
        REQUIRE(parse_frame_header(conn.recv_buf.data() + pos, conn.recv_buf.len() - pos, &frame) ==
                ParseStatus::Complete);
        REQUIRE(pos + kFrameHeaderSize + frame.length <= conn.recv_buf.len());
        if (frame.type == static_cast<u8>(Http2FrameType::Data)) {
            const u8* payload = conn.recv_buf.data() + pos + kFrameHeaderSize;
            REQUIRE(frame.length == 5 + 1 + 2 + 128);
            CHECK_EQ(payload[0], 0u);
            CHECK_EQ(payload[5], 0x0au);
            CHECK_EQ(payload[6], 0x80u);
            CHECK_EQ(payload[7], 0x01u);
            service_found = true;
        }
        pos += kFrameHeaderSize + frame.length;
    }
    CHECK(service_found);
}

TEST(grpc_health_probe, client_processes_data_and_continued_trailers) {
    Http2Conn h2;
    h2.init_client();
    REQUIRE(h2.open_stream(1) != nullptr);
    h2.find_stream(1)->state = Http2StreamState::HalfClosedLocal;
    h2.cb_ctx = nullptr;
    h2.on_headers = &on_probe_h2_headers;
    h2.on_trailers = &on_probe_h2_trailers;
    h2.on_data = &on_probe_h2_data;
    h2.on_reset = &on_probe_h2_reset;

    hpack::Encoder encoder;
    encoder.init(4096);
    const hpack::Header initial[] = {{{":status", 7}, {"200", 3}},
                                     {{"content-type", 12}, {"application/grpc", 16}}};
    const hpack::Header trailer[] = {{{"grpc-status", 11}, {"0", 1}}};
    u8 wire[512];
    u32 wire_len = write_settings_frame(wire, h2.our_settings);
    REQUIRE(wire_len != 0);
    const u32 headers_len = http2_write_headers(
        wire + wire_len, sizeof(wire) - wire_len, 1, initial, 2, false, encoder);
    REQUIRE(headers_len != 0);
    wire_len += headers_len;
    const u8 envelope[] = {0, 0, 0, 0, 2, 0x08, 0x01};
    const u32 data_len = http2_write_data(wire + wire_len, 1, envelope, sizeof(envelope), false);
    REQUIRE(data_len != 0);
    wire_len += data_len;
    u8 trailer_frame[128];
    const u32 trailer_len =
        http2_write_headers(trailer_frame, sizeof(trailer_frame), 1, trailer, 1, true, encoder);
    REQUIRE(trailer_len > kFrameHeaderSize);
    Http2FrameHeader trailer_header{};
    REQUIRE(parse_frame_header(trailer_frame, trailer_len, &trailer_header) ==
            ParseStatus::Complete);
    const u32 trailer_payload_len = trailer_header.length;
    REQUIRE(trailer_payload_len > 1);
    const u32 split = trailer_payload_len / 2;
    wire_len += health_put_frame(wire + wire_len,
                                 Http2FrameType::Headers,
                                 http2_flag::kEndStream,
                                 1,
                                 trailer_frame + kFrameHeaderSize,
                                 split);
    wire_len += health_put_frame(wire + wire_len,
                                 Http2FrameType::Continuation,
                                 http2_flag::kEndHeaders,
                                 1,
                                 trailer_frame + kFrameHeaderSize + split,
                                 trailer_payload_len - split);

    u8 out[512];
    u32 out_len = 0;
    const Http2Result result = h2.process(wire, wire_len, out, sizeof(out), &out_len);
    CHECK_FALSE(result.close);
    CHECK_EQ(result.consumed, wire_len);
    CHECK(health_probe_serving_response(h2));
}

TEST(grpc_health_probe, deframer_accepts_bytewise_prefix_and_exact_message_cap) {
    Http2Conn h2{};
    h2.init_client();
    hpack::Header headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
    };
    on_probe_h2_headers(nullptr, h2, 1, headers, 2, false);

    u8 framed[5 + Http2Conn::kHealthProbeMessageCap];
    framed[0] = 0;
    framed[1] = static_cast<u8>(Http2Conn::kHealthProbeMessageCap >> 24);
    framed[2] = static_cast<u8>(Http2Conn::kHealthProbeMessageCap >> 16);
    framed[3] = static_cast<u8>(Http2Conn::kHealthProbeMessageCap >> 8);
    framed[4] = static_cast<u8>(Http2Conn::kHealthProbeMessageCap);
    framed[5] = 0x08;  // HealthCheckResponse.status = SERVING
    framed[6] = 0x01;
    for (u32 i = 7; i < sizeof(framed); i += 2) {
        framed[i] = 0x78;      // unknown field 15, varint wire type
        framed[i + 1] = 0x01;  // value 1
    }
    for (u32 i = 0; i < 5; ++i) on_probe_h2_data(nullptr, h2, 1, framed + i, 1, false);
    CHECK_EQ(h2.health_probe_prefix_len, 5u);
    CHECK_EQ(h2.health_probe_message_expected, Http2Conn::kHealthProbeMessageCap);
    const u32 first_body_chunk = 127;
    on_probe_h2_data(nullptr, h2, 1, framed + 5, first_body_chunk, false);
    on_probe_h2_data(nullptr,
                     h2,
                     1,
                     framed + 5 + first_body_chunk,
                     Http2Conn::kHealthProbeMessageCap - first_body_chunk,
                     false);
    hpack::Header trailer[] = {{{"grpc-status", 11}, {"0", 1}}};
    on_probe_h2_trailers(nullptr, h2, 1, trailer, 1, true);
    CHECK_EQ(h2.health_probe_message_len, Http2Conn::kHealthProbeMessageCap);
    CHECK(health_probe_serving_response(h2));
}

TEST(grpc_health_probe, deframer_rejects_over_cap_extra_messages_trailing_bytes_and_empty) {
    hpack::Header headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
    };
    const u8 serving[] = {0, 0, 0, 0, 2, 0x08, 0x01};

    Http2Conn over_cap{};
    over_cap.init_client();
    on_probe_h2_headers(nullptr, over_cap, 1, headers, 2, false);
    const u8 over_cap_prefix[] = {0, 0, 4, 1, 0};  // 1025-byte message
    on_probe_h2_data(nullptr, over_cap, 1, over_cap_prefix, sizeof(over_cap_prefix), false);
    CHECK(over_cap.health_probe_malformed);

    Http2Conn second_message{};
    second_message.init_client();
    on_probe_h2_headers(nullptr, second_message, 1, headers, 2, false);
    u8 two_messages[sizeof(serving) + 5];
    for (u32 i = 0; i < sizeof(serving); ++i) two_messages[i] = serving[i];
    for (u32 i = 0; i < 5; ++i) two_messages[sizeof(serving) + i] = 0;
    on_probe_h2_data(nullptr, second_message, 1, two_messages, sizeof(two_messages), false);
    CHECK(second_message.health_probe_malformed);

    Http2Conn trailing{};
    trailing.init_client();
    on_probe_h2_headers(nullptr, trailing, 1, headers, 2, false);
    on_probe_h2_data(nullptr, trailing, 1, serving, sizeof(serving), false);
    const u8 extra = 0;
    on_probe_h2_data(nullptr, trailing, 1, &extra, 1, false);
    CHECK(trailing.health_probe_malformed);

    Http2Conn empty{};
    empty.init_client();
    on_probe_h2_headers(nullptr, empty, 1, headers, 2, false);
    const u8 zero_length[] = {0, 0, 0, 0, 0};
    on_probe_h2_data(nullptr, empty, 1, zero_length, sizeof(zero_length), false);
    hpack::Header trailer[] = {{{"grpc-status", 11}, {"0", 1}}};
    on_probe_h2_trailers(nullptr, empty, 1, trailer, 1, true);
    CHECK(empty.health_probe_message_complete);
    CHECK(!health_probe_serving_response(empty));
}

TEST(grpc_health_probe, rejects_non_serving_or_malformed_responses) {
    Http2Conn h2{};
    h2.init_client();
    hpack::Header headers[] = {
        {{":status", 7}, {"200", 3}},
        {{"content-type", 12}, {"application/grpc", 16}},
    };
    on_probe_h2_headers(nullptr, h2, 1, headers, 2, false);
    const u8 not_serving[] = {0, 0, 0, 0, 2, 0x08, 0x02};
    on_probe_h2_data(nullptr, h2, 1, not_serving, sizeof(not_serving), false);
    hpack::Header trailer[] = {{{"grpc-status", 11}, {"0", 1}}};
    on_probe_h2_trailers(nullptr, h2, 1, trailer, 1, true);
    CHECK(!health_probe_serving_response(h2));

    const u8 serving_body[] = {0, 0, 0, 0, 2, 0x08, 0x01};
    h2.init_client();
    on_probe_h2_headers(nullptr, h2, 1, headers, 2, false);
    on_probe_h2_data(nullptr, h2, 1, serving_body, sizeof(serving_body), false);
    hpack::Header duplicate_trailers[] = {{{"grpc-status", 11}, {"0", 1}},
                                          {{"grpc-status", 11}, {"0", 1}}};
    on_probe_h2_trailers(nullptr, h2, 1, duplicate_trailers, 2, true);
    CHECK(!health_probe_serving_response(h2));

    h2.init_client();
    on_probe_h2_headers(nullptr, h2, 1, headers, 2, false);
    const u8 compressed[] = {1, 0, 0, 0, 0};
    on_probe_h2_data(nullptr, h2, 1, compressed, sizeof(compressed), true);
    CHECK(!health_probe_serving_response(h2));

    h2.init_client();
    on_probe_h2_headers(nullptr, h2, 1, headers, 2, false);
    on_probe_h2_data(nullptr, h2, 1, serving_body, sizeof(serving_body), true);
    CHECK(!health_probe_serving_response(h2));

    h2.init_client();
    hpack::Header trailers_only[] = {{{":status", 7}, {"200", 3}},
                                     {{"content-type", 12}, {"application/grpc", 16}},
                                     {{"grpc-status", 11}, {"0", 1}}};
    on_probe_h2_headers(nullptr, h2, 1, trailers_only, 3, true);
    CHECK(!health_probe_serving_response(h2));  // trailers-only / empty unary response

    h2.init_client();
    on_probe_h2_headers(nullptr, h2, 1, headers, 2, false);
    on_probe_h2_reset(nullptr, h2, 1, Http2Error::Cancel);
    CHECK(!health_probe_serving_response(h2));
}

TEST(grpc_health_probe, short_request_and_control_sends_preserve_preread_h2_response) {
    RouteConfig config{};
    auto uid = config.add_upstream("grpc", 0x7f000001, 50051);
    REQUIRE(uid.has_value());
    UpstreamTarget& target = config.upstreams[uid.value()];
    target.http2 = true;
    const RouteConfig* active_config = &config;

    ProbeHarness loop{};
    loop.config_ptr = &active_config;
    Connection conn{};
    Http2Conn h2{};
    u8 request_storage[SlicePool::kSliceSize];
    u8 send_storage[SlicePool::kSliceSize];
    u8 upstream_storage[SlicePool::kSliceSize];
    prepare_probe_connection(conn,
                             h2,
                             config,
                             request_storage,
                             sizeof(request_storage),
                             send_storage,
                             sizeof(send_storage),
                             upstream_storage,
                             sizeof(upstream_storage));
    REQUIRE(build_grpc_health_probe_request(conn, target, 0));
    h2.cb_ctx = nullptr;
    h2.on_headers = &on_probe_h2_headers;
    h2.on_trailers = &on_probe_h2_trailers;
    h2.on_data = &on_probe_h2_data;
    h2.on_reset = &on_probe_h2_reset;
    conn.on_upstream_send = &on_probe_sent<ProbeHarness>;
    set_probe_in_flight(uid.value(), 0, true);
    record_active_probe_result(uid.value(), 0, false, monotonic_us());
    REQUIRE(backend_ejected(uid.value(), 0, monotonic_us()));

    hpack::Encoder encoder;
    encoder.init(4096);
    u8 response[512];
    u32 response_len = write_settings_frame(response, h2.our_settings);
    REQUIRE(response_len != 0);
    const hpack::Header headers[] = {{{":status", 7}, {"200", 3}},
                                     {{"content-type", 12}, {"application/grpc", 16}}};
    const u32 headers_len = http2_write_headers(
        response + response_len, sizeof(response) - response_len, 1, headers, 2, false, encoder);
    REQUIRE(headers_len != 0);
    response_len += headers_len;
    const u8 body[] = {0, 0, 0, 0, 2, 0x08, 0x01};
    const u32 data_len = http2_write_data(response + response_len, 1, body, sizeof(body), false);
    REQUIRE(data_len != 0);
    response_len += data_len;
    const hpack::Header trailer[] = {{{"grpc-status", 11}, {"0", 1}}};
    u8 trailer_frame[128];
    const u32 trailer_len =
        http2_write_headers(trailer_frame, sizeof(trailer_frame), 1, trailer, 1, true, encoder);
    REQUIRE(trailer_len > kFrameHeaderSize);
    // Leave a partial final frame in the preread buffer. The settings ACK send
    // must not discard it, and parsing resumes after that control write drains.
    REQUIRE(response_len + kFrameHeaderSize / 2 <= sizeof(response));
    for (u32 i = 0; i < kFrameHeaderSize / 2; ++i) response[response_len++] = trailer_frame[i];
    REQUIRE(append_bytes(conn.upstream_recv_buf, response, response_len));

    const u32 request_len = conn.recv_buf.len();
    const u32 request_prefix = request_len / 3;
    on_probe_sent<ProbeHarness>(
        &loop,
        conn,
        IoEvent{conn.id, static_cast<i32>(request_prefix), 0, 0, IoEventType::UpstreamSend, 0});
    CHECK_EQ(conn.send_progress, request_prefix);
    CHECK_EQ(conn.recv_buf.len(), request_len);
    REQUIRE(conn.h2->find_stream(1) != nullptr);
    CHECK(conn.h2->find_stream(1)->state == Http2StreamState::Open);
    CHECK_EQ(loop.send_submits, 1u);
    CHECK_EQ(loop.last_send, conn.recv_buf.data() + request_prefix);
    CHECK_EQ(loop.last_send_len, request_len - request_prefix);
    CHECK_EQ(conn.upstream_recv_buf.len(), response_len);

    on_probe_sent<ProbeHarness>(&loop,
                                conn,
                                IoEvent{conn.id,
                                        static_cast<i32>(request_len - request_prefix),
                                        0,
                                        0,
                                        IoEventType::UpstreamSend,
                                        0});
    REQUIRE(conn.h2->find_stream(1) != nullptr);
    CHECK(conn.h2->find_stream(1)->state == Http2StreamState::HalfClosedLocal);
    CHECK_EQ(conn.recv_buf.len(), 0u);
    CHECK_EQ(conn.upstream_recv_buf.len(), kFrameHeaderSize / 2);
    CHECK_EQ(loop.frees, 0u);
    CHECK(conn.h2->peer_settings_seen);
    CHECK_FALSE(conn.h2->health_probe_malformed);
    CHECK_FALSE(conn.h2->health_probe_terminal);
    CHECK_EQ(loop.send_submits, 2u);  // second send is the SETTINGS ACK
    CHECK_EQ(conn.on_upstream_send, &on_probe_h2_control_sent<ProbeHarness>);
    const u32 ack_len = conn.send_buf.len();
    REQUIRE(ack_len >= kFrameHeaderSize);
    CHECK_EQ(conn.upstream_recv_buf.len(), kFrameHeaderSize / 2);
    CHECK_EQ(loop.frees, 0u);

    const u32 ack_prefix = 3;
    on_probe_h2_control_sent<ProbeHarness>(
        &loop,
        conn,
        IoEvent{conn.id, static_cast<i32>(ack_prefix), 0, 0, IoEventType::UpstreamSend, 0});
    CHECK_EQ(conn.send_progress, ack_prefix);
    CHECK_EQ(loop.send_submits, 3u);
    CHECK_EQ(loop.last_send, conn.send_buf.data() + ack_prefix);
    CHECK_EQ(loop.last_send_len, ack_len - ack_prefix);
    CHECK_EQ(conn.upstream_recv_buf.len(), kFrameHeaderSize / 2);
    CHECK_EQ(loop.frees, 0u);

    on_probe_h2_control_sent<ProbeHarness>(
        &loop,
        conn,
        IoEvent{
            conn.id, static_cast<i32>(ack_len - ack_prefix), 0, 0, IoEventType::UpstreamSend, 0});
    CHECK_EQ(conn.send_progress, 0u);
    CHECK_EQ(conn.upstream_recv_buf.len(), kFrameHeaderSize / 2);
    CHECK_EQ(loop.recv_submits, 1u);
    CHECK_EQ(loop.frees, 0u);

    REQUIRE(append_bytes(conn.upstream_recv_buf,
                         trailer_frame + kFrameHeaderSize / 2,
                         trailer_len - kFrameHeaderSize / 2));
    on_probe_h2_response<ProbeHarness>(
        &loop, conn, IoEvent{conn.id, 1, 0, 0, IoEventType::UpstreamRecv, 0});
    CHECK(conn.h2->health_probe_terminal);
    CHECK_FALSE(conn.h2->health_probe_malformed);
    CHECK(conn.h2->health_probe_initial_headers);
    CHECK(conn.h2->health_probe_grpc_status_seen);
    CHECK(conn.h2->health_probe_message_complete);
    CHECK_EQ(loop.frees, 1u);
    CHECK(!probe_in_flight(uid.value(), 0));
    CHECK(!backend_ejected(uid.value(), 0, monotonic_us()));
    CHECK_EQ(loop.send_submits, 3u);
    CHECK_EQ(loop.recv_submits, 1u);

    // A zero-byte result for an in-flight control ACK is a backend failure,
    // and tears down this probe exactly once.
    Connection failed_conn{};
    Http2Conn failed_h2{};
    u8 failed_request[SlicePool::kSliceSize];
    u8 failed_send[SlicePool::kSliceSize];
    u8 failed_upstream[SlicePool::kSliceSize];
    prepare_probe_connection(failed_conn,
                             failed_h2,
                             config,
                             failed_request,
                             sizeof(failed_request),
                             failed_send,
                             sizeof(failed_send),
                             failed_upstream,
                             sizeof(failed_upstream));
    REQUIRE(append_bytes(failed_conn.send_buf, trailer_frame, kFrameHeaderSize));
    loop.frees = 0;
    set_probe_in_flight(uid.value(), 0, true);
    record_active_probe_result(uid.value(), 0, true, monotonic_us());
    on_probe_h2_control_sent<ProbeHarness>(
        &loop, failed_conn, IoEvent{failed_conn.id, 0, 0, 0, IoEventType::UpstreamSend, 0});
    CHECK_EQ(loop.frees, 1u);
    CHECK(!probe_in_flight(uid.value(), 0));
    CHECK(backend_ejected(uid.value(), 0, monotonic_us()));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
