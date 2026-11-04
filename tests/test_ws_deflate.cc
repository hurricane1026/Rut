#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_deflate.h"
#include "rut/runtime/ws_frame.h"
#include "rut/runtime/ws_terminate.h"
#include "test.h"
#include <cstring>
#include <vector>

using namespace rut;

#if RUT_ENABLE_WEBSOCKET
namespace {
struct Owner {
    SlicePool pool;
    WsDeflateCodec* codec = nullptr;
    ~Owner() {
        ws_deflate_destroy(pool, codec);
        pool.destroy();
    }
    bool init(WsDeflateOptions options = {}) {
        return pool.init(16, 0, 0, 1).has_value() &&
               (codec = ws_deflate_create(pool, options)) != nullptr;
    }
};
constexpr u8 kHello[] = {0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00};
// RFC 7692 section 7.2.3.2: the second message refers to the first one's history.
constexpr u8 kHelloAgain[] = {0xf2, 0x00, 0x11, 0x00, 0x00};

std::vector<u8> frame(
    WsOpcode opcode, bool fin, bool masked, bool compressed, const u8* payload, u32 length) {
    std::vector<u8> wire(length + kWsMaxHeaderSize);
    const u8 key[] = {1, 2, 3, 4};
    const u32 header = ws_write_header(wire.data(), opcode, fin, masked, key, length, compressed);
    if (!header) return {};
    if (length) memcpy(wire.data() + header, payload, length);
    if (masked) ws_unmask(wire.data() + header, length, key);
    wire.resize(header + length);
    return wire;
}
struct MessageProbe {
    const std::vector<u8>* expected = nullptr;
    WsOpcode opcode = WsOpcode::Text;
    WsHandlerOutput* publication = nullptr;
    const std::vector<u8>* replacement = nullptr;
    u32 calls = 0;
    bool valid = true;
    bool drop_first = false;
};
WsFrameAction observe_message(void* value, WsOpcode opcode, const u8* bytes, u64 len, bool) {
    auto& probe = *static_cast<MessageProbe*>(value);
    ++probe.calls;
    probe.valid &= opcode == probe.opcode && len == probe.expected->size() &&
                   memcmp(bytes, probe.expected->data(), len) == 0;
    if (probe.drop_first && probe.calls == 1) return WsFrameAction::Drop;
    if (!probe.publication) return WsFrameAction::Forward;
    *probe.publication = {{reinterpret_cast<const char*>(probe.replacement->data()),
                           static_cast<u32>(probe.replacement->size())},
                          1000,
                          WsOpcode::Binary,
                          true};
    return WsFrameAction::ForwardDynamic;
}
}  // namespace

TEST(ws_deflate, rfc_vectors_decode_with_split_input_and_frame_relative_masking) {
    const std::vector<std::vector<u8>> vectors = {
        {kHello, kHello + sizeof(kHello)},
        {0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00},  // BFINAL=1
        {0x00, 0x05, 0x00, 0xfa, 0xff, 'H', 'e', 'l', 'l', 'o', 0x00},
        {0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00},
    };
    for (const auto& bytes : vectors) {
        for (u32 stride : {1u, 3u, 32u}) {
            for (bool masked : {false, true}) {
                Owner owner;
                REQUIRE(owner.init());
                REQUIRE(ws_inflate_begin(*owner.codec, 32));
                u8 output[32]{};
                u32 length = 0;
                const u8 key[] = {4, 3, 2, 1};
                auto wire = bytes;
                if (masked) ws_unmask(wire.data(), wire.size(), key);
                for (u32 offset = 0; offset < wire.size();) {
                    const u32 take = wire.size() - offset < stride
                                         ? static_cast<u32>(wire.size()) - offset
                                         : stride;
                    REQUIRE_EQ(ws_inflate_chunk(*owner.codec,
                                                wire.data() + offset,
                                                take,
                                                false,
                                                output,
                                                sizeof(output),
                                                &length,
                                                masked ? key : nullptr,
                                                offset),
                               WsDeflateStatus::Ok);
                    offset += take;
                }
                REQUIRE_EQ(ws_inflate_chunk(*owner.codec, nullptr, 0, true, output, 32, &length),
                           WsDeflateStatus::Ok);
                CHECK_EQ(length, 5u);
                CHECK_EQ(memcmp(output, "Hello", 5), 0);
            }
        }
    }
}

TEST(ws_deflate, receive_history_survives_message_boundaries_unless_negotiated_away) {
    for (bool reset : {false, true}) {
        Owner owner;
        REQUIRE(owner.init({15, 15, reset}));
        u8 output[32]{};
        u32 length = 0;
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        REQUIRE_EQ(
            ws_inflate_chunk(*owner.codec, kHello, sizeof(kHello), true, output, 32, &length),
            WsDeflateStatus::Ok);
        CHECK_EQ(length, 5u);
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        const auto status = ws_inflate_chunk(
            *owner.codec, kHelloAgain, sizeof(kHelloAgain), true, output, 32, &length);
        CHECK_EQ(status, reset ? WsDeflateStatus::Error : WsDeflateStatus::Ok);
        if (!reset) {
            CHECK_EQ(length, 5u);
            CHECK_EQ(memcmp(output, "Hello", 5), 0);
        }
    }
}

TEST(ws_deflate, bfinal_streams_preserve_history_inside_and_between_messages) {
    Owner owner;
    REQUIRE(owner.init());
    const u8 wire[] = {0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0xf2, 0x00, 0x11, 0x00, 0x00};
    u8 output[32]{};
    u32 length = 0;
    REQUIRE(ws_inflate_begin(*owner.codec, 32));
    REQUIRE_EQ(ws_inflate_chunk(*owner.codec, wire, sizeof(wire), true, output, 32, &length),
               WsDeflateStatus::Ok);
    CHECK_EQ(length, 10u);
    CHECK_EQ(memcmp(output, "HelloHello", 10), 0);
    REQUIRE(ws_inflate_begin(*owner.codec, 32));
    REQUIRE_EQ(
        ws_inflate_chunk(*owner.codec, kHelloAgain, sizeof(kHelloAgain), true, output, 32, &length),
        WsDeflateStatus::Ok);
    CHECK_EQ(length, 5u);
    CHECK_EQ(memcmp(output, "Hello", 5), 0);
}

TEST(ws_deflate, decoded_and_wire_work_limits_fail_without_publishing_partial_output) {
    {
        Owner owner;
        REQUIRE(owner.init());
        REQUIRE(ws_inflate_begin(*owner.codec, 4));
        u8 output[32]{};
        u32 length = 99;
        CHECK_EQ(ws_inflate_chunk(*owner.codec, kHello, sizeof(kHello), true, output, 32, &length),
                 WsDeflateStatus::Limit);
        CHECK_EQ(length, 0u);
        CHECK_FALSE(ws_inflate_begin(*owner.codec, 32));
    }
    {
        Owner owner;
        REQUIRE(owner.init());
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        std::vector<u8> wire(ws_deflate_wire_limit(32) + 1, 0);
        u8 output[32]{};
        u32 length = 99;
        CHECK_EQ(ws_inflate_chunk(*owner.codec,
                                  wire.data(),
                                  static_cast<u32>(wire.size()),
                                  true,
                                  output,
                                  32,
                                  &length),
                 WsDeflateStatus::Limit);
        CHECK_EQ(length, 0u);
    }
    for (const auto& wire : {std::vector<u8>{0xff}, std::vector<u8>{0xf2, 0x48, 0xcd}}) {
        Owner owner;
        REQUIRE(owner.init());
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        u8 output[32]{};
        u32 length = 99;
        CHECK_EQ(ws_inflate_chunk(*owner.codec,
                                  wire.data(),
                                  static_cast<u32>(wire.size()),
                                  true,
                                  output,
                                  32,
                                  &length),
                 WsDeflateStatus::Error);
        CHECK_EQ(length, 0u);
    }
}

TEST(ws_deflate, all_window_sizes_and_large_incompressible_payloads_fit_one_codec_slice) {
    for (u8 window = 8; window <= 15; ++window) {
        Owner owner;
        REQUIRE(owner.init({window, window, false}));
        std::vector<u8> input(kWsMaxMessageCapacity);
        u32 random = 0x12345678;
        for (u8& byte : input) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            byte = static_cast<u8>(random);
        }
        std::vector<u8> compressed(ws_deflate_wire_limit(kWsMaxMessageCapacity));
        std::vector<u8> output(input.size());
        u32 compressed_length = 0;
        u32 output_length = 0;
        u32 storage_after_first_message = 0;
        for (u32 round = 0; round < 3; ++round) {
            REQUIRE_EQ(ws_deflate_payload(*owner.codec,
                                          input.data(),
                                          static_cast<u32>(input.size()),
                                          compressed.data(),
                                          static_cast<u32>(compressed.size()),
                                          &compressed_length),
                       WsDeflateStatus::Ok);
            REQUIRE(ws_inflate_begin(*owner.codec, kWsMaxMessageCapacity));
            REQUIRE_EQ(ws_inflate_chunk(*owner.codec,
                                        compressed.data(),
                                        compressed_length,
                                        true,
                                        output.data(),
                                        static_cast<u32>(output.size()),
                                        &output_length),
                       WsDeflateStatus::Ok);
            CHECK_EQ(output_length, input.size());
            CHECK_EQ(memcmp(output.data(), input.data(), input.size()), 0);
            CHECK(ws_deflate_storage_used(*owner.codec) < SlicePool::kBulkSliceSize);
            if (round == 0)
                storage_after_first_message = ws_deflate_storage_used(*owner.codec);
            else
                CHECK_EQ(ws_deflate_storage_used(*owner.codec), storage_after_first_message);
        }
    }
}

TEST(ws_deflate, encoder_recovers_after_bounded_output_fallback_and_preserves_empty_messages) {
    Owner owner;
    REQUIRE(owner.init());
    u8 wire[64]{};
    u8 output[32]{};
    u32 length = 0;
    CHECK_EQ(
        ws_deflate_payload(*owner.codec, reinterpret_cast<const u8*>("Hello"), 5, wire, 4, &length),
        WsDeflateStatus::Limit);
    CHECK_EQ(length, 0u);
    for (u32 size : {5u, 0u}) {
        REQUIRE_EQ(ws_deflate_payload(*owner.codec,
                                      reinterpret_cast<const u8*>("Hello"),
                                      size,
                                      wire,
                                      sizeof(wire),
                                      &length),
                   WsDeflateStatus::Ok);
        if (size == 5) {
            CHECK_EQ(length, sizeof(kHello));
            CHECK_EQ(memcmp(wire, kHello, sizeof(kHello)), 0);
        }
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        REQUIRE_EQ(ws_inflate_chunk(*owner.codec, wire, length, true, output, 32, &length),
                   WsDeflateStatus::Ok);
        CHECK_EQ(length, size);
        CHECK_EQ(memcmp(output, "Hello", size), 0);
    }
}

TEST(ws_deflate, creation_failure_and_destroy_restore_the_bulk_pool_budget) {
    Owner owner;
    REQUIRE(owner.pool.init(16, 0, 0, 1));
    CHECK(ws_deflate_create(owner.pool, {7, 15, false}) == nullptr);
    CHECK(ws_deflate_create(owner.pool, {15, 16, false}) == nullptr);
    CHECK_EQ(owner.pool.bulk_available(), 1u);
    owner.codec = ws_deflate_create(owner.pool, {});
    REQUIRE(owner.codec != nullptr);
    CHECK_EQ(owner.pool.bulk_available(), 0u);
    CHECK(ws_deflate_create(owner.pool, {}) == nullptr);
    ws_deflate_destroy(owner.pool, owner.codec);
    owner.codec = nullptr;
    CHECK_EQ(owner.pool.bulk_available(), 1u);
}

TEST(ws_deflate,
     inspector_bridges_independent_compression_legs_with_fragmented_controls_and_rewrites) {
    for (bool masked : {false, true}) {
        for (bool receive_compressed : {false, true}) {
            for (bool send_compressed : {false, true}) {
                for (bool dynamic : {false, true}) {
                    Owner sender, local_receive, local_send, receiver;
                    REQUIRE(sender.init());
                    REQUIRE(local_receive.init());
                    REQUIRE(local_send.init());
                    REQUIRE(receiver.init());
                    constexpr u32 kLimit = 65536;
                    std::vector<u8> payload(20000, 'a');
                    payload[4095] = 0xe2;
                    payload[4096] = 0x82;
                    payload[4097] = 0xac;
                    std::vector<u8> replacement(4000, 'b');
                    std::vector<u8> compressed(ws_deflate_wire_limit(kLimit));
                    u32 compressed_length = 0;
                    REQUIRE_EQ(ws_deflate_payload(*sender.codec,
                                                  payload.data(),
                                                  static_cast<u32>(payload.size()),
                                                  compressed.data(),
                                                  static_cast<u32>(compressed.size()),
                                                  &compressed_length),
                               WsDeflateStatus::Ok);
                    compressed.resize(compressed_length);
                    const auto& body = receive_compressed ? compressed : payload;
                    const u32 half = static_cast<u32>(body.size()) / 2;
                    auto wire =
                        frame(WsOpcode::Text, false, masked, receive_compressed, body.data(), half);
                    const u8 ping_payload[] = {'p'};
                    const auto ping = frame(WsOpcode::Ping, true, masked, false, ping_payload, 1);
                    const auto tail = frame(WsOpcode::Continuation,
                                            true,
                                            masked,
                                            false,
                                            body.data() + half,
                                            static_cast<u32>(body.size()) - half);
                    wire.insert(wire.end(), ping.begin(), ping.end());
                    wire.insert(wire.end(), tail.begin(), tail.end());
                    WsHandlerOutput publication{};
                    WsInspector inspector{};
                    inspector.masked = masked;
                    inspector.max_message_size = kLimit;
                    inspector.decoder = receive_compressed ? local_receive.codec : nullptr;
                    inspector.encoder = send_compressed ? local_send.codec : nullptr;
                    if (dynamic) {
                        inspector.dynamic_output = &publication;
                        inspector.forward_text.source = WsTextSource::Dynamic;
                    }
                    MessageProbe probe{
                        &payload, WsOpcode::Text, dynamic ? &publication : nullptr, &replacement};
                    std::vector<u8> message(kLimit), output(kLimit + kWsMaxHeaderSize);
                    std::vector<u8> pending, forwarded;
                    u32 offset = 0;
                    while (offset < wire.size() || !pending.empty()) {
                        const u32 take = wire.size() - offset > 257
                                             ? 257u
                                             : static_cast<u32>(wire.size()) - offset;
                        pending.insert(
                            pending.end(), wire.data() + offset, wire.data() + offset + take);
                        offset += take;
                        u32 consumed = 0, produced = 0;
                        REQUIRE_EQ(ws_inspect(inspector,
                                              pending.data(),
                                              static_cast<u32>(pending.size()),
                                              output.data(),
                                              static_cast<u32>(output.size()),
                                              message.data(),
                                              kLimit,
                                              observe_message,
                                              &probe,
                                              &consumed,
                                              &produced),
                                   WsInspectStatus::Ok);
                        forwarded.insert(forwarded.end(), output.data(), output.data() + produced);
                        pending.erase(pending.begin(), pending.begin() + consumed);
                        REQUIRE(offset < wire.size() || pending.empty() || consumed || produced);
                    }
                    CHECK_EQ(probe.calls, 1u);
                    REQUIRE(probe.valid);
                    WsFrameHeader header{};
                    REQUIRE_EQ(ws_parse_header(forwarded.data(),
                                               static_cast<u32>(forwarded.size()),
                                               masked,
                                               &header,
                                               true),
                               ParseStatus::Complete);
                    CHECK_EQ(header.opcode, WsOpcode::Ping);
                    CHECK_FALSE(header.compressed);
                    const u32 control_size =
                        header.header_len + static_cast<u32>(header.payload_len);
                    REQUIRE_EQ(ws_parse_header(forwarded.data() + control_size,
                                               static_cast<u32>(forwarded.size()) - control_size,
                                               masked,
                                               &header,
                                               true),
                               ParseStatus::Complete);
                    CHECK_EQ(header.opcode, dynamic ? WsOpcode::Binary : WsOpcode::Text);
                    CHECK_EQ(header.compressed, send_compressed);
                    const u8* bytes = forwarded.data() + control_size + header.header_len;
                    std::vector<u8> decoded(kLimit);
                    u32 length = 0;
                    if (header.compressed) {
                        REQUIRE(ws_inflate_begin(*receiver.codec, kLimit));
                        REQUIRE_EQ(ws_inflate_chunk(*receiver.codec,
                                                    bytes,
                                                    static_cast<u32>(header.payload_len),
                                                    true,
                                                    decoded.data(),
                                                    kLimit,
                                                    &length,
                                                    masked ? header.mask_key : nullptr),
                                   WsDeflateStatus::Ok);
                    } else {
                        length = static_cast<u32>(header.payload_len);
                        memcpy(decoded.data(), bytes, length);
                        if (masked) ws_unmask(decoded.data(), length, header.mask_key);
                    }
                    const auto& expected = dynamic ? replacement : payload;
                    CHECK_EQ(length, expected.size());
                    CHECK_EQ(memcmp(decoded.data(), expected.data(), length), 0);
                }
            }
        }
    }
}

TEST(ws_deflate, inspector_retains_received_history_even_when_the_first_message_is_dropped) {
    Owner owner;
    REQUIRE(owner.init());
    WsInspector inspector{};
    inspector.decoder = owner.codec;
    inspector.max_message_size = 32;
    const std::vector<u8> hello = {'H', 'e', 'l', 'l', 'o'};
    MessageProbe probe{&hello};
    probe.drop_first = true;
    auto wire = frame(WsOpcode::Text, true, false, true, kHello, sizeof(kHello));
    const auto second = frame(WsOpcode::Text, true, false, true, kHelloAgain, sizeof(kHelloAgain));
    wire.insert(wire.end(), second.begin(), second.end());
    u8 message[32]{}, output[256]{};
    u32 consumed = 0, produced = 0;
    REQUIRE_EQ(ws_inspect(inspector,
                          wire.data(),
                          static_cast<u32>(wire.size()),
                          output,
                          sizeof(output),
                          message,
                          sizeof(message),
                          observe_message,
                          &probe,
                          &consumed,
                          &produced),
               WsInspectStatus::Ok);
    CHECK_EQ(probe.calls, 2u);
    CHECK(probe.valid);
    CHECK_EQ(consumed, wire.size());
    WsFrameHeader header{};
    REQUIRE_EQ(ws_parse_header(output, produced, false, &header), ParseStatus::Complete);
    CHECK_EQ(header.payload_len, 5u);
    CHECK_EQ(memcmp(output + header.header_len, "Hello", 5), 0);
}

TEST(ws_deflate, inspector_rejects_decoded_limit_and_invalid_utf8_before_application_dispatch) {
    for (bool invalid_text : {false, true}) {
        Owner sender, local;
        REQUIRE(sender.init());
        REQUIRE(local.init());
        std::vector<u8> input(invalid_text ? 1u : 33u, invalid_text ? 0xff : 'x');
        u8 compressed[128]{};
        u32 length = 0;
        REQUIRE_EQ(ws_deflate_payload(*sender.codec,
                                      input.data(),
                                      static_cast<u32>(input.size()),
                                      compressed,
                                      sizeof(compressed),
                                      &length),
                   WsDeflateStatus::Ok);
        const auto wire = frame(WsOpcode::Text, true, false, true, compressed, length);
        WsInspector inspector{};
        inspector.max_message_size = 32;
        inspector.decoder = local.codec;
        MessageProbe probe{&input};
        u8 message[32]{}, output[256]{};
        u32 consumed = 0, produced = 0;
        CHECK_EQ(ws_inspect(inspector,
                            wire.data(),
                            static_cast<u32>(wire.size()),
                            output,
                            sizeof(output),
                            message,
                            sizeof(message),
                            observe_message,
                            &probe,
                            &consumed,
                            &produced),
                 WsInspectStatus::Error);
        CHECK_EQ(probe.calls, 0u);
        CHECK_EQ(produced, 0u);
    }
}

TEST(ws_deflate, inspector_incompressible_maximum_falls_back_without_losing_owned_output) {
    for (bool masked : {false, true}) {
        Owner destination;
        REQUIRE(destination.init());
        std::vector<u8> input(kWsMaxMessageCapacity);
        u32 random = 0x42;
        for (u8& byte : input) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            byte = static_cast<u8>(random);
        }
        const auto wire = frame(
            WsOpcode::Binary, true, masked, false, input.data(), static_cast<u32>(input.size()));
        std::vector<u8> message(kWsMaxMessageCapacity), output(SlicePool::kBulkSliceSize);
        WsInspector inspector{};
        inspector.masked = masked;
        inspector.max_message_size = kWsMaxMessageCapacity;
        inspector.encoder = destination.codec;
        MessageProbe probe{&input, WsOpcode::Binary};
        u32 consumed = 0, produced = 0;
        REQUIRE_EQ(ws_inspect(inspector,
                              wire.data(),
                              static_cast<u32>(wire.size()),
                              output.data(),
                              static_cast<u32>(output.size()),
                              message.data(),
                              static_cast<u32>(message.size()),
                              observe_message,
                              &probe,
                              &consumed,
                              &produced),
                   WsInspectStatus::Ok);
        CHECK_EQ(probe.calls, 1u);
        CHECK(probe.valid);
        WsFrameHeader header{};
        REQUIRE_EQ(ws_parse_header(output.data(), produced, masked, &header, true),
                   ParseStatus::Complete);
        CHECK_FALSE(header.compressed);
        CHECK_EQ(header.payload_len, input.size());
        if (masked)
            ws_unmask(output.data() + header.header_len, header.payload_len, header.mask_key);
        CHECK_EQ(memcmp(output.data() + header.header_len, input.data(), input.size()), 0);
    }
}

TEST(ws_deflate, closing_discards_negotiated_compressed_data_without_running_the_codec) {
    Owner owner;
    REQUIRE(owner.init());
    WsInspector inspector{};
    inspector.decoder = owner.codec;
    inspector.max_message_size = 32;
    // Invalid DEFLATE is intentionally ignored after local application EOF;
    // framing and the peer's received Close remain independently validated.
    const u8 bad[] = {0xff};
    auto wire = frame(WsOpcode::Text, false, false, true, bad, sizeof(bad));
    const auto tail = frame(WsOpcode::Continuation, true, false, false, bad, sizeof(bad));
    const u8 close_body[] = {3, 0xe8};
    const auto close = frame(WsOpcode::Close, true, false, false, close_body, sizeof(close_body));
    wire.insert(wire.end(), tail.begin(), tail.end());
    wire.insert(wire.end(), close.begin(), close.end());
    u8 ping[kWsMaxControlPayload]{};
    u32 ping_length = 0, consumed = 0;
    REQUIRE_EQ(
        ws_read_closing(
            inspector, wire.data(), static_cast<u32>(wire.size()), ping, &ping_length, &consumed),
        WsClosingRead::Close);
    CHECK_EQ(consumed, wire.size());
    CHECK_EQ(inspector.echo_close_code, 1000u);
    CHECK(inspector.received_close);
    CHECK(ws_inflate_begin(*owner.codec, 32));
}
#endif

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
