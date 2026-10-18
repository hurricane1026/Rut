#include "rut/runtime/grpc_protocol.h"
#include "test.h"

#include <string.h>

using namespace rut;

TEST(grpc_web, content_type_classification) {
    CHECK_EQ(grpc_web_content_type(lit_str("application/grpc")), GrpcWebContentType::Native);
    CHECK_EQ(grpc_web_content_type(lit_str("Application/Grpc+proto; charset=utf-8")),
             GrpcWebContentType::Native);
    CHECK_EQ(grpc_web_content_type(lit_str("application/grpc-web")), GrpcWebContentType::Binary);
    CHECK_EQ(grpc_web_content_type(lit_str("application/grpc-web+proto")),
             GrpcWebContentType::Binary);
    CHECK_EQ(grpc_web_content_type(lit_str("application/grpc-web-text")), GrpcWebContentType::Text);
    CHECK_EQ(grpc_web_content_type(lit_str("application/grpc-web-text+proto; charset=UTF-8")),
             GrpcWebContentType::Text);
    CHECK_EQ(grpc_web_content_type(lit_str("application/grpc-webish")), GrpcWebContentType::Other);
    CHECK_EQ(grpc_web_content_type(lit_str("application/grpc-web+json")),
             GrpcWebContentType::Other);
}

TEST(grpc_web, backend_representation_matches_advertised_proto_type) {
    CHECK(grpc_web_native_proto_content_type(lit_str("application/grpc")));
    CHECK(grpc_web_native_proto_content_type(lit_str("Application/Grpc+Proto ; charset=UTF-8")));
    CHECK(!grpc_web_native_proto_content_type(lit_str("application/grpc+json")));
    CHECK(!grpc_web_native_proto_content_type(lit_str("application/grpc+custom")));
    CHECK(!grpc_web_native_proto_content_type(lit_str("application/grpc-web+proto")));
    CHECK(!grpc_web_native_proto_content_type(lit_str("application/grpc+proto-extra")));
    CHECK(grpc_content_type(lit_str("application/grpc+json")));
    CHECK(grpc_content_type(lit_str("application/grpc+custom")));
}

TEST(grpc_web, base64_decoder_handles_arbitrary_splits_and_padded_blocks) {
    GrpcWebBase64Decoder decoder{};
    decoder.init();
    const u8 first[] = {'T', 'W'};
    const u8 second[] = {'F', 'u', 'Y', 'W', 'J', 'j', 'Z', 'A', '=', '='};
    u8 output[16]{};
    u32 consumed = 0;
    u32 written = 0;
    CHECK_EQ(decoder.feed(first, sizeof(first), consumed, output, sizeof(output), written),
             GrpcWebCodecStatus::Ok);
    CHECK_EQ(consumed, 2u);
    CHECK_EQ(written, 0u);
    CHECK_EQ(decoder.feed(second, 1, consumed, output, sizeof(output), written),
             GrpcWebCodecStatus::Ok);
    CHECK_EQ(consumed, 1u);
    CHECK_EQ(written, 0u);
    CHECK_EQ(
        decoder.feed(second + 1, sizeof(second) - 1, consumed, output, sizeof(output), written),
        GrpcWebCodecStatus::Ok);
    CHECK_EQ(consumed, sizeof(second) - 1);
    CHECK_EQ(written, 7u);
    CHECK(memcmp(output, "Manabcd", 7) == 0);
    CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
}

TEST(grpc_web, base64_decoder_enforces_padding_and_output_backpressure) {
    GrpcWebBase64Decoder decoder{};
    decoder.init();
    const u8 padded[] = {'T', 'Q', '=', '='};
    u8 output[4]{};
    u32 consumed = 0;
    u32 written = 0;
    CHECK_EQ(decoder.feed(padded, sizeof(padded), consumed, output, 0, written),
             GrpcWebCodecStatus::NeedOutput);
    CHECK_EQ(consumed, 4u);
    CHECK_EQ(decoder.feed(nullptr, 0, consumed, output, sizeof(output), written),
             GrpcWebCodecStatus::Ok);
    CHECK_EQ(written, 1u);
    CHECK_EQ(output[0], 'M');

    const u8* invalid[] = {reinterpret_cast<const u8*>("=AAA"),
                           reinterpret_cast<const u8*>("A=AA"),
                           reinterpret_cast<const u8*>("AA=A"),
                           reinterpret_cast<const u8*>("TR=="),
                           reinterpret_cast<const u8*>("TWF="),
                           reinterpret_cast<const u8*>("TW$u")};
    const u32 lengths[] = {4, 4, 4, 4, 4, 4};
    for (u32 i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        decoder.init();
        CHECK_EQ(decoder.feed(invalid[i], lengths[i], consumed, output, sizeof(output), written),
                 GrpcWebCodecStatus::Invalid);
        const u8 prior_len = decoder.quartet_len;
        CHECK_EQ(decoder.feed(nullptr, 0, consumed, output, sizeof(output), written),
                 GrpcWebCodecStatus::Invalid);
        CHECK_EQ(consumed, 0u);
        CHECK_EQ(written, 0u);
        CHECK_EQ(decoder.quartet_len, prior_len);
        const u8 valid[] = {'T', 'W', 'F', 'u'};
        CHECK_EQ(decoder.feed(valid, sizeof(valid), consumed, output, sizeof(output), written),
                 GrpcWebCodecStatus::Invalid);
        CHECK_EQ(consumed, 0u);
        CHECK_EQ(decoder.quartet_len, prior_len);
        CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Invalid);
    }
    decoder.init();
    const u8 misplaced_partial[] = {'A', '='};
    CHECK_EQ(decoder.feed(misplaced_partial,
                          sizeof(misplaced_partial),
                          consumed,
                          output,
                          sizeof(output),
                          written),
             GrpcWebCodecStatus::Invalid);
    CHECK_EQ(decoder.feed(nullptr, 0, consumed, output, sizeof(output), written),
             GrpcWebCodecStatus::Invalid);
    decoder.init();
    const u8 partial[] = {'T', 'W', 'F'};
    CHECK_EQ(decoder.feed(partial, sizeof(partial), consumed, output, sizeof(output), written),
             GrpcWebCodecStatus::Ok);
    CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Incomplete);
}

TEST(grpc_web, base64_decoder_accepts_multiple_independent_padding_blocks) {
    GrpcWebBase64Decoder decoder{};
    decoder.init();
    const u8 input[] = "TWFuTQ==TWE=";
    u8 output[16]{};
    u32 consumed = 0;
    u32 written = 0;
    CHECK_EQ(decoder.feed(input, sizeof(input) - 1, consumed, output, sizeof(output), written),
             GrpcWebCodecStatus::Ok);
    CHECK_EQ(consumed, sizeof(input) - 1);
    CHECK_EQ(written, 6u);
    CHECK(memcmp(output, "ManMMa", 6) == 0);
    CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
}

TEST(grpc_web, base64_decoder_retains_quartet_when_output_fills_midstream) {
    GrpcWebBase64Decoder decoder{};
    decoder.init();
    const u8 input[] = "TQ==Tg==";
    u8 output[1]{};
    u32 consumed = 0;
    u32 written = 0;
    CHECK_EQ(decoder.feed(input, sizeof(input) - 1, consumed, output, sizeof(output), written),
             GrpcWebCodecStatus::NeedOutput);
    CHECK_EQ(consumed, sizeof(input) - 1);
    CHECK_EQ(written, 1u);
    CHECK_EQ(output[0], 'M');
    CHECK_EQ(decoder.feed(nullptr, 0, consumed, output, sizeof(output), written),
             GrpcWebCodecStatus::Ok);
    CHECK_EQ(written, 1u);
    CHECK_EQ(output[0], 'N');
    CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Ok);
}

TEST(grpc_web, base64_encoder_streams_and_flushes_independent_blocks) {
    GrpcWebBase64Encoder encoder{};
    encoder.init();
    const u8 input[] = {'M', 'a', 'n', '!', '!'};
    u8 output[16]{};
    u32 consumed = 0;
    u32 written = 0;
    CHECK_EQ(encoder.feed(input, 1, consumed, output, sizeof(output), written),
             GrpcWebCodecStatus::Ok);
    CHECK_EQ(consumed, 1u);
    CHECK_EQ(written, 0u);
    CHECK_EQ(encoder.feed(input + 1, 2, consumed, output, 4, written), GrpcWebCodecStatus::Ok);
    CHECK_EQ(written, 4u);
    CHECK(memcmp(output, "TWFu", 4) == 0);
    CHECK_EQ(encoder.feed(input + 3, 2, consumed, output + 4, sizeof(output) - 4, written),
             GrpcWebCodecStatus::Ok);
    CHECK_EQ(written, 0u);
    CHECK_EQ(encoder.flush(output + 4, sizeof(output) - 4, written), GrpcWebCodecStatus::Ok);
    CHECK_EQ(written, 4u);
    CHECK(memcmp(output + 4, "ISE=", 4) == 0);
    CHECK_EQ(encoder.flush(output, sizeof(output), written), GrpcWebCodecStatus::Ok);
    CHECK_EQ(written, 0u);

    encoder.init();
    const u8 m[] = {'M'};
    CHECK_EQ(encoder.feed(m, 1, consumed, output, sizeof(output), written), GrpcWebCodecStatus::Ok);
    CHECK_EQ(encoder.flush(output, sizeof(output), written), GrpcWebCodecStatus::Ok);
    CHECK_EQ(written, 4u);
    CHECK(memcmp(output, "TQ==", 4) == 0);
    const u8 ma[] = {'M', 'a'};
    CHECK_EQ(encoder.feed(ma, 2, consumed, output + 4, sizeof(output) - 4, written),
             GrpcWebCodecStatus::Ok);
    CHECK_EQ(encoder.flush(output + 4, sizeof(output) - 4, written), GrpcWebCodecStatus::Ok);
    CHECK_EQ(written, 4u);
    CHECK(memcmp(output + 4, "TWE=", 4) == 0);
}

TEST(grpc_web, base64_codecs_reject_null_buffers_without_state_progress) {
    GrpcWebBase64Decoder decoder{};
    decoder.init();
    u32 consumed = 0;
    u32 written = 0;
    const u8 input[] = {'T'};
    CHECK_EQ(decoder.feed(input, 1, consumed, nullptr, 4, written), GrpcWebCodecStatus::Invalid);
    CHECK_EQ(consumed, 0u);
    CHECK_EQ(decoder.quartet_len, 0u);
    CHECK_EQ(decoder.finish(), GrpcWebCodecStatus::Invalid);

    GrpcWebBase64Encoder encoder{};
    encoder.init();
    CHECK_EQ(encoder.feed(nullptr, 1, consumed, nullptr, 0, written), GrpcWebCodecStatus::Invalid);
    CHECK_EQ(consumed, 0u);
    CHECK_EQ(encoder.pending_len, 0u);
    CHECK_EQ(encoder.flush(nullptr, 4, written), GrpcWebCodecStatus::Invalid);
    CHECK_EQ(written, 0u);
}

TEST(grpc_web, base64_encoder_preserves_full_triplet_on_output_backpressure) {
    GrpcWebBase64Encoder encoder{};
    encoder.init();
    const u8 input[] = {'M', 'a', 'n'};
    u8 output[4]{};
    u32 consumed = 0;
    u32 written = 0;
    CHECK_EQ(encoder.feed(input, sizeof(input), consumed, output, 0, written),
             GrpcWebCodecStatus::NeedOutput);
    CHECK_EQ(consumed, 3u);
    CHECK_EQ(encoder.flush(output, sizeof(output), written), GrpcWebCodecStatus::Ok);
    CHECK_EQ(written, 4u);
    CHECK(memcmp(output, "TWFu", 4) == 0);
}

TEST(grpc_web, trailer_envelope_is_framed_lowercase_and_bounded) {
    const GrpcWebTrailer trailers[] = {{{"Grpc-Status", 11}, {"0", 1}},
                                       {{"X-Trailer", 9}, {"present", 7}}};
    u8 output[128]{};
    u32 written = 0;
    REQUIRE(grpc_web_encode_trailer_envelope(trailers, 2, output, sizeof(output), written));
    CHECK_EQ(output[0], 0x80);
    CHECK_EQ(output[1], 0u);
    CHECK_EQ(output[2], 0u);
    CHECK_EQ(output[3], 0u);
    CHECK_EQ(output[4], 36u);
    CHECK_EQ(written, 41u);
    CHECK(memcmp(output + 5, "grpc-status: 0\r\nx-trailer: present\r\n", 36) == 0);
    CHECK(!grpc_web_encode_trailer_envelope(trailers, 2, output, 40, written));
    const GrpcWebTrailer invalid[] = {{{"x-test", 6}, {"bad\r\nvalue", 10}}};
    CHECK(!grpc_web_encode_trailer_envelope(invalid, 1, output, sizeof(output), written));
    const GrpcWebTrailer pseudo[] = {{{":status", 7}, {"200", 3}}};
    CHECK(!grpc_web_encode_trailer_envelope(pseudo, 1, output, sizeof(output), written));
    const char nul_value[] = {'x', '\0', 'y'};
    const GrpcWebTrailer nul[] = {{{"x-test", 6}, {nul_value, sizeof(nul_value)}}};
    CHECK(!grpc_web_encode_trailer_envelope(nul, 1, output, sizeof(output), written));
    const GrpcWebTrailer repeated[] = {{{"x-tag", 5}, {"one", 3}}, {{"x-tag", 5}, {"two", 3}}};
    REQUIRE(grpc_web_encode_trailer_envelope(repeated, 2, output, sizeof(output), written));
    CHECK_EQ(output[4], 24u);
    CHECK_EQ(written, 29u);
    CHECK(memcmp(output + 5, "x-tag: one\r\nx-tag: two\r\n", 24) == 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
