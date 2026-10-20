#include "rut/common/types.h"
#include "rut/runtime/protobuf_value.h"
#include "test.h"

#include <string.h>
using namespace rut;
using namespace rut::protobuf;
#include "protobuf/codec_message.inc"
#include "protobuf/value_presence_oracle.inc"
TEST(protobuf_value, reference_message_decodes_all_bound_scalar_fields) {
    const Str kInput{reinterpret_cast<const char*>(kCodecMessage), sizeof(kCodecMessage)};
    const u32 kTypes[] = {9, 8, 5, 3, 17, 18, 13, 12};
    const i64 kValues[] = {0,
                           1,
                           -17,
                           9223372036854775807LL,
                           -2147483647 - 1,
                           -9223372036854775807LL - 1,
                           4294967295LL,
                           0};
    u8 output[kMaxMessageBytes];
    Str view{};
    i64 scalar = 0;
    CHECK(apply(0, kInput, {}, 0, output, sizeof(output), view, scalar));
    for (u32 i = 0; i < 8; ++i) {
        REQUIRE(apply((static_cast<u64>(i + 1) << 8) | kTypes[i],
                      kInput,
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
        if (i == 0)
            CHECK(view.eq(lit_str("Rut")));
        else if (i == 7) {
            REQUIRE_EQ(view.len, 2u);
            CHECK_EQ(static_cast<u8>(view.ptr[0]), 0u);
            CHECK_EQ(static_cast<u8>(view.ptr[1]), 255u);
        } else
            CHECK_EQ(scalar, kValues[i]);
    }
}
TEST(protobuf_value, encoding_matches_reference_and_skips_defaults) {
    u8 a[kMaxMessageBytes], b[kMaxMessageBytes];
    const u32 kTypes[] = {9, 8, 5, 3, 17, 18, 13, 12};
    const i64 kValues[] = {0,
                           1,
                           -17,
                           9223372036854775807LL,
                           -2147483647 - 1,
                           -9223372036854775807LL - 1,
                           4294967295LL,
                           0};
    const char kBinary[] = {0, static_cast<char>(255)};
    Str prefix = lit_str("");
    Str view{};
    i64 scalar = 0;
    for (u32 i = 0; i < 8; ++i) {
        const Str kValue = i == 0 ? lit_str("Rut") : i == 7 ? Str{kBinary, 2} : Str{};
        REQUIRE(apply(kEncode | (static_cast<u64>(i + 1) << 8) | kTypes[i],
                      prefix,
                      kValue,
                      kValues[i],
                      b,
                      sizeof(b),
                      view,
                      scalar));
        memcpy(a, view.ptr, view.len);
        prefix = {reinterpret_cast<const char*>(a), view.len};
    }
    REQUIRE_EQ(prefix.len, sizeof(kCodecMessage));
    CHECK_EQ(memcmp(prefix.ptr, kCodecMessage, prefix.len), 0);
    REQUIRE(apply(kEncode | (9u << 8) | 5, prefix, {}, 0, b, sizeof(b), view, scalar));
    CHECK(view.eq(prefix));
    CHECK_FALSE(apply(kEncode | (9u << 8) | 13, prefix, {}, -1, b, sizeof(b), view, scalar));
    CHECK_FALSE(
        apply(kEncode | (9u << 8) | 13, prefix, {}, 4294967296LL, b, sizeof(b), view, scalar));
}
TEST(protobuf_value, malformed_utf8_wire_capacity_and_absent_defaults) {
    const u8 kInvalid[] = {0x0a, 2, 0xc0, 0x80};
    u8 output[16];
    Str view{};
    i64 scalar = 0;
    CHECK_FALSE(apply((1u << 8) | 9,
                      {reinterpret_cast<const char*>(kInvalid), sizeof(kInvalid)},
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
    CHECK(apply((1u << 8) | 12,
                {reinterpret_cast<const char*>(kInvalid), sizeof(kInvalid)},
                {},
                0,
                output,
                sizeof(output),
                view,
                scalar));
    const char kBroken[] = {8, static_cast<char>(128)};
    CHECK_FALSE(apply(0, {kBroken, sizeof(kBroken)}, {}, 0, output, sizeof(output), view, scalar));
    CHECK(apply((1u << 8) | 5, lit_str(""), {}, 0, output, sizeof(output), view, scalar));
    CHECK_EQ(scalar, 0);
    CHECK(apply((1u << 8) | 9, lit_str(""), {}, 0, output, sizeof(output), view, scalar));
    CHECK_EQ(view.len, 0u);
    CHECK_FALSE(apply(kEncode | (1u << 8) | 9,
                      lit_str(""),
                      lit_str("too long for output"),
                      0,
                      output,
                      1,
                      view,
                      scalar));
    CHECK_FALSE(apply(kEncode | (1u << 8) | 9,
                      {nullptr, 0},
                      lit_str("x"),
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
    CHECK_FALSE(apply(2, {nullptr, 0}, {}, 0, output, sizeof(output), view, scalar));
    CHECK(apply(2, lit_str(""), {}, 0, output, sizeof(output), view, scalar));
}
TEST(protobuf_value, fixed_width_signed_and_unsigned_scalars) {
    const u32 kTypes[] = {7, 15, 16};
    const i64 kValues[] = {4294967295LL, -2147483647 - 1, -9223372036854775807LL - 1};
    for (u32 i = 0; i < 3; ++i) {
        u8 output[32];
        Str encoded{};
        i64 number = 0;
        const u64 kOp = (1u << 8) | kTypes[i];
        REQUIRE(apply(
            kEncode | kOp, lit_str(""), {}, kValues[i], output, sizeof(output), encoded, number));
        Str view{};
        REQUIRE(apply(kOp, encoded, {}, 0, nullptr, 0, view, number));
        CHECK_EQ(number, kValues[i]);
    }
}
TEST(protobuf_value, nested_fragment_validation_and_failure_propagation) {
    const u8 kInput[] = {10, 2, 8, 1, 10, 2, 16, 2};
    const u8 kBroken[] = {10, 1, 8, 10, 1, 1};
    const u8 kMerged[] = {8, 1, 16, 2};
    u8 output[32];
    Str view{};
    i64 scalar = 0;
    REQUIRE(apply((1u << 8) | 11,
                  {reinterpret_cast<const char*>(kInput), sizeof(kInput)},
                  {},
                  0,
                  output,
                  sizeof(output),
                  view,
                  scalar));
    CHECK(view.eq({reinterpret_cast<const char*>(kMerged), sizeof(kMerged)}));
    CHECK_FALSE(apply((1u << 8) | 11,
                      {reinterpret_cast<const char*>(kBroken), sizeof(kBroken)},
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
    CHECK_FALSE(apply(3, {}, {}, 0, output, sizeof(output), view, scalar));
    CHECK_FALSE(
        apply(kEncode | (1u << 8) | 11, lit_str(""), {}, 0, output, sizeof(output), view, scalar));
    REQUIRE(apply(kEncode | (1u << 8) | 11,
                  lit_str(""),
                  lit_str(""),
                  0,
                  output,
                  sizeof(output),
                  view,
                  scalar));
    CHECK_EQ(view.len, 2u);
    CHECK_EQ(static_cast<u8>(view.ptr[0]), 10u);
}
TEST(protobuf_value, grpc_unary_envelopes_boundaries_and_malformed_inputs) {
    u8 output[kMaxMessageBytes + 6];
    u8 input[kMaxMessageBytes + 1];
    for (u32 i = 0; i < sizeof(input); ++i) input[i] = static_cast<u8>(i);
    Str framed{}, payload{};
    i64 number = 0;
    const u32 sizes[] = {0, 1, 255, 256, kMaxMessageBytes};
    for (u32 size : sizes) {
        memset(output, 0xa5, sizeof(output));
        REQUIRE(apply(kGrpcFrame,
                      {reinterpret_cast<const char*>(input), size},
                      {},
                      0,
                      output,
                      size + 5,
                      framed,
                      number));
        CHECK_EQ(framed.len, size + 5);
        CHECK_EQ(output[size + 5], 0xa5u);
        REQUIRE(apply(kGrpcUnframe, framed, {}, 0, nullptr, 0, payload, number));
        CHECK_EQ(payload.len, size);
        CHECK_EQ(memcmp(payload.ptr, input, size), 0);
        CHECK_FALSE(apply(kGrpcFrame,
                          {reinterpret_cast<const char*>(input), size},
                          {},
                          0,
                          output,
                          size + 4,
                          framed,
                          number));
    }
    CHECK_FALSE(apply(kGrpcFrame,
                      {reinterpret_cast<const char*>(input), sizeof(input)},
                      {},
                      0,
                      output,
                      sizeof(output),
                      framed,
                      number));
    const u8 valid[] = {0, 0, 0, 0, 2, 0xff, 0};
    const Str bytes{reinterpret_cast<const char*>(valid), sizeof(valid)};
    for (u32 length = 0; length < sizeof(valid); ++length)
        CHECK_FALSE(apply(
            kGrpcUnframe, {bytes.ptr, length}, {}, 0, output, sizeof(output), payload, number));
    const u8 invalid[][10] = {
        {1, 0, 0, 0, 0},                 // compressed message (no decompressor)
        {2, 0, 0, 0, 0},                 // invalid flag
        {128, 0, 0, 0, 0},               // grpc-web trailers are not a native message
        {0, 255, 255, 255, 255},         // huge length
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // two empty messages
    };
    for (u32 i = 0; i < 5; ++i)
        CHECK_FALSE(apply(kGrpcUnframe,
                          {reinterpret_cast<const char*>(invalid[i]), i == 4 ? 10u : 5u},
                          {},
                          0,
                          output,
                          sizeof(output),
                          payload,
                          number));
    CHECK_FALSE(apply(kGrpcUnframe, {nullptr, 5}, {}, 0, output, sizeof(output), payload, number));
    CHECK_FALSE(apply(kGrpcFrame, {nullptr, 1}, {}, 0, output, sizeof(output), payload, number));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(protobuf_value, open_enum_unknown_negative_and_default_values) {
    const i32 values[] = {0, 12345, -1, -2147483647 - 1, 2147483647};
    for (i32 value : values) {
        u8 output[32], scratch[32];
        Str encoded{}, view{};
        i64 scalar = 0;
        REQUIRE(apply(kEncode | (1u << 8) | 14,
                      lit_str(""),
                      {},
                      value,
                      output,
                      sizeof(output),
                      encoded,
                      scalar));
        REQUIRE(apply((1u << 8) | 14, encoded, {}, 0, scratch, sizeof(scratch), view, scalar));
        CHECK_EQ(scalar, static_cast<i64>(value));
        CHECK_EQ(encoded.len, value == 0 ? 0u : value < 0 ? 11u : value == 12345 ? 3u : 6u);
    }
}

TEST(protobuf_value, explicit_scalar_presence_defaults_and_absence) {
    // All scalar carriers supported by the generated-code helper.
    const u8 kTypes[] = {3, 5, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18};
    u8 output[64]{};
    Str view{};
    i64 scalar = 0;
    for (const u8 kType : kTypes) {
        const u64 kOp = (u64{1} << 8) | kType;
        CHECK(apply(kOp, lit_str(""), {}, 0, output, sizeof(output), view, scalar));
        CHECK_FALSE(apply(
            kOp | kExplicitPresence, lit_str(""), {}, 0, output, sizeof(output), view, scalar));
        REQUIRE(apply(
            kOp | kEncode, lit_str(""), lit_str(""), 0, output, sizeof(output), view, scalar));
        CHECK_EQ(view.len, 0u);
        REQUIRE(apply(kOp | kEncode | kExplicitPresence,
                      lit_str(""),
                      lit_str(""),
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
        CHECK(view.len > 0);
        u8 encoded[64]{};
        const u32 kSize = view.len;
        memcpy(encoded, view.ptr, kSize);
        REQUIRE(apply(kOp | kExplicitPresence,
                      {reinterpret_cast<const char*>(encoded), kSize},
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
        CHECK_EQ(scalar, 0);
        if (kType == 9 || kType == 12) CHECK_EQ(view.len, 0u);
    }
}
TEST(protobuf_value, explicit_presence_validates_duplicates_and_tail) {
    u8 output[64]{};
    Str view{};
    i64 scalar = 0;
    const u64 kOp = (u64{1} << 8) | 5 | kExplicitPresence;
    const u8 kWrongWire[] = {10, 0};
    CHECK_FALSE(apply(kOp,
                      {reinterpret_cast<const char*>(kWrongWire), sizeof(kWrongWire)},
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
    const u8 kDuplicate[] = {8, 7, 10, 0, 8, 0};
    REQUIRE(apply(kOp,
                  {reinterpret_cast<const char*>(kDuplicate), sizeof(kDuplicate)},
                  {},
                  0,
                  output,
                  sizeof(output),
                  view,
                  scalar));
    CHECK_EQ(scalar, 0);
    const u8 kBadTail[] = {8, 0, 128};
    CHECK_FALSE(apply(kOp,
                      {reinterpret_cast<const char*>(kBadTail), sizeof(kBadTail)},
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
    CHECK_FALSE(
        apply(kExplicitPresence | 2, lit_str(""), {}, 0, output, sizeof(output), view, scalar));
    CHECK_FALSE(apply(kExplicitPresence | (u64{1} << 8) | 11,
                      lit_str(""),
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
    CHECK_FALSE(apply(kOp | kEncode, lit_str(""), {}, 0, output, 1, view, scalar));
}

TEST(protobuf_value, explicit_defaults_match_google_reference_wire) {
    const u8 kTypes[] = {3, 5, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18};
    u8 output[128]{}, accumulated[128]{};
    Str prefix = lit_str("");
    Str view{};
    i64 scalar = 0;
    const Str kInput{reinterpret_cast<const char*>(kValuePresenceDefaults),
                     sizeof(kValuePresenceDefaults)};
    for (u32 i = 0; i < 12; ++i) {
        const u64 kOp = (static_cast<u64>(i + 1) << 8) | kTypes[i] | kExplicitPresence;
        REQUIRE(apply(kOp, kInput, {}, 0, output, sizeof(output), view, scalar));
        CHECK_EQ(scalar, 0);
        REQUIRE(apply(kOp | kEncode, prefix, lit_str(""), 0, output, sizeof(output), view, scalar));
        memcpy(accumulated, view.ptr, view.len);
        prefix = {reinterpret_cast<const char*>(accumulated), view.len};
    }
    CHECK_EQ(prefix.len, sizeof(kValuePresenceDefaults));
    CHECK(memcmp(prefix.ptr, kValuePresenceDefaults, sizeof(kValuePresenceDefaults)) == 0);
}

TEST(protobuf_value, explicit_message_presence_absent_empty_and_wrong_wire) {
    const u64 kOp = (u64{1} << 8) | 11 | kExplicitPresence;
    u8 output[64]{};
    Str view{};
    i64 scalar = 0;
    CHECK_FALSE(apply(kOp, lit_str(""), {}, 0, output, sizeof(output), view, scalar));
    const u8 kWrong[] = {8, 0};
    CHECK_FALSE(apply(kOp,
                      {reinterpret_cast<const char*>(kWrong), sizeof(kWrong)},
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
    const u8 kEmpty[] = {10, 0};
    REQUIRE(apply(kOp,
                  {reinterpret_cast<const char*>(kEmpty), sizeof(kEmpty)},
                  {},
                  0,
                  output,
                  sizeof(output),
                  view,
                  scalar));
    CHECK_EQ(view.len, 0u);
    REQUIRE(
        apply(kOp | kEncode, lit_str(""), lit_str(""), 0, output, sizeof(output), view, scalar));
    CHECK_EQ(view.len, sizeof(kEmpty));
    CHECK(memcmp(view.ptr, kEmpty, sizeof(kEmpty)) == 0);
    CHECK_FALSE(apply(kOp | kEncode, lit_str(""), {}, 0, output, sizeof(output), view, scalar));
    CHECK_FALSE(apply(kOp | kEncode, lit_str(""), lit_str(""), 0, output, 1, view, scalar));
}

TEST(protobuf_value, explicit_message_presence_merges_and_validates_every_occurrence) {
    const u64 kOp = (u64{1} << 8) | 11 | kExplicitPresence;
    // Empty duplicates preserve presence; wrong-wire occurrences do not clear it.
    const u8 kWire[] = {10, 2, 8, 7, 10, 0, 8, 0, 10, 2, 16, 9};
    const u8 kMerged[] = {8, 7, 16, 9};
    u8 output[64]{};
    Str view{};
    i64 scalar = 0;
    const Str kInput{reinterpret_cast<const char*>(kWire), sizeof(kWire)};
    REQUIRE(apply(kOp, kInput, {}, 0, output, sizeof(output), view, scalar));
    CHECK_EQ(view.len, sizeof(kMerged));
    CHECK(memcmp(view.ptr, kMerged, sizeof(kMerged)) == 0);
    CHECK_FALSE(apply(kOp, kInput, {}, 0, output, 3, view, scalar));
    CHECK_FALSE(apply(kOp, kInput, {}, 0, nullptr, sizeof(output), view, scalar));
    // The next occurrence cannot complete a truncated submessage.
    const u8 kSplit[] = {10, 1, 8, 10, 1, 1};
    CHECK_FALSE(apply(kOp,
                      {reinterpret_cast<const char*>(kSplit), sizeof(kSplit)},
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
    const u8 kBadTail[] = {10, 0, 128};
    CHECK_FALSE(apply(kOp,
                      {reinterpret_cast<const char*>(kBadTail), sizeof(kBadTail)},
                      {},
                      0,
                      output,
                      sizeof(output),
                      view,
                      scalar));
    const u8 kEmpty[] = {10, 0};
    REQUIRE(apply(kOp,
                  {reinterpret_cast<const char*>(kEmpty), sizeof(kEmpty)},
                  {},
                  0,
                  nullptr,
                  0,
                  view,
                  scalar));
    CHECK_EQ(view.len, 0u);
}
