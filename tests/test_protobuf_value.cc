#include "rut/common/types.h"
#include "rut/runtime/protobuf_value.h"
#include "test.h"

#include <string.h>
using namespace rut;
using namespace rut::protobuf;
#include "protobuf/codec_message.inc"
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
int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
