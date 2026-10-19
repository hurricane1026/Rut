#include "rut/common/types.h"
#include "rut/runtime/protobuf_message.h"
#include "rut/runtime/protobuf_value.h"
#include "test.h"

using namespace rut;
using namespace rut::protobuf;
namespace {
constexpr MessageField kChildFields[] = {{1, 9}, {2, 5}};
constexpr MessageLayout kChild{kChildFields, 2};
constexpr MessageField kFields[] = {{1, 5, true}, {2, 11, false, &kChild}, {3, 11, true, &kChild}};
constexpr MessageLayout kLayout{kFields, 3};
Str bytes(const u8* p, u32 n) {
    return {reinterpret_cast<const char*>(p), n};
}
}  // namespace
TEST(protobuf_message, packed_unpacked_and_singular_message_merge) {
    // Independent wire fixture: repeated [1, 2, 0], child {text:"x"} then
    // child {id:7}; repeated child {} followed by {text:"y"}.
    const u8 kInput[] = {8,  1, 10, 2, 2,  0, 18, 3, 10, 1, 'x',
                         18, 2, 16, 7, 26, 0, 26, 3, 10, 1, 'y'};
    MessageValue values[32];
    MessageStorage storage{values, 32};
    u32 head = 99;
    REQUIRE(decode_message(kLayout, bytes(kInput, sizeof(kInput)), storage, head) ==
            MessageStatus::Ok);
    CHECK_EQ(head, 1u);
    u32 n = head;
    const u32 kExpectedValues[] = {1, 2, 0};
    for (u32 const kExpected : kExpectedValues) {
        REQUIRE(n != 0);
        CHECK_EQ(values[n - 1].scalar, kExpected);
        n = values[n - 1].next;
    }
    REQUIRE(n != 0);
    CHECK_EQ(values[n - 1].field, 1u);
    const u32 kChild = values[n - 1].child;
    CHECK(values[kChild - 1].bytes.eq(lit_str("x")));
    CHECK_EQ(values[values[kChild - 1].next - 1].scalar, 7u);
    n = values[n - 1].next;
    REQUIRE(n != 0);
    CHECK_EQ(values[n - 1].child, 0u);
    n = values[n - 1].next;
    REQUIRE(n != 0);
    CHECK(values[values[n - 1].child - 1].bytes.eq(lit_str("y")));
    CHECK_EQ(values[n - 1].next, 0u);
    const u8 kExpected[] = {8, 1, 8, 2, 8, 0, 18, 5, 10, 1, 'x', 16, 7, 26, 0, 26, 3, 10, 1, 'y'};
    u8 output[64];
    u32 size = 0;
    REQUIRE(encode_message(kLayout, storage, head, output, sizeof(output), size) ==
            MessageStatus::Ok);
    CHECK(bytes(output, size).eq(bytes(kExpected, sizeof(kExpected))));
}
TEST(protobuf_message, malformed_nested_packed_utf8_and_limits) {
    const u8 kTruncated[] = {18, 1, 8};
    const u8 kPacked[] = {10, 1, 128};
    const u8 kUtf8[] = {18, 3, 10, 1, 255};
    MessageValue values[32];
    MessageStorage storage{values, 32};
    u32 head = 99;
    const Str kInvalidInputs[] = {bytes(kTruncated, sizeof(kTruncated)),
                                  bytes(kPacked, sizeof(kPacked)),
                                  bytes(kUtf8, sizeof(kUtf8))};
    for (Str const kInput : kInvalidInputs) {
        CHECK(decode_message(kLayout, kInput, storage, head) == MessageStatus::Invalid);
        CHECK_EQ(head, 0u);
        CHECK_EQ(storage.used, 0u);
    }
    const u8 kRepeated[] = {8, 1, 8, 2};
    storage.capacity = 1;
    CHECK(decode_message(kLayout, bytes(kRepeated, sizeof(kRepeated)), storage, head) ==
          MessageStatus::Limit);
    CHECK_EQ(storage.used, 0u);
    MessageLayout recursive{};
    MessageField const kField{1, 11, false, &recursive};
    recursive = {&kField, 1};
    u8 nested[40]{};
    u32 length = 0;
    for (u32 i = 0; i < 17; ++i) {
        for (u32 j = length; j; --j) nested[j + 1] = nested[j - 1];
        nested[0] = 10;
        nested[1] = static_cast<u8>(length);
        length += 2;
    }
    storage.capacity = 32;
    CHECK(decode_message(recursive, bytes(nested, length), storage, head) == MessageStatus::Limit);
    CHECK_EQ(storage.used, 0u);
}
TEST(protobuf_message, unknown_wrong_wire_duplicates_and_output_failure) {
    constexpr MessageField kFields[] = {{1, 5}, {2, 7, true}};
    const MessageLayout kLayout{kFields, 2};
    const u8 kInput[] = {8, 1, 10, 1, 255, 8, 2, 24, 9, 18, 8, 1, 0, 0, 0, 2, 0, 0, 0};
    MessageValue values[16];
    MessageStorage storage{values, 16};
    u32 head = 0;
    REQUIRE(decode_message(kLayout, bytes(kInput, sizeof(kInput)), storage, head) ==
            MessageStatus::Ok);
    CHECK_EQ(values[head - 1].scalar, 2u);
    CHECK_EQ(values[values[head - 1].next - 1].scalar, 1u);
    u8 output[32];
    u32 size = 99;
    CHECK(encode_message(kLayout, storage, head, output, 1, size) == MessageStatus::Limit);
    CHECK_EQ(size, 0u);
    values[head - 1].next = head;
    CHECK(encode_message(kLayout, storage, head, output, sizeof(output), size) ==
          MessageStatus::Limit);
    const u8 kBadFixed[] = {18, 1, 1};
    CHECK(decode_message(kLayout, bytes(kBadFixed, sizeof(kBadFixed)), storage, head) ==
          MessageStatus::Invalid);
}
TEST(protobuf_message, numeric_bits_empty_input_and_invalid_layout) {
    const MessageField kFields[] = {{1, 1}, {2, 2, true}, {3, 4}};
    const MessageLayout kLayout{kFields, 3};
    // double 1.0, packed float 1.0, UINT64_MAX, then unknown fixed32.
    const u8 kInput[] = {9,   0,   0,   0,   0,   0,   0,   240, 63,  18, 4,  0, 0, 128, 63, 24,
                         255, 255, 255, 255, 255, 255, 255, 255, 255, 1,  37, 0, 0, 0,   0};
    MessageValue values[8];
    MessageStorage storage{values, 8};
    u32 head = 0;
    REQUIRE(decode_message(kLayout, bytes(kInput, sizeof(kInput)), storage, head) ==
            MessageStatus::Ok);
    REQUIRE(head > 0 && head <= 8);
    REQUIRE(values[head - 1].next > 0 && values[head - 1].next <= 8);
    CHECK_EQ(values[head - 1].scalar, 0x3ff0000000000000ULL);
    CHECK_EQ(values[values[head - 1].next - 1].scalar, 0x3f800000ULL);
    u8 output[64];
    u32 size = 0;
    REQUIRE(encode_message(kLayout, storage, head, output, sizeof(output), size) ==
            MessageStatus::Ok);
    MessageValue decoded[8];
    MessageStorage again{decoded, 8};
    u32 roundtrip = 0;
    REQUIRE(decode_message(kLayout, bytes(output, size), again, roundtrip) == MessageStatus::Ok);
    const u32 kSecond = decoded[roundtrip - 1].next;
    CHECK_EQ(decoded[decoded[kSecond - 1].next - 1].scalar, ~u64{0});
    CHECK(decode_message(kLayout, {}, storage, head) == MessageStatus::Ok);
    CHECK_EQ(head, 0u);
    const MessageField kDuplicates[] = {{1, 5}, {1, 9}};
    CHECK(decode_message({kDuplicates, 2}, {}, storage, head) == MessageStatus::Invalid);
    CHECK(decode_message({nullptr, 1}, {}, storage, head) == MessageStatus::Invalid);
    CHECK(decode_message(kLayout, {nullptr, 1}, storage, head) == MessageStatus::Invalid);
    CHECK(decode_message(kLayout, {"", kMaxMessageBytes + 1}, storage, head) ==
          MessageStatus::Limit);
    CHECK_EQ(storage.used, 3u);
}
TEST(protobuf_message, bounded_arbitrary_inputs_roundtrip_and_preserve_budget) {
    u32 random = 0x835;
    for (u32 iteration = 0; iteration < 1000; ++iteration) {
        u8 input[32];
        for (u8& byte : input) {
            random = random * 1664525u + 1013904223u;
            byte = static_cast<u8>(random >> 24);
        }
        MessageValue values[32];
        MessageStorage storage{values, 32};
        u32 head = 0;
        const auto kStatus = decode_message(kLayout, bytes(input, iteration % 33), storage, head);
        REQUIRE(storage.used <= 32);
        if (kStatus != MessageStatus::Ok) {
            CHECK_EQ(head, 0u);
            CHECK_EQ(storage.used, 0u);
            continue;
        }
        u8 output[128];
        u32 size = 0;
        REQUIRE(encode_message(kLayout, storage, head, output, sizeof(output), size) ==
                MessageStatus::Ok);
        MessageValue copy[32];
        MessageStorage second{copy, 32};
        u32 root = 0;
        CHECK(decode_message(kLayout, bytes(output, size), second, root) == MessageStatus::Ok);
    }
}
int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
