#include "rut/common/types.h"
#include "rut/runtime/protobuf_wire.h"
#include "test.h"

#include <string.h>

using namespace rut;
using namespace rut::protobuf;

TEST(protobuf_wire, golden_message_and_borrowed_bytes) {
    const u8 kGolden[] = {0x08, 0x96, 0x01, 0x12, 0x03, 'f', 'o', 'o', 0x1d, 0x78, 0x56,
                          0x34, 0x12, 0x21, 1,    2,    3,   4,   5,   6,    7,    8};
    Reader reader(kGolden, sizeof(kGolden));
    u8 output[sizeof(kGolden) + 1];
    memset(output, 0xa5, sizeof(output));
    Writer writer(output, sizeof(kGolden));
    Field field;
    REQUIRE(reader.next(field) == Status::Field);
    CHECK_EQ(field.number, 1u);
    CHECK_EQ(field.value, 150u);
    REQUIRE(writer.write(field));
    REQUIRE(reader.next(field) == Status::Field);
    CHECK_EQ(field.size, 3u);
    CHECK(field.bytes == kGolden + 5);
    REQUIRE(writer.write(field));
    REQUIRE(reader.next(field) == Status::Field);
    CHECK_EQ(field.value, 0x12345678u);
    REQUIRE(writer.write(field));
    REQUIRE(reader.next(field) == Status::Field);
    CHECK_EQ(field.value, 0x0807060504030201ULL);
    REQUIRE(writer.write(field));
    CHECK(reader.next(field) == Status::End);
    CHECK_EQ(writer.size(), sizeof(kGolden));
    CHECK_EQ(memcmp(output, kGolden, sizeof(kGolden)), 0);
    CHECK_EQ(output[sizeof(kGolden)], 0xa5);
}

TEST(protobuf_wire, varint_boundaries_and_zigzag) {
    const u64 kValues[] = {
        0, 1, 127, 128, 16383, 16384, 0xffffffffULL, 0x8000000000000000ULL, ~u64{0}};
    for (const u64 kValue : kValues) {
        u8 output[15];
        Writer writer(output, sizeof(output));
        REQUIRE(writer.write({0x1fffffff, 0, kValue}));
        Reader reader(output, writer.size());
        Field field;
        REQUIRE(reader.next(field) == Status::Field);
        CHECK_EQ(field.number, 0x1fffffffu);
        CHECK_EQ(field.value, kValue);
        CHECK(reader.next(field) == Status::End);
        for (u32 n = 1; n < writer.size(); ++n) {
            Reader partial(output, n);
            CHECK(partial.next(field) == Status::Invalid);
        }
    }
    const i64 kSignedValues[] = {
        0, -1, 1, -2147483647 - 1, 2147483647, -9223372036854775807LL - 1, 9223372036854775807LL};
    for (const i64 kValue : kSignedValues) CHECK_EQ(zigzag_decode(zigzag_encode(kValue)), kValue);
    CHECK_EQ(zigzag_encode(-1), 1u);
}

TEST(protobuf_wire, malformed_input_is_terminal_and_preserves_output) {
    const u8 kInputs[][12] = {{0},
                              {0x0b},
                              {0x0c},
                              {0x0e},
                              {0x0f},
                              {8, 0x80},
                              {8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2},
                              {0x12, 4, 'a'},
                              {0x0d, 1, 2, 3},
                              {0x09, 1, 2, 3, 4, 5, 6, 7},
                              {0x80, 0x80, 0x80, 0x80, 0x10, 0},
                              {0x12, 0xff, 0xff, 0xff, 0xff, 0x0f}};
    const u32 kSizes[] = {1, 1, 1, 1, 1, 2, 11, 3, 4, 8, 6, 6};
    for (u32 i = 0; i < sizeof(kSizes) / sizeof(kSizes[0]); ++i) {
        Reader reader(kInputs[i], kSizes[i]);
        Field field{42, 0, 123};
        CHECK(reader.next(field) == Status::Invalid);
        CHECK_EQ(field.number, 42u);
        CHECK_EQ(field.value, 123u);
        CHECK(reader.next(field) == Status::Invalid);
    }
    Reader invalid(nullptr, 1);
    Field field;
    CHECK(invalid.next(field) == Status::Invalid);
    Reader empty(nullptr, 0, 0);
    CHECK(empty.next(field) == Status::End);
}

TEST(protobuf_wire, budgets_unknown_fields_duplicates_and_empty_payload) {
    const u8 kInput[] = {8, 1, 8, 2, 0x12, 0};
    Reader reader(kInput, sizeof(kInput), 3);
    Field field;
    REQUIRE(reader.next(field) == Status::Field);
    CHECK_EQ(field.value, 1u);
    REQUIRE(reader.next(field) == Status::Field);
    CHECK_EQ(field.value, 2u);
    REQUIRE(reader.next(field) == Status::Field);
    CHECK_EQ(field.size, 0u);
    CHECK(reader.next(field) == Status::End);
    Reader limited(kInput, sizeof(kInput), 2);
    REQUIRE(limited.next(field) == Status::Field);
    REQUIRE(limited.next(field) == Status::Field);
    CHECK(limited.next(field) == Status::Invalid);
}

TEST(protobuf_wire, insufficient_output_is_atomic) {
    const u8 kPayload[] = {1, 2, 3};
    const Field kFields[] = {
        {1, 0, ~u64{0}}, {2, 1, ~u64{0}}, {3, 5, 0xffffffffu}, {4, 2, 0, kPayload, 3}};
    for (const Field& field : kFields) {
        u8 full[32];
        Writer sizing(full, sizeof(full));
        REQUIRE(sizing.write(field));
        for (u32 capacity = 0; capacity < sizing.size(); ++capacity) {
            u8 output[32];
            memset(output, 0xa5, sizeof(output));
            Writer writer(output, capacity);
            CHECK_FALSE(writer.write(field));
            CHECK_EQ(writer.size(), 0u);
            for (const u8 kByte : output) CHECK_EQ(kByte, 0xa5);
        }
    }
    u8 output[16]{};
    Writer writer(output, sizeof(output));
    CHECK_FALSE(writer.write({0, 0, 1}));
    CHECK_FALSE(writer.write({0x20000000, 0, 1}));
    CHECK_FALSE(writer.write({1, 3}));
    CHECK_FALSE(writer.write({1, 2, 0, nullptr, 1}));
    CHECK_EQ(writer.size(), 0u);
}

TEST(protobuf_wire, rejected_append_preserves_committed_prefix) {
    u8 output[8];
    memset(output, 0xa5, sizeof(output));
    Writer writer(output, 3);
    REQUIRE(writer.write({1, 0, 1}));
    CHECK_FALSE(writer.write({2, 0, 150}));
    CHECK_EQ(writer.size(), 2u);
    CHECK_EQ(output[0], 8u);
    CHECK_EQ(output[1], 1u);
    for (u32 i = 2; i < sizeof(output); ++i) CHECK_EQ(output[i], 0xa5);
}

TEST(protobuf_wire, bounded_arbitrary_inputs_never_escape_views_or_iteration_budget) {
    u32 state = 0x12345678;
    for (u32 iteration = 0; iteration < 10000; ++iteration) {
        u8 input[32];
        for (u8& byte : input) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            byte = static_cast<u8>(state);
        }
        const u32 kSize = iteration % 33;
        Reader reader(input, kSize, 8);
        Field field;
        u32 count = 0;
        Status status;
        while ((status = reader.next(field)) == Status::Field) {
            REQUIRE(++count <= 8);
            CHECK(field.number > 0 && field.number <= 0x1fffffff);
            if (field.wire == 2) {
                REQUIRE(field.bytes >= input && field.bytes <= input + kSize);
                CHECK(field.size <= static_cast<u32>(input + kSize - field.bytes));
            }
        }
        CHECK(reader.next(field) == status);
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
