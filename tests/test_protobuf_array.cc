#include "rut/common/types.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/protobuf_array.h"
#include "test.h"
using namespace rut;
using namespace rut::protobuf;
namespace {
Str view(const u8* bytes, u32 count) {
    return {reinterpret_cast<const char*>(bytes), count};
}
}  // namespace
TEST(protobuf_array, packed_unpacked_defaults_and_exact_storage) {
    const u8 input[] = {8, 1, 10, 2, 2, 0, 16, 99};
    ArrayPlan plan{};
    REQUIRE(plan_array(kRepeated | (1u << 8) | 5, view(input, sizeof(input)), plan));
    CHECK_EQ(plan.count, 3u);
    CHECK_EQ(plan.bytes, 0u);
    i32 slots[3]{};
    REQUIRE(fill_array(kRepeated | (1u << 8) | 5,
                       view(input, sizeof(input)),
                       reinterpret_cast<u8*>(slots),
                       nullptr,
                       plan));
    CHECK_EQ(slots[0], 1);
    CHECK_EQ(slots[1], 2);
    CHECK_EQ(slots[2], 0);
    u8 output[32];
    Str encoded{};
    REQUIRE(encode_array(kRepeated | kEncode | (1u << 8) | 5,
                         lit_str(""),
                         reinterpret_cast<const u8*>(slots),
                         3,
                         output,
                         sizeof(output),
                         encoded));
    const u8 expected[] = {8, 1, 8, 2, 8, 0};
    CHECK(encoded.eq(view(expected, sizeof(expected))));
}
TEST(protobuf_array, string_slots_own_bytes_and_preserve_empty_elements) {
    u8 input[] = {18, 1, 'x', 18, 0};
    ArrayPlan plan{};
    REQUIRE(plan_array(kRepeated | (2u << 8) | 9, view(input, sizeof(input)), plan));
    CHECK_EQ(plan.count, 2u);
    CHECK_EQ(plan.bytes, 1u);
    Str slots[2];
    u8 payload[1];
    REQUIRE(fill_array(kRepeated | (2u << 8) | 9,
                       view(input, sizeof(input)),
                       reinterpret_cast<u8*>(slots),
                       payload,
                       plan));
    input[2] = 'z';
    CHECK(slots[0].eq(lit_str("x")));
    CHECK(slots[1].eq(lit_str("")));
    u8 output[32];
    Str encoded{};
    REQUIRE(encode_array(kRepeated | kEncode | (2u << 8) | 9,
                         lit_str(""),
                         reinterpret_cast<const u8*>(slots),
                         2,
                         output,
                         sizeof(output),
                         encoded));
    const u8 expected[] = {18, 1, 'x', 18, 0};
    CHECK(encoded.eq(view(expected, sizeof(expected))));
}
TEST(protobuf_array, malformed_wire_limits_and_budget_reset) {
    const u8 malformed[] = {10, 1, 128};
    const u8 utf8[] = {10, 1, 255};
    ArrayPlan plan{7, 9};
    CHECK_FALSE(plan_array(kRepeated | (1u << 8) | 5, view(malformed, sizeof(malformed)), plan));
    CHECK_EQ(plan.count, 7u);
    CHECK_EQ(plan.bytes, 9u);
    CHECK_FALSE(plan_array(kRepeated | (1u << 8) | 9, view(utf8, sizeof(utf8)), plan));
    u8 many[(kMaxArrayElements + 1) * 2];
    for (u32 i = 0; i < kMaxArrayElements + 1; ++i) {
        many[2 * i] = 8;
        many[2 * i + 1] = 0;
    }
    CHECK_FALSE(plan_array(kRepeated | (1u << 8) | 5, view(many, sizeof(many)), plan));
    REQUIRE(plan_array(kRepeated | (1u << 8) | 5, view(many, sizeof(many) - 2), plan));
    CHECK_EQ(plan.count, kMaxArrayElements);
    MmapArena arena;
    REQUIRE(arena.init(4096));
    arena.set_collection_items(9);
    arena.reset();
    CHECK_EQ(arena.collection_items(), 0u);
    arena.set_collection_items(4);
    arena.destroy();
    CHECK_EQ(arena.collection_items(), 0u);
}
TEST(protobuf_array, scalar_boundaries_empty_packing_and_fixed_width) {
    const u8 packed_fixed[] = {10, 8, 0, 0, 0, 0, 255, 255, 255, 255};
    ArrayPlan plan{};
    REQUIRE(plan_array(kRepeated | (1u << 8) | 7, view(packed_fixed, sizeof(packed_fixed)), plan));
    i64 slots[2];
    REQUIRE(fill_array(kRepeated | (1u << 8) | 7,
                       view(packed_fixed, sizeof(packed_fixed)),
                       reinterpret_cast<u8*>(slots),
                       nullptr,
                       plan));
    CHECK_EQ(slots[0], 0);
    CHECK_EQ(slots[1], 4294967295LL);
    const u8 bad_fixed[] = {10, 1, 0};
    CHECK_FALSE(plan_array(kRepeated | (1u << 8) | 7, view(bad_fixed, sizeof(bad_fixed)), plan));
    const u8 empty[] = {10, 0};
    REQUIRE(plan_array(kRepeated | (1u << 8) | 5, view(empty, sizeof(empty)), plan));
    CHECK_EQ(plan.count, 0u);
    u8 output[32];
    Str encoded{};
    slots[0] = -1;
    CHECK_FALSE(encode_array(kRepeated | kEncode | (1u << 8) | 7,
                             lit_str(""),
                             reinterpret_cast<const u8*>(slots),
                             1,
                             output,
                             sizeof(output),
                             encoded));
}
int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
