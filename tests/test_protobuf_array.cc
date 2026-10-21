#include "rut/common/types.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/protobuf_array.h"
#include "rut/runtime/protobuf_struct_array.h"
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
        many[2ULL * i] = 8;
        many[2ULL * i + 1] = 0;
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
namespace {
Str child_layout(u8* bytes) {
    const u32 words[] = {24, 8, 2, 1, 9, 0, 0, 2, 5, 16, 0};
    u32 cursor = 0;
    for (u32 word : words)
        for (u32 i = 0; i < 4; ++i) bytes[cursor++] = static_cast<u8>(word >> (8 * i));
    return view(bytes, cursor);
}
struct NativeChild {
    Str text;
    i32 id;
};
static_assert(sizeof(NativeChild) == 24);
}  // namespace
TEST(protobuf_array, repeated_messages_own_native_structs_and_preserve_empty) {
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 description[44];
    const Str schema = child_layout(description);
    u8 input[] = {10, 5, 10, 1, 'x', 16, 1, 10, 0};
    Str array{};
    REQUIRE(decode_struct_array(1, schema, view(input, sizeof(input)), &arena, array));
    CHECK_EQ(array.len, 2u);
    CHECK_EQ(arena.collection_items(), 2u);
    NativeChild first{}, second{};
    __builtin_memcpy(&first, array.ptr, sizeof(first));
    __builtin_memcpy(&second, array.ptr + sizeof(first), sizeof(second));
    __builtin_memset(input, 0, sizeof(input));
    CHECK(first.text.eq(lit_str("x")));
    CHECK_EQ(first.id, 1);
    CHECK(second.text.eq(lit_str("")));
    CHECK_EQ(second.id, 0);
    u8 output[64];
    Str encoded{};
    REQUIRE(encode_struct_array(1, schema, lit_str(""), array, output, sizeof(output), encoded));
    const u8 expected[] = {10, 5, 10, 1, 'x', 16, 1, 10, 0};
    CHECK(encoded.eq(view(expected, sizeof(expected))));
    arena.reset();
    CHECK_EQ(arena.collection_items(), 0u);
    arena.destroy();
    pool.destroy();
}
TEST(protobuf_array, measured_plan_matches_decode_preflight_and_empty_semantics) {
    u8 description[44];
    const Str schema = child_layout(description);
    const u8 input[] = {10, 5, 10, 1, 'x', 16, 1};
    protobuf::struct_array_detail::Budget measured{};
    REQUIRE(protobuf::struct_array_detail::measure_array(
        1, schema, view(input, sizeof(input)), measured, 0));
    SlicePool pool;
    REQUIRE(pool.init(4));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    Str output{};
    REQUIRE(decode_struct_array(1, schema, view(input, sizeof(input)), &arena, output, &measured));
    CHECK_EQ(output.len, 1u);
    CHECK_EQ(arena.collection_items(), measured.items);
    arena.destroy();
    pool.destroy();

    const Str empty_input{nullptr, 0};
    protobuf::struct_array_detail::Budget empty_plan{};
    REQUIRE(protobuf::struct_array_detail::measure_array(1, schema, empty_input, empty_plan, 0));
    Str empty_output = lit_str("unchanged");
    // The measured plan is valid only for this unchanged schema/input pair.
    REQUIRE(decode_struct_array(1, schema, empty_input, nullptr, empty_output, &empty_plan));
    CHECK(empty_output.eq(lit_str("")));
}
TEST(protobuf_array, repeated_message_preflight_checks_every_element_and_shared_budget) {
    SlicePool pool;
    REQUIRE(pool.init(1, 0, 0));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 description[44];
    const Str schema = child_layout(description);
    const u8 malformed[] = {10, 3, 10, 1, 'x', 10, 3, 10, 1, 255};
    Str result = lit_str("unchanged");
    const u64 before = arena.space_used();
    CHECK_FALSE(decode_struct_array(1, schema, view(malformed, sizeof(malformed)), &arena, result));
    CHECK(result.eq(lit_str("unchanged")));
    CHECK_EQ(arena.space_used(), before);
    CHECK_EQ(arena.collection_items(), 0u);
    const u8 empty[] = {10, 0, 10, 0};
    arena.set_collection_items(kMaxRequestArrayElements - 1);
    CHECK_FALSE(decode_struct_array(1, schema, view(empty, sizeof(empty)), &arena, result));
    CHECK_EQ(arena.collection_items(), kMaxRequestArrayElements - 1);
    CHECK_EQ(arena.space_used(), before);
    arena.reset();
    REQUIRE(arena.alloc(arena.current->remaining()));
    CHECK_FALSE(decode_struct_array(1, schema, view(empty, sizeof(empty)), &arena, result));
    CHECK_EQ(arena.collection_items(), 0u);
    CHECK(result.eq(lit_str("unchanged")));
    arena.reset();
    REQUIRE(arena.alloc(arena.current->remaining() - 8));
    const u64 before_partial = arena.space_used();
    const u8 one[] = {10, 3, 10, 1, 'x'};
    CHECK_FALSE(decode_struct_array(1, schema, view(one, sizeof(one)), &arena, result));
    CHECK_EQ(arena.collection_items(), 0u);
    CHECK_EQ(arena.space_used(), before_partial + 8);
    CHECK(result.eq(lit_str("unchanged")));
    arena.destroy();
    pool.destroy();
}

TEST(protobuf_array, repeated_message_contiguous_slot_limit) {
    u8 description[140];
    u32 cursor = 0;
    auto word = [&](u32 value) {
        for (u32 i = 0; i < 4; ++i) description[cursor++] = static_cast<u8>(value >> (8 * i));
    };
    word(128);
    word(8);
    word(8);
    for (u32 i = 0; i < 8; ++i) {
        word(i + 1);
        word(9);
        word(i * 16);
        word(0);
    }
    u8 input[256];
    for (u32 i = 0; i < 128; ++i) {
        input[2ULL * i] = 10;
        input[2ULL * i + 1] = 0;
    }
    SlicePool pool;
    REQUIRE(pool.init(2));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    Str result = lit_str("unchanged");
    CHECK_FALSE(decode_struct_array(
        1, view(description, cursor), view(input, sizeof(input)), &arena, result));
    CHECK(result.eq(lit_str("unchanged")));
    CHECK_EQ(arena.space_used(), 0u);
    REQUIRE(decode_struct_array(
        1, view(description, cursor), view(input, sizeof(input) - 2), &arena, result));
    CHECK_EQ(result.len, 127u);
    CHECK_EQ(arena.collection_items(), 127u);
    arena.destroy();
    pool.destroy();
}

#include "protobuf/repeated_oracle.inc"

TEST(protobuf_array, repeated_message_google_protobuf_interoperability) {
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 description[44];
    const Str schema = child_layout(description);
    Str array{};
    REQUIRE(decode_struct_array(
        1, schema, view(kRepeatedOracle, sizeof(kRepeatedOracle)), &arena, array));
    REQUIRE(array.len == 3);
    NativeChild children[3];
    __builtin_memcpy(children, array.ptr, sizeof(children));
    CHECK(children[0].text.eq(Str{"\xe9\x9b\xaa\0", 4}));
    CHECK_EQ(children[0].id, (-2147483647 - 1));
    CHECK_EQ(children[1].text.len, 0u);
    CHECK_EQ(children[1].id, 0);
    CHECK(children[2].text.eq(lit_str("last")));
    CHECK_EQ(children[2].id, 2147483647);
    u8 output[128];
    Str encoded{};
    REQUIRE(encode_struct_array(1, schema, lit_str(""), array, output, sizeof(output), encoded));
    CHECK(encoded.eq(view(kRepeatedOracle, sizeof(kRepeatedOracle))));
    arena.reset();
    REQUIRE(decode_struct_array(
        1, schema, view(kRepeatedNoncanonical, sizeof(kRepeatedNoncanonical)), &arena, array));
    REQUIRE(encode_struct_array(1, schema, lit_str(""), array, output, sizeof(output), encoded));
    CHECK(encoded.eq(view(kRepeatedNormalized, sizeof(kRepeatedNormalized))));
    CHECK_EQ(arena.collection_items(), 2u);
    arena.destroy();
    pool.destroy();
}

TEST(protobuf_array, repeated_message_truncation_and_invalid_later_element_are_atomic) {
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 description[44];
    const Str schema = child_layout(description);
    // Every prefix inside a length-delimited child must fail; complete child
    // boundaries are independently valid protobuf messages.
    const u32 boundaries[] = {0, 19, 21, sizeof(kRepeatedOracle)};
    for (u32 length = 0; length <= sizeof(kRepeatedOracle); ++length) {
        bool complete = false;
        for (u32 boundary : boundaries) complete |= length == boundary;
        Str result = lit_str("unchanged");
        const bool accepted =
            decode_struct_array(1, schema, view(kRepeatedOracle, length), &arena, result);
        CHECK_EQ(accepted, complete);
        if (!accepted) {
            CHECK(result.eq(lit_str("unchanged")));
            CHECK_EQ(arena.space_used(), 0u);
            CHECK_EQ(arena.collection_items(), 0u);
        }
        arena.reset();
    }
    const u8 invalid[][8] = {
        {10, 0, 10, 2, 16, 128, 0, 0},  // truncated varint in second child
        {10, 0, 10, 2, 10, 1, 0, 0},    // string exceeds second child
        {10, 0, 10, 2, 0, 0, 0, 0},     // forbidden zero field tag
        {10, 0, 10, 2, 15, 0, 0, 0},    // forbidden wire type
    };
    for (const auto& bytes : invalid) {
        Str result = lit_str("unchanged");
        CHECK_FALSE(decode_struct_array(1, schema, view(bytes, 6), &arena, result));
        CHECK(result.eq(lit_str("unchanged")));
        CHECK_EQ(arena.space_used(), 0u);
        CHECK_EQ(arena.collection_items(), 0u);
    }
    arena.destroy();
    pool.destroy();
}

TEST(protobuf_array, repeated_message_encode_capacity_prefix_and_invalid_native_values) {
    u8 description[44];
    const Str schema = child_layout(description);
    NativeChild child{lit_str("x"), 1};
    const Str array{reinterpret_cast<const char*>(&child), 1};
    const u8 expected[] = {24, 7, 10, 5, 10, 1, 'x', 16, 1};
    const Str prefix = view(expected, 2);
    u8 output[32];
    for (u32 capacity = 0; capacity <= sizeof(expected); ++capacity) {
        __builtin_memset(output, 0xa5, sizeof(output));
        Str result = lit_str("unchanged");
        const bool ok = encode_struct_array(1, schema, prefix, array, output, capacity, result);
        CHECK_EQ(ok, capacity == sizeof(expected));
        if (ok)
            CHECK(result.eq(view(expected, sizeof(expected))));
        else
            CHECK(result.eq(lit_str("unchanged")));
        for (u32 i = capacity; i < sizeof(output); ++i) CHECK_EQ(output[i], 0xa5u);
    }
    Str result = lit_str("unchanged");
    child.text = Str{"\xff", 1};
    CHECK_FALSE(encode_struct_array(1, schema, lit_str(""), array, output, sizeof(output), result));
    child.text = {nullptr, 1};
    CHECK_FALSE(encode_struct_array(1, schema, lit_str(""), array, output, sizeof(output), result));
    CHECK_FALSE(
        encode_struct_array(1, schema, lit_str(""), {nullptr, 1}, output, sizeof(output), result));
    CHECK_FALSE(encode_struct_array(0, schema, lit_str(""), array, output, sizeof(output), result));
    CHECK(result.eq(lit_str("unchanged")));
}

TEST(protobuf_array, repeated_message_request_budget_boundary_and_reuse) {
    SlicePool pool;
    REQUIRE(pool.init(32));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 description[44];
    const Str schema = child_layout(description);
    const u8 empty[] = {10, 0};
    Str result{};
    arena.set_collection_items(kMaxRequestArrayElements - 1);
    REQUIRE(decode_struct_array(1, schema, view(empty, sizeof(empty)), &arena, result));
    CHECK_EQ(arena.collection_items(), kMaxRequestArrayElements);
    const u64 used = arena.space_used();
    result = lit_str("unchanged");
    CHECK_FALSE(decode_struct_array(1, schema, view(empty, sizeof(empty)), &arena, result));
    CHECK(result.eq(lit_str("unchanged")));
    CHECK_EQ(arena.space_used(), used);
    // Repeated request resets must reclaim both allocation and collection limits.
    for (u32 request = 0; request < 64; ++request) {
        arena.reset();
        CHECK_EQ(arena.collection_items(), 0u);
        CHECK_EQ(arena.space_used(), 0u);
        REQUIRE(decode_struct_array(
            1, schema, view(kRepeatedOracle, sizeof(kRepeatedOracle)), &arena, result));
        CHECK_EQ(result.len, 3u);
        CHECK_EQ(arena.collection_items(), 3u);
    }
    arena.destroy();
    pool.destroy();
}

TEST(protobuf_array, nested_repeated_messages_share_budget_and_own_descendants) {
    u8 description[72];
    const u32 words[] = {16, 8, 1, 1, 11 | 256, 0, 44};
    u32 cursor = 0;
    for (u32 word : words)
        for (u32 i = 0; i < 4; ++i) description[cursor++] = static_cast<u8>(word >> (8 * i));
    child_layout(description + cursor);
    const Str schema = view(description, sizeof(description));
    u8 input[] = {10, 9, 10, 5, 10, 1, 'x', 16, 1, 10, 0};
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    Str result = lit_str("unchanged");
    // One outer message plus its two children must all count against the
    // request budget, including the child with no populated fields.
    arena.set_collection_items(kMaxRequestArrayElements - 2);
    CHECK_FALSE(decode_struct_array(1, schema, view(input, sizeof(input)), &arena, result));
    CHECK(result.eq(lit_str("unchanged")));
    CHECK_EQ(arena.space_used(), 0u);
    arena.set_collection_items(kMaxRequestArrayElements - 3);
    REQUIRE(decode_struct_array(1, schema, view(input, sizeof(input)), &arena, result));
    CHECK_EQ(arena.collection_items(), kMaxRequestArrayElements);
    CHECK_EQ(result.len, 1u);
    Str children;
    __builtin_memcpy(&children, result.ptr, sizeof(children));
    REQUIRE(children.len == 2);
    NativeChild first;
    __builtin_memcpy(&first, children.ptr, sizeof(first));
    __builtin_memset(input, 0xff, sizeof(input));
    CHECK(first.text.eq(lit_str("x")));
    CHECK_EQ(first.id, 1);
    u8 output[32];
    Str encoded;
    REQUIRE(encode_struct_array(1, schema, lit_str(""), result, output, sizeof(output), encoded));
    const u8 expected[] = {10, 9, 10, 5, 10, 1, 'x', 16, 1, 10, 0};
    CHECK(encoded.eq(view(expected, sizeof(expected))));
    arena.destroy();
    pool.destroy();
}

TEST(protobuf_array, invalid_native_layout_is_rejected_before_allocation) {
    SlicePool pool;
    REQUIRE(pool.init(2));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u8 description[44];
    const u8 input[] = {10, 0};
    // Truncated metadata and corrupt sizes, alignment, tags, types and offsets
    // must never escape into a native memory read/write.
    for (u32 length = 0; length < sizeof(description); ++length) {
        child_layout(description);
        Str result = lit_str("unchanged");
        CHECK_FALSE(decode_struct_array(
            1, view(description, length), view(input, sizeof(input)), &arena, result));
        CHECK(result.eq(lit_str("unchanged")));
        CHECK_EQ(arena.space_used(), 0u);
    }
    const u32 positions[] = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40};
    for (u32 position : positions) {
        child_layout(description);
        description[position] = 255;
        Str result = lit_str("unchanged");
        // 255 is a legal tag; make the second tag duplicate instead.
        if (position == 12 || position == 28) description[position] = position == 12 ? 2 : 1;
        CHECK_FALSE(decode_struct_array(
            1, view(description, sizeof(description)), view(input, sizeof(input)), &arena, result));
        CHECK(result.eq(lit_str("unchanged")));
        CHECK_EQ(arena.space_used(), 0u);
        CHECK_EQ(arena.collection_items(), 0u);
    }
    arena.destroy();
    pool.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(protobuf_array, packed_open_enum_preserves_unknown_negative_and_defaults) {
    const u8 input[] = {10, 12, 0, 123, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1};
    ArrayPlan plan{};
    const u64 op = kRepeated | (1u << 8) | 14;
    REQUIRE(plan_array(op, view(input, sizeof(input)), plan));
    REQUIRE_EQ(plan.count, 3u);
    i32 slots[3]{};
    REQUIRE(
        fill_array(op, view(input, sizeof(input)), reinterpret_cast<u8*>(slots), nullptr, plan));
    CHECK_EQ(slots[0], 0);
    CHECK_EQ(slots[1], 123);
    CHECK_EQ(slots[2], -1);
    u8 output[32];
    Str encoded{};
    REQUIRE(encode_array(op | kEncode,
                         lit_str(""),
                         reinterpret_cast<const u8*>(slots),
                         3,
                         output,
                         sizeof(output),
                         encoded));
    ArrayPlan again{};
    REQUIRE(plan_array(op, encoded, again));
    CHECK_EQ(again.count, 3u);
}

TEST(protobuf_array, enum_truncated_varints_limits_and_output_capacity) {
    const u64 op = kRepeated | (1u << 8) | 14;
    for (u32 length = 1; length <= 10; ++length) {
        u8 input[12] = {10, static_cast<u8>(length)};
        for (u32 i = 0; i < length; ++i) input[i + 2] = 255;
        if (length == 10) input[11] = 2;  // Ten-byte varints may carry only one final bit.
        ArrayPlan plan{7, 9};
        CHECK_FALSE(plan_array(op, view(input, length + 2), plan));
        CHECK_EQ(plan.count, 7u);
        CHECK_EQ(plan.bytes, 9u);
    }
    // A 512-element packed enum field has a two-byte length prefix.
    u8 input[3 + kMaxArrayElements] = {10, 128, 4};
    ArrayPlan plan{};
    REQUIRE(plan_array(op, view(input, sizeof(input)), plan));
    CHECK_EQ(plan.count, kMaxArrayElements);
    const i32 values[] = {-1, 0, 12345};
    u8 output[32];
    Str encoded{};
    REQUIRE(encode_array(op | kEncode,
                         lit_str(""),
                         reinterpret_cast<const u8*>(values),
                         3,
                         output,
                         sizeof(output),
                         encoded));
    const u32 required = encoded.len;
    for (u32 capacity = 0; capacity < required; ++capacity) {
        Str failed{};
        CHECK_FALSE(encode_array(op | kEncode,
                                 lit_str(""),
                                 reinterpret_cast<const u8*>(values),
                                 3,
                                 output,
                                 capacity,
                                 failed));
    }
    CHECK_EQ(values[0], -1);
    CHECK_EQ(values[1], 0);
    CHECK_EQ(values[2], 12345);
}

TEST(protobuf_array, rejects_unknown_operation_bits_before_narrowing_tag) {
    const u64 kOp = kRepeated | (u64{1} << 8) | 5;
    const u8 kInput[] = {8, 7};
    const i32 kValue = 7;
    // Reserved bits above the field number are invalid, including singular
    // presence and struct-array dispatch. The packed numeric flag is allowed.
    for (u32 bit = 37; bit < 62; ++bit) {
        if (bit == 59) continue;  // packed numeric array encoding is supported.
        const u64 kInvalid = kOp | (u64{1} << bit);
        ArrayPlan plan{17, 19};
        CHECK_FALSE(plan_array(kInvalid, view(kInput, sizeof(kInput)), plan));
        CHECK_EQ(plan.count, 17u);
        CHECK_EQ(plan.bytes, 19u);
        i32 slot = 123;
        CHECK_FALSE(fill_array(
            kInvalid, view(kInput, sizeof(kInput)), reinterpret_cast<u8*>(&slot), nullptr, {1, 0}));
        CHECK_EQ(slot, 123);
        u8 output[8] = {99};
        Str result = lit_str("unchanged");
        CHECK_FALSE(encode_array(kInvalid | kEncode,
                                 lit_str(""),
                                 reinterpret_cast<const u8*>(&kValue),
                                 1,
                                 output,
                                 sizeof(output),
                                 result));
        CHECK_EQ(output[0], 99u);
        CHECK(result.eq(lit_str("unchanged")));
    }
    ArrayPlan valid{};
    REQUIRE(plan_array(kOp, view(kInput, sizeof(kInput)), valid));
    CHECK_EQ(valid.count, 1u);
    // The highest legal field number must remain accepted.
    REQUIRE(plan_array(kRepeated | (u64{0x1fffffff} << 8) | 5, lit_str(""), valid));
    CHECK_EQ(valid.count, 0u);
}

#include "protobuf/packed_array_oracle.inc"
TEST(protobuf_array, packed_encoding_matches_google_for_all_numeric_carriers) {
    const u8 kTypes[] = {3, 5, 7, 8, 13, 14, 15, 16, 17, 18};
    const Str kExpected[] = {view(kPacked3, sizeof(kPacked3)),
                             view(kPacked5, sizeof(kPacked5)),
                             view(kPacked7, sizeof(kPacked7)),
                             view(kPacked8, sizeof(kPacked8)),
                             view(kPacked13, sizeof(kPacked13)),
                             view(kPacked14, sizeof(kPacked14)),
                             view(kPacked15, sizeof(kPacked15)),
                             view(kPacked16, sizeof(kPacked16)),
                             view(kPacked17, sizeof(kPacked17)),
                             view(kPacked18, sizeof(kPacked18))};
    for (u32 i = 0; i < 10; ++i) {
        const u8 type = kTypes[i];
        const i32 narrow[] = {-1, 0, 150};
        const i64 wide[] = {-1, 0, 150};
        const i64 positive[] = {1, 0, 150};
        const u8 boolean[] = {0, 1, 0};
        const u8* slots = type == 8                       ? boolean
                          : type == 7 || type == 13       ? reinterpret_cast<const u8*>(positive)
                          : array_element_size(type) == 4 ? reinterpret_cast<const u8*>(narrow)
                                                          : reinterpret_cast<const u8*>(wide);
        const u64 op = kRepeated | kPacked | (u64{1} << 8) | type;
        u8 output[64]{};
        Str result{};
        REQUIRE(encode_array(op | kEncode, lit_str(""), slots, 3, output, sizeof(output), result));
        CHECK(result.eq(kExpected[i]));
        ArrayPlan plan{};
        REQUIRE(plan_array(op, result, plan));
        CHECK_EQ(plan.count, 3u);
        for (u32 capacity = 0; capacity < kExpected[i].len; ++capacity)
            CHECK_FALSE(
                encode_array(op | kEncode, lit_str(""), slots, 3, output, capacity, result));
        REQUIRE(
            encode_array(op | kEncode, lit_str(""), nullptr, 0, output, sizeof(output), result));
        CHECK_EQ(result.len, 0u);
    }
    ArrayPlan plan{};
    CHECK_FALSE(plan_array(kRepeated | kPacked | (u64{1} << 8) | 9, lit_str(""), plan));
    CHECK_FALSE(plan_array(kRepeated | kPacked | (u64{1} << 8) | 12, lit_str(""), plan));
}

TEST(protobuf_array, native_message_layout_preserves_packed_numeric_hint) {
    u8 description[28];
    const u32 words[] = {16, 8, 1, 1, 5 | 256 | 512, 0, 0};
    for (u32 n = 0; n < 7; ++n)
        for (u32 i = 0; i < 4; ++i) description[n * 4 + i] = static_cast<u8>(words[n] >> (i * 8));
    const u8 input[] = {10, 4, 8, 1, 8, 0};
    const u8 expected[] = {10, 4, 10, 2, 1, 0};
    SlicePool pool;
    REQUIRE(pool.init(4));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    Str values{};
    REQUIRE(decode_struct_array(
        1, view(description, sizeof(description)), view(input, sizeof(input)), &arena, values));
    u8 output[32]{};
    Str encoded{};
    REQUIRE(encode_struct_array(1,
                                view(description, sizeof(description)),
                                lit_str(""),
                                values,
                                output,
                                sizeof(output),
                                encoded));
    CHECK(encoded.eq(view(expected, sizeof(expected))));
    // A packed hint is invalid for singular or length-delimited fields.
    description[16] = 9;
    struct_array_detail::Layout invalid{};
    CHECK_FALSE(struct_array_detail::layout(view(description, sizeof(description)), invalid));
    arena.destroy();
    pool.destroy();
}
