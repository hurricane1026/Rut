#include "rut/common/types.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/string_split.h"
#include "test.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

using namespace rut;

TEST(string_split, exact_fields_are_owned_and_preserve_empty_and_binary_values) {
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    char input[] = {'|', 'a', '\0', 'b', '|', '|'};
    auto* values = split_string(&arena, {input, sizeof(input)}, lit_str("|"));
    REQUIRE(values);
    REQUIRE_EQ(values->count, 4u);
    CHECK(static_cast<const Str*>(values->get(0, sizeof(Str)))->eq(lit_str("")));
    CHECK(static_cast<const Str*>(values->get(1, sizeof(Str)))->eq(lit_str("a\0b")));
    CHECK(static_cast<const Str*>(values->get(2, sizeof(Str)))->eq(lit_str("")));
    CHECK(static_cast<const Str*>(values->get(3, sizeof(Str)))->eq(lit_str("")));
    memset(input, 'z', sizeof(input));
    CHECK(static_cast<const Str*>(values->get(1, sizeof(Str)))->eq(lit_str("a\0b")));
    CHECK(!values->get(-1, sizeof(Str)));
    CHECK(!values->get(4, sizeof(Str)));
    arena.reset();
    values = split_string(&arena, {}, lit_str("::"));
    REQUIRE(values);
    CHECK_EQ(values->count, 1u);
    CHECK(static_cast<const Str*>(values->get(0, sizeof(Str)))->eq(lit_str("")));
    arena.reset();
    values = split_string(&arena, lit_str("a\0b\0"), lit_str("\0"));
    REQUIRE(values);
    CHECK_EQ(values->count, 3u);
    CHECK(static_cast<const Str*>(values->get(1, sizeof(Str)))->eq(lit_str("b")));
    arena.destroy();
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
}

TEST(string_split, matches_a_nonoverlapping_reference_on_repetitive_inputs) {
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u32 state = 173;
    const auto kNext = [&]() {
        state = state * 1664525u + 1013904223u;
        return state;
    };
    for (u32 sample = 0; sample < 2048; ++sample) {
        char text[80];
        char separator[16];
        const u32 kLength = kNext() % sizeof(text);
        const u32 kSeparatorLength = 1 + kNext() % sizeof(separator);
        for (u32 i = 0; i < kLength; ++i) text[i] = static_cast<char>('a' + kNext() % 3);
        for (u32 i = 0; i < kSeparatorLength; ++i)
            separator[i] = static_cast<char>('a' + kNext() % 3);
        FixedVec<Str, 81> expected;
        u32 start = 0;
        u32 offset = 0;
        while (offset <= kLength && kSeparatorLength <= kLength - offset) {
            if (memcmp(text + offset, separator, kSeparatorLength) != 0) {
                ++offset;
                continue;
            }
            REQUIRE(expected.push({text + start, offset - start}));
            offset += kSeparatorLength;
            start = offset;
        }
        REQUIRE(expected.push({text + start, kLength - start}));
        arena.reset();
        auto* values = split_string(&arena, {text, kLength}, {separator, kSeparatorLength});
        if (expected.len > 64) {
            CHECK(!values);
            continue;
        }
        REQUIRE(values);
        CHECK_EQ(values->count, expected.len);
        for (u32 i = 0; i < expected.len; ++i)
            CHECK(static_cast<const Str*>(values->get(i, sizeof(Str)))->eq(expected[i]));
    }
    arena.destroy();
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
}

TEST(string_split, rejects_bounds_before_allocating_and_exposes_no_partial_result) {
    SlicePool pool;
    REQUIRE(pool.init(40));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    char text[8193];
    memset(text, 'a', sizeof(text));
    auto* values = split_string(&arena, {text, 8192}, lit_str("|"));
    REQUIRE(values);
    CHECK_EQ(static_cast<const Str*>(values->get(0, sizeof(Str)))->len, 8192u);
    char delimiter[257];
    memset(delimiter, 'x', sizeof(delimiter));
    arena.reset();
    REQUIRE(split_string(&arena, lit_str("a"), {delimiter, 256}));
    arena.reset();
    CHECK(!split_string(&arena, {reinterpret_cast<const char*>(1), 8193}, lit_str("|")));
    CHECK(!split_string(&arena, lit_str("a"), {reinterpret_cast<const char*>(1), 257}));
    CHECK(!split_string(&arena, {nullptr, 1}, lit_str("|")));
    CHECK(!split_string(&arena, lit_str("a"), {}));
    CHECK(!split_string(&arena, lit_str("a"), {nullptr, 1}));
    CHECK_EQ(arena.space_used(), 0u);
    memset(text, '|', 64);
    REQUIRE(split_string(&arena, {text, 63}, lit_str("|")));
    arena.reset();
    CHECK(!split_string(&arena, {text, 64}, lit_str("|")));
    CHECK_EQ(arena.space_used(), 0u);
    CHECK(!split_string(nullptr, lit_str("a"), lit_str("|")));
    for (u32 i = 0; i < 32; ++i) REQUIRE(arena.alloc(8192));
    CHECK(!split_string(&arena, lit_str("a"), lit_str("|")));
    arena.destroy();
    u8* held[40]{};
    for (auto& item : held) {
        item = pool.alloc();
        REQUIRE(item);
    }
    CHECK(!split_string(&arena, lit_str("a"), lit_str("|")));
    for (auto* item : held) pool.free(item);
    arena.destroy();
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
    REQUIRE(pool.init(1));
    REQUIRE(arena.init(&pool));
    REQUIRE(arena.alloc(8192));
    memset(text, 'a', sizeof(text));
    CHECK(!split_string(&arena, {text, 8192}, lit_str("|")));
    arena.reset();
    REQUIRE(split_string(&arena, lit_str("ok"), lit_str("|")));
    arena.destroy();
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
}

TEST(string_split, bounded_spans_need_no_terminator_or_padding) {
    const auto kPage = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto* memory = static_cast<char*>(
        mmap(nullptr, kPage * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(memory != MAP_FAILED);
    REQUIRE_EQ(mprotect(memory + kPage, kPage, PROT_NONE), 0);
    REQUIRE_EQ(mprotect(memory + kPage * 3, kPage, PROT_NONE), 0);
    char* text = memory + kPage - 7;
    char* separator = memory + kPage * 3 - 2;
    // These spans deliberately end at protected pages without a terminator.
    // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
    memcpy(text, "ab::c::", 7);
    // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
    memcpy(separator, "::", 2);
    SlicePool pool;
    REQUIRE(pool.init(4));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    auto* values = split_string(&arena, {text, 7}, {separator, 2});
    REQUIRE(values);
    CHECK_EQ(values->count, 3u);
    CHECK(static_cast<const Str*>(values->get(2, sizeof(Str)))->eq(lit_str("")));
    arena.destroy();
    pool.destroy();
    REQUIRE_EQ(munmap(memory, kPage * 4), 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
