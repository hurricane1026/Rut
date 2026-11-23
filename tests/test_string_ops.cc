#include "rut/runtime/slice_pool.h"
#include "rut/runtime/string_ops.h"
#include "test.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
using namespace rut;

TEST(string_ops, trim_is_an_exact_borrowed_ascii_view) {
    const Str values[] = {lit_str(""),
                          lit_str(" \t\n\r\v\f"),
                          lit_str(" a b "),
                          lit_str("\t\0\xff \r"),
                          lit_str("\xc2\xa0 hi \xc2\xa0")};
    const Str expected[] = {lit_str(""),
                            lit_str(""),
                            lit_str("a b"),
                            lit_str("\0\xff"),
                            lit_str("\xc2\xa0 hi \xc2\xa0")};
    for (u32 i = 0; i < 5; ++i) {
        const auto result = trim_ascii_string(values[i]);
        CHECK(result.eq(expected[i]));
        CHECK(result.ptr >= values[i].ptr);
        CHECK(result.ptr + result.len <= values[i].ptr + values[i].len);
    }
    CHECK(trim_ascii_string({}).ptr == nullptr);
    const u32 page = static_cast<u32>(sysconf(_SC_PAGESIZE));
    void* raw = mmap(nullptr, page * 3, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(raw != MAP_FAILED);
    auto* data = static_cast<char*>(raw) + page;
    REQUIRE_EQ(mprotect(data, page, PROT_READ | PROT_WRITE), 0);
    const u32 positions[] = {0u, page - 4};
    for (u32 end : positions) {
        memcpy(data + end, " x \t", 4);
        CHECK(trim_ascii_string({data + end, 4}).eq(lit_str("x")));
    }
    CHECK_EQ(trim_ascii_string({data + page, 0}).len, 0u);
    CHECK_EQ(munmap(raw, page * 3), 0);
}

TEST(string_ops, all_bytes_case_conversion_and_owned_lifetime) {
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    char input[256];
    for (u32 i = 0; i < 256; ++i) input[i] = static_cast<char>(i);
    Str upper, lower;
    REQUIRE(transform_string(&arena, {input, 256}, {}, {}, 0, &upper));
    REQUIRE(transform_string(&arena, {input, 256}, {}, {}, 1, &lower));
    memset(input, 0, sizeof(input));
    for (u32 i = 0; i < 256; ++i) {
        CHECK_EQ(static_cast<u8>(upper.ptr[i]), i >= 'a' && i <= 'z' ? i - 32 : i);
        CHECK_EQ(static_cast<u8>(lower.ptr[i]), i >= 'A' && i <= 'Z' ? i + 32 : i);
    }
    Str empty;
    REQUIRE(transform_string(&arena, {}, {}, {}, 0, &empty));
    CHECK(empty.ptr != nullptr);
    CHECK_EQ(empty.len, 0u);
    arena.destroy();
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
}

TEST(string_ops, literal_replacement_matches_independent_nonoverlapping_reference) {
    SlicePool pool;
    REQUIRE(pool.init(8));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    u32 state = 791;
    const auto next = [&]() {
        state = state * 1664525u + 1013904223u;
        return state;
    };
    for (u32 sample = 0; sample < 4096; ++sample) {
        char text[96], old[12], replacement[12], expected[1200];
        const u32 size = next() % sizeof(text);
        const u32 old_size = 1 + next() % sizeof(old);
        const u32 new_size = next() % sizeof(replacement);
        for (u32 i = 0; i < size; ++i) text[i] = static_cast<char>(next() % 4);
        for (u32 i = 0; i < old_size; ++i) old[i] = static_cast<char>(next() % 4);
        for (u32 i = 0; i < new_size; ++i) replacement[i] = static_cast<char>(next() % 4);
        u32 written = 0;
        for (u32 i = 0; i < size;) {
            if (old_size <= size - i && memcmp(text + i, old, old_size) == 0) {
                memcpy(expected + written, replacement, new_size);
                written += new_size;
                i += old_size;
            } else
                expected[written++] = text[i++];
        }
        Str output;
        REQUIRE(transform_string(
            &arena, {text, size}, {old, old_size}, {replacement, new_size}, 2, &output));
        CHECK(output.eq({expected, written}));
        memset(text, 'z', sizeof(text));
        CHECK(output.eq({expected, written}));
        arena.reset();
    }
    Str output;
    REQUIRE(transform_string(&arena, lit_str("aaaaa"), lit_str("aa"), lit_str("X"), 2, &output));
    CHECK(output.eq(lit_str("XXa")));
    REQUIRE(transform_string(&arena, lit_str("a\0b\0"), lit_str("\0"), {}, 2, &output));
    CHECK(output.eq(lit_str("ab")));
    arena.destroy();
    pool.destroy();
}

TEST(string_ops, rejects_invalid_inputs_limits_and_storage_without_partial_output) {
    SlicePool pool;
    REQUIRE(pool.init(2));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    char bytes[8193];
    memset(bytes, 'a', sizeof(bytes));
    Str output = lit_str("sentinel");
    const auto failure = [&](SliceArena* memory, Str text, Str needle, Str replacement, u32 mode) {
        CHECK_FALSE(transform_string(memory, text, needle, replacement, mode, &output));
        CHECK(output.ptr == nullptr);
        CHECK_EQ(output.len, 0u);
    };
    failure(nullptr, lit_str("x"), {}, {}, 0);
    failure(&arena, {bytes, 8193}, {}, {}, 0);
    failure(&arena, {nullptr, 1}, {}, {}, 0);
    failure(&arena, lit_str("a"), {}, {}, 2);
    failure(&arena, lit_str("a"), {bytes, 257}, {}, 2);
    failure(&arena, lit_str("a"), lit_str("a"), {nullptr, 1}, 2);
    failure(&arena, lit_str("a"), lit_str("a"), {bytes, 8193}, 2);
    failure(&arena, {bytes, 8192}, lit_str("a"), lit_str("xxx"), 2);
    failure(&arena, lit_str("a"), {}, {}, 3);
    CHECK_EQ(arena.space_used(), 0u);
    REQUIRE(transform_string(&arena, {bytes, 8192}, {}, {}, 0, &output));
    CHECK_EQ(output.len, 8192u);
    for (u32 i = 0; i < output.len; ++i) CHECK_EQ(output.ptr[i], 'A');
    while (arena.alloc(8192)) {
    }
    failure(&arena, {bytes, 8192}, {}, {}, 0);
    arena.destroy();
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
}

TEST(string_ops, lazy_request_arena_initialization_and_budget_are_bounded) {
    SlicePool pool;
    REQUIRE(pool.init(40));
    SliceArena arena;
    arena.backend.pool = &pool;
    Str output;
    REQUIRE(transform_string(&arena, lit_str("a"), {}, {}, 0, &output));
    CHECK(output.eq(lit_str("A")));
    arena.reset();
    char bytes[8192];
    memset(bytes, 'a', sizeof(bytes));
    while (arena.space_used() <= kStringArenaBudget - sizeof(bytes))
        REQUIRE(arena.alloc(sizeof(bytes)));
    const auto before = arena.space_used();
    CHECK_FALSE(transform_string(&arena, {bytes, sizeof(bytes)}, {}, {}, 0, &output));
    CHECK(output.ptr == nullptr);
    CHECK_EQ(arena.space_used(), before);
    arena.destroy();
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
