#include "rut/runtime/regex_capture.h"
#include "rut/runtime/slice_pool.h"
#include "test.h"

using namespace rut;
namespace {
struct Program {
    void* value;
    explicit Program(Str pattern) : value(capture_regex_compile(pattern)) {}
    ~Program() { capture_regex_destroy(value); }
};
struct MatchArena {
    SlicePool pool;
    SliceArena arena;
    bool init(u32 slices = 16) { return pool.init(slices) && arena.init(&pool); }
    ~MatchArena() {
        arena.destroy();
        pool.destroy();
    }
};
}  // namespace

TEST(regex_capture, first_match_greedy_alternation_and_named_group_ordinals) {
    Program program({"(?<name>a+)(b|c)?", 17});
    REQUIRE(program.value);
    CHECK_EQ(capture_regex_group_count(program.value), 2u);
    MatchArena memory;
    REQUIRE(memory.init());
    Str output;
    CHECK_EQ(capture_regex_match(program.value, memory.arena, {"xx aaac yy", 10}, 0, &output), 1);
    CHECK(output.eq({"aaac", 4}));
    CHECK_EQ(capture_regex_match(program.value, memory.arena, {"xx aaac yy", 10}, 1, &output), 1);
    CHECK(output.eq({"aaa", 3}));
    CHECK_EQ(capture_regex_match(program.value, memory.arena, {"xx aaac yy", 10}, 2, &output), 1);
    CHECK(output.eq({"c", 1}));
    Program greedy({"^(.*)(a)$", 9});
    REQUIRE(greedy.value);
    CHECK_EQ(capture_regex_match(greedy.value, memory.arena, {"abaa", 4}, 1, &output), 1);
    CHECK(output.eq({"aba", 3}));
}

TEST(regex_capture, missing_optional_and_empty_participation_are_distinct) {
    Program optional({"^a(b)?$", 7});
    Program empty({"^a(b*)$", 7});
    REQUIRE(optional.value && empty.value);
    MatchArena memory;
    REQUIRE(memory.init());
    Str output;
    CHECK_EQ(capture_regex_match(optional.value, memory.arena, {"a", 1}, 1, &output), 0);
    CHECK(output.ptr == nullptr);
    CHECK_EQ(capture_regex_match(empty.value, memory.arena, {"a", 1}, 1, &output), 1);
    CHECK_EQ(output.len, 0u);
    CHECK(output.ptr != nullptr);
    CHECK_EQ(capture_regex_match(empty.value, memory.arena, {"z", 1}, 1, &output), 0);
}

TEST(regex_capture, input_pattern_group_and_connection_bounds_fail_closed) {
    CHECK(capture_regex_compile({"(", 1}) == nullptr);
    CHECK(capture_regex_compile({"()()()()()()()()()", 18}) == nullptr);
    Program program({"(a)", 3});
    REQUIRE(program.value);
    MatchArena memory;
    REQUIRE(memory.init(1));
    Str output;
    char large[8193]{};
    CHECK_EQ(capture_regex_match(program.value, memory.arena, {large, sizeof(large)}, 1, &output),
             2);
    CHECK_EQ(capture_regex_match(program.value, memory.arena, {"a", 1}, 2, &output), 2);
    REQUIRE(memory.arena.alloc(memory.arena.current->remaining()) != nullptr);
    // RE2 does not use the request Arena for its internal scratch allocations.
    CHECK_EQ(capture_regex_match(program.value, memory.arena, {"a", 1}, 1, &output), 1);
    CHECK(output.eq({"a", 1}));
    memory.arena.backend.pool = nullptr;
    CHECK_EQ(capture_regex_match(program.value, memory.arena, {"a", 1}, 1, &output), 2);
    memory.arena.backend.pool = &memory.pool;
    CHECK(output.ptr == nullptr);
    memory.arena.destroy();
    CHECK_EQ(memory.pool.count - memory.pool.available(), 0u);
}

TEST(regex_capture, re2_rejects_backreferences_and_lookaround_at_compile_time) {
    CHECK(capture_regex_compile({"(a)\\1", 5}) == nullptr);
    CHECK(capture_regex_compile({"a(?=b)", 6}) == nullptr);
    CHECK(capture_regex_compile({"a(?!b)", 6}) == nullptr);
}

TEST(regex_capture, ambiguous_failure_is_an_ordinary_nonmatch) {
    Program program({"^(a+)+$", 7});
    REQUIRE(program.value);
    MatchArena memory;
    REQUIRE(memory.init());
    char subject[129];
    __builtin_memset(subject, 'a', sizeof(subject));
    subject[128] = '!';
    Str output;
    CHECK_EQ(
        capture_regex_match(program.value, memory.arena, {subject, sizeof(subject)}, 1, &output),
        0);
    CHECK(output.ptr == nullptr);
    CHECK_EQ(memory.arena.space_used(), 0u);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
