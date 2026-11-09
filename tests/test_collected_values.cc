#include "rut/runtime/bytes_concat.h"
#include "rut/runtime/collected_values.h"
#include "test.h"

#include <sys/mman.h>
#include <unistd.h>

using namespace rut;

TEST(collected_values, nested_views_are_owned_before_guarded_input_is_released) {
    struct Inner {
        i32 code;
        Str bytes;
    };
    struct Record {
        bool present;
        Inner inner;
    };
    const auto page = static_cast<u32>(sysconf(_SC_PAGESIZE));
    auto* memory = static_cast<char*>(
        mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(memory != MAP_FAILED);
    REQUIRE_EQ(mprotect(memory + page, page, PROT_NONE), 0);
    char* text = memory + page - 3;
    text[0] = 'a';
    text[1] = '\0';
    text[2] = static_cast<char>(0xff);
    SlicePool pool;
    REQUIRE(pool.init(4));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    const u32 offsets[] = {__builtin_offsetof(Record, inner) + __builtin_offsetof(Inner, bytes)};
    auto* values = CollectedValues::create(&arena, sizeof(Record), 2, offsets, 1);
    REQUIRE(values);
    const Record record{true, {42, {text, 3}}};
    REQUIRE(values->append(&record, sizeof(record)));
    REQUIRE_EQ(mprotect(memory, page, PROT_NONE), 0);
    const auto* copied = static_cast<const Record*>(values->get(0, sizeof(record)));
    REQUIRE(copied);
    CHECK(copied->present);
    CHECK_EQ(copied->inner.code, 42);
    CHECK(copied->inner.bytes.eq({"a\0\xff", 3}));
    CHECK(copied->inner.bytes.ptr != text);
    CHECK(values->get(-2147483647 - 1, sizeof(record)) == nullptr);
    CHECK(values->get(2147483647, sizeof(record)) == nullptr);
    arena.destroy();
    pool.destroy();
    CHECK_EQ(munmap(memory, page * 2), 0);
}

TEST(collected_values, exhausted_pool_never_exposes_a_partly_copied_record) {
    SlicePool pool;
    REQUIRE(pool.init(1));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    const u32 offsets[] = {0};
    auto* values = CollectedValues::create(&arena, sizeof(Str), 2, offsets, 1);
    REQUIRE(values);
    char text[8192]{};
    text[0] = 'x';
    const Str value{text, sizeof(text)};
    REQUIRE(values->append(&value, sizeof(value)));
    CHECK_FALSE(values->append(&value, sizeof(value)));
    CHECK_EQ(values->count, 1u);
    CHECK(values->get(1, sizeof(value)) == nullptr);
    const auto* first = static_cast<const Str*>(values->get(0, sizeof(value)));
    REQUIRE(first);
    CHECK_EQ(first->len, sizeof(text));
    CHECK_EQ(first->ptr[0], 'x');
    arena.destroy();
    pool.destroy();
}

TEST(bytes_concat, guarded_binary_views_are_copied_and_limits_fail_closed) {
    const auto page = static_cast<u32>(sysconf(_SC_PAGESIZE));
    auto* memory = static_cast<char*>(
        mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(memory != MAP_FAILED);
    REQUIRE_EQ(mprotect(memory + page, page, PROT_NONE), 0);
    char* tail = memory + page - 2;
    tail[0] = '\0';
    tail[1] = static_cast<char>(0xff);
    SlicePool pool;
    REQUIRE(pool.init(2));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    const char* first = concat_bytes(&arena, {"a", 1}, {tail, 2}, 3);
    REQUIRE(first);
    REQUIRE_EQ(mprotect(memory, page, PROT_NONE), 0);
    CHECK((Str{first, 3}.eq({"a\0\xff", 3})));
    const char* second = concat_bytes(&arena, {first, 3}, {first, 3}, 6);
    REQUIRE(second);
    CHECK(
        (Str{second, 6}.eq({"a\0\xff"
                            "a\0\xff",
                            6})));
    CHECK(first != second);
    CHECK(concat_bytes(&arena, {first, 3}, {first, 3}, 5) == nullptr);
    CHECK(concat_bytes(&arena, {nullptr, 1}, {}, 8192) == nullptr);
    CHECK(concat_bytes(&arena, {}, {}, 0) == nullptr);
    CHECK(concat_bytes(&arena, {}, {}, 8193) == nullptr);
    CHECK(concat_bytes(&arena, {}, {}, 8192) != nullptr);
    char maximum[8192]{};
    CHECK(concat_bytes(&arena, {maximum, sizeof(maximum)}, {}, 8192) != nullptr);
    CHECK(concat_bytes(&arena, {maximum, sizeof(maximum)}, {"x", 1}, 8192) == nullptr);
    arena.destroy();
    pool.destroy();
    CHECK_EQ(munmap(memory, page * 2), 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
