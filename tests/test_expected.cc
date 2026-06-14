/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#include "core/expected.h"
#include "test.h"

#include <stdint.h>

using core::Expected;
using core::make_unexpected;
using core::Unexpected;

// ── Error type ──────────────────────────────────────────────────────

enum class Err { BadInput, Overflow, NotFound, Timeout };

// ── Non-trivial type (tracks construction/destruction) ──────────────

static int g_ctor_count = 0;
static int g_dtor_count = 0;
static int g_copy_count = 0;
static int g_move_count = 0;

struct Tracked {
    int val;
    Tracked(int v) : val(v) { ++g_ctor_count; }
    Tracked(const Tracked& o) : val(o.val) { ++g_copy_count; }
    Tracked(Tracked&& o) : val(o.val) {
        o.val = -1;
        ++g_move_count;
    }
    ~Tracked() { ++g_dtor_count; }
};

static void reset_counters() {
    g_ctor_count = g_dtor_count = g_copy_count = g_move_count = 0;
}

// ── Non-trivial error type ──────────────────────────────────────────

struct ErrInfo {
    Err code;
    int detail;
    ErrInfo(Err c, int d) : code(c), detail(d) {}
};

// ── Test helper functions ───────────────────────────────────────────

static Expected<int, Err> parse(const char* s) {
    if (s == nullptr) return Unexpected(Err::BadInput);
    int len = 0;
    while (s[len]) ++len;
    return len;
}

static Expected<int, Err> checked_double(int v) {
    if (v > 1000) return Unexpected(Err::Overflow);
    return v * 2;
}

static Expected<int, Err> checked_add_ten(int v) {
    if (v > 2000) return Unexpected(Err::Overflow);
    return v + 10;
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

// ── 1. Basic construction and observers ─────────────────────────────

TEST(basic, value) {
    Expected<int, Err> r = 42;
    CHECK(r.has_value());
    CHECK(static_cast<bool>(r));
    CHECK_EQ(r.value(), 42);
    CHECK_EQ(*r, 42);
}

TEST(basic, error) {
    Expected<int, Err> r = Unexpected(Err::NotFound);
    CHECK(!r.has_value());
    CHECK(!static_cast<bool>(r));
    CHECK(r.error() == Err::NotFound);
}

// ── 2. Copy and move ────────────────────────────────────────────────

TEST(copy, value) {
    Expected<int, Err> a = 10;
    Expected<int, Err> b = a;
    CHECK(b.has_value());
    CHECK_EQ(b.value(), 10);
    CHECK_EQ(a.value(), 10);
}

TEST(copy, error) {
    Expected<int, Err> a = Unexpected(Err::Timeout);
    Expected<int, Err> b = a;
    CHECK(!b.has_value());
    CHECK(b.error() == Err::Timeout);
}

TEST(move, value) {
    reset_counters();
    {
        Expected<Tracked, Err> a = Tracked(7);
        Expected<Tracked, Err> b = static_cast<Expected<Tracked, Err>&&>(a);
        CHECK(b.has_value());
        CHECK_EQ(b.value().val, 7);
        CHECK_EQ(a.value().val, -1);
    }
    CHECK_GT(g_dtor_count, 0);
}

TEST(move, error) {
    Expected<int, ErrInfo> a = Unexpected(ErrInfo{Err::Overflow, 999});
    Expected<int, ErrInfo> b = static_cast<Expected<int, ErrInfo>&&>(a);
    CHECK(!b.has_value());
    CHECK(b.error().code == Err::Overflow);
    CHECK_EQ(b.error().detail, 999);
}

// ── 3. Assignment ───────────────────────────────────────────────────

TEST(assign, value_to_value) {
    Expected<int, Err> a = 10;
    Expected<int, Err> b = 20;
    a = b;
    CHECK_EQ(a.value(), 20);
}

TEST(assign, error_to_value) {
    Expected<int, Err> a = 10;
    Expected<int, Err> b = Unexpected(Err::NotFound);
    a = b;
    CHECK(!a.has_value());
    CHECK(a.error() == Err::NotFound);
}

TEST(assign, value_to_error) {
    Expected<int, Err> a = Unexpected(Err::BadInput);
    Expected<int, Err> b = 99;
    a = b;
    CHECK(a.has_value());
    CHECK_EQ(a.value(), 99);
}

TEST(assign, error_to_error) {
    Expected<int, Err> a = Unexpected(Err::BadInput);
    Expected<int, Err> b = Unexpected(Err::Timeout);
    a = b;
    CHECK(!a.has_value());
    CHECK(a.error() == Err::Timeout);
}

TEST(assign, self_assign) {
    Expected<int, Err> a = 42;
    a = a;
    CHECK(a.has_value());
    CHECK_EQ(a.value(), 42);
}

TEST(assign, move_assign) {
    Expected<int, Err> a = 10;
    Expected<int, Err> b = 20;
    a = static_cast<Expected<int, Err>&&>(b);
    CHECK_EQ(a.value(), 20);
}

// ── 4. value_or ─────────────────────────────────────────────────────

TEST(value_or, pass_through) {
    Expected<int, Err> v = 5;
    CHECK_EQ(v.value_or(42), 5);
}

TEST(value_or, fallback) {
    Expected<int, Err> e = Unexpected(Err::BadInput);
    CHECK_EQ(e.value_or(42), 42);
    CHECK_EQ(e.value_or(0), 0);
}

// ── 5. operator-> ───────────────────────────────────────────────────

struct Point {
    int x;
    int y;
};

TEST(arrow, access_and_mutate) {
    Expected<Point, Err> r = Point{3, 7};
    CHECK_EQ(r->x, 3);
    CHECK_EQ(r->y, 7);
    r->x = 99;
    CHECK_EQ(r->x, 99);
}

// ── 6. TRY macro ────────────────────────────────────────────────────

static Expected<int, Err> try_pipeline(const char* s) {
    auto len = TRY(parse(s));
    auto doubled = TRY(checked_double(len));
    return doubled + 1;
}

TEST(try_macro, success) {
    auto r = try_pipeline("hi");
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 5);  // len=2, *2=4, +1=5
}

TEST(try_macro, first_error) {
    auto r = try_pipeline(nullptr);
    CHECK(!r.has_value());
    CHECK(r.error() == Err::BadInput);
}

TEST(try_macro, second_error) {
    char big[1024];
    for (int i = 0; i < 1023; ++i) big[i] = 'x';
    big[1023] = '\0';
    auto r = try_pipeline(big);
    CHECK(!r.has_value());
    CHECK(r.error() == Err::Overflow);
}

static Expected<int, Err> try_three_step(const char* s) {
    auto a = TRY(parse(s));
    auto b = TRY(checked_double(a));
    auto c = TRY(checked_add_ten(b));
    return c;
}

TEST(try_macro, three_steps) {
    auto r = try_three_step("abc");  // len=3, *2=6, +10=16
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 16);
}

static Expected<int, ErrInfo> parse_detailed(const char* s) {
    if (s == nullptr) return Unexpected(ErrInfo{Err::BadInput, 42});
    int len = 0;
    while (s[len]) ++len;
    return len;
}

static Expected<int, ErrInfo> try_detailed(const char* s) {
    auto v = TRY(parse_detailed(s));
    return v * 3;
}

TEST(try_macro, non_trivial_error) {
    auto r = try_detailed(nullptr);
    CHECK(!r.has_value());
    CHECK(r.error().code == Err::BadInput);
    CHECK_EQ(r.error().detail, 42);
}

static Expected<void, Err> validate(int v) {
    if (v < 0) return Unexpected(Err::BadInput);
    if (v > 100) return Unexpected(Err::Overflow);
    return {};
}

static Expected<int, Err> try_with_void(int v) {
    TRY_VOID(validate(v));
    return v * 2;
}

TEST(try_macro, void_success) {
    auto r = try_with_void(10);
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 20);
}

TEST(try_macro, void_error) {
    auto r2 = try_with_void(-5);
    CHECK(!r2.has_value());
    CHECK(r2.error() == Err::BadInput);

    auto r3 = try_with_void(200);
    CHECK(!r3.has_value());
    CHECK(r3.error() == Err::Overflow);
}

// ── 7. Monadic: and_then ────────────────────────────────────────────

TEST(and_then, success) {
    auto r = parse("abc").and_then(checked_double);
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 6);
}

TEST(and_then, first_error) {
    auto r = parse(nullptr).and_then(checked_double);
    CHECK(!r.has_value());
    CHECK(r.error() == Err::BadInput);
}

TEST(and_then, second_error) {
    char big[1024];
    for (int i = 0; i < 1023; ++i) big[i] = 'x';
    big[1023] = '\0';
    auto r = parse(big).and_then(checked_double);
    CHECK(!r.has_value());
    CHECK(r.error() == Err::Overflow);
}

TEST(and_then, chain) {
    auto r = parse("ab").and_then(checked_double).and_then(checked_add_ten);
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 14);  // len=2, *2=4, +10=14
}

TEST(and_then, lambda) {
    auto r = parse("test").and_then([](int v) -> Expected<int, Err> {
        if (v == 0) return Unexpected(Err::BadInput);
        return v * v;
    });
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 16);
}

// ── 8. Monadic: transform ───────────────────────────────────────────

TEST(transform, success) {
    auto r = parse("hi").transform([](int v) { return v * 10; });
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 20);
}

TEST(transform, error_propagation) {
    auto r = parse(nullptr).transform([](int v) { return v * 10; });
    CHECK(!r.has_value());
    CHECK(r.error() == Err::BadInput);
}

TEST(transform, type_change) {
    auto r = parse("abc").transform([](int v) { return v > 2; });
    CHECK(r.has_value());
    CHECK(r.value() == true);
}

TEST(transform, chain) {
    auto r =
        parse("ab").transform([](int v) { return v + 100; }).transform([](int v) { return v * 2; });
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 204);  // (2+100)*2
}

// ── 9. Monadic: or_else ─────────────────────────────────────────────

TEST(or_else, pass_through) {
    auto r = parse("ok").or_else([](Err) -> Expected<int, Err> { return 0; });
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 2);
}

TEST(or_else, recover) {
    auto r = parse(nullptr).or_else([](Err) -> Expected<int, Err> { return 0; });
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 0);
}

TEST(or_else, remap_error) {
    auto r = parse(nullptr).or_else([](Err e) -> Expected<int, Err> {
        if (e == Err::BadInput) return Unexpected(Err::NotFound);
        return Unexpected(e);
    });
    CHECK(!r.has_value());
    CHECK(r.error() == Err::NotFound);
}

// ── 10. Mixed monadic chains ────────────────────────────────────────

TEST(mixed, chain_success) {
    auto r = parse("hi")
                 .and_then(checked_double)                // 2 -> 4
                 .transform([](int v) { return v + 1; })  // 4 -> 5
                 .and_then(checked_add_ten);              // 5 -> 15
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 15);
}

TEST(mixed, chain_error_midway) {
    char big[1024];
    for (int i = 0; i < 1023; ++i) big[i] = 'x';
    big[1023] = '\0';
    auto r = parse(big)
                 .and_then(checked_double)                // 1023 > 1000, error
                 .transform([](int v) { return v + 1; })  // skipped
                 .and_then(checked_add_ten);              // skipped
    CHECK(!r.has_value());
    CHECK(r.error() == Err::Overflow);
}

// ── 11. Expected<void, E> ───────────────────────────────────────────

TEST(void_expected, success) {
    Expected<void, Err> r = {};
    CHECK(r.has_value());
}

TEST(void_expected, error) {
    Expected<void, Err> r = Unexpected(Err::Timeout);
    CHECK(!r.has_value());
    CHECK(r.error() == Err::Timeout);
}

TEST(void_expected, copy) {
    Expected<void, Err> a = {};
    Expected<void, Err> b = a;
    CHECK(b.has_value());

    Expected<void, Err> c = Unexpected(Err::BadInput);
    Expected<void, Err> d = c;
    CHECK(!d.has_value());
    CHECK(d.error() == Err::BadInput);
}

TEST(void_expected, move) {
    Expected<void, ErrInfo> a = Unexpected(ErrInfo{Err::Overflow, 7});
    Expected<void, ErrInfo> b = static_cast<Expected<void, ErrInfo>&&>(a);
    CHECK(!b.has_value());
    CHECK_EQ(b.error().detail, 7);
}

TEST(void_expected, assign) {
    Expected<void, Err> a = {};
    Expected<void, Err> b = Unexpected(Err::NotFound);
    a = b;
    CHECK(!a.has_value());
    CHECK(a.error() == Err::NotFound);

    Expected<void, Err> c = {};
    a = c;
    CHECK(a.has_value());
}

// ── 12. Non-trivial types: construction/destruction tracking ────────

TEST(lifecycle, tracked_value) {
    reset_counters();
    {
        Expected<Tracked, Err> r = Tracked(42);
        CHECK(r.has_value());
        CHECK_EQ(r.value().val, 42);
    }
    CHECK_EQ(g_ctor_count, 1);
    CHECK_EQ(g_move_count, 1);
    CHECK_EQ(g_dtor_count, 2);
}

TEST(lifecycle, tracked_error_no_value_dtor) {
    reset_counters();
    {
        Expected<Tracked, Err> r = Unexpected(Err::BadInput);
        CHECK(!r.has_value());
    }
    CHECK_EQ(g_ctor_count, 0);
    CHECK_EQ(g_dtor_count, 0);
}

TEST(lifecycle, tracked_copy) {
    reset_counters();
    {
        Expected<Tracked, Err> a = Tracked(10);
        Expected<Tracked, Err> b = a;
        CHECK_EQ(b.value().val, 10);
    }
    CHECK_EQ(g_copy_count, 1);
}

// ── 13. Different T and E sizes / alignments ────────────────────────

struct Big {
    char data[128];
    int tag;
};
struct Small {
    char c;
};

TEST(size, mismatch) {
    Expected<Big, Small> r1 = Big{{}, 99};
    CHECK(r1.has_value());
    CHECK_EQ(r1->tag, 99);

    Expected<Small, Big> r2 = Unexpected(Big{{}, 77});
    CHECK(!r2.has_value());
    CHECK_EQ(r2.error().tag, 77);
}

struct Aligned {
    alignas(64) int v;
};

TEST(size, alignment) {
    Expected<Aligned, Err> r = Aligned{42};
    CHECK(r.has_value());
    CHECK_EQ(r.value().v, 42);
    auto addr = reinterpret_cast<uintptr_t>(&r.value().v);
    CHECK_EQ(addr % 64, 0u);
}

// ── 14. make_unexpected ─────────────────────────────────────────────

TEST(make_unexpected, rvalue) {
    auto u = make_unexpected(Err::Timeout);
    Expected<int, Err> r = u;
    CHECK(!r.has_value());
    CHECK(r.error() == Err::Timeout);
}

TEST(make_unexpected, lvalue) {
    Err e = Err::NotFound;
    auto u = make_unexpected(e);
    Expected<int, Err> r = u;
    CHECK(r.error() == Err::NotFound);
}

// ── 15. Const correctness ───────────────────────────────────────────

TEST(const_access, value_and_error) {
    const Expected<int, Err> v = 42;
    CHECK(v.has_value());
    CHECK_EQ(v.value(), 42);
    CHECK_EQ(*v, 42);
    CHECK_EQ(v.value_or(0), 42);

    const Expected<int, Err> e = Unexpected(Err::BadInput);
    CHECK(!e.has_value());
    CHECK(e.error() == Err::BadInput);
}

TEST(const_access, monadic) {
    const Expected<int, Err> v = 5;
    auto r = v.and_then(checked_double);
    CHECK_EQ(r.value(), 10);

    auto r2 = v.transform([](int x) { return x + 1; });
    CHECK_EQ(r2.value(), 6);

    const Expected<int, Err> e = Unexpected(Err::BadInput);
    auto r3 = e.or_else([](Err) -> Expected<int, Err> { return 0; });
    CHECK_EQ(r3.value(), 0);
}

// ── 16. Default constructor ──────────────────────────────────────────

TEST(default_ctor, int) {
    Expected<int, Err> r;
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 0);
}

TEST(default_ctor, point) {
    Expected<Point, Err> p;
    CHECK(p.has_value());
}

// ── 17. TRY on same line (__COUNTER__ uniqueness) ───────────────────

static Expected<int, Err> try_same_line(const char* a, const char* b) {
    return TRY(parse(a)) + TRY(parse(b));
}

TEST(try_macro, same_line_success) {
    auto r = try_same_line("ab", "cd");
    CHECK(r.has_value());
    CHECK_EQ(r.value(), 4);  // 2 + 2
}

TEST(try_macro, same_line_first_error) {
    auto r = try_same_line(nullptr, "cd");
    CHECK(!r.has_value());
}

TEST(try_macro, same_line_second_error) {
    auto r = try_same_line("ab", nullptr);
    CHECK(!r.has_value());
}

// ── 18. const Expected through TRY (RemoveCvRef) ────────────────────

static Expected<int, Err> try_from_const() {
    const Expected<int, Err> ce = Unexpected(Err::NotFound);
    if (!ce) return ::core::make_unexpected(ce.error());
    return ce.value();
}

TEST(try_macro, const_expected) {
    auto r = try_from_const();
    CHECK(!r.has_value());
    CHECK(r.error() == Err::NotFound);
}

// ═══════════════════════════════════════════════════════════════════

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
