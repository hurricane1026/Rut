#include "rut/common/integer_conversion.h"
#include "rut/common/range_int.h"

using namespace rut;

static_assert(static_cast<i64>(u64{INT64_MAX}) == INT64_MAX);
// expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
static_assert(static_cast<i64>(u64{UINT64_MAX}) == -1);

i64 explicit_conversion(u64 value) {
    // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
    return static_cast<i64>(value);
}

i64 implicit_conversion(u64 value) {
    return value;  // expected-warning {{u64 to i64 conversion requires a range proof}}
}

template <typename T>
i64 generic_conversion(T value) {
    return value;  // expected-warning {{u64 to i64 conversion requires a range proof}}
}

i64 use_generic_conversion(u64 value) {
    return generic_conversion(value);
}

void consume(i64);

void bounded_for(u32 limit) {
    for (u64 i = 0; i < limit; ++i) consume(static_cast<i64>(i));
}

void bounded_while(u64 i) {
    while (i < (u64{1} << 63)) {
        consume(i);
        ++i;
    }
}

i64 checked_before_use(u64 value) {
    if (value > u64{INT64_MAX}) return 0;
    return value;
}

void unknown_limit(u64 limit) {
    for (u64 i = 0; i < limit; ++i) {
        // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
        consume(i);
    }
}

void write_in_loop(u64 i, bool overwrite) {
    while (i < u64{INT64_MAX}) {
        if (overwrite) {
            i = UINT64_MAX;
        }
        // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
        consume(i);
        ++i;
    }
}

void exit_from_loop(u64 i) {
    while (i <= u64{INT64_MAX}) ++i;
    // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
    consume(i);
}

void alias_write(u64 i) {
    u64& alias = i;
    while (i < 10) {
        alias = UINT64_MAX;
        // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
        consume(i);
    }
}

void alternate_branch(u64 i, bool skip_bound) {
    if (skip_bound || i < 10) {
        // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
        consume(i);
    }
}

void signed_limit(u64 i, i32 limit) {
    if (i < static_cast<u64>(limit)) {
        // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
        consume(i);
    }
}

template <typename Left, typename Right>
concept CanAdd = requires(Left left, Right right) { left + right; };

template <typename Left, typename Right>
concept CanSubtract = requires(Left left, Right right) { left - right; };

using Count = range_int<0, 101>;
using Step = range_int<1, 4>;
static_assert(sizeof(Count) == sizeof(i64));
static_assert(__is_same(decltype(Count{} + Step{}), range_int<1, 104>));
static_assert(__is_same(decltype(Count{} - Step{}), range_int<-3, 100>));
static_assert((Count::constant<99>() + Step::constant<3>()).value() == 102);
static_assert((Count::constant<0>() - Step::constant<3>()).value() == -3);
static_assert(!CanAdd<range_int<0>, Step>);
static_assert(!CanAdd<range_int<INT64_MIN, 1>, range_int<-1, 1>>);
static_assert(!CanSubtract<range_int<INT64_MIN, 1>, Step>);
static_assert(!CanSubtract<range_int<0>, range_int<-1, 1>>);
static_assert(range_int(u32{UINT32_MAX}).value() == UINT32_MAX);
static_assert([] {
    Count count;
    return Count::try_from_u64(100, &count) && !Count::try_from_u64(UINT64_MAX, &count) &&
           !Count::try_from_i64(-1, &count) && !Count::try_from_i64(101, &count) &&
           count.value() == 100;
}());

static_assert([] {
    i64 out = -1;
    return try_u64_to_i64(0, &out) && out == 0 && try_u64_to_i64(u64{INT64_MAX}, &out) &&
           out == INT64_MAX && !try_u64_to_i64(u64{INT64_MAX} + 1, &out) && out == INT64_MAX &&
           !try_u64_to_i64(UINT64_MAX, &out) && out == INT64_MAX;
}());
