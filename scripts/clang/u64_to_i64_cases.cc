#include "rut/common/integer_conversion.h"
#include "rut/common/range_int.h"

#include <limits.h>

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

template <u64 Value>
i64 cast_template_value() {
    // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
    return static_cast<i64>(Value);
}

void use_template_value() {
    (void)cast_template_value<u64{INT64_MAX}>();
    (void)cast_template_value<UINT64_MAX>();
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

template <u64 Max>
i64 checked_template_bound(u64 value) {
    if (value > Max) return 0;
    // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
    return value;
}

void use_checked_template_bound(u64 value) {
    consume(checked_template_bound<INT64_MAX>(value));
    consume(checked_template_bound<UINT64_MAX>(value));
}

static_assert([] {
    i64 value = 0;
    return try_u64_to_i64<7>(7, &value) && value == 7 && !try_u64_to_i64<7>(8, &value) &&
           value == 7;
}());

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

i64 bounded_remainder(u64 value) {
    return value % (u64{1} << 63);
}

i64 oversized_remainder(u64 value) {
    // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
    return value % ((u64{1} << 63) + 1);
}

i64 unknown_remainder(u64 value, u64 divisor) {
    // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
    return value % divisor;
}

i64 bounded_division(u64 value) {
    return value / 2;
}

i64 unbounded_division(u64 value) {
    // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
    return value / 1;
}

i64 unknown_division(u64 value, u64 divisor) {
    // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
    return value / divisor;
}

template <typename Left, typename Right>
concept CanAdd = requires(Left left, Right right) { left + right; };

template <typename Left, typename Right>
concept CanSubtract = requires(Left left, Right right) { left - right; };

template <typename T>
concept CanDeduceRange = requires(T value) { range_int(value); };

template <typename Range, typename T>
concept CanMakeRange = requires(T value) { Range(value); };

template <typename Range, i64 Factor>
concept CanScale = requires(Range value) { value.template scaled_by<Factor>(); };

template <typename Range, size_t Size>
concept CanIndex = requires(Range index, char (&table)[Size]) { index.at(table); };

template <typename Range>
concept CanConvertToU64 = requires(Range value) { value.to_u64(); };

template <u64 Divisor>
concept HasBoundedRemainder = requires(u64 value) { bounded_remainder<Divisor>(value); };

template <u64 Divisor>
concept HasBoundedQuotient = requires(u64 value) { bounded_quotient<Divisor>(value); };

static_assert(!HasBoundedQuotient<0>);
static_assert(!HasBoundedQuotient<1>);
static_assert(__is_same(decltype(bounded_quotient<2>(UINT64_MAX)), range_int<0>));
static_assert(bounded_quotient<2>(UINT64_MAX).value() == INT64_MAX);
static_assert([] {
    i32 narrow = -1;
    i64 wide = -1;
    const auto quotient = bounded_quotient<1'000'000>(UINT64_MAX);
    if (quotient.try_to_signed(&narrow) || narrow != -1) return false;
    return quotient.try_to_signed(&wide) && wide == UINT64_MAX / 1'000'000 &&
           bounded_quotient<1'000'000>(1'000'000).try_to_signed(&narrow) && narrow == 1;
}());

static_assert([] {
    i32 output = 0;
    return range_int(i64{INT32_MIN}).try_to_signed(&output) && output == INT32_MIN &&
           !range_int(i64{INT32_MIN} - 1).try_to_signed(&output) && output == INT32_MIN &&
           range_int(i64{INT32_MAX}).try_to_signed(&output) && output == INT32_MAX &&
           !range_int(i64{INT32_MAX} + 1).try_to_signed(&output) && output == INT32_MAX;
}());

template <typename Range, i64 Value>
concept HasRangeConstant = requires { Range::template constant<Value>(); };

using DecimalDigit = decltype(bounded_remainder<10>(0));
static_assert(__is_same(DecimalDigit, range_int<0, 10>));
static_assert(__is_same(decltype(bounded_remainder<1>(0)), range_int<0, 1>));
static_assert(bounded_remainder<10>(UINT64_MAX).value() == 5);
static_assert(bounded_remainder<(u64{1} << 63)>(UINT64_MAX).value() == INT64_MAX);
static_assert(!HasBoundedRemainder<0>);
static_assert(!HasBoundedRemainder<(u64{1} << 63) + 1>);
static_assert(CanIndex<DecimalDigit, 10>);
static_assert(!CanIndex<DecimalDigit, 9>);
static_assert(!CanIndex<range_int<-1, 10>, 10>);
static_assert(HasRangeConstant<DecimalDigit, 0>);
static_assert(HasRangeConstant<DecimalDigit, 9>);
static_assert(!HasRangeConstant<DecimalDigit, 10>);

static_assert(__is_same(decltype(range_int(i8{})), range_int<INT8_MIN, INT8_MAX + 1>));
static_assert(__is_same(decltype(range_int(u8{})), range_int<0, UINT8_MAX + 1>));
static_assert(__is_same(decltype(range_int(i16{})), range_int<INT16_MIN, INT16_MAX + 1>));
static_assert(__is_same(decltype(range_int(i32{})), range_int<INT32_MIN, i64{INT32_MAX} + 1>));
static_assert(__is_same(decltype(range_int(i64{})), range_int<INT64_MIN>));
static_assert(range_int(i32{INT32_MIN}).value() == INT32_MIN);
static_assert(range_int(i64{INT64_MAX}).value() == INT64_MAX);
static_assert(!CanDeduceRange<u64>);
static_assert(!CanDeduceRange<double>);
static_assert(!CanDeduceRange<bool>);
static_assert(!CanMakeRange<range_int<0>, i32>);

using HeaderIndex = decltype(range_int(u16{}));
using LowFields = decltype(range_int(u32{}));
static_assert(__is_same(HeaderIndex, range_int<0, u64{1} << 16>));
static_assert(__is_same(LowFields, range_int<0, u64{1} << 32>));
static_assert(CanMakeRange<HeaderIndex, u16>);
static_assert(!CanMakeRange<HeaderIndex, u32>);
static_assert(!CanMakeRange<range_int<0, 9>, u16>);
static_assert(CanMakeRange<LowFields, u16>);
static_assert(CanMakeRange<LowFields, u32>);
static_assert(!CanMakeRange<LowFields, u64>);
static_assert(__is_same(decltype(range_int(i32{}) + range_int(u32{})),
                        range_int<INT32_MIN, i64{INT32_MAX} + UINT32_MAX + 1>));
static_assert(!CanScale<HeaderIndex, u64{1} << 48>);
static_assert(!CanScale<range_int<INT64_MIN, 1>, 2>);
static_assert((HeaderIndex::constant<UINT16_MAX>() +
               HeaderIndex::constant<UINT16_MAX>().scaled_by<(u64{1} << 16)>() +
               HeaderIndex::constant<UINT16_MAX>().scaled_by<(u64{1} << 32)>())
                  .value() == 0x0000ffffffffffffLL);
using StatusImmediate = range_int<0, u64{1} << 48>;
static_assert(__is_convertible(decltype(HeaderIndex{}.scaled_by<(u64{1} << 32)>()),
                               StatusImmediate));
static_assert(!__is_convertible(decltype(HeaderIndex{}.scaled_by<(u64{1} << 33)>()),
                                StatusImmediate));
static_assert(range_int<0, 65>::count_leading_zeros(0).value() == 64);
static_assert(range_int<0, 65>::count_leading_zeros(1).value() == 63);
static_assert(range_int<0, 65>::count_leading_zeros(UINT64_MAX).value() == 0);
static_assert(CanConvertToU64<range_int<0>>);
using Positive = range_int<1>;
using Negative = range_int<INT64_MIN, 0>;
static_assert(HasRangeConstant<Positive, INT64_MAX>);
static_assert(!HasRangeConstant<Positive, 0>);
static_assert(HasRangeConstant<Negative, INT64_MIN>);
static_assert(!HasRangeConstant<Negative, 0>);
static_assert(HasRangeConstant<range_int<INT_MIN, 0>, INT_MIN>);
static_assert(!HasRangeConstant<range_int<INT_MIN, 0>, 0>);
static_assert(__is_same(decltype(Positive{}.scaled_by<0>()), range_int<0, 1>));
using One = range_int<1, 2>;
using BeforeMax = range_int<INT64_MAX - 1, INT64_MAX>;
using AfterMin = range_int<INT64_MIN + 1, INT64_MIN + 2>;
static_assert(__is_same(decltype(BeforeMax{} + One{}), range_int<INT64_MAX>));
static_assert((BeforeMax{} + One{}).value() == INT64_MAX);
static_assert((AfterMin{} - One{}).value() == INT64_MIN);
static_assert(!CanAdd<Positive, One>);
static_assert(!CanSubtract<Negative, One>);
static_assert(__is_same(decltype(bounded_remainder<(u64{1} << 63)>(0)), range_int<0>));
static_assert([] {
    Positive positive;
    Negative negative;
    return Positive::try_from_i64(INT64_MAX, &positive) &&
           Negative::try_from_i64(INT64_MIN, &negative) && !Negative::try_from_i64(0, &negative) &&
           !Negative::try_from_u64(0, &negative) && negative.value() == INT64_MIN;
}());
static_assert(!CanConvertToU64<range_int<-1, 10>>);

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

// A representation cast must not bypass the checks for numeric conversions.
i64 bit_cast_to_signed(u64 value) {
    // expected-warning@+1 {{use a value conversion for integer or enum bit casts}}
    return __builtin_bit_cast(i64, value);
}

enum class ByteTag : u8 {};
u8 bit_cast_enum(ByteTag tag) {
    // expected-warning@+1 {{use a value conversion for integer or enum bit casts}}
    return __builtin_bit_cast(u8, tag);
}

static_assert(byte_value('A') == 65);
static_assert(signed_wrapping_value(u64{1} << 63) == INT64_MIN);
static_assert(signed_wrapping_value(UINT64_MAX) == -1);
static_assert(signed_wrapping_value(u64{INT64_MAX}) == INT64_MAX);
