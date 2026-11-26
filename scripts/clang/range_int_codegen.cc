#include "rut/common/range_int.h"

using namespace rut;

#ifdef RUT_USE_RANGE_INT
using Signed = range_int<-100, 100>;
using Small = range_int<3, 10>;
using Negative = range_int<INT64_MIN, 0>;
using Positive = range_int<1>;
using Nonnegative = range_int<0>;
using Full = range_int<INT64_MIN>;
using U16 = decltype(range_int(u16{}));
using U32 = decltype(range_int(u32{}));
using Index = range_int<0, 4>;

static_assert(sizeof(Signed) == sizeof(i64));
static_assert(alignof(Signed) == alignof(i64));
static_assert(__is_trivially_copyable(Signed));
#else
using Signed = i64;
using Small = i64;
using Negative = i64;
using Positive = i64;
using Nonnegative = i64;
using Full = i64;
using U16 = i64;
using U32 = i64;
using Index = i64;
#endif

extern "C" {

Signed compare_default() {
#ifdef RUT_USE_RANGE_INT
    return Signed{};
#else
    return -100;
#endif
}

Signed compare_constant() {
#ifdef RUT_USE_RANGE_INT
    return Signed::constant<-17>();
#else
    return -17;
#endif
}

Full compare_widen(Signed value) {
    return value;
}

U16 compare_from_u16(u16 value) {
#ifdef RUT_USE_RANGE_INT
    return range_int(value);
#else
    return value;
#endif
}

U32 compare_from_u32(u32 value) {
#ifdef RUT_USE_RANGE_INT
    return range_int(value);
#else
    return value;
#endif
}

Full compare_from_i8(i8 value) {
#ifdef RUT_USE_RANGE_INT
    return range_int(value);
#else
    return value;
#endif
}

Full compare_from_u8(u8 value) {
#ifdef RUT_USE_RANGE_INT
    return range_int(value);
#else
    return value;
#endif
}

Full compare_from_i16(i16 value) {
#ifdef RUT_USE_RANGE_INT
    return range_int(value);
#else
    return value;
#endif
}

Full compare_from_i32(i32 value) {
#ifdef RUT_USE_RANGE_INT
    return range_int(value);
#else
    return value;
#endif
}

Full compare_from_i64(i64 value) {
#ifdef RUT_USE_RANGE_INT
    return range_int(value);
#else
    return value;
#endif
}

i64 compare_value(Signed value) {
#ifdef RUT_USE_RANGE_INT
    return value.value();
#else
    return value;
#endif
}

u64 compare_to_u64(Nonnegative value) {
#ifdef RUT_USE_RANGE_INT
    return value.to_u64();
#else
    return static_cast<u64>(value);
#endif
}

Full compare_add(Signed left, Small right) {
    return left + right;
}

Full compare_subtract(Signed left, Small right) {
    return left - right;
}

Full compare_scale(Signed value) {
#ifdef RUT_USE_RANGE_INT
    return value.scaled_by<8>();
#else
    return value * 8;
#endif
}

Full compare_scale_zero(Full value) {
#ifdef RUT_USE_RANGE_INT
    return value.scaled_by<0>();
#else
    return value * 0;
#endif
}

const i64* compare_at(Index index, const i64 (&values)[4]) {
#ifdef RUT_USE_RANGE_INT
    return &index.at(values);
#else
    return &values[index];
#endif
}

i64 compare_remainder(u64 value) {
#ifdef RUT_USE_RANGE_INT
    return bounded_remainder<10>(value).value();
#else
    return static_cast<i64>(value % 10);
#endif
}

i64 compare_remainder_power_of_two(u64 value) {
#ifdef RUT_USE_RANGE_INT
    return bounded_remainder<(u64{1} << 63)>(value).value();
#else
    return static_cast<i64>(value % (u64{1} << 63));
#endif
}

i64 compare_quotient(u64 value) {
#ifdef RUT_USE_RANGE_INT
    return bounded_quotient<1'000'000>(value).value();
#else
    return static_cast<i64>(value / 1'000'000);
#endif
}

i64 compare_quotient_power_of_two(u64 value) {
#ifdef RUT_USE_RANGE_INT
    return bounded_quotient<2>(value).value();
#else
    return static_cast<i64>(value / 2);
#endif
}

i64 compare_leading_zeros(u64 value) {
#ifdef RUT_USE_RANGE_INT
    return range_int<0, 65>::count_leading_zeros(value).value();
#else
    return value == 0 ? 64 : __builtin_clzll(value);
#endif
}

bool compare_try_from_i64(i64 value, Signed* out) {
#ifdef RUT_USE_RANGE_INT
    return Signed::try_from_i64(value, out);
#else
    if (value < -100 || value >= 100) return false;
    *out = value;
    return true;
#endif
}

bool compare_try_from_i64_lower_bound(i64 value, Positive* out) {
#ifdef RUT_USE_RANGE_INT
    return Positive::try_from_i64(value, out);
#else
    if (value < 1) return false;
    *out = value;
    return true;
#endif
}

bool compare_try_from_i64_upper_bound(i64 value, Negative* out) {
#ifdef RUT_USE_RANGE_INT
    return Negative::try_from_i64(value, out);
#else
    if (value >= 0) return false;
    *out = value;
    return true;
#endif
}

bool compare_try_from_i64_full(i64 value, Full* out) {
#ifdef RUT_USE_RANGE_INT
    return Full::try_from_i64(value, out);
#else
    *out = value;
    return true;
#endif
}

bool compare_try_from_u64(u64 value, Small* out) {
#ifdef RUT_USE_RANGE_INT
    return Small::try_from_u64(value, out);
#else
    if (value >= 10) return false;
    if (value < 3) return false;
    *out = static_cast<i64>(value);
    return true;
#endif
}

bool compare_try_from_u64_nonnegative(u64 value, Nonnegative* out) {
#ifdef RUT_USE_RANGE_INT
    return Nonnegative::try_from_u64(value, out);
#else
    if (value > u64{INT64_MAX}) return false;
    *out = static_cast<i64>(value);
    return true;
#endif
}

bool compare_try_from_u64_negative([[maybe_unused]] u64 value, [[maybe_unused]] Negative* out) {
#ifdef RUT_USE_RANGE_INT
    return Negative::try_from_u64(value, out);
#else
    return false;
#endif
}

bool compare_try_to_i64(Full value, i64* out) {
#ifdef RUT_USE_RANGE_INT
    return value.try_to_signed(out);
#else
    *out = value;
    return true;
#endif
}

bool compare_try_to_i32_proven(Signed value, i32* out) {
#ifdef RUT_USE_RANGE_INT
    return value.try_to_signed(out);
#else
    *out = static_cast<i32>(value);
    return true;
#endif
}

bool compare_try_to_i32_checked(Full value, i32* out) {
#ifdef RUT_USE_RANGE_INT
    return value.try_to_signed(out);
#else
    i32 converted;
    if (__builtin_add_overflow(value, 0, &converted)) return false;
    *out = converted;
    return true;
#endif
}

void compare_copy(Signed* out, const Signed& value) {
    *out = value;
}

bool compare_checked_alignment(u64 value, i64* out) {
#ifdef RUT_USE_RANGE_INT
    range_int<0, kI64ExclusiveEnd - 7> input;
    if (!decltype(input)::try_from_u64(value, &input)) return false;
    const auto padded = input + range_int<7, 8>::constant<7>();
    *out = padded.value() / 8 * 8;
#else
    if (value > u64{INT64_MAX - 7}) return false;
    *out = (static_cast<i64>(value) + 7) / 8 * 8;
#endif
    return true;
}

i64 compare_pack_fields(u16 status, u16 body, u16 headers) {
#ifdef RUT_USE_RANGE_INT
    using Packed = range_int<0, u64{1} << 48>;
    const Packed packed = range_int(status) + range_int(body).scaled_by<(u64{1} << 16)>() +
                          range_int(headers).scaled_by<(u64{1} << 32)>();
    return packed.value();
#else
    const u32 low = u32{status} | (u32{body} << 16);
    return i64{headers} * (i64{1} << 32) + low;
#endif
}

u64 compare_accumulate(const u32* values, u32 size) {
    u64 total = 0;
    for (u32 i = 0; i < size; ++i) {
#ifdef RUT_USE_RANGE_INT
        total += (range_int(values[i]).scaled_by<4>() + U16::constant<7>()).to_u64();
#else
        total += static_cast<u64>(i64{values[i]} * 4 + 7);
#endif
    }
    return total;
}

u64 compare_checked_accumulate(const u64* values, u32 size) {
    u64 total = 0;
    for (u32 i = 0; i < size; ++i) {
#ifdef RUT_USE_RANGE_INT
        range_int<3, 100> value;
        if (decltype(value)::try_from_u64(values[i], &value)) total += value.to_u64();
#else
        const u64 value = values[i];
        if (value >= 3 && value < 100) total += value;
#endif
    }
    return total;
}

}  // extern "C"
