#pragma once

#include "rut/common/integer_conversion.h"

namespace rut {

// One past INT64_MAX is a valid bound, even though it is not an i64 value.
inline constexpr __int128_t kI64ExclusiveEnd = __int128_t{INT64_MAX} + 1;

namespace detail {

template <typename T>
concept RangeSource =
    __is_same(T, i8) || __is_same(T, u8) || __is_same(T, i16) || __is_same(T, u16) ||
    __is_same(T, i32) || __is_same(T, u32) || __is_same(T, i64);

template <RangeSource T>
inline constexpr bool kRangeSourceSigned = static_cast<T>(-1) < T{0};

template <RangeSource T>
inline constexpr __int128_t kRangeSourceEnd =
    __int128_t{1} << (sizeof(T) * __CHAR_BIT__ - kRangeSourceSigned<T>);

template <RangeSource T>
inline constexpr i64 kRangeSourceBegin =
    kRangeSourceSigned<T> ? static_cast<i64>(-kRangeSourceEnd<T>) : 0;

struct RangeProof {};
inline constexpr RangeProof kRangeProof{};

constexpr __int128_t min_product(__int128_t a, __int128_t b, __int128_t c, __int128_t d) {
    const auto kFirst = a < b ? a : b;
    const auto kSecond = c < d ? c : d;
    return kFirst < kSecond ? kFirst : kSecond;
}

constexpr __int128_t max_product(__int128_t a, __int128_t b, __int128_t c, __int128_t d) {
    const auto kFirst = a > b ? a : b;
    const auto kSecond = c > d ? c : d;
    return kFirst > kSecond ? kFirst : kSecond;
}

template <i64 A, __int128_t B, i64 C, __int128_t D>
struct ProductRange {
    static constexpr auto kMin =
        min_product(__int128_t{A} * C, A*(D - 1), (B - 1) * C, (B - 1) * (D - 1));
    static constexpr auto kMax =
        max_product(__int128_t{A} * C, A*(D - 1), (B - 1) * C, (B - 1) * (D - 1));
};

}  // namespace detail

// An i64 in the half-open interval [Begin, End). Omitting End leaves the
// value bounded above only by the underlying i64 type.
template <i64 Begin, __int128_t End = kI64ExclusiveEnd>
class range_int {
    static_assert(Begin < End && End <= kI64ExclusiveEnd);

    template <i64, __int128_t>
    friend class range_int;

    template <u64 Divisor>
        requires(Divisor > 0 && Divisor <= (u64{1} << 63))
    friend constexpr auto bounded_remainder(u64 value);

    template <u64 Divisor>
        requires(Divisor >= 2)
    friend constexpr auto bounded_quotient(u64 value);

    i64 value_ = Begin;
    constexpr range_int(detail::RangeProof, i64 value) : value_(value) {}

public:
    constexpr range_int() = default;

    template <detail::RangeSource T>
        requires(Begin <= detail::kRangeSourceBegin<T> && detail::kRangeSourceEnd<T> <= End)
    explicit constexpr range_int(T value) : value_(value) {}

    template <i64 Value>
        requires(Begin <= Value && Value < End)
    static consteval range_int constant() {
        return range_int(detail::kRangeProof, Value);
    }

    template <i64 OtherBegin, __int128_t OtherEnd>
        requires(Begin <= OtherBegin && OtherEnd <= End)
    constexpr range_int(range_int<OtherBegin, OtherEnd> other) : value_(other.value()) {}

    static constexpr range_int count_leading_zeros(u64 value)
        requires(Begin <= 0 && End > 64)
    {
        return range_int(detail::kRangeProof, value == 0 ? 64 : __builtin_clzll(value));
    }

    template <typename T, size_t N>
        requires(Begin >= 0 && End <= N)
    constexpr T& at(T (&array)[N]) const {
        return array[value_];
    }

    template <i64 Factor>
        requires(Factor >= 0 && static_cast<__int128_t>(Begin) * Factor >= INT64_MIN &&
                 (End - 1) * Factor <= INT64_MAX)
    constexpr auto scaled_by() const {
        // RUT_INTEGER_RANGE: the requires clause bounds the product of both endpoints.
        const i64 kResult = value_ * Factor;
        return range_int<Begin * Factor, (End - 1) * Factor + 1>(detail::kRangeProof, kResult);
    }

    // The conversion functions require a writable output and write only on success.
    [[nodiscard]] static constexpr bool try_from_i64(i64 value, range_int* out) {
        if constexpr (Begin == 0) {
            // A negative i64 maps above every nonnegative i64.
            if (static_cast<u64>(value) >= static_cast<u64>(End)) return false;
        } else if (value < Begin || value >= End) {
            return false;
        }
        out->value_ = value;
        return true;
    }

    [[nodiscard]] static constexpr bool try_from_u64(u64 value, range_int* out) {
        if constexpr (End <= 0) {
            return false;
        } else {
            constexpr u64 kMax = static_cast<u64>(End - 1);
            if (value > kMax) return false;
            if constexpr (Begin > 0) {
                if (value < static_cast<u64>(Begin)) return false;
            }
            return try_u64_to_i64(value, &out->value_);
        }
    }

    // Accept a count no larger than this limit, including zero.
    [[nodiscard]] constexpr bool try_count(i64 count, range_int* out) const
        requires(Begin == 0)
    {
        if (static_cast<u64>(count) > to_u64()) return false;
        out->value_ = count;
        return true;
    }

    // Select the prefix that fits and skip empty copies with the same guard
    // that rejects negative requests.
    [[nodiscard]] constexpr bool try_nonempty_prefix(i64 requested, range_int* out) const
        requires(Begin == 0)
    {
        const i64 kPrefix = requested < value_ ? requested : value_;
        if (kPrefix <= 0) return false;
        out->value_ = kPrefix;
        return true;
    }

    constexpr i64 value() const { return value_; }

    template <i64 OtherBegin, __int128_t OtherEnd>
    constexpr auto min(range_int<OtherBegin, OtherEnd> other) const {
        constexpr auto kLower = Begin < OtherBegin ? Begin : OtherBegin;
        constexpr auto kUpper = End < OtherEnd ? End : OtherEnd;
        return range_int<kLower, kUpper>(detail::kRangeProof,
                                         value_ < other.value() ? value_ : other.value());
    }

    template <i64 OtherBegin, __int128_t OtherEnd>
    constexpr auto max(range_int<OtherBegin, OtherEnd> other) const {
        constexpr auto kLower = Begin > OtherBegin ? Begin : OtherBegin;
        constexpr auto kUpper = End > OtherEnd ? End : OtherEnd;
        return range_int<kLower, kUpper>(detail::kRangeProof,
                                         value_ > other.value() ? value_ : other.value());
    }

    // A pointer or container index must have a nonnegative lower bound.
    constexpr i64 index() const
        requires(Begin >= 0)
    {
        return value_;
    }

    // Only expose the conversion if the destination can represent every value.
    template <detail::RangeSource T>
        requires(Begin >= detail::kRangeSourceBegin<T> && End <= detail::kRangeSourceEnd<T>)
    constexpr T to() const {
        return static_cast<T>(value_);
    }

    // A narrower destination for a value whose range is known only at runtime.
    // A failed conversion leaves the caller's output unchanged.
    template <detail::RangeSource T>
    [[nodiscard]] constexpr bool to(T* out) const {
        if constexpr (Begin < detail::kRangeSourceBegin<T>)
            if (value_ < detail::kRangeSourceBegin<T>) return false;
        if constexpr (End > detail::kRangeSourceEnd<T>)
            if (value_ >= detail::kRangeSourceEnd<T>) return false;
        *out = static_cast<T>(value_);
        return true;
    }

    template <i64 Divisor>
        requires(Divisor > 0)
    constexpr auto divided_by() const {
        return range_int<Begin / Divisor, (End - 1) / Divisor + 1>(detail::kRangeProof,
                                                                   value_ / Divisor);
    }

    constexpr u64 to_u64() const
        requires(Begin >= 0)
    {
        return static_cast<u64>(value_);
    }

    // out must point to writable storage. Write only if the ABI type can hold the value.
    template <typename T>
        requires(__is_same(T, signed char) || __is_same(T, short) || __is_same(T, int) ||
                 __is_same(T, long) || __is_same(T, long long))
    [[nodiscard]] constexpr bool try_to_signed(T* out) const {
        constexpr auto kLimit = __int128_t{1} << (sizeof(T) * __CHAR_BIT__ - 1);
        if constexpr (Begin < -kLimit || End > kLimit) {
            constexpr i64 kMin = static_cast<i64>(-kLimit);
            constexpr i64 kMax = static_cast<i64>(kLimit - 1);
            if (value_ < kMin || value_ > kMax) return false;
        }
        *out = static_cast<T>(value_);
        return true;
    }

    template <i64 OtherBegin, __int128_t OtherEnd>
        requires(static_cast<__int128_t>(Begin) + OtherBegin >= INT64_MIN &&
                 End + OtherEnd - 1 <= kI64ExclusiveEnd)
    constexpr auto operator+(range_int<OtherBegin, OtherEnd> other) const {
        // RUT_INTEGER_RANGE: the requires clause bounds the sum of both operand ranges.
        const i64 kResult = value_ + other.value();
        return range_int<Begin + OtherBegin, End + OtherEnd - 1>(detail::kRangeProof, kResult);
    }

    template <i64 OtherBegin, __int128_t OtherEnd>
        requires(Begin - (OtherEnd - 1) >= INT64_MIN && End - OtherBegin <= kI64ExclusiveEnd)
    constexpr auto operator-(range_int<OtherBegin, OtherEnd> other) const {
        // RUT_INTEGER_RANGE: the requires clause bounds the difference of both operand ranges.
        const i64 kResult = value_ - other.value();
        return range_int<Begin - (OtherEnd - 1), End - OtherBegin>(detail::kRangeProof, kResult);
    }

    template <i64 OtherBegin, __int128_t OtherEnd>
        requires(detail::ProductRange<Begin, End, OtherBegin, OtherEnd>::kMin >= INT64_MIN &&
                 detail::ProductRange<Begin, End, OtherBegin, OtherEnd>::kMax <= INT64_MAX)
    constexpr auto operator*(range_int<OtherBegin, OtherEnd> other) const {
        using Product = detail::ProductRange<Begin, End, OtherBegin, OtherEnd>;
        // RUT_INTEGER_RANGE: the requires clause checks all four endpoint products.
        const i64 kResult = value_ * other.value();
        return range_int<Product::kMin, Product::kMax + 1>(detail::kRangeProof, kResult);
    }
};

// Constructing from a native integer carries exactly the source type's range.
template <detail::RangeSource T>
range_int(T) -> range_int<detail::kRangeSourceBegin<T>, detail::kRangeSourceEnd<T>>;

// A nonzero divisor bounds the unsigned remainder to [0, Divisor).
template <u64 Divisor>
    requires(Divisor > 0 && Divisor <= (u64{1} << 63))
constexpr auto bounded_remainder(u64 value) {
    return range_int<0, Divisor>(detail::kRangeProof, value % Divisor);
}

// Division by two or more makes even the largest u64 quotient fit in i64.
template <u64 Divisor>
    requires(Divisor >= 2)
constexpr auto bounded_quotient(u64 value) {
    return range_int<0, UINT64_MAX / Divisor + 1>(detail::kRangeProof, value / Divisor);
}

// Decode the low 64 bits of a deliberate wrapping operation as a signed value.
[[nodiscard]] constexpr i64 signed_wrapping_value(u64 bits) {
    constexpr u64 kSignBit = u64{1} << 63;
    const auto low = bounded_remainder<kSignBit>(bits);
    return bits < kSignBit ? low.value() : (range_int<INT64_MIN, INT64_MIN + 1>{} + low).value();
}

}  // namespace rut
