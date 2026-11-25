#pragma once

#include "rut/common/types.h"

#include <limits.h>

namespace rut {
namespace detail {

template <typename T>
concept FixedWidthInteger =
    __is_same(T, i8) || __is_same(T, u8) || __is_same(T, i16) || __is_same(T, u16) ||
    __is_same(T, i32) || __is_same(T, u32) || __is_same(T, i64) || __is_same(T, u64);

// Use a wider type only in constant expressions so even two u64 limits can be added.
template <FixedWidthInteger T>
inline constexpr bool kIsSignedInteger = T(-1) < T(0);

template <FixedWidthInteger T>
inline constexpr __int128_t kIntegerMin =
    kIsSignedInteger<T> ? -(__int128_t{1} << (sizeof(T) * CHAR_BIT - 1)) : 0;

template <FixedWidthInteger T>
inline constexpr __int128_t kIntegerMax =
    (__int128_t{1} << (sizeof(T) * CHAR_BIT - kIsSignedInteger<T>)) - 1;

}  // namespace detail

template <detail::FixedWidthInteger To, detail::FixedWidthInteger From>
    requires(detail::kIntegerMin<To> <= detail::kIntegerMin<From> &&
             detail::kIntegerMax<From> <= detail::kIntegerMax<To>)
constexpr To proven_integer_cast(From value) {
    return static_cast<To>(value);
}

template <detail::FixedWidthInteger Result,
          detail::FixedWidthInteger Left,
          detail::FixedWidthInteger Right>
    requires(detail::kIntegerMin<Result> <=
                 detail::kIntegerMin<Left> + detail::kIntegerMin<Right> &&
             detail::kIntegerMax<Left> + detail::kIntegerMax<Right> <= detail::kIntegerMax<Result>)
constexpr Result add_proven_in_range(Left left, Right right) {
    return proven_integer_cast<Result>(left) + proven_integer_cast<Result>(right);
}

// Use only when an existing check or an invariant already establishes the range.
constexpr void assume_integer_range(bool in_range) {
    if (!in_range) __builtin_unreachable();
}

template <typename T>
constexpr T add_assuming_in_range(T left, T right) {
    T result;
    assume_integer_range(!__builtin_add_overflow(left, right, &result));
    return result;
}

template <typename T>
constexpr T subtract_assuming_in_range(T left, T right) {
    T result;
    assume_integer_range(!__builtin_sub_overflow(left, right, &result));
    return result;
}

template <typename T>
constexpr void advance_assuming_in_range(T& value, T increment) {
    assume_integer_range(!__builtin_add_overflow(value, increment, &value));
}

}  // namespace rut
