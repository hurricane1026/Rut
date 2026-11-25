#pragma once

namespace rut {

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
