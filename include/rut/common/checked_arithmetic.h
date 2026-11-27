#pragma once

namespace rut {

// Return true if the mathematical result does not fit in Result. Like the
// compiler builtins, these operations always write the result bits. Callers
// must handle overflow before using the output as an exact value.
template <typename Left, typename Right, typename Result>
[[nodiscard, gnu::always_inline]] constexpr bool add_overflow(Left left, Right right, Result* out) {
    return __builtin_add_overflow(left, right, out);
}

template <typename Left, typename Right, typename Result>
[[nodiscard, gnu::always_inline]] constexpr bool sub_overflow(Left left, Right right, Result* out) {
    return __builtin_sub_overflow(left, right, out);
}

template <typename Left, typename Right, typename Result>
[[nodiscard, gnu::always_inline]] constexpr bool mul_overflow(Left left, Right right, Result* out) {
    return __builtin_mul_overflow(left, right, out);
}

namespace detail {
template <typename T>
concept WrappingInteger =
    __is_same(T, unsigned char) || __is_same(T, unsigned short) || __is_same(T, unsigned int) ||
    __is_same(T, unsigned long) || __is_same(T, unsigned long long);
}

// Modular arithmetic for protocols and counters whose rollover is intentional.
// The widened operation is exact. The conversion keeps the low bits of T.
template <detail::WrappingInteger T>
[[nodiscard, gnu::always_inline]] constexpr T wrapping_add(T left, T right) {
    // RUT_INTEGER_RANGE: the conversion implements modulo arithmetic for T.
    return static_cast<T>(__int128{left} + __int128{right});
}

template <detail::WrappingInteger T>
[[nodiscard, gnu::always_inline]] constexpr T wrapping_sub(T left, T right) {
    // RUT_INTEGER_RANGE: the conversion implements modulo arithmetic for T.
    return static_cast<T>(__int128{left} - __int128{right});
}

template <detail::WrappingInteger T>
[[nodiscard, gnu::always_inline]] constexpr T wrapping_mul(T left, T right) {
    // RUT_INTEGER_RANGE: the exact unsigned product fits in 128 bits.
    return static_cast<T>(static_cast<unsigned __int128>(left) *
                          static_cast<unsigned __int128>(right));
}

}  // namespace rut
