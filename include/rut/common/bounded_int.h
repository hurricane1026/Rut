#pragma once

#include "core/expected.h"
#include "rut/common/integer_range.h"
#include "rut/common/types.h"

#ifdef __clang__
#define RUT_REPRESENTABLE [[clang::annotate("rut_representable")]]
#else
#define RUT_REPRESENTABLE
#endif

namespace rut {

enum class IntegerRangeError : u8 { OutOfRange };

// Tag identifies the unit even when two quantities have identical limits.
template <typename Tag, i64 Minimum, i64 Maximum>
class BoundedInt {
    static_assert(Minimum <= Maximum);
    i64 value_;
    explicit constexpr BoundedInt(i64 value) : value_(value) {}

public:
    template <i64 Value>
    static constexpr BoundedInt constant() {
        static_assert(Value >= Minimum && Value <= Maximum);
        return BoundedInt(Value);
    }

    [[nodiscard]] static core::Expected<BoundedInt, IntegerRangeError> from(
        i64 value RUT_REPRESENTABLE) {
        if (value < Minimum || value > Maximum)
            return core::make_unexpected(IntegerRangeError::OutOfRange);
        return BoundedInt(value);
    }

    [[nodiscard]] static constexpr BoundedInt clamp(i64 value) {
        return BoundedInt(value < Minimum ? Minimum : value > Maximum ? Maximum : value);
    }

    constexpr i64 value() const { return value_; }

    [[nodiscard]] constexpr bool try_increment() {
        if (value_ >= Maximum) return false;
        ++value_;
        return true;
    }

    [[nodiscard]] constexpr bool try_decrement() {
        if (value_ <= Minimum) return false;
        --value_;
        return true;
    }
};

template <detail::FixedWidthInteger To, typename Tag, i64 Min, i64 Max>
    requires(detail::kIntegerMin<To> <= Min && Max <= detail::kIntegerMax<To>)
constexpr To proven_integer_cast(BoundedInt<Tag, Min, Max> value) {
    return static_cast<To>(value.value());
}

template <detail::FixedWidthInteger Result,
          typename LeftTag,
          i64 LeftMin,
          i64 LeftMax,
          typename RightTag,
          i64 RightMin,
          i64 RightMax>
    requires(detail::kIsSignedInteger<Result> &&
             detail::kIntegerMin<Result> <= static_cast<__int128_t>(LeftMin) - RightMax &&
             static_cast<__int128_t>(LeftMax) - RightMin <= detail::kIntegerMax<Result>)
constexpr Result subtract_proven_in_range(BoundedInt<LeftTag, LeftMin, LeftMax> left,
                                          BoundedInt<RightTag, RightMin, RightMax> right) {
    return static_cast<Result>(static_cast<__int128_t>(left.value()) - right.value());
}

}  // namespace rut

#undef RUT_REPRESENTABLE
