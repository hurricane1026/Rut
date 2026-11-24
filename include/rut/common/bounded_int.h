#pragma once

#include "core/expected.h"
#include "rut/common/types.h"

#ifdef __clang__
#define RUT_REPRESENTABLE [[clang::annotate("rut_representable")]]
#else
#define RUT_REPRESENTABLE
#endif

namespace rut {

enum class IntegerRangeError { OutOfRange };

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

}  // namespace rut

#undef RUT_REPRESENTABLE
