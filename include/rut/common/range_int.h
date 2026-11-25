#pragma once

#include "rut/common/integer_conversion.h"

namespace rut {

// An i64 with a closed interval known to callers and to arithmetic templates.
template <i64 Begin, i64 End>
class range_int {
    static_assert(Begin <= End);

    template <i64, i64>
    friend class range_int;

    i64 value_ = Begin;
    explicit constexpr range_int(i64 value) : value_(value) {}

public:
    constexpr range_int() = default;

    template <i64 Value>
        requires(Begin <= Value && Value <= End)
    static consteval range_int constant() {
        return range_int(Value);
    }

    template <i64 OtherBegin, i64 OtherEnd>
        requires(Begin <= OtherBegin && OtherEnd <= End)
    constexpr range_int(range_int<OtherBegin, OtherEnd> other) : value_(other.value()) {}

    static constexpr range_int from_u32(u32 value)
        requires(Begin <= 0 && End >= UINT32_MAX)
    {
        return range_int(value);
    }

    [[nodiscard]] static constexpr bool try_from_i64(i64 value, range_int& out) {
        if (value < Begin || value > End) return false;
        out.value_ = value;
        return true;
    }

    [[nodiscard]] static constexpr bool try_from_u64(u64 value, range_int& out) {
        i64 converted;
        return try_u64_to_i64(value, converted) && try_from_i64(converted, out);
    }

    constexpr i64 value() const { return value_; }

    template <i64 OtherBegin, i64 OtherEnd>
        requires(static_cast<__int128_t>(Begin) + OtherBegin >= INT64_MIN &&
                 static_cast<__int128_t>(End) + OtherEnd <= INT64_MAX)
    constexpr auto operator+(range_int<OtherBegin, OtherEnd> other) const {
        return range_int<Begin + OtherBegin, End + OtherEnd>(value_ + other.value());
    }

    template <i64 OtherBegin, i64 OtherEnd>
        requires(static_cast<__int128_t>(Begin) - OtherEnd >= INT64_MIN &&
                 static_cast<__int128_t>(End) - OtherBegin <= INT64_MAX)
    constexpr auto operator-(range_int<OtherBegin, OtherEnd> other) const {
        return range_int<Begin - OtherEnd, End - OtherBegin>(value_ - other.value());
    }
};

}  // namespace rut
