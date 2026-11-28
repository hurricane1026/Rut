#pragma once

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"
#include "rut/runtime/timer_wheel.h"

namespace rut {

// Absolute expiry ticks, oldest idle age first. The half-open interval can
// cross the u32 wrap point; iteration stops on equality with end.
struct IdleTrimWindow {
    static constexpr u32 kMinIdleTicks = 5;
    static constexpr u32 kAgeWindow = 40;

    u32 begin;
    u32 end;
};

[[nodiscard]] constexpr IdleTrimWindow idle_trim_window(u32 cursor, u32 timeout) {
    if (timeout >= TimerWheel::kSlots || timeout <= IdleTrimWindow::kMinIdleTicks) return {};
    const u32 kYoungest = IdleTrimWindow::kMinIdleTicks;
    constexpr auto kAge =
        range_int<kYoungest, i64{kYoungest} + 1>{} +
        range_int<IdleTrimWindow::kAgeWindow, i64{IdleTrimWindow::kAgeWindow} + 1>{} -
        range_int<1, 2>{};
    constexpr u32 kMaxAge = kAge.to<u32>();
    const u32 kOldest =
        timeout <= kMaxAge
            ? (range_int(timeout) - range_int<1, 2>{}).max(range_int<0, 1>{}).to<u32>()
            : kMaxAge;
    const u32 kFirstOffset =
        (range_int(timeout) - range_int(kOldest)).max(range_int<0, 1>{}).to<u32>();
    const u32 kLastOffset =
        (range_int(timeout) - range_int(kYoungest)).max(range_int<0, 1>{}).to<u32>();
    return {wrapping_add(cursor, kFirstOffset),
            wrapping_add(wrapping_add(cursor, kLastOffset), u32{1})};
}

}  // namespace rut
