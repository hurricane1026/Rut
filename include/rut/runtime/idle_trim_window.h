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

constexpr IdleTrimWindow idle_trim_window(u32 cursor, u32 timeout) {
    if (timeout >= TimerWheel::kSlots || timeout <= IdleTrimWindow::kMinIdleTicks) return {};
    const u32 kYoungest = IdleTrimWindow::kMinIdleTicks;
    constexpr auto kAge = range_int(IdleTrimWindow::kMinIdleTicks) +
                          range_int(IdleTrimWindow::kAgeWindow) - range_int<1, 2>{};
    constexpr u32 kMaxAge = static_cast<u32>(kAge.value());
    const u32 kOldest = timeout <= kMaxAge
                            ? static_cast<u32>((range_int(timeout) - range_int<1, 2>{}).value())
                            : kMaxAge;
    const u32 kFirstOffset = static_cast<u32>((range_int(timeout) - range_int(kOldest)).value());
    const u32 kLastOffset = static_cast<u32>((range_int(timeout) - range_int(kYoungest)).value());
    return {wrapping_add(cursor, kFirstOffset),
            wrapping_add(wrapping_add(cursor, kLastOffset), u32{1})};
}

}  // namespace rut
