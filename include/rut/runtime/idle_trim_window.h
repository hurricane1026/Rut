#pragma once

#include "rut/common/types.h"
#include "rut/runtime/timer_wheel.h"

namespace rut {

constexpr u32 idle_trim_mod_add(u32 lhs, u32 rhs) {
    u32 result;
    (void)__builtin_add_overflow(lhs, rhs, &result);
    return result;
}

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
    const u32 kMaxAge = static_cast<u32>(static_cast<i64>(kYoungest) +
                                         static_cast<i64>(IdleTrimWindow::kAgeWindow) - 1);
    const u32 kOldest =
        timeout <= kMaxAge ? static_cast<u32>(static_cast<i64>(timeout) - 1) : kMaxAge;
    const u32 kFirstOffset =
        static_cast<u32>(static_cast<i64>(timeout) - static_cast<i64>(kOldest));
    const u32 kLastOffset =
        static_cast<u32>(static_cast<i64>(timeout) - static_cast<i64>(kYoungest));
    return {idle_trim_mod_add(cursor, kFirstOffset),
            idle_trim_mod_add(idle_trim_mod_add(cursor, kLastOffset), 1)};
}

}  // namespace rut
