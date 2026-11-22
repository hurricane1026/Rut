#pragma once

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
    const u32 kMaxAge = kYoungest + IdleTrimWindow::kAgeWindow - 1;
    const u32 kOldest = timeout <= kMaxAge ? timeout - 1 : kMaxAge;
    return {cursor + (timeout - kOldest), cursor + (timeout - kYoungest) + 1};
}

}  // namespace rut
