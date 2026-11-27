#include "rut/runtime/idle_trim_window.h"

#include "rut/common/range_int.h"
#include "rut/common/types.h"
#include "rut/runtime/timer_wheel.h"

namespace rut {
namespace {

// Independently arm one timer at every possible age, from oldest to
// youngest. Compare its expiry to the next tick the sweep plans to visit.
[[nodiscard]] consteval bool matches_armed_timers(u32 cursor, u32 timeout) {
    constexpr i64 kCycle = i64{1} << 32;
    const auto kWindow = idle_trim_window(cursor, timeout);
    u32 next = kWindow.begin;
    constexpr u32 kMaxAge = IdleTrimWindow::kMinIdleTicks + IdleTrimWindow::kAgeWindow;
    for (u32 age = TimerWheel::kSlots; age > 0;) {
        --age;
        if (timeout >= TimerWheel::kSlots || age >= timeout ||
            age < IdleTrimWindow::kMinIdleTicks || age >= kMaxAge)
            continue;
        const auto kExpiry = range_int(cursor) - range_int(age) + range_int(timeout) +
                             range_int<kCycle, kCycle + 1>{};
        const u32 kExpected = bounded_remainder<kCycle>(kExpiry.to_u64()).to<u32>();
        if (next == kWindow.end || next != kExpected) return false;
        next = bounded_remainder<kCycle>((range_int(next) + range_int<1, 2>{}).to_u64()).to<u32>();
    }
    return next == kWindow.end;
}

[[nodiscard]] consteval bool window_contract() {
    constexpr u32 kCursors[] = {0, TimerWheel::kSlots - 1, 0xfffffff0u, 0xffffffffu};
    for (const u32 kCursor : kCursors) {
        for (u32 timeout = 0; timeout <= TimerWheel::kSlots + 1; ++timeout)
            if (!matches_armed_timers(kCursor, timeout)) return false;
        if (!matches_armed_timers(kCursor, 0xffffffffu)) return false;
    }
    return true;
}

static_assert(window_contract(), "Idle trim window must visit exactly the eligible expiry ticks");

}  // namespace

}  // namespace rut
