#include "rut/runtime/idle_trim_window.h"

#include "rut/common/types.h"
#include "rut/runtime/timer_wheel.h"

namespace rut {
namespace {

// Independently arm one timer at every possible age, from oldest to
// youngest. Compare its expiry to the next tick the sweep plans to visit.
consteval bool matches_armed_timers(u32 cursor, u32 timeout) {
    const auto kWindow = idle_trim_window(cursor, timeout);
    u32 next = kWindow.begin;
    for (u32 age = TimerWheel::kSlots; age-- > 0;) {
        if (timeout >= TimerWheel::kSlots || age >= timeout ||
            age < IdleTrimWindow::kMinIdleTicks ||
            age - IdleTrimWindow::kMinIdleTicks >= IdleTrimWindow::kAgeWindow)
            continue;
        const u32 kArmedAt = cursor - age;
        if (next == kWindow.end || next != kArmedAt + timeout) return false;
        ++next;
    }
    return next == kWindow.end;
}

consteval bool window_contract() {
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
