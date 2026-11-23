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
    for (u32 age = TimerWheel::kSlots; age != 0;) {
        age = static_cast<u32>(static_cast<i64>(age) - 1);
        if (timeout >= TimerWheel::kSlots || age >= timeout ||
            age < IdleTrimWindow::kMinIdleTicks ||
            static_cast<i64>(age) - static_cast<i64>(IdleTrimWindow::kMinIdleTicks) >=
                static_cast<i64>(IdleTrimWindow::kAgeWindow))
            continue;
        u32 kArmedAt;
        (void)__builtin_sub_overflow(cursor, age, &kArmedAt);
        u32 kExpected;
        (void)__builtin_add_overflow(kArmedAt, timeout, &kExpected);
        if (next == kWindow.end || next != kExpected) return false;
        (void)__builtin_add_overflow(next, u32{1}, &next);
    }
    return next == kWindow.end;
}

consteval bool window_contract() {
    constexpr u32 kCursors[] = {
        0, static_cast<u32>(static_cast<i64>(TimerWheel::kSlots) - 1), 0xfffffff0u, 0xffffffffu};
    for (const u32 kCursor : kCursors) {
        for (u32 timeout = 0; static_cast<i64>(timeout) <= static_cast<i64>(TimerWheel::kSlots) + 1;
             timeout = static_cast<u32>(static_cast<i64>(timeout) + 1))
            if (!matches_armed_timers(kCursor, timeout)) return false;
        if (!matches_armed_timers(kCursor, 0xffffffffu)) return false;
    }
    return true;
}

static_assert(window_contract(), "Idle trim window must visit exactly the eligible expiry ticks");

}  // namespace

}  // namespace rut
