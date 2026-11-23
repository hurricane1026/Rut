#include "rut/runtime/timer_wheel.h"

#include "rut/runtime/connection.h"

#include <stddef.h>  // offsetof

namespace rut {

namespace {

template <typename T>
constexpr bool has_raw_tick_arithmetic =
    requires(T t) { t + 1; } || requires(T t) { t - 1; } || requires(T t) { t - t; };

static_assert(!has_raw_tick_arithmetic<decltype(TimerWheel::cursor)>);

consteval bool cursor_wrap_contract() {
    TimerWheel wheel{};
    using Tick = TimerWheel::Tick;
    wheel.cursor = Tick{UINT32_MAX};
    const Tick incremented = wheel.cursor++;
    if (incremented != Tick{UINT32_MAX} || wheel.cursor != Tick{}) return false;
    const Tick decremented = wheel.cursor--;
    if (decremented != Tick{} || wheel.cursor != Tick{UINT32_MAX}) return false;
    Tick* incremented_address = &++wheel.cursor;
    if (incremented_address != &wheel.cursor || wheel.cursor != Tick{}) return false;
    Tick* decremented_address = &--wheel.cursor;
    if (decremented_address != &wheel.cursor || wheel.cursor != Tick{UINT32_MAX}) return false;
    return wheel.slot_after(0) == static_cast<u32>(static_cast<i64>(TimerWheel::kSlots) - 1) &&
           wheel.tick_after(1) == Tick{} && wheel.slot_after(1) == 0 &&
           wheel.tick_after(UINT32_MAX) == Tick{UINT32_MAX - 1} &&
           TimerWheel::elapsed_ticks(Tick{UINT32_MAX - 1}, Tick{1}) == 3;
}

static_assert(cursor_wrap_contract());
static_assert(TimerWheel::remaining_ticks(3, 1) == 2 && TimerWheel::remaining_ticks(3, 3) == 0 &&
              TimerWheel::remaining_ticks(3, UINT32_MAX) == 0);

// Check both ends of every representable bucket against the wheel geometry.
consteval bool yield_fallback_contract() {
    if (TimerWheel::yield_fallback_seconds(0) != 1) return false;
    for (u32 seconds = 1; seconds < TimerWheel::kSlots;
         seconds = static_cast<u32>(static_cast<i64>(seconds) + 1)) {
        if (TimerWheel::yield_fallback_seconds(
                static_cast<u32>((static_cast<i64>(seconds) - 1) * 1000 + 1)) != seconds ||
            TimerWheel::yield_fallback_seconds(
                static_cast<u32>(static_cast<i64>(seconds) * 1000)) != seconds)
            return false;
    }
    return TimerWheel::yield_fallback_seconds(
               static_cast<u32>((static_cast<i64>(TimerWheel::kSlots) - 1) * 1000 + 1)) == 0 &&
           TimerWheel::yield_fallback_seconds(
               static_cast<u32>(static_cast<i64>(TimerWheel::kSlots) * 1000)) == 0 &&
           TimerWheel::yield_fallback_seconds(0xffffffffu) == 0;
}

static_assert(yield_fallback_contract(), "Yield fallback must fit within one timer wheel rotation");

}  // namespace

// The idle-trim mark should share the cache line timer_node is about to dirty, so
// the clear in add() costs no extra line on every arm. alignof(Connection) is 8 and
// sizeof(Connection) is 3696 (48 mod 64), so a slot's offsets may sit 48 bytes
// off a cache line; keep the layout assertion in test_iouring_idle_trim.cc.
// boundary: only a 32-byte-aligned block is guaranteed to share a line in every
// slot. Require the mark and all of timer_node inside one such block.
static_assert(offsetof(Connection, idle_trim_examined) / 32 ==
                  (offsetof(Connection, timer_node) + sizeof(ListNode) - 1) / 32,
              "idle_trim_examined must share a 32-byte block with timer_node");

void TimerWheel::add(Connection* c, u32 seconds) {
    // Every arm and re-arm (refresh() goes through here) starts a fresh examination
    // epoch for the idle-buffer trim sweep: a node that was examined under an
    // earlier arming must not look "already handled" in its new list, whatever
    // timeout and expiry tick the new arming picked.
    c->idle_trim_examined = false;
    slots[slot_after(seconds)].insert_after(&c->timer_node);
}

void TimerWheel::refresh(Connection* c, u32 seconds) {
    c->timer_node.detach();
    add(c, seconds);
}

void TimerWheel::remove(Connection* c) {
    c->timer_node.detach();
}

u64 TimerWheel::timer_node_offset() {
    return offsetof(Connection, timer_node);
}

}  // namespace rut
