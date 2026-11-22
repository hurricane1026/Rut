#pragma once

#include "rut/common/types.h"

namespace rut {

struct ConnectionBase;              // forward decl
using Connection = ConnectionBase;  // alias (matches connection.h)

constexpr u32 timer_seconds_from_ms(u32 ms) {
    return static_cast<u32>((static_cast<u64>(ms) + 999u) / 1000u);
}

// Timer wheel — O(1) add, refresh, tick.
// 64 slots (power of 2 for fast modulo), 1-second resolution, driven by single timerfd per shard.
// Note: timeouts > 63s wrap via modulo (e.g., 1000s → slot 40). For keepalive timeouts <= 60s
// this is fine. For longer timeouts, use a hierarchical wheel (not implemented).
//
// Usage:
//   wheel.add(&conn, 60);      // timeout in 60 seconds
//   wheel.refresh(&conn, 60);  // reset on activity
//   wheel.tick(close_fn);      // called every second, closes expired

struct TimerWheel {
    static constexpr u32 kSlots = 64;  // power of 2 for fast modulo

    // Zero is the rejection sentinel. An immediate yield uses the next slot.
    static constexpr u32 yield_fallback_seconds(u32 ms) {
        const u32 seconds = timer_seconds_from_ms(ms);
        if (seconds >= kSlots) return 0;
        return seconds == 0 ? 1 : seconds;
    }

    ListNode slots[kSlots];
    enum class Tick : u32 {};
    Tick cursor;  // Absolute tick modulo 2^32. Only its low bits select a slot.

    // Tick is a modular timestamp. Widen before each step, then select the low 32 bits.
    friend constexpr Tick& operator++(Tick& t) {
        t = Tick{static_cast<u32>(static_cast<u64>(t) + 1)};
        return t;
    }

    friend constexpr Tick& operator--(Tick& t) {
        t = Tick{static_cast<u32>(static_cast<i64>(t) - 1)};
        return t;
    }

    friend constexpr Tick operator++(Tick& t, int) {
        const Tick old = t;
        ++t;
        return old;
    }

    friend constexpr Tick operator--(Tick& t, int) {
        const Tick old = t;
        --t;
        return old;
    }

    constexpr Tick tick_after(u32 seconds) const {
        u32 result;
        (void)__builtin_add_overflow(static_cast<u32>(cursor), seconds, &result);
        return Tick{result};
    }

    constexpr u32 slot_after(u32 seconds) const {
        return static_cast<u32>(tick_after(seconds)) % kSlots;
    }

    // Elapsed ticks for intervals shorter than one complete 32-bit cycle.
    static constexpr u32 elapsed_ticks(Tick start, Tick now) {
        u32 result;
        (void)__builtin_sub_overflow(static_cast<u32>(now), static_cast<u32>(start), &result);
        return result;
    }

    static constexpr u32 remaining_ticks(u32 timeout, u32 elapsed) {
        u32 remaining;
        return __builtin_sub_overflow(timeout, elapsed, &remaining) ? 0 : remaining;
    }

    void init() {
        cursor = Tick{};
        for (u32 i = 0; i < kSlots; i++) {
            slots[i].init();
        }
    }

    // Add connection with timeout in `seconds` from now. O(1).
    void add(Connection* c, u32 seconds);

    // Remove and re-add with new timeout. O(1).
    void refresh(Connection* c, u32 seconds);

    // Remove from wheel (e.g., connection closing). O(1).
    void remove(Connection* c);

    // Advance cursor, call `on_expire` for each expired connection.
    // Returns number of expired connections.
    template <typename Fn>
    u32 tick(Fn on_expire) {
        u32 count = 0;
        ListNode* head = &slots[slot_after(0)];
        ListNode* node = head->next;
        while (node != head) {
            ListNode* next = node->next;
            node->detach();
            // container_of: timer_node is at a known offset in Connection
            auto* conn =
                reinterpret_cast<Connection*>(reinterpret_cast<char*>(node) - timer_node_offset());
            on_expire(conn);
            count++;
            node = next;
        }
        ++cursor;
        return count;
    }

    // Offset of timer_node within Connection. Defined in .cc after Connection is complete.
    static u64 timer_node_offset();
};

}  // namespace rut
