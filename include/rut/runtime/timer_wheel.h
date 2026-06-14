/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "rut/common/types.h"

namespace rut {

struct ConnectionBase;              // forward decl
using Connection = ConnectionBase;  // alias (matches connection.h)

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

    ListNode slots[kSlots];
    u32 cursor;

    void init() {
        cursor = 0;
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
        ListNode* head = &slots[cursor & (kSlots - 1)];
        ListNode* node = head->next;
        while (node != head) {
            ListNode* next = node->next;
            node->remove();
            node->init();
            // container_of: timer_node is at a known offset in Connection
            auto* conn =
                reinterpret_cast<Connection*>(reinterpret_cast<char*>(node) - timer_node_offset());
            on_expire(conn);
            count++;
            node = next;
        }
        cursor++;
        return count;
    }

    // Offset of timer_node within Connection. Defined in .cc after Connection is complete.
    static u64 timer_node_offset();
};

}  // namespace rut
